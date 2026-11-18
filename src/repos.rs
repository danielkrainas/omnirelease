//! Per-repository snapshot cache: fetches releases, downloads and parses new package assets
//! (results are cached on disk by asset id), and rebuilds indexes in the background.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use futures_util::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::config::Config;
use crate::github::{Asset, Fetch, GitHub};
use crate::index::Snapshot;
use crate::pkg::{self, Kind, Meta, Package};
use crate::signing::Signer;

/// Upper bound on distinct repositories kept in memory (matters for `*/*` patterns).
const MAX_REPOS: usize = 1024;

pub struct Repos {
    pub cfg: Arc<Config>,
    pub signer: Option<Arc<Signer>>,
    gh: GitHub,
    entries: StdMutex<HashMap<String, Arc<Entry>>>,
    /// Group name -> (member snapshots it was built from, combined snapshot). Holding the
    /// member Arcs keeps `Arc::ptr_eq` comparisons sound.
    groups: StdMutex<HashMap<String, GroupCache>>,
}

type GroupCache = (Vec<Arc<Snapshot>>, Arc<Snapshot>);

#[derive(Default)]
struct Entry {
    snapshot: RwLock<Option<Arc<Snapshot>>>,
    refresh_lock: Arc<Mutex<()>>,
    last_check: StdMutex<Option<Instant>>,
}

/// What we persist per asset, so each asset is downloaded and parsed at most once.
#[derive(Serialize, Deserialize)]
enum Cached {
    Ok(Package),
    Failed(String),
}

impl Repos {
    pub fn new(cfg: Arc<Config>, signer: Option<Arc<Signer>>) -> Result<Arc<Self>> {
        std::fs::create_dir_all(cfg.cache_dir.join("meta"))
            .with_context(|| format!("creating cache dir {}", cfg.cache_dir.display()))?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("omnirelease/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?;
        let gh = GitHub::new(http, &cfg.github_api, cfg.github_token.clone());
        Ok(Arc::new(Self {
            cfg,
            signer,
            gh,
            entries: StdMutex::new(HashMap::new()),
            groups: StdMutex::new(HashMap::new()),
        }))
    }

    pub fn github(&self) -> &GitHub {
        &self.gh
    }

    /// Return the current snapshot for `owner/repo`, building it on first use. Stale
    /// snapshots are served immediately while a refresh runs in the background.
    pub async fn get(self: &Arc<Self>, owner: &str, repo: &str) -> Result<Arc<Snapshot>> {
        let key = format!(
            "{}/{}",
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        );
        let entry = {
            let mut entries = self.entries.lock().unwrap();
            if !entries.contains_key(&key) && entries.len() >= MAX_REPOS {
                bail!("too many repositories tracked");
            }
            entries.entry(key.clone()).or_default().clone()
        };

        if let Some(snap) = entry.snapshot.read().await.clone() {
            let stale = entry
                .last_check
                .lock()
                .unwrap()
                .is_none_or(|t| t.elapsed() >= self.cfg.refresh_interval);
            if stale && let Ok(guard) = entry.refresh_lock.clone().try_lock_owned() {
                let this = self.clone();
                let (owner, repo, entry2) = (owner.to_string(), repo.to_string(), entry.clone());
                tokio::spawn(async move {
                    let _guard = guard;
                    if let Err(e) = this.refresh(&owner, &repo, &entry2).await {
                        tracing::warn!("background refresh of {owner}/{repo} failed: {e:#}");
                    }
                });
            }
            return Ok(snap);
        }

        let _guard = entry.refresh_lock.lock().await;
        if let Some(snap) = entry.snapshot.read().await.clone() {
            return Ok(snap); // someone else built it while we waited
        }
        self.refresh(owner, repo, &entry).await
    }

    /// Return the combined snapshot for a configured group. It is assembled from the
    /// members' snapshots (no extra GitHub traffic) and rebuilt whenever any member's
    /// snapshot changes. Members that fail to index are left out with a warning.
    pub async fn get_group(self: &Arc<Self>, name: &str) -> Result<Arc<Snapshot>> {
        let group = self
            .cfg
            .groups
            .get(name)
            .with_context(|| format!("unknown group {name}"))?;

        let results =
            futures_util::future::join_all(group.repositories.iter().map(|m| async move {
                let (owner, repo) = m.split_once('/').expect("validated in Config::load");
                (m, self.get(owner, repo).await)
            }))
            .await;
        let mut members = Vec::new();
        for (m, res) in results {
            match res {
                Ok(snap) => members.push((m.clone(), snap)),
                Err(e) => tracing::warn!("group {name}: leaving out {m}: {e:#}"),
            }
        }
        if members.is_empty() {
            bail!("none of the repositories in group {name} could be indexed");
        }

        if let Some((built_from, snap)) = self.groups.lock().unwrap().get(name)
            && built_from.len() == members.len()
            && built_from
                .iter()
                .zip(&members)
                .all(|(a, (_, b))| Arc::ptr_eq(a, b))
        {
            return Ok(snap.clone());
        }

        let mut packages = Vec::new();
        let mut sigs = Vec::new();
        for (m, snap) in &members {
            packages.extend(snap.packages.iter().cloned().map(|mut p| {
                p.source = Some(m.clone());
                p
            }));
            sigs.extend(snap.arch_sigs.iter().cloned());
        }
        let mut snap = Snapshot::build(name, &self.cfg.origin, packages, sigs)?;
        if let Some(signer) = &self.signer {
            snap.sign_static(signer)?;
        }
        let (d, r, a) = snap.counts();
        tracing::info!(
            "assembled group {name} from {} repositories: {d} deb, {r} rpm, {a} arch packages",
            members.len()
        );
        let snap = Arc::new(snap);
        let built_from = members.into_iter().map(|(_, s)| s).collect();
        self.groups
            .lock()
            .unwrap()
            .insert(name.to_string(), (built_from, snap.clone()));
        Ok(snap)
    }

    /// Kick off indexing of all explicitly configured (non-wildcard) repositories,
    /// including group members.
    pub fn warm(self: &Arc<Self>) {
        let members = self
            .cfg
            .groups
            .values()
            .flat_map(|g| g.repositories.clone());
        let mut seen = std::collections::HashSet::new();
        for pat in self.cfg.repositories.clone().into_iter().chain(members) {
            if !seen.insert(pat.clone()) {
                continue;
            }
            let Some((o, r)) = pat.split_once('/') else {
                continue;
            };
            if o == "*" || r == "*" {
                continue;
            }
            let (this, o, r) = (self.clone(), o.to_string(), r.to_string());
            tokio::spawn(async move {
                if let Err(e) = this.get(&o, &r).await {
                    tracing::warn!("initial indexing of {o}/{r} failed: {e:#}");
                }
            });
        }
    }

    async fn refresh(&self, owner: &str, repo: &str, entry: &Entry) -> Result<Arc<Snapshot>> {
        let started = Instant::now();
        let fetched = self.gh.releases(owner, repo).await;
        // Record the attempt even on failure so we don't hammer GitHub.
        *entry.last_check.lock().unwrap() = Some(Instant::now());

        let releases = match fetched? {
            Fetch::NotModified => {
                if let Some(s) = entry.snapshot.read().await.clone() {
                    tracing::debug!("{owner}/{repo}: not modified");
                    return Ok(s);
                }
                // Lost our snapshot somehow; force a full fetch next time.
                bail!("GitHub returned 304 but no snapshot is cached");
            }
            Fetch::Changed(r) => r,
        };

        let mut jobs = Vec::new();
        let mut sigs: Vec<(String, String)> = Vec::new();
        for rel in releases
            .iter()
            .filter(|r| !r.draft && (self.cfg.include_prereleases || !r.prerelease))
            .take(self.cfg.max_releases)
        {
            let by_name: HashMap<&str, &Asset> =
                rel.assets.iter().map(|a| (a.name.as_str(), a)).collect();
            for asset in &rel.assets {
                let Some(kind) = Kind::from_filename(&asset.name) else {
                    continue;
                };
                let sig = if kind == Kind::Arch {
                    by_name
                        .get(format!("{}.sig", asset.name).as_str())
                        .map(|a| (*a).clone())
                } else {
                    None
                };
                if let Some(s) = &sig {
                    sigs.push((s.name.clone(), s.browser_download_url.clone()));
                }
                jobs.push((rel.tag_name.clone(), asset.clone(), kind, sig));
            }
        }

        let packages: Vec<Package> = futures_util::stream::iter(jobs)
            .map(|(tag, asset, kind, sig)| async move {
                match self.package(&tag, &asset, kind, sig.as_ref()).await {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!("{owner}/{repo}: skipping {}: {e:#}", asset.name);
                        None
                    }
                }
            })
            .buffered(self.cfg.index_concurrency)
            .filter_map(|p| async move { p })
            .collect()
            .await;

        let mut snap =
            Snapshot::build(&format!("{owner}/{repo}"), &self.cfg.origin, packages, sigs)?;
        if let Some(signer) = &self.signer {
            snap.sign_static(signer)?;
        }
        let (d, r, a) = snap.counts();
        tracing::info!(
            "indexed {owner}/{repo}: {d} deb, {r} rpm, {a} arch packages in {:.1?}",
            started.elapsed()
        );
        let snap = Arc::new(snap);
        *entry.snapshot.write().await = Some(snap.clone());
        Ok(snap)
    }

    fn cache_path(&self, asset: &Asset) -> PathBuf {
        let mut h = Sha256::new();
        h.update(asset.updated_at.as_bytes());
        h.update(asset.size.to_le_bytes());
        h.update(asset.browser_download_url.as_bytes());
        let tag = &hex::encode(h.finalize())[..16];
        self.cfg
            .cache_dir
            .join("meta")
            .join(format!("{}-{tag}.json", asset.id))
    }

    /// Metadata for one asset, from the disk cache or by downloading and parsing it.
    async fn package(
        &self,
        tag: &str,
        asset: &Asset,
        kind: Kind,
        sig: Option<&Asset>,
    ) -> Result<Package> {
        let cache = self.cache_path(asset);
        if let Ok(raw) = tokio::fs::read(&cache).await {
            match serde_json::from_slice::<Cached>(&raw) {
                Ok(Cached::Ok(p)) => return Ok(p),
                Ok(Cached::Failed(e)) => bail!("{e} (cached)"),
                Err(_) => {} // corrupt or old format: rebuild
            }
        }

        tracing::info!(
            "inspecting {} ({} bytes) for indexing",
            asset.name,
            asset.size
        );
        let result = self.download_and_parse(tag, asset, kind, sig).await;
        let cached = match &result {
            Ok(p) => Some(Cached::Ok(p.clone())),
            // Only remember parse failures, not transient network errors.
            Err(e) if e.to_string().starts_with("parse:") => Some(Cached::Failed(format!("{e:#}"))),
            Err(_) => None,
        };
        if let Some(c) = cached {
            let tmp = cache.with_extension("json.tmp");
            tokio::fs::write(&tmp, serde_json::to_vec(&c)?).await?;
            tokio::fs::rename(&tmp, &cache).await?;
        }
        result
    }

    /// Stream the asset and parse its header without saving it to disk. When GitHub
    /// supplies a sha256 digest we stop reading as soon as the metadata is parsed (usually
    /// within the first few KiB); otherwise the rest of the stream is drained to hash it.
    async fn download_and_parse(
        &self,
        tag: &str,
        asset: &Asset,
        kind: Kind,
        sig: Option<&Asset>,
    ) -> Result<Package> {
        let known_sha = asset
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase);

        let resp = self.gh.download(&asset.browser_download_url).await?;
        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        let reader = SyncIoBridge::new(StreamReader::new(stream));
        let name = asset.name.clone();
        let need_hash = known_sha.is_none();

        let (meta, sha256, size) =
            tokio::task::spawn_blocking(move || -> Result<(Meta, Option<String>, u64)> {
                let mut r = HashingReader {
                    inner: reader,
                    hasher: Sha256::new(),
                    size: 0,
                    io_error: false,
                };
                let parsed = match kind {
                    Kind::Deb => pkg::parse_deb(&mut r).map(Meta::Deb),
                    Kind::Rpm => pkg::parse_rpm(&mut r).map(Meta::Rpm),
                    Kind::Arch => pkg::parse_arch(&mut r, &name).map(Meta::Arch),
                };
                let meta = match parsed {
                    Ok(m) => m,
                    // A broken connection is retried next refresh; a bad file is cached as bad.
                    Err(e) if r.io_error => return Err(e.context("download interrupted")),
                    Err(e) => bail!("parse: {e:#}"),
                };
                if !need_hash {
                    return Ok((meta, None, 0));
                }
                std::io::copy(&mut r, &mut std::io::sink())?;
                Ok((meta, Some(hex::encode(r.hasher.finalize())), r.size))
            })
            .await??;

        let (sha256, size) = match (known_sha, sha256) {
            (Some(h), _) => (h, asset.size),
            (None, Some(h)) => (h, size),
            (None, None) => unreachable!("hash is computed when no digest is known"),
        };

        let meta = match (meta, sig) {
            (Meta::Arch(mut a), Some(sig)) => {
                let bytes = self
                    .gh
                    .download(&sig.browser_download_url)
                    .await?
                    .bytes()
                    .await?;
                a.pgpsig = Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
                Meta::Arch(a)
            }
            (m, _) => m,
        };

        Ok(Package {
            tag: tag.to_string(),
            filename: asset.name.clone(),
            download_url: asset.browser_download_url.clone(),
            size,
            sha256,
            meta,
            source: None,
        })
    }
}

/// Hashes and counts everything read through it, and remembers transport errors.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    size: u64,
    io_error: bool,
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                self.hasher.update(&buf[..n]);
                self.size += n as u64;
                Ok(n)
            }
            Err(e) => {
                self.io_error = true;
                Err(e)
            }
        }
    }
}
