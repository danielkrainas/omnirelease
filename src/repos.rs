//! Per-repository snapshots: fetches releases, downloads and parses new package assets
//! (results are cached by asset id, see `cache`), and rebuilds indexes in the background.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use futures_util::{StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::cache::{Cache, CachedAsset, RepoState};
use crate::config::Config;
use crate::github::{Asset, GitHub, Releases};
use crate::index::Snapshot;
use crate::pkg::{self, Kind, Meta, Package};
use crate::signing::Signer;

/// Upper bound on distinct repositories kept in memory (matters for `*/*` patterns).
const MAX_REPOS: usize = 1024;

pub struct Repos {
    pub cfg: Arc<Config>,
    pub signer: Option<Arc<Signer>>,
    gh: GitHub,
    cache: Arc<Cache>,
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
    /// ETag of the release list the snapshot was built from.
    built_etag: StdMutex<Option<String>>,
}

impl Repos {
    pub async fn new(cfg: Arc<Config>, signer: Option<Arc<Signer>>) -> Result<Arc<Self>> {
        let cache = Arc::new(Cache::new(&cfg).await?);
        let http = reqwest::Client::builder()
            .user_agent(concat!("omnirelease/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?;
        let gh = GitHub::new(
            http,
            &cfg.github_api,
            cfg.github_token.clone(),
            cache.clone(),
        );
        Ok(Arc::new(Self {
            cfg,
            signer,
            gh,
            cache,
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
        // A package set cached by an earlier run or another replica can be served at once;
        // it is left unchecked, so the next request triggers a background refresh.
        if let Some(snap) = self.restore(owner, repo, &entry).await {
            return Ok(snap);
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

    async fn restore(&self, owner: &str, repo: &str, entry: &Entry) -> Option<Arc<Snapshot>> {
        let key = repo_key(owner, repo);
        let state = self.cache.repo_state(&key).await?;
        if state.max_releases != self.cfg.max_releases
            || state.include_prereleases != self.cfg.include_prereleases
        {
            return None;
        }
        let snap = match self.build(owner, repo, state.packages, state.arch_sigs) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("{key}: could not rebuild cached index: {e:#}");
                return None;
            }
        };
        let (d, r, a) = snap.counts();
        tracing::info!("restored {key} from cache: {d} deb, {r} rpm, {a} arch packages");
        *entry.built_etag.lock().unwrap() = Some(state.etag);
        *entry.snapshot.write().await = Some(snap.clone());
        Some(snap)
    }

    fn build(
        &self,
        owner: &str,
        repo: &str,
        packages: Vec<Package>,
        sigs: Vec<(String, String)>,
    ) -> Result<Arc<Snapshot>> {
        let mut snap =
            Snapshot::build(&format!("{owner}/{repo}"), &self.cfg.origin, packages, sigs)?;
        if let Some(signer) = &self.signer {
            snap.sign_static(signer)?;
        }
        Ok(Arc::new(snap))
    }

    async fn refresh(&self, owner: &str, repo: &str, entry: &Entry) -> Result<Arc<Snapshot>> {
        let started = Instant::now();
        let fetched = self.gh.releases(owner, repo).await;
        // Record the attempt even on failure so we don't hammer GitHub.
        *entry.last_check.lock().unwrap() = Some(Instant::now());
        let Releases {
            etag,
            list: releases,
        } = fetched?;

        let unchanged = etag.is_some() && *entry.built_etag.lock().unwrap() == etag;
        if unchanged && let Some(s) = entry.snapshot.read().await.clone() {
            tracing::debug!("{owner}/{repo}: not modified");
            return Ok(s);
        }

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

        let snap = self.build(owner, repo, packages, sigs)?;
        let (d, r, a) = snap.counts();
        tracing::info!(
            "indexed {owner}/{repo}: {d} deb, {r} rpm, {a} arch packages in {:.1?}",
            started.elapsed()
        );
        if let Some(etag) = &etag {
            let state = RepoState {
                etag: etag.clone(),
                max_releases: self.cfg.max_releases,
                include_prereleases: self.cfg.include_prereleases,
                packages: snap.packages.clone(),
                arch_sigs: snap.arch_sigs.clone(),
            };
            self.cache
                .put_repo_state(&repo_key(owner, repo), &state)
                .await;
        }
        *entry.built_etag.lock().unwrap() = etag;
        *entry.snapshot.write().await = Some(snap.clone());
        Ok(snap)
    }

    /// Metadata for one asset, from the cache or by downloading and parsing it.
    async fn package(
        &self,
        tag: &str,
        asset: &Asset,
        kind: Kind,
        sig: Option<&Asset>,
    ) -> Result<Package> {
        match self.cache.asset(asset).await {
            Some(CachedAsset::Ok(p)) => return Ok(p),
            Some(CachedAsset::Failed(e)) => bail!("{e} (cached)"),
            None => {}
        }

        tracing::info!(
            "inspecting {} ({} bytes) for indexing",
            asset.name,
            asset.size
        );
        let result = self.download_and_parse(tag, asset, kind, sig).await;
        let cached = match &result {
            Ok(p) => Some(CachedAsset::Ok(p.clone())),
            // Only remember parse failures, not transient network errors.
            Err(e) if e.to_string().starts_with("parse:") => {
                Some(CachedAsset::Failed(format!("{e:#}")))
            }
            Err(_) => None,
        };
        if let Some(c) = cached {
            self.cache.put_asset(asset, &c).await?;
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

fn repo_key(owner: &str, repo: &str) -> String {
    format!("{owner}/{repo}").to_ascii_lowercase()
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
