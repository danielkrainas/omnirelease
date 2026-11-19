//! Cache for GitHub release lists (with their ETags), each repository's indexed package set,
//! and per-asset parsed metadata.
//!
//! Without Redis, release lists are kept in memory, asset metadata is written to
//! `cache_dir`, and package sets are not persisted. With Redis, all three are stored there,
//! so restarts and replicas share one cache. Redis is treated as a cache, not a store:
//! once connected, errors are logged and the server carries on as if the key was missing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::github::{Asset, Release};
use crate::pkg::Package;

/// Bump when the format of any cached value changes; old keys are then ignored and expire.
const FORMAT: &str = "v1";

/// A repository's releases as of the last successful (200) fetch.
#[derive(Clone, Serialize, Deserialize)]
pub struct CachedReleases {
    pub etag: String,
    pub releases: Vec<Release>,
}

/// The packages indexed for a repository from the releases with ETag `etag`.
#[derive(Serialize, Deserialize)]
pub struct RepoState {
    pub etag: String,
    /// Settings the package set depends on; a state built with different ones is ignored.
    pub max_releases: usize,
    pub include_prereleases: bool,
    pub packages: Vec<Package>,
    pub arch_sigs: Vec<(String, String)>,
}

/// Outcome of inspecting one asset, so each is downloaded and parsed at most once.
#[derive(Serialize, Deserialize)]
pub enum CachedAsset {
    Ok(Package),
    Failed(String),
}

pub struct Cache {
    backend: Backend,
}

enum Backend {
    Local {
        meta_dir: PathBuf,
        releases: Mutex<HashMap<String, CachedReleases>>,
    },
    Redis(Redis),
}

struct Redis {
    conn: ConnectionManager,
    prefix: String,
    ttl: Option<Duration>,
}

impl Cache {
    pub async fn new(cfg: &Config) -> Result<Self> {
        let backend = match &cfg.redis.url {
            Some(url) => {
                let client = redis::Client::open(url.as_str())
                    .context("invalid Redis URL (expected redis://… or rediss://…)")?;
                let conn_cfg = ConnectionManagerConfig::new()
                    .set_connection_timeout(Some(Duration::from_secs(5)))
                    .set_response_timeout(Some(Duration::from_secs(5)))
                    .set_number_of_retries(3);
                let mut conn = ConnectionManager::new_with_config(client, conn_cfg)
                    .await
                    .context("connecting to Redis")?;
                let _: String = redis::cmd("PING")
                    .query_async(&mut conn)
                    .await
                    .context("pinging Redis")?;
                let ttl = Some(cfg.redis.ttl).filter(|t| !t.is_zero());
                tracing::info!(
                    "caching in Redis at {} (key prefix {:?}, ttl {})",
                    redacted(url),
                    cfg.redis.prefix,
                    ttl.map_or("none".into(), |t| humantime::format_duration(t).to_string())
                );
                Backend::Redis(Redis {
                    conn,
                    prefix: cfg.redis.prefix.clone(),
                    ttl,
                })
            }
            None => {
                let meta_dir = cfg.cache_dir.join("meta");
                std::fs::create_dir_all(&meta_dir)
                    .with_context(|| format!("creating cache dir {}", meta_dir.display()))?;
                Backend::Local {
                    meta_dir,
                    releases: Mutex::new(HashMap::new()),
                }
            }
        };
        Ok(Self { backend })
    }

    /// `key` is the lowercased `owner/repo`.
    pub async fn releases(&self, key: &str) -> Option<CachedReleases> {
        match &self.backend {
            Backend::Local { releases, .. } => releases.lock().await.get(key).cloned(),
            Backend::Redis(r) => r.get(&format!("releases:{key}")).await,
        }
    }

    pub async fn put_releases(&self, key: &str, value: CachedReleases) {
        match &self.backend {
            Backend::Local { releases, .. } => {
                releases.lock().await.insert(key.to_string(), value);
            }
            Backend::Redis(r) => r.set(&format!("releases:{key}"), &value).await,
        }
    }

    pub async fn repo_state(&self, key: &str) -> Option<RepoState> {
        match &self.backend {
            Backend::Local { .. } => None,
            Backend::Redis(r) => r.get(&format!("repo:{key}")).await,
        }
    }

    pub async fn put_repo_state(&self, key: &str, value: &RepoState) {
        if let Backend::Redis(r) = &self.backend {
            r.set(&format!("repo:{key}"), value).await;
        }
    }

    pub async fn asset(&self, asset: &Asset) -> Option<CachedAsset> {
        let id = asset_id(asset);
        match &self.backend {
            Backend::Local { meta_dir, .. } => {
                let raw = tokio::fs::read(meta_dir.join(format!("{id}.json")))
                    .await
                    .ok()?;
                serde_json::from_slice(&raw).ok() // corrupt or old format: rebuild
            }
            Backend::Redis(r) => r.get(&format!("asset:{id}")).await,
        }
    }

    pub async fn put_asset(&self, asset: &Asset, value: &CachedAsset) -> Result<()> {
        let id = asset_id(asset);
        match &self.backend {
            Backend::Local { meta_dir, .. } => {
                let path = meta_dir.join(format!("{id}.json"));
                let tmp = path.with_extension("json.tmp");
                tokio::fs::write(&tmp, serde_json::to_vec(value)?).await?;
                tokio::fs::rename(&tmp, &path).await?;
            }
            Backend::Redis(r) => r.set(&format!("asset:{id}"), value).await,
        }
        Ok(())
    }
}

/// Identifies an asset's contents: re-uploading a file under the same name changes it.
fn asset_id(asset: &Asset) -> String {
    let mut h = Sha256::new();
    h.update(asset.updated_at.as_bytes());
    h.update(asset.size.to_le_bytes());
    h.update(asset.browser_download_url.as_bytes());
    format!("{}-{}", asset.id, &hex::encode(h.finalize())[..16])
}

impl Redis {
    fn key(&self, k: &str) -> String {
        format!("{}{FORMAT}:{k}", self.prefix)
    }

    async fn get<T: DeserializeOwned>(&self, k: &str) -> Option<T> {
        let key = self.key(k);
        let raw: Option<Vec<u8>> = match self.conn.clone().get(&key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Redis GET {key} failed: {e}");
                return None;
            }
        };
        let decoded = zstd::decode_all(raw?.as_slice())
            .map_err(anyhow::Error::from)
            .and_then(|json| Ok(serde_json::from_slice(&json)?));
        match decoded {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("ignoring unreadable Redis value {key}: {e:#}");
                None
            }
        }
    }

    async fn set<T: Serialize>(&self, k: &str, value: &T) {
        let key = self.key(k);
        let encoded = serde_json::to_vec(value)
            .map_err(anyhow::Error::from)
            .and_then(|json| Ok(zstd::encode_all(json.as_slice(), 3)?));
        let bytes = match encoded {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("could not encode {key} for Redis: {e:#}");
                return;
            }
        };
        let mut conn = self.conn.clone();
        let res: redis::RedisResult<()> = match self.ttl {
            Some(ttl) => conn.set_ex(&key, bytes, ttl.as_secs().max(1)).await,
            None => conn.set(&key, bytes).await,
        };
        if let Err(e) = res {
            tracing::warn!("Redis SET {key} failed: {e}");
        }
    }
}

/// The URL with any password replaced, for logging.
fn redacted(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("***"));
            u.to_string()
        }
        Ok(u) => u.to_string(),
        Err(_) => "<unparseable url>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password() {
        assert_eq!(
            redacted("redis://:hunter2@cache:6379/0"),
            "redis://:***@cache:6379/0"
        );
        assert_eq!(redacted("rediss://cache:6380"), "rediss://cache:6380");
    }
}
