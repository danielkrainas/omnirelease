//! Runtime configuration: an optional TOML file, overridden by CLI flags / env vars.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use serde::Deserialize;

/// How package downloads are served to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DownloadMode {
    /// Respond with a redirect to the GitHub asset URL (default, cheapest).
    Redirect,
    /// Stream the asset through this server.
    Proxy,
}

/// Values accepted on the command line or through `OMNIRELEASE_*` environment variables.
/// Anything set here wins over the config file.
#[derive(Debug, Default, Args)]
pub struct Overrides {
    /// Address to listen on.
    #[arg(long, env = "OMNIRELEASE_LISTEN")]
    pub listen: Option<String>,

    /// Public base URL (e.g. https://pkg.example.com). Derived from request headers if unset.
    #[arg(long, env = "OMNIRELEASE_BASE_URL")]
    pub base_url: Option<String>,

    /// Directory used to cache parsed package metadata.
    #[arg(long, env = "OMNIRELEASE_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

    /// GitHub API token (raises rate limits from 60 to 5000 requests/hour).
    #[arg(long, env = "GITHUB_TOKEN", hide_env_values = true)]
    pub github_token: Option<String>,

    /// Allowed repositories, comma-separated: `owner/repo`, `owner/*` or `*/*`.
    #[arg(long, env = "OMNIRELEASE_REPOSITORIES", value_delimiter = ',')]
    pub repositories: Option<Vec<String>>,

    /// How often to re-check GitHub for new releases (e.g. `10m`, `1h`).
    #[arg(long, env = "OMNIRELEASE_REFRESH_INTERVAL", value_parser = humantime::parse_duration)]
    pub refresh_interval: Option<Duration>,

    /// Number of most recent releases to index per repository.
    #[arg(long, env = "OMNIRELEASE_MAX_RELEASES")]
    pub max_releases: Option<usize>,

    /// Include GitHub pre-releases in the index.
    #[arg(long, env = "OMNIRELEASE_INCLUDE_PRERELEASES")]
    pub include_prereleases: Option<bool>,

    /// `redirect` (default) or `proxy`.
    #[arg(long, env = "OMNIRELEASE_DOWNLOAD_MODE")]
    pub download_mode: Option<DownloadMode>,

    /// Path to an ASCII-armored OpenPGP secret key used to sign repository metadata.
    #[arg(long, env = "OMNIRELEASE_SIGNING_KEY_FILE")]
    pub signing_key_file: Option<PathBuf>,

    /// Passphrase for the signing key, if it is protected.
    #[arg(
        long,
        env = "OMNIRELEASE_SIGNING_KEY_PASSPHRASE",
        hide_env_values = true
    )]
    pub signing_key_passphrase: Option<String>,

    /// Define a group served as one combined repository at `/<name>/`:
    /// `name=owner/repo,owner/repo`. Repeatable; in the environment variable separate
    /// groups with `;`. Overrides a config-file group of the same name.
    #[arg(long = "group", env = "OMNIRELEASE_GROUPS", value_delimiter = ';')]
    pub groups: Option<Vec<String>>,

    /// Redis URL (`redis://[:password@]host:port[/db]`, or `rediss://` for TLS). When set,
    /// release lists, indexed packages and parsed metadata are cached in Redis instead of
    /// memory and `--cache-dir`, so restarts and replicas share them.
    #[arg(long, env = "OMNIRELEASE_REDIS_URL", hide_env_values = true)]
    pub redis_url: Option<String>,

    /// Prefix for all Redis keys.
    #[arg(long, env = "OMNIRELEASE_REDIS_PREFIX")]
    pub redis_prefix: Option<String>,

    /// Expiry for Redis entries (e.g. `30d`; `0s` for none). Entries are rewritten when
    /// their contents change.
    #[arg(long, env = "OMNIRELEASE_REDIS_TTL", value_parser = humantime::parse_duration)]
    pub redis_ttl: Option<Duration>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub base_url: Option<String>,
    pub cache_dir: PathBuf,
    pub github_api: String,
    pub github_token: Option<String>,
    pub repositories: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub refresh_interval: Duration,
    pub max_releases: usize,
    pub include_prereleases: bool,
    pub download_mode: DownloadMode,
    /// Max number of package assets downloaded concurrently while indexing.
    pub index_concurrency: usize,
    /// Value of the `Origin`/`Label` fields in APT Release files.
    pub origin: String,
    pub signing: Signing,
    /// Named groups of repositories served as one combined repository at `/<name>/`.
    pub groups: BTreeMap<String, Group>,
    pub redis: RedisConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedisConfig {
    /// Unset: cache in memory and on disk.
    pub url: Option<String>,
    pub prefix: String,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: None,
            prefix: "omnirelease:".into(),
            ttl: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Member repositories (`owner/repo`; no wildcards), in priority order.
    pub repositories: Vec<String>,
}

/// Path segments that follow a group name; repositories with these names under an owner
/// with the same name as a group would be unreachable.
pub const FORMAT_SEGMENTS: &[&str] = &["deb", "rpm", "arch"];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Signing {
    pub key_file: Option<PathBuf>,
    pub passphrase: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".into(),
            base_url: None,
            cache_dir: PathBuf::from("./cache"),
            github_api: "https://api.github.com".into(),
            github_token: None,
            repositories: Vec::new(),
            refresh_interval: Duration::from_secs(15 * 60),
            max_releases: 10,
            include_prereleases: false,
            download_mode: DownloadMode::Redirect,
            index_concurrency: 4,
            origin: "omnirelease".into(),
            signing: Signing::default(),
            groups: BTreeMap::new(),
            redis: RedisConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&PathBuf>, o: Overrides) -> Result<Self> {
        let mut cfg = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config file {}", p.display()))?;
                toml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
            }
            None => Config::default(),
        };

        if let Some(v) = o.listen {
            cfg.listen = v;
        }
        if let Some(v) = o.base_url {
            cfg.base_url = Some(v);
        }
        if let Some(v) = o.cache_dir {
            cfg.cache_dir = v;
        }
        if let Some(v) = o.github_token {
            cfg.github_token = Some(v);
        }
        if let Some(v) = o.repositories {
            cfg.repositories = v;
        }
        if let Some(v) = o.refresh_interval {
            cfg.refresh_interval = v;
        }
        if let Some(v) = o.max_releases {
            cfg.max_releases = v;
        }
        if let Some(v) = o.include_prereleases {
            cfg.include_prereleases = v;
        }
        if let Some(v) = o.download_mode {
            cfg.download_mode = v;
        }
        if let Some(v) = o.signing_key_file {
            cfg.signing.key_file = Some(v);
        }
        if let Some(v) = o.signing_key_passphrase {
            cfg.signing.passphrase = Some(v);
        }
        if let Some(v) = o.redis_url {
            cfg.redis.url = Some(v);
        }
        if let Some(v) = o.redis_prefix {
            cfg.redis.prefix = v;
        }
        if let Some(v) = o.redis_ttl {
            cfg.redis.ttl = v;
        }
        cfg.redis.url = cfg
            .redis
            .url
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());
        for spec in o.groups.unwrap_or_default() {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            let (name, members) = spec.split_once('=').with_context(|| {
                format!("invalid group {spec:?}; expected name=owner/repo,owner/repo")
            })?;
            let repositories = members.split(',').map(str::to_string).collect();
            cfg.groups
                .insert(name.trim().to_string(), Group { repositories });
        }

        cfg.repositories = cfg
            .repositories
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if cfg.github_token.as_deref() == Some("") {
            cfg.github_token = None;
        }
        cfg.base_url = cfg
            .base_url
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty());
        cfg.index_concurrency = cfg.index_concurrency.max(1);
        cfg.max_releases = cfg.max_releases.max(1);

        for pat in &cfg.repositories {
            anyhow::ensure!(
                pat.split('/').count() == 2 && pat.split('/').all(|p| !p.is_empty()),
                "invalid repository pattern {pat:?}; expected owner/repo, owner/* or */*"
            );
        }
        cfg.groups = std::mem::take(&mut cfg.groups)
            .into_iter()
            .map(|(name, g)| {
                let repositories: Vec<String> = g
                    .repositories
                    .iter()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                (name.trim().to_ascii_lowercase(), Group { repositories })
            })
            .collect();
        for (name, g) in &cfg.groups {
            anyhow::ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                    && !name.starts_with('.')
                    && !["healthz", "key.asc", "key.gpg"].contains(&name.as_str()),
                "invalid group name {name:?}; use letters, digits, '-', '_' and '.'"
            );
            anyhow::ensure!(
                !g.repositories.is_empty(),
                "group {name:?} has no repositories"
            );
            for m in &g.repositories {
                let parts: Vec<&str> = m.split('/').collect();
                anyhow::ensure!(
                    parts.len() == 2 && parts.iter().all(|p| !p.is_empty() && *p != "*"),
                    "group {name:?}: invalid member {m:?}; expected owner/repo (wildcards are not allowed in groups)"
                );
            }
            for seg in FORMAT_SEGMENTS {
                let shadowed = format!("{name}/{seg}");
                anyhow::ensure!(
                    !cfg.repositories.contains(&shadowed),
                    "group {name:?} conflicts with repository {shadowed:?}: /{shadowed}/ would be ambiguous; rename the group"
                );
            }
            if cfg.repositories.contains(&format!("{name}/*")) {
                tracing::warn!(
                    "group {name:?} shadows repositories {name}/deb, {name}/rpm and {name}/arch allowed by {name}/*"
                );
            }
        }

        if cfg.repositories.is_empty() && cfg.groups.is_empty() {
            tracing::warn!("no repositories or groups configured; every request will be rejected");
        }
        Ok(cfg)
    }

    /// Is `owner/repo` allowed by the configured patterns?
    pub fn allows(&self, owner: &str, repo: &str) -> bool {
        let (owner, repo) = (owner.to_ascii_lowercase(), repo.to_ascii_lowercase());
        self.repositories.iter().any(|pat| {
            let (po, pr) = pat.split_once('/').unwrap_or((pat, ""));
            (po == "*" || po == owner) && (pr == "*" || pr == repo)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        let cfg = Config {
            repositories: vec!["cli/cli".into(), "sharkdp/*".into()],
            ..Default::default()
        };
        assert!(cfg.allows("cli", "cli"));
        assert!(cfg.allows("CLI", "Cli"));
        assert!(cfg.allows("sharkdp", "bat"));
        assert!(!cfg.allows("cli", "other"));
        let any = Config {
            repositories: vec!["*/*".into()],
            ..Default::default()
        };
        assert!(any.allows("x", "y"));
    }

    fn load(o: Overrides) -> Result<Config> {
        Config::load(None, o)
    }

    #[test]
    fn groups_from_flags() {
        let cfg = load(Overrides {
            groups: Some(vec![
                "Acme=acme/acme-apps, acme/acme-core".into(),
                "tools=sharkdp/bat".into(),
            ]),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            cfg.groups["acme"].repositories,
            vec!["acme/acme-apps", "acme/acme-core"]
        );
        assert_eq!(cfg.groups["tools"].repositories, vec!["sharkdp/bat"]);
    }

    #[test]
    fn group_validation() {
        let bad = |g: &str, repos: Vec<String>| {
            load(Overrides {
                groups: Some(vec![g.into()]),
                repositories: Some(repos),
                ..Default::default()
            })
            .is_err()
        };
        assert!(bad("acme=acme/*", vec![]));
        assert!(bad("acme=", vec![]));
        assert!(bad("noequals", vec![]));
        assert!(bad("healthz=a/b", vec![]));
        assert!(bad("acme=a/b", vec!["acme/deb".into()]));
        assert!(!bad("acme=a/b", vec!["acme/*".into()]));
    }
}
