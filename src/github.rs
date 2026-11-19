//! Minimal GitHub Releases API client with ETag-based conditional requests.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use reqwest::{StatusCode, header};
use serde::{Deserialize, Serialize};

use crate::cache::{Cache, CachedReleases};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub updated_at: String,
    pub browser_download_url: String,
    /// `sha256:<hex>`, provided by GitHub for assets uploaded since mid-2025.
    #[serde(default)]
    pub digest: Option<String>,
}

pub struct GitHub {
    http: reqwest::Client,
    api: String,
    token: Option<String>,
    /// Holds each repository's last release list and its ETag.
    cache: Arc<Cache>,
}

pub struct Releases {
    /// Identifies this version of the list; `None` if GitHub sent no ETag.
    pub etag: Option<String>,
    pub list: Vec<Release>,
}

impl GitHub {
    pub fn new(http: reqwest::Client, api: &str, token: Option<String>, cache: Arc<Cache>) -> Self {
        Self {
            http,
            api: api.trim_end_matches('/').to_string(),
            token,
            cache,
        }
    }

    fn get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        req
    }

    /// Fetch the 100 most recent releases (callers filter out drafts/pre-releases and trim,
    /// so we over-fetch: repos with many nightlies would otherwise show nothing). Uses
    /// `If-None-Match` against the cached list, which is returned on 304; 304 responses do
    /// not count against the GitHub API rate limit.
    pub async fn releases(&self, owner: &str, repo: &str) -> Result<Releases> {
        let key = format!("{owner}/{repo}").to_ascii_lowercase();
        let url = format!("{}/repos/{owner}/{repo}/releases?per_page=100", self.api);

        let mut req = self.get(&url);
        let mut cached = self.cache.releases(&key).await;
        if let Some(c) = &cached {
            req = req.header(header::IF_NONE_MATCH, &c.etag);
        }

        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        match resp.status() {
            StatusCode::NOT_MODIFIED if cached.is_some() => {
                let c = cached.take().expect("checked above");
                return Ok(Releases {
                    etag: Some(c.etag),
                    list: c.releases,
                });
            }
            StatusCode::NOT_FOUND => bail!("repository {key} not found"),
            s if !s.is_success() => {
                let body = resp.text().await.unwrap_or_default();
                bail!(
                    "GitHub API returned {s} for {key}: {}",
                    body.chars().take(300).collect::<String>()
                );
            }
            _ => {}
        }

        let etag = resp
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let list: Vec<Release> = resp.json().await.context("decoding releases JSON")?;
        if let Some(etag) = &etag {
            let value = CachedReleases {
                etag: etag.clone(),
                releases: list.clone(),
            };
            self.cache.put_releases(&key, value).await;
        }
        Ok(Releases { etag, list })
    }

    /// Start downloading a release asset (follows redirects to the CDN).
    pub async fn download(&self, url: &str) -> Result<reqwest::Response> {
        let mut req = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/octet-stream");
        // Only attach the token for github.com URLs; the CDN redirect is pre-signed.
        if let Some(t) = &self.token
            && url.starts_with("https://github.com/")
        {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            bail!("download of {url} failed: {}", resp.status());
        }
        Ok(resp)
    }
}
