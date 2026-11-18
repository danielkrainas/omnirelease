//! Minimal GitHub Releases API client with ETag-based conditional requests.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use reqwest::{StatusCode, header};
use serde::Deserialize;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
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
    /// `owner/repo` -> (etag, releases) from the last successful fetch.
    etags: Mutex<HashMap<String, (String, Vec<Release>)>>,
}

pub enum Fetch {
    /// Releases changed (or this is the first fetch).
    Changed(Vec<Release>),
    /// GitHub returned 304: nothing changed since the previous fetch.
    NotModified,
}

impl GitHub {
    pub fn new(http: reqwest::Client, api: &str, token: Option<String>) -> Self {
        Self {
            http,
            api: api.trim_end_matches('/').to_string(),
            token,
            etags: Mutex::new(HashMap::new()),
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
    /// `If-None-Match`; 304 responses do not count against the GitHub API rate limit.
    pub async fn releases(&self, owner: &str, repo: &str) -> Result<Fetch> {
        let key = format!("{owner}/{repo}");
        let url = format!("{}/repos/{owner}/{repo}/releases?per_page=100", self.api);

        let mut req = self.get(&url);
        let cached_etag = self.etags.lock().await.get(&key).map(|(e, _)| e.clone());
        if let Some(etag) = &cached_etag {
            req = req.header(header::IF_NONE_MATCH, etag);
        }

        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        match resp.status() {
            StatusCode::NOT_MODIFIED if cached_etag.is_some() => return Ok(Fetch::NotModified),
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
        let releases: Vec<Release> = resp.json().await.context("decoding releases JSON")?;
        if let Some(etag) = etag {
            self.etags
                .lock()
                .await
                .insert(key, (etag, releases.clone()));
        }
        Ok(Fetch::Changed(releases))
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
