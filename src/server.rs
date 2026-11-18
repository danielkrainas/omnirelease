//! HTTP routes.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use crate::config::{DownloadMode, FORMAT_SEGMENTS};
use crate::index::{Resolved, Snapshot};
use crate::repos::Repos;

pub fn router(repos: Arc<Repos>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(|| async { "ok" }))
        .route("/key.asc", get(key_armored))
        .route("/key.gpg", get(key_binary))
        .route("/{name}", get(group_home))
        .route("/{name}/", get(group_home))
        .route("/{owner}/{repo}", get(repo_home))
        .route("/{owner}/{repo}/", get(repo_home))
        .route("/{owner}/{repo}/{*path}", get(repo_file))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(repos)
}

fn text(status: StatusCode, body: impl Into<String>) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body.into(),
    )
        .into_response()
}

fn base_url(repos: &Repos, headers: &HeaderMap) -> String {
    if let Some(b) = &repos.cfg.base_url {
        return b.clone();
    }
    let h = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
    };
    let proto = h("x-forwarded-proto").unwrap_or_else(|| "http".into());
    let host = h("x-forwarded-host")
        .or_else(|| h("host"))
        .unwrap_or_else(|| "localhost".into());
    format!("{proto}://{host}")
}

fn valid_gh_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

async fn home(State(repos): State<Arc<Repos>>, headers: HeaderMap) -> Response {
    let base = base_url(&repos, &headers);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "omnirelease {} - APT / RPM / pacman repositories backed by GitHub Releases\n",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out, "Allowed repositories:");
    for r in &repos.cfg.repositories {
        let _ = writeln!(out, "  {r}");
    }
    if !repos.cfg.groups.is_empty() {
        let _ = writeln!(out, "\nGroups (one combined repository each):");
        for (name, g) in &repos.cfg.groups {
            let _ = writeln!(out, "  {base}/{name}/  ({})", g.repositories.join(", "));
        }
    }
    let _ = writeln!(
        out,
        "\nSetup instructions for a repository: {base}/<owner>/<repo>/ or {base}/<group>/"
    );
    match &repos.signer {
        Some(s) => {
            let _ = writeln!(
                out,
                "Signing key: {base}/key.asc (fingerprint {})",
                s.fingerprint()
            );
        }
        None => {
            let _ = writeln!(
                out,
                "Repository metadata is NOT signed (no signing key configured)."
            );
        }
    }
    text(StatusCode::OK, out)
}

async fn key_armored(State(repos): State<Arc<Repos>>) -> Response {
    match &repos.signer {
        Some(s) => (
            [(header::CONTENT_TYPE, "application/pgp-keys")],
            s.public_key_armored().to_string(),
        )
            .into_response(),
        None => text(StatusCode::NOT_FOUND, "no signing key configured\n"),
    }
}

async fn key_binary(State(repos): State<Arc<Repos>>) -> Response {
    match repos.signer.as_ref().map(|s| s.public_key_binary()) {
        Some(Ok(b)) => ([(header::CONTENT_TYPE, "application/pgp-keys")], b).into_response(),
        Some(Err(e)) => text(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}\n")),
        None => text(StatusCode::NOT_FOUND, "no signing key configured\n"),
    }
}

fn check_repo(repos: &Repos, owner: &str, repo: &str) -> Result<(), Response> {
    if !valid_gh_name(owner) || !valid_gh_name(repo) {
        return Err(text(StatusCode::BAD_REQUEST, "invalid repository name\n"));
    }
    if !repos.cfg.allows(owner, repo) {
        return Err(text(
            StatusCode::FORBIDDEN,
            format!("{owner}/{repo} is not served by this proxy\n"),
        ));
    }
    Ok(())
}

/// What a request is for: a single GitHub repository or a configured group.
enum Target {
    Repo { owner: String, repo: String },
    Group(String),
}

impl Target {
    /// URL path of the target below the base URL.
    fn path(&self) -> String {
        match self {
            Target::Repo { owner, repo } => format!("{owner}/{repo}"),
            Target::Group(name) => name.clone(),
        }
    }

    /// Identifier used for list/.repo file names.
    fn id(&self) -> String {
        match self {
            Target::Repo { owner, repo } => format!("{owner}-{repo}").to_ascii_lowercase(),
            Target::Group(name) => name.clone(),
        }
    }

    fn pacman_name(&self) -> String {
        let raw = match self {
            Target::Repo { repo, .. } => repo,
            Target::Group(name) => name,
        };
        raw.to_ascii_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    }

    async fn snapshot(&self, repos: &Arc<Repos>) -> Result<Arc<Snapshot>, Response> {
        let res = match self {
            Target::Repo { owner, repo } => repos.get(owner, repo).await,
            Target::Group(name) => repos.get_group(name).await,
        };
        res.map_err(|e| {
            let p = self.path();
            tracing::warn!("{p}: {e:#}");
            text(
                StatusCode::BAD_GATEWAY,
                format!("could not index {p}: {e:#}\n"),
            )
        })
    }
}

fn group_name(repos: &Repos, segment: &str) -> Option<String> {
    let name = segment.to_ascii_lowercase();
    repos.cfg.groups.contains_key(&name).then_some(name)
}

async fn group_home(
    State(repos): State<Arc<Repos>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    match group_name(&repos, &name) {
        Some(g) => setup_page(&repos, Target::Group(g), &headers).await,
        None => text(StatusCode::NOT_FOUND, "not found\n"),
    }
}

async fn repo_home(
    State(repos): State<Arc<Repos>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(g) = group_name(&repos, &owner)
        && FORMAT_SEGMENTS.contains(&repo.as_str())
    {
        return text(
            StatusCode::NOT_FOUND,
            format!("see /{g}/ for setup instructions\n"),
        );
    }
    if let Err(r) = check_repo(&repos, &owner, &repo) {
        return r;
    }
    setup_page(&repos, Target::Repo { owner, repo }, &headers).await
}

async fn setup_page(repos: &Arc<Repos>, target: Target, headers: &HeaderMap) -> Response {
    let snap = match target.snapshot(repos).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let base = base_url(repos, headers);
    let root = format!("{base}/{}", target.path());
    let id = target.id();
    let signed = repos.signer.is_some();
    let (d, r, a) = snap.counts();

    let mut o = String::new();
    let _ = writeln!(
        o,
        "{} - indexed {} ({d} deb, {r} rpm, {a} pacman packages)",
        snap.label,
        snap.built.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Target::Group(name) = &target {
        let members = repos.cfg.groups[name].repositories.join(", ");
        let _ = writeln!(o, "group of: {members}");
    }
    o.push('\n');

    let _ = writeln!(o, "== Debian / Ubuntu (apt) ==");
    if signed {
        let _ = writeln!(o, "sudo install -d -m 0755 /etc/apt/keyrings");
        let _ = writeln!(
            o,
            "curl -fsSL {base}/key.asc | sudo tee /etc/apt/keyrings/omnirelease.asc >/dev/null"
        );
        let _ = writeln!(
            o,
            "echo \"deb [signed-by=/etc/apt/keyrings/omnirelease.asc] {root}/deb stable main\" | sudo tee /etc/apt/sources.list.d/{id}.list"
        );
    } else {
        let _ = writeln!(
            o,
            "echo \"deb [trusted=yes] {root}/deb stable main\" | sudo tee /etc/apt/sources.list.d/{id}.list"
        );
    }
    let _ = writeln!(o, "sudo apt update\n");

    let _ = writeln!(o, "== Fedora / RHEL / openSUSE (dnf, yum, zypper) ==");
    let _ = writeln!(
        o,
        "sudo curl -fsSL -o /etc/yum.repos.d/{id}.repo {root}/rpm/{id}.repo"
    );
    let _ = writeln!(o, "# zypper: sudo zypper addrepo {root}/rpm/{id}.repo\n");

    let _ = writeln!(o, "== Arch Linux (pacman) ==");
    if let Some(s) = &repos.signer {
        let _ = writeln!(o, "curl -fsSL {base}/key.asc | sudo pacman-key --add -");
        let _ = writeln!(o, "sudo pacman-key --lsign-key {}", s.fingerprint());
    }
    let _ = writeln!(o, "# then append to /etc/pacman.conf:");
    let _ = writeln!(o, "[{}]", target.pacman_name());
    let _ = writeln!(
        o,
        "SigLevel = {}",
        if signed {
            "PackageOptional DatabaseRequired TrustedOnly"
        } else {
            "Optional TrustAll"
        }
    );
    let _ = writeln!(o, "Server = {root}/arch/$arch");
    text(StatusCode::OK, o)
}

async fn repo_file(
    State(repos): State<Arc<Repos>>,
    Path((owner, repo, path)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    // `/<group>/<format>/...` takes precedence over `/<owner>/<repo>/...`; config
    // validation rejects groups that would shadow an explicitly allowed repository.
    let (target, path) = match group_name(&repos, &owner) {
        Some(g) if FORMAT_SEGMENTS.contains(&repo.as_str()) => {
            (Target::Group(g), format!("{repo}/{path}"))
        }
        _ => {
            if let Err(r) = check_repo(&repos, &owner, &repo) {
                return r;
            }
            (Target::Repo { owner, repo }, path)
        }
    };
    serve_file(&repos, target, &path, &headers).await
}

async fn serve_file(
    repos: &Arc<Repos>,
    target: Target,
    path: &str,
    headers: &HeaderMap,
) -> Response {
    if path.split('/').any(|seg| seg == "..") {
        return text(StatusCode::BAD_REQUEST, "invalid path\n");
    }

    // The .repo file embeds the public URL, so it is rendered per request.
    let id = target.id();
    if path == format!("rpm/{id}.repo") {
        let base = base_url(repos, headers);
        let signed = repos.signer.is_some();
        let mut body = format!(
            "[{id}]\nname={} (GitHub releases via omnirelease)\nbaseurl={base}/{}/rpm\nenabled=1\ngpgcheck=0\nrepo_gpgcheck={}\n",
            target.path(),
            target.path(),
            signed as u8
        );
        if signed {
            let _ = writeln!(body, "gpgkey={base}/key.asc");
        }
        return text(StatusCode::OK, body);
    }

    let snap = match target.snapshot(repos).await {
        Ok(s) => s,
        Err(r) => return r,
    };

    match snap.resolve(path, repos.signer.as_deref()) {
        Ok(Some(Resolved::File { body, content_type })) => {
            let mut resp = Response::new(Body::from(body));
            let h = resp.headers_mut();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            h.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            resp
        }
        Ok(Some(Resolved::Download { url, filename })) => match repos.cfg.download_mode {
            DownloadMode::Redirect => Redirect::to(&url).into_response(),
            DownloadMode::Proxy => proxy(repos, &url, &filename).await,
        },
        Ok(None) => text(StatusCode::NOT_FOUND, "not found\n"),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}\n")),
    }
}

async fn proxy(repos: &Repos, url: &str, filename: &str) -> Response {
    let upstream = match repos.github().download(url).await {
        Ok(r) => r,
        Err(e) => return text(StatusCode::BAD_GATEWAY, format!("{e:#}\n")),
    };
    let len = upstream.content_length();
    let mut resp = Response::new(Body::from_stream(upstream.bytes_stream()));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        filename.replace('"', "")
    )) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(len) = len {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    }
    resp
}
