#![allow(clippy::large_enum_variant, clippy::result_large_err)]

mod config;
mod github;
mod index;
mod pkg;
mod repos;
mod server;
mod signing;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::config::{Config, Overrides};

/// Serve GitHub Releases as APT, RPM (dnf/yum/zypper) and pacman repositories.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a TOML config file.
    #[arg(short, long, env = "OMNIRELEASE_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    overrides: Overrides,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Serve,
    /// Generate an Ed25519 OpenPGP key for signing repository metadata.
    Keygen {
        /// User ID embedded in the key.
        #[arg(long, default_value = "omnirelease repository signing key")]
        uid: String,
        /// Write the secret key here (the public key goes to <out>.pub.asc).
        #[arg(long, default_value = "signing-key.asc")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omnirelease=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Keygen { uid, out } => keygen(&uid, &out),
        Command::Serve => serve(Config::load(cli.config.as_ref(), cli.overrides)?).await,
    }
}

fn keygen(uid: &str, out: &PathBuf) -> Result<()> {
    anyhow::ensure!(
        !out.exists(),
        "{} already exists; refusing to overwrite",
        out.display()
    );
    let (secret, public) = signing::generate(uid)?;
    let pub_path = PathBuf::from(format!("{}.pub.asc", out.with_extension("").display()));
    write_private(out, &secret)?;
    std::fs::write(&pub_path, public)?;
    let fpr = signing::Signer::from_armored(&secret, None)?.fingerprint();
    println!(
        "secret key: {}\npublic key: {}\nfingerprint: {fpr}",
        out.display(),
        pub_path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &PathBuf, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &PathBuf, contents: &str) -> Result<()> {
    Ok(std::fs::write(path, contents)?)
}

async fn serve(cfg: Config) -> Result<()> {
    let signer = match &cfg.signing.key_file {
        Some(path) => {
            let s = signing::Signer::from_file(path, cfg.signing.passphrase.as_deref())?;
            tracing::info!("signing repository metadata with key {}", s.fingerprint());
            Some(Arc::new(s))
        }
        None => {
            tracing::warn!(
                "no signing key configured; metadata will be unsigned (clients need [trusted=yes] / SigLevel = Optional TrustAll)"
            );
            None
        }
    };

    let listen = cfg.listen.clone();
    let repos = repos::Repos::new(Arc::new(cfg), signer)?;
    repos.warm();

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    tracing::info!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, server::router(repos))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}
