# omnirelease

**Turn any project's GitHub Releases into a real package repository.**

Many projects attach `.deb`, `.rpm` and Arch `.pkg.tar.zst` files to their GitHub
releases, but don't run an APT/YUM/pacman repository, so users have to download and
install packages by hand, and never get updates. omnirelease is a small proxy that sits
in front of the GitHub Releases API and presents those assets as standard
repositories:

| Client                                   | Repository URL                              |
| ---------------------------------------- | ------------------------------------------- |
| `apt` (Debian, Ubuntu, …)                | `https://<host>/<owner>/<repo>/deb`         |
| `dnf` / `yum` / `zypper` (Fedora, RHEL, openSUSE, …) | `https://<host>/<owner>/<repo>/rpm` |
| `pacman` (Arch Linux, …)                 | `https://<host>/<owner>/<repo>/arch/$arch`  |

Then `apt upgrade`, `dnf upgrade` and `pacman -Syu` pick up new upstream releases
automatically.

Several GitHub repositories can also be combined into a **group** that is served as one
repository at `https://<host>/<group>/deb`, `/rpm` and `/arch/$arch`. Users then add a
single source and get packages from all of them (see [Groups](#groups)).

## How it works

1. The first time a repository is requested, omnirelease lists its recent releases
   through the GitHub API and finds every `.deb`, `.rpm` (excluding `.src.rpm`) and
   `.pkg.tar.{zst,xz,gz}` asset.
2. For each new asset it streams the start of the file and parses the package header
   (`control` for Debian, the RPM header, `.PKGINFO` for Arch). GitHub publishes a
   SHA-256 digest for assets, so the download usually stops after a few KiB. For older
   assets without a digest, the file is streamed through once to hash it. Results are
   cached on disk by asset ID, so each asset is inspected at most once.
3. It generates the repository metadata in memory: APT `Release`/`InRelease`/`Packages`,
   RPM `repodata/` (`repomd.xml`, `primary`, `filelists`, `other`), and a pacman `.db`.
   If you provide an OpenPGP key, the metadata is signed with it.
4. Package downloads are answered with a **redirect** to GitHub's CDN by default, so
   the proxy uses almost no bandwidth. Set `download_mode = "proxy"` to stream them
   through the server instead.
5. Indexes refresh in the background every `refresh_interval` (15 minutes by default).
   Refreshes use conditional (`ETag`) requests, which don't count against GitHub's rate
   limit when nothing has changed.

Nothing is stored except a few KiB of parsed metadata per package. There is no database
and no upload step.

## Quick start (Docker)

```sh
git clone <this repo> omnirelease && cd omnirelease
docker build -t omnirelease .

# 1. Generate a signing key into a named volume (once).
docker run --rm -v omnirelease-keys:/etc/omnirelease omnirelease \
  keygen --out /etc/omnirelease/signing-key.asc

# 2. Run the server.
docker run -d --name omnirelease -p 8080:8080 \
  -v omnirelease-keys:/etc/omnirelease \
  -v omnirelease-cache:/var/cache/omnirelease \
  -e OMNIRELEASE_SIGNING_KEY_FILE=/etc/omnirelease/signing-key.asc \
  -e OMNIRELEASE_REPOSITORIES="cli/cli,sharkdp/bat" \
  -e OMNIRELEASE_BASE_URL="https://pkg.example.com" \
  omnirelease
```

Open `http://localhost:8080/sharkdp/bat/` to see copy-paste setup commands for that
repository.

Or with Docker Compose (edit `docker-compose.yml` first):

```sh
docker compose run --rm omnirelease keygen --out /etc/omnirelease/signing-key.asc
docker compose up -d
```

The image is built on `gcr.io/distroless/cc-debian12:nonroot`, is about 35 MB, and runs
as UID 65532. If you bind-mount a key file from the host instead of using the named
volume, make sure that UID can read it (for example `sudo chown 65532:65532 signing-key.asc`).

> Back up the signing key. If you lose it, every client has to re-import a new one. To
> copy it out of the volume: `docker cp omnirelease:/etc/omnirelease/signing-key.asc .`

## Building and running from source

You need a recent stable Rust toolchain (install it from https://rustup.rs) and a C
compiler (for the bundled zstd/liblzma).

```sh
cargo build --release
./target/release/omnirelease keygen --out signing-key.asc   # optional, but recommended
cp config.example.toml config.toml                          # then edit it
./target/release/omnirelease --config config.toml
```

Or configure it entirely with flags or environment variables:

```sh
./target/release/omnirelease \
  --repositories cli/cli,sharkdp/bat \
  --signing-key-file signing-key.asc \
  --listen 0.0.0.0:8080
```

Run the tests with `cargo test`.

## Configuration

Settings are read from a TOML file (`--config`, or `OMNIRELEASE_CONFIG`), and then
overridden by command-line flags or environment variables. All options are documented in
[`config.example.toml`](config.example.toml).

| Setting               | Flag / environment variable                                      | Default                  |
| --------------------- | ---------------------------------------------------------------- | ------------------------ |
| `repositories`        | `--repositories` / `OMNIRELEASE_REPOSITORIES` (comma-separated)  | *(none: serve nothing)*  |
| `listen`              | `--listen` / `OMNIRELEASE_LISTEN`                                | `0.0.0.0:8080`           |
| `base_url`            | `--base-url` / `OMNIRELEASE_BASE_URL`                            | from `Host` headers      |
| `cache_dir`           | `--cache-dir` / `OMNIRELEASE_CACHE_DIR`                          | `./cache`                |
| `github_token`        | `--github-token` / `GITHUB_TOKEN`                                | *(anonymous)*            |
| `refresh_interval`    | `--refresh-interval` / `OMNIRELEASE_REFRESH_INTERVAL`            | `15m`                    |
| `max_releases`        | `--max-releases` / `OMNIRELEASE_MAX_RELEASES`                    | `10`                     |
| `include_prereleases` | `--include-prereleases` / `OMNIRELEASE_INCLUDE_PRERELEASES`      | `false`                  |
| `download_mode`       | `--download-mode` / `OMNIRELEASE_DOWNLOAD_MODE`                  | `redirect`               |
| `signing.key_file`    | `--signing-key-file` / `OMNIRELEASE_SIGNING_KEY_FILE`            | *(unsigned)*             |
| `signing.passphrase`  | `--signing-key-passphrase` / `OMNIRELEASE_SIGNING_KEY_PASSPHRASE`| *(none)*                 |
| `groups`              | `--group` (repeatable) / `OMNIRELEASE_GROUPS` (`;`-separated)    | *(none)*                 |
| `redis.url`           | `--redis-url` / `OMNIRELEASE_REDIS_URL`                          | *(memory and disk)*      |
| `redis.prefix`        | `--redis-prefix` / `OMNIRELEASE_REDIS_PREFIX`                    | `omnirelease:`           |
| `redis.ttl`           | `--redis-ttl` / `OMNIRELEASE_REDIS_TTL`                          | `30d`                    |

**Repository patterns.** `owner/repo` allows a single repository, `owner/*` allows every
repository of a user or organization, and `*/*` turns the server into an open proxy for
any public repository. Matching is case-insensitive. Requests for anything else get
`403`.

### Groups

A group serves several GitHub repositories as **one** repository, so users need a single
apt line, `.repo` file or pacman section for all of them. For example, an organization
that ships `acme-apps` and `acme-core` from separate repositories:

```toml
[groups.acme]
repositories = ["acme/acme-apps", "acme/acme-core"]
```

Or the same thing as a flag or environment variable. Separate several groups with `;`:

```sh
omnirelease --group acme=acme/acme-apps,acme/acme-core
OMNIRELEASE_GROUPS="acme=acme/acme-apps,acme/acme-core;tools=sharkdp/bat,cli/cli"
```

The group is then served at `https://<host>/acme/deb`, `/acme/rpm` and
`/acme/arch/$arch`, and its setup page is `https://<host>/acme/`.

- Members are exact `owner/repo` names; wildcards are not allowed. Members don't need
  to be listed in `repositories`; that setting only controls access to each repository's
  own `/<owner>/<repo>/` URL.
- A group is assembled from its members' indexes, so it costs no extra GitHub requests.
  It updates whenever any member refreshes. If a member can't be fetched, the group is
  served without it and a warning is logged.
- Download paths are namespaced by the source repository
  (`pool/acme/acme-core/v1.2.0/…`), so identical tags in different repositories don't
  collide.
- If two members publish a package with the same name, apt and dnf list every version
  and install the highest. pacman lists only the highest version. On equal versions,
  the member listed first wins.
- The group name takes the first path segment, so a group called `acme` takes priority
  over the repositories `acme/deb`, `acme/rpm` and `acme/arch`. Allowing one of those
  repositories explicitly alongside the group is a configuration error.

**GitHub token.** Anonymous API access is limited to 60 requests per hour per IP. That's
enough for a handful of repositories, because unchanged refreshes are free. For more,
set `GITHUB_TOKEN`; a fine-grained token with no extra permissions is enough for public
repositories.

**Logging.** Set `RUST_LOG`, for example `RUST_LOG=omnirelease=debug`.

### Redis cache (optional)

By default the GitHub release lists (and their ETags) are kept in memory and parsed
package metadata is written to `cache_dir`. Each repository's index is rebuilt after a
restart, which costs one GitHub API call per repository but no package downloads.

Set `redis.url` to keep all of it in Redis (or a compatible server such as Valkey)
instead:

```sh
omnirelease --redis-url redis://:password@localhost:6379/0 --repositories cli/cli serve
```

Three kinds of key are stored, all under `redis.prefix`. Each value is zstd-compressed
JSON, and expires after `redis.ttl`. The expiry is renewed whenever a value changes.

| Key                         | Contents                                                     |
| --------------------------- | ------------------------------------------------------------ |
| `v1:releases:<owner>/<repo>` | The last release list fetched from GitHub, with its ETag     |
| `v1:repo:<owner>/<repo>`     | The indexed packages built from that list                    |
| `v1:asset:<id>-<hash>`       | The parsed metadata of one package file (or why it failed)   |

This gives you:

- **Instant restarts.** Repositories are served from Redis straight away, and are then
  checked against GitHub in the background.
- **Replicas.** Several instances behind a load balancer share release lists, ETags and
  parsed packages, so each package file is inspected once in total, not once per
  instance. A shared ETag also lets most refreshes end in a free `304`.
- **No disk state.** `cache_dir` is not used.

omnirelease refuses to start if it cannot reach Redis, so a mistyped URL is noticed.
After startup Redis is treated as a cache only. If it becomes unavailable, requests are
still answered from memory and errors are logged. Package files are inspected again while
Redis is down, and the client reconnects when it is back. Use `rediss://` for TLS.

### Signing keys

`omnirelease keygen` creates an Ed25519 OpenPGP key. It writes the secret key (mode 0600)
and a `.pub.asc` copy of the public key. You can also bring your own key, for example from
GnuPG:

```sh
gpg --quick-gen-key "My Repo Signing Key" ed25519 sign never
gpg --armor --export-secret-keys "My Repo Signing Key" > signing-key.asc
```

When a key has a signing-capable subkey, that subkey is used; otherwise the primary
key is used. The public key is published at `/key.asc` (armored) and `/key.gpg`
(binary).

Without a key, the server still works, but clients must be told to trust it blindly
(`[trusted=yes]` for apt, `repo_gpgcheck=0` for dnf, `SigLevel = Optional TrustAll` for
pacman). Use that only for testing or a trusted network.

Note that omnirelease signs the **repository metadata**, and the metadata pins each
package's SHA-256. It does not re-sign the packages themselves. Packages that upstream
signed (RPM signatures, Arch `.sig` files published next to the package) are passed
through unchanged.

## Client setup

Every repository has a setup page at `https://<host>/<owner>/<repo>/` with commands that
already contain the right URLs. The examples below use `pkg.example.com` and
`sharkdp/bat`.

### apt (Debian, Ubuntu, Mint, …)

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://pkg.example.com/key.asc | sudo tee /etc/apt/keyrings/omnirelease.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/omnirelease.asc] https://pkg.example.com/sharkdp/bat/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/sharkdp-bat.list
sudo apt update && sudo apt install bat
```

Any distribution name works in place of `stable`, and the only component is `main`.
Packages built for `Architecture: all` appear for every architecture.

### dnf / yum (Fedora, RHEL, Rocky, Alma, …)

```sh
sudo curl -fsSL -o /etc/yum.repos.d/sharkdp-bat.repo \
  https://pkg.example.com/sharkdp/bat/rpm/sharkdp-bat.repo
sudo dnf install bat
```

The generated `.repo` file sets `repo_gpgcheck=1` (metadata is verified against
`/key.asc`) and `gpgcheck=0`, since most upstream RPMs on GitHub are unsigned. If the
project signs its RPMs, change it to `gpgcheck=1` and add the project's key to
`gpgkey=`.

### zypper (openSUSE, SLES)

```sh
sudo zypper addrepo https://pkg.example.com/sharkdp/bat/rpm/sharkdp-bat.repo
sudo zypper refresh && sudo zypper install bat
```

### pacman (Arch Linux, Manjaro, EndeavourOS, …)

```sh
curl -fsSL https://pkg.example.com/key.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key <fingerprint shown on the setup page>
```

Then add the repository to `/etc/pacman.conf`:

```ini
[bat]
SigLevel = PackageOptional DatabaseRequired TrustedOnly
Server = https://pkg.example.com/sharkdp/bat/arch/$arch
```

Then run `sudo pacman -Sy bat`. The section name (`[bat]`) is up to you, because the
database is served under any name. If an official repository ships a package with the
same name, install from this one explicitly, for example `pacman -S bat/bat`.

## HTTP endpoints

| Path                                      | Description                                        |
| ----------------------------------------- | -------------------------------------------------- |
| `/`                                       | Server info and allowed repositories               |
| `/healthz`                                | Liveness check (returns `ok`)                      |
| `/key.asc`, `/key.gpg`                    | Public signing key (armored / binary)              |
| `/<owner>/<repo>/`                        | Setup instructions for a repository                |
| `/<owner>/<repo>/deb/dists/<dist>/…`      | APT `Release`, `InRelease`, `Release.gpg`, `Packages[.gz]` |
| `/<owner>/<repo>/deb/pool/<tag>/<file>`   | `.deb` download (redirect or proxy)                |
| `/<owner>/<repo>/rpm/repodata/…`          | `repomd.xml`, `repomd.xml.asc`, metadata files     |
| `/<owner>/<repo>/rpm/packages/<tag>/<file>` | `.rpm` download                                  |
| `/<owner>/<repo>/rpm/<owner>-<repo>.repo` | Ready-made `.repo` file                            |
| `/<owner>/<repo>/arch/<arch>/<name>.db`   | pacman database (also `.db.sig`, `.files`)         |
| `/<owner>/<repo>/arch/<arch>/<file>`      | Arch package (and upstream `.sig`) download        |
| `/<group>/`, `/<group>/{deb,rpm,arch}/…`  | The same as above, for a group of repositories     |

## Deployment notes

- **TLS.** omnirelease serves plain HTTP. Put it behind a reverse proxy (Caddy, nginx,
  Traefik, a cloud load balancer) for HTTPS, and either set `base_url` or forward the
  `Host`, `X-Forwarded-Host` and `X-Forwarded-Proto` headers.
- **Caching.** Metadata responses carry `Cache-Control: max-age=60`, so a CDN in front of
  the server works well.
- **State.** The only state is the metadata cache in `cache_dir`, or in Redis when
  configured (see [Redis cache](#redis-cache-optional)). Either is safe to delete, and is
  rebuilt on demand.
- **Many releases.** By default the 10 newest non-draft, non-pre-release releases are
  indexed (`max_releases`). apt and dnf see every version, so users can pin or downgrade.
  pacman sees the newest version of each package.

## Limitations

- Only public repositories are supported. Private repositories would need
  token-authenticated asset downloads on every client request.
- Only binary packages are indexed. Source packages (`.dsc`, `.src.rpm`), `.apk` and
  Flatpak bundles are ignored.
- RPM changelogs are not included in `other.xml`, and the pacman `.files` database
  contains no file lists, so `pacman -F` finds nothing.
- One flat APT component (`main`) per GitHub repository, with no per-distribution
  package selection. If a project publishes separate `.deb` files per distribution
  release, all of them are listed.

## License

omnirelease is dedicated to the public domain under
[CC0 1.0 Universal](LICENSE). You can copy, modify, distribute and use the work, even
commercially, without asking permission.
