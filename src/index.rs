//! Builds repository metadata for APT, RPM (dnf/yum/zypper) and pacman from a list of
//! packages, and resolves request paths against it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Mutex;

use anyhow::Result;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};

use crate::pkg::{ArchMeta, DebMeta, Meta, Package, RpmDep, RpmMeta};
use crate::signing::Signer;

/// Architectures advertised for APT when only `Architecture: all` packages exist.
const DEFAULT_DEB_ARCHS: &[&str] = &["amd64", "arm64", "armhf", "i386"];

pub enum Resolved {
    File {
        body: Bytes,
        content_type: &'static str,
    },
    Download {
        url: String,
        filename: String,
    },
}

/// Fully-built repository metadata for one GitHub repository or a group of them.
pub struct Snapshot {
    /// `owner/repo`, or the group name.
    pub label: String,
    pub built: DateTime<Utc>,
    pub packages: Vec<Package>,
    /// Upstream Arch `.sig` files: (file name, asset URL).
    pub arch_sigs: Vec<(String, String)>,
    origin: String,
    /// Static files keyed by path relative to `/{owner}/{repo}/`.
    files: HashMap<String, (Bytes, &'static str)>,
    /// Download paths (relative to `/{owner}/{repo}/`) -> GitHub asset URL.
    downloads: HashMap<String, String>,
    /// Arch package file name -> asset URL (pacman fetches `Server/<filename>`).
    arch_files: HashMap<String, String>,
    deb_archs: Vec<String>,
    deb_index_sums: Vec<(String, u64, String)>,
    /// Lazily-built, signed, per-request-shape files (APT Release per dist, pacman db per arch).
    memo: Mutex<HashMap<String, (Bytes, &'static str)>>,
}

impl Snapshot {
    pub fn build(
        label: &str,
        origin: &str,
        packages: Vec<Package>,
        arch_sigs: Vec<(String, String)>,
    ) -> Result<Self> {
        let mut s = Snapshot {
            label: label.into(),
            built: Utc::now(),
            packages,
            arch_sigs,
            origin: origin.into(),
            files: HashMap::new(),
            downloads: HashMap::new(),
            arch_files: HashMap::new(),
            deb_archs: Vec::new(),
            deb_index_sums: Vec::new(),
            memo: Mutex::new(HashMap::new()),
        };
        s.build_deb();
        s.build_rpm()?;
        for p in &s.packages {
            if let Meta::Arch(_) = p.meta {
                s.arch_files
                    .entry(p.filename.clone())
                    .or_insert_with(|| p.download_url.clone());
            }
        }
        for (name, url) in &s.arch_sigs {
            s.arch_files
                .entry(name.clone())
                .or_insert_with(|| url.clone());
        }
        Ok(s)
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for p in &self.packages {
            match p.meta {
                Meta::Deb(_) => c.0 += 1,
                Meta::Rpm(_) => c.1 += 1,
                Meta::Arch(_) => c.2 += 1,
            }
        }
        c
    }

    pub fn resolve(&self, path: &str, signer: Option<&Signer>) -> Result<Option<Resolved>> {
        let path = path.trim_start_matches('/');
        if let Some((body, ct)) = self.files.get(path) {
            return Ok(Some(Resolved::File {
                body: body.clone(),
                content_type: ct,
            }));
        }
        if let Some(url) = self.downloads.get(path) {
            let filename = path.rsplit('/').next().unwrap_or(path).to_string();
            return Ok(Some(Resolved::Download {
                url: url.clone(),
                filename,
            }));
        }
        if let Some((body, ct)) = self.memo.lock().unwrap().get(path) {
            return Ok(Some(Resolved::File {
                body: body.clone(),
                content_type: ct,
            }));
        }

        let parts: Vec<&str> = path.split('/').collect();
        let generated = match parts.as_slice() {
            // APT: deb/dists/<dist>/{Release,InRelease,Release.gpg}
            ["deb", "dists", dist, file] if valid_name(dist) => {
                let release = self.deb_release(dist);
                match *file {
                    "Release" => Some((Bytes::from(release), "text/plain; charset=utf-8")),
                    "InRelease" => match signer {
                        Some(s) => Some((
                            Bytes::from(s.clearsign(&release)?),
                            "text/plain; charset=utf-8",
                        )),
                        None => None,
                    },
                    "Release.gpg" => match signer {
                        Some(s) => Some((
                            Bytes::from(s.detached_armored(release.as_bytes())?),
                            "application/pgp-signature",
                        )),
                        None => None,
                    },
                    _ => None,
                }
            }
            // APT: deb/dists/<dist>/main/binary-<arch>/Packages[.gz] (dist independent)
            ["deb", "dists", dist, "main", bin, file] if valid_name(dist) => {
                return Ok(self
                    .files
                    .get(&format!("deb/main/{bin}/{file}"))
                    .map(|(b, ct)| Resolved::File {
                        body: b.clone(),
                        content_type: ct,
                    }));
            }
            // pacman: arch/<arch>/<repo>.db[.tar.gz][.sig] | .files[...] | <package file>
            ["arch", arch, file] if valid_name(arch) => {
                if let Some(url) = self.arch_files.get(*file) {
                    return Ok(Some(Resolved::Download {
                        url: url.clone(),
                        filename: file.to_string(),
                    }));
                }
                let (base, sig) = match file.strip_suffix(".sig") {
                    Some(b) => (b, true),
                    None => (*file, false),
                };
                let is_db = [".db", ".db.tar.gz", ".files", ".files.tar.gz"]
                    .iter()
                    .any(|ext| {
                        base.strip_suffix(ext)
                            .is_some_and(|name| !name.is_empty() && valid_name(name))
                    });
                if !is_db {
                    None
                } else {
                    let db = self.pacman_db(arch)?;
                    if sig {
                        match signer {
                            Some(s) => Some((
                                Bytes::from(s.detached_binary(&db)?),
                                "application/pgp-signature",
                            )),
                            None => None,
                        }
                    } else {
                        Some((Bytes::from(db), "application/gzip"))
                    }
                }
            }
            _ => None,
        };

        Ok(generated.map(|(body, ct)| {
            let mut memo = self.memo.lock().unwrap();
            if memo.len() < 256 {
                memo.insert(path.to_string(), (body.clone(), ct));
            }
            Resolved::File {
                body,
                content_type: ct,
            }
        }))
    }

    // -----------------------------------------------------------------------------------
    // APT
    // -----------------------------------------------------------------------------------

    fn build_deb(&mut self) {
        let debs: Vec<(&Package, &DebMeta)> = self
            .packages
            .iter()
            .filter_map(|p| match &p.meta {
                Meta::Deb(d) => Some((p, d)),
                _ => None,
            })
            .collect();

        let mut archs: BTreeSet<String> = debs
            .iter()
            .map(|(_, d)| d.architecture().to_string())
            .filter(|a| a != "all")
            .collect();
        if archs.is_empty() || debs.iter().any(|(_, d)| d.architecture() == "all") {
            archs.extend(DEFAULT_DEB_ARCHS.iter().map(|s| s.to_string()));
        }

        let mut files = Vec::new();
        for arch in &archs {
            let mut out = String::new();
            for (p, d) in debs
                .iter()
                .filter(|(_, d)| d.architecture() == arch || d.architecture() == "all")
            {
                let pool = format!("pool/{}/{}", p.pool_dir(), p.filename);
                out.push_str(&deb_paragraph(p, d, &pool));
                out.push('\n');
            }
            let plain = Bytes::from(out);
            let gz = Bytes::from(gzip(&plain));
            files.push((format!("main/binary-{arch}/Packages"), plain));
            files.push((format!("main/binary-{arch}/Packages.gz"), gz));
        }

        for (rel, body) in files {
            self.deb_index_sums
                .push((sha256_hex(&body), body.len() as u64, rel.clone()));
            let ct = if rel.ends_with(".gz") {
                "application/gzip"
            } else {
                "text/plain; charset=utf-8"
            };
            self.files.insert(format!("deb/{rel}"), (body, ct));
        }
        for (p, _) in &debs {
            self.downloads.insert(
                format!("deb/pool/{}/{}", p.pool_dir(), p.filename),
                p.download_url.clone(),
            );
        }
        self.deb_archs = archs.into_iter().collect();
    }

    fn deb_release(&self, dist: &str) -> String {
        let mut r = String::new();
        let _ = writeln!(r, "Origin: {}", self.origin);
        let _ = writeln!(r, "Label: {}", self.label);
        let _ = writeln!(r, "Suite: {dist}");
        let _ = writeln!(r, "Codename: {dist}");
        let _ = writeln!(
            r,
            "Date: {}",
            self.built.format("%a, %d %b %Y %H:%M:%S UTC")
        );
        let _ = writeln!(r, "Architectures: {}", self.deb_archs.join(" "));
        let _ = writeln!(r, "Components: main");
        let _ = writeln!(
            r,
            "Description: GitHub releases of {} served by omnirelease",
            self.label
        );
        let _ = writeln!(r, "SHA256:");
        for (sum, size, path) in &self.deb_index_sums {
            let _ = writeln!(r, " {sum} {size:>16} {path}");
        }
        r
    }

    // -----------------------------------------------------------------------------------
    // RPM (repodata)
    // -----------------------------------------------------------------------------------

    fn build_rpm(&mut self) -> Result<()> {
        let rpms: Vec<(&Package, &RpmMeta)> = self
            .packages
            .iter()
            .filter_map(|p| match &p.meta {
                Meta::Rpm(r) => Some((p, r)),
                _ => None,
            })
            .collect();

        let n = rpms.len();
        let mut primary = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{n}\">\n"
        );
        let mut filelists = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"{n}\">\n"
        );
        let mut other = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"{n}\">\n"
        );

        for (p, r) in &rpms {
            let href = format!("packages/{}/{}", p.pool_dir(), p.filename);
            self.downloads
                .insert(format!("rpm/{href}"), p.download_url.clone());
            let version = format!(
                "<version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>",
                r.epoch,
                esc(&r.version),
                esc(&r.release)
            );
            let id = format!(
                "pkgid=\"{}\" name=\"{}\" arch=\"{}\"",
                p.sha256,
                esc(&r.name),
                esc(&r.arch)
            );

            let _ = write!(
                primary,
                "<package type=\"rpm\">\n  <name>{}</name>\n  <arch>{}</arch>\n  {version}\n  <checksum type=\"sha256\" pkgid=\"YES\">{}</checksum>\n  <summary>{}</summary>\n  <description>{}</description>\n  <packager>{}</packager>\n  <url>{}</url>\n  <time file=\"{}\" build=\"{}\"/>\n  <size package=\"{}\" installed=\"{}\" archive=\"{}\"/>\n  <location href=\"{}\"/>\n  <format>\n    <rpm:license>{}</rpm:license>\n    <rpm:vendor>{}</rpm:vendor>\n    <rpm:group>{}</rpm:group>\n    <rpm:buildhost>{}</rpm:buildhost>\n    <rpm:sourcerpm>{}</rpm:sourcerpm>\n    <rpm:header-range start=\"{}\" end=\"{}\"/>\n",
                esc(&r.name),
                esc(&r.arch),
                p.sha256,
                esc(&r.summary),
                esc(&r.description),
                esc(&r.packager),
                esc(&r.url),
                r.build_time,
                r.build_time,
                p.size,
                r.installed_size,
                r.installed_size,
                esc(&href),
                esc(&r.license),
                esc(&r.vendor),
                esc(&r.group),
                esc(&r.buildhost),
                esc(&r.sourcerpm),
                r.header_start,
                r.header_end,
            );
            for (tag, deps) in [
                ("provides", &r.provides),
                ("requires", &r.requires),
                ("conflicts", &r.conflicts),
                ("obsoletes", &r.obsoletes),
                ("recommends", &r.recommends),
                ("suggests", &r.suggests),
                ("enhances", &r.enhances),
                ("supplements", &r.supplements),
            ] {
                write_deps(&mut primary, tag, deps, tag == "requires");
            }
            for f in r.files.iter().filter(|f| is_primary_file(&f.path)) {
                primary.push_str(&file_xml("    ", f));
            }
            primary.push_str("  </format>\n</package>\n");

            let _ = writeln!(filelists, "<package {id}>\n  {version}");
            for f in &r.files {
                filelists.push_str(&file_xml("  ", f));
            }
            filelists.push_str("</package>\n");

            let _ = writeln!(other, "<package {id}>\n  {version}\n</package>");
        }
        primary.push_str("</metadata>\n");
        filelists.push_str("</filelists>\n");
        other.push_str("</otherdata>\n");

        let ts = self.built.timestamp();
        let mut repomd = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n  <revision>{ts}</revision>\n"
        );
        for (kind, xml) in [
            ("primary", primary),
            ("filelists", filelists),
            ("other", other),
        ] {
            let open_sum = sha256_hex(xml.as_bytes());
            let gz = gzip(xml.as_bytes());
            let sum = sha256_hex(&gz);
            let href = format!("repodata/{sum}-{kind}.xml.gz");
            let _ = write!(
                repomd,
                "  <data type=\"{kind}\">\n    <checksum type=\"sha256\">{sum}</checksum>\n    <open-checksum type=\"sha256\">{open_sum}</open-checksum>\n    <location href=\"{href}\"/>\n    <timestamp>{ts}</timestamp>\n    <size>{}</size>\n    <open-size>{}</open-size>\n  </data>\n",
                gz.len(),
                xml.len()
            );
            self.files
                .insert(format!("rpm/{href}"), (Bytes::from(gz), "application/gzip"));
        }
        repomd.push_str("</repomd>\n");
        self.files.insert(
            "rpm/repodata/repomd.xml".into(),
            (Bytes::from(repomd), "text/xml; charset=utf-8"),
        );
        Ok(())
    }

    /// Finalize signed files that do not depend on the request (needs the signer).
    pub fn sign_static(&mut self, signer: &Signer) -> Result<()> {
        let repomd = self.files["rpm/repodata/repomd.xml"].0.clone();
        let sig = signer.detached_armored(&repomd)?;
        self.files.insert(
            "rpm/repodata/repomd.xml.asc".into(),
            (Bytes::from(sig), "application/pgp-signature"),
        );
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // pacman
    // -----------------------------------------------------------------------------------

    fn pacman_db(&self, arch: &str) -> Result<Vec<u8>> {
        // A pacman database holds one entry per package name: keep the highest version.
        // On a tie the earlier package wins (newer release, or earlier group member).
        let mut newest: BTreeMap<&str, (&Package, &ArchMeta)> = BTreeMap::new();
        for p in &self.packages {
            let Meta::Arch(a) = &p.meta else { continue };
            if a.arch() != arch && a.arch() != "any" {
                continue;
            }
            let name = a.get("pkgname").unwrap_or_default();
            let ver = a.get("pkgver").unwrap_or_default();
            match newest.get(name) {
                Some((_, cur))
                    if rpm_version::rpm_evr_compare(ver, cur.get("pkgver").unwrap_or_default())
                        != std::cmp::Ordering::Greater => {}
                _ => {
                    newest.insert(name, (p, a));
                }
            }
        }

        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mtime = self.built.timestamp().max(0) as u64;
        for (name, (p, a)) in newest {
            let dir = format!("{}-{}", name, a.get("pkgver").unwrap_or_default());
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o755);
            h.set_mtime(mtime);
            h.set_size(0);
            tar.append_data(&mut h, format!("{dir}/"), std::io::empty())?;

            let desc = pacman_desc(p, a);
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_mtime(mtime);
            h.set_size(desc.len() as u64);
            tar.append_data(&mut h, format!("{dir}/desc"), desc.as_bytes())?;
        }
        Ok(tar.into_inner()?.finish()?)
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+~".contains(c))
}

fn deb_paragraph(p: &Package, d: &DebMeta, pool: &str) -> String {
    const SKIP: &[&str] = &[
        "filename",
        "size",
        "md5sum",
        "sha1",
        "sha256",
        "sha512",
        "description",
    ];
    let mut out = String::new();
    for (k, v) in &d.fields {
        if !SKIP.contains(&k.to_ascii_lowercase().as_str()) {
            let _ = writeln!(out, "{k}: {v}");
        }
    }
    let _ = writeln!(out, "Filename: {pool}");
    let _ = writeln!(out, "Size: {}", p.size);
    let _ = writeln!(out, "SHA256: {}", p.sha256);
    if let Some(desc) = d.get("Description") {
        let _ = writeln!(out, "Description: {desc}");
    }
    out
}

fn pacman_desc(p: &Package, a: &ArchMeta) -> String {
    let mut out = String::new();
    let mut section = |key: &str, values: Vec<&str>| {
        let values: Vec<&str> = values.into_iter().filter(|v| !v.is_empty()).collect();
        if !values.is_empty() {
            let _ = write!(out, "%{key}%\n{}\n\n", values.join("\n"));
        }
    };
    let size = p.size.to_string();
    section("FILENAME", vec![&p.filename]);
    section("NAME", a.all("pkgname"));
    section("BASE", a.all("pkgbase"));
    section("VERSION", a.all("pkgver"));
    section("DESC", a.all("pkgdesc"));
    section("GROUPS", a.all("group"));
    section("CSIZE", vec![&size]);
    section("ISIZE", a.all("size"));
    section("SHA256SUM", vec![&p.sha256]);
    section("PGPSIG", a.pgpsig.as_deref().into_iter().collect());
    section("URL", a.all("url"));
    section("LICENSE", a.all("license"));
    section("ARCH", a.all("arch"));
    section("BUILDDATE", a.all("builddate"));
    section("PACKAGER", a.all("packager"));
    section("REPLACES", a.all("replaces"));
    section("CONFLICTS", a.all("conflict"));
    section("PROVIDES", a.all("provides"));
    section("DEPENDS", a.all("depend"));
    section("OPTDEPENDS", a.all("optdepend"));
    section("MAKEDEPENDS", a.all("makedepend"));
    section("CHECKDEPENDS", a.all("checkdepend"));
    out
}

fn write_deps(out: &mut String, tag: &str, deps: &[RpmDep], allow_pre: bool) {
    if deps.is_empty() {
        return;
    }
    let _ = writeln!(out, "    <rpm:{tag}>");
    for d in deps {
        let mut attrs = format!("name=\"{}\"", esc(&d.name));
        if !d.flags.is_empty() {
            let _ = write!(attrs, " flags=\"{}\"", d.flags);
            if let Some(e) = &d.epoch {
                let _ = write!(attrs, " epoch=\"{}\"", esc(e));
            }
            if let Some(v) = &d.ver {
                let _ = write!(attrs, " ver=\"{}\"", esc(v));
            }
            if let Some(r) = &d.rel {
                let _ = write!(attrs, " rel=\"{}\"", esc(r));
            }
        }
        if allow_pre && d.pre {
            attrs.push_str(" pre=\"1\"");
        }
        let _ = writeln!(out, "      <rpm:entry {attrs}/>");
    }
    let _ = writeln!(out, "    </rpm:{tag}>");
}

fn file_xml(indent: &str, f: &crate::pkg::RpmFile) -> String {
    if f.kind.is_empty() {
        format!("{indent}<file>{}</file>\n", esc(&f.path))
    } else {
        format!(
            "{indent}<file type=\"{}\">{}</file>\n",
            f.kind,
            esc(&f.path)
        )
    }
}

/// createrepo only lists "important" files in primary.xml (the rest go to filelists.xml).
fn is_primary_file(path: &str) -> bool {
    path.starts_with("/etc/") || path.contains("bin/") || path == "/usr/lib/sendmail"
}

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters are not allowed in XML 1.0.
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\r' | '\t') => {}
            c => out.push(c),
        }
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).expect("writing to Vec cannot fail");
    enc.finish().expect("writing to Vec cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::ArchMeta;

    fn deb(src: Option<&str>, tag: &str, name: &str, ver: &str) -> Package {
        Package {
            tag: tag.into(),
            filename: format!("{name}_{ver}_amd64.deb"),
            download_url: format!("https://example.invalid/{name}/{ver}.deb"),
            size: 10,
            sha256: "0".repeat(64),
            meta: Meta::Deb(DebMeta {
                fields: vec![
                    ("Package".into(), name.into()),
                    ("Version".into(), ver.into()),
                    ("Architecture".into(), "amd64".into()),
                ],
            }),
            source: src.map(str::to_string),
        }
    }

    fn arch(src: &str, tag: &str, name: &str, ver: &str) -> Package {
        Package {
            tag: tag.into(),
            filename: format!("{name}-{ver}-x86_64.pkg.tar.zst"),
            download_url: format!("https://example.invalid/{src}/{name}-{ver}"),
            size: 10,
            sha256: "0".repeat(64),
            meta: Meta::Arch(ArchMeta {
                info: vec![
                    ("pkgname".into(), name.into()),
                    ("pkgver".into(), ver.into()),
                    ("arch".into(), "x86_64".into()),
                ],
                pgpsig: None,
            }),
            source: Some(src.into()),
        }
    }

    fn body(s: &Snapshot, path: &str) -> String {
        match s.resolve(path, None).unwrap() {
            Some(Resolved::File { body, .. }) => String::from_utf8_lossy(&body).into_owned(),
            _ => panic!("{path} is not a file"),
        }
    }

    #[test]
    fn single_repo_paths_are_not_namespaced() {
        let s =
            Snapshot::build("o/r", "test", vec![deb(None, "v1", "app", "1.0")], vec![]).unwrap();
        assert!(
            body(&s, "deb/dists/stable/main/binary-amd64/Packages")
                .contains("Filename: pool/v1/app_1.0_amd64.deb")
        );
        assert!(matches!(
            s.resolve("deb/pool/v1/app_1.0_amd64.deb", None).unwrap(),
            Some(Resolved::Download { .. })
        ));
    }

    #[test]
    fn group_paths_are_namespaced_by_source() {
        // Two repos with the same tag must not collide.
        let s = Snapshot::build(
            "acme",
            "test",
            vec![
                deb(Some("acme/apps"), "v1", "app", "1.0"),
                deb(Some("acme/core"), "v1", "core", "1.0"),
            ],
            vec![],
        )
        .unwrap();
        let pk = body(&s, "deb/dists/stable/main/binary-amd64/Packages");
        assert!(pk.contains("Filename: pool/acme/apps/v1/app_1.0_amd64.deb"));
        assert!(pk.contains("Filename: pool/acme/core/v1/core_1.0_amd64.deb"));
        match s
            .resolve("deb/pool/acme/core/v1/core_1.0_amd64.deb", None)
            .unwrap()
        {
            Some(Resolved::Download { url, .. }) => assert!(url.contains("/core/")),
            _ => panic!("missing download"),
        }
        assert!(body(&s, "deb/dists/stable/Release").contains("Label: acme\n"));
    }

    #[test]
    fn pacman_db_keeps_highest_version() {
        let s = Snapshot::build(
            "acme",
            "test",
            vec![
                arch("acme/apps", "v1", "tool", "1.9-1"),
                arch("acme/core", "v2", "tool", "1.10-1"),
                arch("acme/core", "v2", "other", "2.0-1"),
            ],
            vec![],
        )
        .unwrap();
        let db = s.pacman_db("x86_64").unwrap();
        let mut names: Vec<String> = tar::Archive::new(flate2::read::GzDecoder::new(&db[..]))
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .filter(|p| p.ends_with("/desc"))
            .collect();
        names.sort();
        assert_eq!(names, vec!["other-2.0-1/desc", "tool-1.10-1/desc"]);
    }
}
