//! Package format detection and metadata extraction for .deb, .rpm and Arch packages.

use std::io::{BufRead, BufReader, Read};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Deb,
    Rpm,
    Arch,
}

impl Kind {
    /// Classify a release asset by file name. Returns `None` for anything that is not a
    /// binary package we know how to index.
    pub fn from_filename(name: &str) -> Option<Kind> {
        let n = name.to_ascii_lowercase();
        if n.ends_with(".deb") {
            Some(Kind::Deb)
        } else if n.ends_with(".rpm") && !n.ends_with(".src.rpm") {
            Some(Kind::Rpm)
        } else if [".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar"]
            .iter()
            .any(|s| n.ends_with(s))
        {
            Some(Kind::Arch)
        } else {
            None
        }
    }
}

/// Everything we need to know about one package to put it into any index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Release tag the asset belongs to.
    pub tag: String,
    /// Asset file name.
    pub filename: String,
    pub download_url: String,
    pub size: u64,
    pub sha256: String,
    pub meta: Meta,
    /// `owner/repo` the package came from, set only when it is served as part of a group
    /// (download paths are then namespaced by it). Never persisted.
    #[serde(skip)]
    pub source: Option<String>,
}

impl Package {
    /// Directory (relative to the format's pool) that the package is served from.
    pub fn pool_dir(&self) -> String {
        match &self.source {
            Some(src) => format!("{src}/{}", self.tag),
            None => self.tag.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Meta {
    Deb(DebMeta),
    Rpm(RpmMeta),
    Arch(ArchMeta),
}

// ---------------------------------------------------------------------------------------
// Debian
// ---------------------------------------------------------------------------------------

/// The fields of DEBIAN/control, in order. Multi-line values keep their continuation lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebMeta {
    pub fields: Vec<(String, String)>,
}

impl DebMeta {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
    pub fn architecture(&self) -> &str {
        self.get("Architecture").unwrap_or("all")
    }
}

// All parsers read only as far as they need to, so callers can stream a download and stop
// early. They take the reader by value; pass `&mut reader` to keep using it afterwards.

pub fn parse_deb(reader: impl Read) -> Result<DebMeta> {
    let mut archive = ar::Archive::new(reader);
    while let Some(entry) = archive.next_entry() {
        let entry = entry.context("reading ar member")?;
        let name = String::from_utf8_lossy(entry.header().identifier())
            .trim_end_matches('/')
            .to_string();
        if !name.starts_with("control.tar") {
            continue;
        }
        let reader: Box<dyn Read + '_> = match name.as_str() {
            "control.tar" => Box::new(entry),
            "control.tar.gz" => Box::new(flate2::read::GzDecoder::new(entry)),
            "control.tar.xz" => Box::new(xz2::read::XzDecoder::new(entry)),
            "control.tar.zst" => Box::new(zstd::stream::read::Decoder::new(entry)?),
            other => bail!("unsupported control archive {other}"),
        };
        let mut tar = tar::Archive::new(reader);
        for file in tar.entries()? {
            let mut file = file?;
            let p = file.path()?.to_string_lossy().to_string();
            if p.trim_start_matches("./") == "control" {
                let mut text = String::new();
                file.read_to_string(&mut text)?;
                let fields = parse_control(&text);
                if !fields
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("Package"))
                {
                    bail!("control file has no Package field");
                }
                return Ok(DebMeta { fields });
            }
        }
        bail!("no control file in {name}");
    }
    bail!("no control.tar member found; not a Debian package?")
}

/// Parse an RFC822-style Debian control paragraph.
pub fn parse_control(text: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !fields.is_empty() {
                break; // only the first paragraph
            }
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, v)) = fields.last_mut() {
                v.push('\n');
                v.push_str(line);
            }
        } else if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    fields
}

// ---------------------------------------------------------------------------------------
// RPM
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpmDep {
    pub name: String,
    /// One of EQ, LT, GT, LE, GE or empty.
    pub flags: String,
    pub epoch: Option<String>,
    pub ver: Option<String>,
    pub rel: Option<String>,
    pub pre: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpmFile {
    pub path: String,
    /// "", "dir" or "ghost" (createrepo's file types).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpmMeta {
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub summary: String,
    pub description: String,
    pub packager: String,
    pub url: String,
    pub license: String,
    pub vendor: String,
    pub group: String,
    pub buildhost: String,
    pub sourcerpm: String,
    pub build_time: u64,
    pub installed_size: u64,
    pub header_start: u64,
    pub header_end: u64,
    pub provides: Vec<RpmDep>,
    pub requires: Vec<RpmDep>,
    pub conflicts: Vec<RpmDep>,
    pub obsoletes: Vec<RpmDep>,
    pub recommends: Vec<RpmDep>,
    pub suggests: Vec<RpmDep>,
    pub enhances: Vec<RpmDep>,
    pub supplements: Vec<RpmDep>,
    pub files: Vec<RpmFile>,
}

pub fn parse_rpm(reader: impl Read) -> Result<RpmMeta> {
    let mut reader = BufReader::new(reader);
    let md =
        rpm::PackageMetadata::parse(&mut reader).map_err(|e| anyhow!("parsing RPM header: {e}"))?;
    let offsets = md.get_package_segment_offsets();
    let s = |r: Result<&str, rpm::Error>| r.unwrap_or_default().to_string();

    let deps = |r: Result<Vec<rpm::Dependency>, rpm::Error>, skip_rpmlib: bool| -> Vec<RpmDep> {
        r.unwrap_or_default()
            .into_iter()
            .filter(|d| !(skip_rpmlib && d.name.starts_with("rpmlib(")))
            .map(convert_dep)
            .collect()
    };

    let files = md
        .get_file_entries()
        .unwrap_or_default()
        .iter()
        .map(|f| RpmFile {
            path: f.path().to_string_lossy().to_string(),
            kind: if f.flags().contains(rpm::FileFlags::GHOST) {
                "ghost".into()
            } else if f.file_type() == rpm::FileType::Dir {
                "dir".into()
            } else {
                String::new()
            },
        })
        .collect();

    Ok(RpmMeta {
        name: s(md.get_name()),
        epoch: md.get_epoch().unwrap_or(0),
        version: s(md.get_version()),
        release: s(md.get_release()),
        arch: s(md.get_arch()),
        summary: s(md.get_summary()),
        description: s(md.get_description()),
        packager: s(md.get_packager()),
        url: s(md.get_url()),
        license: s(md.get_license()),
        vendor: s(md.get_vendor()),
        group: s(md.get_group()),
        buildhost: s(md.get_build_host()),
        sourcerpm: s(md.get_source_rpm()),
        build_time: md.get_build_time().unwrap_or(0),
        installed_size: md.get_installed_size().unwrap_or(0),
        header_start: offsets.header,
        header_end: offsets.payload,
        provides: deps(md.get_provides(), false),
        requires: deps(md.get_requires(), true),
        conflicts: deps(md.get_conflicts(), false),
        obsoletes: deps(md.get_obsoletes(), false),
        recommends: deps(md.get_recommends(), false),
        suggests: deps(md.get_suggests(), false),
        enhances: deps(md.get_enhances(), false),
        supplements: deps(md.get_supplements(), false),
        files,
    })
}

fn convert_dep(d: rpm::Dependency) -> RpmDep {
    use rpm::DependencyFlags as F;
    let flags = match d.flags & (F::LESS | F::GREATER | F::EQUAL) {
        F::LE => "LE",
        F::GE => "GE",
        F::LESS => "LT",
        F::GREATER => "GT",
        F::EQUAL => "EQ",
        _ => "",
    };
    let pre = d
        .flags
        .intersects(F::PREREQ | F::SCRIPT_PRE | F::SCRIPT_POST);
    let (epoch, ver, rel) = if d.version.is_empty() {
        (None, None, None)
    } else {
        split_evr(&d.version)
    };
    RpmDep {
        name: d.name,
        flags: flags.into(),
        epoch,
        ver,
        rel,
        pre,
    }
}

/// Split `[epoch:]version[-release]` into its parts.
fn split_evr(evr: &str) -> (Option<String>, Option<String>, Option<String>) {
    let (epoch, rest) = match evr.split_once(':') {
        Some((e, r)) if e.chars().all(|c| c.is_ascii_digit()) => (e.to_string(), r),
        _ => ("0".to_string(), evr),
    };
    let (ver, rel) = match rest.rsplit_once('-') {
        Some((v, r)) => (v.to_string(), Some(r.to_string())),
        None => (rest.to_string(), None),
    };
    (Some(epoch), Some(ver), rel)
}

// ---------------------------------------------------------------------------------------
// Arch Linux
// ---------------------------------------------------------------------------------------

/// Key/value pairs from `.PKGINFO` (keys may repeat, e.g. `depend`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchMeta {
    pub info: Vec<(String, String)>,
    /// Base64 of a detached `.sig` published next to the package, if any.
    pub pgpsig: Option<String>,
}

impl ArchMeta {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.info
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.info
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    pub fn arch(&self) -> &str {
        self.get("arch").unwrap_or("any")
    }
}

pub fn parse_arch(reader: impl Read, filename: &str) -> Result<ArchMeta> {
    let file = BufReader::new(reader);
    let n = filename.to_ascii_lowercase();
    let reader: Box<dyn Read + '_> = if n.ends_with(".zst") {
        Box::new(zstd::stream::read::Decoder::new(file)?)
    } else if n.ends_with(".xz") {
        Box::new(xz2::read::XzDecoder::new(file))
    } else if n.ends_with(".gz") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let entry = entry?;
        if entry.path()?.to_string_lossy() == ".PKGINFO" {
            let mut info = Vec::new();
            for line in BufReader::new(entry).lines() {
                let line = line?;
                if line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once(" = ") {
                    info.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            if !info.iter().any(|(k, _)| k == "pkgname") {
                bail!(".PKGINFO has no pkgname");
            }
            return Ok(ArchMeta { info, pgpsig: None });
        }
    }
    bail!("no .PKGINFO found; not an Arch package?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(Kind::from_filename("foo_1.0_amd64.deb"), Some(Kind::Deb));
        assert_eq!(Kind::from_filename("foo-1.0-1.x86_64.rpm"), Some(Kind::Rpm));
        assert_eq!(Kind::from_filename("foo-1.0-1.src.rpm"), None);
        assert_eq!(
            Kind::from_filename("foo-1.0-1-x86_64.pkg.tar.zst"),
            Some(Kind::Arch)
        );
        assert_eq!(
            Kind::from_filename("foo-1.0-1-x86_64.pkg.tar.zst.sig"),
            None
        );
        assert_eq!(Kind::from_filename("foo.tar.gz"), None);
    }

    #[test]
    fn control() {
        let f = parse_control(
            "Package: foo\nVersion: 1.0\nDescription: short\n long line\n .\n more\n\nPackage: ignored\n",
        );
        assert_eq!(f.len(), 3);
        assert_eq!(f[2].1, "short\n long line\n .\n more");
    }

    #[test]
    fn evr() {
        assert_eq!(
            split_evr("1:2.0-3"),
            (Some("1".into()), Some("2.0".into()), Some("3".into()))
        );
        assert_eq!(
            split_evr("2.0"),
            (Some("0".into()), Some("2.0".into()), None)
        );
    }
}
