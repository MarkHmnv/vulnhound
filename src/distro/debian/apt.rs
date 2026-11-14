//! Installed packages (from `dpkg-query`) and where apt can get each one (from `apt-cache policy`).

use crate::debver;
use crate::system::System;
use anyhow::{Context, Result};
use std::cmp::Ordering;
use std::collections::HashMap;

const SEP: char = '\t';
const DPKG_STATUS: &str = "/var/lib/dpkg/status";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    /// With an architecture qualifier for foreign and multi-arch packages: `libc6:amd64`.
    pub name: String,
    pub version: String,
    pub source_name: String,
    pub source_version: String,
    /// Without the e-mail address.
    pub maintainer: String,
}

impl InstalledPackage {
    /// The name without architecture, as `apt install` takes it.
    pub fn bare_name(&self) -> &str {
        self.name.split(':').next().unwrap_or(&self.name)
    }
}

pub fn query_installed(sys: &dyn System) -> Result<Vec<InstalledPackage>> {
    let format = format!(
        "${{binary:Package}}{SEP}${{Version}}{SEP}${{source:Package}}{SEP}${{source:Version}}{SEP}${{db:Status-Abbrev}}{SEP}${{Maintainer}}\n"
    );
    let out = sys
        .run("dpkg-query", &["-W", "-f", &format])
        .context("listing installed packages")?;
    Ok(parse_installed(&out))
}

pub fn parse_installed(out: &str) -> Vec<InstalledPackage> {
    out.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(SEP).collect();
            // Status "ii ", "hi ": installed. "rc " (removed, config left) and the like are not.
            if f.len() < 6 || f[4].as_bytes().get(1) != Some(&b'i') {
                return None;
            }
            let maintainer = f[5].split('<').next().unwrap_or("").trim().to_string();
            Some(InstalledPackage {
                name: f[0].to_string(),
                version: f[1].to_string(),
                source_name: if f[2].is_empty() { f[0] } else { f[2] }.to_string(),
                source_version: if f[3].is_empty() { f[1] } else { f[3] }.to_string(),
                maintainer,
            })
        })
        .collect()
}

/// A package index apt reads, e.g. `http://deb.debian.org/debian bookworm/main amd64 Packages`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Origin {
    /// `o=`: Debian, Ubuntu, UbuntuESMApps, Docker, LP-PPA-mozillateam, ...
    pub origin: String,
    /// `n=` (codename, e.g. bookworm-security) or else `a=` (archive, e.g. noble-security).
    pub suite: String,
    /// Host name, for indexes without an origin.
    pub site: String,
}

impl Origin {
    /// Who publishes it, for the report.
    pub fn vendor(&self) -> &str {
        if self.origin.is_empty() {
            &self.site
        } else {
            &self.origin
        }
    }
}

/// `apt-cache policy` without arguments: every package index and its release data.
pub fn parse_origins(out: &str) -> HashMap<String, Origin> {
    let mut out_map = HashMap::new();
    let mut current: Option<(String, Origin)> = None;
    for line in out.lines() {
        let trimmed = line.trim();
        if let Some(key) = index_key(line) {
            if let Some((k, o)) = current.take() {
                out_map.insert(k, o);
            }
            current = Some((key.to_string(), Origin::default()));
        } else if let Some(release) = trimmed.strip_prefix("release ") {
            if let Some((_, o)) = current.as_mut() {
                let fields: HashMap<&str, &str> = release.split(',').filter_map(|kv| kv.split_once('=')).collect();
                o.origin = fields.get("o").copied().unwrap_or_default().to_string();
                let n = fields.get("n").copied().unwrap_or_default();
                let a = fields.get("a").copied().unwrap_or_default();
                // Debian's security index says n=bookworm-security, Ubuntu's n=noble a=noble-security.
                o.suite = if n.contains('-') || a.is_empty() { n } else { a }.to_string();
            }
        } else if let Some(site) = trimmed.strip_prefix("origin ")
            && let Some((_, o)) = current.as_mut()
        {
            o.site = site.to_string();
        }
    }
    if let Some((k, o)) = current {
        out_map.insert(k, o);
    }
    out_map.remove(DPKG_STATUS);
    out_map
}

/// ` 500 http://deb.debian.org/debian bookworm/main amd64 Packages` → the part after the priority.
fn index_key(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let (prio, rest) = t.split_once(' ')?;
    (line.starts_with(' ') && prio.parse::<i32>().is_ok() && !rest.is_empty()).then_some(rest.trim())
}

/// One package as `apt-cache policy <names>` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub installed: Option<String>,
    pub candidate: Option<String>,
    /// Each version apt knows and the indexes that have it; `/var/lib/dpkg/status` is left out.
    pub versions: Vec<(String, Vec<String>)>,
}

impl Policy {
    pub fn indexes_of(&self, version: &str) -> &[String] {
        self.versions
            .iter()
            .find(|(v, _)| v == version)
            .map_or(&[], |(_, idx)| idx.as_slice())
    }

    /// The newest version in any index, and the indexes that have it.
    pub fn newest_available(&self) -> Option<(&str, &[String])> {
        self.versions
            .iter()
            .filter(|(_, idx)| !idx.is_empty())
            .max_by(|a, b| debver::cmp(&a.0, &b.0))
            .map(|(v, idx)| (v.as_str(), idx.as_slice()))
    }
}

/// Package name (as the header shows it: `libc6` for the native architecture, `libc6:i386` for
/// others) → its policy.
pub fn parse_policy(out: &str) -> HashMap<String, Policy> {
    let mut map: HashMap<String, Policy> = HashMap::new();
    let mut current: Option<(String, Policy)> = None;
    for line in out.lines() {
        if !line.starts_with(' ') {
            if let Some(name) = line.strip_suffix(':').filter(|n| !n.is_empty() && !n.contains(' ')) {
                if let Some((n, p)) = current.take() {
                    map.insert(n, p);
                }
                current = Some((name.to_string(), Policy::default()));
            }
            continue;
        }
        let Some((_, p)) = current.as_mut() else { continue };
        let t = line.trim();
        let none = |v: &str| (v != "(none)").then(|| v.to_string());
        if let Some(v) = t.strip_prefix("Installed: ") {
            p.installed = none(v);
        } else if let Some(v) = t.strip_prefix("Candidate: ") {
            p.candidate = none(v);
        } else if t == "Version table:" {
        } else if let Some(key) = index_key(line).filter(|_| line.starts_with("        ")) {
            if let Some((_, idx)) = p.versions.last_mut()
                && key != DPKG_STATUS
            {
                idx.push(key.to_string());
            }
        } else {
            // ` *** 1.2-3 500` or `     1.2-3 500`
            let t = t.trim_start_matches("***").trim();
            if let Some((version, prio)) = t.split_once(' ')
                && prio.trim().parse::<i32>().is_ok()
            {
                p.versions.push((version.to_string(), Vec::new()));
            }
        }
    }
    if let Some((n, p)) = current {
        map.insert(n, p);
    }
    map
}

/// The global and per-package policy. Fails if apt cannot be run.
pub fn query_policy(
    sys: &dyn System,
    installed: &[InstalledPackage],
) -> Result<(HashMap<String, Origin>, HashMap<String, Policy>)> {
    let origins = parse_origins(
        &sys.run("apt-cache", &["policy"])
            .context("reading apt's package indexes")?,
    );
    let mut names: Vec<&str> = installed.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut args = vec!["policy"];
    args.extend(names);
    let policies = parse_policy(&sys.run("apt-cache", &args).context("reading apt's package versions")?);
    Ok((origins, policies))
}

/// `libc6:amd64` is shown as `libc6` when amd64 is the native architecture.
pub fn policy_for<'a>(policies: &'a HashMap<String, Policy>, pkg: &InstalledPackage) -> Option<&'a Policy> {
    policies.get(&pkg.name).or_else(|| policies.get(pkg.bare_name()))
}

pub fn newer(a: &str, b: &str) -> bool {
    debver::cmp(a, b) == Ordering::Greater
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const ORIGINS: &str = "Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
     release v=12,o=Debian,a=oldstable-security,n=bookworm-security,l=Debian-Security,c=main,b=amd64
     origin deb.debian.org
 500 http://deb.debian.org/debian bookworm/main amd64 Packages
     release v=12.15,o=Debian,a=oldstable,n=bookworm,l=Debian,c=main,b=amd64
     origin deb.debian.org
 500 https://download.docker.com/linux/debian bookworm/stable amd64 Packages
     release o=Docker,a=bookworm,l=Docker CE,c=stable,b=amd64
     origin download.docker.com
 500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=main,b=amd64
     origin security.ubuntu.com
 500 file:/srv/repo ./ Packages
Pinned packages:
";

    #[test]
    fn parses_indexes_and_their_origin() {
        let o = parse_origins(ORIGINS);
        assert_eq!(o.len(), 5, "{o:?}");
        let sec = &o["http://deb.debian.org/debian-security bookworm-security/main amd64 Packages"];
        assert_eq!(
            (sec.origin.as_str(), sec.suite.as_str()),
            ("Debian", "bookworm-security")
        );
        let docker = &o["https://download.docker.com/linux/debian bookworm/stable amd64 Packages"];
        assert_eq!((docker.vendor(), docker.suite.as_str()), ("Docker", "bookworm"));
        let ubuntu = &o["http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages"];
        assert_eq!(ubuntu.suite, "noble-security", "Ubuntu's codename has no pocket");
        assert_eq!(o["file:/srv/repo ./ Packages"].vendor(), "", "no release file");
    }

    pub const POLICY: &str = "libc6:
  Installed: 2.36-9+deb12u7
  Candidate: 2.36-9+deb12u14
  Version table:
     2.36-9+deb12u14 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
 *** 2.36-9+deb12u7 100
        100 /var/lib/dpkg/status
libc6:i386:
  Installed: 2.36-9+deb12u14
  Candidate: 2.36-9+deb12u14
  Version table:
 *** 2.36-9+deb12u14 500
        500 http://deb.debian.org/debian bookworm/main i386 Packages
        100 /var/lib/dpkg/status
localtool:
  Installed: 1.0
  Candidate: 1.0
  Version table:
 *** 1.0 100
        100 /var/lib/dpkg/status
docker-ce:
  Installed: 5:28.0.0-1~debian.12~bookworm
  Candidate: 5:28.1.0-1~debian.12~bookworm
  Version table:
     5:28.1.0-1~debian.12~bookworm 500
        500 https://download.docker.com/linux/debian bookworm/stable amd64 Packages
 *** 5:28.0.0-1~debian.12~bookworm 500
        500 https://download.docker.com/linux/debian bookworm/stable amd64 Packages
        100 /var/lib/dpkg/status
";

    #[test]
    fn parses_package_versions_and_their_indexes() {
        let p = parse_policy(POLICY);
        assert_eq!(p.len(), 4);
        let libc = &p["libc6"];
        assert_eq!(libc.installed.as_deref(), Some("2.36-9+deb12u7"));
        assert_eq!(libc.candidate.as_deref(), Some("2.36-9+deb12u14"));
        assert!(libc.indexes_of("2.36-9+deb12u7").is_empty(), "only in the dpkg status");
        assert_eq!(
            libc.newest_available(),
            Some((
                "2.36-9+deb12u14",
                &["http://deb.debian.org/debian bookworm/main amd64 Packages".to_string()][..]
            ))
        );
        assert!(p["localtool"].newest_available().is_none());
        assert_eq!(p["docker-ce"].indexes_of("5:28.0.0-1~debian.12~bookworm").len(), 1);
    }

    #[test]
    fn finds_the_policy_of_native_and_foreign_packages() {
        let p = parse_policy(POLICY);
        let pkg = |name: &str| InstalledPackage {
            name: name.into(),
            version: String::new(),
            source_name: String::new(),
            source_version: String::new(),
            maintainer: String::new(),
        };
        assert_eq!(
            policy_for(&p, &pkg("libc6:amd64")).unwrap().installed.as_deref(),
            Some("2.36-9+deb12u7")
        );
        assert_eq!(
            policy_for(&p, &pkg("libc6:i386")).unwrap().installed.as_deref(),
            Some("2.36-9+deb12u14")
        );
        assert!(policy_for(&p, &pkg("gone")).is_none());
    }

    #[test]
    fn parses_installed_packages() {
        let out = "libc6:amd64\t2.36-9+deb12u7\tglibc\t2.36-9+deb12u7\tii \tGNU Libc Maintainers <debian-glibc@lists.debian.org>\n\
                   bash\t5.2.15-2+b2\t\t\tii \tMatthias Klose <doko@debian.org>\n\
                   oldconf\t1.0\toldconf\t1.0\trc \tX <x@y>\n\
                   held\t1.0\theld\t1.0\thi \t\n\
                   broken line\n";
        let p = parse_installed(out);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].source_name, "glibc");
        assert_eq!(p[0].bare_name(), "libc6");
        assert_eq!(p[0].maintainer, "GNU Libc Maintainers");
        assert_eq!(
            (p[1].source_name.as_str(), p[1].source_version.as_str()),
            ("bash", "5.2.15-2+b2"),
            "no source field: the package is its own source"
        );
        assert_eq!(p[2].name, "held", "held packages are installed");
    }
}
