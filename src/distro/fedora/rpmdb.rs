//! Installed packages (from `rpm`) and pending upgrades (from `dnf`).

use crate::rpmver::{Evr, split_nvr};
use crate::system::System;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};

const SEP: char = '\t';

/// Their updates live in Bodhi.
pub const FEDORA_REPOS: &[&str] = &["fedora", "updates", TESTING_REPO];

pub const TESTING_REPO: &str = "updates-testing";

pub const FEDORA_VENDOR: &str = "Fedora Project";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub evr: Evr,
    pub arch: String,
    pub source_name: String,
    pub source_evr: Evr,
    pub vendor: String,
    pub buildtime: i64,
}

impl InstalledPackage {
    pub fn is_fedora(&self) -> bool {
        self.vendor == FEDORA_VENDOR
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpgrade {
    pub name: String,
    pub evr: Evr,
    pub arch: String,
    pub source_name: String,
    /// As Bodhi names builds, e.g. git-2.56.1-1.fc45.
    pub source_nvr: String,
    pub repo: String,
}

impl PendingUpgrade {
    pub fn is_fedora_repo(&self) -> bool {
        FEDORA_REPOS.contains(&self.repo.as_str())
    }
}

pub fn query_installed(sys: &dyn System) -> Result<Vec<InstalledPackage>> {
    let qf = format!(
        "%{{NAME}}{SEP}%{{EPOCHNUM}}{SEP}%{{VERSION}}{SEP}%{{RELEASE}}{SEP}%{{ARCH}}{SEP}%{{SOURCERPM}}{SEP}%{{VENDOR}}{SEP}%{{BUILDTIME}}\n"
    );
    let out = sys
        .run("rpm", &["-qa", "--qf", &qf])
        .context("listing installed packages")?;
    Ok(parse_installed(&out))
}

pub fn parse_installed(out: &str) -> Vec<InstalledPackage> {
    let mut pkgs = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split(SEP).collect();
        if f.len() < 8 || f[0] == "gpg-pubkey" {
            continue;
        }
        let Some((source_name, source_evr)) = split_nvr(f[5]) else {
            continue;
        };
        let epoch = f[1].parse().unwrap_or(0);
        pkgs.push(InstalledPackage {
            name: f[0].to_string(),
            evr: Evr::new(epoch, f[2], f[3]),
            arch: f[4].to_string(),
            source_name,
            source_evr: Evr::new(epoch, &source_evr.version, &source_evr.release),
            vendor: if f[6] == "(none)" {
                String::new()
            } else {
                f[6].to_string()
            },
            buildtime: f[7].parse().unwrap_or(0),
        });
    }
    pkgs
}

/// Includes `updates-testing`, where fixes not yet in stable are.
pub fn query_pending(sys: &dyn System) -> Result<Vec<PendingUpgrade>> {
    let qf = format!(
        "%{{name}}{SEP}%{{epoch}}{SEP}%{{version}}{SEP}%{{release}}{SEP}%{{arch}}{SEP}%{{sourcerpm}}{SEP}%{{repoid}}\n"
    );
    let enable_testing = format!("--enablerepo={TESTING_REPO}");
    let args = [
        "repoquery",
        "-q",
        "--upgrades",
        "--queryformat",
        qf.as_str(),
        &enable_testing,
    ];
    let out = sys.run("dnf", &args).context("listing available upgrades")?;
    Ok(parse_pending(&out))
}

/// Installed packages no enabled repository provides.
pub fn query_extras(sys: &dyn System) -> Result<BTreeSet<String>> {
    let out = sys
        .run("dnf", &["repoquery", "-q", "--extras", "--queryformat", "%{name}\n"])
        .context("listing packages without a repository")?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Keeps the newest build per package, arch and repository.
pub fn parse_pending(out: &str) -> Vec<PendingUpgrade> {
    let mut best: BTreeMap<(String, String, String), PendingUpgrade> = BTreeMap::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split(SEP).collect();
        if f.len() < 7 {
            continue;
        }
        let Some((source_name, _)) = split_nvr(f[5]) else {
            continue;
        };
        let p = PendingUpgrade {
            name: f[0].to_string(),
            evr: Evr::new(f[1].parse().unwrap_or(0), f[2], f[3]),
            arch: f[4].to_string(),
            source_name,
            source_nvr: f[5].strip_suffix(".src.rpm").unwrap_or(f[5]).to_string(),
            repo: f[6].to_string(),
        };
        let key = (p.name.clone(), p.arch.clone(), p.repo.clone());
        match best.get(&key) {
            Some(old) if old.evr >= p.evr => {}
            _ => {
                best.insert(key, p);
            }
        }
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rpm_qa_and_skips_gpg_keys() {
        let out = "git-core\t0\t2.56.0\t1.fc45\tx86_64\tgit-2.56.0-1.fc45.src.rpm\tFedora Project\t1791211692\n\
                   gpg-pubkey\t0\tabc\t123\t(none)\t(none)\t(none)\t0\n\
                   vim-minimal\t2\t9.2.1300\t1.fc45\tx86_64\tvim-9.2.1300-1.fc45.src.rpm\tFedora Project\t1790000000\n\
                   code\t0\t1.145.0\t1.el8\tx86_64\tcode-1.145.0-1.el8.src.rpm\t(none)\t1790000000\n";
        let p = parse_installed(out);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].name, "git-core");
        assert_eq!(p[0].source_name, "git");
        assert_eq!(p[0].source_evr, Evr::new(0, "2.56.0", "1.fc45"));
        assert_eq!(p[0].buildtime, 1791211692);
        assert!(p[0].is_fedora());
        assert_eq!(p[1].evr.epoch, 2);
        assert_eq!(p[1].source_evr.epoch, 2, "source inherits the binary epoch");
        assert_eq!(p[2].vendor, "");
        assert!(!p[2].is_fedora());
    }

    #[test]
    fn parses_repoquery_and_keeps_newest_per_repo() {
        let out = "code\t0\t1.145.3\t1.el8\tx86_64\tcode-1.145.3-1.el8.src.rpm\tcode\n\
                   code\t0\t1.146.0\t1.el8\tx86_64\tcode-1.146.0-1.el8.src.rpm\tcode\n\
                   git-core\t0\t2.56.1\t1.fc45\tx86_64\tgit-2.56.1-1.fc45.src.rpm\tupdates-testing\n\
                   broken line\n";
        let p = parse_pending(out);
        assert_eq!(p.len(), 2);
        let code = p.iter().find(|x| x.name == "code").unwrap();
        assert_eq!(code.evr.version, "1.146.0");
        assert!(!code.is_fedora_repo());
        let git = p.iter().find(|x| x.name == "git-core").unwrap();
        assert_eq!(git.source_name, "git");
        assert_eq!(git.source_nvr, "git-2.56.1-1.fc45");
        assert!(git.is_fedora_repo());
    }

    #[test]
    fn query_extras_returns_unique_names() {
        use crate::system::fake::FakeSystem;
        let sys = FakeSystem::new().on("--extras", "wordcraft\nkmod-nvidia\n\nkmod-nvidia\n");
        let extras = query_extras(&sys).unwrap();
        assert_eq!(extras.into_iter().collect::<Vec<_>>(), vec!["kmod-nvidia", "wordcraft"]);
    }

    #[test]
    fn query_pending_includes_testing() {
        use crate::system::fake::FakeSystem;
        let sys = FakeSystem::new().on("dnf repoquery", "");
        query_pending(&sys).unwrap();
        assert!(sys.requests()[0].contains("--enablerepo=updates-testing"));
    }
}
