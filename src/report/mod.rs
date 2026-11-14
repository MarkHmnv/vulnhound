//! Terminal summary, Markdown report and progress display.

pub mod console;
pub mod markdown;
pub mod progress;

use crate::model::{Finding, Report, Severity, ThirdPartyStatus, UpstreamRelease};
use std::collections::BTreeMap;

/// (affected, likely fixed only).
pub(crate) fn split_findings(report: &Report) -> (Vec<&Finding>, Vec<&Finding>) {
    report.findings.iter().partition(|f| !f.is_likely_fixed_only())
}

pub(crate) fn severity_counts(findings: &[&Finding]) -> Vec<(Severity, usize)> {
    let mut counts: BTreeMap<std::cmp::Reverse<Severity>, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(std::cmp::Reverse(f.severity)).or_default() += 1;
    }
    counts.into_iter().map(|(s, n)| (s.0, n)).collect()
}

pub(crate) fn fix_commands(findings: &[&Finding]) -> Vec<String> {
    merged_commands(
        findings
            .iter()
            .filter_map(|f| f.update.as_ref())
            .map(|u| (u.command.as_str(), u.upgrades.as_slice())),
    )
}

pub(crate) fn third_party_commands(report: &Report) -> Vec<String> {
    merged_commands(report.third_party.iter().filter_map(|t| match &t.status {
        ThirdPartyStatus::UpdateAvailable { command, upgrades, .. } => Some((command.as_str(), upgrades.as_slice())),
        ThirdPartyStatus::NoRepository => None,
    }))
}

/// Upstream releases of packages that have no finding in `shown`.
pub(crate) fn upstream_without_findings<'a>(report: &'a Report, shown: &[&Finding]) -> Vec<&'a UpstreamRelease> {
    report
        .upstream
        .iter()
        .filter(|u| !shown.iter().any(|f| f.package == u.package))
        .collect()
}

/// Words that differ between backends.
pub(crate) struct Terms {
    /// What is installed: "package" or "program".
    pub item: &'static str,
    /// What items are checked against.
    pub data: String,
    /// Items that cannot be checked, in a short phrase.
    pub uncovered: &'static str,
    /// Why those cannot be checked.
    pub coverage_intro: &'static str,
    pub updates_heading: &'static str,
    pub updates_intro: &'static str,
    pub updates_label: &'static str,
    /// Summary line for `third_party`, after the count.
    pub updates_summary: (&'static str, &'static str),
}

pub(crate) fn terms(report: &Report) -> Terms {
    if report.backend == "windows" {
        Terms {
            item: "program",
            data: "MSRC and NVD vulnerability data".into(),
            uncovered: "not checked",
            coverage_intro: "have no known NVD product, so they were not checked",
            updates_heading: "Program updates",
            updates_intro: "Programs without known CVEs that winget can update.",
            updates_label: "Updates:",
            updates_summary: ("program update", "available in winget"),
        }
    } else {
        let data = match report.backend.as_str() {
            "debian" => "Debian's security tracker".to_string(),
            "ubuntu" => "Ubuntu's OVAL data".to_string(),
            other => format!("{other} vulnerability data"),
        };
        Terms {
            item: "package",
            data,
            uncovered: "third-party",
            coverage_intro: "come from outside the distro",
            updates_heading: "Third-party packages",
            updates_intro: "No vulnerability data exists for packages from outside the distro, so only their update \
                            status is checked.",
            updates_label: "Third-party:",
            updates_summary: ("third-party package", "need attention"),
        }
    }
}

/// Channel of a fix that only a not yet enabled Ubuntu Pro service delivers: `pro:esm-apps`.
pub const PRO_CHANNEL_PREFIX: &str = "pro:";

/// Where an update comes from, after "**Update:** `<build>`".
pub(crate) fn update_place(channel: &str) -> String {
    if let Some(service) = channel.strip_prefix(PRO_CHANNEL_PREFIX) {
        return format!("only from Ubuntu Pro ({service}), which this machine does not get");
    }
    match channel {
        "testing" => "in testing repository only".into(),
        "stable" => "in stable".into(),
        "vendor" => "from the vendor, no winget package".into(),
        other => format!("in {other}"),
    }
}

pub(crate) fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// Merges `<prefix> <packages>` commands into one per prefix; other commands stay as they are.
fn merged_commands<'a>(updates: impl Iterator<Item = (&'a str, &'a [String])>) -> Vec<String> {
    let mut merged: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut other: Vec<String> = Vec::new();
    for (command, upgrades) in updates {
        let pkgs = upgrades.join(" ");
        match command.strip_suffix(&format!(" {pkgs}")).filter(|_| !pkgs.is_empty()) {
            Some(prefix) => merged
                .entry(prefix.trim_end().to_string())
                .or_default()
                .extend(upgrades.iter().cloned()),
            None if !command.is_empty() && !other.iter().any(|o| o == command) => other.push(command.to_string()),
            None => {}
        }
    }
    let mut out: Vec<String> = merged
        .into_iter()
        .map(|(prefix, mut pkgs)| {
            pkgs.sort();
            pkgs.dedup();
            format!("{prefix} {}", pkgs.join(" "))
        })
        .collect();
    out.extend(other);
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    use crate::model::*;

    pub fn vuln(id: &str, sev: Severity, conf: Confidence) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            severity: sev,
            title: format!("title of {id}"),
            url: format!("https://bugs/{id}"),
            confidence: conf,
            source: "bugzilla-tracker".into(),
        }
    }

    pub fn finding(package: &str, installed: &str, vulns: Vec<Vulnerability>, update: Option<Update>) -> Finding {
        let mut f = Finding {
            package: package.into(),
            installed: installed.into(),
            severity: Severity::Unknown,
            vulnerabilities: vulns,
            update,
            notes: Vec::new(),
        };
        f.recompute_severity();
        f
    }

    /// One affected (git) and one likely fixed (zlib) package, upstream, third-party, a warning.
    pub fn sample() -> Report {
        let git = finding(
            "git",
            "2.56.0-1.fc45",
            vec![
                vuln("CVE-2026-111760", Severity::High, Confidence::Affected),
                vuln("CVE-2026-113408", Severity::Medium, Confidence::Affected),
            ],
            Some(Update {
                id: "FEDORA-2026-5c62077075".into(),
                kind: "enhancement".into(),
                severity: Severity::Unknown,
                build: "git-2.56.1-1.fc45".into(),
                channel: "testing".into(),
                url: "https://bodhi/FEDORA-2026-5c62077075".into(),
                upgrades: vec!["git-core".into()],
                command: "sudo dnf upgrade --refresh --enablerepo=updates-testing git-core".into(),
            }),
        );
        let zlib = finding(
            "zlib",
            "1.3-1",
            vec![vuln("CVE-2026-1111", Severity::Critical, Confidence::LikelyFixed)],
            None,
        );
        Report {
            distro: "Fedora Linux 45".into(),
            backend: "fedora".into(),
            coverage: Coverage {
                installed_packages: 10,
                covered_packages: 8,
                uncovered_packages: 2,
                uncovered_vendors: vec![("RPM Fusion".into(), 2)],
                fixed_suppressed: 3,
            },
            findings: vec![git, zlib],
            third_party: vec![
                ThirdPartyPackage {
                    package: "brave-origin".into(),
                    vendor: "Brave Software, Inc.".into(),
                    installed: "1.99.55-1".into(),
                    status: ThirdPartyStatus::UpdateAvailable {
                        version: "1.99.56-1".into(),
                        repo: "brave-browser".into(),
                        upgrades: vec!["brave-origin".into()],
                        command: "sudo dnf upgrade --refresh brave-origin".into(),
                    },
                },
                ThirdPartyPackage {
                    package: "wordcraft".into(),
                    vendor: "Learning Machines LLC".into(),
                    installed: "0.17.0-1".into(),
                    status: ThirdPartyStatus::NoRepository,
                },
            ],
            upstream: vec![
                UpstreamRelease {
                    package: "git".into(),
                    distro_version: "2.56.1".into(),
                    upstream_version: "2.56.2".into(),
                    project: "git".into(),
                },
                UpstreamRelease {
                    package: "openssh".into(),
                    distro_version: "10.5p1".into(),
                    upstream_version: "10.6p2".into(),
                    project: "OpenSSH".into(),
                },
            ],
            warnings: vec!["Bodhi is down".into()],
            notes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_commands_by_prefix() {
        let t = |pkgs: &[&str], testing: bool| {
            let pkgs: Vec<String> = pkgs.iter().map(std::string::ToString::to_string).collect();
            let flag = if testing { " --enablerepo=updates-testing" } else { "" };
            (format!("sudo dnf upgrade --refresh{flag} {}", pkgs.join(" ")), pkgs)
        };
        let ups = [
            t(&["git-core", "git-core-doc"], true),
            t(&["openssl"], false),
            t(&["poppler", "git-core"], true),
            ("custom-tool fix".to_string(), vec!["x".to_string()]),
        ];
        assert_eq!(
            merged_commands(ups.iter().map(|(c, p)| (c.as_str(), p.as_slice()))),
            vec![
                "sudo dnf upgrade --refresh openssl",
                "sudo dnf upgrade --refresh --enablerepo=updates-testing git-core git-core-doc poppler",
                "custom-tool fix",
            ]
        );
    }

    #[test]
    fn splits_and_counts_findings() {
        let r = fixtures::sample();
        let (affected, likely) = split_findings(&r);
        assert_eq!(affected.len(), 1);
        assert_eq!(likely[0].package, "zlib");
        assert_eq!(severity_counts(&affected), vec![(Severity::High, 1)]);
        assert_eq!(
            fix_commands(&affected),
            vec!["sudo dnf upgrade --refresh --enablerepo=updates-testing git-core"]
        );
        assert_eq!(
            third_party_commands(&r),
            vec!["sudo dnf upgrade --refresh brave-origin"]
        );
        let up: Vec<&str> = upstream_without_findings(&r, &affected)
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert_eq!(up, vec!["openssh"]);
    }
}
