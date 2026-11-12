//! Distro-independent report model.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Accepts the words of Bodhi and Bugzilla; anything else (e.g. "unspecified") is `Unknown`.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "urgent" | "critical" => Self::Critical,
            "high" | "important" => Self::High,
            "medium" | "moderate" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.pad(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Affected,
    /// The package was rebased to a newer upstream version after the report; unconfirmed.
    LikelyFixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub url: String,
    pub confidence: Confidence,
    /// e.g. "bugzilla-tracker", "bodhi-advisory", "kernel-cna".
    pub source: String,
}

/// An available update that is not installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// Advisory id, e.g. FEDORA-2026-5c62077075.
    pub id: String,
    /// As the distro marked it: security, bugfix, enhancement, newpackage.
    pub kind: String,
    pub severity: Severity,
    pub build: String,
    /// stable or testing.
    pub channel: String,
    pub url: String,
    /// Installed binary packages it upgrades.
    pub upgrades: Vec<String>,
    pub command: String,
}

/// Everything found for one source package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub package: String,
    pub installed: String,
    pub severity: Severity,
    pub vulnerabilities: Vec<Vulnerability>,
    pub update: Option<Update>,
    /// Shown under the finding in the report.
    pub notes: Vec<String>,
}

impl Finding {
    pub fn recompute_severity(&mut self) {
        let vulns = self
            .vulnerabilities
            .iter()
            .filter(|v| v.confidence == Confidence::Affected)
            .map(|v| v.severity);
        let update = self.update.iter().filter(|u| u.kind == "security").map(|u| u.severity);
        self.severity = vulns.chain(update).max().unwrap_or(Severity::Unknown);
    }

    pub fn is_likely_fixed_only(&self) -> bool {
        let security_update = self.update.as_ref().is_some_and(|u| u.kind == "security");
        !security_update
            && !self.vulnerabilities.is_empty()
            && self
                .vulnerabilities
                .iter()
                .all(|v| v.confidence == Confidence::LikelyFixed)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    pub installed_packages: usize,
    pub covered_packages: usize,
    /// Third-party packages: no vulnerability data exists for them.
    pub uncovered_packages: usize,
    pub uncovered_vendors: Vec<(String, usize)>,
    /// CVEs dropped because the installed package has the fix.
    pub fixed_suppressed: usize,
}

/// A third-party package that is behind its repository or has none. Not a vulnerability
/// finding: nobody publishes vulnerability data for these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThirdPartyPackage {
    pub package: String,
    pub vendor: String,
    pub installed: String,
    pub status: ThirdPartyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThirdPartyStatus {
    UpdateAvailable {
        version: String,
        repo: String,
        upgrades: Vec<String>,
        command: String,
    },
    /// Will never be updated automatically.
    NoRepository,
}

/// An upstream release newer than anything the distro offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRelease {
    pub package: String,
    /// Newest version the distro offers, installed or in a repository.
    pub distro_version: String,
    pub upstream_version: String,
    pub project: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub distro: String,
    pub backend: String,
    pub coverage: Coverage,
    pub findings: Vec<Finding>,
    pub third_party: Vec<ThirdPartyPackage>,
    pub upstream: Vec<UpstreamRelease>,
    /// Non-fatal problems, e.g. an unreachable data source.
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(sev: Severity, conf: Confidence) -> Vulnerability {
        Vulnerability {
            id: "CVE-1".into(),
            severity: sev,
            title: String::new(),
            url: String::new(),
            confidence: conf,
            source: "test".into(),
        }
    }

    fn finding(vulns: Vec<Vulnerability>, update: Option<Update>) -> Finding {
        Finding {
            package: "p".into(),
            installed: "1-1".into(),
            severity: Severity::Unknown,
            vulnerabilities: vulns,
            update,
            notes: Vec::new(),
        }
    }

    fn update(kind: &str, sev: Severity) -> Update {
        Update {
            id: "A".into(),
            kind: kind.into(),
            severity: sev,
            build: "p-2-1".into(),
            channel: "stable".into(),
            url: String::new(),
            upgrades: vec![],
            command: String::new(),
        }
    }

    #[test]
    fn parses_severity_words_from_all_sources() {
        assert_eq!(Severity::parse("urgent"), Severity::Critical);
        assert_eq!(Severity::parse("High"), Severity::High);
        assert_eq!(Severity::parse("moderate"), Severity::Medium);
        assert_eq!(Severity::parse("low"), Severity::Low);
        assert_eq!(Severity::parse("unspecified"), Severity::Unknown);
        assert_eq!(Severity::parse(""), Severity::Unknown);
    }

    #[test]
    fn severity_ignores_likely_fixed_vulnerabilities() {
        let mut f = finding(
            vec![
                vuln(Severity::Critical, Confidence::LikelyFixed),
                vuln(Severity::Low, Confidence::Affected),
            ],
            None,
        );
        f.recompute_severity();
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn severity_counts_security_updates_but_not_enhancements() {
        let mut f = finding(vec![], Some(update("security", Severity::High)));
        f.recompute_severity();
        assert_eq!(f.severity, Severity::High);

        let mut f = finding(vec![], Some(update("enhancement", Severity::High)));
        f.recompute_severity();
        assert_eq!(f.severity, Severity::Unknown);
    }

    #[test]
    fn likely_fixed_only_requires_all_vulns_likely_fixed_and_no_security_update() {
        let lf = vuln(Severity::High, Confidence::LikelyFixed);
        assert!(finding(vec![lf.clone()], None).is_likely_fixed_only());
        assert!(!finding(vec![lf.clone(), vuln(Severity::Low, Confidence::Affected)], None).is_likely_fixed_only());
        assert!(!finding(vec![lf], Some(update("security", Severity::Low))).is_likely_fixed_only());
        assert!(!finding(vec![], None).is_likely_fixed_only());
    }
}
