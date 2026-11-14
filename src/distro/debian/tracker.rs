//! Debian's security tracker: every CVE of every source package and its state in each release,
//! including the ones Debian has not fixed (yet), with the reason.
//!
//! The export is 90 MB of JSON (15 MB compressed), so the entries of one release are kept as an
//! index in the cache and refreshed once a day.

use super::{Advisory, Status, short_title};
use crate::model::Severity;
use crate::system::System;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;

pub const URL: &str = "https://security-tracker.debian.org/tracker/data/json";

pub fn cve_url(id: &str) -> String {
    format!("https://security-tracker.debian.org/tracker/{id}")
}

#[derive(Deserialize)]
struct Cve {
    #[serde(default)]
    description: String,
    #[serde(default)]
    releases: HashMap<String, Release>,
}

#[derive(Deserialize)]
struct Release {
    status: String,
    #[serde(default)]
    repositories: HashMap<String, String>,
    #[serde(default)]
    fixed_version: Option<String>,
    #[serde(default)]
    urgency: String,
    /// Why there is no DSA, e.g. "Minor issue".
    #[serde(default)]
    nodsa: Option<String>,
    /// "postponed" or "ignored".
    #[serde(default)]
    nodsa_reason: Option<String>,
    /// The fix is in proposed-updates, waiting for the next point release.
    #[serde(default)]
    next_point_update: bool,
}

/// What Debian's urgency says, or `None` for "unimportant": no security impact on Debian's build.
fn severity(urgency: &str) -> Option<Severity> {
    // "low**": not confirmed yet.
    match urgency.trim_end_matches('*') {
        "unimportant" => None,
        u => Some(Severity::parse(u)),
    }
}

/// The advisories of `codename` in the tracker's export. Fails if the release is not tracked
/// (any more): reporting it as clean would be wrong.
pub fn parse(json: &[u8], codename: &str) -> Result<Vec<Advisory>> {
    let data: HashMap<String, HashMap<String, Cve>> =
        serde_json::from_slice(json).context("parsing Debian security tracker data")?;
    let mut out = Vec::new();
    let mut tracked = false;
    for (package, cves) in data {
        for (id, cve) in cves {
            let Some(rel) = cve.releases.get(codename) else {
                continue;
            };
            tracked = true;
            // TEMP-* entries are issues without a CVE yet.
            if !id.starts_with("CVE-") {
                continue;
            }
            let Some(severity) = severity(&rel.urgency) else {
                continue;
            };
            let Some(status) = status(rel, codename) else { continue };
            out.push(Advisory {
                package: package.clone(),
                cve: id,
                severity,
                title: short_title(&cve.description),
                status,
            });
        }
    }
    if !tracked {
        bail!(
            "Debian's security tracker has no data for '{codename}': it is not a release Debian supports with \
             security updates (any more)"
        );
    }
    out.sort_by(|a, b| a.package.cmp(&b.package).then(a.cve.cmp(&b.cve)));
    Ok(out)
}

/// `None` when the release is not affected.
fn status(rel: &Release, codename: &str) -> Option<Status> {
    match rel.status.as_str() {
        "resolved" => {
            let version = rel.fixed_version.clone().filter(|v| !v.is_empty())?;
            // "0": the release never had the vulnerable code.
            if version == "0" {
                return None;
            }
            Some(Status::Fixed {
                pocket: pocket(rel, &version, codename),
                version,
            })
        }
        "undetermined" => Some(Status::Open {
            note: "not triaged by Debian yet".into(),
        }),
        _ => {
            let note = if rel.urgency == "end-of-life" {
                format!("Debian no longer provides security updates for this package in {codename}")
            } else if rel.next_point_update {
                "fixed in the next Debian point release".into()
            } else if rel.nodsa_reason.as_deref() == Some("ignored") {
                let why = rel.nodsa.as_deref().map(str::trim).filter(|s| !s.is_empty());
                match why {
                    Some(why) => format!("Debian will not fix this in {codename}: {}", why.trim_end_matches('.')),
                    None => format!("Debian will not fix this in {codename}"),
                }
            } else if rel.nodsa_reason.as_deref() == Some("postponed") {
                "fix postponed to a later update".into()
            } else {
                "no fix yet".into()
            };
            Some(Status::Open { note })
        }
    }
}

/// The repository that has the fix: the release itself (point release) or its security archive.
fn pocket(rel: &Release, fixed: &str, codename: &str) -> String {
    let has_fix = |repo: &str| {
        rel.repositories
            .get(repo)
            .is_some_and(|v| crate::debver::cmp(v, fixed) != std::cmp::Ordering::Less)
    };
    let security = format!("{codename}-security");
    if has_fix(codename) {
        codename.to_string()
    } else if has_fix(&security) {
        security
    } else {
        String::new()
    }
}

/// Downloads the export; it is served compressed.
pub fn download(sys: &dyn System) -> Result<Vec<u8>> {
    sys.http_get_bytes(URL)
        .context("downloading Debian security tracker data")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Trimmed real entries, 2026-11-14.
    pub const EXPORT: &str = r#"{
      "openssl": {
        "CVE-2026-9076": {"description": "Issue summary: A crafted PKCS#12 file can crash the application. More text.",
          "scope": "remote", "releases": {
            "bookworm": {"status": "resolved", "repositories": {"bookworm": "3.0.20-1~deb12u2", "bookworm-security": "3.0.22-1~deb12u2"},
                         "fixed_version": "3.0.20-1~deb12u2", "urgency": "not yet assigned"},
            "trixie": {"status": "resolved", "repositories": {"trixie": "3.5.7-1~deb13u2", "trixie-security": "3.5.7-1~deb13u3"},
                       "fixed_version": "3.5.6-1~deb13u2", "urgency": "not yet assigned"}}},
        "CVE-2026-95691": {"description": "CMS_encrypt() may loop indefinitely",
          "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "3.0.20-1~deb12u2"}, "urgency": "low"}}},
        "CVE-2026-1000": {"description": "only in the security archive",
          "releases": {"bookworm": {"status": "resolved", "repositories": {"bookworm": "3.0.20-1~deb12u2", "bookworm-security": "3.0.22-1~deb12u2"},
                         "fixed_version": "3.0.22-1~deb12u1", "urgency": "high"}}},
        "CVE-2000-1254": {"description": "ancient", "releases": {"bookworm": {"status": "resolved",
          "repositories": {"bookworm": "3.0.20-1~deb12u2"}, "fixed_version": "0", "urgency": "not yet assigned"}}},
        "TEMP-0000000-ABCDEF": {"description": "no CVE yet", "releases": {"bookworm": {"status": "open",
          "repositories": {"bookworm": "3.0.20-1~deb12u2"}, "urgency": "not yet assigned"}}}
      },
      "7zip": {
        "CVE-2026-14266": {"description": "", "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "22.01+dfsg-8"},
          "urgency": "not yet assigned", "nodsa": "Minor issue, will be fixed via spu", "nodsa_reason": "", "next_point_update": true}}},
        "CVE-2026-48092": {"description": "", "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "22.01+dfsg-8"},
          "urgency": "unimportant"}}},
        "CVE-2026-2222": {"description": "", "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "22.01+dfsg-8"},
          "urgency": "low**", "nodsa": "Minor issue.", "nodsa_reason": "ignored"}}},
        "CVE-2026-3333": {"description": "", "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "22.01+dfsg-8"},
          "urgency": "not yet assigned", "nodsa": "", "nodsa_reason": "postponed"}}},
        "CVE-2026-4444": {"description": "", "releases": {"bookworm": {"status": "undetermined", "repositories": {},
          "urgency": "not yet assigned"}}}
      },
      "chromium": {
        "CVE-2026-5555": {"description": "Use after free in V8", "releases": {"bookworm": {"status": "open",
          "repositories": {"bookworm": "120.0-1~deb12u1"}, "urgency": "end-of-life"}}}
      }
    }"#;

    fn find<'a>(a: &'a [Advisory], cve: &str) -> Option<&'a Advisory> {
        a.iter().find(|x| x.cve == cve)
    }

    #[test]
    fn reads_fixed_versions_and_where_they_are() {
        let a = parse(EXPORT.as_bytes(), "bookworm").unwrap();
        let fixed = find(&a, "CVE-2026-9076").unwrap();
        assert_eq!(fixed.package, "openssl");
        assert_eq!(
            fixed.title,
            "Issue summary: A crafted PKCS#12 file can crash the application"
        );
        assert_eq!(
            fixed.status,
            Status::Fixed {
                version: "3.0.20-1~deb12u2".into(),
                pocket: "bookworm".into()
            },
            "in a point release"
        );
        assert_eq!(
            find(&a, "CVE-2026-1000").unwrap().status,
            Status::Fixed {
                version: "3.0.22-1~deb12u1".into(),
                pocket: "bookworm-security".into()
            }
        );
        assert_eq!(find(&a, "CVE-2026-1000").unwrap().severity, Severity::High);
        assert!(find(&a, "CVE-2000-1254").is_none(), "never affected");
        assert!(find(&a, "TEMP-0000000-ABCDEF").is_none());
    }

    #[test]
    fn explains_why_open_cves_are_open() {
        let a = parse(EXPORT.as_bytes(), "bookworm").unwrap();
        let note = |cve: &str| match &find(&a, cve).unwrap().status {
            Status::Open { note } => note.clone(),
            s => panic!("{s:?}"),
        };
        assert_eq!(note("CVE-2026-95691"), "no fix yet");
        assert_eq!(note("CVE-2026-14266"), "fixed in the next Debian point release");
        assert_eq!(
            note("CVE-2026-2222"),
            "Debian will not fix this in bookworm: Minor issue"
        );
        assert_eq!(find(&a, "CVE-2026-2222").unwrap().severity, Severity::Low, "low**");
        assert_eq!(note("CVE-2026-3333"), "fix postponed to a later update");
        assert_eq!(note("CVE-2026-4444"), "not triaged by Debian yet");
        assert_eq!(
            note("CVE-2026-5555"),
            "Debian no longer provides security updates for this package in bookworm"
        );
        assert!(find(&a, "CVE-2026-48092").is_none(), "unimportant");
    }

    #[test]
    fn untracked_releases_are_an_error() {
        let err = parse(EXPORT.as_bytes(), "bullseye").unwrap_err().to_string();
        assert!(err.contains("no data for 'bullseye'"), "{err}");
        assert_eq!(parse(EXPORT.as_bytes(), "trixie").unwrap().len(), 1);
    }
}
