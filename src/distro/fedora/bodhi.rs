//! Bodhi, Fedora's update system.

use crate::cve;
use crate::model::Severity;
use crate::progress::Progress;
use crate::system::{System, url_with_query};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;

pub const BASE: &str = "https://bodhi.fedoraproject.org/updates/";
const RELEASES: &str = "https://bodhi.fedoraproject.org/releases/";
const BUILDS_PER_REQUEST: usize = 20;
const ROWS_PER_PAGE: &str = "100";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodhiUpdate {
    pub alias: String,
    /// security, bugfix, enhancement or newpackage.
    pub kind: String,
    pub severity: Severity,
    /// stable, testing, pending, ...
    pub status: String,
    pub builds: Vec<String>,
    pub bug_ids: Vec<u64>,
    /// CVE ids in the linked bugs, title or notes.
    pub cves: Vec<String>,
    pub url: String,
}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    updates: Vec<RawUpdate>,
    #[serde(default)]
    pages: u32,
}

#[derive(Deserialize)]
struct RawUpdate {
    alias: String,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    builds: Vec<RawBuild>,
    #[serde(default)]
    bugs: Vec<RawBug>,
}

#[derive(Deserialize)]
struct RawBuild {
    nvr: String,
}

#[derive(Deserialize)]
struct RawBug {
    bug_id: u64,
    #[serde(default)]
    title: Option<String>,
}

impl From<RawUpdate> for BodhiUpdate {
    fn from(u: RawUpdate) -> Self {
        let mut text = format!("{}\n{}", u.title, u.notes);
        for b in &u.bugs {
            if let Some(t) = &b.title {
                text.push('\n');
                text.push_str(t);
            }
        }
        Self {
            url: if u.url.is_empty() {
                format!("{BASE}{}", u.alias)
            } else {
                u.url
            },
            alias: u.alias,
            kind: u.kind,
            severity: Severity::parse(&u.severity),
            status: u.status,
            builds: u.builds.into_iter().map(|b| b.nvr).collect(),
            bug_ids: u.bugs.iter().map(|b| b.bug_id).collect(),
            cves: cve::extract(&text),
        }
    }
}

pub fn parse_page(body: &str) -> Result<(Vec<BodhiUpdate>, u32)> {
    let page: Page = serde_json::from_str(body).context("parsing Bodhi response")?;
    Ok((page.updates.into_iter().map(Into::into).collect(), page.pages))
}

/// Updates containing the given builds (e.g. `git-2.56.1-1.fc45`).
pub fn updates_for_builds(sys: &dyn System, builds: &[String], progress: &dyn Progress) -> Result<Vec<BodhiUpdate>> {
    let mut out: Vec<BodhiUpdate> = Vec::new();
    progress.add_total(builds.chunks(BUILDS_PER_REQUEST).len() as u64);
    for chunk in builds.chunks(BUILDS_PER_REQUEST) {
        let mut page = 1u32;
        loop {
            let page_str = page.to_string();
            let mut query: Vec<(&str, &str)> = chunk.iter().map(|b| ("builds", b.as_str())).collect();
            query.push(("rows_per_page", ROWS_PER_PAGE));
            query.push(("page", &page_str));
            let body = sys.http_get(&url_with_query(BASE, &query))?;
            progress.advance(1);
            let (updates, pages) = parse_page(&body)?;
            for u in updates {
                if !out.iter().any(|o| o.alias == u.alias) {
                    out.push(u);
                }
            }
            if page >= pages {
                break;
            }
            if page == 1 {
                progress.add_total(u64::from(pages - 1));
            }
            page += 1;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branched {
    No,
    At(DateTime<Utc>),
}

impl Branched {
    pub fn has_rawhide_fix_from(self, t: DateTime<Utc>) -> bool {
        match self {
            Branched::No => true,
            Branched::At(branch) => t < branch,
        }
    }
}

#[derive(Deserialize)]
struct ReleasesPage {
    #[serde(default)]
    releases: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct DatedPage {
    #[serde(default)]
    updates: Vec<DatedUpdate>,
    #[serde(default)]
    pages: u32,
}

#[derive(Deserialize)]
struct DatedUpdate {
    #[serde(default)]
    date_submitted: Option<String>,
}

/// When `release` branched from rawhide: the first `fedora-release` update of the next release.
/// No next release in Bodhi means `release` is rawhide itself.
pub fn branched(sys: &dyn System, release: &str) -> Result<Branched> {
    let n: u32 = release
        .parse()
        .with_context(|| format!("release '{release}' is not a number"))?;
    let next = format!("F{}", n + 1);

    let body = sys.http_get(&url_with_query(RELEASES, &[("name", &next)]))?;
    let page: ReleasesPage = serde_json::from_str(&body).context("parsing Bodhi releases")?;
    if page.releases.is_empty() {
        return Ok(Branched::No);
    }

    // Newest first, so the first update is on the last page.
    let url = |page: &str| {
        url_with_query(
            BASE,
            &[
                ("releases", &next),
                ("packages", "fedora-release"),
                ("rows_per_page", "1"),
                ("page", page),
            ],
        )
    };
    let parse = |body: &str| -> Result<DatedPage> { serde_json::from_str(body).context("parsing Bodhi response") };
    let mut page = parse(&sys.http_get(&url("1"))?)?;
    if page.pages > 1 {
        page = parse(&sys.http_get(&url(&page.pages.to_string()))?)?;
    }
    let Some(date) = page.updates.first().and_then(|u| u.date_submitted.as_deref()) else {
        bail!("Bodhi has no fedora-release update for {next}");
    };
    let date = NaiveDateTime::parse_from_str(date, "%Y-%m-%d %H:%M:%S")
        .with_context(|| format!("parsing Bodhi date '{date}'"))?;
    Ok(Branched::At(date.and_utc()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::progress::Silent;
    use crate::system::fake::FakeSystem;

    /// Trimmed real responses from bodhi.fedoraproject.org.
    pub const GIT_AND_KERNEL: &str = r#"{
      "updates": [
        {"alias": "FEDORA-2026-5c62077075", "type": "enhancement", "severity": "unspecified",
         "status": "testing", "title": "git-2.56.1-1.fc45", "notes": "update to 2.56.1",
         "url": "https://bodhi.fedoraproject.org/updates/FEDORA-2026-5c62077075",
         "builds": [{"nvr": "git-2.56.1-1.fc45"}], "bugs": []},
        {"alias": "FEDORA-2026-655049a906", "type": "security", "severity": "medium",
         "status": "stable", "title": "kernel-7.3.3-300.fc45 kernel-headers-7.3.3-300.fc45",
         "notes": "The 7.3.3 stable kernel rebase", "url": "",
         "builds": [{"nvr": "kernel-7.3.3-300.fc45"}, {"nvr": "kernel-headers-7.3.3-300.fc45"}],
         "bugs": [{"bug_id": 2570001, "title": "CVE-2026-4242 kernel: something [fedora-all]", "security": true}]}
      ],
      "page": 1, "pages": 1, "rows_per_page": 100, "total": 2
    }"#;

    #[test]
    fn parses_updates_with_cves_from_bug_titles() {
        let (u, pages) = parse_page(GIT_AND_KERNEL).unwrap();
        assert_eq!(pages, 1);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].kind, "enhancement");
        assert_eq!(u[0].severity, Severity::Unknown);
        assert!(u[0].cves.is_empty());
        assert_eq!(u[1].severity, Severity::Medium);
        assert_eq!(
            u[1].builds,
            vec!["kernel-7.3.3-300.fc45", "kernel-headers-7.3.3-300.fc45"]
        );
        assert_eq!(u[1].bug_ids, vec![2570001]);
        assert_eq!(u[1].cves, vec!["CVE-2026-4242"]);
        assert_eq!(
            u[1].url,
            "https://bodhi.fedoraproject.org/updates/FEDORA-2026-655049a906"
        );
    }

    #[test]
    fn follows_pagination_and_dedupes() {
        let p1 = r#"{"updates":[{"alias":"A","builds":[{"nvr":"a-1-1"}]}],"pages":2}"#;
        let p2 = r#"{"updates":[{"alias":"A","builds":[{"nvr":"a-1-1"}]},{"alias":"B"}],"pages":2}"#;
        let sys = FakeSystem::new().on("&page=1", p1).on("&page=2", p2);
        let u = updates_for_builds(&sys, &["a-1-1".into()], &Silent).unwrap();
        assert_eq!(u.iter().map(|x| x.alias.as_str()).collect::<Vec<_>>(), vec!["A", "B"]);
        assert_eq!(sys.requests().len(), 2);
    }

    #[test]
    fn batches_builds() {
        let sys = FakeSystem::new().on("bodhi", r#"{"updates":[],"pages":1}"#);
        let builds: Vec<String> = (0..45).map(|i| format!("p{i}-1-1")).collect();
        updates_for_builds(&sys, &builds, &Silent).unwrap();
        assert_eq!(sys.requests().len(), 3);
        assert!(sys.requests()[0].contains("builds=p0-1-1&builds=p1-1-1"));
    }

    pub const F46_RELEASE: &str = r#"{"releases":[{"name":"F46","branch":"rawhide"}],"pages":1}"#;
    pub const F46_FIRST_UPDATE: &str = r#"{"updates":[{"alias":"FEDORA-2026-1","date_submitted":"2026-08-11 19:07:02",
        "title":"fedora-release-46-0.1 fedora-repos-46-0.1"}],"pages":1}"#;

    #[test]
    fn branch_point_is_the_first_update_of_the_next_release() {
        let sys = FakeSystem::new()
            .on("releases/?name=F46", F46_RELEASE)
            .on(
                "&page=1",
                r#"{"updates":[{"date_submitted":"2026-10-01 00:00:00"}],"pages":3}"#,
            )
            .on("&page=3", F46_FIRST_UPDATE);
        let b = branched(&sys, "45").unwrap();
        assert_eq!(b, Branched::At("2026-08-11T19:07:02Z".parse().unwrap()));
        assert!(sys.requests()[1].contains("packages=fedora-release"));
        assert!(b.has_rawhide_fix_from("2012-01-18T23:10:18Z".parse().unwrap()));
        assert!(!b.has_rawhide_fix_from("2026-11-11T09:00:00Z".parse().unwrap()));
    }

    #[test]
    fn rawhide_has_every_rawhide_fix() {
        let sys = FakeSystem::new().on("releases/?name=F47", r#"{"releases":[],"pages":0}"#);
        let b = branched(&sys, "46").unwrap();
        assert_eq!(b, Branched::No);
        assert!(b.has_rawhide_fix_from("2026-11-11T09:00:00Z".parse().unwrap()));
        assert_eq!(sys.requests().len(), 1);
    }

    #[test]
    fn branch_point_errors() {
        assert!(branched(&FakeSystem::new(), "rawhide").is_err());
        let sys = FakeSystem::new()
            .on("releases/?name=F46", F46_RELEASE)
            .on("releases=F46", r#"{"updates":[],"pages":0}"#);
        assert!(branched(&sys, "45").is_err());
    }
}
