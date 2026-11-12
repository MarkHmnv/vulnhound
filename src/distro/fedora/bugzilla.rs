//! Red Hat Bugzilla. Product Security files one "flaw" bug per CVE and one "tracker" bug per
//! affected Fedora package that blocks it. `[fedora-all]` trackers are filed against rawhide but
//! apply to every release.
//!
//! Anonymous clients get at most 20 bugs per request whatever `limit` says, so queries paginate
//! by the page size the server actually returns.

use crate::cve;
use crate::model::Severity;
use crate::progress::Progress;
use crate::rpmver::rpmvercmp;
use crate::system::{System, parallel_map, url_with_query};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::HashSet;

pub const BASE: &str = "https://bugzilla.redhat.com/rest/bug";
/// Keeps URLs short.
const COMPONENTS_PER_REQUEST: usize = 50;
/// No more than one server page.
const IDS_PER_REQUEST: usize = 20;
const REQUESTED_LIMIT: &str = "1000";
const PARALLEL_REQUESTS: usize = 8;

const TRACKER_FIELDS: &str = "id,summary,component,version,status,resolution,creation_time,cf_last_closed,blocks";
const FLAW_FIELDS: &str = "id,summary,severity,creation_time,cf_fixed_in";

pub fn bug_url(id: u64) -> String {
    format!("https://bugzilla.redhat.com/show_bug.cgi?id={id}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracker {
    pub id: u64,
    pub cve: String,
    pub component: String,
    pub summary: String,
    pub versions: Vec<String>,
    pub status: String,
    pub resolution: String,
    pub created: Option<DateTime<Utc>>,
    /// Last close time; also set on reopened trackers.
    pub closed: Option<DateTime<Utc>>,
    /// Flaw bug ids.
    pub flaws: Vec<u64>,
}

impl Tracker {
    pub fn is_open(&self) -> bool {
        self.status != "CLOSED"
    }

    /// When the fix landed in rawhide, for trackers closed as `RAWHIDE`.
    pub fn fixed_in_rawhide_at(&self) -> Option<DateTime<Utc>> {
        if self.is_open() || self.resolution != "RAWHIDE" {
            return None;
        }
        self.closed
    }

    /// The trailing `[fedora-all]` / `[fedora-NN]` tag decides, else the version field.
    pub fn applies_to(&self, release: &str) -> bool {
        if let Some(tag) = trailing_tag(&self.summary) {
            let tag = tag.to_ascii_lowercase();
            if let Some(rel) = tag.strip_prefix("fedora-") {
                return rel == "all" || rel.split(',').any(|r| r.trim() == release);
            }
        }
        self.versions.iter().any(|v| v == release)
    }
}

fn trailing_tag(summary: &str) -> Option<&str> {
    let s = summary.trim_end();
    let s = s.strip_suffix(']')?;
    let open = s.rfind('[')?;
    Some(&s[open + 1..])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flaw {
    pub id: u64,
    pub severity: Severity,
    pub summary: String,
    pub created: Option<DateTime<Utc>>,
    /// Free text like "git 2.56.1, git 2.55.1". Often empty.
    pub fixed_in: String,
}

#[derive(Deserialize)]
struct Page<T> {
    #[serde(default = "Vec::new")]
    bugs: Vec<T>,
    #[serde(default)]
    total_matches: Option<usize>,
}

#[derive(Deserialize)]
struct RawTracker {
    id: u64,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    component: Vec<String>,
    #[serde(default)]
    version: Vec<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    resolution: String,
    #[serde(default)]
    creation_time: Option<String>,
    #[serde(default)]
    cf_last_closed: Option<String>,
    #[serde(default)]
    blocks: Vec<u64>,
}

#[derive(Deserialize)]
struct RawFlaw {
    id: u64,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    creation_time: Option<String>,
    #[serde(default)]
    cf_fixed_in: Option<String>,
}

fn parse_time(s: Option<&str>) -> Option<DateTime<Utc>> {
    s.and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
}

/// One entry per CVE; trackers naming no CVE are dropped.
pub fn parse_trackers(body: &str) -> Result<Vec<Tracker>> {
    let page: Page<RawTracker> = serde_json::from_str(body).context("parsing Bugzilla trackers")?;
    let mut out = Vec::new();
    for b in page.bugs {
        let Some(component) = b.component.first().cloned() else {
            continue;
        };
        for id in cve::leading(&b.summary) {
            out.push(Tracker {
                id: b.id,
                cve: id,
                component: component.clone(),
                summary: b.summary.clone(),
                versions: b.version.clone(),
                status: b.status.clone(),
                resolution: b.resolution.clone(),
                created: parse_time(b.creation_time.as_deref()),
                closed: parse_time(b.cf_last_closed.as_deref()),
                flaws: b.blocks.clone(),
            });
        }
    }
    Ok(out)
}

pub fn parse_flaws(body: &str) -> Result<Vec<Flaw>> {
    let page: Page<RawFlaw> = serde_json::from_str(body).context("parsing Bugzilla flaws")?;
    Ok(page
        .bugs
        .into_iter()
        .map(|b| Flaw {
            id: b.id,
            severity: Severity::parse(&b.severity),
            summary: b.summary,
            created: parse_time(b.creation_time.as_deref()),
            fixed_in: b.cf_fixed_in.unwrap_or_default(),
        })
        .collect())
}

fn page_counts(body: &str) -> Result<(usize, Option<usize>)> {
    let page: Page<serde_json::Value> = serde_json::from_str(body).context("parsing Bugzilla response")?;
    Ok((page.bugs.len(), page.total_matches))
}

fn tracker_url(components: &[String], offset: usize) -> String {
    let offset = offset.to_string();
    let mut q: Vec<(&str, &str)> = vec![
        ("product", "Fedora"),
        ("keywords", "SecurityTracking"),
        ("keywords_type", "allwords"),
        ("resolution", "---"),
        ("resolution", "RAWHIDE"),
        ("include_fields", TRACKER_FIELDS),
        ("limit", REQUESTED_LIMIT),
        ("offset", &offset),
        // Keeps pages from shifting between requests.
        ("order", "bug_id"),
    ];
    q.extend(components.iter().map(|c| ("component", c.as_str())));
    url_with_query(BASE, &q)
}

/// Open trackers and trackers fixed only in rawhide.
pub fn trackers_for_components(
    sys: &dyn System,
    components: &[String],
    progress: &dyn Progress,
) -> Result<Vec<Tracker>> {
    let chunks: Vec<&[String]> = components.chunks(COMPONENTS_PER_REQUEST).collect();
    progress.add_total(chunks.len() as u64);

    // First page of every chunk tells how many pages follow.
    let first = parallel_map(&chunks, PARALLEL_REQUESTS, |c| {
        let r = sys.http_get(&tracker_url(c, 0));
        progress.advance(1);
        r
    });
    let mut bodies = Vec::new();
    let mut rest: Vec<(&[String], usize)> = Vec::new();
    for (chunk, body) in chunks.iter().zip(first) {
        let body = body?;
        let (got, total) = page_counts(&body)?;
        if got > 0 {
            let mut offset = got;
            while offset < total.unwrap_or(0) {
                rest.push((chunk, offset));
                offset += got;
            }
        }
        bodies.push(body);
    }
    progress.add_total(rest.len() as u64);
    for body in parallel_map(&rest, PARALLEL_REQUESTS, |(c, off)| {
        let r = sys.http_get(&tracker_url(c, *off));
        progress.advance(1);
        r
    }) {
        bodies.push(body?);
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for body in &bodies {
        for t in parse_trackers(body)? {
            if seen.insert((t.id, t.cve.clone())) {
                out.push(t);
            }
        }
    }
    Ok(out)
}

pub fn flaws_by_id(sys: &dyn System, ids: &[u64], progress: &dyn Progress) -> Result<Vec<Flaw>> {
    let chunks: Vec<&[u64]> = ids.chunks(IDS_PER_REQUEST).collect();
    progress.add_total(chunks.len() as u64);
    let bodies = parallel_map(&chunks, PARALLEL_REQUESTS, |chunk| {
        let ids = chunk.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        let limit = chunk.len().to_string();
        let r = sys.http_get(&url_with_query(
            BASE,
            &[("id", &ids), ("include_fields", FLAW_FIELDS), ("limit", &limit)],
        ));
        progress.advance(1);
        r
    });
    let mut out = Vec::new();
    for body in bodies {
        out.extend(parse_flaws(&body?)?);
    }
    Ok(out)
}

/// Whether the flaw's "fixed in" text (`name version, ...`) covers `installed_version`: at least a
/// fixed version of the same `major.minor` series, or at least the newest one.
pub fn fixed_in_covers(fixed_in: &str, component: &str, installed_version: &str) -> bool {
    let versions: Vec<&str> = fixed_in
        .split([',', ';'])
        .filter_map(|entry| {
            let entry = entry.trim();
            let (name, version) = match entry.rsplit_once(char::is_whitespace) {
                Some((n, v)) => (n.trim(), v.trim()),
                None => ("", entry),
            };
            let name_ok = name.is_empty() || name.eq_ignore_ascii_case(component);
            let looks_like_version = version.chars().next().is_some_and(|c| c.is_ascii_digit());
            (name_ok && looks_like_version).then_some(version)
        })
        .collect();
    if versions.is_empty() {
        return false;
    }
    let at_least = |v: &str| rpmvercmp(installed_version, v) != Ordering::Less;
    let same_series = |v: &str| series(v) == series(installed_version);
    if versions.iter().any(|v| same_series(v) && at_least(v)) {
        return true;
    }
    let newest = versions
        .iter()
        .copied()
        .max_by(|a, b| rpmvercmp(a, b))
        .expect("non-empty");
    at_least(newest)
}

fn series(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// Keeps leading tags like `[Exploits (KEV)]`; drops CVE ids, `component:` prefixes and the
/// `[fedora-…]` tag.
pub fn display_title(summary: &str, component: &str) -> String {
    let mut s = summary.trim();
    if let Some(tag) = trailing_tag(s) {
        s = s[..s.len() - tag.len() - 2].trim_end();
    }
    let (tags, mut s) = cve::split_leading_tags(s);
    while let Some(tok) = s.split_whitespace().next() {
        if !cve::is_cve_token(tok) {
            break;
        }
        s = s[tok.len()..].trim_start();
    }
    for _ in 0..2 {
        let n = component.len();
        let matches = s.get(..n).is_some_and(|p| p.eq_ignore_ascii_case(component));
        match s.get(n..).filter(|_| matches).and_then(|r| r.strip_prefix(':')) {
            Some(rest) => s = rest.trim_start(),
            None => break,
        }
    }
    if tags.is_empty() {
        s.to_string()
    } else {
        format!("{tags} {s}")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::progress::Silent;
    use crate::system::fake::FakeSystem;

    /// Trimmed real tracker search response.
    pub const GIT_TRACKERS: &str = r#"{"bugs":[
      {"id":2571477,"status":"CLOSED","resolution":"RAWHIDE","version":["rawhide"],"component":["git"],
       "blocks":[2567365],"creation_time":"2026-11-11T07:03:10Z","cf_last_closed":"2026-11-11T09:00:00Z",
       "summary":"CVE-2026-111760 git: Git: Arbitrary code execution via unsafe submodule metadata during recursive clones [fedora-all]"},
      {"id":2571484,"status":"CLOSED","resolution":"RAWHIDE","version":["rawhide"],"component":["git"],
       "blocks":[2567369],"creation_time":"2026-11-11T07:04:00Z",
       "summary":"CVE-2026-113408 git: git: Unintended file writes via malformed unborn HEAD advertisement [fedora-all]"},
      {"id":2408120,"status":"NEW","resolution":"","version":["43"],"component":["aerc"],
       "blocks":[2407260],"creation_time":"2025-10-30T19:44:39Z",
       "summary":"CVE-2025-58189 aerc: go crypto/tls ALPN negotiation error [fedora-43]"},
      {"id":2173769,"status":"NEW","resolution":"","version":["rawhide"],"component":["distribution"],
       "blocks":[],"summary":"[Tracker] Invalid Security Bugs"}
    ],"limit":20,"offset":0,"total_matches":4}"#;

    fn page(ids: std::ops::Range<u64>, total: usize) -> String {
        let bugs: Vec<String> = ids
            .map(|i| format!(r#"{{"id":{i},"summary":"CVE-2026-{i:05} c: x [fedora-all]","component":["c"]}}"#))
            .collect();
        format!(r#"{{"bugs":[{}],"limit":20,"total_matches":{total}}}"#, bugs.join(","))
    }

    #[test]
    fn parses_trackers_and_drops_ones_without_cve() {
        let t = parse_trackers(GIT_TRACKERS).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].cve, "CVE-2026-111760");
        assert_eq!(t[0].component, "git");
        assert_eq!(t[0].flaws, vec![2567365]);
        assert!(!t[0].is_open());
        assert_eq!(t[0].created.unwrap().to_rfc3339(), "2026-11-11T07:03:10+00:00");
        assert!(t[2].is_open());
    }

    #[test]
    fn rawhide_fix_time_only_for_trackers_closed_as_rawhide() {
        let t = parse_trackers(GIT_TRACKERS).unwrap();
        assert_eq!(
            t[0].fixed_in_rawhide_at().unwrap().to_rfc3339(),
            "2026-11-11T09:00:00+00:00"
        );
        assert_eq!(t[1].fixed_in_rawhide_at(), None, "close time unknown");
        let mut reopened = t[0].clone();
        reopened.status = "NEW".into();
        reopened.resolution = String::new();
        assert_eq!(
            reopened.fixed_in_rawhide_at(),
            None,
            "reopened trackers keep a close time"
        );
    }

    #[test]
    fn release_tags_decide_applicability() {
        let t = parse_trackers(GIT_TRACKERS).unwrap();
        assert!(t[0].applies_to("45"), "[fedora-all] applies everywhere");
        assert!(t[2].applies_to("43"));
        assert!(!t[2].applies_to("45"), "[fedora-43] does not apply to 45");

        let mut untagged = t[2].clone();
        untagged.summary = "CVE-2025-1 foo: bar".into();
        untagged.versions = vec!["45".into()];
        assert!(untagged.applies_to("45"));
        assert!(!untagged.applies_to("44"));
    }

    #[test]
    fn fixed_in_matches_same_series_or_newest() {
        let fi = "git 2.56.1, git 2.55.1, git 2.50.2";
        assert!(!fixed_in_covers(fi, "git", "2.56.0"));
        assert!(fixed_in_covers(fi, "git", "2.56.1"));
        assert!(fixed_in_covers(fi, "git", "2.55.1"));
        assert!(
            !fixed_in_covers(fi, "git", "2.54.0"),
            "2.54 has its own backport not listed here"
        );
        assert!(fixed_in_covers(fi, "git", "2.57.0"), "newer than every fixed version");
        assert!(!fixed_in_covers("", "git", "9.9"));
        assert!(!fixed_in_covers("openssl 3.5.1", "git", "9.9"), "other component");
        assert!(fixed_in_covers("1.2.3", "foo", "1.2.4"), "bare version");
        assert!(
            !fixed_in_covers("libfoo before 2.0", "libfoo", "1.0"),
            "not a version list"
        );
    }

    #[test]
    fn shortens_titles() {
        assert_eq!(
            display_title("CVE-2026-113408 git: git: Unintended file writes [fedora-all]", "git"),
            "Unintended file writes"
        );
        assert_eq!(
            display_title("CVE-2026-111760 git: Git: Arbitrary code execution", "git"),
            "Arbitrary code execution"
        );
        assert_eq!(
            display_title(
                "[Exploits (KEV)] CVE-2026-46333 kernel: Read root-owned files",
                "kernel"
            ),
            "[Exploits (KEV)] Read root-owned files"
        );
        assert_eq!(
            display_title("CVE-2026-75803 openssl: AEAD forgeries [fedora-all]", "samba"),
            "openssl: AEAD forgeries",
            "a bundled library's name stays"
        );
        assert_eq!(display_title("CVE-2026-1111 CVE-2026-2222 gitk: x", "git"), "gitk: x");
    }

    #[test]
    fn tracker_query_filters() {
        let sys = FakeSystem::new().on("offset=0", GIT_TRACKERS);
        let t = trackers_for_components(&sys, &["git".into(), "libstdc++".into()], &Silent).unwrap();
        assert_eq!(t.len(), 3);
        let reqs = sys.requests();
        assert_eq!(reqs.len(), 1, "total_matches fits in the first page");
        assert!(reqs[0].contains("product=Fedora"));
        assert!(reqs[0].contains("keywords=SecurityTracking"));
        assert!(reqs[0].contains("resolution=---&resolution=RAWHIDE"));
        assert!(reqs[0].contains("component=git&component=libstdc%2B%2B"));
        assert!(reqs[0].contains("order=bug_id"));
    }

    #[test]
    fn tracker_query_follows_the_server_page_size() {
        let sys = FakeSystem::new()
            .on("offset=0&", &page(0..20, 45))
            .on("offset=20&", &page(20..40, 45))
            .on("offset=40&", &page(40..45, 45));
        let t = trackers_for_components(&sys, &["c".into()], &Silent).unwrap();
        assert_eq!(t.len(), 45);
        assert_eq!(sys.requests().len(), 3);
    }

    #[test]
    fn tracker_query_splits_components_into_chunks() {
        let sys = FakeSystem::new().on("rest/bug", r#"{"bugs":[],"total_matches":0}"#);
        let comps: Vec<String> = (0..120).map(|i| format!("pkg{i}")).collect();
        trackers_for_components(&sys, &comps, &Silent).unwrap();
        assert_eq!(sys.requests().len(), 3);
    }

    #[test]
    fn tracker_query_dedupes_shifted_pages() {
        let sys = FakeSystem::new()
            .on("offset=0&", &page(0..20, 25))
            .on("offset=20&", &page(15..25, 25));
        let t = trackers_for_components(&sys, &["c".into()], &Silent).unwrap();
        assert_eq!(t.len(), 25);
    }

    #[test]
    fn fetches_flaws_in_batches_with_explicit_limit() {
        let sys = FakeSystem::new().on("rest/bug?id=", r#"{"bugs":[]}"#);
        let ids: Vec<u64> = (1..=45).collect();
        flaws_by_id(&sys, &ids, &Silent).unwrap();
        let reqs = sys.requests();
        assert_eq!(reqs.len(), 3);
        assert!(
            reqs.iter()
                .any(|r| r.contains("id=1%2C2%2C3") && r.contains("limit=20"))
        );
        assert!(reqs.iter().any(|r| r.contains("id=41%2C") && r.contains("limit=5")));
    }
}
