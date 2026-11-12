//! Kernel CVEs from the kernel CNA, via OSV's `Linux` export (the OSV query API cannot match
//! kernel versions). The export is ~60 MB, so a compact index is cached and refreshed daily.
//!
//! Version matching is only valid for kernels that follow upstream stable releases (Fedora, Arch),
//! not for distros that backport fixes (Debian, Ubuntu, RHEL).

use crate::progress::Progress;
use crate::system::System;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::io::Read;
use std::time::{Duration, SystemTime};

pub const OSV_EXPORT: &str = "https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip";
const CACHE_FILE: &str = "osv-linux-index.json";
const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Bump when the index format changes.
const INDEX_FORMAT: u32 = 1;

pub fn cve_url(id: &str) -> String {
    format!("https://osv.dev/vulnerability/{id}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCve {
    pub id: String,
    pub summary: String,
    /// `None` when no release fixes it yet.
    pub fixed_in: Option<String>,
}

/// Ranges are OSV events: `introduced` followed by `fixed` versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub summary: String,
    pub ranges: Vec<Vec<Event>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Event {
    Introduced(String),
    Fixed(String),
}

#[derive(Serialize, Deserialize)]
struct Index {
    format: u32,
    records: Vec<Record>,
}

/// The cached index if it is fresh, else a new download; a stale cache if the download fails.
pub fn index(sys: &dyn System, progress: &dyn Progress, warnings: &mut Vec<String>) -> Result<Vec<Record>> {
    let cached = sys.cache_read(CACHE_FILE).and_then(|(text, written)| {
        let index: Index = serde_json::from_str(&text).ok()?;
        (index.format == INDEX_FORMAT).then_some((index.records, written))
    });
    let age = |written: SystemTime| SystemTime::now().duration_since(written).unwrap_or_default();
    if let Some((records, written)) = &cached
        && age(*written) < CACHE_MAX_AGE
    {
        return Ok(records.clone());
    }

    progress.detail("downloading about 60 MB from OSV, once a day");
    let fresh = sys
        .http_get_bytes(OSV_EXPORT)
        .and_then(|zip| {
            progress.detail("indexing");
            parse_export(&zip)
        })
        .context("downloading kernel CVE data from OSV");
    match (fresh, cached) {
        (Ok(records), _) => {
            let index = Index {
                format: INDEX_FORMAT,
                records,
            };
            if let Err(e) = sys.cache_write(CACHE_FILE, &serde_json::to_string(&index)?) {
                warnings.push(format!(
                    "cannot cache kernel CVE data, it will be downloaded again: {e:#}"
                ));
            }
            Ok(index.records)
        }
        (Err(e), Some((records, written))) => {
            let days = age(written).as_secs() / 86_400;
            warnings.push(format!("kernel CVE data is {days} days old, refreshing failed: {e:#}"));
            Ok(records)
        }
        (Err(e), None) => Err(e),
    }
}

#[derive(Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize)]
struct OsvPackage {
    #[serde(default)]
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// Skips withdrawn CVEs and ones without version ranges (pre-2024 records only list commits).
pub fn parse_export(zip: &[u8]) -> Result<Vec<Record>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).context("reading the OSV export")?;
    let mut records = Vec::new();
    let mut text = String::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("reading the OSV export")?;
        let name = file.name().context("reading the OSV export")?.into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        text.clear();
        file.read_to_string(&mut text)
            .with_context(|| format!("reading {name} from the OSV export"))?;
        let osv: OsvRecord =
            serde_json::from_str(&text).with_context(|| format!("parsing {name} from the OSV export"))?;
        if let Some(record) = to_record(osv) {
            records.push(record);
        }
    }
    if records.is_empty() {
        bail!("the OSV export has no kernel CVEs");
    }
    Ok(records)
}

fn to_record(osv: OsvRecord) -> Option<Record> {
    if osv.withdrawn.is_some() {
        return None;
    }
    let ranges: Vec<Vec<Event>> = osv
        .affected
        .iter()
        .filter(|a| a.package.as_ref().is_some_and(|p| p.ecosystem == "Linux"))
        .flat_map(|a| &a.ranges)
        .filter(|r| r.kind == "ECOSYSTEM")
        .map(|r| {
            r.events
                .iter()
                .flat_map(|e| e.iter())
                .filter_map(|(k, v)| {
                    let v = v.as_str()?.to_string();
                    match k.as_str() {
                        "introduced" => Some(Event::Introduced(v)),
                        "fixed" => Some(Event::Fixed(v)),
                        _ => None,
                    }
                })
                .collect()
        })
        .collect();
    (!ranges.is_empty()).then_some(Record {
        id: osv.id,
        summary: osv.summary,
        ranges,
    })
}

pub fn affecting(records: &[Record], version: &str) -> Result<Vec<KernelCve>> {
    if parse_version(version).is_none() {
        bail!("cannot compare kernel version '{version}'");
    }
    let mut out: Vec<KernelCve> = records
        .iter()
        .filter_map(|r| {
            let fixed_in = r.ranges.iter().find_map(|range| range_match(range, version))?;
            Some(KernelCve {
                id: r.id.clone(),
                summary: r.summary.clone(),
                fixed_in,
            })
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// `Some(fix)` if the range covers `version`. A `fixed` closes the span opened by `introduced`;
/// further `fixed` events in the same span belong to other stable lines.
fn range_match(events: &[Event], version: &str) -> Option<Option<String>> {
    let mut open: Option<&str> = None;
    for e in events {
        match e {
            Event::Introduced(v) => open = Some(v),
            Event::Fixed(fixed) => {
                if let Some(start) = open.take()
                    && cmp(start, version) != Ordering::Greater
                    && cmp(version, fixed) == Ordering::Less
                {
                    return Some(Some(fixed.clone()));
                }
            }
        }
    }
    open.filter(|start| cmp(start, version) != Ordering::Greater)
        .map(|_| None)
}

fn parse_version(v: &str) -> Option<Vec<u64>> {
    v.split('.').map(|p| p.parse().ok()).collect()
}

/// "7.4" == "7.4.0". Unparsable versions compare equal, which never satisfies `v < fixed`.
fn cmp(a: &str, b: &str) -> Ordering {
    let (Some(a), Some(b)) = (parse_version(a), parse_version(b)) else {
        return Ordering::Equal;
    };
    let len = a.len().max(b.len());
    let part = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
    (0..len)
        .map(|i| part(&a, i).cmp(&part(&b, i)))
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;
    use std::io::Write;

    /// Trimmed real OSV records.
    pub const CVE_2026_99286: &str = r#"{"id":"CVE-2026-99286","summary":"xen-netback: Fix XenBus connection failure cleanup",
      "published":"2026-11-10T00:00:00Z","affected":[
        {"ranges":[{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
          "events":[{"introduced":"c0b220cf7d80"},{"fixed":"07aca7d25ce8"}]}]},
        {"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[
          {"type":"ECOSYSTEM","events":[{"introduced":"6.19.0"},{"fixed":"7.2.16"}]},
          {"type":"ECOSYSTEM","events":[{"introduced":"7.3.0"},{"fixed":"7.3.4"}]}]}]}"#;
    pub const CVE_2026_64538: &str = r#"{"id":"CVE-2026-64538","summary":"ipv6: Fix null-ptr-deref in fib6_nh_mtu_change()",
      "affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[
          {"type":"ECOSYSTEM","events":[{"introduced":"6.13.0"},{"fixed":"6.18.40"}]},
          {"type":"ECOSYSTEM","events":[{"introduced":"6.19.0"},{"fixed":"7.1.5"}]}]}]}"#;
    pub const UNFIXED: &str = r#"{"id":"CVE-2026-99999","summary":"net: no fix yet",
      "affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[
          {"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#;
    pub const WITHDRAWN: &str = r#"{"id":"CVE-2026-99998","summary":"rejected","withdrawn":"2026-11-01T00:00:00Z",
      "affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[
          {"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#;
    pub const GIT_ONLY: &str = r#"{"id":"CVE-2022-0001","summary":"old","affected":[
        {"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abcdef"}]}]}]}"#;

    pub fn export(records: &[&str]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (i, r) in records.iter().enumerate() {
            zip.start_file(format!("{i}.json"), opts).unwrap();
            zip.write_all(r.as_bytes()).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    pub fn sample_export() -> Vec<u8> {
        export(&[CVE_2026_99286, CVE_2026_64538, UNFIXED, WITHDRAWN, GIT_ONLY])
    }

    fn ids(cves: &[KernelCve]) -> Vec<&str> {
        cves.iter().map(|c| c.id.as_str()).collect()
    }

    #[test]
    fn compares_versions_numerically() {
        assert_eq!(cmp("7.3.10", "7.3.9"), Ordering::Greater);
        assert_eq!(cmp("7.4", "7.4.0"), Ordering::Equal);
        assert_eq!(cmp("0", "2.6.39.2"), Ordering::Less);
        assert_eq!(cmp("2.6.39.2", "2.6.39"), Ordering::Greater);
    }

    #[test]
    fn parses_export_and_drops_withdrawn_and_git_only_records() {
        let records = parse_export(&sample_export()).unwrap();
        assert_eq!(
            records.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["CVE-2026-99286", "CVE-2026-64538", "CVE-2026-99999"]
        );
        assert_eq!(
            records[0].ranges[1],
            vec![Event::Introduced("7.3.0".into()), Event::Fixed("7.3.4".into())]
        );
    }

    #[test]
    fn matches_versions_against_ranges() {
        let records = parse_export(&sample_export()).unwrap();
        let cves = affecting(&records, "7.3.3").unwrap();
        assert_eq!(ids(&cves), vec!["CVE-2026-99286", "CVE-2026-99999"]);
        assert_eq!(cves[0].fixed_in.as_deref(), Some("7.3.4"));
        assert_eq!(cves[1].fixed_in, None, "no fix anywhere yet");

        assert_eq!(ids(&affecting(&records, "7.3.4").unwrap()), vec!["CVE-2026-99999"]);
        assert_eq!(
            ids(&affecting(&records, "7.1.4").unwrap()),
            vec!["CVE-2026-64538", "CVE-2026-99286", "CVE-2026-99999"]
        );
        assert_eq!(
            affecting(&records, "7.1.4").unwrap()[1].fixed_in.as_deref(),
            Some("7.2.16"),
            "7.1 has no fix of its own: the first fixed release is in a newer line"
        );
        assert_eq!(
            ids(&affecting(&records, "7.2.0").unwrap()),
            vec!["CVE-2026-99286", "CVE-2026-99999"]
        );
    }

    #[test]
    fn extra_fixed_events_close_nothing_new() {
        let range = vec![
            Event::Introduced("5.5.0".into()),
            Event::Fixed("5.10.96".into()),
            Event::Fixed("5.15.19".into()),
        ];
        assert_eq!(range_match(&range, "5.10.50"), Some(Some("5.10.96".into())));
        assert_eq!(range_match(&range, "5.12.0"), None);
    }

    fn cves_affecting(sys: &FakeSystem, version: &str, warnings: &mut Vec<String>) -> Result<Vec<KernelCve>> {
        affecting(&index(sys, &crate::progress::Silent, warnings)?, version)
    }

    #[test]
    fn downloads_once_and_then_uses_the_cache() {
        let sys = FakeSystem::new().on_bytes("Linux/all.zip", &sample_export());
        let mut warnings = Vec::new();
        assert_eq!(cves_affecting(&sys, "7.3.3", &mut warnings).unwrap().len(), 2);
        assert_eq!(cves_affecting(&sys, "7.3.3", &mut warnings).unwrap().len(), 2);
        assert_eq!(sys.requests().len(), 1);
        assert!(warnings.is_empty());
    }

    fn cached_index() -> String {
        let records = parse_export(&export(&[CVE_2026_64538])).unwrap();
        serde_json::to_string(&Index {
            format: INDEX_FORMAT,
            records,
        })
        .unwrap()
    }

    #[test]
    fn refreshes_a_day_old_cache() {
        let sys = FakeSystem::new().on_bytes("Linux/all.zip", &sample_export()).cached(
            CACHE_FILE,
            &cached_index(),
            Duration::from_secs(25 * 3600),
        );
        let cves = cves_affecting(&sys, "7.3.3", &mut Vec::new()).unwrap();
        assert_eq!(cves.len(), 2, "fresh data, not the cached record");
    }

    #[test]
    fn falls_back_to_a_stale_cache_with_a_warning() {
        let sys = FakeSystem::new().fail("Linux/all.zip", "offline").cached(
            CACHE_FILE,
            &cached_index(),
            Duration::from_secs(3 * 86_400),
        );
        let mut warnings = Vec::new();
        let cves = cves_affecting(&sys, "7.1.4", &mut warnings).unwrap();
        assert_eq!(ids(&cves), vec!["CVE-2026-64538"]);
        assert!(
            warnings[0].contains("3 days old") && warnings[0].contains("offline"),
            "{warnings:?}"
        );
    }

    #[test]
    fn ignores_a_cache_in_an_old_format() {
        let sys = FakeSystem::new().on_bytes("Linux/all.zip", &sample_export()).cached(
            CACHE_FILE,
            r#"{"format":0,"records":[]}"#,
            Duration::ZERO,
        );
        assert_eq!(cves_affecting(&sys, "7.3.3", &mut Vec::new()).unwrap().len(), 2);
    }

    #[test]
    fn errors_without_data_or_with_an_odd_version() {
        let sys = FakeSystem::new().fail("Linux/all.zip", "offline");
        assert!(cves_affecting(&sys, "7.3.3", &mut Vec::new()).is_err());
        let records = parse_export(&sample_export()).unwrap();
        assert!(
            affecting(&records, "7.4.0-rc2").is_err(),
            "would match every open-ended range otherwise"
        );
    }
}
