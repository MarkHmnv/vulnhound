//! CVEs of applications from the NIST National Vulnerability Database, by CPE vendor and product.
//!
//! NVD filters by product and version; the CPE match criteria of each CVE are checked here again.
//! Without an API key NVD allows 5 requests per 30 seconds.

use super::version;
use crate::model::Severity;
use crate::system::{System, url_with_query};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

pub const API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE: usize = 2000;
const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Bump when [`Cached`] changes.
const CACHE_FORMAT: u32 = 3;
const ATTEMPTS: usize = 4;
const RETRY_PAUSE: Duration = Duration::from_secs(5);

pub fn cve_url(id: &str) -> String {
    format!("https://nvd.nist.gov/vuln/detail/{id}")
}

/// A CPE application name, as NVD spells it (`notepad\+\+` keeps its escapes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cpe {
    pub vendor: &'static str,
    pub product: &'static str,
}

impl Cpe {
    pub fn match_string(&self) -> String {
        format!("cpe:2.3:a:{}:{}:*:*:*:*:*:*:*:*", self.vendor, self.product)
    }
}

/// A CVE reduced to what matching needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub severity: Severity,
    pub summary: String,
    /// Any one of them makes a version vulnerable.
    pub ranges: Vec<Range>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    pub exact: Option<String>,
    pub start_including: Option<String>,
    pub start_excluding: Option<String>,
    pub end_including: Option<String>,
    pub end_excluding: Option<String>,
}

impl Range {
    pub fn contains(&self, v: &str) -> bool {
        let c = |b: &Option<String>| b.as_deref().map(|b| version::cmp(v, b));
        if let Some(o) = c(&self.exact) {
            return o == Ordering::Equal;
        }
        c(&self.start_including).is_none_or(|o| o != Ordering::Less)
            && c(&self.start_excluding).is_none_or(|o| o == Ordering::Greater)
            && c(&self.end_including).is_none_or(|o| o != Ordering::Greater)
            && c(&self.end_excluding).is_none_or(|o| o == Ordering::Less)
    }

    /// The first version outside the range, if the data says.
    pub fn fixed_in(&self) -> Option<&str> {
        self.end_excluding.as_deref()
    }
}

impl Cve {
    pub fn affects(&self, v: &str) -> Option<&Range> {
        self.ranges.iter().find(|r| r.contains(v))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    total_results: usize,
    #[serde(default)]
    vulnerabilities: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    cve: RawCve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCve {
    id: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct Metrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<Metric>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metric {
    #[serde(default, rename = "type")]
    kind: String,
    cvss_data: CvssData,
    /// CVSS v2 has it here.
    #[serde(default)]
    base_severity: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    #[serde(default)]
    base_severity: Option<String>,
}

#[derive(Deserialize)]
struct Configuration {
    #[serde(default)]
    operator: Option<String>,
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

/// Splits a CPE 2.3 string at unescaped colons; escapes stay in place.
fn cpe_fields(cpe: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in cpe.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            ':' => {
                out.push(&cpe[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&cpe[start..]);
    out
}

/// Fields after `cpe:2.3:`: part, vendor, product, version, update, edition, language,
/// sw_edition, target_sw, target_hw, other.
const PART: usize = 2;
const VENDOR: usize = 3;
const PRODUCT: usize = 4;
const VERSION: usize = 5;
const UPDATE: usize = 6;
const TARGET_SW: usize = 10;

fn any(field: Option<&&str>) -> bool {
    matches!(field.copied(), None | Some("*" | "-" | ""))
}

impl CpeMatch {
    /// The range this criterion marks vulnerable for `cpe` on Windows.
    fn range_for(&self, cpe: &Cpe) -> Option<Range> {
        let f = cpe_fields(&self.criteria);
        let applies = self.vulnerable
            && f.get(PART) == Some(&"a")
            && f.get(VENDOR) == Some(&cpe.vendor)
            && f.get(PRODUCT) == Some(&cpe.product)
            // Betas and other pre-releases are not what people install.
            && any(f.get(UPDATE))
            && (any(f.get(TARGET_SW)) || f.get(TARGET_SW) == Some(&"windows"));
        if !applies {
            return None;
        }
        let version = f.get(VERSION).copied().unwrap_or("*");
        if !any(Some(&version)) {
            return Some(Range {
                exact: Some(version.replace('\\', "")),
                ..Range::default()
            });
        }
        let range = Range {
            exact: None,
            start_including: self.version_start_including.clone(),
            start_excluding: self.version_start_excluding.clone(),
            end_including: self.version_end_including.clone(),
            end_excluding: self.version_end_excluding.clone(),
        };
        // "chrome:*" with no range: old protocol-level CVEs (TLS, HTTP/2) and unfinished analyses
        // name the product without versions. They would flag every release, so they say nothing.
        let unbounded = range == Range::default();
        (!unbounded).then_some(range)
    }

    fn is_os(&self) -> bool {
        cpe_fields(&self.criteria).get(PART) == Some(&"o")
    }

    fn is_windows(&self) -> bool {
        let f = cpe_fields(&self.criteria);
        f.get(VENDOR) == Some(&"microsoft") && f.get(PRODUCT).is_some_and(|p| p.starts_with("windows"))
    }
}

/// "Application X running on macOS": an AND configuration whose platform node names operating
/// systems, none of them Windows.
fn other_platform_only(config: &Configuration) -> bool {
    config.operator.as_deref() == Some("AND")
        && config.nodes.iter().any(|n| {
            !n.negate
                && !n.cpe_match.is_empty()
                && n.cpe_match.iter().all(|m| !m.vulnerable && m.is_os())
                && !n.cpe_match.iter().any(CpeMatch::is_windows)
        })
}

fn severity(m: &Metrics) -> Severity {
    for list in [&m.v40, &m.v31, &m.v30, &m.v2] {
        let best = list.iter().find(|x| x.kind == "Primary").or_else(|| list.first());
        if let Some(x) = best
            && let Some(s) = x.cvss_data.base_severity.as_ref().or(x.base_severity.as_ref())
        {
            return Severity::parse(s);
        }
    }
    Severity::Unknown
}

fn summary(descriptions: &[Description]) -> String {
    let text = descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| descriptions.first())
        .map(|d| d.value.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    const MAX: usize = 160;
    if text.chars().count() <= MAX {
        return text;
    }
    let cut: String = text.chars().take(MAX).collect();
    let cut = cut.rsplit_once(' ').map_or(cut.as_str(), |(head, _)| head);
    format!("{}…", cut.trim_end_matches([',', '.', ';', ':']))
}

/// The CVEs of one page that apply to `cpe` on Windows, and the total number of results.
pub fn parse_page(json: &str, cpe: &Cpe) -> Result<(Vec<Cve>, usize)> {
    let page: Page = serde_json::from_str(json).context("parsing an NVD response")?;
    let mut out = Vec::new();
    for item in page.vulnerabilities {
        let c = item.cve;
        if c.vuln_status == "Rejected" {
            continue;
        }
        let ranges: Vec<Range> = c
            .configurations
            .iter()
            .filter(|cfg| !other_platform_only(cfg))
            .flat_map(|cfg| cfg.nodes.iter().filter(|n| !n.negate))
            .flat_map(|n| n.cpe_match.iter().filter_map(|m| m.range_for(cpe)))
            .collect();
        if ranges.is_empty() {
            continue;
        }
        out.push(Cve {
            severity: severity(&c.metrics),
            summary: summary(&c.descriptions),
            id: c.id,
            ranges,
        });
    }
    Ok((out, page.total_results))
}

#[derive(Serialize, Deserialize)]
struct Cached {
    format: u32,
    cves: Vec<Cve>,
}

fn cache_name(cpe: &Cpe, version: &str) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!(
        "nvd-{}-{}-{}.json",
        clean(cpe.vendor),
        clean(cpe.product),
        clean(version)
    )
}

/// NVD's limit is a number of requests in a rolling 30 seconds.
const WINDOW: Duration = Duration::from_secs(31);

/// Requests in one window: 5 without an API key, 50 with one.
pub fn requests_per_window(api_key: Option<&str>) -> usize {
    if api_key.is_some() { 50 } else { 5 }
}

/// Requests NVD for many products at once, within its rate limit. NVD takes 5 to 20 seconds per
/// answer, so requests run in parallel.
pub struct Client<'a> {
    sys: &'a dyn System,
    api_key: Option<&'a str>,
    /// When the requests of the current window started.
    starts: Mutex<VecDeque<Instant>>,
}

impl<'a> Client<'a> {
    pub fn new(sys: &'a dyn System, api_key: Option<&'a str>) -> Self {
        Self {
            sys,
            api_key,
            starts: Mutex::new(VecDeque::new()),
        }
    }

    pub fn parallelism(&self) -> usize {
        requests_per_window(self.api_key)
    }

    /// Whether this lookup has fresh cached data, i.e. costs no request.
    pub fn is_cached(&self, cpe: &Cpe, version: &str) -> bool {
        self.cached(cpe, version).is_some_and(|(_, fresh)| fresh)
    }

    fn cached(&self, cpe: &Cpe, version: &str) -> Option<(Vec<Cve>, bool)> {
        let (text, written) = self.sys.cache_read(&cache_name(cpe, version))?;
        let c: Cached = serde_json::from_str(&text).ok()?;
        if c.format != CACHE_FORMAT {
            return None;
        }
        let age = SystemTime::now().duration_since(written).unwrap_or_default();
        Some((c.cves, age < CACHE_MAX_AGE))
    }

    /// CVEs of `cpe` that NVD lists for `version` on Windows: cached for a day, stale cache if NVD
    /// fails.
    pub fn cves(&self, cpe: &Cpe, version: &str, warnings: &mut Vec<String>) -> Result<Vec<Cve>> {
        let cached = self.cached(cpe, version);
        if let Some((cves, true)) = &cached {
            return Ok(cves.clone());
        }
        match self.download(cpe, version) {
            Ok(cves) => {
                let data = serde_json::to_string(&Cached {
                    format: CACHE_FORMAT,
                    cves: cves.clone(),
                })?;
                let _ = self.sys.cache_write(&cache_name(cpe, version), &data);
                Ok(cves)
            }
            Err(e) => match cached {
                Some((cves, _)) => {
                    warnings.push(format!(
                        "NVD data for {}:{} is from an earlier scan, refreshing failed: {e:#}",
                        cpe.vendor, cpe.product
                    ));
                    Ok(cves)
                }
                None => Err(e),
            },
        }
    }

    /// NVD filters by version itself, so only the CVEs whose ranges contain `version` come back
    /// (Chrome: none or a few, instead of 7700 records in 4 pages of 13 MB). They are still
    /// matched here, which drops other platforms, pre-releases and unbounded criteria.
    fn download(&self, cpe: &Cpe, version: &str) -> Result<Vec<Cve>> {
        let mut out = Vec::new();
        let mut start = 0;
        loop {
            let url = format!(
                "{}&noRejected",
                url_with_query(
                    API,
                    &[
                        ("virtualMatchString", &cpe.match_string()),
                        ("versionStart", version),
                        ("versionStartType", "including"),
                        ("versionEnd", version),
                        ("versionEndType", "including"),
                        ("resultsPerPage", &PAGE_SIZE.to_string()),
                        ("startIndex", &start.to_string()),
                    ],
                )
            );
            let body = self.get(&url)?;
            let (cves, total) = parse_page(&body, cpe)?;
            out.extend(cves.into_iter().filter(|c| c.affects(version).is_some()));
            start += PAGE_SIZE;
            if start >= total {
                return Ok(out);
            }
        }
    }

    /// Waits until the rolling window has room for one more request.
    fn acquire(&self) {
        let limit = requests_per_window(self.api_key);
        loop {
            let mut starts = self.starts.lock().expect("no panics while holding the lock");
            let now = self.sys.now();
            while starts.front().is_some_and(|t| now.duration_since(*t) >= WINDOW) {
                starts.pop_front();
            }
            if starts.len() < limit {
                starts.push_back(now);
                return;
            }
            let wait = WINDOW - now.duration_since(starts[0]);
            drop(starts);
            self.sys.sleep(wait);
        }
    }

    /// NVD often answers 503 when busy, and 403 when the rate limit is hit: wait longer each time.
    fn get(&self, url: &str) -> Result<String> {
        let headers: Vec<(&str, &str)> = self.api_key.map(|k| ("apiKey", k)).into_iter().collect();
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                self.sys.sleep(RETRY_PAUSE * (1 << (attempt - 1)));
            }
            self.acquire();
            match self.sys.http_get_with(url, &headers) {
                Ok(body) => return Ok(body),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("at least one attempt")).context("querying NVD")
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    pub const SEVEN_ZIP: Cpe = Cpe {
        vendor: "7-zip",
        product: "7-zip",
    };

    /// Trimmed from real NVD records for 7-Zip.
    pub const PAGE: &str = r#"{"resultsPerPage":6,"startIndex":0,"totalResults":6,"format":"NVD_CVE","version":"2.0",
      "vulnerabilities":[
        {"cve":{"id":"CVE-2024-11477","vulnStatus":"Modified",
          "descriptions":[{"lang":"es","value":"Vulnerabilidad"},{"lang":"en","value":"7-Zip Zstandard Decompression Integer Underflow Remote Code Execution Vulnerability."}],
          "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":7.8,"baseSeverity":"HIGH"}}],
                     "cvssMetricV30":[{"source":"zdi","type":"Secondary","cvssData":{"version":"3.0","baseSeverity":"LOW"}}]},
          "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionEndExcluding":"24.07","matchCriteriaId":"x"}]}]}]}},
        {"cve":{"id":"CVE-2007-4725","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Old"}],
          "metrics":{"cvssMetricV2":[{"type":"Primary","cvssData":{"version":"2.0"},"baseSeverity":"MEDIUM"}]},
          "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionEndIncluding":"4.42"},
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:4.43:beta:*:*:*:*:*:*"},
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:9.20:*:*:*:*:*:*:*"}]}]}]}},
        {"cve":{"id":"CVE-2016-2335","vulnStatus":"Modified","descriptions":[{"lang":"en","value":"Distro only"}],
          "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*"},
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:p7zip:*:*:*:*:*:*:*:*","versionEndIncluding":"16.02"}]}]}]}},
        {"cve":{"id":"CVE-2099-0001","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Mac only"}],
          "configurations":[{"operator":"AND","nodes":[
            {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionEndExcluding":"30.0"}]},
            {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"}]}]}]}},
        {"cve":{"id":"CVE-2011-3389","vulnStatus":"Modified","descriptions":[{"lang":"en","value":"The SSL protocol..."}],
          "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*"},
            {"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:-:*:*:*:*:*:*:*"}]}]}]}},
        {"cve":{"id":"CVE-2099-0002","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Windows and Linux"}],
          "configurations":[{"operator":"AND","nodes":[
            {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionStartIncluding":"24.0","versionEndExcluding":"30.0"}]},
            {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
                                                        {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]}}
      ]}"#;

    fn ids(cves: &[Cve], v: &str) -> Vec<String> {
        cves.iter()
            .filter(|c| c.affects(v).is_some())
            .map(|c| c.id.clone())
            .collect()
    }

    #[test]
    fn matches_versions_against_cpe_criteria() {
        let (cves, total) = parse_page(PAGE, &SEVEN_ZIP).unwrap();
        assert_eq!(total, 6);
        let all: Vec<&str> = cves.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            all,
            ["CVE-2024-11477", "CVE-2007-4725", "CVE-2099-0002"],
            "not p7zip, not macOS-only, not without versions"
        );
        assert_eq!(ids(&cves, "24.06"), ["CVE-2024-11477", "CVE-2099-0002"]);
        assert_eq!(ids(&cves, "24.07"), ["CVE-2099-0002"]);
        assert_eq!(ids(&cves, "4.42"), ["CVE-2024-11477", "CVE-2007-4725"]);
        assert_eq!(ids(&cves, "4.43"), ["CVE-2024-11477"], "the beta criterion is skipped");
        assert_eq!(ids(&cves, "9.20"), ["CVE-2024-11477", "CVE-2007-4725"], "exact version");
        assert_eq!(cves[0].severity, Severity::High, "primary CVSS 3.1");
        assert_eq!(cves[1].severity, Severity::Medium, "CVSS 2 keeps it outside cvssData");
        assert_eq!(cves[0].affects("24.06").unwrap().fixed_in(), Some("24.07"));
        assert!(cves[0].summary.starts_with("7-Zip Zstandard"));
    }

    #[test]
    fn splits_cpes_with_escapes() {
        let f = cpe_fields(r"cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6\:1:*:*:*:*:windows:*:*");
        assert_eq!(f[PRODUCT], r"notepad\+\+");
        assert_eq!(f[VERSION], r"8.6\:1");
        assert_eq!(f[TARGET_SW], "windows");
    }

    #[test]
    fn shortens_long_summaries_at_a_word() {
        let long = vec![Description {
            lang: "en".into(),
            value: format!("{} end", "word ".repeat(60)),
        }];
        let s = summary(&long);
        assert!(s.ends_with("word…") && s.chars().count() <= 161, "{s}");
    }

    #[test]
    fn asks_nvd_for_one_version_pages_and_caches() {
        let page1 = PAGE.replace(r#""totalResults":6"#, r#""totalResults":2500"#);
        let sys = FakeSystem::new()
            .on("startIndex=2000", r#"{"totalResults":2500,"vulnerabilities":[]}"#)
            .on("startIndex=0", &page1);
        let client = Client::new(&sys, None);
        let mut w = Vec::new();
        let cves = client.cves(&SEVEN_ZIP, "24.06", &mut w).unwrap();
        let ids: Vec<&str> = cves.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2024-11477", "CVE-2099-0002"], "re-checked against 24.06");
        let reqs = sys.requests();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].contains("virtualMatchString=cpe%3A2.3%3Aa%3A7-zip%3A7-zip%3A%2A"));
        assert!(
            reqs[0].contains("versionStart=24.06&versionStartType=including&versionEnd=24.06&versionEndType=including")
        );
        assert!(reqs[0].ends_with("&noRejected"));
        assert_eq!(
            *sys.slept.lock().unwrap(),
            Duration::ZERO,
            "two requests fit the window"
        );

        assert!(client.is_cached(&SEVEN_ZIP, "24.06"));
        assert!(!client.is_cached(&SEVEN_ZIP, "24.07"), "per version");
        client.cves(&SEVEN_ZIP, "24.06", &mut w).unwrap();
        assert_eq!(sys.requests().len(), 2, "second lookup comes from the cache");
    }

    #[test]
    fn keeps_to_five_requests_per_window_across_threads() {
        let sys = FakeSystem::new().on("nvd.nist.gov", r#"{"totalResults":0,"vulnerabilities":[]}"#);
        let client = Client::new(&sys, None);
        let versions: Vec<String> = (0..12).map(|i| format!("1.{i}")).collect();
        crate::system::parallel_map(&versions, client.parallelism(), |v| {
            client.cves(&SEVEN_ZIP, v, &mut Vec::new()).unwrap();
        });
        assert_eq!(sys.requests().len(), 12);
        // 5 at once, 5 a window later, the last 2 another window later.
        let slept = *sys.slept.lock().unwrap();
        assert!(slept >= WINDOW * 2, "{slept:?}");
        let starts = client.starts.lock().unwrap();
        assert!(starts.len() <= 5);
    }

    #[test]
    fn retries_then_falls_back_to_a_stale_cache() {
        let stale = serde_json::to_string(&Cached {
            format: CACHE_FORMAT,
            cves: parse_page(PAGE, &SEVEN_ZIP).unwrap().0,
        })
        .unwrap();
        let sys = FakeSystem::new().fail("nvd.nist.gov", "503").cached(
            &cache_name(&SEVEN_ZIP, "24.06"),
            &stale,
            Duration::from_secs(3 * 86_400),
        );
        let mut w = Vec::new();
        let cves = Client::new(&sys, Some("key"))
            .cves(&SEVEN_ZIP, "24.06", &mut w)
            .unwrap();
        assert_eq!(cves.len(), 3);
        assert_eq!(sys.requests().len(), ATTEMPTS);
        assert!(w[0].contains("earlier scan"), "{w:?}");

        let sys = FakeSystem::new().fail("nvd.nist.gov", "503");
        assert!(Client::new(&sys, None).cves(&SEVEN_ZIP, "24.06", &mut w).is_err());
    }
}
