//! Windows CVEs from the Microsoft Security Response Center's monthly CVRF documents. Each CVE
//! lists, per Windows release, the KB that fixes it and the build that KB brings.
//!
//! Updates are cumulative: once a month's update is installed, every older month is fixed too, so
//! months are checked newest first until one is fully installed.

use super::inventory::Inventory;
use super::version;
use crate::model::Severity;
use crate::progress::Progress;
use crate::system::System;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

pub const UPDATES_URL: &str = "https://api.msrc.microsoft.com/cvrf/v3.0/updates";
/// Further back than this the machine is so outdated that the answer is the same: update.
pub const MAX_MONTHS: usize = 6;
/// Bump when [`MonthData`] changes.
const CACHE_FORMAT: u32 = 1;

pub fn cve_url(id: &str) -> String {
    format!("https://msrc.microsoft.com/update-guide/vulnerability/{id}")
}

pub fn kb_url(kb: &str) -> String {
    format!("https://support.microsoft.com/help/{kb}")
}

/// The product name MSRC uses for this Windows, e.g. "Windows 11 Version 24H2 for x64-based
/// Systems" or "Windows Server 2022 (Server Core installation)".
pub fn product_name(inv: &Inventory) -> Result<String> {
    let build: u32 = inv
        .build
        .trim()
        .parse()
        .with_context(|| format!("cannot read the Windows build number '{}'", inv.build))?;
    let server = inv.installation_type.starts_with("Server") || inv.product_name.contains("Server");
    if server {
        let year = match build {
            9200 => "2012".to_string(),
            9600 => "2012 R2".to_string(),
            14393 => "2016".to_string(),
            17763 => "2019".to_string(),
            20348 => "2022".to_string(),
            26100 => "2025".to_string(),
            _ => {
                let rest = inv
                    .product_name
                    .split_once("Server ")
                    .map(|(_, r)| r)
                    .with_context(|| format!("unknown Windows Server build {build}"))?;
                let mut words = rest.split_whitespace();
                let mut year = words.next().unwrap_or_default().to_string();
                if words.next() == Some("R2") {
                    year.push_str(" R2");
                }
                year
            }
        };
        let core = if inv.installation_type == "Server Core" {
            " (Server Core installation)"
        } else {
            ""
        };
        return Ok(format!("Windows Server {year}{core}"));
    }

    let release = [&inv.display_version, &inv.release_id]
        .into_iter()
        .map(|v| v.trim())
        .find(|v| !v.is_empty())
        .context("the registry does not say which Windows release this is (DisplayVersion)")?;
    // ProductName still says "Windows 10" on Windows 11.
    let family = if build >= 22000 { "Windows 11" } else { "Windows 10" };
    let arch = match inv.arch.trim().to_ascii_uppercase().as_str() {
        "AMD64" => "x64-based",
        "ARM64" => "ARM64-based",
        "X86" => "32-bit",
        other => bail!("unknown processor architecture '{other}'"),
    };
    Ok(format!("{family} Version {release} for {arch} Systems"))
}

/// One monthly document, from the list of all of them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Month {
    #[serde(rename = "ID")]
    pub id: String,
    pub initial_release_date: String,
    /// Changes whenever MSRC revises the document.
    pub current_release_date: String,
    pub cvrf_url: String,
}

#[derive(Deserialize)]
struct MonthList {
    value: Vec<Month>,
}

/// Newest first.
pub fn parse_months(json: &str) -> Result<Vec<Month>> {
    let mut months = serde_json::from_str::<MonthList>(json)
        .context("parsing the MSRC update list")?
        .value;
    months.sort_by(|a, b| b.initial_release_date.cmp(&a.initial_release_date));
    Ok(months)
}

/// What a month's document says about one product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonthData {
    format: u32,
    current_release_date: String,
    /// The document lists the product at all.
    pub product_found: bool,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub cve: String,
    pub title: String,
    pub severity: String,
    pub exploited: bool,
    pub remedies: Vec<Remedy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remedy {
    /// e.g. KB5132061.
    pub kb: String,
    pub fixed_build: Option<String>,
    /// Hotpatches (no restart) have their own builds, interleaved with the regular ones.
    pub hotpatch: bool,
    pub url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Doc {
    product_tree: ProductTree,
    #[serde(default, deserialize_with = "null_as_empty")]
    vulnerability: Vec<Vuln>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProductTree {
    #[serde(default, deserialize_with = "null_as_empty")]
    full_product_name: Vec<FullProductName>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FullProductName {
    #[serde(rename = "ProductID")]
    product_id: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Vuln {
    #[serde(rename = "CVE", default)]
    cve: String,
    title: Option<Text>,
    #[serde(default, deserialize_with = "null_as_empty")]
    threats: Vec<Threat>,
    #[serde(default, deserialize_with = "null_as_empty")]
    remediations: Vec<Remediation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Text {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Threat {
    description: Option<Text>,
    #[serde(rename = "ProductID", default, deserialize_with = "null_as_empty")]
    product_id: Vec<String>,
    #[serde(rename = "Type")]
    kind: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Remediation {
    description: Option<Text>,
    #[serde(rename = "URL", default)]
    url: Option<String>,
    #[serde(rename = "ProductID", default, deserialize_with = "null_as_empty")]
    product_id: Vec<String>,
    #[serde(rename = "Type")]
    kind: i64,
    #[serde(default)]
    fixed_build: Option<String>,
    restart_required: Option<Text>,
    #[serde(default)]
    sub_type: Option<String>,
}

fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

fn text(t: Option<&Text>) -> &str {
    t.and_then(|t| t.value.as_deref()).unwrap_or_default().trim()
}

const THREAT_EXPLOIT_STATUS: i64 = 1;
const THREAT_SEVERITY: i64 = 3;
const REMEDIATION_VENDOR_FIX: i64 = 2;

pub fn parse_doc(json: &str, product: &str, current_release_date: &str) -> Result<MonthData> {
    let doc: Doc = serde_json::from_str(json).context("parsing an MSRC CVRF document")?;
    let Some(pid) = doc
        .product_tree
        .full_product_name
        .iter()
        .find(|p| p.value.trim().eq_ignore_ascii_case(product))
        .map(|p| p.product_id.clone())
    else {
        return Ok(MonthData {
            format: CACHE_FORMAT,
            current_release_date: current_release_date.into(),
            product_found: false,
            entries: Vec::new(),
        });
    };

    let mut entries = Vec::new();
    for v in doc.vulnerability {
        let remedies: Vec<Remedy> = v
            .remediations
            .iter()
            .filter(|r| r.kind == REMEDIATION_VENDOR_FIX && r.product_id.contains(&pid))
            .filter_map(|r| {
                let digits = text(r.description.as_ref());
                if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                let url = r.url.as_deref().map(str::trim).unwrap_or_default();
                Some(Remedy {
                    kb: format!("KB{digits}"),
                    fixed_build: r
                        .fixed_build
                        .as_deref()
                        .map(str::trim)
                        .filter(|b| !b.is_empty())
                        .map(Into::into),
                    hotpatch: text(r.restart_required.as_ref()).eq_ignore_ascii_case("no")
                        || r.sub_type.as_deref().is_some_and(|s| s.contains("Hotpatch")),
                    url: if url.is_empty() {
                        kb_url(&format!("KB{digits}"))
                    } else {
                        url.into()
                    },
                })
            })
            .collect();
        if remedies.is_empty() {
            continue;
        }
        let severities = |own: bool| {
            v.threats
                .iter()
                .filter(|t| t.kind == THREAT_SEVERITY && (!own || t.product_id.contains(&pid)))
                .map(|t| text(t.description.as_ref()))
                .max_by_key(|s| Severity::parse(s))
                .map(str::to_string)
        };
        entries.push(Entry {
            title: text(v.title.as_ref()).to_string(),
            severity: severities(true).or_else(|| severities(false)).unwrap_or_default(),
            exploited: v
                .threats
                .iter()
                .any(|t| t.kind == THREAT_EXPLOIT_STATUS && text(t.description.as_ref()).contains("Exploited:Yes")),
            cve: v.cve,
            remedies,
        });
    }
    Ok(MonthData {
        format: CACHE_FORMAT,
        current_release_date: current_release_date.into(),
        product_found: true,
        entries,
    })
}

/// `None`: the data cannot tell (no fixed build, KB not installed).
pub fn is_fixed(entry: &Entry, installed: &str, inv: &Inventory) -> Option<bool> {
    if entry.remedies.iter().any(|r| inv.has_hotfix(&r.kb)) {
        return Some(true);
    }
    let at_least = |b: &&str| version::cmp(installed, b) != Ordering::Less;
    let builds = |hot: bool| -> Vec<&str> {
        entry
            .remedies
            .iter()
            .filter(|r| r.hotpatch == hot)
            .filter_map(|r| r.fixed_build.as_deref())
            .collect()
    };
    let (regular, hot) = (builds(false), builds(true));
    if regular.is_empty() && hot.is_empty() {
        return None;
    }
    // Several regular KBs (e.g. a re-release) all fix it; the earliest is enough.
    let fixed = regular.iter().min_by(|a, b| version::cmp(a, b)).is_some_and(at_least)
        || hot.iter().any(|b| version::cmp(installed, b) == Ordering::Equal)
        || (regular.is_empty() && hot.iter().any(at_least));
    Some(fixed)
}

pub struct OsCheck {
    /// Not fixed by the installed build, newest month first.
    pub unfixed: Vec<Entry>,
    /// Ids of the documents read.
    pub months: Vec<String>,
}

pub fn check(
    sys: &dyn System,
    inv: &Inventory,
    product: &str,
    installed: &str,
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> Result<OsCheck> {
    let months = parse_months(&sys.http_get(UPDATES_URL)?)?;
    let mut out = OsCheck {
        unfixed: Vec::new(),
        months: Vec::new(),
    };
    for (i, month) in months.iter().take(MAX_MONTHS).enumerate() {
        let data = month_data(sys, month, product, progress)?;
        if !data.product_found {
            if i == 0 {
                bail!(
                    "Microsoft's {} security data does not list \"{product}\"; this Windows release may be out \
                     of support",
                    month.id
                );
            }
            break;
        }
        out.months.push(month.id.clone());
        let mut decided = 0;
        let mut unfixed = 0;
        for e in data.entries {
            match is_fixed(&e, installed, inv) {
                Some(true) => decided += 1,
                Some(false) => {
                    decided += 1;
                    unfixed += 1;
                    if !out.unfixed.iter().any(|u| u.cve == e.cve) {
                        out.unfixed.push(e);
                    }
                }
                None => {}
            }
        }
        if decided > 0 && unfixed == 0 {
            return Ok(out);
        }
        if i + 1 == MAX_MONTHS {
            warnings.push(format!(
                "Windows is missing more than {MAX_MONTHS} months of security updates; older months were not checked"
            ));
        }
    }
    Ok(out)
}

fn month_data(sys: &dyn System, month: &Month, product: &str, progress: &dyn Progress) -> Result<MonthData> {
    let slug: String = product
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let cache_name = format!("msrc-{}-{slug}.json", month.id);
    if let Some((text, _)) = sys.cache_read(&cache_name)
        && let Ok(data) = serde_json::from_str::<MonthData>(&text)
        && data.format == CACHE_FORMAT
        && data.current_release_date == month.current_release_date
    {
        return Ok(data);
    }
    progress.detail(&format!("downloading {} (about 20 MB)", month.id));
    let json = sys
        .http_get(&month.cvrf_url)
        .with_context(|| format!("downloading MSRC document {}", month.id))?;
    let data = parse_doc(&json, product, &month.current_release_date)?;
    // A failed cache write only costs a download next time.
    let _ = sys.cache_write(&cache_name, &serde_json::to_string(&data)?);
    Ok(data)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::distro::windows::inventory;
    use crate::progress::Silent;
    use crate::system::fake::FakeSystem;

    pub const MONTHS: &str = r#"{"value":[
        {"ID":"2026-Oct","Alias":"2026-Oct","DocumentTitle":"October 2026 Security Updates","Severity":null,
         "InitialReleaseDate":"2026-10-13T07:00:00Z","CurrentReleaseDate":"2026-11-13T01:43:06Z",
         "CvrfUrl":"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"},
        {"ID":"2026-Nov","Alias":"2026-Nov","DocumentTitle":"November 2026 Security Updates","Severity":null,
         "InitialReleaseDate":"2026-11-10T08:00:00Z","CurrentReleaseDate":"2026-11-13T08:00:00Z",
         "CvrfUrl":"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov"}]}"#;

    /// Trimmed from the real 2026-Nov document: a regular and a hotpatch KB for 24H2.
    pub const NOV: &str = r#"{"DocumentTitle":{"Value":"November 2026 Security Updates"},
      "ProductTree":{"Branch":[],"FullProductName":[
        {"ProductID":"12390","Value":"Windows 11 Version 24H2 for x64-based Systems"},
        {"ProductID":"12097","Value":"Windows 10 Version 22H2 for x64-based Systems"},
        {"ProductID":"20853","Value":"Windows 11 version 26H1 for x64-based Systems"}]},
      "Vulnerability":[
        {"Title":{"Value":"Windows NTFS Elevation of Privilege Vulnerability"},"CVE":"CVE-2026-100223",
         "Threats":[{"Description":{"Value":"Elevation of Privilege"},"ProductID":["12390"],"Type":0},
                    {"Description":{"Value":"Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"},"Type":1},
                    {"Description":{"Value":"Important"},"ProductID":["12097"],"Type":3},
                    {"Description":{"Value":"Critical"},"ProductID":["12390"],"Type":3}],
         "Remediations":[
           {"Description":{"Value":"5132061"},"URL":"https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5132061",
            "ProductID":["12389","12390"],"Type":2,"RestartRequired":{"Value":"Yes"},"SubType":"Security Update","FixedBuild":"10.0.26100.9974"},
           {"URL":"https://support.microsoft.com/help/5132061","ProductID":["12390"],"Type":3,"SubType":"5132061"},
           {"Description":{"Value":"5132043"},"URL":"","ProductID":["12390"],"Type":2,"RestartRequired":{"Value":"No"},
            "SubType":"Security Update","FixedBuild":"10.0.26100.9911"},
           {"Description":{"Value":"5131111"},"URL":"","ProductID":["12097"],"Type":2,"FixedBuild":"10.0.19045.7846"}]},
        {"Title":{"Value":"Windows Kernel Information Disclosure Vulnerability"},"CVE":"CVE-2026-100300",
         "Threats":[{"Description":{"Value":"Important"},"ProductID":["12390"],"Type":3}],
         "Remediations":[{"Description":{"Value":"5132061"},"URL":null,"ProductID":["12390"],"Type":2,
            "RestartRequired":{"Value":"Yes"},"FixedBuild":"10.0.26100.9974"}]},
        {"Title":{"Value":"Office thing"},"CVE":"CVE-2026-1","Threats":null,
         "Remediations":[{"Description":{"Value":"Click to Run"},"ProductID":["12390"],"Type":2}]}]}"#;

    pub const OCT: &str = r#"{"ProductTree":{"FullProductName":[
        {"ProductID":"12390","Value":"Windows 11 Version 24H2 for x64-based Systems"}]},
      "Vulnerability":[{"Title":{"Value":"Old one"},"CVE":"CVE-2026-90000",
         "Threats":[{"Description":{"Value":"Moderate"},"ProductID":["12390"],"Type":3}],
         "Remediations":[{"Description":{"Value":"5127648"},"ProductID":["12390"],"Type":2,
            "RestartRequired":{"Value":"Yes"},"FixedBuild":"10.0.26100.9711"}]}]}"#;

    fn inv(json: &str) -> Inventory {
        inventory::parse(json).unwrap()
    }

    const WIN11: &str = r#"{"product_name":"Windows 10 Pro","display_version":"24H2","build":"26100","ubr":"9500",
        "installation_type":"Client","arch":"AMD64"}"#;

    #[test]
    fn names_the_product_like_msrc() {
        assert_eq!(
            product_name(&inv(WIN11)).unwrap(),
            "Windows 11 Version 24H2 for x64-based Systems"
        );
        let w10 = inv(
            r#"{"display_version":"","release_id":"1809","build":"17763","installation_type":"Client","arch":"x86"}"#,
        );
        assert_eq!(
            product_name(&w10).unwrap(),
            "Windows 10 Version 1809 for 32-bit Systems"
        );
        let core = inv(
            r#"{"product_name":"Windows Server 2022 Datacenter","build":"20348","installation_type":"Server Core","arch":"AMD64"}"#,
        );
        assert_eq!(
            product_name(&core).unwrap(),
            "Windows Server 2022 (Server Core installation)"
        );
        let r2 = inv(
            r#"{"product_name":"Windows Server 2012 R2 Standard","build":"9601","installation_type":"Server","arch":"AMD64"}"#,
        );
        assert_eq!(product_name(&r2).unwrap(), "Windows Server 2012 R2");
        assert!(product_name(&inv(r#"{"build":"26100","display_version":"24H2","arch":"IA64"}"#)).is_err());
        assert!(product_name(&inv(r#"{"build":"","arch":"AMD64"}"#)).is_err());
    }

    #[test]
    fn parses_fixes_for_one_product() {
        let d = parse_doc(NOV, "windows 11 version 24h2 for x64-based systems", "r1").unwrap();
        assert!(d.product_found);
        assert_eq!(d.entries.len(), 2, "the Office entry has no KB");
        let e = &d.entries[0];
        assert_eq!(e.severity, "Critical", "this product's severity, not another's");
        assert!(e.exploited);
        assert_eq!(e.remedies.len(), 2, "not the Windows 10 KB");
        assert_eq!(
            e.remedies[0],
            Remedy {
                kb: "KB5132061".into(),
                fixed_build: Some("10.0.26100.9974".into()),
                hotpatch: false,
                url: "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5132061".into(),
            }
        );
        assert!(e.remedies[1].hotpatch);
        assert_eq!(e.remedies[1].url, kb_url("KB5132043"));
        assert_eq!(d.entries[1].remedies[0].url, kb_url("KB5132061"), "null URL");
        assert!(
            !parse_doc(NOV, "Windows 11 Version 25H2 for x64-based Systems", "r1")
                .unwrap()
                .product_found
        );
    }

    #[test]
    fn decides_fixes_by_build_hotpatch_and_installed_kb() {
        let d = parse_doc(NOV, "Windows 11 Version 24H2 for x64-based Systems", "r1").unwrap();
        let e = &d.entries[0];
        let none = inv(r#"{"hotfixes":[]}"#);
        assert_eq!(is_fixed(e, "10.0.26100.9500", &none), Some(false));
        assert_eq!(is_fixed(e, "10.0.26100.9974", &none), Some(true));
        assert_eq!(is_fixed(e, "10.0.26100.10010", &none), Some(true));
        assert_eq!(is_fixed(e, "10.0.26100.9911", &none), Some(true), "the hotpatch build");
        assert_eq!(
            is_fixed(e, "10.0.26100.9930", &none),
            Some(false),
            "a preview build above the hotpatch is not the hotpatch"
        );
        let kb = inv(r#"{"hotfixes":["KB5132061"]}"#);
        assert_eq!(is_fixed(e, "10.0.26100.9500", &kb), Some(true));
        let unknown = Entry {
            remedies: vec![Remedy {
                fixed_build: None,
                ..e.remedies[0].clone()
            }],
            ..e.clone()
        };
        assert_eq!(is_fixed(&unknown, "10.0.26100.9500", &none), None);
    }

    fn sys() -> FakeSystem {
        FakeSystem::new()
            .on(UPDATES_URL, MONTHS)
            .on("cvrf/2026-Nov", NOV)
            .on("cvrf/2026-Oct", OCT)
    }

    const PRODUCT: &str = "Windows 11 Version 24H2 for x64-based Systems";

    #[test]
    fn stops_at_the_first_fully_installed_month() {
        let s = sys();
        let mut w = Vec::new();
        let r = check(&s, &inv(WIN11), PRODUCT, "10.0.26100.9974", &Silent, &mut w).unwrap();
        assert!(r.unfixed.is_empty());
        assert_eq!(r.months, ["2026-Nov"]);
        assert!(!s.requests().iter().any(|r| r.contains("2026-Oct")));

        let r = check(&s, &inv(WIN11), PRODUCT, "10.0.26100.9800", &Silent, &mut w).unwrap();
        let ids: Vec<&str> = r.unfixed.iter().map(|e| e.cve.as_str()).collect();
        assert_eq!(ids, ["CVE-2026-100223", "CVE-2026-100300"]);
        assert_eq!(
            r.months,
            ["2026-Nov", "2026-Oct"],
            "October is installed, so the search stops"
        );

        let r = check(&s, &inv(WIN11), PRODUCT, "10.0.26100.9000", &Silent, &mut w).unwrap();
        assert_eq!(r.unfixed.len(), 3);
        assert!(w.is_empty(), "two months is below the limit");
    }

    #[test]
    fn caches_reduced_documents_until_msrc_revises_them() {
        let s = sys();
        let mut w = Vec::new();
        check(&s, &inv(WIN11), PRODUCT, "10.0.26100.9974", &Silent, &mut w).unwrap();
        check(&s, &inv(WIN11), PRODUCT, "10.0.26100.9974", &Silent, &mut w).unwrap();
        let downloads = s.requests().iter().filter(|r| r.contains("cvrf/2026-Nov")).count();
        assert_eq!(downloads, 1);

        let revised = MONTHS.replace("2026-11-13T08:00:00Z", "2026-11-14T08:00:00Z");
        let s2 = FakeSystem::new().on(UPDATES_URL, &revised).on("cvrf/2026-Nov", NOV);
        *s2.cache.lock().unwrap() = s.cache.lock().unwrap().clone();
        check(&s2, &inv(WIN11), PRODUCT, "10.0.26100.9974", &Silent, &mut w).unwrap();
        assert!(s2.requests().iter().any(|r| r.contains("cvrf/2026-Nov")));
    }

    #[test]
    fn refuses_a_release_msrc_does_not_list() {
        let mut w = Vec::new();
        let err = check(
            &sys(),
            &inv(WIN11),
            "Windows 11 Version 21H2 for x64-based Systems",
            "10.0.22000.1",
            &Silent,
            &mut w,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("does not list"), "{err}");
    }
}
