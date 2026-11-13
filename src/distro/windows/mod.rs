//! Windows backend: the registry for what is installed, MSRC for Windows itself, NVD for programs
//! and winget for available program updates.
//!
//! Programs are found wherever they came from (installers, winget, portable apps that register);
//! only those whose NVD product is known (built-in table, or a publisher/name guess with an API
//! key) can be checked.

pub mod catalog;
pub mod inventory;
pub mod msrc;
pub mod nvd;
pub mod version;
pub mod winget;

use crate::distro::{Backend, ScanOptions, Steps, or_warn};
use crate::model::{
    Confidence, Coverage, Finding, Report, Severity, ThirdPartyPackage, ThirdPartyStatus, Update, Vulnerability,
};
use crate::progress::Progress;
use crate::report::plural;
use crate::system::System;
use anyhow::Result;
use catalog::VersionFrom;
use inventory::{Inventory, Program};
use nvd::Cpe;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub struct Windows;

pub const UPDATE_COMMAND: &str = "start ms-settings:windowsupdate";
pub const VENDOR_CHANNEL: &str = "vendor";
const NVD_SOURCE: &str = "nvd";

/// A program and the NVD products it is checked against.
#[derive(Debug, Clone)]
struct Matched {
    program: Program,
    version: String,
    cpes: Vec<Cpe>,
    guessed: bool,
}

/// CPEs live in the static table; guesses are leaked once per scan to share the type.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

impl Backend for Windows {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn scan(&self, sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
        let mut warnings = Vec::new();

        progress.start("Reading the registry", None);
        let inv = inventory::query(sys).inspect_err(|e| progress.warn(&format!("{e:#}")))?;
        let programs = inv.programs();
        progress.finish(&plural(programs.len(), "program"));

        let mut steps = Steps::new(progress, &mut warnings);
        let installed_build = format!("10.0.{}.{}", inv.build.trim(), inv.ubr.trim());
        let os = steps.run(
            "Checking Windows against Microsoft security updates",
            |w| check_windows(sys, &inv, &installed_build, progress, w),
            |f| match f {
                Some(f) if !f.vulnerabilities.is_empty() => {
                    format!(
                        "{} not fixed in build {}",
                        plural(f.vulnerabilities.len(), "CVE"),
                        f.installed
                    )
                }
                Some(f) => format!("build {} is up to date", f.installed),
                None => String::new(),
            },
        );

        let api_key = opts.nvd_api_key.as_deref().filter(|k| !k.trim().is_empty());
        let matched = match_programs(&programs, api_key.is_some());
        let client = nvd::Client::new(sys, api_key);
        let checked = steps.run(
            "Checking programs against NVD",
            |w| check_programs(&client, &matched, progress, w),
            |c| {
                let vulnerable = c.findings.len();
                format!(
                    "{} checked, {vulnerable} vulnerable",
                    plural(c.covered.len(), "program")
                )
            },
        );

        let upgrades = steps.run(
            "Listing winget updates",
            |w| {
                or_warn(
                    winget::query(sys),
                    w,
                    "cannot list winget updates, program updates are not shown",
                )
            },
            |u| plural(u.len(), "update"),
        );

        let mut findings = checked.findings;
        attach_upgrades(&mut findings, &checked.cves, &upgrades);
        let third_party = third_party(&upgrades, &findings, &programs);
        let covered: BTreeSet<&str> = checked.covered.iter().map(String::as_str).collect();
        let mut coverage = coverage(&programs, &covered);
        let mut notes = Vec::new();
        if let Some(mut f) = os {
            coverage.installed_packages += 1;
            coverage.covered_packages += 1;
            if f.vulnerabilities.is_empty() {
                notes.push(format!("{} build {} has all security updates.", f.package, f.installed));
            } else {
                f.recompute_severity();
                findings.push(f);
            }
        }
        if api_key.is_none() {
            let unmatched = coverage.uncovered_packages;
            if unmatched > 0 {
                warnings.push(format!(
                    "{} not in vulnhound's table were not checked; set NVD_API_KEY (free at \
                     https://nvd.nist.gov/developers/request-an-api-key) to look them up by publisher and name",
                    plural(unmatched, "program")
                ));
            }
        }
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package)));

        Ok(Report {
            distro: describe(&inv),
            backend: self.name().into(),
            coverage,
            findings,
            third_party,
            upstream: Vec::new(),
            warnings,
            notes,
        })
    }
}

/// "Windows 11 Pro 24H2 (build 26100.9911)".
fn describe(inv: &Inventory) -> String {
    let build: u32 = inv.build.trim().parse().unwrap_or(0);
    let mut name = inv.product_name.trim().to_string();
    // ProductName was never updated for Windows 11.
    if build >= 22000 && name.starts_with("Windows 10") {
        name = name.replacen("Windows 10", "Windows 11", 1);
    }
    if name.is_empty() {
        name = "Windows".into();
    }
    let release = inv.display_version.trim();
    let release = if release.is_empty() {
        inv.release_id.trim()
    } else {
        release
    };
    let mut out = name;
    if !release.is_empty() {
        out.push(' ');
        out.push_str(release);
    }
    format!("{out} (build {}.{})", inv.build.trim(), inv.ubr.trim())
}

/// `None` if Windows could not be checked; the reason is in `warnings`.
fn check_windows(
    sys: &dyn System,
    inv: &Inventory,
    installed: &str,
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> Option<Finding> {
    let product = match msrc::product_name(inv) {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!(
                "cannot tell which Windows this is, Windows itself was not checked: {e:#}"
            ));
            return None;
        }
    };
    let checked = match msrc::check(sys, inv, &product, installed, progress, warnings) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(format!("cannot check Windows against MSRC data: {e:#}"));
            return None;
        }
    };

    // "Windows 11 Version 24H2", the architecture is in the report header.
    let package = product.split(" for ").next().unwrap_or(&product).to_string();
    let mut f = Finding {
        package,
        installed: installed.to_string(),
        severity: Severity::Unknown,
        vulnerabilities: Vec::new(),
        update: None,
        notes: Vec::new(),
    };
    if product.starts_with("Windows 10") && !inv.edition.trim().ends_with('S') {
        f.notes.push(
            "Windows 10 reached end of support on 2025-10-14. Without Extended Security Updates it \
             gets no more fixes; upgrade to Windows 11."
                .into(),
        );
    }
    if checked.unfixed.is_empty() {
        return Some(f);
    }

    let exploited = checked.unfixed.iter().filter(|e| e.exploited).count();
    if exploited > 0 {
        f.notes.push(format!(
            "Microsoft reports {} as exploited in the wild.",
            plural(exploited, "of these CVEs")
        ));
    }
    // The newest regular cumulative update fixes all of them.
    let newest = checked
        .unfixed
        .iter()
        .flat_map(|e| &e.remedies)
        .filter(|r| !r.hotpatch)
        .filter_map(|r| r.fixed_build.as_deref().map(|b| (b, r)))
        .max_by(|a, b| version::cmp(a.0, b.0));
    let severity = checked
        .unfixed
        .iter()
        .map(|e| Severity::parse(&e.severity))
        .max()
        .unwrap_or(Severity::Unknown);
    f.update = newest.map(|(build, r)| Update {
        id: r.kb.clone(),
        kind: "security".into(),
        severity,
        build: build.to_string(),
        channel: "Windows Update".into(),
        url: msrc::kb_url(&r.kb),
        upgrades: Vec::new(),
        command: UPDATE_COMMAND.into(),
    });
    f.vulnerabilities = checked
        .unfixed
        .into_iter()
        .map(|e| Vulnerability {
            title: if e.exploited {
                format!("{} (exploited)", e.title)
            } else {
                e.title
            },
            url: msrc::cve_url(&e.cve),
            severity: Severity::parse(&e.severity),
            id: e.cve,
            confidence: Confidence::Affected,
            source: "msrc".into(),
        })
        .collect();
    f.vulnerabilities
        .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    Some(f)
}

fn match_programs(programs: &[Program], guess: bool) -> Vec<Matched> {
    let mut out = Vec::new();
    for p in programs {
        if let Some(known) = catalog::lookup(p) {
            if let Some(version) = catalog::program_version(p, known.version) {
                out.push(Matched {
                    program: p.clone(),
                    version,
                    cpes: known.cpes.to_vec(),
                    guessed: false,
                });
            }
        } else if guess
            && let Some((vendor, product)) = catalog::guess(p)
            && let Some(version) = catalog::program_version(p, VersionFrom::DisplayVersion)
        {
            out.push(Matched {
                program: p.clone(),
                version,
                cpes: vec![Cpe {
                    vendor: leak(vendor),
                    product: leak(product),
                }],
                guessed: true,
            });
        }
    }
    out
}

#[derive(Default)]
struct Checked {
    findings: Vec<Finding>,
    /// Program names that NVD knows.
    covered: Vec<String>,
    /// NVD data of each vulnerable program, to judge the available update.
    cves: BTreeMap<String, Vec<nvd::Cve>>,
}

fn check_programs(
    client: &nvd::Client,
    matched: &[Matched],
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> Checked {
    let lookups: Vec<(Cpe, String)> = matched
        .iter()
        .flat_map(|m| m.cpes.iter().map(|c| (*c, m.version.clone())))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let to_download = lookups.iter().filter(|(c, v)| !client.is_cached(c, v)).count();
    progress.add_total(lookups.len() as u64);
    // NVD takes 5-20 s per answer; a window of requests runs at once.
    let windows = to_download.div_ceil(client.parallelism());
    if windows > 1 {
        progress.detail(&format!(
            "NVD allows {} requests per 30 s, about {} s the first time",
            client.parallelism(),
            windows * 30
        ));
    }

    let results = crate::system::parallel_map(&lookups, client.parallelism(), |(cpe, version)| {
        let mut w = Vec::new();
        let r = client.cves(cpe, version, &mut w);
        progress.advance(1);
        (r, w)
    });
    let mut data: BTreeMap<(Cpe, String), Vec<nvd::Cve>> = BTreeMap::new();
    let mut failed = Vec::new();
    for ((cpe, version), (r, w)) in lookups.iter().zip(results) {
        match r {
            Ok(cves) => {
                data.insert((*cpe, version.clone()), cves);
            }
            Err(e) => failed.push(format!("{}:{} ({e:#})", cpe.vendor, cpe.product)),
        }
        warnings.extend(w);
    }
    if !failed.is_empty() {
        let guessed: BTreeSet<Cpe> = matched
            .iter()
            .filter(|m| m.guessed)
            .flat_map(|m| m.cpes.clone())
            .collect();
        // A guessed name NVD rejects is just a wrong guess.
        let real: Vec<&String> = failed
            .iter()
            .filter(|f| {
                !guessed
                    .iter()
                    .any(|g| f.starts_with(&format!("{}:{} ", g.vendor, g.product)))
            })
            .collect();
        if !real.is_empty() {
            warnings.push(format!(
                "cannot get NVD data for {}: {}",
                plural(real.len(), "product"),
                real.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; ")
            ));
        }
    }

    let mut out = Checked::default();
    for m in matched {
        let key = |c: &Cpe| (*c, m.version.clone());
        let cves: Vec<&nvd::Cve> = m.cpes.iter().filter_map(|c| data.get(&key(c))).flatten().collect();
        let known_to_nvd = m.cpes.iter().any(|c| data.contains_key(&key(c)));
        // A guess is only right if NVD has something under that name.
        if !known_to_nvd || (m.guessed && cves.is_empty()) {
            continue;
        }
        out.covered.push(m.program.name.clone());
        let mut vulns: Vec<Vulnerability> = Vec::new();
        for c in &cves {
            let Some(range) = c.affects(&m.version) else { continue };
            if vulns.iter().any(|v| v.id == c.id) {
                continue;
            }
            let fix = match range.fixed_in() {
                Some(v) => format!("fixed in {v}"),
                None => "no fixed version listed".into(),
            };
            vulns.push(Vulnerability {
                id: c.id.clone(),
                severity: c.severity,
                title: format!("{} ({fix})", c.summary),
                url: nvd::cve_url(&c.id),
                confidence: Confidence::Affected,
                source: NVD_SOURCE.into(),
            });
        }
        if vulns.is_empty() {
            continue;
        }
        vulns.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
        let mut f = Finding {
            package: m.program.name.clone(),
            installed: m.version.clone(),
            severity: Severity::Unknown,
            vulnerabilities: vulns,
            update: None,
            notes: Vec::new(),
        };
        if m.guessed {
            let c = &m.cpes[0];
            f.notes.push(format!(
                "Matched to NVD product {}:{} by publisher and name; check that it is this program.",
                c.vendor, c.product
            ));
        }
        f.recompute_severity();
        let affecting: Vec<nvd::Cve> = cves
            .into_iter()
            .filter(|c| f.vulnerabilities.iter().any(|v| v.id == c.id))
            .cloned()
            .collect();
        out.cves.insert(f.package.clone(), affecting);
        out.findings.push(f);
    }
    out
}

/// A winget update for each vulnerable program, else the vendor's fixed version from NVD.
fn attach_upgrades(findings: &mut [Finding], cves: &BTreeMap<String, Vec<nvd::Cve>>, upgrades: &[winget::Upgrade]) {
    for f in findings.iter_mut() {
        let data = cves.get(&f.package).map(Vec::as_slice).unwrap_or_default();
        if let Some(u) = upgrades.iter().find(|u| u.matches_name(&f.package)) {
            let still = data.iter().filter(|c| c.affects(&u.available).is_some()).count();
            if still > 0 {
                f.notes.push(format!(
                    "winget's {} is still affected by {} of these.",
                    u.available,
                    plural(still, "CVE")
                ));
            }
            f.update = Some(Update {
                id: String::new(),
                kind: "upgrade".into(),
                severity: Severity::Unknown,
                build: u.available.clone(),
                channel: "winget".into(),
                url: String::new(),
                upgrades: Vec::new(),
                command: u.command(),
            });
            continue;
        }
        // Every CVE needs a fixed version for the newest of them to fix all.
        let fixes: Option<Vec<&str>> = data
            .iter()
            .map(|c| c.affects(&f.installed).and_then(|r| r.fixed_in()))
            .collect();
        if let Some(newest) = fixes.and_then(|v| v.into_iter().max_by(|a, b| version::cmp(a, b))) {
            f.update = Some(Update {
                id: String::new(),
                kind: "upgrade".into(),
                severity: Severity::Unknown,
                build: newest.to_string(),
                channel: VENDOR_CHANNEL.into(),
                url: String::new(),
                upgrades: Vec::new(),
                command: String::new(),
            });
        }
    }
}

/// winget updates of programs without a finding.
fn third_party(upgrades: &[winget::Upgrade], findings: &[Finding], programs: &[Program]) -> Vec<ThirdPartyPackage> {
    let mut out: Vec<ThirdPartyPackage> = upgrades
        .iter()
        .filter(|u| !findings.iter().any(|f| u.matches_name(&f.package)))
        // winget sometimes offers what is installed already, e.g. with an odd version scheme.
        .filter(|u| version::cmp(&u.available, &u.installed) == Ordering::Greater || u.installed.is_empty())
        .map(|u| ThirdPartyPackage {
            package: u.name.clone(),
            vendor: programs
                .iter()
                .find(|p| u.matches_name(&p.name))
                .map(|p| p.publisher.clone())
                .unwrap_or_default(),
            installed: u.installed.clone(),
            status: ThirdPartyStatus::UpdateAvailable {
                version: u.available.clone(),
                repo: if u.source.is_empty() {
                    "winget".into()
                } else {
                    u.source.clone()
                },
                upgrades: Vec::new(),
                command: u.command(),
            },
        })
        .collect();
    out.sort_by_key(|t| t.package.to_lowercase());
    out
}

fn coverage(programs: &[Program], covered: &BTreeSet<&str>) -> Coverage {
    let mut publishers: BTreeMap<String, usize> = BTreeMap::new();
    for p in programs.iter().filter(|p| !covered.contains(p.name.as_str())) {
        let name = if p.publisher.is_empty() {
            "(no publisher)".to_string()
        } else {
            p.publisher.clone()
        };
        *publishers.entry(name).or_default() += 1;
    }
    let mut uncovered_vendors: Vec<(String, usize)> = publishers.into_iter().collect();
    uncovered_vendors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let covered_n = programs.iter().filter(|p| covered.contains(p.name.as_str())).count();
    Coverage {
        installed_packages: programs.len(),
        covered_packages: covered_n,
        uncovered_packages: programs.len() - covered_n,
        uncovered_vendors,
        fixed_suppressed: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::recording::Recording;
    use crate::system::fake::FakeSystem;

    fn sys() -> FakeSystem {
        FakeSystem::new()
            .os("windows")
            .on("powershell.exe", inventory::tests::SAMPLE)
            .on(msrc::UPDATES_URL, msrc::tests::MONTHS)
            .on("cvrf/2026-Nov", msrc::tests::NOV)
            .on("cvrf/2026-Oct", msrc::tests::OCT)
            .on("cpe%3A2.3%3Aa%3A7-zip%3A7-zip", nvd::tests::PAGE)
            .on("nvd.nist.gov", r#"{"totalResults":0,"vulnerabilities":[]}"#)
            .on("winget upgrade", winget::tests::OUTPUT)
    }

    fn scan(sys: &FakeSystem, opts: &ScanOptions) -> (Report, Recording) {
        let rec = Recording::default();
        let r = Windows.scan(sys, opts, &rec).unwrap();
        (r, rec)
    }

    #[test]
    fn scans_windows_and_programs() {
        let (r, rec) = scan(&sys(), &ScanOptions::default());
        assert_eq!(r.distro, "Windows 11 Pro 24H2 (build 26100.9911)");
        assert_eq!(r.backend, "windows");

        let names: Vec<&str> = r.findings.iter().map(|f| f.package.as_str()).collect();
        assert_eq!(names, ["7-Zip 24.06 (x64)", "Windows 11 Version 24H2"]);

        let win = &r.findings[1];
        assert_eq!(win.severity, Severity::High);
        let ids: Vec<&str> = win.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        // KB5132043 (the hotpatch) is installed, so CVE-2026-100223 is fixed; October is too.
        assert_eq!(ids, ["CVE-2026-100300"]);
        let u = win.update.as_ref().unwrap();
        assert_eq!((u.id.as_str(), u.build.as_str()), ("KB5132061", "10.0.26100.9974"));
        assert_eq!(u.command, UPDATE_COMMAND);

        let zip = &r.findings[0];
        assert_eq!(zip.installed, "24.06");
        let ids: Vec<&str> = zip.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2024-11477", "CVE-2099-0002"]);
        assert!(zip.vulnerabilities[0].title.ends_with("(fixed in 24.07)"));
        let u = zip.update.as_ref().unwrap();
        assert_eq!((u.channel.as_str(), u.build.as_str()), ("winget", "24.08"));
        assert_eq!(zip.notes, ["winget's 24.08 is still affected by 1 CVE of these."]);

        // Chrome and Git are in the table, NVD has nothing for them here; Steam and the
        // Cyrillic one are not.
        assert_eq!(r.coverage.installed_packages, 6, "5 programs and Windows");
        assert_eq!(r.coverage.covered_packages, 4);
        assert_eq!(
            r.coverage.uncovered_vendors,
            [("(no publisher)".into(), 1), ("Valve Corporation".into(), 1)]
        );
        assert!(r.warnings.iter().any(|w| w.contains("NVD_API_KEY")), "{:?}", r.warnings);

        let tp: Vec<&str> = r.third_party.iter().map(|t| t.package.as_str()).collect();
        assert_eq!(
            tp,
            ["Discord", "Google Chrome", "Microsoft Visual C++ 2015-2022 Redist…"]
        );
        assert_eq!(r.third_party[1].vendor, "Google LLC");

        let steps: Vec<String> = rec.steps().into_iter().map(|s| s.name).collect();
        assert_eq!(steps.len(), 4);
    }

    #[test]
    fn guesses_other_programs_with_an_api_key() {
        let s = sys().on("valve_corporation", "unused");
        let opts = ScanOptions {
            nvd_api_key: Some("k".into()),
            ..ScanOptions::default()
        };
        let (r, _) = scan(&s, &opts);
        assert!(!r.warnings.iter().any(|w| w.contains("NVD_API_KEY")));
        // Steam has no DisplayVersion, so nothing to guess with.
        assert!(!s.requests().iter().any(|q| q.contains("steam")));
    }

    #[test]
    fn falls_back_to_the_vendor_fix_without_winget() {
        let s = FakeSystem::new()
            .os("windows")
            .on("powershell.exe", inventory::tests::SAMPLE)
            .fail(msrc::UPDATES_URL, "offline")
            .on("cpe%3A2.3%3Aa%3A7-zip%3A7-zip", nvd::tests::PAGE)
            .on("nvd.nist.gov", r#"{"totalResults":0,"vulnerabilities":[]}"#)
            .fail("winget", "not found");
        let (r, rec) = scan(&s, &ScanOptions::default());
        assert_eq!(r.findings.len(), 1, "Windows could not be checked");
        let u = r.findings[0].update.as_ref().unwrap();
        // CVE-2099-0002 is fixed in 30.0, the newest fix.
        assert_eq!((u.channel.as_str(), u.build.as_str()), (VENDOR_CHANNEL, "30.0"));
        assert!(r.warnings.iter().any(|w| w.contains("MSRC")));
        assert!(r.warnings.iter().any(|w| w.contains("winget")));
        assert!(rec.steps().iter().filter(|s| s.outcome.is_err()).count() == 2);
    }

    #[test]
    fn says_when_windows_is_up_to_date() {
        let json = inventory::tests::SAMPLE.replace(r#""ubr":"9911""#, r#""ubr":"9974""#);
        let s = FakeSystem::new()
            .os("windows")
            .on("powershell.exe", &json)
            .on(msrc::UPDATES_URL, msrc::tests::MONTHS);
        let s = s
            .on("cvrf/2026-Nov", msrc::tests::NOV)
            .on("nvd.nist.gov", r#"{"totalResults":0,"vulnerabilities":[]}"#);
        let (r, _) = scan(&s.fail("winget", "none"), &ScanOptions::default());
        assert_eq!(
            r.notes,
            ["Windows 11 Version 24H2 build 10.0.26100.9974 has all security updates."]
        );
        assert!(!r.findings.iter().any(|f| f.package.starts_with("Windows")));
    }

    #[test]
    fn a_registry_failure_stops_the_scan() {
        let s = FakeSystem::new().os("windows").fail("powershell.exe", "access denied");
        assert!(
            Windows
                .scan(&s, &ScanOptions::default(), &crate::progress::Silent)
                .is_err()
        );
    }

    #[test]
    fn warns_about_windows_10() {
        let json = inventory::tests::SAMPLE
            .replace(r#""display_version":"24H2""#, r#""display_version":"22H2""#)
            .replace(r#""build":"26100""#, r#""build":"19045""#);
        let inv = inventory::parse(&json).unwrap();
        let s = FakeSystem::new()
            .on(msrc::UPDATES_URL, msrc::tests::MONTHS)
            .on("cvrf/2026-Nov", msrc::tests::NOV);
        let mut w = Vec::new();
        let f = check_windows(&s, &inv, "10.0.19045.9999", &crate::progress::Silent, &mut w).unwrap();
        assert!(f.vulnerabilities.is_empty());
        assert!(f.notes[0].contains("end of support"));
        assert_eq!(describe(&inv), "Windows 10 Pro 22H2 (build 19045.9911)");
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use crate::report::{console, markdown};

    #[test]
    fn reports_read_naturally() {
        let r = Windows
            .scan(&tests_sys(), &ScanOptions::default(), &crate::progress::Silent)
            .unwrap();
        let text = console::summary(&r, Some("r.md"), console::Palette::new(false));
        let md = markdown::render(&r, "2026-11-13 20:00 UTC");
        if std::env::var_os("VULNHOUND_PRINT").is_some() {
            println!("{text}\n=====\n{md}");
        }
        assert!(text.contains("4 of 6 programs checked against MSRC and NVD vulnerability data, 2 not checked"));
        assert!(text.contains("  winget upgrade --exact --id 7zip.7zip\n  start ms-settings:windowsupdate\n"));
        assert!(md.contains("## Vulnerable programs"));
        assert!(text.contains("Updates: 3 programs outdated"));
        assert!(md.contains("**Update:** `10.0.26100.9974` in Windows Update ([KB5132061](https://support.microsoft.com/help/KB5132061), security, high)"));
        assert!(md.contains("**Update:** `24.08` in winget\n"));
        assert!(md.contains("## Program updates"));
        assert!(md.contains("2 of 6 programs have no known NVD product, so they were not checked:"));
    }

    fn tests_sys() -> crate::system::fake::FakeSystem {
        crate::system::fake::FakeSystem::new()
            .os("windows")
            .on("powershell.exe", inventory::tests::SAMPLE)
            .on(msrc::UPDATES_URL, msrc::tests::MONTHS)
            .on("cvrf/2026-Nov", msrc::tests::NOV)
            .on("cvrf/2026-Oct", msrc::tests::OCT)
            .on("cpe%3A2.3%3Aa%3A7-zip%3A7-zip", nvd::tests::PAGE)
            .on("nvd.nist.gov", r#"{"totalResults":0,"vulnerabilities":[]}"#)
            .on("winget upgrade", winget::tests::OUTPUT)
    }
}
