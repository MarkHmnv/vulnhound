//! Fedora backend: rpm, dnf, Bodhi, Red Hat Bugzilla, release-monitoring.org and kernel CNA data.
//! Third-party packages have no vulnerability data; only their update status is checked.

pub mod bodhi;
pub mod bugzilla;
pub mod changelog;
pub mod rpmdb;

use crate::distro::{Backend, ScanOptions, Steps, or_warn};
use crate::model::{
    Confidence, Coverage, Finding, Report, Severity, ThirdPartyPackage, ThirdPartyStatus, Update, UpstreamRelease,
    Vulnerability,
};
use crate::progress::Progress;
use crate::report::plural;
use crate::rpmver::{Evr, rpmvercmp};
use crate::system::System;
use crate::{kernel, upstream};
use anyhow::Result;
use bodhi::{BodhiUpdate, Branched};
use bugzilla::{Flaw, Tracker};
use changelog::Changelog;
use rpmdb::{InstalledPackage, PendingUpgrade, TESTING_REPO};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

pub struct Fedora {
    pub release: String,
    pub pretty_name: String,
}

const KERNEL: &str = "kernel";
pub const KERNEL_CNA_SOURCE: &str = "kernel-cna";

const UPSTREAM_DISTRIBUTION: &str = "Fedora";

/// Always compared with upstream: network-facing, privileged or parsing untrusted input.
const UPSTREAM_WATCHLIST: &[&str] = &[
    "NetworkManager",
    "bash",
    "bind",
    "curl",
    "dnf5",
    "firefox",
    "git",
    "glibc",
    "gnupg2",
    "gnutls",
    "krb5",
    "libssh",
    "nss",
    "openssh",
    "openssl",
    "pam",
    "polkit",
    "rpm",
    "sudo",
    "systemd",
    "xz",
];

#[derive(Debug, Clone)]
struct SourcePackage {
    name: String,
    evr: Evr,
    vendor: String,
    binaries: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct Candidate {
    nvr: String,
    evr: Evr,
    repo: String,
    advisory: Option<BodhiUpdate>,
    upgrades: BTreeSet<String>,
}

impl Backend for Fedora {
    fn name(&self) -> &'static str {
        "fedora"
    }

    fn scan(&self, sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
        let mut warnings = Vec::new();
        let mut steps = Steps::new(progress, &mut warnings);

        progress.start("Reading installed packages", None);
        let installed = rpmdb::query_installed(sys).inspect_err(|e| progress.warn(&e.to_string()))?;
        progress.finish(&plural(installed.len(), "package"));
        let mut coverage = coverage(&installed);
        let sources = group_sources(installed.iter().filter(|p| p.is_fedora()));
        let foreign = group_sources(installed.iter().filter(|p| !p.is_fedora()));

        let pending = steps.run(
            "Listing available updates",
            |w| {
                or_warn(
                    rpmdb::query_pending(sys),
                    w,
                    "cannot list available upgrades, fixes will not be shown",
                )
            },
            |p| plural(p.len(), "package update"),
        );
        let candidates = steps.run(
            "Fetching update advisories from Bodhi",
            |w| candidates(sys, &sources, &pending, progress, w),
            |c| {
                let builds = c.values().flatten().count();
                format!("{}, {} security", plural(builds, "update"), security_count(c))
            },
        );

        let trackers = steps.run(
            "Searching Bugzilla for CVE trackers",
            |w| self.trackers(sys, &sources, progress, w),
            |t| plural(t.len(), "tracker"),
        );
        let flaws = if trackers.is_empty() {
            HashMap::new()
        } else {
            steps.run(
                "Fetching CVE details from Bugzilla",
                |w| flaws(sys, &trackers, progress, w),
                |f| plural(f.len(), "CVE"),
            )
        };
        let branched = if trackers.iter().any(|t| t.fixed_in_rawhide_at().is_some()) {
            steps.run(
                &format!("Checking when Fedora {} left rawhide", self.release),
                |w| self.branched(sys, w),
                |b| match b {
                    Some(Branched::At(t)) => t.format("%Y-%m-%d").to_string(),
                    Some(Branched::No) => "it is rawhide".into(),
                    None => String::new(),
                },
            )
        } else {
            None
        };
        let changelogs = steps.run(
            "Reading package changelogs",
            |w| {
                let tracked: BTreeSet<&String> = trackers.iter().map(|t| &t.component).collect();
                changelogs(sys, tracked.iter().map(|c| &sources[*c]), w)
            },
            |c| plural(c.len(), "package"),
        );
        let mut findings = tracker_findings(&trackers, &flaws, branched, &changelogs, &sources, &mut coverage);
        if opts.kernel_cves && sources.contains_key(KERNEL) {
            steps.run(
                "Checking the kernel against kernel CNA data",
                |w| add_kernel_cves(sys, &mut findings, &sources, &candidates, progress, w),
                |checked| match checked {
                    Some((n, version)) => {
                        let verb = if *n == 1 { "affects" } else { "affect" };
                        format!("{} {verb} {version}", plural(*n, "CVE"))
                    }
                    None => String::new(),
                },
            );
        }
        add_security_advisories(&mut findings, &candidates, &sources);
        let findings = finish(findings, &trackers, &candidates);

        let third_party = if foreign.is_empty() {
            Vec::new()
        } else {
            steps.run(
                "Checking third-party packages",
                |w| {
                    let extras = or_warn(
                        rpmdb::query_extras(sys),
                        w,
                        "cannot tell which packages have no repository",
                    );
                    third_party(&foreign, &pending, &extras)
                },
                |t| format!("{} need attention", plural(t.len(), "package")),
            )
        };

        let upstream = if opts.upstream {
            steps.run(
                "Comparing with upstream releases",
                |w| {
                    let names = upstream_names(&findings, &sources);
                    upstream_releases(sys, &names, &sources, &candidates, progress, w)
                },
                |u| format!("{} not in Fedora yet", plural(u.len(), "newer release")),
            )
        } else {
            Vec::new()
        };

        Ok(Report {
            distro: self.pretty_name.clone(),
            backend: self.name().into(),
            coverage,
            findings,
            third_party,
            upstream,
            warnings,
            notes: Vec::new(),
        })
    }
}

fn security_count(candidates: &BTreeMap<String, Vec<Candidate>>) -> usize {
    candidates
        .values()
        .flatten()
        .filter(|c| c.advisory.as_ref().is_some_and(|a| a.kind == "security"))
        .count()
}

impl Fedora {
    fn trackers(
        &self,
        sys: &dyn System,
        sources: &BTreeMap<String, SourcePackage>,
        progress: &dyn Progress,
        warnings: &mut Vec<String>,
    ) -> Vec<Tracker> {
        let components: Vec<String> = sources.keys().cloned().collect();
        or_warn(
            bugzilla::trackers_for_components(sys, &components, progress),
            warnings,
            "cannot query Red Hat Bugzilla, CVE trackers are missing",
        )
        .into_iter()
        .filter(|t| t.applies_to(&self.release) && sources.contains_key(&t.component))
        .collect()
    }
}

impl Fedora {
    /// `None` on failure: `RAWHIDE` trackers then stay in the report.
    fn branched(&self, sys: &dyn System, warnings: &mut Vec<String>) -> Option<Branched> {
        bodhi::branched(sys, &self.release)
            .map_err(|e| {
                warnings.push(format!(
                    "cannot tell when Fedora {} branched from rawhide, old rawhide fixes are reported as open: {e:#}",
                    self.release
                ))
            })
            .ok()
    }
}

fn flaws(
    sys: &dyn System,
    trackers: &[Tracker],
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> HashMap<u64, Flaw> {
    let ids: BTreeSet<u64> = trackers.iter().flat_map(|t| t.flaws.iter().copied()).collect();
    if ids.is_empty() {
        return HashMap::new();
    }
    let ids: Vec<u64> = ids.into_iter().collect();
    or_warn(
        bugzilla::flaws_by_id(sys, &ids, progress),
        warnings,
        "cannot fetch CVE details, severities are unknown",
    )
    .into_iter()
    .map(|f| (f.id, f))
    .collect()
}

fn tracker_findings(
    trackers: &[Tracker],
    flaws: &HashMap<u64, Flaw>,
    branched: Option<Branched>,
    changelogs: &HashMap<String, Changelog>,
    sources: &BTreeMap<String, SourcePackage>,
    coverage: &mut Coverage,
) -> BTreeMap<String, Finding> {
    let mut findings: BTreeMap<String, Finding> = BTreeMap::new();
    for t in trackers {
        let src = &sources[&t.component];
        let log = changelogs.get(&src.name);
        let flaw = t.flaws.iter().find_map(|id| flaws.get(id));
        // Fixed in rawhide before the branch: the release grew out of a rawhide with the fix.
        let fixed_before_branch = branched
            .zip(t.fixed_in_rawhide_at())
            .is_some_and(|(b, at)| b.has_rawhide_fix_from(at));
        if fixed_before_branch
            || log.is_some_and(|c| c.mentions(&t.cve))
            || flaw.is_some_and(|f| bugzilla::fixed_in_covers(&f.fixed_in, &src.name, &src.evr.version))
        {
            coverage.fixed_suppressed += 1;
            continue;
        }

        // Trackers often stay open long after a rebase fixed them.
        let rebased = t
            .created
            .is_some_and(|c| log.is_some_and(|l| l.rebased_since(c.timestamp(), &src.evr.version)));

        let summary = flaw.map_or(t.summary.as_str(), |f| f.summary.as_str());
        let vuln = Vulnerability {
            id: t.cve.clone(),
            severity: flaw.map_or(Severity::Unknown, |f| f.severity),
            title: bugzilla::display_title(summary, &src.name),
            url: bugzilla::bug_url(t.id),
            confidence: if rebased {
                Confidence::LikelyFixed
            } else {
                Confidence::Affected
            },
            source: "bugzilla-tracker".into(),
        };
        let f = findings.entry(src.name.clone()).or_insert_with(|| empty_finding(src));
        if !f.vulnerabilities.iter().any(|v| v.id == vuln.id) {
            f.vulnerabilities.push(vuln);
        }
    }
    findings
}

/// Fedora ships upstream stable kernels with few patches, so the version tells which fixes are in.
fn add_kernel_cves(
    sys: &dyn System,
    findings: &mut BTreeMap<String, Finding>,
    sources: &BTreeMap<String, SourcePackage>,
    candidates: &BTreeMap<String, Vec<Candidate>>,
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> Option<(usize, String)> {
    let src = sources.get(KERNEL)?;
    // Rawhide release candidates: 7.4.0-0.rc2 is not 7.4.0.
    if src.evr.release.starts_with("0.") {
        warnings.push(format!(
            "kernel {} is a pre-release, it is not checked against kernel CVE data",
            src.evr
        ));
        return None;
    }
    let offered = candidates
        .get(KERNEL)
        .and_then(|c| c.iter().max_by(|a, b| a.evr.cmp(&b.evr)));
    let checked = kernel::index(sys, progress, warnings).and_then(|records| {
        let installed = kernel::affecting(&records, &src.evr.version)?;
        let after_update = offered
            .map(|c| kernel::affecting(&records, &c.evr.version))
            .transpose()?;
        Ok((installed, after_update))
    });
    let (cves, after_update) = match checked {
        Ok(r) => r,
        Err(e) => {
            warnings.push(format!("cannot check the kernel against kernel CVE data: {e:#}"));
            return None;
        }
    };
    let checked = Some((cves.len(), src.evr.version.clone()));
    if cves.is_empty() {
        return checked;
    }

    let unfixed = cves.iter().filter(|c| c.fixed_in.is_none()).count();
    let verb = |n: usize, one: &str, many: &str| if n == 1 { one.to_string() } else { many.to_string() };
    let mut note = format!(
        "Kernel CNA data: {} {} {}",
        plural(cves.len(), "CVE"),
        verb(cves.len(), "affects", "affect"),
        src.evr.version
    );
    match (offered, &after_update) {
        (Some(c), Some(after)) => {
            let fixed = cves.iter().filter(|c| !after.iter().any(|a| a.id == c.id)).count();
            let channel = if c.repo == TESTING_REPO { "testing" } else { "stable" };
            let _ = write!(note, "; {} ({channel}) fixes {fixed}", c.evr.version);
        }
        _ => note.push_str("; no newer kernel is offered yet"),
    }
    if unfixed > 0 {
        let _ = write!(
            note,
            "; {unfixed} {} no fixed release yet",
            verb(unfixed, "has", "have")
        );
    }
    note.push_str(
        ". The CNA publishes CVEs days to weeks after the stable release that fixes them, so a new \
         release usually fixes more than listed.",
    );

    let f = findings.entry(src.name.clone()).or_insert_with(|| empty_finding(src));
    f.notes.push(note);
    for c in cves {
        if f.vulnerabilities.iter().any(|v| v.id == c.id) {
            continue;
        }
        let fix = match &c.fixed_in {
            Some(v) => format!("fixed in {v}"),
            None => "no fixed release yet".to_string(),
        };
        f.vulnerabilities.push(Vulnerability {
            title: format!("{} ({fix})", c.summary),
            url: kernel::cve_url(&c.id),
            id: c.id,
            severity: Severity::Unknown,
            confidence: Confidence::Affected,
            source: KERNEL_CNA_SOURCE.into(),
        });
    }
    checked
}

/// CVEs of security advisories that are available but not installed.
fn add_security_advisories(
    findings: &mut BTreeMap<String, Finding>,
    candidates: &BTreeMap<String, Vec<Candidate>>,
    sources: &BTreeMap<String, SourcePackage>,
) {
    for (name, cands) in candidates {
        for adv in cands
            .iter()
            .filter_map(|c| c.advisory.as_ref())
            .filter(|a| a.kind == "security")
        {
            let f = findings
                .entry(name.clone())
                .or_insert_with(|| empty_finding(&sources[name]));
            for id in &adv.cves {
                if !f.vulnerabilities.iter().any(|v| &v.id == id) {
                    f.vulnerabilities.push(Vulnerability {
                        id: id.clone(),
                        severity: adv.severity,
                        title: format!("fixed by {}", adv.alias),
                        url: adv.url.clone(),
                        confidence: Confidence::Affected,
                        source: "bodhi-advisory".into(),
                    });
                }
            }
        }
    }
}

fn finish(
    findings: BTreeMap<String, Finding>,
    trackers: &[Tracker],
    candidates: &BTreeMap<String, Vec<Candidate>>,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = findings
        .into_values()
        .map(|mut f| {
            let bug_ids: BTreeSet<u64> = trackers
                .iter()
                .filter(|t| t.component == f.package)
                .flat_map(|t| std::iter::once(t.id).chain(t.flaws.iter().copied()))
                .collect();
            if let Some(cands) = candidates.get(&f.package) {
                f.update = best_candidate(cands, &f, &bug_ids).map(to_update);
            }
            f.vulnerabilities
                .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
            f.recompute_severity();
            f
        })
        .collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package)));
    out
}

fn upstream_names(findings: &[Finding], sources: &BTreeMap<String, SourcePackage>) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = findings
        .iter()
        .filter(|f| !f.is_likely_fixed_only())
        .map(|f| f.package.clone())
        .collect();
    names.extend(
        UPSTREAM_WATCHLIST
            .iter()
            .filter(|n| sources.contains_key(**n))
            .map(|n| (*n).to_string()),
    );
    names
}

fn candidates(
    sys: &dyn System,
    sources: &BTreeMap<String, SourcePackage>,
    pending: &[PendingUpgrade],
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, Vec<Candidate>> {
    let mut by_nvr: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut owner: HashMap<String, String> = HashMap::new();
    for p in pending
        .iter()
        .filter(|p| p.is_fedora_repo() && sources.contains_key(&p.source_name))
    {
        let c = by_nvr.entry(p.source_nvr.clone()).or_insert_with(|| Candidate {
            nvr: p.source_nvr.clone(),
            evr: crate::rpmver::split_nvr(&p.source_nvr).map_or_else(|| p.evr.clone(), |(_, e)| e),
            repo: p.repo.clone(),
            advisory: None,
            upgrades: BTreeSet::new(),
        });
        c.upgrades.insert(p.name.clone());
        owner.insert(p.source_nvr.clone(), p.source_name.clone());
    }

    let nvrs: Vec<String> = by_nvr.keys().cloned().collect();
    if !nvrs.is_empty() {
        match bodhi::updates_for_builds(sys, &nvrs, progress) {
            Ok(updates) => {
                for u in updates {
                    for b in &u.builds {
                        if let Some(c) = by_nvr.get_mut(b) {
                            c.advisory = Some(u.clone());
                        }
                    }
                }
            }
            Err(e) => warnings.push(format!("cannot query Bodhi, advisory types are unknown: {e:#}")),
        }
    }

    let mut out: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
    for (nvr, c) in by_nvr {
        out.entry(owner[&nvr].clone()).or_default().push(c);
    }
    out
}

fn empty_finding(src: &SourcePackage) -> Finding {
    Finding {
        package: src.name.clone(),
        installed: src.evr.to_string(),
        severity: Severity::Unknown,
        vulnerabilities: Vec::new(),
        update: None,
        notes: Vec::new(),
    }
}

fn coverage(installed: &[InstalledPackage]) -> Coverage {
    let mut vendors: BTreeMap<String, usize> = BTreeMap::new();
    let mut covered = 0;
    for p in installed {
        if p.is_fedora() {
            covered += 1;
        } else {
            let v = if p.vendor.is_empty() {
                "(no vendor)".to_string()
            } else {
                p.vendor.clone()
            };
            *vendors.entry(v).or_default() += 1;
        }
    }
    let mut uncovered_vendors: Vec<(String, usize)> = vendors.into_iter().collect();
    uncovered_vendors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Coverage {
        installed_packages: installed.len(),
        covered_packages: covered,
        uncovered_packages: installed.len() - covered,
        uncovered_vendors,
        fixed_suppressed: 0,
    }
}

/// Of several installed versions (old kernels), only the newest counts, as for dnf.
fn group_sources<'a>(packages: impl Iterator<Item = &'a InstalledPackage>) -> BTreeMap<String, SourcePackage> {
    let mut out: BTreeMap<String, SourcePackage> = BTreeMap::new();
    for p in packages {
        let entry = out.entry(p.source_name.clone()).or_insert_with(|| SourcePackage {
            name: p.source_name.clone(),
            evr: p.source_evr.clone(),
            vendor: String::new(),
            binaries: BTreeSet::new(),
        });
        // Locally built kmods have no vendor; a sibling package has it.
        if entry.vendor.is_empty() {
            entry.vendor.clone_from(&p.vendor);
        }
        if p.source_evr > entry.evr {
            entry.evr = p.source_evr.clone();
            entry.binaries.clear();
        }
        if p.source_evr == entry.evr {
            entry.binaries.insert(p.name.clone());
        }
    }
    out
}

fn third_party(
    sources: &BTreeMap<String, SourcePackage>,
    pending: &[PendingUpgrade],
    extras: &BTreeSet<String>,
) -> Vec<ThirdPartyPackage> {
    let mut out = Vec::new();
    for src in sources.values() {
        let newer: Vec<&PendingUpgrade> = pending
            .iter()
            .filter(|p| p.source_name == src.name && src.binaries.contains(&p.name))
            .collect();
        let status = if let Some(best) = newer.iter().max_by(|a, b| a.evr.cmp(&b.evr)) {
            let upgrades: BTreeSet<String> = newer.iter().map(|p| p.name.clone()).collect();
            let upgrades: Vec<String> = upgrades.into_iter().collect();
            ThirdPartyStatus::UpdateAvailable {
                version: best.evr.to_string(),
                repo: best.repo.clone(),
                command: upgrade_command(&best.repo, &upgrades),
                upgrades,
            }
        } else if src.binaries.iter().all(|b| extras.contains(b)) {
            ThirdPartyStatus::NoRepository
        } else {
            continue;
        };
        out.push(ThirdPartyPackage {
            package: src.name.clone(),
            vendor: src.vendor.clone(),
            installed: src.evr.to_string(),
            status,
        });
    }
    out
}

fn upstream_releases(
    sys: &dyn System,
    names: &BTreeSet<String>,
    sources: &BTreeMap<String, SourcePackage>,
    candidates: &BTreeMap<String, Vec<Candidate>>,
    progress: &dyn Progress,
    warnings: &mut Vec<String>,
) -> Vec<UpstreamRelease> {
    let names: Vec<String> = names.iter().cloned().collect();
    let mut out = Vec::new();
    let mut failures = 0;
    let mut first_error = None;
    for (name, result) in names
        .iter()
        .zip(upstream::latest_versions(sys, UPSTREAM_DISTRIBUTION, &names, progress))
    {
        let latest = match result {
            Ok(Some(latest)) => latest,
            Ok(None) => continue,
            Err(e) => {
                failures += 1;
                first_error.get_or_insert(e);
                continue;
            }
        };
        let offered = candidates
            .get(name)
            .into_iter()
            .flatten()
            .map(|c| c.evr.version.as_str())
            .chain(std::iter::once(sources[name].evr.version.as_str()))
            .max_by(|a, b| rpmvercmp(a, b))
            .expect("the installed version is always there");
        if rpmvercmp(&latest.version, offered) == Ordering::Greater {
            out.push(UpstreamRelease {
                package: name.clone(),
                distro_version: offered.to_string(),
                upstream_version: latest.version,
                project: latest.project,
            });
        }
    }
    if let Some(e) = first_error {
        warnings.push(format!(
            "cannot check upstream releases of {failures} of {} packages: {e:#}",
            names.len()
        ));
    }
    out
}

/// Source name → changelog, read through one binary package of each.
fn changelogs<'a>(
    sys: &dyn System,
    sources: impl Iterator<Item = &'a SourcePackage>,
    warnings: &mut Vec<String>,
) -> HashMap<String, Changelog> {
    let by_binary: BTreeMap<&str, &str> = sources
        .filter_map(|s| s.binaries.iter().next().map(|b| (b.as_str(), s.name.as_str())))
        .collect();
    let binaries: Vec<&str> = by_binary.keys().copied().collect();
    match changelog::read(sys, &binaries) {
        Ok(mut logs) => by_binary
            .iter()
            .filter_map(|(bin, src)| logs.remove(*bin).map(|l| (src.to_string(), l)))
            .collect(),
        Err(e) => {
            warnings.push(format!(
                "cannot read package changelogs, backported fixes are not recognized: {e:#}"
            ));
            HashMap::new()
        }
    }
}

/// Prefers an advisory that names the finding's bugs or CVEs, then a security one, then the newest.
fn best_candidate<'a>(cands: &'a [Candidate], f: &Finding, bug_ids: &BTreeSet<u64>) -> Option<&'a Candidate> {
    let rank = |c: &Candidate| {
        let adv = c.advisory.as_ref();
        let linked = adv.is_some_and(|a| {
            a.bug_ids.iter().any(|b| bug_ids.contains(b))
                || a.cves.iter().any(|id| f.vulnerabilities.iter().any(|v| &v.id == id))
        });
        let security = adv.is_some_and(|a| a.kind == "security");
        (linked, security)
    };
    cands
        .iter()
        .max_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.evr.cmp(&b.evr)))
}

fn upgrade_command(repo: &str, packages: &[String]) -> String {
    let enable = if repo == TESTING_REPO {
        format!(" --enablerepo={TESTING_REPO}")
    } else {
        String::new()
    };
    format!("sudo dnf upgrade --refresh{enable} {}", packages.join(" "))
}

fn to_update(c: &Candidate) -> Update {
    let channel = if c.repo == TESTING_REPO { "testing" } else { "stable" };
    let upgrades: Vec<String> = c.upgrades.iter().cloned().collect();
    let command = upgrade_command(&c.repo, &upgrades);
    let (id, kind, severity, url) = match &c.advisory {
        Some(a) => (a.alias.clone(), a.kind.clone(), a.severity, a.url.clone()),
        None => (String::new(), "unknown".to_string(), Severity::Unknown, String::new()),
    };
    Update {
        id,
        kind,
        severity,
        build: c.nvr.clone(),
        channel: channel.into(),
        url,
        upgrades,
        command,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::Silent;
    use crate::progress::recording::Recording;
    use crate::system::fake::FakeSystem;

    const RPM_QA: &str = "git-core\t0\t2.56.0\t1.fc45\tx86_64\tgit-2.56.0-1.fc45.src.rpm\tFedora Project\t1791211692\n\
git-core-doc\t0\t2.56.0\t1.fc45\tnoarch\tgit-2.56.0-1.fc45.src.rpm\tFedora Project\t1791211692\n\
kernel-core\t0\t7.2.15\t300.fc45\tx86_64\tkernel-7.2.15-300.fc45.src.rpm\tFedora Project\t1790000000\n\
kernel-core\t0\t7.3.3\t300.fc45\tx86_64\tkernel-7.3.3-300.fc45.src.rpm\tFedora Project\t1791900000\n\
openssl\t1\t3.6.0\t1.fc45\tx86_64\topenssl-3.6.0-1.fc45.src.rpm\tFedora Project\t1790000000\n\
yasm\t0\t1.3.0\t30.fc45\tx86_64\tyasm-1.3.0-30.fc45.src.rpm\tFedora Project\t1790000000\n\
code\t0\t1.145.0\t1.el8\tx86_64\tcode-1.145.0-1.el8.src.rpm\t(none)\t1790000000\n\
akmod-nvidia\t3\t620.70.05\t1.fc45\tx86_64\tnvidia-kmod-620.70.05-1.fc45.src.rpm\tRPM Fusion\t1790000000\n\
kmod-nvidia-7.3.3\t3\t620.70.05\t1.fc45\tx86_64\tnvidia-kmod-620.70.05-1.fc45.src.rpm\t(none)\t1790000000\n\
wordcraft\t0\t0.17.0\t1\tx86_64\twordcraft-0.17.0-1.src.rpm\tLearning Machines LLC\t1790000000\n";

    /// Installed packages that no repository provides: a local install and a locally built kmod.
    const EXTRAS: &str = "wordcraft\nkmod-nvidia-7.3.3\n";

    fn upstream_fixture(name: &str, version: &str) -> String {
        format!(r#"{{"items":[{{"name":"{name}","project":"{name}","stable_version":"{version}"}}]}}"#)
    }

    const REPOQUERY: &str = "git-core\t0\t2.56.1\t1.fc45\tx86_64\tgit-2.56.1-1.fc45.src.rpm\tupdates-testing\n\
git-core-doc\t0\t2.56.1\t1.fc45\tnoarch\tgit-2.56.1-1.fc45.src.rpm\tupdates-testing\n\
openssl\t1\t3.6.1\t1.fc45\tx86_64\topenssl-3.6.1-1.fc45.src.rpm\tupdates\n\
code\t0\t1.146.0\t1.el8\tx86_64\tcode-1.146.0-1.el8.src.rpm\tcode\n";

    const BODHI: &str = r#"{"updates":[
      {"alias":"FEDORA-2026-5c62077075","type":"enhancement","severity":"unspecified","status":"testing",
       "title":"git-2.56.1-1.fc45","notes":"update to 2.56.1","url":"https://bodhi.example/git",
       "builds":[{"nvr":"git-2.56.1-1.fc45"}],"bugs":[]},
      {"alias":"FEDORA-2026-0pen55l","type":"security","severity":"high","status":"stable",
       "title":"openssl-3.6.1-1.fc45","notes":"Fixes CVE-2026-7777","url":"https://bodhi.example/openssl",
       "builds":[{"nvr":"openssl-3.6.1-1.fc45"}],"bugs":[]}
    ],"pages":1}"#;

    const TRACKERS: &str = r#"{"bugs":[
      {"id":2571477,"status":"CLOSED","resolution":"RAWHIDE","version":["rawhide"],"component":["git"],
       "blocks":[2567365],"creation_time":"2026-11-11T07:03:10Z","cf_last_closed":"2026-11-11T09:00:00Z",
       "summary":"CVE-2026-111760 git: Git: Arbitrary code execution via unsafe submodule metadata [fedora-all]"},
      {"id":2571484,"status":"CLOSED","resolution":"RAWHIDE","version":["rawhide"],"component":["git"],
       "blocks":[2567369],"creation_time":"2026-11-11T07:04:00Z",
       "summary":"CVE-2026-113408 git: git: Unintended file writes via malformed unborn HEAD [fedora-all]"},
      {"id":2400001,"status":"NEW","resolution":"","version":["45"],"component":["git"],
       "blocks":[2400000],"creation_time":"2025-01-01T00:00:00Z",
       "summary":"CVE-2025-1111 git: old issue already fixed by a backport [fedora-all]"},
      {"id":2122744,"status":"NEW","resolution":"","version":["45"],"component":["yasm"],
       "blocks":[2122713],"creation_time":"2022-08-30T17:18:22Z",
       "summary":"CVE-2021-33458 yasm: NULL pointer dereference in find_cc() [fedora-all]"},
      {"id":2408120,"status":"NEW","resolution":"","version":["43"],"component":["yasm"],
       "blocks":[2407260],"creation_time":"2025-10-30T19:44:39Z",
       "summary":"CVE-2025-58189 yasm: only for fedora 43 [fedora-43]"},
      {"id":782697,"status":"CLOSED","resolution":"RAWHIDE","version":["rawhide"],"component":["yasm"],
       "blocks":[782696],"creation_time":"2012-01-18T10:00:00Z","cf_last_closed":"2012-01-18T23:10:18Z",
       "summary":"CVE-2012-0058 yasm: fixed in rawhide long before Fedora 45 branched [fedora-all]"}
    ]}"#;

    const FLAWS: &str = r#"{"bugs":[
      {"id":2567365,"severity":"high","creation_time":"2026-11-06T10:00:00Z","cf_fixed_in":"",
       "summary":"CVE-2026-111760 git: Git: Arbitrary code execution via unsafe submodule metadata"},
      {"id":2567369,"severity":"medium","creation_time":"2026-11-06T10:05:00Z","cf_fixed_in":"",
       "summary":"CVE-2026-113408 git: git: Unintended file writes via malformed unborn HEAD"},
      {"id":2122713,"severity":"low","creation_time":"2022-08-30T17:00:00Z","cf_fixed_in":"",
       "summary":"CVE-2021-33458 yasm: NULL pointer dereference in find_cc()"}
    ]}"#;

    fn system() -> FakeSystem {
        system_after(FakeSystem::new())
    }

    /// The standard fixture, consulted after the rules already in `first`.
    fn system_after(first: FakeSystem) -> FakeSystem {
        first
            .on("rpm -qa", RPM_QA)
            .on("--extras", EXTRAS)
            .on("dnf repoquery", REPOQUERY)
            .on("releases/?name=F46", bodhi::tests::F46_RELEASE)
            .on("releases=F46", bodhi::tests::F46_FIRST_UPDATE)
            .on("bodhi", BODHI)
            .on_bytes("Linux/all.zip", &kernel::tests::sample_export())
            .on("keywords=SecurityTracking", TRACKERS)
            .on("rest/bug?id=", FLAWS)
            .on("rpm -q --qf", &changelogs_fixture())
            .on("&name=git", &upstream_fixture("git", "2.56.1"))
            .on("&name=openssl", &upstream_fixture("openssl", "3.6.2"))
            .on("release-monitoring.org", r#"{"items":[]}"#)
    }

    fn changelogs_fixture() -> String {
        changelog::tests::render(&[
            (
                "git-core",
                &[
                    (1791000000, "P <p@x> - 2.56.0-1", "- update to 2.56.0"),
                    (
                        1782000000,
                        "P <p@x> - 2.55.0-1",
                        "- update to 2.55.0\n- fixes CVE-2025-1111",
                    ),
                ],
            ),
            ("yasm", &[(1780000000, "P <p@x> - 1.3.0-30", "- rebuilt")]),
        ])
    }

    #[test]
    fn changelog_failure_is_a_warning() {
        let pkgs = rpmdb::parse_installed(RPM_QA);
        let sources = group_sources(pkgs.iter().filter(|p| p.is_fedora()));
        let sys = FakeSystem::new().fail("rpm -q --qf", "boom");
        let mut warnings = vec![];
        assert!(changelogs(&sys, [&sources["git"]].into_iter(), &mut warnings).is_empty());
        assert!(warnings[0].contains("changelogs"));
    }

    fn fedora() -> Fedora {
        Fedora {
            release: "45".into(),
            pretty_name: "Fedora Linux 45".into(),
        }
    }

    fn scan(sys: &FakeSystem) -> Report {
        fedora().scan(sys, &ScanOptions::default(), &Silent).unwrap()
    }

    #[test]
    fn every_step_is_closed_and_counts_all_its_requests() {
        let progress = Recording::default();
        fedora().scan(&system(), &ScanOptions::default(), &progress).unwrap();
        let steps = progress.steps();
        assert!(steps.len() >= 8);
        for s in &steps {
            assert!(s.outcome.is_ok(), "{s:?}");
            if let Some(total) = s.total {
                assert_eq!(s.done, total, "{}", s.name);
            }
        }
    }

    #[test]
    fn failed_steps_end_with_their_warning() {
        let progress = Recording::default();
        let sys = system_after(FakeSystem::new().fail("keywords=SecurityTracking", "offline"));
        fedora().scan(&sys, &ScanOptions::default(), &progress).unwrap();
        let bz = progress
            .steps()
            .into_iter()
            .find(|s| s.name.starts_with("Searching Bugzilla"))
            .unwrap();
        assert_eq!(
            bz.outcome,
            Err("cannot query Red Hat Bugzilla, CVE trackers are missing: offline".into())
        );
    }

    #[test]
    fn finds_git_cves_and_the_fix_waiting_in_testing() {
        let r = scan(&system());
        let git = r.findings.iter().find(|f| f.package == "git").expect("git finding");
        assert_eq!(git.installed, "2.56.0-1.fc45");
        assert_eq!(git.severity, Severity::High);
        let ids: Vec<&str> = git.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2026-111760", "CVE-2026-113408"], "sorted by severity");
        assert!(git.vulnerabilities.iter().all(|v| v.confidence == Confidence::Affected));
        assert_eq!(
            git.vulnerabilities[0].title,
            "Arbitrary code execution via unsafe submodule metadata"
        );
        assert_eq!(
            git.vulnerabilities[0].url,
            "https://bugzilla.redhat.com/show_bug.cgi?id=2571477"
        );

        let up = git.update.as_ref().expect("update in testing");
        assert_eq!(up.build, "git-2.56.1-1.fc45");
        assert_eq!(up.channel, "testing");
        assert_eq!(up.kind, "enhancement");
        assert_eq!(up.upgrades, vec!["git-core", "git-core-doc"]);
        assert_eq!(
            up.command,
            "sudo dnf upgrade --refresh --enablerepo=updates-testing git-core git-core-doc"
        );
    }

    #[test]
    fn suppresses_cves_named_in_the_installed_changelog() {
        let r = scan(&system());
        let git = r.findings.iter().find(|f| f.package == "git").unwrap();
        assert!(!git.vulnerabilities.iter().any(|v| v.id == "CVE-2025-1111"));
        assert_eq!(r.coverage.fixed_suppressed, 2, "the backport and the old rawhide fix");
    }

    #[test]
    fn rawhide_fixes_from_before_the_branch_are_in_the_release() {
        let r = scan(&system());
        let yasm = r.findings.iter().find(|f| f.package == "yasm").unwrap();
        assert!(!yasm.vulnerabilities.iter().any(|v| v.id == "CVE-2012-0058"));
        let git = r.findings.iter().find(|f| f.package == "git").unwrap();
        assert!(
            git.vulnerabilities.iter().any(|v| v.id == "CVE-2026-111760"),
            "fixed in rawhide after the branch: still open here"
        );
    }

    #[test]
    fn unknown_branch_point_keeps_rawhide_fixes_and_warns() {
        let sys = system_after(FakeSystem::new().fail("releases/?name=F46", "bodhi down"));
        let r = scan(&sys);
        let yasm = r.findings.iter().find(|f| f.package == "yasm").unwrap();
        assert!(yasm.vulnerabilities.iter().any(|v| v.id == "CVE-2012-0058"));
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("branched from rawhide") && w.contains("bodhi down")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn reports_pending_security_advisories_without_trackers() {
        let r = scan(&system());
        let ssl = r
            .findings
            .iter()
            .find(|f| f.package == "openssl")
            .expect("openssl finding");
        assert_eq!(ssl.installed, "1:3.6.0-1.fc45");
        assert_eq!(ssl.severity, Severity::High);
        assert_eq!(ssl.vulnerabilities[0].id, "CVE-2026-7777");
        assert_eq!(ssl.vulnerabilities[0].source, "bodhi-advisory");
        assert_eq!(ssl.update.as_ref().unwrap().channel, "stable");
        assert_eq!(
            ssl.update.as_ref().unwrap().command,
            "sudo dnf upgrade --refresh openssl"
        );
    }

    #[test]
    fn keeps_open_trackers_and_skips_other_releases() {
        let r = scan(&system());
        let yasm = r.findings.iter().find(|f| f.package == "yasm").expect("yasm finding");
        let ids: Vec<&str> = yasm.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2021-33458"]);
        assert_eq!(yasm.severity, Severity::Low);
        assert!(yasm.update.is_none());
    }

    #[test]
    fn findings_are_sorted_by_severity() {
        let r = scan(&system());
        let names: Vec<&str> = r.findings.iter().map(|f| f.package.as_str()).collect();
        assert_eq!(
            names,
            vec!["git", "openssl", "yasm", "kernel"],
            "kernel CVEs have no severity, so they do not push the kernel up"
        );
    }

    #[test]
    fn adds_kernel_cves_for_the_newest_installed_kernel() {
        let r = scan(&system());
        let k = r
            .findings
            .iter()
            .find(|f| f.package == "kernel")
            .expect("kernel finding");
        assert_eq!(k.installed, "7.3.3-300.fc45");
        let rows: Vec<(&str, &str)> = k
            .vulnerabilities
            .iter()
            .map(|v| (v.id.as_str(), v.title.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    "CVE-2026-99286",
                    "xen-netback: Fix XenBus connection failure cleanup (fixed in 7.3.4)"
                ),
                ("CVE-2026-99999", "net: no fix yet (no fixed release yet)"),
            ]
        );
        assert!(k.vulnerabilities.iter().all(|v| v.source == KERNEL_CNA_SOURCE
            && v.severity == Severity::Unknown
            && v.url.starts_with("https://osv.dev/vulnerability/")));
        assert_eq!(
            k.notes[0].split(". ").next().unwrap(),
            "Kernel CNA data: 2 CVEs affect 7.3.3; no newer kernel is offered yet; 1 has no fixed release yet"
        );
    }

    #[test]
    fn kernel_note_counts_what_the_offered_update_fixes() {
        let repoquery = format!(
            "{REPOQUERY}kernel-core\t0\t7.3.4\t300.fc45\tx86_64\tkernel-7.3.4-300.fc45.src.rpm\tupdates-testing\n"
        );
        let sys = system_after(FakeSystem::new().on("--upgrades", &repoquery));
        let r = scan(&sys);
        let k = r.findings.iter().find(|f| f.package == "kernel").unwrap();
        assert!(
            k.notes[0].starts_with(
                "Kernel CNA data: 2 CVEs affect 7.3.3; 7.3.4 (testing) fixes 1; 1 has no fixed release yet. "
            ),
            "{}",
            k.notes[0]
        );
        assert_eq!(k.update.as_ref().unwrap().build, "kernel-7.3.4-300.fc45");
    }

    #[test]
    fn prerelease_kernels_are_not_matched_by_version() {
        let rpm = RPM_QA.replace(
            "7.3.3\t300.fc45\tx86_64\tkernel-7.3.3-300.fc45.src.rpm",
            "7.4.0\t0.rc2.24.fc46\tx86_64\tkernel-7.4.0-0.rc2.24.fc46.src.rpm",
        );
        assert_ne!(rpm, RPM_QA);
        let sys = system_after(FakeSystem::new().on("rpm -qa", &rpm));
        let r = scan(&sys);
        assert!(!r.findings.iter().any(|f| f.package == "kernel"));
        assert!(r.warnings.iter().any(|w| w.contains("pre-release")), "{:?}", r.warnings);
    }

    #[test]
    fn trackers_are_likely_fixed_after_an_upstream_rebase() {
        // git moved from 2.55.0 to 2.56.0 after every git tracker was filed.
        let log = changelog::tests::render(&[
            (
                "git-core",
                &[
                    (1799999999, "P <p@x> - 2.56.0-1", "- update to 2.56.0"),
                    (1782000000, "P <p@x> - 2.55.0-1", "- update to 2.55.0"),
                ],
            ),
            ("yasm", &[(1780000000, "P <p@x> - 1.3.0-30", "- rebuilt")]),
        ]);
        let sys = FakeSystem::new()
            .on("rpm -qa", RPM_QA)
            .on("dnf repoquery", "")
            .on("keywords=SecurityTracking", TRACKERS)
            .on("rest/bug?id=", FLAWS)
            .on("rpm -q --qf", &log);
        let r = scan(&sys);
        let git = r.findings.iter().find(|f| f.package == "git").unwrap();
        assert_eq!(git.vulnerabilities.len(), 3);
        assert!(
            git.vulnerabilities
                .iter()
                .all(|v| v.confidence == Confidence::LikelyFixed)
        );
        assert!(git.is_likely_fixed_only());

        // yasm kept the same upstream version, so its old open tracker stays affected.
        let yasm = r.findings.iter().find(|f| f.package == "yasm").unwrap();
        assert_eq!(yasm.vulnerabilities[0].confidence, Confidence::Affected);
    }

    #[test]
    fn fixed_in_data_suppresses_cves() {
        let flaws = FLAWS.replace(
            r#""severity":"high","creation_time":"2026-11-06T10:00:00Z","cf_fixed_in":"""#,
            r#""severity":"high","creation_time":"2026-11-06T10:00:00Z","cf_fixed_in":"git 2.56.0""#,
        );
        let sys = FakeSystem::new()
            .on("rpm -qa", RPM_QA)
            .on("dnf repoquery", "")
            .on("keywords=SecurityTracking", TRACKERS)
            .on("rest/bug?id=", &flaws)
            .on("rpm -q --qf", "");
        let r = scan(&sys);
        let git = r.findings.iter().find(|f| f.package == "git").unwrap();
        assert!(!git.vulnerabilities.iter().any(|v| v.id == "CVE-2026-111760"));
    }

    #[test]
    fn coverage_counts_third_party_packages() {
        let r = scan(&system());
        assert_eq!(r.coverage.installed_packages, 10);
        assert_eq!(r.coverage.covered_packages, 6);
        assert_eq!(r.coverage.uncovered_packages, 4);
        assert_eq!(
            r.coverage.uncovered_vendors,
            vec![
                ("(no vendor)".to_string(), 2),
                ("Learning Machines LLC".to_string(), 1),
                ("RPM Fusion".to_string(), 1)
            ]
        );
    }

    #[test]
    fn third_party_packages_report_updates_and_missing_repositories() {
        let r = scan(&system());
        assert_eq!(
            r.third_party,
            vec![
                ThirdPartyPackage {
                    package: "code".into(),
                    vendor: String::new(),
                    installed: "1.145.0-1.el8".into(),
                    status: ThirdPartyStatus::UpdateAvailable {
                        version: "1.146.0-1.el8".into(),
                        repo: "code".into(),
                        upgrades: vec!["code".into()],
                        command: "sudo dnf upgrade --refresh code".into(),
                    },
                },
                ThirdPartyPackage {
                    package: "wordcraft".into(),
                    vendor: "Learning Machines LLC".into(),
                    installed: "0.17.0-1".into(),
                    status: ThirdPartyStatus::NoRepository,
                },
            ],
            "nvidia-kmod is current: its akmod comes from a repository, only the built kmod does not"
        );
        assert!(
            !r.findings.iter().any(|f| f.package == "code"),
            "never a vulnerability finding"
        );
    }

    #[test]
    fn upstream_reports_only_releases_fedora_does_not_offer() {
        let sys = system();
        let r = scan(&sys);
        // git 2.56.1 is upstream's latest and already waits in testing; openssl 3.6.2 is newer
        // than the pending 3.6.1; yasm has no upstream mapping.
        assert_eq!(
            r.upstream,
            vec![UpstreamRelease {
                package: "openssl".into(),
                distro_version: "3.6.1".into(),
                upstream_version: "3.6.2".into(),
                project: "openssl".into(),
            }]
        );
        let asked: Vec<String> = sys
            .requests()
            .into_iter()
            .filter(|u| u.contains("release-monitoring.org"))
            .collect();
        assert_eq!(asked.len(), 4, "packages with findings: git, openssl, yasm, kernel");
        assert!(asked.iter().all(|u| u.contains("distribution=Fedora")));
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    #[test]
    fn watchlist_finds_upstream_releases_without_findings() {
        let sys = FakeSystem::new()
            .on("rpm -qa", RPM_QA)
            .on("dnf repoquery", "")
            .on("keywords=SecurityTracking", r#"{"bugs":[]}"#)
            .on("&name=git", &upstream_fixture("git", "2.56.1"))
            .on("release-monitoring.org", r#"{"items":[]}"#);
        let r = scan(&sys);
        assert!(r.findings.is_empty());
        // No tracker and no pending update, yet the watchlist catches the new git release.
        assert_eq!(r.upstream.len(), 1);
        assert_eq!(r.upstream[0].package, "git");
        assert_eq!(r.upstream[0].distro_version, "2.56.0");
        assert_eq!(r.upstream[0].upstream_version, "2.56.1");
    }

    #[test]
    fn disabled_sources_are_not_contacted() {
        let sys = system();
        let opts = ScanOptions {
            upstream: false,
            kernel_cves: false,
            nvd_api_key: None,
        };
        let r = fedora().scan(&sys, &opts, &Silent).unwrap();
        assert!(r.upstream.is_empty());
        assert!(!r.findings.iter().any(|f| f.package == "kernel"));
        assert!(
            !sys.requests()
                .iter()
                .any(|u| u.contains("release-monitoring.org") || u.contains("osv"))
        );
    }

    #[test]
    fn upstream_failures_become_one_warning() {
        let sys = FakeSystem::new()
            .on("rpm -qa", RPM_QA)
            .on("dnf repoquery", "")
            .on("keywords=SecurityTracking", r#"{"bugs":[]}"#)
            .on("&name=git", &upstream_fixture("git", "2.56.1"))
            .fail("release-monitoring.org", "timeout");
        let opts = ScanOptions {
            kernel_cves: false,
            ..ScanOptions::default()
        };
        let r = fedora().scan(&sys, &opts, &Silent).unwrap();
        assert_eq!(r.upstream.len(), 1, "successful lookups still count");
        assert_eq!(r.warnings.len(), 1);
        assert!(
            r.warnings[0].contains("upstream releases of 1 of 2 packages: timeout"),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn only_queries_bugzilla_for_fedora_packages() {
        let sys = system();
        scan(&sys);
        let reqs = sys.requests();
        let q = reqs.iter().find(|r| r.contains("SecurityTracking")).unwrap();
        assert!(q.contains("component=git"));
        assert!(!q.contains("component=code"));
        assert!(!q.contains("component=nvidia-kmod"));
    }

    #[test]
    fn network_failures_become_warnings() {
        let sys = FakeSystem::new()
            .on("rpm -qa", RPM_QA)
            .fail("dnf repoquery", "dnf exploded")
            .fail("keywords=SecurityTracking", "offline");
        let r = scan(&sys);
        assert!(r.findings.is_empty());
        assert!(r.third_party.is_empty());
        assert!(r.upstream.is_empty());
        assert_eq!(r.warnings.len(), 5, "{:?}", r.warnings);
        assert!(r.warnings[0].contains("dnf exploded"));
        assert!(r.warnings[1].contains("Bugzilla"));
        assert!(r.warnings[2].contains("kernel CVE data"));
        assert!(r.warnings[3].contains("no repository"));
        assert!(r.warnings[4].contains("upstream releases of 2 of 2 packages"));
    }

    #[test]
    fn missing_rpm_is_an_error() {
        let sys = FakeSystem::new().fail("rpm -qa", "rpm not found");
        assert!(fedora().scan(&sys, &ScanOptions::default(), &Silent).is_err());
    }

    #[test]
    fn groups_binaries_by_source_package() {
        let pkgs = rpmdb::parse_installed(RPM_QA);
        let fedora = group_sources(pkgs.iter().filter(|p| p.is_fedora()));
        assert_eq!(fedora["kernel"].evr.version, "7.3.3", "old kernels are ignored");
        assert_eq!(fedora["git"].binaries.len(), 2);
        let foreign = group_sources(pkgs.iter().filter(|p| !p.is_fedora()));
        // The locally built kmod has no vendor; its akmod sibling names it.
        assert_eq!(foreign["nvidia-kmod"].vendor, "RPM Fusion");
        assert_eq!(foreign["code"].vendor, "");
    }
}
