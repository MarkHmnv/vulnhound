//! Debian and Ubuntu backend: dpkg and apt for what is installed and where it comes from, Debian's
//! security tracker or Ubuntu's OVAL data for CVEs, and Ubuntu Pro's status for fixes that only Pro
//! subscribers get.
//!
//! Both distributions backport fixes into the version they shipped, so a CVE applies when the
//! installed source package is older than the version the distribution names as fixed, or when it
//! names no fix yet. Upstream versions and kernel CNA data say nothing about backports and are not
//! used.

pub mod apt;
pub mod oval;
pub mod pro;
pub mod tracker;

use crate::debver;
use crate::distro::{Backend, ScanOptions, Steps};
use crate::model::{
    Confidence, Coverage, Finding, Report, Severity, ThirdPartyPackage, ThirdPartyStatus, Update, Vulnerability,
};
use crate::progress::Progress;
use crate::report::{PRO_CHANNEL_PREFIX, plural};
use crate::system::System;
use anyhow::{Context, Result};
use apt::{InstalledPackage, Origin, Policy};
use pro::ProStatus;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Debian,
    Ubuntu,
}

pub struct Debian {
    pub flavor: Flavor,
    pub codename: String,
    pub pretty_name: String,
}

/// One CVE of one source package in the scanned release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub package: String,
    pub cve: String,
    pub severity: Severity,
    pub title: String,
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Status {
    /// Versions older than `version` are affected. `pocket` is where the fix is published: the
    /// release, its security archive, Ubuntu Pro's `esm-apps` or `esm-infra`; empty if unknown.
    Fixed { version: String, pocket: String },
    /// The release has no fix; `note` says why, e.g. "no fix yet".
    Open { note: String },
}

const TITLE_MAX: usize = 120;

/// The first sentence of a CVE description, at most [`TITLE_MAX`] characters.
pub(crate) fn short_title(description: &str) -> String {
    let text = description.split_whitespace().collect::<Vec<_>>().join(" ");
    let first = text.split(". ").next().unwrap_or("").trim_end_matches('.');
    if first.chars().count() <= TITLE_MAX {
        return first.to_string();
    }
    let mut out = String::new();
    for word in first.split(' ') {
        if out.chars().count() + word.chars().count() + 1 > TITLE_MAX {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out.push('…');
    out
}

const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Bump when the index format changes.
const INDEX_FORMAT: u32 = 2;

/// The cached advisories. Ubuntu lists each kernel CVE for some 30 kernel flavours, so CVE details
/// are stored once and packages refer to them.
#[derive(Serialize, Deserialize)]
struct Index {
    format: u32,
    /// (id, severity, title)
    cves: Vec<(String, Severity, String)>,
    /// Package → (index into `cves`, fixed version or "" if open, pocket if fixed or else note).
    packages: BTreeMap<String, Vec<(u32, String, String)>>,
}

impl Index {
    fn new(advisories: &[Advisory]) -> Self {
        let mut cves = Vec::new();
        let mut ids: HashMap<&str, u32> = HashMap::new();
        let mut packages: BTreeMap<String, Vec<(u32, String, String)>> = BTreeMap::new();
        for a in advisories {
            let i = *ids.entry(&a.cve).or_insert_with(|| {
                cves.push((a.cve.clone(), a.severity, a.title.clone()));
                u32::try_from(cves.len() - 1).expect("fewer than 4 billion CVEs")
            });
            let (version, other) = match &a.status {
                Status::Fixed { version, pocket } => (version.clone(), pocket.clone()),
                Status::Open { note } => (String::new(), note.clone()),
            };
            packages.entry(a.package.clone()).or_default().push((i, version, other));
        }
        Self {
            format: INDEX_FORMAT,
            cves,
            packages,
        }
    }

    fn advisories(self) -> Option<Vec<Advisory>> {
        let mut out = Vec::new();
        for (package, entries) in self.packages {
            for (i, version, other) in entries {
                let (cve, severity, title) = self.cves.get(i as usize)?;
                out.push(Advisory {
                    package: package.clone(),
                    cve: cve.clone(),
                    severity: *severity,
                    title: title.clone(),
                    status: if version.is_empty() {
                        Status::Open { note: other }
                    } else {
                        Status::Fixed { version, pocket: other }
                    },
                });
            }
        }
        Some(out)
    }
}

const KERNEL_UPGRADE: &str = "sudo apt update && sudo apt full-upgrade";
const KERNEL_NOTE: &str = "Each kernel version is a new package: `apt full-upgrade` installs it through the kernel \
                           metapackage (linux-image-amd64 on Debian, linux-generic on Ubuntu, or the one for your \
                           kernel flavour; install it if it is missing). Reboot to run the new kernel.";

/// A source package as installed: its newest version and the binary packages built from it.
#[derive(Debug, Clone)]
struct SourcePackage {
    name: String,
    version: String,
    vendor: String,
    /// Names as `apt install` takes them.
    binaries: BTreeSet<String>,
}

impl SourcePackage {
    fn is_kernel(&self) -> bool {
        self.binaries
            .iter()
            .any(|b| b.starts_with("linux-image-") || b.starts_with("linux-modules-"))
    }
}

impl Flavor {
    fn name(self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Debian => "Debian",
            Self::Ubuntu => "Ubuntu",
        }
    }

    fn is_own_origin(self, origin: &str) -> bool {
        match self {
            // "Debian Backports" too.
            Self::Debian => origin == "Debian" || origin.starts_with("Debian "),
            // Ubuntu, UbuntuESM, UbuntuESMApps, UbuntuFIPS, ... but not LP-PPA-*.
            Self::Ubuntu => origin.starts_with("Ubuntu"),
        }
    }

    /// The source package and version the security data tracks. Signed kernel images are built
    /// from their own source package; their version is the kernel's. `None` for the kernel's
    /// headers and tools: kernel CVEs apply to an installed kernel, not to those.
    fn tracked_source(self, pkg: &InstalledPackage) -> Option<(String, String)> {
        if is_kernel_extra(pkg.bare_name()) {
            return None;
        }
        Some(match (self, pkg.source_name.strip_prefix("linux-signed")) {
            // linux-signed-amd64 6.12.117+1 builds linux-image-6.12.117+deb13-amd64 6.12.117-1.
            (Self::Debian, Some(_)) => ("linux".into(), pkg.version.clone()),
            // linux-signed-hwe-6.8 → linux-hwe-6.8, with the same version.
            (Self::Ubuntu, Some(rest)) => (format!("linux{rest}"), pkg.source_version.clone()),
            _ => (pkg.source_name.clone(), pkg.source_version.clone()),
        })
    }
}

impl Backend for Debian {
    fn name(&self) -> &'static str {
        self.flavor.name()
    }

    fn scan(&self, sys: &dyn System, _opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
        let mut warnings = Vec::new();
        let label = self.flavor.label();

        progress.start("Reading installed packages", None);
        let installed = apt::query_installed(sys).inspect_err(|e| progress.warn(&format!("{e:#}")))?;
        progress.finish(&plural(installed.len(), "package"));

        // apt and the Pro client (a Python program) take a few seconds; they run while the
        // security data downloads.
        let (advisories, apt, pro) = std::thread::scope(|s| -> Result<_> {
            let apt = s.spawn(|| {
                let mut w = Vec::new();
                (self.apt_state(sys, &installed, &mut w), w)
            });
            let pro = (self.flavor == Flavor::Ubuntu).then(|| s.spawn(|| pro::query(sys)));

            progress.start(
                match self.flavor {
                    Flavor::Debian => "Fetching Debian's security tracker data",
                    Flavor::Ubuntu => "Fetching Ubuntu's OVAL data",
                },
                None,
            );
            let before = warnings.len();
            let advisories = self
                .advisories(sys, progress, &mut warnings)
                .inspect_err(|e| progress.warn(&format!("{e:#}")))?;
            match warnings.get(before) {
                Some(w) => progress.warn(w),
                None => {
                    let cves: BTreeSet<&str> = advisories.iter().map(|a| a.cve.as_str()).collect();
                    progress.finish(&plural(cves.len(), "CVE"));
                }
            }

            let mut steps = Steps::new(progress, &mut warnings);
            let apt = steps.run(
                "Reading apt's package lists",
                |w| {
                    let (apt, apt_warnings) = apt.join().expect("reading apt's state does not panic");
                    w.extend(apt_warnings);
                    apt
                },
                |a| match a {
                    Some(a) => plural(a.origins.len(), "package list"),
                    None => String::new(),
                },
            );
            let pro = match pro {
                Some(pro) => steps.run(
                    "Checking Ubuntu Pro",
                    |_| pro.join().expect("querying pro does not panic"),
                    describe_pro,
                ),
                None => ProStatus::default(),
            };
            Ok((advisories, apt, pro))
        })?;

        let (distro, foreign, coverage) = classify(self.flavor, &installed, apt.as_ref());
        let sources = group_sources(self.flavor, distro.iter().copied());
        let mut findings = self.findings(&sources, &advisories, apt.as_ref(), &pro);
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package)));

        let mut notes = Vec::new();
        if !findings.iter().any(|f| f.update.is_some()) {
            notes.push(format!("Every security fix {label} has published is installed."));
        }
        self.pro_messages(&findings, &advisories, &pro, &mut warnings, &mut notes);
        let third_party = match &apt {
            Some(apt) => third_party(&group_sources(self.flavor, foreign.iter().copied()), &foreign, apt),
            None => Vec::new(),
        };

        Ok(Report {
            distro: self.pretty_name.clone(),
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

fn describe_pro(p: &ProStatus) -> String {
    match (p.client, p.attached) {
        (false, _) => "no Pro client, not attached".into(),
        (true, false) => "not attached".into(),
        (true, true) if p.enabled.is_empty() => "attached, no services enabled".into(),
        (true, true) => format!("attached: {}", p.enabled.join(", ")),
    }
}

/// apt's view of the installed packages: its package lists and every installed package's versions.
struct AptState {
    origins: HashMap<String, Origin>,
    policies: HashMap<String, Policy>,
}

impl Debian {
    fn apt_state(
        &self,
        sys: &dyn System,
        installed: &[InstalledPackage],
        warnings: &mut Vec<String>,
    ) -> Option<AptState> {
        let (origins, policies) = match apt::query_policy(sys, installed) {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!(
                    "cannot ask apt where packages come from, third-party packages are not told apart: {e:#}"
                ));
                return None;
            }
        };
        if !origins.values().any(|o| self.flavor.is_own_origin(&o.origin)) {
            warnings.push(format!(
                "apt has no package lists from {} (run `sudo apt update`), third-party packages are not told apart",
                self.flavor.label()
            ));
            return None;
        }
        Some(AptState { origins, policies })
    }

    /// The release's advisories from the cache if fresh, else downloaded; a stale cache if the
    /// download fails.
    fn advisories(
        &self,
        sys: &dyn System,
        progress: &dyn Progress,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<Advisory>> {
        let cache_file = format!("{}-{}-advisories.json", self.flavor.name(), self.codename);
        let cached = sys.cache_read(&cache_file).and_then(|(text, written)| {
            let index: Index = serde_json::from_str(&text).ok()?;
            (index.format == INDEX_FORMAT).then_some(())?;
            Some((index.advisories()?, written))
        });
        let age = |written: SystemTime| SystemTime::now().duration_since(written).unwrap_or_default();
        if let Some((advisories, written)) = &cached
            && age(*written) < CACHE_MAX_AGE
        {
            return Ok(advisories.clone());
        }

        let fresh = match self.flavor {
            Flavor::Debian => {
                progress.detail("downloading about 15 MB from Debian, once a day");
                tracker::download(sys).and_then(|json| {
                    progress.detail("indexing");
                    tracker::parse(&json, &self.codename)
                })
            }
            Flavor::Ubuntu => {
                progress.detail("downloading about 12 MB from Canonical, once a day");
                oval::download(sys, &self.codename).and_then(|bz2| {
                    progress.detail("indexing");
                    oval::parse_bz2(&bz2, &self.codename)
                })
            }
        };
        match (fresh, cached) {
            (Ok(advisories), _) => {
                if let Err(e) = sys.cache_write(&cache_file, &serde_json::to_string(&Index::new(&advisories))?) {
                    warnings.push(format!(
                        "cannot cache security data, it will be downloaded again: {e:#}"
                    ));
                }
                Ok(advisories)
            }
            (Err(e), Some((advisories, written))) => {
                let days = age(written).as_secs() / 86_400;
                warnings.push(format!("security data is {days} days old, refreshing failed: {e:#}"));
                Ok(advisories)
            }
            (Err(e), None) => Err(e).context("without security data nothing can be checked"),
        }
    }

    fn cve_url(&self, id: &str) -> String {
        match self.flavor {
            Flavor::Debian => tracker::cve_url(id),
            Flavor::Ubuntu => oval::cve_url(id),
        }
    }

    fn findings(
        &self,
        sources: &BTreeMap<String, SourcePackage>,
        advisories: &[Advisory],
        apt: Option<&AptState>,
        pro: &ProStatus,
    ) -> Vec<Finding> {
        let mut by_package: HashMap<&str, Vec<&Advisory>> = HashMap::new();
        for a in advisories {
            by_package.entry(a.package.as_str()).or_default().push(a);
        }
        let mut out = Vec::new();
        for src in sources.values() {
            let Some(advs) = by_package.get(src.name.as_str()) else {
                continue;
            };
            let mut vulns = Vec::new();
            // The fixes the installed version lacks: (version, pocket, severity).
            let mut needed: Vec<(&str, &str, Severity)> = Vec::new();
            for a in advs {
                let note = match &a.status {
                    Status::Fixed { version, pocket } => {
                        if debver::cmp(&src.version, version) != Ordering::Less {
                            continue;
                        }
                        needed.push((version, pocket, a.severity));
                        None
                    }
                    Status::Open { note } => Some(note.as_str()),
                };
                if vulns.iter().any(|v: &Vulnerability| v.id == a.cve) {
                    continue;
                }
                let title = match (a.title.as_str(), note) {
                    ("", Some(n)) => n.to_string(),
                    (t, Some(n)) => format!("{t} ({n})"),
                    (t, None) => t.to_string(),
                };
                vulns.push(Vulnerability {
                    id: a.cve.clone(),
                    severity: a.severity,
                    title,
                    url: self.cve_url(&a.cve),
                    confidence: Confidence::Affected,
                    source: format!("{}-security-data", self.flavor.name()),
                });
            }
            if vulns.is_empty() {
                continue;
            }
            vulns.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
            let mut f = Finding {
                package: src.name.clone(),
                installed: src.version.clone(),
                severity: Severity::Unknown,
                vulnerabilities: vulns,
                update: None,
                notes: Vec::new(),
            };
            if let Some((update, note)) = self.update(src, &needed, apt, pro) {
                f.update = Some(update);
                f.notes.extend(note);
            }
            f.recompute_severity();
            out.push(f);
        }
        out
    }

    /// The update that fixes every CVE with a fix, and a note when apt cannot see it yet.
    fn update(
        &self,
        src: &SourcePackage,
        needed: &[(&str, &str, Severity)],
        apt: Option<&AptState>,
        pro: &ProStatus,
    ) -> Option<(Update, Option<String>)> {
        let &(target, pocket, _) = needed.iter().max_by(|a, b| debver::cmp(a.0, b.0))?;
        let severity = needed.iter().map(|n| n.2).max().unwrap_or(Severity::Unknown);
        let upgrades: Vec<String> = src.binaries.iter().cloned().collect();
        let kernel = src.is_kernel();
        // A new kernel is a new package (linux-image-6.8.0-149-generic); its metapackage pulls it in.
        let apt_upgrade = if kernel {
            KERNEL_UPGRADE.to_string()
        } else {
            format!(
                "sudo apt update && sudo apt install --only-upgrade {}",
                upgrades.join(" ")
            )
        };
        let update = |version: &str, channel: String, command: String| Update {
            id: String::new(),
            kind: "security".into(),
            severity,
            build: format!("{} {version}", src.name),
            channel,
            url: String::new(),
            upgrades: upgrades.clone(),
            command,
        };

        // Fixes in esm-apps and esm-infra reach only machines with that Pro service enabled.
        if self.flavor == Flavor::Ubuntu && pocket.starts_with("esm-") && !pro.delivers(pocket) {
            let enable = if !pro.client {
                "sudo apt install ubuntu-pro-client && sudo pro attach".to_string()
            } else if !pro.attached {
                "sudo pro attach".to_string()
            } else {
                format!("sudo pro enable {pocket}")
            };
            let command = format!("{enable} && {apt_upgrade}");
            let note = kernel.then(|| KERNEL_NOTE.to_string());
            return Some((update(target, format!("{PRO_CHANNEL_PREFIX}{pocket}"), command), note));
        }

        let candidate = if kernel {
            None
        } else {
            apt.and_then(|a| self.candidate(src, a))
        };
        Some(match candidate {
            Some((version, suite)) if debver::cmp(&version, target) != Ordering::Less => {
                (update(&version, suite, apt_upgrade), None)
            }
            _ => {
                let channel = if pocket.is_empty() {
                    self.codename.clone()
                } else {
                    pocket.to_string()
                };
                let note = if kernel {
                    Some(KERNEL_NOTE.to_string())
                } else {
                    apt.map(|_| {
                        format!("apt's package lists do not have {target} yet; `sudo apt update` fetches them.")
                    })
                };
                (update(target, channel, apt_upgrade), note)
            }
        })
    }

    /// The newest version apt would install for any binary of `src`, from the distribution, and
    /// the suite it is in.
    fn candidate(&self, src: &SourcePackage, apt: &AptState) -> Option<(String, String)> {
        src.binaries
            .iter()
            .filter_map(|b| apt.policies.get(b))
            .filter_map(|p| {
                let version = p.candidate.as_ref()?;
                let origin = p
                    .indexes_of(version)
                    .iter()
                    .filter_map(|k| apt.origins.get(k))
                    .find(|o| self.flavor.is_own_origin(&o.origin))?;
                Some((version.clone(), origin.suite.clone()))
            })
            .max_by(|a, b| debver::cmp(&a.0, &b.0))
    }

    fn pro_messages(
        &self,
        findings: &[Finding],
        advisories: &[Advisory],
        pro: &ProStatus,
        warnings: &mut Vec<String>,
        notes: &mut Vec<String>,
    ) {
        if self.flavor != Flavor::Ubuntu {
            return;
        }
        // Past standard support, Canonical publishes the release's fixes to esm-infra only.
        let in_esm = advisories
            .iter()
            .any(|a| matches!(&a.status, Status::Fixed { pocket, .. } if pocket == "esm-infra"));
        if in_esm && !pro.delivers("esm-infra") {
            warnings.push(format!(
                "Ubuntu {} is past its standard support: security fixes for its main packages are published to \
                 Ubuntu Pro (esm-infra) only, which this machine does not get",
                self.codename
            ));
        }
        let pro_only: BTreeMap<String, usize> = findings
            .iter()
            .filter_map(|f| {
                f.update
                    .as_ref()?
                    .channel
                    .strip_prefix(PRO_CHANNEL_PREFIX)
                    .map(String::from)
            })
            .fold(BTreeMap::new(), |mut m, s| {
                *m.entry(s).or_default() += 1;
                m
            });
        if !pro_only.is_empty() {
            let parts: Vec<String> = pro_only
                .iter()
                .map(|(service, n)| format!("{} in {service}", plural(*n, "package")))
                .collect();
            warnings.push(format!(
                "fixes for {} are published to Ubuntu Pro only, which this machine does not get; Pro is free for \
                 personal use on up to 5 machines: https://ubuntu.com/pro",
                parts.join(" and ")
            ));
        }
        if pro.attached && !pro.enabled.is_empty() {
            notes.push(format!("Ubuntu Pro is attached: {}.", pro.enabled.join(", ")));
        }
    }
}

/// (distro packages, third-party packages, coverage). Without apt's view every package counts as
/// the distribution's.
fn classify<'a>(
    flavor: Flavor,
    installed: &'a [InstalledPackage],
    apt: Option<&AptState>,
) -> (Vec<&'a InstalledPackage>, Vec<&'a InstalledPackage>, Coverage) {
    let mut distro = Vec::new();
    let mut foreign = Vec::new();
    let mut vendors: BTreeMap<String, usize> = BTreeMap::new();
    for p in installed {
        match apt.map_or(Ok(()), |a| origin_of(flavor, p, a)) {
            Ok(()) => distro.push(p),
            Err(vendor) => {
                let v = if vendor.is_empty() {
                    "(no vendor)".to_string()
                } else {
                    vendor
                };
                *vendors.entry(v).or_default() += 1;
                foreign.push(p);
            }
        }
    }
    let mut uncovered_vendors: Vec<(String, usize)> = vendors.into_iter().collect();
    uncovered_vendors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let coverage = Coverage {
        installed_packages: installed.len(),
        covered_packages: distro.len(),
        uncovered_packages: foreign.len(),
        uncovered_vendors,
        fixed_suppressed: 0,
    };
    (distro, foreign, coverage)
}

/// `Ok` for the distribution's packages, else `Err(vendor)`. The installed version's lists decide;
/// if no list has it any more (Debian drops superseded versions), the newest available version's.
fn origin_of(flavor: Flavor, p: &InstalledPackage, apt: &AptState) -> Result<(), String> {
    let Some(policy) = apt::policy_for(&apt.policies, p) else {
        return Err(p.maintainer.clone());
    };
    let mut indexes = policy.indexes_of(&p.version);
    if indexes.is_empty() {
        indexes = policy.newest_available().map_or(&[], |(_, idx)| idx);
    }
    let origins: Vec<&Origin> = indexes.iter().filter_map(|k| apt.origins.get(k)).collect();
    if origins.iter().any(|o| flavor.is_own_origin(&o.origin)) {
        Ok(())
    } else {
        Err(origins
            .first()
            .map_or_else(|| p.maintainer.clone(), |o| o.vendor().to_string()))
    }
}

/// Packages built from a kernel source that are not the kernel: `linux-libc-dev` comes with any
/// compiler, also in containers that run another kernel.
fn is_kernel_extra(binary: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "linux-libc-dev",
        "linux-headers-",
        "linux-kbuild-",
        "linux-tools-",
        "linux-cloud-tools-",
        "linux-source",
        "linux-doc",
        "linux-bpf-dev",
    ];
    PREFIXES.iter().any(|p| binary.starts_with(p))
        // Ubuntu's linux-hwe-6.8-headers-6.8.0-51, linux-aws-tools-6.8.0-1021, ...
        || (binary.starts_with("linux-") && (binary.contains("-headers-") || binary.contains("-tools-")))
}

/// Of several installed versions (old kernels), only the newest counts.
fn group_sources<'a>(
    flavor: Flavor,
    packages: impl Iterator<Item = &'a InstalledPackage>,
) -> BTreeMap<String, SourcePackage> {
    let mut out: BTreeMap<String, SourcePackage> = BTreeMap::new();
    for p in packages {
        let Some((name, version)) = flavor.tracked_source(p) else {
            continue;
        };
        let entry = out.entry(name.clone()).or_insert_with(|| SourcePackage {
            name,
            version: version.clone(),
            vendor: p.maintainer.clone(),
            binaries: BTreeSet::new(),
        });
        match debver::cmp(&version, &entry.version) {
            Ordering::Greater => {
                entry.version = version;
                entry.binaries.clear();
                entry.binaries.insert(p.bare_name().to_string());
            }
            Ordering::Equal => {
                entry.binaries.insert(p.bare_name().to_string());
            }
            Ordering::Less => {}
        }
    }
    out
}

fn third_party(
    sources: &BTreeMap<String, SourcePackage>,
    foreign: &[&InstalledPackage],
    apt: &AptState,
) -> Vec<ThirdPartyPackage> {
    let mut out = Vec::new();
    for src in sources.values() {
        let binaries: Vec<&&InstalledPackage> = foreign
            .iter()
            .filter(|p| src.binaries.contains(p.bare_name()))
            .collect();
        let policies: Vec<(&InstalledPackage, &Policy)> = binaries
            .iter()
            .filter_map(|p| apt::policy_for(&apt.policies, p).map(|pol| (**p, pol)))
            .collect();
        let newer: Vec<(&InstalledPackage, &str, &[String])> = policies
            .iter()
            .filter_map(|(p, pol)| {
                let (v, idx) = pol.newest_available()?;
                apt::newer(v, &p.version).then_some((*p, v, idx))
            })
            .collect();
        let vendor = |idx: &[String]| {
            idx.iter()
                .filter_map(|k| apt.origins.get(k))
                .map(Origin::vendor)
                .find(|v| !v.is_empty())
                .unwrap_or_default()
                .to_string()
        };
        let status = if let Some((_, version, idx)) = newer.iter().max_by(|a, b| debver::cmp(a.1, b.1)) {
            let upgrades: BTreeSet<String> = newer.iter().map(|(p, ..)| p.bare_name().to_string()).collect();
            let upgrades: Vec<String> = upgrades.into_iter().collect();
            ThirdPartyStatus::UpdateAvailable {
                version: (*version).to_string(),
                repo: vendor(idx),
                command: format!(
                    "sudo apt update && sudo apt install --only-upgrade {}",
                    upgrades.join(" ")
                ),
                upgrades,
            }
        } else if policies.iter().all(|(_, pol)| pol.newest_available().is_none()) {
            ThirdPartyStatus::NoRepository
        } else {
            continue;
        };
        let installed_vendor = policies
            .iter()
            .find_map(|(p, pol)| Some(vendor(pol.indexes_of(&p.version))).filter(|v| !v.is_empty()));
        out.push(ThirdPartyPackage {
            package: src.name.clone(),
            vendor: installed_vendor.unwrap_or_else(|| src.vendor.clone()),
            installed: src.version.clone(),
            status,
        });
    }
    out
}

#[cfg(test)]
mod tests;
