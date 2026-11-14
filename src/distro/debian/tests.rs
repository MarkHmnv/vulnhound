use super::*;
use crate::progress::Silent;
use crate::progress::recording::Recording;
use crate::system::fake::FakeSystem;

// ---- Debian 12 -------------------------------------------------------------------------------

const DPKG_BOOKWORM: &str = "\
libssl3:amd64\t3.0.20-1~deb12u1\topenssl\t3.0.20-1~deb12u1\tii \tDebian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
openssl\t3.0.20-1~deb12u1\topenssl\t3.0.20-1~deb12u1\tii \tDebian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
7zip\t22.01+dfsg-8\t7zip\t22.01+dfsg-8\tii \tYOKOTA Hiroshi <yokota.hgml@gmail.com>
libc6:amd64\t2.36-9+deb12u14\tglibc\t2.36-9+deb12u14\tii \tGNU Libc Maintainers <debian-glibc@lists.debian.org>
linux-image-6.1.0-50-amd64\t6.1.180-1\tlinux-signed-amd64\t6.1.180+1\tii \tDebian Kernel Team <debian-kernel@lists.debian.org>
linux-image-6.1.0-54-amd64\t6.1.190-1\tlinux-signed-amd64\t6.1.190+1\tii \tDebian Kernel Team <debian-kernel@lists.debian.org>
linux-libc-dev:amd64\t6.1.195-1\tlinux\t6.1.195-1\tii \tDebian Kernel Team <debian-kernel@lists.debian.org>
docker-ce\t5:28.0.0-1~debian.12~bookworm\tdocker-ce\t5:28.0.0-1~debian.12~bookworm\tii \tDocker <support@docker.com>
localtool\t1.0\tlocaltool\t1.0\tii \tJane Doe <j@x>
";

const ORIGINS_BOOKWORM: &str = "Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
     release v=12,o=Debian,a=oldstable-security,n=bookworm-security,l=Debian-Security,c=main,b=amd64
     origin deb.debian.org
 500 http://deb.debian.org/debian bookworm/main amd64 Packages
     release v=12.15,o=Debian,a=oldstable,n=bookworm,l=Debian,c=main,b=amd64
     origin deb.debian.org
 500 https://download.docker.com/linux/debian bookworm/stable amd64 Packages
     release o=Docker,a=bookworm,l=Docker CE,c=stable,b=amd64
     origin download.docker.com
";

const DEB: &str = "http://deb.debian.org/debian bookworm/main amd64 Packages";
const DEB_SEC: &str = "http://deb.debian.org/debian-security bookworm-security/main amd64 Packages";
const DOCKER: &str = "https://download.docker.com/linux/debian bookworm/stable amd64 Packages";

fn policy(name: &str, installed: &str, versions: &[(&str, &[&str])]) -> String {
    let candidate = versions
        .iter()
        .filter(|(_, idx)| !idx.is_empty())
        .map(|(v, _)| *v)
        .chain(std::iter::once(installed))
        .max_by(|a, b| debver::cmp(a, b))
        .unwrap();
    let mut out = format!("{name}:\n  Installed: {installed}\n  Candidate: {candidate}\n  Version table:\n");
    for (v, idx) in versions {
        let mark = if *v == installed { " ***" } else { "    " };
        out.push_str(&format!("{mark} {v} 500\n"));
        for i in *idx {
            out.push_str(&format!("        500 {i}\n"));
        }
        if *v == installed {
            out.push_str("        100 /var/lib/dpkg/status\n");
        }
    }
    out
}

fn policy_bookworm() -> String {
    [
        // The installed openssl was superseded: no list has it any more.
        policy(
            "libssl3",
            "3.0.20-1~deb12u1",
            &[("3.0.22-1~deb12u2", &[DEB_SEC]), ("3.0.20-1~deb12u1", &[])],
        ),
        policy(
            "openssl",
            "3.0.20-1~deb12u1",
            &[("3.0.22-1~deb12u2", &[DEB_SEC]), ("3.0.20-1~deb12u1", &[])],
        ),
        policy("7zip", "22.01+dfsg-8", &[("22.01+dfsg-8", &[DEB])]),
        policy("libc6", "2.36-9+deb12u14", &[("2.36-9+deb12u14", &[DEB])]),
        policy("linux-image-6.1.0-50-amd64", "6.1.180-1", &[("6.1.180-1", &[DEB])]),
        policy("linux-image-6.1.0-54-amd64", "6.1.190-1", &[("6.1.190-1", &[DEB_SEC])]),
        policy("linux-libc-dev", "6.1.195-1", &[("6.1.195-1", &[DEB_SEC])]),
        policy(
            "docker-ce",
            "5:28.0.0-1~debian.12~bookworm",
            &[
                ("5:28.1.0-1~debian.12~bookworm", &[DOCKER]),
                ("5:28.0.0-1~debian.12~bookworm", &[DOCKER]),
            ],
        ),
        policy("localtool", "1.0", &[("1.0", &[])]),
    ]
    .concat()
}

const TRACKER: &str = r#"{
  "openssl": {
    "CVE-2026-9076": {"description": "A crafted PKCS#12 file can crash the application.", "releases": {
      "bookworm": {"status": "resolved", "repositories": {"bookworm": "3.0.20-1~deb12u2", "bookworm-security": "3.0.22-1~deb12u2"},
                   "fixed_version": "3.0.20-1~deb12u2", "urgency": "medium"}}},
    "CVE-2026-1000": {"description": "Heap overflow in X.509 parsing.", "releases": {
      "bookworm": {"status": "resolved", "repositories": {"bookworm": "3.0.20-1~deb12u2", "bookworm-security": "3.0.22-1~deb12u2"},
                   "fixed_version": "3.0.22-1~deb12u1", "urgency": "high"}}},
    "CVE-2025-0001": {"description": "Fixed long ago.", "releases": {
      "bookworm": {"status": "resolved", "repositories": {"bookworm": "3.0.20-1~deb12u2"},
                   "fixed_version": "3.0.15-1~deb12u1", "urgency": "high"}}},
    "CVE-2026-95691": {"description": "CMS_encrypt() may loop indefinitely.", "releases": {
      "bookworm": {"status": "open", "repositories": {"bookworm": "3.0.20-1~deb12u2"}, "urgency": "low"}}}
  },
  "7zip": {
    "CVE-2026-14266": {"description": "", "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "22.01+dfsg-8"},
      "urgency": "not yet assigned", "nodsa": "Minor issue", "nodsa_reason": "", "next_point_update": true}}},
    "CVE-2026-48092": {"description": "", "releases": {"bookworm": {"status": "open", "repositories": {"bookworm": "22.01+dfsg-8"},
      "urgency": "unimportant"}}}
  },
  "linux": {
    "CVE-2026-7001": {"description": "net: use-after-free in tcp.", "releases": {"bookworm": {"status": "resolved",
      "repositories": {"bookworm": "6.1.190-1", "bookworm-security": "6.1.195-1"}, "fixed_version": "6.1.195-1", "urgency": "not yet assigned"}}},
    "CVE-2026-7002": {"description": "Fixed in the installed kernel.", "releases": {"bookworm": {"status": "resolved",
      "repositories": {"bookworm": "6.1.190-1"}, "fixed_version": "6.1.185-1", "urgency": "not yet assigned"}}}
  },
  "docker.io": {
    "CVE-2026-8000": {"description": "Not the package that is installed.", "releases": {"bookworm": {"status": "open",
      "repositories": {"bookworm": "20.10.24+dfsg1-1"}, "urgency": "high"}}}
  }
}"#;

fn bookworm_system() -> FakeSystem {
    FakeSystem::new()
        .on("dpkg-query", DPKG_BOOKWORM)
        .on("apt-cache policy ", &policy_bookworm())
        .on("apt-cache policy", ORIGINS_BOOKWORM)
        .on("security-tracker.debian.org", TRACKER)
}

fn bookworm() -> Debian {
    Debian {
        flavor: Flavor::Debian,
        codename: "bookworm".into(),
        pretty_name: "Debian GNU/Linux 12 (bookworm)".into(),
    }
}

fn scan(backend: &Debian, sys: &FakeSystem) -> Report {
    backend.scan(sys, &ScanOptions::default(), &Silent).unwrap()
}

fn finding<'a>(r: &'a Report, package: &str) -> &'a Finding {
    r.findings
        .iter()
        .find(|f| f.package == package)
        .unwrap_or_else(|| panic!("no finding for {package}: {:?}", r.findings))
}

#[test]
fn finds_cves_the_installed_version_lacks_and_the_update_that_fixes_them() {
    let r = scan(&bookworm(), &bookworm_system());
    assert_eq!(r.backend, "debian");
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let ssl = finding(&r, "openssl");
    assert_eq!(ssl.installed, "3.0.20-1~deb12u1");
    assert_eq!(ssl.severity, Severity::High);
    let rows: Vec<(&str, &str)> = ssl
        .vulnerabilities
        .iter()
        .map(|v| (v.id.as_str(), v.title.as_str()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("CVE-2026-1000", "Heap overflow in X.509 parsing"),
            ("CVE-2026-9076", "A crafted PKCS#12 file can crash the application"),
            ("CVE-2026-95691", "CMS_encrypt() may loop indefinitely (no fix yet)"),
        ],
        "CVE-2025-0001 is fixed in the installed version"
    );
    assert_eq!(
        ssl.vulnerabilities[0].url,
        "https://security-tracker.debian.org/tracker/CVE-2026-1000"
    );

    let up = ssl.update.as_ref().unwrap();
    assert_eq!(up.build, "openssl 3.0.22-1~deb12u2");
    assert_eq!(up.channel, "bookworm-security");
    assert_eq!(up.kind, "security");
    assert_eq!(up.severity, Severity::High);
    assert_eq!(up.upgrades, vec!["libssl3", "openssl"]);
    assert_eq!(
        up.command,
        "sudo apt update && sudo apt install --only-upgrade libssl3 openssl"
    );
    assert!(ssl.notes.is_empty(), "apt has the fix: {:?}", ssl.notes);
}

#[test]
fn open_cves_say_why_and_unimportant_ones_are_left_out() {
    let r = scan(&bookworm(), &bookworm_system());
    let zip = finding(&r, "7zip");
    let rows: Vec<(&str, &str)> = zip
        .vulnerabilities
        .iter()
        .map(|v| (v.id.as_str(), v.title.as_str()))
        .collect();
    assert_eq!(rows, vec![("CVE-2026-14266", "fixed in the next Debian point release")]);
    assert!(zip.update.is_none());
    assert_eq!(zip.severity, Severity::Unknown);
}

#[test]
fn signed_kernels_are_checked_as_the_newest_linux() {
    let r = scan(&bookworm(), &bookworm_system());
    let k = finding(&r, "linux");
    assert_eq!(
        k.installed, "6.1.190-1",
        "the newest kernel, with the image's version; linux-libc-dev is not a kernel"
    );
    let ids: Vec<&str> = k.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids, vec!["CVE-2026-7001"]);
    let up = k.update.as_ref().unwrap();
    assert_eq!(up.build, "linux 6.1.195-1");
    assert_eq!(up.channel, "bookworm-security");
    assert_eq!(up.upgrades, vec!["linux-image-6.1.0-54-amd64"]);
    assert_eq!(
        up.command, "sudo apt update && sudo apt full-upgrade",
        "a new kernel is a new package, --only-upgrade would not install it"
    );
    assert!(
        k.notes[0].starts_with("Each kernel version is a new package"),
        "{:?}",
        k.notes
    );
}

#[test]
fn third_party_packages_are_not_matched_against_debian_data() {
    let r = scan(&bookworm(), &bookworm_system());
    assert!(!r.findings.iter().any(|f| f.package.starts_with("docker")));
    assert_eq!(r.coverage.installed_packages, 9);
    assert_eq!(r.coverage.covered_packages, 7);
    assert_eq!(
        r.coverage.uncovered_vendors,
        vec![("Docker".to_string(), 1), ("Jane Doe".to_string(), 1)]
    );
    assert_eq!(
        r.third_party,
        vec![
            ThirdPartyPackage {
                package: "docker-ce".into(),
                vendor: "Docker".into(),
                installed: "5:28.0.0-1~debian.12~bookworm".into(),
                status: ThirdPartyStatus::UpdateAvailable {
                    version: "5:28.1.0-1~debian.12~bookworm".into(),
                    repo: "Docker".into(),
                    upgrades: vec!["docker-ce".into()],
                    command: "sudo apt update && sudo apt install --only-upgrade docker-ce".into(),
                },
            },
            ThirdPartyPackage {
                package: "localtool".into(),
                vendor: "Jane Doe".into(),
                installed: "1.0".into(),
                status: ThirdPartyStatus::NoRepository,
            },
        ]
    );
}

#[test]
fn findings_are_sorted_and_steps_closed() {
    let progress = Recording::default();
    let r = bookworm()
        .scan(&bookworm_system(), &ScanOptions::default(), &progress)
        .unwrap();
    let names: Vec<&str> = r.findings.iter().map(|f| f.package.as_str()).collect();
    assert_eq!(names, vec!["openssl", "7zip", "linux"], "by severity, then name");
    let steps = progress.steps();
    assert_eq!(steps.len(), 3, "{steps:?}");
    assert!(steps.iter().all(|s| s.outcome.is_ok()), "{steps:?}");
    assert_eq!(
        steps[1].outcome,
        Ok("8 CVEs".into()),
        "unimportant ones are not indexed"
    );
    assert_eq!(steps[2].outcome, Ok("3 package lists".into()));
}

#[test]
fn the_cache_index_keeps_every_advisory() {
    let a = oval::parse_bz2(&oval::tests::bz2(oval::tests::NOBLE), "noble").unwrap();
    let mut b = tracker::parse(TRACKER.as_bytes(), "bookworm").unwrap();
    b.extend(a);
    b.sort_by(|x, y| x.package.cmp(&y.package));
    let json = serde_json::to_string(&Index::new(&b)).unwrap();
    let back: Index = serde_json::from_str(&json).unwrap();
    assert_eq!(back.advisories().unwrap(), b);
}

#[test]
fn security_data_is_cached_for_a_day() {
    let sys = bookworm_system();
    scan(&bookworm(), &sys);
    let cached = sys
        .cache
        .lock()
        .unwrap()
        .get("debian-bookworm-advisories.json")
        .cloned();
    assert!(cached.is_some());

    // A fresh cache answers without a download.
    let (text, _) = cached.unwrap();
    let sys = FakeSystem::new()
        .on("dpkg-query", DPKG_BOOKWORM)
        .on("apt-cache policy ", &policy_bookworm())
        .on("apt-cache policy", ORIGINS_BOOKWORM)
        .cached("debian-bookworm-advisories.json", &text, Duration::from_secs(3600));
    let r = scan(&bookworm(), &sys);
    assert_eq!(finding(&r, "openssl").vulnerabilities.len(), 3);
    assert!(!sys.requests().iter().any(|r| r.contains("security-tracker")));

    // A stale one is used when the download fails, with a warning.
    let sys = FakeSystem::new()
        .on("dpkg-query", DPKG_BOOKWORM)
        .on("apt-cache policy ", &policy_bookworm())
        .on("apt-cache policy", ORIGINS_BOOKWORM)
        .fail("security-tracker.debian.org", "offline")
        .cached(
            "debian-bookworm-advisories.json",
            &text,
            Duration::from_secs(3 * 86_400),
        );
    let r = scan(&bookworm(), &sys);
    assert_eq!(finding(&r, "openssl").vulnerabilities.len(), 3);
    assert!(
        r.warnings[0].contains("3 days old") && r.warnings[0].contains("offline"),
        "{:?}",
        r.warnings
    );
}

#[test]
fn without_security_data_the_scan_fails() {
    let sys = FakeSystem::new()
        .on("dpkg-query", DPKG_BOOKWORM)
        .on("apt-cache policy ", &policy_bookworm())
        .on("apt-cache policy", ORIGINS_BOOKWORM)
        .fail("security-tracker.debian.org", "offline");
    let err = bookworm().scan(&sys, &ScanOptions::default(), &Silent).unwrap_err();
    assert!(format!("{err:#}").contains("offline"), "{err:#}");

    let sys = bookworm_system();
    let bullseye = Debian {
        codename: "bullseye".into(),
        ..bookworm()
    };
    let err = bullseye.scan(&sys, &ScanOptions::default(), &Silent).unwrap_err();
    assert!(format!("{err:#}").contains("no data for 'bullseye'"), "{err:#}");
}

#[test]
fn without_apt_lists_every_package_counts_as_debian_and_it_says_so() {
    let sys = FakeSystem::new()
        .on("dpkg-query", DPKG_BOOKWORM)
        .on("apt-cache policy ", "")
        .on(
            "apt-cache policy",
            "Package files:\n 100 /var/lib/dpkg/status\n     release a=now\n",
        )
        .on("security-tracker.debian.org", TRACKER);
    let r = scan(&bookworm(), &sys);
    assert!(r.warnings[0].contains("sudo apt update"), "{:?}", r.warnings);
    assert_eq!(r.coverage.covered_packages, 9);
    assert!(r.third_party.is_empty());
    let ssl = finding(&r, "openssl");
    let up = ssl.update.as_ref().unwrap();
    assert_eq!(
        (up.build.as_str(), up.channel.as_str()),
        ("openssl 3.0.22-1~deb12u1", "bookworm-security"),
        "the tracker's fixed version"
    );
    assert!(ssl.notes.is_empty(), "no lists to compare with");
}

#[test]
fn missing_dpkg_is_an_error() {
    let sys = FakeSystem::new().fail("dpkg-query", "not found");
    assert!(bookworm().scan(&sys, &ScanOptions::default(), &Silent).is_err());
}

#[test]
fn up_to_date_system_says_so() {
    let dpkg: String = DPKG_BOOKWORM
        .lines()
        .filter(|l| l.starts_with("libc6") || l.starts_with("docker"))
        .map(|l| format!("{l}\n"))
        .collect();
    let sys = FakeSystem::new()
        .on("dpkg-query", &dpkg)
        .on("apt-cache policy ", &policy_bookworm())
        .on("apt-cache policy", ORIGINS_BOOKWORM)
        .on("security-tracker.debian.org", TRACKER);
    let r = scan(&bookworm(), &sys);
    assert!(r.findings.is_empty());
    assert_eq!(r.notes, vec!["Every security fix Debian has published is installed."]);
}

// ---- Ubuntu 24.04 ----------------------------------------------------------------------------

const DPKG_NOBLE: &str = "\
libssl3t64:amd64\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4\tii \tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
gpac\t2.2.1+dfsg1-3.1build3\tgpac\t2.2.1+dfsg1-3.1build3\tii \tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
ffmpeg\t7:6.1.1-3ubuntu5\tffmpeg\t7:6.1.1-3ubuntu5\tii \tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
linux-modules-6.8.0-31-generic\t6.8.0-31.31\tlinux\t6.8.0-31.31\tii \tUbuntu Kernel Team <kernel-team@lists.ubuntu.com>
linux-image-6.8.0-31-generic\t6.8.0-31.31\tlinux-signed\t6.8.0-31.31\tii \tUbuntu Kernel Team <kernel-team@lists.ubuntu.com>
";

const ORIGINS_NOBLE: &str = "Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=main,b=amd64
     origin security.ubuntu.com
 500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=universe,b=amd64
     origin archive.ubuntu.com
";

const NOBLE_SEC: &str = "http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages";
const NOBLE_UNIVERSE: &str = "http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages";

fn policy_noble() -> String {
    [
        policy(
            "libssl3t64",
            "3.0.13-0ubuntu3.4",
            &[("3.0.13-0ubuntu3.6", &[NOBLE_SEC]), ("3.0.13-0ubuntu3.4", &[])],
        ),
        policy(
            "gpac",
            "2.2.1+dfsg1-3.1build3",
            &[("2.2.1+dfsg1-3.1build3", &[NOBLE_UNIVERSE])],
        ),
        policy("ffmpeg", "7:6.1.1-3ubuntu5", &[("7:6.1.1-3ubuntu5", &[NOBLE_UNIVERSE])]),
        policy(
            "linux-modules-6.8.0-31-generic",
            "6.8.0-31.31",
            &[("6.8.0-31.31", &[NOBLE_SEC])],
        ),
        policy(
            "linux-image-6.8.0-31-generic",
            "6.8.0-31.31",
            &[("6.8.0-31.31", &[NOBLE_SEC])],
        ),
    ]
    .concat()
}

fn noble_system(pro: Option<&str>) -> FakeSystem {
    let sys = FakeSystem::new()
        .on("dpkg-query", DPKG_NOBLE)
        .on("apt-cache policy ", &policy_noble())
        .on("apt-cache policy", ORIGINS_NOBLE)
        .on_bytes(
            "com.ubuntu.noble.cve.oval.xml.bz2",
            &oval::tests::bz2(oval::tests::NOBLE),
        );
    match pro {
        Some(json) => sys.on("pro security-status", json),
        None => sys.fail("pro security-status", "pro: command not found"),
    }
}

fn noble() -> Debian {
    Debian {
        flavor: Flavor::Ubuntu,
        codename: "noble".into(),
        pretty_name: "Ubuntu 24.04.3 LTS".into(),
    }
}

#[test]
fn ubuntu_fixes_in_the_archive_come_from_apt() {
    let r = scan(&noble(), &noble_system(Some(pro::tests::UNATTACHED)));
    assert_eq!(r.backend, "ubuntu");
    let ssl = finding(&r, "openssl");
    let ids: Vec<&str> = ssl.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids, vec!["CVE-2026-1540", "CVE-2026-107496"]);
    assert_eq!(ssl.vulnerabilities[0].url, "https://ubuntu.com/security/CVE-2026-1540");
    let up = ssl.update.as_ref().unwrap();
    assert_eq!(up.build, "openssl 3.0.13-0ubuntu3.6");
    assert_eq!(up.channel, "noble-security");
    assert_eq!(
        up.command,
        "sudo apt update && sudo apt install --only-upgrade libssl3t64"
    );
}

#[test]
fn ubuntu_pro_only_fixes_need_pro_and_say_so() {
    let r = scan(&noble(), &noble_system(Some(pro::tests::UNATTACHED)));
    let gpac = finding(&r, "gpac");
    let up = gpac.update.as_ref().unwrap();
    assert_eq!(up.build, "gpac 2.2.1+dfsg1-3.1ubuntu0.1~esm2");
    assert_eq!(up.channel, "pro:esm-apps");
    assert_eq!(
        up.command,
        "sudo pro attach && sudo apt update && sudo apt install --only-upgrade gpac"
    );
    let ffmpeg = finding(&r, "ffmpeg");
    assert_eq!(
        ffmpeg.vulnerabilities[0].title,
        "Heap overflow in X.509 & PKCS#7 parsing allows remote code execution \
         (no fix yet; it will be published to Ubuntu Pro (esm-apps) only)"
    );
    assert!(ffmpeg.update.is_none());
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    assert!(
        r.warnings[0].starts_with("fixes for 1 package in esm-apps are published to Ubuntu Pro only"),
        "{}",
        r.warnings[0]
    );

    // Without the client, it has to be installed first.
    let r = scan(&noble(), &noble_system(None));
    assert!(
        finding(&r, "gpac")
            .update
            .as_ref()
            .unwrap()
            .command
            .starts_with("sudo apt install ubuntu-pro-client && sudo pro attach && sudo apt update")
    );
}

#[test]
fn attached_machines_get_pro_fixes_through_apt() {
    let r = scan(&noble(), &noble_system(Some(pro::tests::ATTACHED)));
    let up = finding(&r, "gpac").update.as_ref().unwrap().clone();
    assert_eq!(up.channel, "esm-apps");
    assert_eq!(up.command, "sudo apt update && sudo apt install --only-upgrade gpac");
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r.notes, vec!["Ubuntu Pro is attached: esm-apps, esm-infra, livepatch."]);
}

#[test]
fn ubuntu_kernels_are_checked_by_source_package() {
    let r = scan(&noble(), &noble_system(Some(pro::tests::UNATTACHED)));
    let k = finding(&r, "linux");
    assert_eq!(k.installed, "6.8.0-31.31");
    assert_eq!(k.vulnerabilities[0].id, "CVE-2020-12351");
    assert_eq!(
        k.update.as_ref().unwrap().upgrades,
        vec!["linux-image-6.8.0-31-generic", "linux-modules-6.8.0-31-generic"]
    );
    assert!(!r.findings.iter().any(|f| f.package == "linux-aws"), "not installed");
}

#[test]
fn releases_past_standard_support_warn_without_esm_infra() {
    let oval = oval::tests::NOBLE.replace(
        "openssl source package in noble, is affected",
        "openssl source package in esm-infra/noble, is affected",
    );
    let sys = FakeSystem::new()
        .on("dpkg-query", DPKG_NOBLE)
        .on("apt-cache policy ", &policy_noble())
        .on("apt-cache policy", ORIGINS_NOBLE)
        .on_bytes("security-metadata.canonical.com", &oval::tests::bz2(&oval))
        .on("pro security-status", pro::tests::UNATTACHED);
    let r = scan(&noble(), &sys);
    assert!(
        r.warnings[0].contains("past its standard support") && r.warnings[0].contains("esm-infra"),
        "{:?}",
        r.warnings
    );
    assert_eq!(finding(&r, "openssl").update.as_ref().unwrap().channel, "pro:esm-infra");
}

#[test]
fn kernel_headers_and_tools_are_not_kernels() {
    for extra in [
        "linux-libc-dev",
        "linux-headers-6.8.0-31-generic",
        "linux-hwe-6.8-headers-6.8.0-51",
        "linux-aws-tools-6.8.0-1021",
        "linux-kbuild-6.1",
    ] {
        assert!(is_kernel_extra(extra), "{extra}");
    }
    for kernel in [
        "linux-image-6.8.0-31-generic",
        "linux-modules-6.8.0-31-generic",
        "linux-firmware",
        "linux-base",
    ] {
        assert!(!is_kernel_extra(kernel), "{kernel}");
    }
}

#[test]
fn titles_are_the_first_sentence() {
    assert_eq!(short_title("One. Two."), "One");
    assert_eq!(short_title("  spaced\n  out.  "), "spaced out");
    let long = "word ".repeat(40);
    let t = short_title(&long);
    assert!(t.ends_with('…') && t.chars().count() <= TITLE_MAX + 1, "{t}");
    assert_eq!(short_title(""), "");
}
