//! vulnhound: a vulnerability scanner for Linux and Windows hosts that also shows fixes the distro
//! has not shipped to stable yet.

// Each platform's binary carries only its own backend (the Linux side pulls in `zip`); tests
// build both, so either backend is tested on any host.
#[cfg(any(not(windows), test))]
pub mod cve;
#[cfg(any(not(windows), test))]
pub mod debver;
pub mod distro;
#[cfg(any(not(windows), test))]
pub mod kernel;
pub mod model;
#[cfg(any(not(windows), test))]
pub mod osrelease;
pub mod progress;
pub mod report;
#[cfg(any(not(windows), test))]
pub mod rpmver;
pub mod system;
#[cfg(any(not(windows), test))]
pub mod upstream;

use anyhow::Result;
use distro::ScanOptions;
use model::Report;
use progress::Progress;
use system::System;

#[cfg(any(not(windows), test))]
pub const OS_RELEASE_PATHS: &[&str] = &["/etc/os-release", "/usr/lib/os-release"];

pub fn scan(sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
    if sys.os() == "windows" {
        scan_windows(sys, opts, progress)
    } else {
        scan_linux(sys, opts, progress)
    }
}

#[cfg(any(windows, test))]
fn scan_windows(sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
    distro::Backend::scan(&distro::windows::Windows, sys, opts, progress)
}

#[cfg(all(not(windows), not(test)))]
fn scan_windows(_: &dyn System, _: &ScanOptions, _: &dyn Progress) -> Result<Report> {
    anyhow::bail!("this build of vulnhound is for Linux; build it on or for Windows to scan Windows")
}

#[cfg(all(windows, not(test)))]
fn scan_linux(_: &dyn System, _: &ScanOptions, _: &dyn Progress) -> Result<Report> {
    anyhow::bail!("this build of vulnhound is for Windows; build it on or for Linux to scan Linux")
}

#[cfg(any(not(windows), test))]
fn scan_linux(sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
    let text = OS_RELEASE_PATHS
        .iter()
        .find_map(|p| sys.read_file(p).ok())
        .ok_or_else(|| anyhow::anyhow!("cannot read os-release from {}", OS_RELEASE_PATHS.join(" or ")))?;
    let os = osrelease::OsRelease::parse(&text);
    distro::detect(&os)?.scan(sys, opts, progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use system::fake::FakeSystem;

    #[test]
    fn scan_falls_back_to_usr_lib_os_release() {
        let sys = FakeSystem::new()
            .fail("file:/etc/os-release", "missing")
            .on("file:/usr/lib/os-release", "ID=arch\n");
        let err = scan(&sys, &ScanOptions::default(), &progress::Silent)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("unsupported distribution 'arch'"));
    }

    #[test]
    fn windows_needs_no_os_release() {
        let sys = FakeSystem::new().os("windows").fail("powershell.exe", "no powershell");
        let err = scan(&sys, &ScanOptions::default(), &progress::Silent)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("powershell"), "{err}");
        assert!(!sys.requests().iter().any(|r| r.contains("os-release")));
    }
}
