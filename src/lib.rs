//! vulnhound: a vulnerability scanner for Linux hosts that also shows fixes the distro has not
//! shipped to stable yet.

pub mod cve;
pub mod distro;
pub mod kernel;
pub mod model;
pub mod osrelease;
pub mod progress;
pub mod report;
pub mod rpmver;
pub mod system;
pub mod upstream;

use anyhow::Result;
use distro::ScanOptions;
use model::Report;
use progress::Progress;
use system::System;

pub const OS_RELEASE_PATHS: &[&str] = &["/etc/os-release", "/usr/lib/os-release"];

pub fn scan(sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report> {
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
}
