//! One backend per distribution family.

#[cfg(any(not(windows), test))]
pub mod fedora;
#[cfg(any(windows, test))]
pub mod windows;

use crate::model::Report;
#[cfg(any(not(windows), test))]
use crate::osrelease::OsRelease;
use crate::progress::Progress;
use crate::system::System;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub upstream: bool,
    pub kernel_cves: bool,
    /// Raises NVD's rate limit tenfold; Windows only.
    pub nvd_api_key: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            upstream: true,
            kernel_cves: true,
            nvd_api_key: None,
        }
    }
}

pub trait Backend {
    fn name(&self) -> &'static str;
    fn scan(&self, sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report>;
}

pub(crate) struct Steps<'a> {
    progress: &'a dyn Progress,
    warnings: &'a mut Vec<String>,
}

impl<'a> Steps<'a> {
    pub(crate) fn new(progress: &'a dyn Progress, warnings: &'a mut Vec<String>) -> Self {
        Self { progress, warnings }
    }

    /// The step ends with a warning if it added one to the report, else with `describe`.
    pub(crate) fn run<T>(
        &mut self,
        name: &str,
        work: impl FnOnce(&mut Vec<String>) -> T,
        describe: impl FnOnce(&T) -> String,
    ) -> T {
        self.progress.start(name, None);
        let before = self.warnings.len();
        let out = work(self.warnings);
        match self.warnings.get(before) {
            Some(w) => self.progress.warn(w),
            None => self.progress.finish(&describe(&out)),
        }
        out
    }
}

/// One unreachable data source must not stop the scan.
pub(crate) fn or_warn<T: Default>(result: Result<T>, warnings: &mut Vec<String>, what: &str) -> T {
    result.unwrap_or_else(|e| {
        warnings.push(format!("{what}: {e:#}"));
        T::default()
    })
}

/// An unsupported distribution is an error, never an empty report that looks clean.
#[cfg(any(not(windows), test))]
pub fn detect(os: &OsRelease) -> Result<Box<dyn Backend>> {
    match os.id.as_str() {
        "fedora" => {
            if os.version_id.is_empty() {
                anyhow::bail!("cannot tell the Fedora release: VERSION_ID is missing from os-release");
            }
            Ok(Box::new(fedora::Fedora {
                release: os.version_id.clone(),
                pretty_name: os.pretty_name.clone(),
            }))
        }
        other => anyhow::bail!(
            "unsupported distribution '{}' ({}). vulnhound supports: fedora, windows. \
             It refuses to scan rather than report a system it cannot check as clean.",
            if other.is_empty() { "unknown" } else { other },
            os.pretty_name
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_unsupported_distros_instead_of_reporting_clean() {
        let os = OsRelease::parse("ID=debian\nVERSION_ID=13\nPRETTY_NAME=\"Debian GNU/Linux 13\"");
        let err = detect(&os).err().unwrap().to_string();
        assert!(err.contains("unsupported distribution 'debian'"));
    }

    #[test]
    fn refuses_fedora_without_version() {
        let os = OsRelease::parse("ID=fedora");
        assert!(detect(&os).is_err());
    }
}
