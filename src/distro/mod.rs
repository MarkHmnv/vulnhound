//! One backend per distribution family.

pub mod fedora;

use crate::model::Report;
use crate::osrelease::OsRelease;
use crate::progress::Progress;
use crate::system::System;
use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub upstream: bool,
    pub kernel_cves: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            upstream: true,
            kernel_cves: true,
        }
    }
}

pub trait Backend {
    fn name(&self) -> &'static str;
    fn scan(&self, sys: &dyn System, opts: &ScanOptions, progress: &dyn Progress) -> Result<Report>;
}

/// An unsupported distribution is an error, never an empty report that looks clean.
pub fn detect(os: &OsRelease) -> Result<Box<dyn Backend>> {
    match os.id.as_str() {
        "fedora" => {
            if os.version_id.is_empty() {
                bail!("cannot tell the Fedora release: VERSION_ID is missing from os-release");
            }
            Ok(Box::new(fedora::Fedora {
                release: os.version_id.clone(),
                pretty_name: os.pretty_name.clone(),
            }))
        }
        other => bail!(
            "unsupported distribution '{}' ({}). vulnhound supports: fedora. \
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
