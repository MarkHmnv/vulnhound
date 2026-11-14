//! Ubuntu Pro: whether this machine is attached and which services deliver updates to it.
//!
//! `pro security-status` answers from local state, without root or network.

use crate::system::System;
use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProStatus {
    /// `pro` is installed. Without it the machine cannot be attached.
    pub client: bool,
    pub attached: bool,
    /// e.g. esm-apps, esm-infra, livepatch.
    pub enabled: Vec<String>,
}

impl ProStatus {
    pub fn delivers(&self, service: &str) -> bool {
        self.attached && self.enabled.iter().any(|s| s == service)
    }
}

#[derive(Deserialize)]
struct SecurityStatus {
    summary: Summary,
}

#[derive(Deserialize)]
struct Summary {
    ua: Ua,
}

#[derive(Deserialize)]
struct Ua {
    #[serde(default)]
    attached: bool,
    #[serde(default)]
    enabled_services: Vec<String>,
}

/// A missing or failing client means not attached; there is nothing to warn about.
pub fn query(sys: &dyn System) -> ProStatus {
    let Ok(out) = sys.run("pro", &["security-status", "--format", "json"]) else {
        return ProStatus::default();
    };
    parse(&out).unwrap_or(ProStatus {
        client: true,
        ..ProStatus::default()
    })
}

fn parse(json: &str) -> Option<ProStatus> {
    let s: SecurityStatus = serde_json::from_str(json).ok()?;
    Some(ProStatus {
        client: true,
        attached: s.summary.ua.attached,
        enabled: s.summary.ua.enabled_services,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    /// Real output on an unattached Ubuntu 22.04, trimmed.
    pub const UNATTACHED: &str = r#"{"_schema_version": "0.1", "livepatch": {"fixed_cves": []}, "packages": [],
      "summary": {"num_esm_apps_packages": 0, "num_installed_packages": 126, "reboot_required": "no",
      "ua": {"attached": false, "enabled_services": [], "entitled_services": []}}}"#;

    pub const ATTACHED: &str = r#"{"_schema_version": "0.1", "packages": [],
      "summary": {"ua": {"attached": true, "enabled_services": ["esm-apps", "esm-infra", "livepatch"],
      "entitled_services": ["esm-apps", "esm-infra", "livepatch"]}}}"#;

    #[test]
    fn reads_attachment_and_services() {
        let s = query(&FakeSystem::new().on("pro security-status", ATTACHED));
        assert!(s.attached && s.delivers("esm-apps") && s.delivers("esm-infra"));
        let s = query(&FakeSystem::new().on("pro security-status", UNATTACHED));
        assert!(s.client && !s.attached && !s.delivers("esm-apps"));
        let s = query(&FakeSystem::new().fail("pro security-status", "not found"));
        assert_eq!(s, ProStatus::default());
    }
}
