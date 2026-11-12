//! Latest upstream releases, from release-monitoring.org (Anitya).
//!
//! Anitya maps distro package names to upstream projects. Only those explicit mappings are used:
//! looking projects up by name finds unrelated projects that happen to share it.

use crate::progress::Progress;
use crate::system::{System, parallel_map, url_with_query};
use anyhow::{Context, Result};
use serde::Deserialize;

pub const BASE: &str = "https://release-monitoring.org/api/v2/packages/";
const PARALLEL_REQUESTS: usize = 8;

/// Latest stable release of the upstream project behind a distro package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latest {
    pub project: String,
    pub version: String,
}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    name: String,
    project: String,
    #[serde(default)]
    stable_version: Option<String>,
}

/// Parses a package lookup response. `None` when the package has no mapping or the project has
/// no stable release.
pub fn parse(body: &str, name: &str) -> Result<Option<Latest>> {
    let page: Page = serde_json::from_str(body).context("parsing release-monitoring.org response")?;
    Ok(page.items.into_iter().filter(|i| i.name == name).find_map(|i| {
        let version = i.stable_version.filter(|v| !v.is_empty())?;
        Some(Latest {
            project: i.project,
            version,
        })
    }))
}

/// Looks up each package of `distribution` (Anitya's name, e.g. "Fedora"), in the order of
/// `names`. Lookups fail independently.
pub fn latest_versions(
    sys: &dyn System,
    distribution: &str,
    names: &[String],
    progress: &dyn Progress,
) -> Vec<Result<Option<Latest>>> {
    progress.add_total(names.len() as u64);
    parallel_map(names, PARALLEL_REQUESTS, |name| {
        let url = url_with_query(BASE, &[("distribution", distribution), ("name", name)]);
        let r = sys.http_get(&url).and_then(|body| parse(&body, name));
        progress.advance(1);
        r
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    /// Real response for git on 2026-11-11.
    const GIT: &str = r#"{"items":[{"distribution":"Fedora","ecosystem":"https://git-scm.com","name":"git",
        "project":"git","stable_version":"2.56.1","version":"2.57.0-rc0"}],
        "items_per_page":25,"page":1,"total_items":1}"#;

    #[test]
    fn parses_the_stable_version_of_an_exact_mapping() {
        assert_eq!(parse(GIT, "git").unwrap().unwrap().version, "2.56.1", "not the rc");
        assert_eq!(parse(r#"{"items":[],"total_items":0}"#, "docker-ce").unwrap(), None);
        let pre = r#"{"items":[{"name":"x","project":"x","stable_version":null,"version":"1.0-rc1"}]}"#;
        assert_eq!(parse(pre, "x").unwrap(), None);
        assert_eq!(parse(GIT, "gitk").unwrap(), None);
        assert!(parse("<html>", "git").is_err());
    }

    #[test]
    fn looks_up_each_package_independently() {
        let sys = FakeSystem::new().on("name=git", GIT).fail("name=curl", "timeout");
        let names = vec!["git".to_string(), "curl".to_string(), "lib++".to_string()];
        let r = latest_versions(&sys, "Fedora", &names, &crate::progress::Silent);
        assert_eq!(r[0].as_ref().unwrap().as_ref().unwrap().version, "2.56.1");
        assert!(r[1].is_err());
        assert!(r[2].is_err(), "no rule in the fake");
        let reqs = sys.requests();
        assert!(reqs.iter().any(|u| u.contains("distribution=Fedora&name=lib%2B%2B")));
    }
}
