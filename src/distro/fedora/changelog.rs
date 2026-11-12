//! RPM changelogs: a CVE id means the fix was applied (often backported); dated entries tell
//! whether the package was rebased after a CVE was reported. Fedora trims them to ~2 years.

use crate::rpmver::rpmvercmp;
use crate::system::System;
use anyhow::Result;
use std::cmp::Ordering;
use std::collections::HashMap;

const PACKAGE_MARK: &str = "@@vulnhound-package@@";
const ENTRY_MARK: &str = "@@vulnhound-entry@@";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub time: i64,
    /// From the header `Name <email> - [epoch:]version-release`.
    pub version: Option<String>,
    pub text: String,
}

/// Newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changelog {
    pub entries: Vec<Entry>,
}

impl Changelog {
    pub fn mentions(&self, cve: &str) -> bool {
        self.entries.iter().any(|e| e.text.contains(cve))
    }

    /// If the history starts after `t`, the oldest known version: the one at `t` was that or older.
    pub fn version_at(&self, t: i64) -> Option<&str> {
        let with_version = || self.entries.iter().filter(|e| e.version.is_some());
        with_version()
            .find(|e| e.time <= t)
            .or_else(|| with_version().next_back())
            .and_then(|e| e.version.as_deref())
    }

    pub fn rebased_since(&self, t: i64, installed_version: &str) -> bool {
        self.version_at(t)
            .is_some_and(|v| rpmvercmp(v, installed_version) == Ordering::Less)
    }
}

/// `Jane Doe <jane@example.org> - 1:7.1.2.35-1` → `7.1.2.35`.
pub fn header_version(header: &str) -> Option<String> {
    let (_, evr) = header.rsplit_once(" - ")?;
    let evr = evr.trim();
    let evr = evr.split_once(':').map_or(evr, |(_, rest)| rest);
    let version = evr.rsplit_once('-').map_or(evr, |(v, _)| v);
    version
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit())
        .then(|| version.to_string())
}

pub fn query_format() -> String {
    format!("{PACKAGE_MARK} %{{NAME}}\n[{ENTRY_MARK} %{{CHANGELOGTIME}}\t%{{CHANGELOGNAME}}\n%{{CHANGELOGTEXT}}\n]")
}

/// Binary package → changelog. With several installed versions (kernels) the newest wins.
pub fn parse(text: &str) -> HashMap<String, Changelog> {
    let mut listings: Vec<(String, Changelog)> = Vec::new();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix(PACKAGE_MARK) {
            listings.push((name.trim().to_string(), Changelog::default()));
        } else if let Some((_, cl)) = listings.last_mut() {
            if let Some(header) = line.strip_prefix(ENTRY_MARK) {
                let (time, name) = header
                    .trim_start()
                    .split_once('\t')
                    .unwrap_or_else(|| (header.trim(), ""));
                cl.entries.push(Entry {
                    time: time.trim().parse().unwrap_or(0),
                    version: header_version(name),
                    text: String::new(),
                });
            } else if let Some(entry) = cl.entries.last_mut() {
                entry.text.push_str(line);
                entry.text.push('\n');
            }
        }
    }
    let newest = |cl: &Changelog| cl.entries.first().map_or(i64::MIN, |e| e.time);
    let mut out: HashMap<String, Changelog> = HashMap::new();
    for (name, cl) in listings {
        match out.get(&name) {
            Some(old) if newest(old) >= newest(&cl) => {}
            _ => {
                out.insert(name, cl);
            }
        }
    }
    out
}

pub fn read(sys: &dyn System, binaries: &[&str]) -> Result<HashMap<String, Changelog>> {
    if binaries.is_empty() {
        return Ok(HashMap::new());
    }
    let qf = query_format();
    let mut args = vec!["-q", "--qf", qf.as_str()];
    args.extend_from_slice(binaries);
    Ok(parse(&sys.run("rpm", &args)?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    /// (time, header, text) of one changelog entry.
    pub type EntrySpec<'a> = (i64, &'a str, &'a str);

    pub fn render(packages: &[(&str, &[EntrySpec])]) -> String {
        let mut s = String::new();
        for (name, entries) in packages {
            s.push_str(&format!("{PACKAGE_MARK} {name}\n"));
            for (time, header, text) in *entries {
                s.push_str(&format!("{ENTRY_MARK} {time}\t{header}\n{text}\n"));
            }
        }
        s
    }

    fn git() -> String {
        render(&[(
            "git-core",
            &[
                (1791000000, "Packager <p@x> - 2.56.0-1", "- update to 2.56.0"),
                (1784000000, "Release Engineering <r@x> - 2.55.0-2", "- Rebuilt"),
                (
                    1782000000,
                    "Packager <p@x> - 2.55.0-1",
                    "- update to 2.55.0\n- fixes CVE-2026-1234",
                ),
            ],
        )])
    }

    #[test]
    fn parses_entries_with_versions_and_text() {
        let cl = &parse(&git())["git-core"];
        assert_eq!(cl.entries.len(), 3);
        assert_eq!(cl.entries[0].time, 1791000000);
        assert_eq!(cl.entries[0].version.as_deref(), Some("2.56.0"));
        assert_eq!(cl.entries[2].text, "- update to 2.55.0\n- fixes CVE-2026-1234\n");
        assert!(cl.mentions("CVE-2026-1234"));
        assert!(!cl.mentions("CVE-2026-9999"));
    }

    #[test]
    fn reads_header_versions() {
        assert_eq!(header_version("A <a@x> - 1:7.1.2.35-1").as_deref(), Some("7.1.2.35"));
        assert_eq!(header_version("A <a@x> - 2.56.0-1").as_deref(), Some("2.56.0"));
        assert_eq!(header_version("A <a@x> - 2.56.0").as_deref(), Some("2.56.0"));
        assert_eq!(header_version("A <a@x>"), None);
        assert_eq!(header_version("A <a@x> - snapshot"), None);
    }

    #[test]
    fn version_at_picks_the_entry_in_effect() {
        let cl = &parse(&git())["git-core"];
        assert_eq!(cl.version_at(1795000000), Some("2.56.0"));
        assert_eq!(cl.version_at(1790000000), Some("2.55.0"));
        assert_eq!(
            cl.version_at(1700000000),
            Some("2.55.0"),
            "before history: oldest known"
        );
    }

    #[test]
    fn rebased_since_compares_with_installed_version() {
        let cl = &parse(&git())["git-core"];
        assert!(!cl.rebased_since(1795000000, "2.56.0"), "report after the last rebase");
        assert!(cl.rebased_since(1790000000, "2.56.0"), "rebased after the report");
        assert!(
            cl.rebased_since(1600000000, "2.56.0"),
            "old report, rebased within history"
        );
        assert!(
            !Changelog::default().rebased_since(1600000000, "2.56.0"),
            "no history, no claim"
        );
    }

    #[test]
    fn duplicate_listings_keep_the_newest() {
        for (first, second) in [(1, 2), (2, 1)] {
            let text = render(&[
                ("kernel-core", &[(first, &format!("A <a@x> - 7.{first}-300"), "- x")]),
                ("kernel-core", &[(second, &format!("A <a@x> - 7.{second}-300"), "- x")]),
            ]);
            let cl = &parse(&text)["kernel-core"];
            assert_eq!(cl.entries.len(), 1);
            assert_eq!(cl.entries[0].version.as_deref(), Some("7.2"));
        }
    }

    #[test]
    fn read_uses_one_rpm_call() {
        let sys = FakeSystem::new().on("rpm -q --qf", &git());
        let c = read(&sys, &["git-core", "yasm"]).unwrap();
        assert!(c.contains_key("git-core"));
        let reqs = sys.requests();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].ends_with(" git-core yasm"));
        assert!(read(&sys, &[]).unwrap().is_empty());
    }
}
