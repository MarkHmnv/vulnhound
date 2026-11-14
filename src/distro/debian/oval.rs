//! Ubuntu's CVE OVAL data: every CVE of a release, its priority and, per source package, whether
//! it is fixed and in which pocket. Fixes in `esm-apps/<release>` or `esm-infra/<release>` are only
//! published to Ubuntu Pro subscribers.
//!
//! The file is 11 MB of bzip2 that unpacks to about 280 MB of XML; it is read line by line, and
//! only the entries are cached.

use super::{Advisory, Status, short_title};
use crate::model::Severity;
use crate::system::System;
use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Read};

pub fn url(codename: &str) -> String {
    format!("https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2")
}

pub fn cve_url(id: &str) -> String {
    format!("https://ubuntu.com/security/{id}")
}

pub fn download(sys: &dyn System, codename: &str) -> Result<Vec<u8>> {
    sys.http_get_bytes(&url(codename))
        .with_context(|| format!("downloading Ubuntu's OVAL data for {codename}"))
}

/// Ubuntu's priority, or `None` for "negligible": not treated as a security problem.
fn severity(priority: &str) -> Option<Severity> {
    match priority {
        "negligible" => None,
        p => Some(Severity::parse(p)),
    }
}

#[derive(Default)]
struct Definition {
    cve: String,
    priority: String,
    description: String,
    /// (package, pocket, fixed version or `None` if open)
    packages: Vec<(String, String, Option<String>)>,
}

/// Reads the bzip2-compressed OVAL file of `codename`.
pub fn parse_bz2(data: &[u8], codename: &str) -> Result<Vec<Advisory>> {
    parse(bzip2::read::BzDecoder::new(data), codename)
}

pub fn parse(xml: impl Read, codename: &str) -> Result<Vec<Advisory>> {
    let mut out = Vec::new();
    let mut def: Option<Definition> = None;
    let mut definitions = 0;
    for line in BufReader::new(xml).lines() {
        let line = line.context("reading Ubuntu's OVAL data")?;
        let t = line.trim_start();
        if t.starts_with("<definition ") && t.contains(r#"class="vulnerability""#) {
            def = Some(Definition::default());
            definitions += 1;
        } else if t.starts_with("</definition>") {
            if let Some(d) = def.take() {
                push(&mut out, d);
            }
        } else if let Some(d) = def.as_mut() {
            if let Some(rest) = t.strip_prefix("<description>") {
                d.description = unescape(rest.split("</description>").next().unwrap_or(rest));
            } else if t.starts_with("<cve ") {
                d.priority = attr(t, "priority").unwrap_or_default().to_string();
                d.cve = t
                    .split_once('>')
                    .and_then(|(_, rest)| rest.split_once('<'))
                    .map(|(id, _)| id.trim().to_string())
                    .unwrap_or_default();
            } else if t.starts_with("<criterion ")
                && let Some(c) = attr(t, "comment")
                && let Some(p) = criterion(&unescape(c), codename)
            {
                d.packages.push(p);
            }
        }
    }
    if definitions == 0 {
        bail!("Ubuntu's OVAL data for {codename} has no CVEs");
    }
    out.sort_by(|a, b| a.package.cmp(&b.package).then(a.cve.cmp(&b.cve)));
    Ok(out)
}

fn push(out: &mut Vec<Advisory>, d: Definition) {
    if !d.cve.starts_with("CVE-") {
        return;
    }
    let Some(severity) = severity(&d.priority) else { return };
    let title = short_title(&d.description);
    let mut packages = d.packages;
    packages.sort();
    packages.dedup();
    for (package, pocket, fixed) in packages {
        let status = match fixed {
            Some(version) => Status::Fixed { version, pocket },
            None => Status::Open {
                note: match pocket.as_str() {
                    "" => "no fix yet".to_string(),
                    p => format!("no fix yet; it will be published to Ubuntu Pro ({p}) only"),
                },
            },
        };
        out.push(Advisory {
            package,
            cve: d.cve.clone(),
            severity,
            title: title.clone(),
            status,
        });
    }
}

/// The package, pocket and fix of one criterion:
/// - `openssl source package in noble, might be affected and may need fixing.`
/// - `gpac source package in esm-apps/noble, is affected and has been fixed (note: '2.2-1~esm1').`
/// - `'linux-aws' kernel in noble was vulnerable but has been fixed (note: '6.8.0-1009.9').`
fn criterion(comment: &str, codename: &str) -> Option<(String, String, Option<String>)> {
    let (package, rest) = if let Some((p, rest)) = comment.split_once(" source package in ") {
        (p.to_string(), rest)
    } else {
        let (p, rest) = comment.split_once(" kernel in ")?;
        (p.trim_matches('\'').to_string(), rest)
    };
    let (place, state) = rest.split_once([',', ' '])?;
    let pocket = place.strip_suffix(codename)?.trim_end_matches('/').to_string();
    let fixed = if state.contains("has been fixed") {
        let version = state.split_once("(note: '")?.1.split_once('\'')?.0;
        Some(version.to_string())
    } else if state.contains("may need fixing") {
        None
    } else {
        return None;
    };
    Some((package, pocket, fixed))
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let start = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    let len = tag[start..].find('"')?;
    Some(&tag[start..start + len])
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e => e
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| e.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(if c == '\u{a0}' { ' ' } else { c });
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Trimmed real definitions from com.ubuntu.noble.cve.oval.xml, 2026-11-13.
    pub const NOBLE: &str = r#"<oval_definitions>
  <definitions>
    <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:20261074960000000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-107496 on Ubuntu 24.04 LTS (noble) - medium</title>
        <description>Issue summary: Encrypting a CMS message to an EC certificate whose group order is 1 may cause CMS_encrypt() to loop indefinitely. Impact summary: ...</description>
        <advisory from="security@ubuntu.com">
          <severity>Medium</severity>
          <cve href="https://ubuntu.com/security/CVE-2026-107496" priority="medium" public="20261112">CVE-2026-107496</cve>
        </advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:2023452360000000" comment="edk2 source package in noble, might be affected and may need fixing." />
          <criterion test_ref="oval:com.ubuntu.noble:tst:2026888220000000" comment="openssl source package in noble, might be affected and may need fixing." />
        </criteria>
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:20261540000000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-1540 on Ubuntu 24.04 LTS (noble) - high</title>
        <description>Heap overflow in X.509 &amp; PKCS#7 parsing&#160;allows remote code execution.</description>
        <advisory from="security@ubuntu.com">
          <cve href="https://ubuntu.com/security/CVE-2026-1540" priority="high" public="20260301" usns="8001-1">CVE-2026-1540</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:1" comment="openssl source package in noble, is affected and has been fixed (note: '3.0.13-0ubuntu3.5')." />
        <criterion test_ref="oval:com.ubuntu.noble:tst:2" comment="gpac source package in esm-apps/noble, is affected and has been fixed (note: '2.2.1+dfsg1-3.1ubuntu0.1~esm2')." />
        <criterion test_ref="oval:com.ubuntu.noble:tst:3" comment="ffmpeg source package in esm-apps/noble, might be affected and may need fixing." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:2020123510000000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2020-12351 on Ubuntu 24.04 LTS (noble) - high</title>
        <description>Improper input validation in BlueZ may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.  Update Instructions:  Run `sudo pro fix CVE-2020-12351` to fix the vulnerability.</description>
        <advisory from="security@ubuntu.com">
          <cve href="https://ubuntu.com/security/CVE-2020-12351" priority="high" public="20201014">CVE-2020-12351</cve>
        </advisory>
      </metadata>
      <criteria>
        <criteria operator="OR">
          <criteria operator="AND">
            <criterion test_ref="oval:com.ubuntu.noble:tst:201245420000000" comment="Is kernel 'linux' running?" />
            <criterion test_ref="oval:com.ubuntu.noble:tst:2020123510000000" comment="'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-35.35')." />
          </criteria>
          <criteria operator="AND">
            <criterion test_ref="oval:com.ubuntu.noble:tst:2020123510000010" comment="Is kernel 'linux-aws' running?" />
            <criterion test_ref="oval:com.ubuntu.noble:tst:2020123510000020" comment="'linux-aws' kernel in noble was vulnerable but has been fixed (note: '6.8.0-1009.9')." />
          </criteria>
        </criteria>
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:2026900" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-0900 on Ubuntu 24.04 LTS (noble) - negligible</title>
        <description>Theoretical issue.</description>
        <advisory><cve href="https://ubuntu.com/security/CVE-2026-0900" priority="negligible">CVE-2026-0900</cve></advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:4" comment="openssl source package in noble, might be affected and may need fixing." />
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:1" comment="Does the 'openssl' package exist?" />
  </tests>
</oval_definitions>
"#;

    pub fn bz2(text: &str) -> Vec<u8> {
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        enc.write_all(text.as_bytes()).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn reads_fixes_pockets_and_open_cves() {
        let a = parse_bz2(&bz2(NOBLE), "noble").unwrap();
        let rows: Vec<(&str, &str, &Status)> = a
            .iter()
            .map(|x| (x.package.as_str(), x.cve.as_str(), &x.status))
            .collect();
        let fixed = |v: &str, p: &str| Status::Fixed {
            version: v.into(),
            pocket: p.into(),
        };
        let open = |n: &str| Status::Open { note: n.into() };
        assert_eq!(
            rows,
            vec![
                ("edk2", "CVE-2026-107496", &open("no fix yet")),
                (
                    "ffmpeg",
                    "CVE-2026-1540",
                    &open("no fix yet; it will be published to Ubuntu Pro (esm-apps) only")
                ),
                (
                    "gpac",
                    "CVE-2026-1540",
                    &fixed("2.2.1+dfsg1-3.1ubuntu0.1~esm2", "esm-apps")
                ),
                ("linux", "CVE-2020-12351", &fixed("6.8.0-35.35", "")),
                ("linux-aws", "CVE-2020-12351", &fixed("6.8.0-1009.9", "")),
                ("openssl", "CVE-2026-107496", &open("no fix yet")),
                ("openssl", "CVE-2026-1540", &fixed("3.0.13-0ubuntu3.5", "")),
            ],
            "the negligible CVE is left out"
        );
        let ssl = a.iter().find(|x| x.cve == "CVE-2026-1540").unwrap();
        assert_eq!(ssl.severity, Severity::High);
        assert_eq!(
            ssl.title,
            "Heap overflow in X.509 & PKCS#7 parsing allows remote code execution"
        );
        let bluez = a.iter().find(|x| x.cve == "CVE-2020-12351").unwrap();
        assert!(!bluez.title.contains("pro fix"), "{}", bluez.title);
    }

    #[test]
    fn other_releases_and_empty_files_are_not_read() {
        assert!(
            criterion(
                "x source package in jammy, might be affected and may need fixing.",
                "noble"
            )
            .is_none()
        );
        assert!(parse_bz2(&bz2("<oval_definitions/>"), "noble").is_err());
        assert!(parse_bz2(b"not bzip2", "noble").is_err());
    }

    #[test]
    fn unescapes_xml() {
        assert_eq!(
            unescape("a &amp; b &lt;c&gt; &#39;d&#x27; &bogus; & e"),
            "a & b <c> 'd' &bogus; & e"
        );
    }
}
