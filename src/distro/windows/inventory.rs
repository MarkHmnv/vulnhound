//! What is installed: the Windows build and the programs listed in "Installed apps", read from the
//! registry by one PowerShell call.

use crate::system::System;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;

/// Output is ASCII-only JSON: non-ASCII characters are escaped, so the console code page cannot
/// garble program names.
pub const SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$sysenv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$uninstall = 'Microsoft\Windows\CurrentVersion\Uninstall\*'
$roots = @(
  @('machine', "HKLM:\SOFTWARE\$uninstall"),
  @('machine', "HKLM:\SOFTWARE\WOW6432Node\$uninstall")
)
foreach ($u in Get-ChildItem 'Registry::HKEY_USERS') {
  if ($u.PSChildName -like '*_Classes') { continue }
  $roots += ,@('user', "Registry::HKEY_USERS\$($u.PSChildName)\Software\$uninstall")
  $roots += ,@('user', "Registry::HKEY_USERS\$($u.PSChildName)\Software\WOW6432Node\$uninstall")
}
$programs = foreach ($r in $roots) {
  foreach ($p in Get-ItemProperty $r[1]) {
    if (-not $p.DisplayName) { continue }
    [pscustomobject]@{
      name = [string]$p.DisplayName
      version = [string]$p.DisplayVersion
      publisher = [string]$p.Publisher
      system_component = [string]$p.SystemComponent
      parent = [string]$p.ParentKeyName
      release_type = [string]$p.ReleaseType
      key = [string]$p.PSChildName
      scope = $r[0]
    }
  }
}
$hotfixes = foreach ($h in Get-HotFix) { [string]$h.HotFixID }
$out = [pscustomobject]@{
  product_name = [string]$cv.ProductName
  display_version = [string]$cv.DisplayVersion
  release_id = [string]$cv.ReleaseId
  build = [string]$cv.CurrentBuildNumber
  ubr = [string]$cv.UBR
  edition = [string]$cv.EditionID
  installation_type = [string]$cv.InstallationType
  arch = [string]$sysenv.PROCESSOR_ARCHITECTURE
  hotfixes = @($hotfixes | Where-Object { $_ })
  programs = @($programs | Where-Object { $_ })
}
$json = ConvertTo-Json -InputObject $out -Depth 4 -Compress
[regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
"#;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Inventory {
    #[serde(default)]
    pub product_name: String,
    #[serde(default)]
    pub display_version: String,
    #[serde(default)]
    pub release_id: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub ubr: String,
    #[serde(default)]
    pub edition: String,
    #[serde(default)]
    pub installation_type: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub hotfixes: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub programs: Vec<RawProgram>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RawProgram {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub system_component: String,
    #[serde(default)]
    pub parent: String,
    #[serde(default)]
    pub release_type: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub scope: String,
}

fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// A program as "Installed apps" shows it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Program {
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// Registry key name; unlike the name, it does not depend on the display language.
    pub key: String,
}

impl Inventory {
    /// Like "Installed apps": no system components, updates or entries that belong to another.
    /// Each name and version once (32- and 64-bit or per-user and machine entries).
    pub fn programs(&self) -> Vec<Program> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for p in &self.programs {
            let name = p.name.trim();
            let hidden = p.system_component.trim() == "1"
                || !p.parent.trim().is_empty()
                || matches!(
                    p.release_type.trim().to_ascii_lowercase().as_str(),
                    "update" | "hotfix" | "security update" | "service pack"
                )
                || is_kb(name);
            if name.is_empty() || hidden {
                continue;
            }
            let version = p.version.trim().to_string();
            if seen.insert((name.to_lowercase(), version.clone())) {
                out.push(Program {
                    name: name.to_string(),
                    version,
                    publisher: p.publisher.trim().to_string(),
                    key: p.key.trim().to_string(),
                });
            }
        }
        out.sort();
        out
    }

    pub fn has_hotfix(&self, kb: &str) -> bool {
        let kb = kb.trim_start_matches("KB");
        self.hotfixes
            .iter()
            .any(|h| h.trim().trim_start_matches("KB").eq_ignore_ascii_case(kb))
    }
}

/// "Security Update for Windows (KB5034441)", "KB2468871".
fn is_kb(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.match_indices("KB").any(|(i, _)| {
        let digits = upper[i + 2..].chars().take_while(char::is_ascii_digit).count();
        digits >= 6 && (i == 0 || upper.as_bytes()[i - 1] == b'(')
    })
}

pub fn parse(json: &str) -> Result<Inventory> {
    serde_json::from_str(json.trim()).context("parsing the registry inventory from PowerShell")
}

pub fn query(sys: &dyn System) -> Result<Inventory> {
    let out = sys.run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encode_command(SCRIPT),
        ],
    )?;
    parse(&out)
}

/// `-EncodedCommand` takes base64 of UTF-16LE and avoids every quoting problem of `-Command`.
pub fn encode_command(script: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Shape of the script's output on Windows 11 24H2, trimmed.
    pub const SAMPLE: &str = r#"{"product_name":"Windows 10 Pro","display_version":"24H2","release_id":"2009",
        "build":"26100","ubr":"9911","edition":"Professional","installation_type":"Client","arch":"AMD64",
        "hotfixes":["KB5054979","KB5132043"],
        "programs":[
          {"name":"7-Zip 24.06 (x64)","version":"24.06","publisher":"Igor Pavlov","system_component":"","parent":"","release_type":"","key":"7-Zip","scope":"machine"},
          {"name":"Git","version":"2.45.1","publisher":"The Git Development Community","system_component":"","parent":"","release_type":"","key":"Git_is1","scope":"machine"},
          {"name":"Google Chrome","version":"131.0.6778.86","publisher":"Google LLC","system_component":"","parent":"","release_type":"","key":"Google Chrome","scope":"machine"},
          {"name":"Google Chrome","version":"131.0.6778.86","publisher":"Google LLC","system_component":"","parent":"","release_type":"","key":"Google Chrome","scope":"user"},
          {"name":"Телеграм","version":"5.8","publisher":"","system_component":"","parent":"","release_type":"","key":"x","scope":"user"},
          {"name":"Microsoft Visual C++ 2022 X64 Minimum Runtime","version":"14.40","publisher":"Microsoft Corporation","system_component":"1","parent":"","release_type":"","key":"{A}","scope":"machine"},
          {"name":"Security Update for Microsoft Office (KB5002623)","version":"","publisher":"Microsoft","system_component":"","parent":"Office16","release_type":"Security Update","key":"{B}","scope":"machine"},
          {"name":"KB2468871","version":"","publisher":"Microsoft","system_component":"","parent":"","release_type":"","key":"{C}","scope":"machine"},
          {"name":"Steam","version":"","publisher":"Valve Corporation","system_component":"","parent":"","release_type":"","key":"Steam","scope":"machine"}
        ]}"#;

    #[test]
    fn lists_programs_like_installed_apps() {
        let inv = parse(SAMPLE).unwrap();
        let programs = inv.programs();
        let names: Vec<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["7-Zip 24.06 (x64)", "Git", "Google Chrome", "Steam", "Телеграм"]
        );
        assert_eq!(inv.build, "26100");
        assert!(inv.has_hotfix("KB5132043") && inv.has_hotfix("5132043") && !inv.has_hotfix("KB1"));
    }

    #[test]
    fn tolerates_null_lists_from_powershell() {
        let inv = parse(r#"{"build":"19045","ubr":"1","hotfixes":null,"programs":null}"#).unwrap();
        assert!(inv.programs().is_empty() && inv.hotfixes.is_empty());
    }

    #[test]
    fn recognizes_kb_entries_but_not_names_with_kb_in_them() {
        assert!(is_kb("KB2468871"));
        assert!(is_kb("Update for Windows (KB5034441)"));
        assert!(!is_kb("KBackup 1.2"));
        assert!(!is_kb("Logitech KB800 driver"));
    }

    #[test]
    fn encodes_commands_as_utf16_base64() {
        // [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('dir'))
        assert_eq!(encode_command("dir"), "ZABpAHIA");
        assert_eq!(encode_command("ab"), "YQBiAA==");
        assert_eq!(encode_command("é"), "6QA=");
    }
}
