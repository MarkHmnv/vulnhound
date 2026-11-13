//! Available updates from winget. `winget upgrade` prints only a table, in the display language;
//! columns are found from the header line above the dashes, whatever its words are.

use crate::system::System;
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade {
    pub name: String,
    pub id: String,
    pub installed: String,
    pub available: String,
    pub source: String,
}

impl Upgrade {
    /// winget truncates long names and ids with "…".
    pub fn id_is_complete(&self) -> bool {
        !self.id.ends_with('…') && !self.id.is_empty()
    }

    pub fn command(&self) -> String {
        if self.id_is_complete() {
            format!("winget upgrade --exact --id {}", self.id)
        } else {
            format!("winget upgrade \"{}\"", self.name.trim_end_matches('…'))
        }
    }

    /// The registry name of the same program: winget shows it, possibly truncated.
    pub fn matches_name(&self, registry_name: &str) -> bool {
        let (a, b) = (self.name.to_lowercase(), registry_name.to_lowercase());
        match a.strip_suffix('…') {
            Some(prefix) => b.starts_with(prefix.trim_end()),
            None => a == b,
        }
    }
}

/// winget exits non-zero when there is nothing to upgrade, so its status says little; the table
/// is the answer.
pub fn query(sys: &dyn System) -> Result<Vec<Upgrade>> {
    let out = sys.run_any_status(
        "winget",
        &["upgrade", "--accept-source-agreements", "--disable-interactivity"],
    )?;
    Ok(parse(&out))
}

/// Column starts: where a word begins in the header.
fn columns(header: &[char]) -> Vec<usize> {
    (0..header.len())
        .filter(|&i| !header[i].is_whitespace() && (i == 0 || header[i - 1].is_whitespace()))
        .collect()
}

fn cell(line: &[char], from: usize, to: Option<usize>) -> String {
    let end = to.unwrap_or(line.len()).min(line.len());
    if from >= end {
        return String::new();
    }
    line[from..end].iter().collect::<String>().trim().to_string()
}

pub fn parse(output: &str) -> Vec<Upgrade> {
    // Spinners redraw with \r; only the last frame of a line counts.
    let lines: Vec<Vec<char>> = output
        .lines()
        .map(|l| l.rsplit('\r').next().unwrap_or_default().chars().collect())
        .collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let is_rule = lines[i].len() >= 10 && lines[i].iter().all(|&c| c == '-');
        if !is_rule || i == 0 {
            i += 1;
            continue;
        }
        let cols = columns(&lines[i - 1]);
        // Name, Id, Version, Available and usually Source.
        if cols.len() < 4 {
            i += 1;
            continue;
        }
        i += 1;
        while i < lines.len() {
            let line = &lines[i];
            let next_is_rule = lines
                .get(i + 1)
                .is_some_and(|n| n.len() >= 10 && n.iter().all(|&c| c == '-'));
            if line.iter().all(|c| c.is_whitespace()) || line.len() <= cols[3] || next_is_rule {
                break;
            }
            let get = |k: usize| cell(line, cols[k], cols.get(k + 1).copied());
            let up = Upgrade {
                name: get(0),
                id: get(1),
                installed: get(2),
                available: get(3),
                source: if cols.len() > 4 { get(4) } else { String::new() },
            };
            if !up.name.is_empty() && !up.available.is_empty() {
                out.push(up);
            }
            i += 1;
        }
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const OUTPUT: &str = "   - \r   \\ \r                                                                                                                        \r\
Name                                   Id                        Version        Available      Source
-----------------------------------------------------------------------------------------------------
7-Zip 24.06 (x64)                      7zip.7zip                 24.06          24.08          winget
Google Chrome                          Google.Chrome             131.0.6778.86  131.0.6778.109 winget
Microsoft Visual C++ 2015-2022 Redist… Microsoft.VCRedist.2015+… 14.38.33135.0  14.40.33810.0  winget
3 upgrades available.

The following packages have an upgrade available, but require explicit targeting for upgrade:
Name    Id         Version Available Source
-------------------------------------------
Discord Discord.D… 1.0.9170 1.0.9171 winget
";

    #[test]
    fn parses_both_tables_and_truncated_cells() {
        let ups = parse(OUTPUT);
        assert_eq!(ups.len(), 4);
        assert_eq!(
            ups[0],
            Upgrade {
                name: "7-Zip 24.06 (x64)".into(),
                id: "7zip.7zip".into(),
                installed: "24.06".into(),
                available: "24.08".into(),
                source: "winget".into(),
            }
        );
        assert_eq!(ups[1].available, "131.0.6778.109");
        assert!(!ups[2].id_is_complete());
        assert_eq!(
            ups[2].command(),
            "winget upgrade \"Microsoft Visual C++ 2015-2022 Redist\""
        );
        assert_eq!(ups[0].command(), "winget upgrade --exact --id 7zip.7zip");
        assert_eq!(ups[3].name, "Discord");
        assert!(ups[2].matches_name("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135"));
        assert!(ups[1].matches_name("google chrome") && !ups[1].matches_name("Google Chrome Beta"));
    }

    #[test]
    fn reads_localized_headers() {
        let ru = "Имя     ИД          Версия Доступно Источник\n\
                  ----------------------------------------------\n\
                  Git     Git.Git     2.45.1 2.47.0   winget\n\
                  Обновлений доступно: 1.\n";
        let ups = parse(ru);
        assert_eq!(ups.len(), 1);
        assert_eq!((ups[0].id.as_str(), ups[0].available.as_str()), ("Git.Git", "2.47.0"));
    }

    #[test]
    fn nothing_to_upgrade() {
        assert!(parse("No installed package found matching input criteria.\n").is_empty());
        assert!(parse("").is_empty());
    }
}
