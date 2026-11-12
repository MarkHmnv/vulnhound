//! Parsing of `/etc/os-release` (see os-release(5)).

use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
}

impl OsRelease {
    pub fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), unquote(v.trim()));
            }
        }
        let get = |k: &str| map.get(k).cloned().unwrap_or_default();
        Self {
            id: get("ID").to_ascii_lowercase(),
            version_id: get("VERSION_ID"),
            pretty_name: map
                .get("PRETTY_NAME")
                .cloned()
                .unwrap_or_else(|| format!("{} {}", get("NAME"), get("VERSION_ID")).trim().to_string()),
        }
    }
}

fn unquote(v: &str) -> String {
    let inner = v
        .strip_circumfix('"', '"')
        .or_else(|| v.strip_circumfix('\'', '\''))
        .unwrap_or(v);
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_and_escaped_values() {
        let os = OsRelease::parse("# c\nID=Fedora\nVERSION_ID=\"45\"\nNAME='Rocky \\\"Linux\\\"'");
        assert_eq!(os.id, "fedora");
        assert_eq!(os.version_id, "45");
        assert_eq!(os.pretty_name, "Rocky \"Linux\" 45", "falls back to NAME VERSION_ID");
    }
}
