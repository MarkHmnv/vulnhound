//! Finding CVE identifiers in free text.

/// A CVE id found in text: `CVE-<4-digit year>-<4 or more digits>`, case-insensitive, not
/// glued to other letters, digits or underscores.
fn find_ids(text: &str) -> impl Iterator<Item = (usize, usize, String)> + '_ {
    let bytes = text.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let digits_from = |at: usize| bytes[at..].iter().take_while(|b| b.is_ascii_digit()).count();
    (0..bytes.len()).filter_map(move |start| {
        let prefix = bytes.get(start..start + 4)?;
        if !prefix.eq_ignore_ascii_case(b"cve-") || start > 0 && is_word(bytes[start - 1]) {
            return None;
        }
        let year_at = start + 4;
        if digits_from(year_at) != 4 || bytes.get(year_at + 4) != Some(&b'-') {
            return None;
        }
        let seq_at = year_at + 5;
        let seq_len = digits_from(seq_at);
        let end = seq_at + seq_len;
        if seq_len < 4 || bytes.get(end).is_some_and(|&b| is_word(b)) {
            return None;
        }
        let id = format!("CVE-{}-{}", &text[year_at..year_at + 4], &text[seq_at..end]);
        Some((start, end, id))
    })
}

/// Returns the CVE ids in `text`, upper-cased, deduplicated, in order of first appearance.
pub fn extract(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (_, _, id) in find_ids(text) {
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// Whether `token` is exactly one CVE id, optionally followed by `:` or `,`.
pub fn is_cve_token(token: &str) -> bool {
    let t = token.trim_end_matches([':', ',']);
    find_ids(t)
        .next()
        .is_some_and(|(start, end, _)| start == 0 && end == t.len())
}

/// Removes leading `[...]` tags from a Bugzilla summary and returns (tags, rest).
pub fn split_leading_tags(summary: &str) -> (&str, &str) {
    let s = summary.trim_start();
    let mut end = 0;
    while s[end..].starts_with('[') {
        match s[end..].find(']') {
            Some(close) => {
                end += close + 1;
                end += s[end..].len() - s[end..].trim_start().len();
            }
            None => break,
        }
    }
    (s[..end].trim_end(), &s[end..])
}

/// CVE ids that a Bugzilla summary is about: the ones listed at its start, after any `[...]`
/// tags. CVEs merely mentioned later ("regression in CVE-X fix") do not count. Falls back to
/// every CVE in the text when none leads.
pub fn leading(summary: &str) -> Vec<String> {
    let (_, rest) = split_leading_tags(summary);
    let mut out = Vec::new();
    for tok in rest
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
    {
        if !is_cve_token(tok) {
            break;
        }
        let id = extract(tok).remove(0);
        if !out.contains(&id) {
            out.push(id);
        }
    }
    if out.is_empty() { extract(summary) } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_takes_only_the_ids_the_summary_is_about() {
        assert_eq!(
            leading("CVE-2026-85498 kdeplasma-addons: Regression in CVE-2026-4897 fix [fedora-all]"),
            vec!["CVE-2026-85498"]
        );
        assert_eq!(
            leading("CVE-2026-1111 CVE-2026-2222, CVE-2026-3333 foo: bar"),
            vec!["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"]
        );
        assert_eq!(
            leading("[Exploits (KEV)] CVE-2026-46333 kernel: Read root-owned files"),
            vec!["CVE-2026-46333"]
        );
        assert_eq!(
            leading("kernel: issue described as CVE-2026-5555"),
            vec!["CVE-2026-5555"]
        );
    }

    #[test]
    fn splits_leading_tags() {
        assert_eq!(split_leading_tags("[A] [B c] rest [x]"), ("[A] [B c]", "rest [x]"));
        assert_eq!(split_leading_tags("no tags"), ("", "no tags"));
        assert_eq!(split_leading_tags("[unclosed rest"), ("", "[unclosed rest"));
    }

    #[test]
    fn extracts_ids() {
        let t = "CVE-2026-111760 git: foo; also cve-2024-1234 and CVE-2026-111760 again";
        assert_eq!(extract(t), vec!["CVE-2026-111760", "CVE-2024-1234"]);
        assert_eq!(extract("(CVE-2026-12345)."), vec!["CVE-2026-12345"]);
        assert_eq!(extract("ünïcode CVE-2026-7777"), vec!["CVE-2026-7777"]);
        for junk in [
            "CVE-2026-1234x",
            "CVE-2026-1234_",
            "a_CVE-2026-1234",
            "XCVE-2026-12345",
            "CVE-20261-1234",
            "CVE-26-1234",
            "CVE-2026-12",
            "CVE-2026-777",
            "CVE-2026-",
        ] {
            assert!(extract(junk).is_empty(), "{junk}");
        }
    }
}
