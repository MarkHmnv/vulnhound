//! Versions of Windows programs: dotted numbers with the odd suffix (`24.07`, `3.0.21`,
//! `131.0.6778.86`, `1.1.1w`, `2.0rc1`).

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Num(String),
    Alpha(String),
}

/// Pre-release words sort before the release they lead to; other letters after it (`1.1.1w`).
const PRE_RELEASE: &[&str] = &["dev", "alpha", "a", "beta", "b", "pre", "preview", "rc"];

fn segments(v: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut chars = v.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut n = String::new();
            while let Some(&d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                n.push(d);
                chars.next();
            }
            let trimmed = n.trim_start_matches('0');
            out.push(Segment::Num(if trimmed.is_empty() {
                "0".into()
            } else {
                trimmed.into()
            }));
        } else if c.is_ascii_alphabetic() {
            let mut a = String::new();
            while let Some(&l) = chars.peek().filter(|l| l.is_ascii_alphabetic()) {
                a.push(l.to_ascii_lowercase());
                chars.next();
            }
            out.push(Segment::Alpha(a));
        } else {
            chars.next();
        }
    }
    out
}

fn cmp_num(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Missing numeric segments count as 0, so `3.0` equals `3.0.0.0`.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (segments(a), segments(b));
    let zero = Segment::Num("0".into());
    for i in 0..a.len().max(b.len()) {
        let ord = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => cmp_segment(x, y),
            (Some(x), None) => cmp_missing(x, &zero),
            (None, Some(y)) => cmp_missing(y, &zero).reverse(),
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn cmp_segment(a: &Segment, b: &Segment) -> Ordering {
    match (a, b) {
        (Segment::Num(x), Segment::Num(y)) => cmp_num(x, y),
        (Segment::Alpha(x), Segment::Alpha(y)) => {
            let rank = |s: &str| PRE_RELEASE.iter().position(|p| *p == s);
            match (rank(x), rank(y)) {
                (Some(i), Some(j)) => i.cmp(&j),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => x.cmp(y),
            }
        }
        // 1.0.1 is a later release than 1.0rc1 or 1.0a.
        (Segment::Num(_), Segment::Alpha(_)) => Ordering::Greater,
        (Segment::Alpha(_), Segment::Num(_)) => Ordering::Less,
    }
}

/// `present` against a version that has ended.
fn cmp_missing(present: &Segment, zero: &Segment) -> Ordering {
    match present {
        Segment::Num(_) => cmp_segment(present, zero),
        Segment::Alpha(a) if PRE_RELEASE.contains(&a.as_str()) => Ordering::Less,
        Segment::Alpha(_) => Ordering::Greater,
    }
}

/// The first version-looking token: `6.2.5 (50227)` gives `6.2.5`, `Python 3.12.4 (64-bit)` gives
/// `3.12.4`, `7.1.1-39` stays whole. `None` if there is no digit.
pub fn extract(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let start = (0..bytes.len()).find(|&i| {
        bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'v')
    })?;
    let mut end = start;
    let digits = |from: usize| (from..bytes.len()).take_while(|&j| bytes[j].is_ascii_digit()).count();
    end += digits(end);
    // .N groups, then one -N group (build numbers), then a letter suffix such as `w` or `rc1`.
    while end + 1 < bytes.len() && bytes[end] == b'.' && bytes[end + 1].is_ascii_digit() {
        end += 1 + digits(end + 1);
    }
    if end + 1 < bytes.len() && bytes[end] == b'-' && bytes[end + 1].is_ascii_digit() {
        end += 1 + digits(end + 1);
    }
    let letters = (end..bytes.len())
        .take_while(|&j| bytes[j].is_ascii_alphabetic())
        .count();
    if letters > 0 && letters <= 7 {
        let after = end + letters;
        let next_ok = after == bytes.len() || !bytes[after].is_ascii_alphabetic();
        if next_ok {
            end = after + digits(after);
        }
    }
    Some(text[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn compares_like_vendors_number_releases() {
        assert_eq!(cmp("24.07", "24.7"), Equal);
        assert_eq!(cmp("24.08", "24.07"), Greater);
        assert_eq!(cmp("3.0", "3.0.0.0"), Equal);
        assert_eq!(cmp("131.0.6778.86", "131.0.6778.85"), Greater);
        assert_eq!(cmp("10.0.26100.9974", "10.0.26100.10001"), Less);
        assert_eq!(cmp("2.0rc1", "2.0"), Less);
        assert_eq!(cmp("2.0beta", "2.0rc1"), Less);
        assert_eq!(cmp("1.1.1w", "1.1.1"), Greater);
        assert_eq!(cmp("1.1.1w", "1.1.1v"), Greater);
        assert_eq!(cmp("1.0.1", "1.0rc1"), Greater);
        assert_eq!(cmp("7.1.1-39", "7.1.1-4"), Greater);
        assert_eq!(cmp("99999999999999999999", "1"), Greater, "no overflow");
    }

    #[test]
    fn extracts_the_version_from_free_text() {
        assert_eq!(extract("6.2.5 (50227)").as_deref(), Some("6.2.5"));
        assert_eq!(extract("Python 3.12.4 (64-bit)").as_deref(), Some("3.12.4"));
        assert_eq!(extract("NVIDIA Graphics Driver 566.14").as_deref(), Some("566.14"));
        assert_eq!(extract("7.1.1-39").as_deref(), Some("7.1.1-39"));
        assert_eq!(extract("2.6.10-I001").as_deref(), Some("2.6.10"));
        assert_eq!(extract("1.1.1w").as_deref(), Some("1.1.1w"));
        assert_eq!(extract("v2.4.0rc2").as_deref(), Some("2.4.0rc2"));
        assert_eq!(
            extract("IntelliJ IDEA Community Edition 2024.2.4").as_deref(),
            Some("2024.2.4")
        );
        assert_eq!(extract("Win64 build"), None);
        assert_eq!(extract(""), None);
    }
}
