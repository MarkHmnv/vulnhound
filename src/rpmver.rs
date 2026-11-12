//! RPM version parsing and comparison (the `rpmvercmp` algorithm).

use std::cmp::Ordering;
use std::fmt;

/// Compares two version or release strings the way rpm does.
///
/// Strings are split into alternating numeric and alphabetic segments, separators are ignored,
/// `~` sorts before everything (pre-releases) and `^` sorts after the base version but before
/// any further segment (post-release snapshots).
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);

    loop {
        // Skip separators: anything that is not alphanumeric, '~' or '^'.
        while i < a.len() && !is_segment_byte(a[i]) {
            i += 1;
        }
        while j < b.len() && !is_segment_byte(b[j]) {
            j += 1;
        }

        // Tilde sorts before everything, including the end of the string.
        let ta = a.get(i) == Some(&b'~');
        let tb = b.get(j) == Some(&b'~');
        if ta || tb {
            if !ta {
                return Ordering::Greater;
            }
            if !tb {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Caret sorts after the end of the string but before any other segment.
        let ca = a.get(i) == Some(&b'^');
        let cb = b.get(j) == Some(&b'^');
        if ca || cb {
            if i >= a.len() {
                return Ordering::Less;
            }
            if j >= b.len() {
                return Ordering::Greater;
            }
            if !ca {
                return Ordering::Greater;
            }
            if !cb {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        if i >= a.len() || j >= b.len() {
            break;
        }

        let numeric = a[i].is_ascii_digit();
        let take = |s: &[u8], start: usize| {
            let mut end = start;
            while end < s.len()
                && (if numeric {
                    s[end].is_ascii_digit()
                } else {
                    s[end].is_ascii_alphabetic()
                })
            {
                end += 1;
            }
            end
        };
        let ea = take(a, i);
        let eb = take(b, j);
        let sa = &a[i..ea];
        let sb = &b[j..eb];

        // Segments of different types: numeric is newer than alphabetic.
        if sb.is_empty() {
            return if numeric { Ordering::Greater } else { Ordering::Less };
        }

        let ord = if numeric {
            let sa = trim_leading_zeros(sa);
            let sb = trim_leading_zeros(sb);
            sa.len().cmp(&sb.len()).then_with(|| sa.cmp(sb))
        } else {
            sa.cmp(sb)
        };
        if ord != Ordering::Equal {
            return ord;
        }
        i = ea;
        j = eb;
    }

    // Whichever string still has segments left is newer.
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

fn is_segment_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'~' || c == b'^'
}

fn trim_leading_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| c == b'0').count();
    &s[n..]
}

/// Epoch, version and release of a package.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Evr {
    pub epoch: u64,
    pub version: String,
    pub release: String,
}

impl Evr {
    pub fn new(epoch: u64, version: &str, release: &str) -> Self {
        Self {
            epoch,
            version: version.to_string(),
            release: release.to_string(),
        }
    }
}

impl Ord for Evr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| rpmvercmp(&self.version, &other.version))
            .then_with(|| rpmvercmp(&self.release, &other.release))
    }
}

impl PartialOrd for Evr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Evr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch > 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}-{}", self.version, self.release)
    }
}

/// Splits `name-version-release` (as in a source rpm or a Koji build) into name and EVR.
/// Returns `None` if the string has fewer than three dash-separated parts.
pub fn split_nvr(nvr: &str) -> Option<(String, Evr)> {
    let nvr = nvr.strip_suffix(".src.rpm").unwrap_or(nvr);
    let (rest, release) = nvr.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    Some((name.to_string(), Evr::new(0, version, release)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    // Vectors from rpm's own test suite (tests/rpmvercmp.at).
    #[test]
    fn matches_rpm_test_suite() {
        let cases = [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0", "1.0", Greater),
            ("2.0.1", "2.0.1", Equal),
            ("2.0", "2.0.1", Less),
            ("2.0.1a", "2.0.1", Greater),
            ("5.5p1", "5.5p2", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("xyz10", "xyz10.1", Less),
            ("xyz.4", "8", Less),
            ("8", "xyz.4", Greater),
            ("5.5p1", "5.6p1", Less),
            ("6.0.rc1", "6.0", Greater),
            ("10b2", "10a1", Greater),
            ("1.0aa", "1.0a", Greater),
            ("10.0001", "10.1", Equal),
            ("10.0001", "10.0039", Less),
            ("4.999.9", "5.0", Less),
            ("20101121", "20101122", Less),
            ("2_0", "2_0", Equal),
            ("2.0", "2_0", Equal),
            ("a", "a", Equal),
            ("a+", "a+", Equal),
            ("a+", "a_", Equal),
            ("+a", "_a", Equal),
            ("+_", "_+", Equal),
            ("1.0~rc1", "1.0~rc1", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0~rc1", Greater),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0^", "1.0", Greater),
            ("1.0^git1", "1.0", Greater),
            ("1.0^git1", "1.0^git2", Less),
            ("1.0^git1", "1.01", Less),
            ("1.0^20160101", "1.0.1", Less),
            ("1.0^20160101^git1", "1.0^20160101", Greater),
            ("1.0~rc1^git1", "1.0~rc1", Greater),
            ("1.0^git1~pre", "1.0^git1", Less),
        ];
        for (a, b, want) in cases {
            assert_eq!(rpmvercmp(a, b), want, "rpmvercmp({a:?}, {b:?})");
            assert_eq!(rpmvercmp(b, a), want.reverse(), "rpmvercmp({b:?}, {a:?})");
        }
    }

    #[test]
    fn evr_compares_epoch_first() {
        assert!(Evr::new(1, "1.0", "1") > Evr::new(0, "9.9", "9"));
        assert!(Evr::new(0, "2.56.1", "1.fc45") > Evr::new(0, "2.56.0", "1.fc45"));
        assert!(Evr::new(0, "2.56.0", "2.fc45") > Evr::new(0, "2.56.0", "1.fc45"));
    }

    #[test]
    fn splits_source_rpm_and_build_names() {
        let (n, e) = split_nvr("git-2.56.0-1.fc45.src.rpm").unwrap();
        assert_eq!(n, "git");
        assert_eq!(e, Evr::new(0, "2.56.0", "1.fc45"));

        let (n, e) = split_nvr("kernel-headers-7.3.3-300.fc45").unwrap();
        assert_eq!(n, "kernel-headers");
        assert_eq!(e.version, "7.3.3");

        assert!(split_nvr("nodashes").is_none());
        assert!(split_nvr("one-dash").is_none());
    }
}
