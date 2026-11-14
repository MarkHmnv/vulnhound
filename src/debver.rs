//! Debian package version comparison, as `dpkg --compare-versions` does it (deb-version(7)).

use std::cmp::Ordering;

/// `[epoch:]upstream[-revision]`; a missing epoch is 0 and a missing revision is empty.
fn split(v: &str) -> (u64, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (e.parse().unwrap_or(0), rest),
        _ => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((upstream, revision)) => (epoch, upstream, revision),
        None => (epoch, rest, ""),
    }
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua, ub))
        .then_with(|| verrevcmp(ra, rb))
}

/// `~` sorts before anything, even the end of the string; letters before other characters.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        // Non-digit prefix, character by character.
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = order(a.get(i).copied());
            let bc = order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        // Numeric part, ignoring leading zeros.
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cases from dpkg's own test suite (t-version.c) and real Debian and Ubuntu versions.
    #[test]
    fn compares_like_dpkg() {
        let less = [
            ("1.0", "1.1"),
            ("1.0~rc1", "1.0"),
            ("1.0~~", "1.0~"),
            ("1.0~", "1.0"),
            ("1.0", "1.0a"),
            ("1.0a", "1.0+"),
            ("1.0-1", "1.0-2"),
            ("1.0", "1.0-0.1"),
            ("9.9", "1:0.1"),
            ("2.36-9+deb12u7", "2.36-9+deb12u14"),
            ("3.0.13-0ubuntu3", "3.0.13-0ubuntu3.16"),
            ("23.01+dfsg-11", "23.01+dfsg-11ubuntu0.1~esm1"),
            ("23.01+dfsg-11ubuntu0.1~esm1", "23.01+dfsg-11ubuntu0.1"),
            ("6.8.0-35.35", "6.8.0-60.63"),
            ("3.0.11-1~deb12u2", "3.0.15-1~deb12u1"),
            ("1.2.3", "1.2.10"),
            ("0:1.0", "1:0.9"),
        ];
        for (a, b) in less {
            assert_eq!(cmp(a, b), Ordering::Less, "{a} < {b}");
            assert_eq!(cmp(b, a), Ordering::Greater, "{b} > {a}");
        }
        for (a, b) in [("1.0", "1.0"), ("0:1.0", "1.0"), ("1.01", "1.1"), ("1.0-0", "1.0-")] {
            assert_eq!(cmp(a, b), Ordering::Equal, "{a} = {b}");
        }
    }

    #[test]
    fn splits_off_epoch_and_revision() {
        assert_eq!(split("1:9.6p1-3ubuntu13.14"), (1, "9.6p1", "3ubuntu13.14"));
        assert_eq!(split("1.0"), (0, "1.0", ""));
        assert_eq!(
            split("1.2-3-4"),
            (0, "1.2-3", "4"),
            "the revision is after the last hyphen"
        );
        assert_eq!(split("a:1.0"), (0, "a:1.0", ""), "not an epoch");
    }
}
