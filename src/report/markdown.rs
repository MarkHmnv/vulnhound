//! Full report as Markdown.

use super::{
    fix_commands, plural, severity_counts, split_findings, terms, third_party_commands, update_place,
    upstream_without_findings,
};
use crate::model::{Confidence, Finding, Report, ThirdPartyStatus};
use std::fmt::Write;

pub fn render(report: &Report, generated: &str) -> String {
    let mut out = String::new();
    let (affected, likely) = split_findings(report);

    let _ = writeln!(out, "# vulnhound report\n");
    let _ = writeln!(
        out,
        "{} · vulnhound {} · {}\n",
        esc(&report.distro),
        env!("CARGO_PKG_VERSION"),
        esc(generated)
    );
    write_summary(&mut out, report, &affected, &likely);

    if !report.warnings.is_empty() {
        let _ = writeln!(out, "## Warnings\n");
        for w in &report.warnings {
            let _ = writeln!(out, "- {}", esc(w));
        }
        out.push('\n');
    }

    let fixes = fix_commands(&affected);
    if !fixes.is_empty() {
        let _ = writeln!(out, "## Fixes available now\n");
        write_commands(&mut out, &fixes);
    }

    if !affected.is_empty() {
        let _ = writeln!(out, "## Vulnerable {}s\n", terms(report).item);
        for f in &affected {
            write_finding(&mut out, report, f);
        }
    }

    write_likely_fixed(&mut out, &likely);
    write_upstream(&mut out, report, &affected);
    write_third_party(&mut out, report);
    write_coverage(&mut out, report);

    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

fn write_summary(out: &mut String, report: &Report, affected: &[&Finding], likely: &[&Finding]) {
    let c = &report.coverage;
    let t = terms(report);
    let _ = writeln!(out, "## Summary\n");
    let _ = writeln!(
        out,
        "- {} of {} {}s checked against {}.",
        c.covered_packages, c.installed_packages, t.item, t.data
    );
    for n in &report.notes {
        let _ = writeln!(out, "- {}", esc(n));
    }
    if affected.is_empty() {
        let _ = writeln!(out, "- No known vulnerabilities in the checked {}s.", t.item);
    } else {
        let counts: Vec<String> = severity_counts(affected)
            .into_iter()
            .map(|(s, n)| format!("{n} {s}"))
            .collect();
        let _ = writeln!(
            out,
            "- **{} vulnerable**: {}.",
            plural(affected.len(), t.item),
            counts.join(", ")
        );
    }
    if !likely.is_empty() {
        let _ = writeln!(
            out,
            "- {} likely fixed by a rebase to a newer upstream version.",
            plural(likely.len(), "package")
        );
    }
    if c.fixed_suppressed > 0 {
        let _ = writeln!(
            out,
            "- {} skipped because the installed package already has the fix.",
            plural(c.fixed_suppressed, "CVE")
        );
    }
    if !report.upstream.is_empty() {
        let _ = writeln!(
            out,
            "- {} not offered by {} yet.",
            plural(report.upstream.len(), "newer upstream release"),
            report.backend
        );
    }
    if !report.third_party.is_empty() {
        let _ = writeln!(
            out,
            "- {} {}.",
            plural(report.third_party.len(), t.updates_summary.0),
            t.updates_summary.1
        );
    }
    out.push('\n');
}

fn write_likely_fixed(out: &mut String, likely: &[&Finding]) {
    if likely.is_empty() {
        return;
    }
    let _ = writeln!(out, "## Likely fixed\n");
    let _ = writeln!(
        out,
        "These packages moved to a newer upstream version after the CVEs were reported, so the \
             fixes are probably in. The distro has not confirmed it.\n"
    );
    let _ = writeln!(out, "| Package | Installed | CVEs |\n|---|---|---|");
    for f in likely {
        let ids: Vec<String> = f
            .vulnerabilities
            .iter()
            .map(|v| format!("[{}]({})", v.id, v.url))
            .collect();
        let _ = writeln!(out, "| {} | `{}` | {} |", esc(&f.package), f.installed, ids.join(", "));
    }
    out.push('\n');
}

fn write_upstream(out: &mut String, report: &Report, affected: &[&Finding]) {
    let upstream = upstream_without_findings(report, affected);
    if upstream.is_empty() {
        return;
    }
    let _ = writeln!(out, "## Newer upstream releases\n");
    let _ = writeln!(
        out,
        "Packages without known CVEs whose upstream released a version {} does not offer yet. \
             New releases often carry security fixes before a CVE tracker exists.\n",
        report.backend
    );
    let _ = writeln!(
        out,
        "| Package | {} offers | Upstream | Project |\n|---|---|---|---|",
        report.backend
    );
    for u in upstream {
        let _ = writeln!(
            out,
            "| {} | `{}` | `{}` | {} |",
            esc(&u.package),
            u.distro_version,
            u.upstream_version,
            esc(&u.project)
        );
    }
    out.push('\n');
}

fn write_third_party(out: &mut String, report: &Report) {
    if report.third_party.is_empty() {
        return;
    }
    let t = terms(report);
    let _ = writeln!(out, "## {}\n", t.updates_heading);
    let _ = writeln!(out, "{}\n", t.updates_intro);
    let item = if t.item == "program" { "Program" } else { "Package" };
    let _ = writeln!(out, "| {item} | Vendor | Installed | Status |\n|---|---|---|---|");
    for t in &report.third_party {
        let status = match &t.status {
            ThirdPartyStatus::UpdateAvailable { version, repo, .. } => {
                format!("update `{version}` in {}", esc(repo))
            }
            ThirdPartyStatus::NoRepository => "**in no repository**, will not get updates".to_string(),
        };
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | {status} |",
            esc(&t.package),
            esc(&t.vendor),
            t.installed
        );
    }
    out.push('\n');
    let commands = third_party_commands(report);
    if !commands.is_empty() {
        write_commands(out, &commands);
    }
}

fn write_coverage(out: &mut String, report: &Report) {
    let c = &report.coverage;
    if c.uncovered_packages == 0 {
        return;
    }
    let t = terms(report);
    let _ = writeln!(out, "## Coverage\n");
    let _ = writeln!(
        out,
        "{} of {} {}s {}:\n",
        c.uncovered_packages, c.installed_packages, t.item, t.coverage_intro
    );
    for (vendor, n) in &c.uncovered_vendors {
        let _ = writeln!(out, "- {}: {n}", esc(vendor));
    }
    out.push('\n');
}

fn write_finding(out: &mut String, report: &Report, f: &Finding) {
    let _ = writeln!(
        out,
        "### {} · {} `{}`\n",
        f.severity.to_string().to_uppercase(),
        esc(&f.package),
        f.installed
    );
    let affected: Vec<_> = f
        .vulnerabilities
        .iter()
        .filter(|v| v.confidence == Confidence::Affected)
        .collect();
    if !affected.is_empty() {
        let _ = writeln!(out, "| Severity | CVE | Description |\n|---|---|---|");
        for v in affected {
            let _ = writeln!(out, "| {} | [{}]({}) | {} |", v.severity, v.id, v.url, esc(&v.title));
        }
        out.push('\n');
    }
    let likely: Vec<String> = f
        .vulnerabilities
        .iter()
        .filter(|v| v.confidence == Confidence::LikelyFixed)
        .map(|v| format!("[{}]({})", v.id, v.url))
        .collect();
    if !likely.is_empty() {
        let _ = writeln!(out, "Likely fixed by a later rebase: {}.\n", likely.join(", "));
    }
    for note in &f.notes {
        let _ = writeln!(out, "{}\n", esc(note));
    }
    match &f.update {
        Some(u) => {
            let place = update_place(&u.channel);
            let advisory = match (u.id.is_empty(), u.kind.as_str()) {
                (true, _) => String::new(),
                (false, "security") => format!(" ([{}]({}), security, {})", u.id, u.url, u.severity),
                (false, kind) => format!(" ([{}]({}), marked {kind})", u.id, u.url),
            };
            let _ = writeln!(out, "**Update:** `{}` {place}{advisory}\n", u.build);
            if !u.command.is_empty() {
                write_commands(out, std::slice::from_ref(&u.command));
            }
        }
        None => {
            let _ = writeln!(out, "**Update:** none available yet\n");
        }
    }
    if let Some(u) = report.upstream.iter().find(|u| u.package == f.package) {
        let _ = writeln!(
            out,
            "**Upstream:** `{}` is out, {} offers `{}` at most.\n",
            u.upstream_version, report.backend, u.distro_version
        );
    }
}

fn write_commands(out: &mut String, commands: &[String]) {
    let _ = writeln!(out, "```sh");
    for c in commands {
        let _ = writeln!(out, "{c}");
    }
    let _ = writeln!(out, "```\n");
}

/// Text from data sources must not break tables or start formatting.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::fixtures::sample;

    fn md() -> String {
        render(&sample(), "2026-11-11 18:00 UTC")
    }

    #[test]
    fn has_header_and_summary() {
        let t = md();
        assert!(t.starts_with(&format!(
            "# vulnhound report\n\nFedora Linux 45 · vulnhound {} · 2026-11-11 18:00 UTC\n\n## Summary\n\n",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(t.contains("- **1 package vulnerable**: 1 high.\n"));
        assert!(t.contains("- 1 package likely fixed by a rebase"));
        assert!(t.contains("- 3 CVEs skipped"));
        assert!(t.contains("## Warnings\n\n- Bodhi is down\n"));
    }

    #[test]
    fn findings_have_cve_tables_updates_and_upstream() {
        let t = md();
        assert!(
            t.contains(
                "### HIGH · git `2.56.0-1.fc45`\n\n\
             | Severity | CVE | Description |\n|---|---|---|\n\
             | high | [CVE-2026-111760](https://bugs/CVE-2026-111760) | title of CVE-2026-111760 |\n\
             | medium | [CVE-2026-113408](https://bugs/CVE-2026-113408) | title of CVE-2026-113408 |\n\n\
             **Update:** `git-2.56.1-1.fc45` in testing repository only \
             ([FEDORA-2026-5c62077075](https://bodhi/FEDORA-2026-5c62077075), marked enhancement)\n\n\
             ```sh\nsudo dnf upgrade --refresh --enablerepo=updates-testing git-core\n```\n\n\
             **Upstream:** `2.56.2` is out, fedora offers `2.56.1` at most.\n"
            ),
            "{t}"
        );
    }

    #[test]
    fn likely_fixed_upstream_and_third_party_sections() {
        let t = md();
        assert!(t.contains("## Likely fixed\n"));
        assert!(t.contains("| zlib | `1.3-1` | [CVE-2026-1111](https://bugs/CVE-2026-1111) |\n"));
        assert!(t.contains("| openssh | `10.5p1` | `10.6p2` | OpenSSH |\n"));
        assert!(
            !t.contains("| git | `2.56.1`"),
            "git's upstream release sits under its finding"
        );
        assert!(
            t.contains("| brave-origin | Brave Software, Inc. | `1.99.55-1` | update `1.99.56-1` in brave-browser |\n")
        );
        assert!(t.contains("| wordcraft | Learning Machines LLC | `0.17.0-1` | **in no repository**"));
        assert!(t.contains("```sh\nsudo dnf upgrade --refresh brave-origin\n```"));
        assert!(t.ends_with("## Coverage\n\n2 of 10 packages come from outside the distro:\n\n- RPM Fusion: 2\n"));
    }

    #[test]
    fn sections_are_left_out_when_empty() {
        let mut r = sample();
        r.findings.clear();
        r.warnings.clear();
        r.third_party.clear();
        r.upstream.clear();
        r.coverage.uncovered_packages = 0;
        let t = render(&r, "now");
        assert!(t.contains("- No known vulnerabilities in the checked packages.\n"));
        for heading in [
            "## Warnings",
            "## Fixes",
            "## Vulnerable",
            "## Likely",
            "## Newer",
            "## Third",
            "## Coverage",
        ] {
            assert!(!t.contains(heading), "{heading} in\n{t}");
        }
    }

    #[test]
    fn escapes_text_from_data_sources() {
        assert_eq!(
            esc("a|b *c* [d](e) <f> `g` #h\nnext"),
            "a\\|b \\*c\\* \\[d\\](e) \\<f\\> \\`g\\` \\#h next"
        );
        let mut r = sample();
        r.findings[0].vulnerabilities[0].title = "pipe | in title".into();
        assert!(render(&r, "now").contains("| pipe \\| in title |"));
    }
}
