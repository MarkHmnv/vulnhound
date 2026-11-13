//! Terminal summary; details go to the Markdown report.

use super::{
    fix_commands, plural, severity_counts, split_findings, terms, third_party_commands, upstream_without_findings,
};
use crate::model::{Finding, Report, Severity, ThirdPartyStatus};
use anstyle::{AnsiColor, Style};
use std::fmt::Write;

const TOP: usize = 10;

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn paint(self, style: Style, text: &str) -> String {
        if self.enabled {
            format!("{style}{text}{style:#}")
        } else {
            text.to_string()
        }
    }

    fn fg(color: AnsiColor) -> Style {
        Style::new().fg_color(Some(color.into()))
    }

    pub fn severity(self, severity: Severity, text: &str) -> String {
        let style = match severity {
            Severity::Critical => Self::fg(AnsiColor::Magenta).bold(),
            Severity::High => Self::fg(AnsiColor::Red).bold(),
            Severity::Medium => Self::fg(AnsiColor::Yellow),
            Severity::Low => Self::fg(AnsiColor::Blue),
            Severity::Unknown => Style::new().dimmed(),
        };
        self.paint(style, text)
    }

    pub fn bold(self, text: &str) -> String {
        self.paint(Style::new().bold(), text)
    }

    pub fn dim(self, text: &str) -> String {
        self.paint(Style::new().dimmed(), text)
    }

    pub fn good(self, text: &str) -> String {
        self.paint(Self::fg(AnsiColor::Green), text)
    }

    pub fn warn(self, text: &str) -> String {
        self.paint(Self::fg(AnsiColor::Yellow), text)
    }

    pub fn command(self, text: &str) -> String {
        self.paint(Self::fg(AnsiColor::Cyan), text)
    }
}

pub fn summary(report: &Report, report_path: Option<&str>, p: Palette) -> String {
    let mut out = String::new();
    let c = &report.coverage;
    let (affected, likely) = split_findings(report);

    let _ = writeln!(
        out,
        "{} {} · {}",
        p.bold("vulnhound"),
        env!("CARGO_PKG_VERSION"),
        report.distro
    );
    let t = terms(report);
    let mut checked = format!(
        "{} of {} {}s checked against {}",
        c.covered_packages, c.installed_packages, t.item, t.data
    );
    if c.uncovered_packages > 0 {
        let _ = write!(checked, ", {} {}", c.uncovered_packages, t.uncovered);
    }
    let _ = writeln!(out, "{}", p.dim(&checked));
    for w in &report.warnings {
        let _ = writeln!(out, "{} {w}", p.warn("warning:"));
    }
    out.push('\n');

    for n in &report.notes {
        let _ = writeln!(out, "{}", p.good(n));
    }
    if affected.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            p.good(&format!("No known vulnerabilities in the checked {}s.", t.item))
        );
    } else {
        let counts: Vec<String> = severity_counts(&affected)
            .into_iter()
            .map(|(s, n)| p.severity(s, &format!("{n} {s}")))
            .collect();
        let _ = writeln!(
            out,
            "{}: {}",
            p.bold(&format!("{} vulnerable", plural(affected.len(), t.item))),
            counts.join(" · ")
        );
        write_top(&mut out, &affected, p);
    }
    let mut quiet = Vec::new();
    if !likely.is_empty() {
        quiet.push(format!("{} likely fixed", plural(likely.len(), "package")));
    }
    if c.fixed_suppressed > 0 {
        quiet.push(format!("{} already fixed", plural(c.fixed_suppressed, "CVE")));
    }
    if !quiet.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            p.dim(&format!("{} (details in the report)", quiet.join(", ")))
        );
    }

    let fixes = fix_commands(&affected);
    if !fixes.is_empty() {
        let n = affected
            .iter()
            .filter(|f| f.update.as_ref().is_some_and(|u| !u.command.is_empty()))
            .count();
        let _ = writeln!(
            out,
            "\n{}",
            p.bold(&format!("Fixes available now for {}:", plural(n, t.item)))
        );
        for cmd in fixes {
            let _ = writeln!(out, "  {}", p.command(&cmd));
        }
    }

    let upstream = upstream_without_findings(report, &affected);
    if !upstream.is_empty() {
        let names: Vec<&str> = upstream.iter().map(|u| u.package.as_str()).collect();
        let _ = writeln!(
            out,
            "\n{} {} not in {} yet: {}",
            p.bold("Upstream:"),
            plural(upstream.len(), "newer release"),
            report.backend,
            names.join(", ")
        );
    }

    if !report.third_party.is_empty() {
        let outdated = report
            .third_party
            .iter()
            .filter(|t| matches!(t.status, ThirdPartyStatus::UpdateAvailable { .. }))
            .count();
        let orphaned = report.third_party.len() - outdated;
        let mut parts = Vec::new();
        if outdated > 0 {
            parts.push(format!("{} outdated", plural(outdated, t.item)));
        }
        if orphaned > 0 {
            parts.push(format!("{orphaned} in no repository"));
        }
        let _ = writeln!(out, "\n{} {}", p.bold(t.updates_label), parts.join(", "));
        for cmd in third_party_commands(report) {
            let _ = writeln!(out, "  {}", p.command(&cmd));
        }
    }

    if let Some(path) = report_path {
        let _ = writeln!(out, "\n{} {}", p.bold("Full report:"), path);
    }
    out
}

/// Highest severity first, then packages with a fix, then the most CVEs.
fn write_top(out: &mut String, affected: &[&Finding], p: Palette) {
    let mut top: Vec<&Finding> = affected.to_vec();
    top.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.update.is_some().cmp(&a.update.is_some()))
            .then(b.vulnerabilities.len().cmp(&a.vulnerabilities.len()))
            .then(a.package.cmp(&b.package))
    });
    top.truncate(TOP);

    let label = |f: &Finding| format!("{} {}", f.package, f.installed);
    let width = top.iter().map(|f| label(f).len()).max().unwrap_or(0);
    for f in &top {
        let sev = p.severity(f.severity, &format!("{:<8}", f.severity.to_string().to_uppercase()));
        let cves = plural(
            f.vulnerabilities
                .iter()
                .filter(|v| v.confidence == crate::model::Confidence::Affected)
                .count(),
            "CVE",
        );
        let fix = match &f.update {
            Some(u) if u.channel == "testing" => p.warn("fix in testing"),
            Some(_) => p.good("fix available"),
            None => p.dim("no fix yet"),
        };
        let _ = writeln!(out, "  {sev} {:<width$}  {:>8}  {fix}", label(f), cves);
    }
    if affected.len() > top.len() {
        let _ = writeln!(
            out,
            "  {}",
            p.dim(&format!("… and {} more", affected.len() - top.len()))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Confidence;
    use crate::report::fixtures::{finding, sample, vuln};

    fn plain(r: &Report) -> String {
        summary(r, Some("vulnhound-report.md"), Palette::new(false))
    }

    #[test]
    fn summary_without_color() {
        let t = plain(&sample());
        let want = "\
vulnhound 0.1.0 · Fedora Linux 45
8 of 10 packages checked against fedora vulnerability data, 2 third-party
warning: Bodhi is down

1 package vulnerable: 1 high
  HIGH     git 2.56.0-1.fc45    2 CVEs  fix in testing
1 package likely fixed, 3 CVEs already fixed (details in the report)

Fixes available now for 1 package:
  sudo dnf upgrade --refresh --enablerepo=updates-testing git-core

Upstream: 1 newer release not in fedora yet: openssh

Third-party: 1 package outdated, 1 in no repository
  sudo dnf upgrade --refresh brave-origin

Full report: vulnhound-report.md
";
        assert_eq!(t, want.replace("0.1.0", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn clean_system_is_one_line() {
        let mut r = sample();
        r.findings.clear();
        r.warnings.clear();
        r.third_party.clear();
        r.upstream.clear();
        r.coverage.fixed_suppressed = 0;
        let t = summary(&r, None, Palette::new(false));
        assert!(
            t.ends_with("\n\nNo known vulnerabilities in the checked packages.\n"),
            "{t}"
        );
    }

    #[test]
    fn top_list_is_capped_and_ordered() {
        let mut r = sample();
        r.findings = (0..12)
            .map(|i| {
                let sev = if i == 11 { Severity::Critical } else { Severity::Low };
                finding(
                    &format!("pkg{i:02}"),
                    "1-1",
                    vec![vuln("CVE-2026-1234", sev, Confidence::Affected)],
                    None,
                )
            })
            .collect();
        let t = plain(&r);
        let critical = t.find("CRITICAL pkg11").expect("critical first");
        assert!(critical < t.find("LOW      pkg00").unwrap());
        assert!(!t.contains("pkg09"), "only the top 10");
        assert!(t.contains("… and 2 more"));
    }
}
