use chrono::{DateTime, Utc};
use clap::Parser;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;
use vulnhound::distro::ScanOptions;
use vulnhound::progress::{Progress, Silent};
use vulnhound::report::progress::TerminalProgress;
use vulnhound::report::{console, markdown};
use vulnhound::system::LiveSystem;

/// Scan the installed packages for known vulnerabilities, including ones whose fix the distro has
/// built but not released to stable yet.
///
/// Prints a summary and writes the full report as Markdown.
///
/// On Windows, set NVD_API_KEY (free from NVD) to look up programs ten times faster and to also
/// check programs that are not in vulnhound's built-in table.
///
/// Exit status: 0 nothing found, 1 vulnerable packages found, 2 error.
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
struct Cli {
    /// Where to write the full Markdown report.
    #[arg(short, long, value_name = "FILE", default_value = "vulnhound-report.md")]
    output: PathBuf,

    /// Do not compare packages with upstream releases (release-monitoring.org).
    #[arg(long)]
    no_upstream: bool,

    /// Do not check the kernel against kernel CNA data (a daily 60 MB download).
    #[arg(long)]
    no_kernel_cves: bool,
}

/// https://no-color.org
fn color(is_terminal: bool) -> bool {
    is_terminal
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let palette = console::Palette::new(color(std::io::stdout().is_terminal()));
    let show_progress = std::io::stderr().is_terminal();
    let terminal_progress;
    let progress: &dyn Progress = if show_progress {
        terminal_progress = TerminalProgress::new(color(true));
        &terminal_progress
    } else {
        &Silent
    };
    let sys = LiveSystem::new();
    let opts = ScanOptions {
        upstream: !cli.no_upstream,
        kernel_cves: !cli.no_kernel_cves,
        nvd_api_key: std::env::var("NVD_API_KEY").ok().filter(|k| !k.trim().is_empty()),
    };

    let scanned = vulnhound::scan(&sys, &opts, progress);
    if show_progress {
        eprintln!();
    }
    let rep = match scanned {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vulnhound: {e:#}");
            return ExitCode::from(2);
        }
    };
    let generated = DateTime::<Utc>::from(SystemTime::now())
        .format("%Y-%m-%d %H:%M UTC")
        .to_string();
    let path = cli.output.display().to_string();
    let written = std::fs::write(&cli.output, markdown::render(&rep, &generated));

    print!(
        "{}",
        console::summary(&rep, written.is_ok().then_some(path.as_str()), palette)
    );
    if let Err(e) = written {
        eprintln!("vulnhound: cannot write the report to {path}: {e}");
        return ExitCode::from(2);
    }

    if rep.findings.iter().any(|f| !f.is_likely_fixed_only()) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
