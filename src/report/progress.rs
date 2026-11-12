//! Live progress on stderr: a spinner or request bar for the running step, one line per finished
//! step.

use crate::progress::Progress;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_REASON: usize = 90;

pub struct TerminalProgress {
    color: bool,
    current: Mutex<Option<Running>>,
}

struct Running {
    bar: ProgressBar,
    name: String,
    started: Instant,
    counted: bool,
}

impl TerminalProgress {
    pub fn new(color: bool) -> Self {
        Self {
            color,
            current: Mutex::new(None),
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn spinner_style(&self) -> ProgressStyle {
        let template = if self.color {
            "  {spinner:.cyan} {msg} {elapsed:.dim}"
        } else {
            "  {spinner} {msg} {elapsed}"
        };
        ProgressStyle::with_template(template)
            .expect("valid template")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠿"])
    }

    fn bar_style(&self) -> ProgressStyle {
        let template = if self.color {
            "  {spinner:.cyan} {msg} {bar:30.cyan/blue} {pos}/{len} {elapsed:.dim}"
        } else {
            "  {spinner} {msg} {bar:30} {pos}/{len} {elapsed}"
        };
        ProgressStyle::with_template(template)
            .expect("valid template")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠿"])
            .progress_chars("━╸─")
    }

    fn with(&self, f: impl FnOnce(&mut Running)) {
        if let Some(r) = self.current.lock().expect("no panics while holding the lock").as_mut() {
            f(r);
        }
    }

    fn end(&self, mark: &str, text: &str) {
        let Some(r) = self.current.lock().expect("no panics while holding the lock").take() else {
            return;
        };
        r.bar.finish_and_clear();
        let elapsed = format_elapsed(r.started.elapsed());
        let sep = self.paint("2", "·");
        let mut line = format!("  {mark} {}", r.name);
        if !text.is_empty() {
            line.push_str(&format!(" {sep} {text}"));
        }
        line.push_str(&format!(" {sep} {}", self.paint("2", &elapsed)));
        eprintln!("{line}");
    }
}

impl Progress for TerminalProgress {
    fn start(&self, step: &str, total: Option<u64>) {
        // Close a step left open by an early return.
        self.end(&self.paint("2", "-"), "");
        let bar = ProgressBar::with_draw_target(total, ProgressDrawTarget::stderr());
        let counted = total.is_some();
        bar.set_style(if counted {
            self.bar_style()
        } else {
            self.spinner_style()
        });
        bar.set_message(step.to_string());
        bar.enable_steady_tick(Duration::from_millis(100));
        *self.current.lock().expect("no panics while holding the lock") = Some(Running {
            bar,
            name: step.to_string(),
            started: Instant::now(),
            counted,
        });
    }

    fn add_total(&self, n: u64) {
        if n == 0 {
            return;
        }
        let style = self.bar_style();
        self.with(|r| {
            if r.counted {
                r.bar.inc_length(n);
            } else {
                r.bar.set_length(n);
                r.bar.set_style(style);
                r.counted = true;
            }
        });
    }

    fn advance(&self, n: u64) {
        self.with(|r| r.bar.inc(n));
    }

    fn detail(&self, text: &str) {
        let detail = self.paint("2", &format!("· {text}"));
        self.with(|r| r.bar.set_message(format!("{} {detail}", r.name)));
    }

    fn finish(&self, result: &str) {
        self.end(&self.paint("32", "✓"), &self.paint("2", result));
    }

    fn warn(&self, reason: &str) {
        let reason = shorten(reason.lines().next().unwrap_or(""), MAX_REASON);
        self.end(&self.paint("33", "!"), &self.paint("33", &reason));
    }
}

/// `0.4s`, `12s`, `1m 05s`.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 10.0 {
        format!("{secs:.1}s")
    } else if secs < 60.0 {
        format!("{secs:.0}s")
    } else {
        let s = d.as_secs();
        format!("{}m {:02}s", s / 60, s % 60)
    }
}

fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max - 1).collect();
    format!("{}…", cut.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_elapsed_time() {
        assert_eq!(format_elapsed(Duration::from_millis(420)), "0.4s");
        assert_eq!(format_elapsed(Duration::from_millis(18_300)), "18s");
        assert_eq!(format_elapsed(Duration::from_secs(65)), "1m 05s");
    }

    #[test]
    fn shortens_long_reasons() {
        assert_eq!(shorten("short", 10), "short");
        assert_eq!(shorten("cannot query Red Hat Bugzilla", 12), "cannot quer…");
    }
}
