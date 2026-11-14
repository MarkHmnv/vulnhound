//! Scan progress. Backends report sequential steps; the binary decides how to show them.

/// Steps do not nest: `start` opens one, `finish` or `warn` closes it. Units are usually requests;
/// `advance` and `add_total` may come from several threads.
pub trait Progress: Sync {
    fn start(&self, step: &str, total: Option<u64>);
    fn add_total(&self, n: u64);
    fn advance(&self, n: u64);
    fn detail(&self, text: &str);
    fn finish(&self, result: &str);
    /// The step failed or its data is incomplete; the full text is in the report's warnings.
    fn warn(&self, reason: &str);
}

pub struct Silent;

impl Progress for Silent {
    fn start(&self, _: &str, _: Option<u64>) {}
    fn add_total(&self, _: u64) {}
    fn advance(&self, _: u64) {}
    fn detail(&self, _: &str) {}
    fn finish(&self, _: &str) {}
    fn warn(&self, _: &str) {}
}

/// Background work's `detail`, held until its step [`Deferred::attach`]es.
pub struct Deferred<'a> {
    target: &'a dyn Progress,
    /// (attached, pending detail)
    state: std::sync::Mutex<(bool, Option<String>)>,
}

impl<'a> Deferred<'a> {
    pub fn new(target: &'a dyn Progress) -> Self {
        Self {
            target,
            state: std::sync::Mutex::new((false, None)),
        }
    }

    pub fn attach(&self) {
        let mut state = self.state.lock().expect("no panics while holding the lock");
        state.0 = true;
        if let Some(text) = state.1.take() {
            self.target.detail(&text);
        }
    }

    pub fn done(&self) {
        let mut state = self.state.lock().expect("no panics while holding the lock");
        state.0 = false;
        state.1 = None;
    }
}

impl Progress for Deferred<'_> {
    fn start(&self, _: &str, _: Option<u64>) {}
    fn add_total(&self, _: u64) {}
    fn advance(&self, _: u64) {}
    fn detail(&self, text: &str) {
        let mut state = self.state.lock().expect("no panics while holding the lock");
        if state.0 {
            self.target.detail(text);
        } else {
            state.1 = Some(text.into());
        }
    }
    fn finish(&self, _: &str) {}
    fn warn(&self, _: &str) {}
}

#[cfg(test)]
pub mod recording {

    use super::Progress;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Step {
        pub name: String,
        pub done: u64,
        pub total: Option<u64>,
        pub outcome: Result<String, String>,
    }

    #[derive(Default)]
    pub struct Recording {
        current: Mutex<Option<Step>>,
        pub steps: Mutex<Vec<Step>>,
    }

    impl Recording {
        pub fn steps(&self) -> Vec<Step> {
            assert!(self.current.lock().unwrap().is_none(), "a step was left open");
            self.steps.lock().unwrap().clone()
        }

        fn end(&self, outcome: Result<String, String>) {
            let mut step = self.current.lock().unwrap().take().expect("no step to end");
            step.outcome = outcome;
            self.steps.lock().unwrap().push(step);
        }

        fn with(&self, f: impl FnOnce(&mut Step)) {
            f(self.current.lock().unwrap().as_mut().expect("no step started"));
        }
    }

    impl Progress for Recording {
        fn start(&self, step: &str, total: Option<u64>) {
            let mut current = self.current.lock().unwrap();
            assert!(current.is_none(), "steps do not nest: {step}");
            *current = Some(Step {
                name: step.into(),
                done: 0,
                total,
                outcome: Ok(String::new()),
            });
        }
        fn add_total(&self, n: u64) {
            self.with(|s| s.total = Some(s.total.unwrap_or(0) + n));
        }
        fn advance(&self, n: u64) {
            self.with(|s| s.done += n);
        }
        fn detail(&self, _: &str) {
            self.with(|_| {});
        }
        fn finish(&self, result: &str) {
            self.end(Ok(result.into()));
        }
        fn warn(&self, reason: &str) {
            self.end(Err(reason.into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Details(Mutex<Vec<String>>);

    impl Progress for Details {
        fn start(&self, _: &str, _: Option<u64>) {}
        fn add_total(&self, _: u64) {}
        fn advance(&self, _: u64) {}
        fn detail(&self, text: &str) {
            self.0.lock().unwrap().push(text.into());
        }
        fn finish(&self, _: &str) {}
        fn warn(&self, _: &str) {}
    }

    #[test]
    fn deferred_shows_the_latest_detail_once_attached() {
        let target = Details::default();
        let d = Deferred::new(&target);
        d.detail("downloading 2026-Nov");
        d.detail("downloading 2026-Oct");
        assert!(target.0.lock().unwrap().is_empty());
        d.attach();
        d.detail("downloading 2026-Sep");
        assert_eq!(
            *target.0.lock().unwrap(),
            ["downloading 2026-Oct", "downloading 2026-Sep"]
        );
    }

    #[test]
    fn deferred_drops_details_of_finished_work() {
        let target = Details::default();
        let d = Deferred::new(&target);
        d.detail("downloading 2026-Nov");
        d.done();
        d.attach();
        assert!(target.0.lock().unwrap().is_empty());
    }
}
