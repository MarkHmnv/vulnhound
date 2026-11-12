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
