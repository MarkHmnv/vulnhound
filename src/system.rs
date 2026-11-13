//! All I/O goes through [`System`], so tests can replace it with canned answers.

use anyhow::{Context, Result, bail};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

/// `Sync`: backends make requests from several threads.
pub trait System: Sync {
    /// Stdout of the program; fails if it cannot start or exits non-zero.
    fn run(&self, program: &str, args: &[&str]) -> Result<String>;
    /// Stdout of the program whatever its exit status; fails only if it cannot start.
    fn run_any_status(&self, program: &str, args: &[&str]) -> Result<String>;
    fn read_file(&self, path: &str) -> Result<String>;
    /// Fails on transport errors and non-2xx responses.
    fn http_get(&self, url: &str) -> Result<String>;
    fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>>;
    /// [`System::http_get`] with extra request headers, e.g. an API key.
    fn http_get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<String>;
    /// A file in the cache directory and when it was written.
    fn cache_read(&self, name: &str) -> Option<(String, SystemTime)>;
    fn cache_write(&self, name: &str, data: &str) -> Result<()>;
    /// `std::env::consts::OS` of the scanned host: "linux", "windows", ...
    fn os(&self) -> &str;
    /// Waits, e.g. to stay under a rate limit.
    fn sleep(&self, duration: Duration);
    /// A monotonic clock that [`System::sleep`] advances.
    fn now(&self) -> Instant;
}

pub struct LiveSystem {
    agent: ureq::Agent,
}

impl LiveSystem {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(concat!("vulnhound/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent: config.into() }
    }
}

impl Default for LiveSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl System for LiveSystem {
    fn run(&self, program: &str, args: &[&str]) -> Result<String> {
        let out = Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .with_context(|| format!("cannot run {program}"))?;
        if !out.status.success() {
            bail!(
                "{program} {} failed ({}): {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn run_any_status(&self, program: &str, args: &[&str]) -> Result<String> {
        let out = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("cannot run {program}"))?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn read_file(&self, path: &str) -> Result<String> {
        std::fs::read_to_string(path).with_context(|| format!("cannot read {path}"))
    }

    fn http_get(&self, url: &str) -> Result<String> {
        self.http_get_with(url, &[])
    }

    fn http_get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<String> {
        // Dropped connections are common when a scan makes hundreds of requests, so transport
        // errors get one more try. An HTTP error status is the server's answer and is final.
        let mut last = None;
        for _ in 0..HTTP_ATTEMPTS {
            match self.get_once(url, headers) {
                Ok(body) => return Ok(body),
                Err(e @ ureq::Error::StatusCode(_)) => return Err(e).with_context(|| format!("GET {url}")),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("at least one attempt was made")).with_context(|| format!("GET {url}"))
    }

    fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let mut resp = self.agent.get(url).call().with_context(|| format!("GET {url}"))?;
        resp.body_mut()
            .with_config()
            .limit(DOWNLOAD_LIMIT)
            .read_to_vec()
            .with_context(|| format!("GET {url}"))
    }

    fn cache_read(&self, name: &str) -> Option<(String, SystemTime)> {
        let path = cache_dir()?.join(name);
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
        Some((std::fs::read_to_string(&path).ok()?, modified))
    }

    fn cache_write(&self, name: &str, data: &str) -> Result<()> {
        let dir = cache_dir().context("cannot find a cache directory (XDG_CACHE_HOME, HOME or LOCALAPPDATA)")?;
        std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        // Write and rename, so an interrupted run never leaves a half-written file.
        let tmp = dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, data).with_context(|| format!("cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, dir.join(name)).with_context(|| format!("cannot write {}", dir.join(name).display()))
    }

    fn os(&self) -> &str {
        std::env::consts::OS
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

const HTTP_ATTEMPTS: usize = 2;
const DOWNLOAD_LIMIT: u64 = 512 * 1024 * 1024;

/// `$XDG_CACHE_HOME/vulnhound`, or `~/.cache/vulnhound`; `%LOCALAPPDATA%/vulnhound` on Windows.
fn cache_dir() -> Option<PathBuf> {
    let non_empty = |k| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if cfg!(windows) {
        non_empty("LOCALAPPDATA")?
    } else {
        non_empty("XDG_CACHE_HOME").or_else(|| non_empty("HOME").map(|h| h.join(".cache")))?
    };
    Some(base.join("vulnhound"))
}

impl LiveSystem {
    fn get_once(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, ureq::Error> {
        let mut req = self.agent.get(url).header("Accept", "application/json");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut resp = req.call()?;
        resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_string()
    }
}

/// Maps `items` on up to `threads` threads, keeping their order.
pub fn parallel_map<T: Sync, R: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads.clamp(1, items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let r = f(item);
                    results.lock().expect("no panics while holding the lock")[i] = Some(r);
                }
            });
        }
    });
    results
        .into_inner()
        .expect("no panics while holding the lock")
        .into_iter()
        .map(|r| r.expect("every item was processed"))
        .collect()
}

/// RFC 3986 unreserved characters.
const QUERY_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// `base?k=v&k=v`, percent-encoded. Repeated keys are kept.
pub fn url_with_query(base: &str, query: &[(&str, &str)]) -> String {
    let mut url = base.to_string();
    for (i, (k, v)) in query.iter().enumerate() {
        url.push(if i == 0 { '?' } else { '&' });
        url.extend(utf8_percent_encode(k, QUERY_UNRESERVED));
        url.push('=');
        url.extend(utf8_percent_encode(v, QUERY_UNRESERVED));
    }
    url
}

#[cfg(test)]
pub mod fake {

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The first rule whose needle is in the request wins. Requests are `program args...`,
    /// `file:<path>` or the URL.
    #[derive(Default)]
    pub struct FakeSystem {
        rules: Vec<(String, Result<Vec<u8>, String>)>,
        pub requests: Mutex<Vec<String>>,
        pub cache: Mutex<HashMap<String, (String, SystemTime)>>,
        os: Option<String>,
        pub slept: Mutex<Duration>,
        start: std::sync::OnceLock<Instant>,
    }

    impl FakeSystem {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn on(self, needle: &str, response: &str) -> Self {
            self.on_bytes(needle, response.as_bytes())
        }

        pub fn on_bytes(mut self, needle: &str, response: &[u8]) -> Self {
            self.rules.push((needle.to_string(), Ok(response.to_vec())));
            self
        }

        /// Puts a cache file in place, written `age` ago.
        pub fn cached(self, name: &str, data: &str, age: Duration) -> Self {
            let written = SystemTime::now() - age;
            self.cache.lock().unwrap().insert(name.into(), (data.into(), written));
            self
        }

        /// The host OS; "linux" by default.
        pub fn os(mut self, os: &str) -> Self {
            self.os = Some(os.to_string());
            self
        }

        pub fn fail(mut self, needle: &str, error: &str) -> Self {
            self.rules.push((needle.to_string(), Err(error.to_string())));
            self
        }

        pub fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        fn answer(&self, key: String) -> Result<Vec<u8>> {
            self.requests.lock().unwrap().push(key.clone());
            for (needle, resp) in &self.rules {
                if key.contains(needle.as_str()) {
                    return resp.clone().map_err(|e| anyhow::anyhow!(e));
                }
            }
            bail!("FakeSystem: no rule for {key}")
        }
    }

    impl System for FakeSystem {
        fn run(&self, program: &str, args: &[&str]) -> Result<String> {
            Ok(String::from_utf8(
                self.answer(format!("{program} {}", args.join(" ")))?,
            )?)
        }
        fn run_any_status(&self, program: &str, args: &[&str]) -> Result<String> {
            self.run(program, args)
        }
        fn read_file(&self, path: &str) -> Result<String> {
            Ok(String::from_utf8(self.answer(format!("file:{path}"))?)?)
        }
        fn http_get(&self, url: &str) -> Result<String> {
            Ok(String::from_utf8(self.answer(url.to_string())?)?)
        }
        fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>> {
            self.answer(url.to_string())
        }
        fn http_get_with(&self, url: &str, _headers: &[(&str, &str)]) -> Result<String> {
            self.http_get(url)
        }
        fn cache_read(&self, name: &str) -> Option<(String, SystemTime)> {
            self.cache.lock().unwrap().get(name).cloned()
        }
        fn cache_write(&self, name: &str, data: &str) -> Result<()> {
            self.cache
                .lock()
                .unwrap()
                .insert(name.into(), (data.into(), SystemTime::now()));
            Ok(())
        }
        fn os(&self) -> &str {
            self.os.as_deref().unwrap_or("linux")
        }
        fn sleep(&self, duration: Duration) {
            *self.slept.lock().unwrap() += duration;
        }
        /// Only sleeping moves it, so tests never wait.
        fn now(&self) -> Instant {
            *self.start.get_or_init(Instant::now) + *self.slept.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_query_strings() {
        let u = url_with_query("https://x/y", &[("component", "libstdc++"), ("component", "git")]);
        assert_eq!(u, "https://x/y?component=libstdc%2B%2B&component=git");
        let u = url_with_query("https://x/y", &[("ids", "1,2"), ("r", "---"), ("q", "a b&c=d/é~_.")]);
        assert_eq!(u, "https://x/y?ids=1%2C2&r=---&q=a%20b%26c%3Dd%2F%C3%A9~_.");
        assert_eq!(url_with_query("https://x/y", &[]), "https://x/y");
    }

    #[test]
    fn parallel_map_keeps_order() {
        let items: Vec<u32> = (0..100).collect();
        let out = parallel_map(&items, 8, |x| x * 2);
        assert_eq!(out, (0..100).map(|x| x * 2).collect::<Vec<_>>());
        assert!(parallel_map(&Vec::<u32>::new(), 8, |x| *x).is_empty());
    }
}
