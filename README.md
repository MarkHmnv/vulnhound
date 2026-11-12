# vulnhound

Vulnerability scanner for Linux workstations and servers. Besides the advisories your distribution
has already published, it shows:

- known CVEs that are not fixed in stable yet, and fixes waiting in the testing repository;
- kernel CVEs from the kernel's own CVE authority;
- upstream releases the distribution has not packaged yet;
- third-party packages that are outdated or no longer come from any repository.

Supported: **Fedora**. On other distributions vulnhound exits with an error rather than report a
system it cannot check as clean.

## Install

Requires a recent stable Rust toolchain (edition 2024).

```sh
cargo install --path .
```

No root needed, only network access.

## Usage

```sh
vulnhound                     # scan, print a summary, write vulnhound-report.md
vulnhound -o ~/scan.md        # write the report elsewhere
vulnhound --no-upstream       # skip the upstream release check (faster)
vulnhound --no-kernel-cves    # skip the kernel CVE check (no daily 60 MB download)
```

While scanning, each step is shown with its progress. Afterwards you get:

- **Terminal summary**: counts by severity, the most important vulnerable packages, and ready-to-run
  commands that install every available fix.
- **Markdown report**: every CVE with links, the update that fixes it, likely fixed CVEs, newer
  upstream releases, third-party packages and what the scan could not cover.

Color and progress are only used on a terminal; `NO_COLOR` is respected.

Exit status: `0` nothing found, `1` vulnerable packages found, `2` error. Upstream releases and
third-party packages do not change it.

A scan takes about 40 seconds, most of it querying Bugzilla.

## How it works on Fedora

### Data sources

| Source | Used for |
|---|---|
| `rpm` | installed packages, changelogs |
| `dnf repoquery` | available updates, including `updates-testing` |
| [Bodhi](https://bodhi.fedoraproject.org) | advisory type, severity and CVEs of each update; release branch dates |
| [Red Hat Bugzilla](https://bugzilla.redhat.com) | CVE trackers filed against Fedora packages, their severity |
| [OSV](https://osv.dev) | kernel CVEs published by the kernel CNA |
| [release-monitoring.org](https://release-monitoring.org) | latest upstream releases |

### Deciding what is vulnerable

A CVE applies to a package when Red Hat filed a tracker for it that is open (or fixed only in
rawhide) and tagged for all Fedora releases or for yours. It is dropped when:

- the package changelog names the CVE (the fix was backported);
- the CVE's "fixed in" data lists a version the installed one satisfies;
- it was fixed in rawhide before your release branched from rawhide.

If the package was rebased to a newer upstream version after the tracker was filed, the CVE is
shown as **likely fixed**: Red Hat often leaves trackers open long after such a rebase. Likely
fixed CVEs are listed in the report but not counted as vulnerable.

Security updates from Bodhi that are not installed are reported even without a tracker.

### Kernel

Red Hat files few Fedora trackers for kernel CVEs, because Fedora ships upstream stable kernels.
vulnhound therefore also matches the kernel version against the kernel CNA's data, which lists the
stable releases that fix each CVE. The data comes from OSV's export (about 60 MB); a 5 MB index is
kept in `~/.cache/vulnhound` and refreshed once a day.

The report says how many of these CVEs the kernel Fedora currently offers would fix. The CNA
publishes CVEs days to weeks after the fixing release, so a new kernel usually fixes more than
listed. These CVEs have no severity rating. Release-candidate kernels are not checked.

### Upstream releases

For packages with findings and a built-in list of critical packages (openssh, openssl, sudo,
systemd, …), vulnhound looks up the latest upstream release. A release newer than anything Fedora
offers is reported as a hint: it may carry security fixes before Fedora builds it or a CVE tracker
exists. Only packages with an explicit Fedora mapping on release-monitoring.org are checked.

### Third-party packages

Packages not built by Fedora (RPM Fusion, vendor repositories, COPR, local installs) have no
published vulnerability data. vulnhound only reports whether their repository offers a newer build
and whether any enabled repository provides them at all.

### Limits

- A bugfix or enhancement update that silently fixes a CVE is only linked to it when a tracker exists.
- Upstream versions are compared with rpm's algorithm; projects with unusual version schemes can
  give false hints.
- Only the newest installed version of a package is checked (old kernels kept for fallback are not).

## Development

```sh
cargo test                           # unit tests, no network
cargo test -- --ignored live_scan    # full scan of this machine
cargo clippy --all-targets
```

All I/O goes through the `System` trait (`src/system.rs`), so tests run against `FakeSystem` with
recorded responses.

```
src/
  main.rs            CLI
  distro/mod.rs      Backend trait, distribution detection
  distro/fedora/     Fedora backend: rpmdb, changelog, bodhi, bugzilla
  kernel.rs          kernel CNA data (OSV), shared by backends
  upstream.rs        release-monitoring.org client, shared by backends
  model.rs           report model
  progress.rs        progress events
  report/            terminal summary, Markdown report, progress display
  rpmver.rs          rpm version comparison
  system.rs          commands, files, HTTP, cache
```

To add a distribution, implement `Backend` in a new module under `src/distro/` and register it in
`distro::detect`. Use `kernel.rs` only if the distribution ships upstream stable kernels.

## License

MIT, see [LICENSE](LICENSE).
