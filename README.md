# vulnhound

Vulnerability scanner for Linux and Windows workstations and servers. Besides the advisories your
distribution has already published, it shows:

- known CVEs that are not fixed in stable yet, and fixes waiting in the testing repository;
- kernel CVEs from the kernel's own CVE authority;
- upstream releases the distribution has not packaged yet;
- third-party packages that are outdated or no longer come from any repository.

Supported: **Fedora** and **Windows** 10, 11 and Server (see [Windows](#windows)). On other
distributions vulnhound exits with an error rather than report a system it cannot check as clean.

## Install

From [COPR](https://copr.fedorainfracloud.org/coprs/markhmnv/vulnhound/):

```sh
sudo dnf copr enable markhmnv/vulnhound
sudo dnf install vulnhound
```

Updates then come with `dnf upgrade`. Or build from source with a recent stable Rust toolchain:

```sh
cargo install --path .
```

Scanning needs no root, only network access.

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

## Windows

```powershell
cargo build --release
.\target\release\vulnhound.exe
```

No administrator rights are needed. The same options, report and exit status apply; the Fedora-only
options are ignored.

### Data sources

| Source | Used for |
|---|---|
| Registry (via PowerShell) | Windows build, installed programs (the "Uninstall" keys of the machine and of every loaded user profile), installed KBs |
| [MSRC](https://api.msrc.microsoft.com/cvrf/v3.0/updates) | Windows CVEs and the KB and build that fix each, per Windows release |
| [NVD](https://nvd.nist.gov) | CVEs of programs, with affected version ranges |
| `winget upgrade` | available program updates |

### Windows itself

vulnhound names the release the way Microsoft's security data does (e.g. "Windows 11 Version 24H2
for x64-based Systems") and compares the installed build (`10.0.26100.9911`) with the build that
fixes each CVE. A CVE also counts as fixed when its KB is installed, or the build is the hotpatch
that fixes it. Updates are cumulative, so months are checked newest first until one is fully
installed, at most six. A Windows release that Microsoft no longer lists is reported as a warning,
not as clean.

### Programs

Programs are found wherever they came from: installers, winget, portable apps that register
themselves. Each one has to be matched to its NVD product, because registry names
are free text:

- A built-in table maps about 70 common, often attacked programs (browsers, archivers, PDF
  readers, remote access and VPN clients, developer tools, NVIDIA drivers, ...) to NVD products,
  and knows where each keeps its real version (Python's and JetBrains' DisplayVersion is a build
  number, so the version is taken from the name).
- With `NVD_API_KEY` set ([free](https://nvd.nist.gov/developers/request-an-api-key)), other
  programs are looked up by a product name guessed from publisher and name
  (`Igor Pavlov` / `7-Zip` → `igor_pavlov:7-zip`). A guess only counts if NVD has data under it,
  and findings from guesses say so.

NVD lists affected version ranges; vulnhound matches the installed version against them, skipping
criteria for other platforms (macOS, Android, Linux-only configurations), pre-releases, and
criteria that name the product without any version (old protocol-level CVEs).

vulnhound asks NVD for the installed version only, so answers are small. NVD takes 5 to 20 seconds
per answer and, without an API key, allows 5 requests per 30 seconds, so requests run 5 at a time:
about 30 seconds per 5 products on the first scan. Answers are cached in
`%LOCALAPPDATA%\vulnhound` for a day.

For a vulnerable program, the update is winget's (with a note if winget's version is still
affected), or else the version NVD names as fixed. Other programs that winget can update are listed
separately.

### Limits

- Programs not in the table are not checked without an API key, and their count is shown.
- Store (MSIX) apps, Office, .NET and Visual Studio are not checked yet.
- NVD's version ranges are only as good as its analysis; recent CVEs may not have ranges yet.
- `winget upgrade` prints a table, not data; long names and ids come truncated.

## Development

```sh
cargo test                           # unit tests, no network
cargo test -- --ignored live_scan    # full scan of this machine
cargo clippy --all-targets
```

CI runs the tests on Linux and Windows and scans the Windows runner; the report is attached to
each run.

Each platform's binary contains only its own backend (`#[cfg]` in `src/lib.rs` and
`src/distro/mod.rs`); tests build both, so either backend is tested on any host.

All I/O goes through the `System` trait (`src/system.rs`), so tests run against `FakeSystem` with
recorded responses.

```
src/
  main.rs            CLI
  distro/mod.rs      Backend trait, distribution detection
  distro/fedora/     Fedora backend: rpmdb, changelog, bodhi, bugzilla
  distro/windows/    Windows backend: registry inventory, msrc, nvd, program catalog, winget
  kernel.rs          kernel CNA data (OSV), shared by backends
  upstream.rs        release-monitoring.org client, shared by backends
  model.rs           report model
  progress.rs        progress events
  report/            terminal summary, Markdown report, progress display
  rpmver.rs          rpm version comparison
  system.rs          commands, files, HTTP, cache
vulnhound.spec       RPM spec
.copr/Makefile       builds the SRPM for COPR, with vendored crates
```

To add a distribution, implement `Backend` in a new module under `src/distro/` and register it in
`distro::detect`. Use `kernel.rs` only if the distribution ships upstream stable kernels.

## License

MIT, see [LICENSE](LICENSE).
