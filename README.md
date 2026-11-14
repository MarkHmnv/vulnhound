# vulnhound

Vulnerability scanner for Linux and Windows workstations and servers. Besides the advisories your
distribution has already published, it shows:

- known CVEs that are not fixed in stable yet, and fixes waiting in the testing repository;
- on Ubuntu, fixes that only Ubuntu Pro subscribers get;
- kernel CVEs from the kernel's own CVE authority;
- upstream releases the distribution has not packaged yet;
- third-party packages that are outdated or no longer come from any repository.

Supported: **Fedora**, **Debian**, **Ubuntu** (see [Debian and Ubuntu](#debian-and-ubuntu)) and
**Windows** 10, 11 and Server (see [Windows](#windows)). On other distributions, derivatives
like Linux Mint included, vulnhound exits with an error rather than report a system it cannot check
as clean.

## Install

From [COPR](https://copr.fedorainfracloud.org/coprs/markhmnv/vulnhound/):

```sh
sudo dnf copr enable markhmnv/vulnhound
sudo dnf install vulnhound
```

Updates then come with `dnf upgrade`.

On Debian 12+ and Ubuntu 20.04+ (amd64), download `vulnhound_<version>-1_amd64.deb` from
[Releases](https://github.com/MarkHmnv/vulnhound/releases) and install it; for a newer version,
install the newer package the same way:

```sh
sudo apt install ./vulnhound_0.2.0-1_amd64.deb
```

Or build from source with a recent stable Rust toolchain:

```sh
cargo install --path .
```

Scanning needs no root, only network access.

## Usage

```sh
vulnhound                     # scan, print a summary, write vulnhound-report.md
vulnhound -o ~/scan.md        # write the report elsewhere
vulnhound --no-upstream       # skip the upstream release check (faster; Fedora only)
vulnhound --no-kernel-cves    # skip the kernel CVE check (no daily 60 MB download; Fedora only)
```

While scanning, each step is shown with its progress. Afterwards you get:

- **Terminal summary**: counts by severity, the most important vulnerable packages, and ready-to-run
  commands that install every available fix.
- **Markdown report**: every CVE with links, the update that fixes it, likely fixed CVEs, newer
  upstream releases, third-party packages and what the scan could not cover.

Color and progress are only used on a terminal; `NO_COLOR` is respected.

Exit status: `0` nothing found, `1` vulnerable packages found, `2` error. Upstream releases and
third-party packages do not change it.

A scan takes about 40 seconds on Fedora, most of it querying Bugzilla, and a few seconds on Debian
and Ubuntu.

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

## Debian and Ubuntu

Tested on Debian 12 and 13 and Ubuntu 20.04, 22.04 and 24.04. Debian testing works too (unstable
calls itself testing in os-release and is checked as such), as do Ubuntu releases that Canonical
publishes OVAL data for.

### Data sources

| Source | Used for |
|---|---|
| `dpkg-query` | installed packages and their source packages |
| `apt-cache policy` | which repository each package comes from, versions apt can install |
| [Debian security tracker](https://security-tracker.debian.org/tracker/) | Debian: every CVE of every source package, per release: fixed version or why it is open |
| [Ubuntu OVAL data](https://security-metadata.canonical.com/oval/) | Ubuntu: every CVE per release, its priority, the fixed version and the pocket it is published in |
| `pro security-status` | Ubuntu: whether Ubuntu Pro is attached and which services are enabled |

The security data of the release is downloaded once a day (Debian 15 MB, Ubuntu about 12 MB) and
kept as an index in `~/.cache/vulnhound`.

### Deciding what is vulnerable

Debian and Ubuntu backport fixes into the version a release shipped, so upstream versions say
nothing. A CVE applies when the installed source package is older than the version the distribution
names as fixed in this release, or when it has no fix in this release. Open CVEs say why, as the
distribution does: no fix yet, fix postponed, "will not fix" (Debian's minor issues), fix waiting for
the next Debian point release, or not triaged yet. CVEs that Debian rates *unimportant* and Ubuntu
*negligible* are left out: both consider them without real security impact.

For each vulnerable package the update is the newest fixed version, shown with the suite apt would
install it from (e.g. `bookworm-security`). If apt's package lists do not have it yet, the report
says so; `sudo apt update` fetches them.

Debian rarely rates CVEs, so most have no severity. Ubuntu's priority is used as is.

### Ubuntu Pro

Canonical publishes some fixes to Ubuntu Pro subscribers only:

- **esm-apps**: fixes for packages in `universe` (ImageMagick, FFmpeg, Node.js, ...), for the whole
  life of an LTS release. Without Pro these packages get only the fixes the community uploads.
- **esm-infra**: once an LTS release leaves its five years of standard support (20.04 did in
  2025), fixes for `main` too.

Fixes in `main` during standard support are free and come out at the same time for everyone.

vulnhound reads in which pocket each fix is published. A fix in esm-apps or esm-infra that this
machine does not get is shown as "fix in Ubuntu Pro", with the commands to attach (`sudo pro
attach`) or enable the service, and a warning counts them. Pro is free for personal use on up to
5 machines. A release past standard support without esm-infra gets a warning of its own.

### Kernel

The kernel is matched like any other package, as its source package (`linux`, `linux-hwe-6.8`,
`linux-aws`, ...), for the newest installed kernel image. A new kernel version is a new package, so
the fix command is `apt full-upgrade`, which installs it through the kernel metapackage, followed by
a reboot. Packages that are not the kernel itself, like `linux-libc-dev` that comes with any
compiler, are not matched against kernel CVEs. Kernel CNA data is not used: Debian and Ubuntu
backport kernel fixes.

### Third-party packages

A package counts as the distribution's when apt has its installed version (or, after Debian
dropped a superseded version, its newest version) from a Debian or Ubuntu repository, Ubuntu Pro's
included. Packages from other repositories (Docker, PPAs, vendors) and local installs are reported
like on Fedora: whether their repository offers a newer version and whether any repository has them
at all. Without apt's package lists (e.g. a container before `apt update`) every package counts as
the distribution's, with a warning.

### Limits

- apt's view is only as recent as its package lists; vulnhound cannot refresh them without root.
- Debian and Ubuntu publish no machine-readable link from a CVE to its DSA, DLA or USN, so updates
  are shown without an advisory id.
- The upstream release check is not done: stable releases do not follow upstream versions.
- Livepatch is not taken into account; the installed kernel package counts.

## Windows

Download `vulnhound-<version>-windows-x86_64.exe` from
[Releases](https://github.com/MarkHmnv/vulnhound/releases) and run it, or build it:

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

CI runs the tests on Linux and Windows and scans Fedora (in a container), the Windows runner, and
Debian 12 and 13 and Ubuntu 20.04, 22.04 and 24.04 (in containers, with the .deb installed); the
reports are attached to each run.

Each platform's binary contains only its own backend (`#[cfg]` in `src/lib.rs` and
`src/distro/mod.rs`); tests build both, so either backend is tested on any host.

All I/O goes through the `System` trait (`src/system.rs`), so tests run against `FakeSystem` with
recorded responses.

```
src/
  main.rs            CLI
  distro/mod.rs      Backend trait, distribution detection
  distro/fedora/     Fedora backend: rpmdb, changelog, bodhi, bugzilla
  distro/debian/     Debian and Ubuntu backend: apt, Debian tracker, Ubuntu OVAL, Ubuntu Pro
  distro/windows/    Windows backend: registry inventory, msrc, nvd, program catalog, winget
  kernel.rs          kernel CNA data (OSV), shared by backends
  upstream.rs        release-monitoring.org client, shared by backends
  model.rs           report model
  progress.rs        progress events
  report/            terminal summary, Markdown report, progress display
  rpmver.rs          rpm version comparison
  debver.rs          dpkg version comparison
  system.rs          commands, files, HTTP, cache
vulnhound.spec       RPM spec
.github/build-deb.sh builds the .deb from a release binary
.copr/Makefile       builds the SRPM for COPR, with vendored crates
```

To add a distribution, implement `Backend` in a new module under `src/distro/` and register it in
`distro::detect`. Use `kernel.rs` only if the distribution ships upstream stable kernels.

## License

MIT, see [LICENSE](LICENSE).
