## Install

**Fedora** — from [COPR](https://copr.fedorainfracloud.org/coprs/markhmnv/vulnhound/); the RPM of this version appears there a few minutes after the release:

```sh
sudo dnf copr enable markhmnv/vulnhound
sudo dnf install vulnhound    # or: sudo dnf upgrade vulnhound
```

**Debian 12+, Ubuntu 20.04+** (amd64) — download `vulnhound_{{VERSION}}-1_amd64.deb` below and install it:

```sh
sudo apt install ./vulnhound_{{VERSION}}-1_amd64.deb
```

**Windows** — download `vulnhound-{{VERSION}}-windows-x86_64.exe` below and run it from a terminal:

```powershell
.\vulnhound-{{VERSION}}-windows-x86_64.exe
```

No root or administrator rights needed. Optional: set `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) for faster and wider program checks on Windows.
