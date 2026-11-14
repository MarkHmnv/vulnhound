## Install

**Fedora** — from [COPR](https://copr.fedorainfracloud.org/coprs/markhmnv/vulnhound/); the RPM of this version appears there a few minutes after the release:

```sh
sudo dnf copr enable markhmnv/vulnhound
sudo dnf install vulnhound    # or: sudo dnf upgrade vulnhound
```

**Windows** — download `vulnhound-{{VERSION}}-windows-x86_64.exe` below and run it from a terminal:

```powershell
.\vulnhound-{{VERSION}}-windows-x86_64.exe
```

No root or administrator rights needed. Optional: set `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) for faster and wider program checks on Windows.
