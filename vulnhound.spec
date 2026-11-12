Name:           vulnhound
# Set from Cargo.toml by .copr/Makefile, which also adds %%changelog.
Version:        0
Release:        1%{?dist}
Summary:        Vulnerability scanner for Fedora

# Vendored dependencies are listed in LICENSE.dependencies.
License:        MIT
URL:            https://github.com/MarkHmnv/vulnhound
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

BuildRequires:  cargo-rpm-macros >= 26
Requires:       dnf
Requires:       rpm

%description
Reports CVEs that apply to installed packages, fixes waiting in updates-testing,
kernel CVEs, newer upstream releases and outdated third-party packages.

%prep
%autosetup -a1
%cargo_prep -v vendor

%build
%cargo_build
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies
%cargo_vendor_manifest

%install
# Not %%cargo_install: it would also install the crate sources, which only -devel packages need.
install -Dpm 0755 target/rpm/vulnhound %{buildroot}%{_bindir}/vulnhound

%check
%cargo_test

%files
%license LICENSE LICENSE.dependencies cargo-vendor.txt
%doc README.md
%{_bindir}/vulnhound
