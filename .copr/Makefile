# COPR "make_srpm": source and vendored crates go into the SRPM, so the build needs no network.
name := vulnhound
top := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
version := $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' $(top)/Cargo.toml | head -n1)
outdir ?= $(top)
work := $(shell mktemp -d)

srpm:
	dnf -y install cargo git rpm-build
	git -C $(top) archive --prefix=$(name)-$(version)/ -o $(work)/$(name)-$(version).tar.gz HEAD
	cd $(top) && cargo vendor --locked --versioned-dirs $(work)/vendor > /dev/null
	tar -C $(work) -cJf $(work)/$(name)-$(version)-vendor.tar.xz vendor
	sed 's/^Version:.*/Version:        $(version)/' $(top)/$(name).spec > $(work)/$(name).spec
	printf '\n%%changelog\n* %s %s - %s-1\n- Release %s\n' \
	  "$$(git -C $(top) log -1 --format=%cd --date=format:'%a %b %d %Y')" \
	  "$$(git -C $(top) log -1 --format=%an)" $(version) $(version) >> $(work)/$(name).spec
	rpmbuild -bs --define '_sourcedir $(work)' --define '_srcrpmdir $(outdir)' $(work)/$(name).spec
