ifeq ($(RUNE_VERSION),)
$(error "Please run make package in the root directory")
endif

ifeq ($(RUNE_MAINTAINER),)
$(error "Please run make package in the root directory")
endif

PROJECT_DIR := $(shell cd ../..; pwd)
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_URL := https://github.com/alibaba/inclavare-containers/archive/v$(RUNE_VERSION).tar.gz
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(RUNE_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@wget -P $(RPMBUILD_DIR)/SOURCES $(RELEASE_TARBALL_URL)
endif

rpm: rpm/rune.spec release-tarball
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba rpm/rune.spec
	@cp $(RPMBUILD_DIR)/RPMS/x86_64/*.rpm $(PROJECT_DIR)
	@rm -rf $(RPMBUILD_DIR)
	@echo "the rpms of rune located in $(PROJECT_DIR)"	

deb: deb/debian/changelog
	@cd deb && ./build.sh
	@echo "the debs of rune located in $(PROJECT_DIR)"

package: rpm/rune.spec.in deb/debian/changelog.in
ifeq (/etc/debian_version, $(wildcard /etc/debian_version))
	date=`date "+%a, %d %b %Y %H:%M:%S"` && \
	sed "1i\rune ($(RUNE_VERSION)-1) unstable; urgency=low\n\n  * Update to version $(RUNE_VERSION).\n\n -- $(RUNE_MAINTAINER)  $$date +0000\n" deb/debian/changelog.in > deb/debian/changelog;
	make deb
else ifeq (/etc/redhat-release, $(wildcard /etc/redhat-release))
	sed 's/Version: %{RUNE_VERSION}/Version: $(RUNE_VERSION)/' rpm/rune.spec.in > rpm/rune.spec && egrep -q '^\* .+ - $(RUNE_VERSION)' rpm/rune.spec || { \
	date=`date "+%a %b %d %Y"` && \
	sed -i "/%changelog/a* $$date $(RUNE_MAINTAINER) - $(RUNE_VERSION)\n- Update to version $(RUNE_VERSION)\n" rpm/rune.spec; };
	make rpm
else
	@echo "error! don't support generating packages on this system"
endif

.PHONY: release-tarball rpm deb package
