ifeq ($(VERDICTD_VERSION),)
$(error "Please run make package in the root directory")
endif

ifeq ($(VERDICTD_MAINTAINER),)
$(error "Please run make package in the root directory")
endif

PROJECT_DIR := $(shell cd ../..; pwd)
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_URL := https://github.com/alibaba/inclavare-containers/archive/v$(VERDICTD_VERSION).tar.gz
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(VERDICTD_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@wget -P $(RPMBUILD_DIR)/SOURCES $(RELEASE_TARBALL_URL)
endif

rpm: rpm/verdictd.spec release-tarball
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba rpm/verdictd.spec
	@cp $(RPMBUILD_DIR)/RPMS/x86_64/*.rpm $(PROJECT_DIR)
	@rm -rf $(RPMBUILD_DIR)
	@echo "the rpms of verdictd located in $(PROJECT_DIR)"

deb: deb/debian/changelog
	@cd deb && ./build.sh
	@echo "the debs of verdictd located in $(PROJECT_DIR)"

package: rpm/verdictd.spec.in deb/debian/changelog.in
ifeq (/etc/debian_version, $(wildcard /etc/debian_version))
	date=`date "+%a, %d %b %Y %H:%M:%S"` && \
	sed "i\verdictd ($(VERDICTD_VERSION)-1) unstable; urgency=low\n\n  * Package init version $(VERDICTD_VERSION).\n\n -- $(VERDICTD_MAINTAINER)  $$date +0000\n" deb/debian/changelog.in > deb/debian/changelog;
	make deb
else ifeq (/etc/redhat-release, $(wildcard /etc/redhat-release))
	sed 's/Version: %{VERDICTD_VERSION}/Version: $(VERDICTD_VERSION)/' rpm/verdictd.spec.in > rpm/verdictd.spec && egrep -q '^\* .+ - $(VERDICTD_VERSION)' rpm/verdictd.spec || { \
	date=`date "+%a %b %d %Y"` && \
	sed -i "/%changelog/a* $$date $(VERDICTD_MAINTAINER) - $(VERDICTD_VERSION)\n- Package init version $(VERDICTD_VERSION)\n" rpm/verdictd.spec; };
	make rpm
else
	@echo "error! don't support generating packages on this system"
endif

.PHONY: release-tarball rpm deb package
