# Variables for building rpm
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_URL := https://github.com/alibaba/inclavare-containers/archive/v$(INCLAVARE_CONTAINERS_VERSION).tar.gz
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(INCLAVARE_CONTAINERS_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@wget -P $(RPMBUILD_DIR)/SOURCES $(RELEASE_TARBALL_URL)
endif

rpm: release-tarball
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba centos/shim-rune.spec
	@echo "the rpms of shim-rune located in $(RPMBUILD_DIR)/RPMS"

.PHONY: release-tarball rpm
