ifeq ($(ENCLAVE_TLS_VERSION),)
$(error "Please run make package in the root directory")
endif

ifeq ($(ENCLAVE_TLS_MAINTAINER),)
$(error "Please run make package in the root directory")
endif

PROJECT_DIR := $(shell cd ../..; pwd)
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_URL := https://github.com/alibaba/inclavare-containers/archive/v$(ENCLAVE_TLS_VERSION).tar.gz
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(ENCLAVE_TLS_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@wget -P $(RPMBUILD_DIR)/SOURCES $(RELEASE_TARBALL_URL)
endif

rpm: rpm/enclave_tls.spec release-tarball
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba rpm/enclave_tls.spec
	@cp $(RPMBUILD_DIR)/RPMS/x86_64/*.rpm $(PROJECT_DIR)
	@rm -rf $(RPMBUILD_DIR)
	@echo "the rpms of enclave tls located in $(PROJECT_DIR)"

deb: deb/debian/changelog
	@cd deb && ./build.sh
	@echo "the debs of enclave tls located in $(PROJECT_DIR)"

package: rpm/enclave_tls.spec.in deb/debian/changelog.in
ifeq (/etc/debian_version, $(wildcard /etc/debian_version))
	date=`date "+%a, %d %b %Y %H:%M:%S"` && \
	sed "1i\enclave-tls ($(ENCLAVE_TLS_VERSION)-1) unstable; urgency=low\n\n  * Update to version $(ENCLAVE_TLS_VERSION).\n\n -- $(ENCLAVE_TLS_MAINTAINER)  $$date +0000\n" deb/debian/changelog.in > deb/debian/changelog;
	make deb
else ifeq (/etc/redhat-release, $(wildcard /etc/redhat-release))
	sed 's/Version: %{ENCLAVE_TLS_VERSION}/Version: $(ENCLAVE_TLS_VERSION)/' rpm/enclave_tls.spec.in > rpm/enclave_tls.spec && egrep -q '^\* .+ - $(ENCLAVE_TLS_VERSION)' rpm/enclave_tls.spec || { \
	date=`date "+%a %b %d %Y"` && \
	sed -i "/%changelog/a* $$date $(ENCLAVE_TLS_MAINTAINER) - $(ENCLAVE_TLS_VERSION)\n- Update to version $(ENCLAVE_TLS_VERSION)\n" rpm/enclave_tls.spec; };
	make rpm
else
	@echo "error! don't support generating packages on this system"
endif

.PHONY: release-tarball rpm deb package
