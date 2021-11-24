# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ENCLAVE_TLS_VERSION := $(shell cat $(ROOTDIR)/VERSION)
ENCLAVE_TLS_MAINTAINER := $(shell head -1 $(ROOTDIR)/MAINTAINERS)

Topdir := $(shell readlink -f .)

export Topdir

include $(Topdir)/rules/build_env.mk

client_dir := $(Topdir)/samples/enclave-tls-client
server_dir := $(Topdir)/samples/enclave-tls-server
stub_dir := $(Topdir)/samples/sgx-stub-enclave
dirs := $(Enclave_Tls_Srcdir) $(client_dir) $(server_dir) $(stub_dir)

all: $(Build_Bindir)/enclave-tls-client $(Build_Bindir)/enclave-tls-server $(stub_dir)/sgx_stub_enclave.signed.so
	@make -C $(Enclave_Tls_Srcdir)

$(Build_Bindir)/enclave-tls-client:
	@make -C $(client_dir)

$(Build_Bindir)/enclave-tls-server:
	@make -C $(server_dir)

$(stub_dir)/sgx_stub_enclave.signed.so:
	@make -C $(stub_dir)

Cleans += $(Build_Dir)
RPM_SPEC_DIR := $(Topdir)/dist/rpm/enclave_tls.spec
CHANGELOG_DIR := $(Topdir)/dist/deb/debian/changelog
Cleans += $(RPM_SPEC_DIR)
Cleans += $(CHANGELOG_DIR)
Clean_Dirs += $(dirs) $(Enclave_Tls_Srcdir)/sgx

install: all
	@for d in $(dirs); do \
	  make -C $$d $@ || exit 1; \
	done

uninstall:
	@for d in $(dirs); do \
	  make -C $$d $@; \
	done
	@rm -rf $(shell dirname $(Enclave_Tls_Bindir))

package:
	$(MAKE) -C dist package ENCLAVE_TLS_VERSION="$(ENCLAVE_TLS_VERSION)" ENCLAVE_TLS_MAINTAINER="$(ENCLAVE_TLS_MAINTAINER)"

include $(Topdir)/rules/build_rules.mk
