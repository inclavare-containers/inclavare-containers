# samples/enclave-tls-server/Makefile
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../..)

include $(Topdir)/rules/build_env.mk

Targets := $(Build_Bindir)/enclave-tls-server

cflags := $(CFLAGS) -pie -fPIE -I$(Topdir)/src/include
ldflags := \
  $(LDFLAGS) -L$(Topdir)/build/lib -lenclave_tls \
  -Wl,--rpath=/opt/enclave-tls/lib,--enable-new-dtags
ifdef SGX
  ldflags += -L/opt/intel/sgxsdk/lib64 -lsgx_urts -lm
endif

Dependencies += $(Build_Libdir)/libenclave_tls.so

$(Targets): server.c $(Build_Libdir)/libenclave_tls.so
	dest=$(dir $@); \
	$(INSTALL) -d -m 0755 $$dest
	$(CC) $(cflags) server.c -o $@ $(ldflags)

$(Build_Libdir)/libenclave_tls.so:
	make -C $(Enclave_Tls_Srcdir) $@

Clean += $(wildcard *.o) $(target)

install: all
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Bindir)
	$(INSTALL) -m 0755 $(Targets) $(Enclave_Tls_Bindir)

uninstall:
	@rm -f $(Enclave_Tls_Bindir)/$(notdir $(Targets))

include $(Topdir)/rules/build_rules.mk
