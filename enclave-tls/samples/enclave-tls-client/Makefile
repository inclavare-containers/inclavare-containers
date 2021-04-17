# samples/enclave-tls-client/Makefile
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../..)

include $(Topdir)/rules/build_env.mk

Targets := $(Build_Bindir)/enclave-tls-client

C_FLAGS += -pie -fPIE -I$(Topdir)/src/include
CLIENT_LDFLAGS := \
  -L$(Topdir)/build/lib -lenclave_tls \
  -Wl,--rpath=/opt/enclave-tls/lib,--enable-new-dtags

ifndef OCCLUM
  CLIENT_LDFLAGS += -lsgx_urts -lm
else
  C_FLAGS += -DOCCLUM
endif

Dependencies += $(Build_Libdir)/libenclave_tls.so

$(Targets): client.c $(Build_Libdir)/libenclave_tls.so
	dest=$(dir $@); \
	$(INSTALL) -d -m 0755 $$dest
	$(CC) $(C_FLAGS) client.c -o $@ $(CLIENT_LDFLAGS)

$(Build_Libdir)/libenclave_tls.so:
	make -C $(Enclave_Tls_Srcdir) $@

Clean += $(wildcard *.o) $(target)

install: all
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Bindir)
	$(INSTALL) -m 0755 $(Targets) $(Enclave_Tls_Bindir)

uninstall:
	@rm -f $(Enclave_Tls_Bindir)/$(notdir $(target))

include $(Topdir)/rules/build_rules.mk
