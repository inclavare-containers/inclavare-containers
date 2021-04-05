# src/Makefile
#

Topdir ?= $(shell readlink -f ..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

libenclave_tls := $(notdir $(Enclave_Tls_Lib))
crypto_wrappers := $(addsuffix .so,$(addprefix libcrypto_wrapper_,nullcrypto wolfcrypt wolfcrypt-sgx))
tls_wrappers := $(addsuffix .so,$(addprefix libtls_wrapper_,nulltls wolfssl wolfssl-sgx))
enclave_quotes := $(addsuffix .so,$(addprefix libenclave_quote_,nullquote sgx-ecdsa))
all: $(addprefix $(Build_Libdir)/,$(libenclave_tls) $(crypto_wrappers) $(tls_wrappers) $(enclave_quotes))
#Targets: 

#objs := $(WOLFSSL_ENCLAVE_DIR)/wolfssl_enclave_u.o
#tlibs := libtls_wrapper_wolfssl_sgx.a wolfssl_enclave.signed.so
#all += $(objs) $(tlibs)

this_dir := $(shell pwd)
libenclave_tls_files := \
  $(wildcard \
    $(this_dir)/core/*.c $(this_dir)/api/*.c \
    $(this_dir)/crypto_wrappers/internal/*.c $(this_dir)/crypto_wrappers/api/*.c \
    $(this_dir)/tls_wrappers/internal/*.c $(this_dir)/tls_wrappers/api/*.c \
    $(this_dir)/enclave_quotes/internal/*.c $(this_dir)/enclave_quotes/api/*.c \
  )
libenclave_tls_objs := $(libenclave_tls_files:.c=.o)
$(Build_Libdir)/$(libenclave_tls): $(libenclave_tls_objs)
	@$(INSTALL) -d -m 0755 $(dir $@)
	$(LD) $(Enclave_Tls_Ldflags) -soname=$(notdir $@).$(Major_Version) -o $@ $^ -ldl

$(libenclave_tls_objs): %.o: %.c
	$(CC) -c $(Enclave_Tls_Cflags) -o $@ $<

$(addprefix $(Build_Libdir)/,$(crypto_wrappers) $(tls_wrappers) $(enclave_quotes)):
	@n=$(patsubst lib%.so,%,$(notdir $@)); \
	 dir=`echo $$n | cut -d '_' -f1-2`; \
	 name=$${n#$${dir}_}; \
	 make -C $(this_dir)/$${dir}s/$$name

wolfssl_dir := $(this_dir)/external/wolfssl

install_libenclave_tls: $(Build_Libdir)/$(libenclave_tls)
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)
	dest=$(libenclave_tls).$(Major_Version).$(Minor_Version).$(Patch_Version); \
	$(INSTALL) -m 0755 $< $(Enclave_Tls_Libdir)/$$dest && \
	ln -sf $$dest $(Enclave_Tls_Libdir)/$(libenclave_tls).$(Major_Version) && \
	ln -sf $$dest $(Enclave_Tls_Libdir)/$(libenclave_tls)

install: all
	make install_libenclave_tls
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Root)/include/enclave-tls
	$(INSTALL) -m 0744 $(Enclave_Tls_Incdir)/enclave-tls/* $(Enclave_Tls_Root)/include/enclave-tls
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/crypto-wrappers
	$(INSTALL) -m 0755 $(Build_Libdir)/crypto-wrappers/libcrypto_wrapper_* \
	  $(Enclave_Tls_Libdir)/crypto-wrappers
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/tls-wrappers
	$(INSTALL) -m 0755 $(Build_Libdir)/tls-wrappers/libtls_wrapper_* \
	  $(Enclave_Tls_Libdir)/tls-wrappers
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/enclave-quotes
	$(INSTALL) -m 0755 $(Build_Libdir)/enclave-quotes/libenclave_quote_* \
	  $(Enclave_Tls_Libdir)/enclave-quotes
	make -C $(wolfssl_dir) install

uninstall:
	@rm -rf $(Enclave_Tls_Root)

Cleans += $(Build_Libdir) $(libenclave_tls_objs)
Clean_Dirs += crypto_wrappers tls_wrappers enclave_quotes external/wolfssl

mrproper:
	@make -C $(this_dir)/external/wolfssl mrproper

Extra_Phonies += install_libenclave_tls

include $(Topdir)/rules/build_rules.mk
