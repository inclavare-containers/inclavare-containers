# src/Makefile
#

Topdir ?= $(shell readlink -f ..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

libenclave_tls := $(notdir $(Enclave_Tls_Lib))
crypto_wrappers := $(addsuffix .so,$(addprefix libcrypto_wrapper_,nullcrypto wolfcrypt))
tls_wrappers := $(addsuffix .so,$(addprefix libtls_wrapper_,nulltls wolfssl wolfssl-sgx))
enclave_quotes := $(addsuffix .so,$(addprefix libenclave_quote_,nullquote ecdsa))
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



LIBDIR := $(TOPDIR)/src/lib
TLS_WRAPPERS := $(LIBDIR)/tls_wrappers
ENCLAVE_QUOTES := $(LIBDIR)/enclave_quotes
CRYPTO_WRAPPERS := $(LIBDIR)/crypto_wrappers
INCDIR := $(TOPDIR)/src/include
#COMMONDIR := $(TOPDIR)/src/external
WOLFSSL_ENCLAVE_DIR := $(TLS_WRAPPERS)/wolfssl-sgx/wolfssl-enclave

NULL_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/null/*.c)
WOLFSSL_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl/*.c)
WOLFSSL_SGX_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl-sgx/*.c) \
	$(filter-out main.c, $(wildcard $(TLS_WRAPPERS)/wolfssl/*.c))

NULL_ENCLAVE_QUOTE_C_FILES := $(wildcard $(ENCLAVE_QUOTES)/null/*.c)

WOLFCRYPT_WRAPPER_C_FILES := $(wildcard $(CRYPTO_WRAPPERS)/wolfcrypt/*.c)

WOLFSSL_SGX_ENCLAVE_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl-sgx/wolfssl-enclave/*.c)


NULL_TLS_WRAPPER_C_Objects := $(NULL_TLS_WRAPPER_C_FILES:.c=.o)
WOLFSSL_TLS_WRAPPER_C_Objects := $(WOLFSSL_TLS_WRAPPER_C_FILES:.c=.o)
WOLFSSL_SGX_TLS_WRAPPER_C_Objects := $(WOLFSSL_SGX_TLS_WRAPPER_C_FILES:.c=.o)
NULL_ENCLAVE_QUOTE_C_Objects := $(NULL_ENCLAVE_QUOTE_C_FILES:.c=.o)
WOLFCRYPT_WRAPPER_C_Objects := $(WOLFCRYPT_WRAPPER_C_FILES:.c=.o)
WOLFSSL_SGX_ENCLAVE_WRAPPER_C_Objects := $(WOLFSSL_SGX_ENCLAVE_WRAPPER_C_FILES:.c=.o)

#$(Build_Libdir)/libtls_wrapper_wolfssl.so: CFLAGS += $(WOLFSSL_CFLAGS)

#$(Build_Libdir)/libtls_wrapper_wolfssl_sgx.so: $(WOLFSSL_SGX_TLS_WRAPPER_C_Objects) $(objs) $(Build_Libdir)/libenclave_tls.so $(Enclave_Tls_Libdir)/libwolfssl.so
#	$(CC) $(HOST_LDFLAGS) -Wl,-soname=libtls_wrapper_wolfssl_sgx.so.$(Major_Version) -o $@ $^ -lsgx_urts

#$(Build_Libdir)/libcrypto_wrapper_wolfcrypt.so: CFLAGS += $(WOLFSSL_CFLAGS)
#	$(CC) $(HOST_LDFLAGS) -Wl,-soname=libcrypto_wrapper_wolfcrypt.so.$(Major_Version) -o $@ $^

$(WOLFSSL_SGX_TLS_WRAPPER_C_Objects) $(WOLFCRYPT_WRAPPER_C_Objects): %.o: %.c
	$(CC) -c $(CFLAGS) -I$(BUILD_INCDIR) -o $@ $< -I$(SGX_SDK)/include


libtls_wrapper_wolfssl_sgx.a:
	make -C $(TLS_WRAPPERS)/wolfssl-sgx

wolfssl_enclave.signed.so: libtls_wrapper_wolfssl_sgx.a
	make -C $(WOLFSSL_ENCLAVE_DIR)

$(WOLFSSL_ENCLAVE_DIR)/wolfssl_enclave_u.o:
	make -C $(WOLFSSL_ENCLAVE_DIR) pre-install

$(Enclave_Tls_Libdir)/libwolfssl.so:
	make -C $(COMMONDIR) && make -C $(COMMONDIR) install

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

define clean_src
  for d in crypto_wrappers tls_wrappers enclave_quotes external/wolfssl; do \
    make -C $(this_dir)/$$d clean; \
  done
endef

Clean_Cmds += clean_src

clean:
	@rm -rf $(Build_Libdir) $(libenclave_tls_objs)
	for d in crypto_wrappers tls_wrappers enclave_quotes external/wolfssl; do \
	  make -C $(this_dir)/$$d clean; \
	done

mrproper:
	@make -C $(this_dir)/external/wolfssl mrproper

Extra_Phonies += install_libenclave_tls

#include $(Topdir)/rules/build_rules.mk
