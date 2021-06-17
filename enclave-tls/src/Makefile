# src/Makefile
#

Topdir ?= $(shell readlink -f ..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

ifdef SGX
  include $(Topdir)/rules/wolfssl_env.mk
  Enclave_Tls_Cflags += \
    $(Wolfssl_Cflags) -DWOLFSSL_SGX_WRAPPER \
    -I$(Topdir)/samples/sgx-stub-enclave \
    -I/opt/intel/sgxsdk/include \
    -I$(Topdir)/build/include
  Enclave_Tls_Extra_Ldflags := \
    -L/opt/intel/sgxsgk/lib64 -lsgx_uae_service -lsgx_urts \
    -lsgx_dcap_ql -lsgx_dcap_quoteverify \
    -L$(Topdir)/build/lib -lwolfssl
endif

libenclave_tls := $(notdir $(Enclave_Tls_Lib))
crypto_wrappers := $(addsuffix .so,$(addprefix libcrypto_wrapper_,nullcrypto wolfcrypt))
tls_wrappers := $(addsuffix .so,$(addprefix libtls_wrapper_,nulltls wolfssl openssl))
attesters := $(addsuffix .so,$(addprefix libattester_,nullattester))
verifiers := $(addsuffix .so,$(addprefix libverifier_,nullverifier))

ifdef OCCLUM
  Enclave_Tls_Cflags += -DOCCLUM
  attesters += $(addsuffix .so,$(addprefix libattester_,sgx-ecdsa))
  verifiers += $(addsuffix .so,$(addprefix libverifier_,sgx-ecdsa))
endif

ifdef SGX
  crypto_wrappers += $(addsuffix .so,$(addprefix libcrypto_wrapper_,wolfcrypt-sgx))
  tls_wrappers += $(addsuffix .so,$(addprefix libtls_wrapper_,wolfssl-sgx))
  attesters += $(addsuffix .so,$(addprefix libattester_,sgx-ecdsa sgx-la))
  verifiers += $(addsuffix .so,$(addprefix libverifier_,sgx-ecdsa sgx-ecdsa-qve sgx-la))
endif

all: $(addprefix $(Build_Libdir)/,$(libenclave_tls) $(crypto_wrappers) $(tls_wrappers) $(attesters) $(verifiers))

this_dir := $(shell pwd)
libenclave_tls_files := \
  $(wildcard \
    $(this_dir)/core/*.c $(this_dir)/api/*.c \
    $(this_dir)/crypto_wrappers/internal/*.c $(this_dir)/crypto_wrappers/api/*.c \
    $(this_dir)/tls_wrappers/internal/*.c $(this_dir)/tls_wrappers/api/*.c \
    $(this_dir)/attesters/internal/*.c $(this_dir)/attesters/api/*.c \
    $(this_dir)/verifiers/internal/*.c $(this_dir)/verifiers/api/*.c \
    $(this_dir)/util/*.c \
  )

ocall_files := \
  $(this_dir)/sgx/ocalls.c \
  $(this_dir)/tls_wrappers/wolfssl-sgx/ocalls.c \
  $(this_dir)/attesters/sgx-ecdsa/ocalls.c \
  $(this_dir)/verifiers/sgx-ecdsa/ocalls.c \
  $(this_dir)/verifiers/sgx-ecdsa-qve/ocalls.c
ocall_objs := $(patsubst %c,%o,$(ocall_files))
ifdef SGX
  libenclave_tls_files += $(ocall_files)
  Build_Dependencies += $(Build_Libdir)/libwolfssl.so 
  include $(Topdir)/rules/wolfssl_env.mk
endif

$(Build_Libdir)/libwolfssl.so $(Build_Libdir)/libwolfssl_sgx.a:
	make -C $(Wolfssl_Root) $@

libenclave_tls_objs := $(libenclave_tls_files:.c=.o)
$(Build_Libdir)/$(libenclave_tls): $(Build_Dependencies) $(libenclave_tls_objs)
	@$(INSTALL) -d -m 0755 $(dir $@)
	$(LD) $(Enclave_Tls_Ldflags) -soname=$(notdir $@).$(Major_Version) -o $@ $(libenclave_tls_objs) -ldl $(Enclave_Tls_Extra_Ldflags)

$(libenclave_tls_objs): %.o: %.c
	$(CC) -c $(Enclave_Tls_Cflags) -o $@ $<

$(addprefix $(Build_Libdir)/,$(crypto_wrappers) $(tls_wrappers)):
	@n=$(patsubst lib%.so,%,$(notdir $@)); \
	dir=`echo $$n | cut -d '_' -f1-2`; \
	name=$${n#$${dir}_}; \
	make -C $(this_dir)/$${dir}s/$$name

$(addprefix $(Build_Libdir)/,$(attesters) $(verifiers)):
	@n=$(patsubst lib%.so,%,$(notdir $@)); \
	dir=`echo $$n | cut -d '_' -f1`; \
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
	$(INSTALL) -m 0444 $(Enclave_Tls_Incdir)/enclave-tls/* $(Enclave_Tls_Root)/include/enclave-tls
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/crypto-wrappers
	$(INSTALL) -m 0755 $(Build_Libdir)/crypto-wrappers/libcrypto_wrapper_* \
	  $(Enclave_Tls_Libdir)/crypto-wrappers
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/tls-wrappers
	$(INSTALL) -m 0755 $(Build_Libdir)/tls-wrappers/libtls_wrapper_* \
	  $(Enclave_Tls_Libdir)/tls-wrappers
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/attesters
	$(INSTALL) -m 0755 $(Build_Libdir)/attesters/libattester_* \
	  $(Enclave_Tls_Libdir)/attesters
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Libdir)/verifiers
	$(INSTALL) -m 0755 $(Build_Libdir)/verifiers/libverifier_* \
	  $(Enclave_Tls_Libdir)/verifiers
	make -C $(wolfssl_dir) install

uninstall:
	@rm -rf $(Enclave_Tls_Root)

Cleans += $(Build_Libdir) $(libenclave_tls_objs) $(ocall_objs) 
Clean_Dirs += crypto_wrappers tls_wrappers attesters verifiers external/wolfssl

mrproper:
	@make -C $(this_dir)/external/wolfssl mrproper

Extra_Phonies += install_libenclave_tls

include $(Topdir)/rules/build_rules.mk
