# samples/sgx-stub-enclave/makefile
#

Topdir ?= $(shell readlink -f ../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/wolfssl_env.mk

App_Name := sgx_stub
#Enclave_Cxxflags += $(Wolfssl_Cflags) -DSGX_ENCLAVE
Enclave_Extra_Cxxflags += $(Wolfssl_Cflags) -DSGX_ENCLAVE
#Enclave_Extra_Ldflags := -L$(Build_Libdir) -lwolfssl_sgx -lwolfssl
Enclave_Extra_Ldflags := -L$(Build_Libdir) -l:libwolfssl_sgx.a
include $(Topdir)/rules/sgx_env.mk

wolfcrypt_sgx_enclave := $(Build_Libdir)/libcrypto_wrapper_wolfcrypt_sgx.a
$(wolfcrypt_sgx_enclave): FORCE
	make -C $(Enclave_Tls_Srcdir)/crypto_wrappers/wolfcrypt-sgx $@

wolfssl_sgx_enclave := $(Build_Libdir)/libtls_wrapper_wolfssl_sgx.a
$(wolfssl_sgx_enclave): FORCE
	make -C $(Enclave_Tls_Srcdir)/tls_wrappers/wolfssl-sgx $@

sgx_ecdsa_enclave := $(Build_Libdir)/libenclave_quote_sgx_ecdsa.a
$(sgx_ecdsa_enclave): FORCE
	make -C $(Enclave_Tls_Srcdir)/enclave_quotes/sgx-ecdsa $@

Enclave_Static_Lib := $(wolfcrypt_sgx_enclave) $(wolfssl_sgx_enclave) $(sgx_ecdsa_enclave)
include $(Topdir)/rules/sgx_rules.mk

install:
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Bindir)
	$(INSTALL) -m 0755 $(App_Name)_enclave.signed.so $(Enclave_Tls_Bindir)

include $(Topdir)/rules/build_rules.mk
