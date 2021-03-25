Topdir ?= $(shell readlink -f ../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

App_Name := sgx_stub
enclave_name := $(App_Name)

wolfssl_sgx_enclave := $(Build_Libdir)/libtls_wrapper_wolfssl_sgx.a
ecdsa_sgx_quote := $(Build_Libdir)/libenclave_quote_sgx_ecdsa.a

Enclave_Static_Lib := $(ecdsa_sgx_quote) $(wolfssl_sgx_enclave)

include $(Topdir)/rules/wolfssl_env.mk

Enclave_Extra_Ldflags := -L$(Build_Libdir) -lwolfssl_sgx -lwolfssl
include $(Topdir)/rules/sgx_env.mk

Enclave_Cxxflags += $(Wolfssl_Cflags) -DSGX_ENCLAVE
$(wolfssl_sgx_enclave): FORCE
	make -C $(Enclave_Tls_Srcdir)/tls_wrappers/wolfssl-sgx $(wolfssl_sgx_enclave)

$(ecdsa_sgx_quote): FORCE
	make -C $(Enclave_Tls_Srcdir)/enclave_quotes/ecdsa $(ecdsa_sgx_quote)

include $(Topdir)/rules/sgx_rules.mk

include $(Topdir)/rules/build_rules.mk

install:
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Bindir)
	$(INSTALL) -m 0755 $(App_Name)_enclave.signed.so $(Enclave_Tls_Bindir)
