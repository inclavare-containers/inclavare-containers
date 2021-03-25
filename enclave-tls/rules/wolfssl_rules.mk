# rules/wolfssl_rule.mk
#
# This file should be gone becasuse libwolfssl* stuffs can be
# available through the installation of enclave-tls SDK.

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifeq ($(Wolfssl_Root),)
  $(error "Please define Wolfssl_Root first!")
else
  Wolfssl_Root := $(Enclave_Tls_Srcdir)/external/wolfssl
endif

$(Build_Libdir)/libwolfssl.so $(Build_Libdir)/libwolfssl_sgx.a:
	make -C $(Wolfssl_Root) $@
