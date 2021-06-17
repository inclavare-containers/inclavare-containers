# rules/openssl_rule.mk

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifeq ($(Openssl_Root),)
  $(error "Please define Openssl_Root first!")
else
  Openssl_Root := $(Enclave_Tls_Srcdir)/external/openssl
endif
