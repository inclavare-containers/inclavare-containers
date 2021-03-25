# src/crypto_wrappers/nullcrypto
#

Topdir ?= $(shell readlink -f ../../..)

Enclave_Tls_Instance_Name := nullcrypto
Enclave_Tls_Instance_Type := crypto-wrapper

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/instance.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
