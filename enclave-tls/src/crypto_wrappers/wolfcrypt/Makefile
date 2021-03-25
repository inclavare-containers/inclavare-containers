# src/crypto_wrappers/wolfcrypt/Makefile
#

Topdir ?= $(shell readlink -f ../../..)

Enclave_Tls_Instance_Name := wolfcrypt
Enclave_Tls_Instance_Type := crypto-wrapper

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/wolfssl_env.mk
include $(Topdir)/rules/instance.mk
include $(Topdir)/rules/wolfssl_rules.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
