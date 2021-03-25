# src/tls_wrappers/wolfssl/Makefile
#

Topdir ?= $(shell readlink -f ../../..)

Enclave_Tls_Instance_Name := wolfssl
Enclave_Tls_Instance_Type := tls-wrapper
Enclave_Tls_Instance_Extra_Files := oid.c un_negotiate.c

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/wolfssl_env.mk
include $(Topdir)/rules/instance.mk
include $(Topdir)/rules/wolfssl_rules.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
