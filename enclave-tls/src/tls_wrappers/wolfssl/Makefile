# src/tls_wrappers/wolfssl/Makefile
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/wolfssl_env.mk

Enclave_Tls_Instance_Name := wolfssl
Enclave_Tls_Instance_Type := tls-wrapper
Enclave_Tls_Instance_Extra_Files := oid.c un_negotiate.c
include $(Topdir)/rules/instance.mk

include $(Topdir)/rules/wolfssl_rules.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif