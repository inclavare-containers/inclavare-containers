# src/tls_wrappers/openssl/Makefile
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/openssl_env.mk

Enclave_Tls_Instance_Name := openssl
Enclave_Tls_Instance_Type := tls-wrapper
Enclave_Tls_Instance_Extra_Files := un_negotiate.c
include $(Topdir)/rules/instance.mk

include $(Topdir)/rules/openssl_rules.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
