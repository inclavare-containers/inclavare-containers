# src/tls_wrappers/nulltls
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif

Enclave_Tls_Instance_Name := nulltls
Enclave_Tls_Instance_Type := tls-wrapper
include $(Topdir)/rules/instance.mk

ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif