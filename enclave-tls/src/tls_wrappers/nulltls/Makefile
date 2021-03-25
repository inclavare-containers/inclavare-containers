# src/tls_wrappers/nulltls
#

Topdir ?= $(shell readlink -f ../../..)

Enclave_Tls_Instance_Name := nulltls
Enclave_Tls_Instance_Type := tls-wrapper

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
include $(Topdir)/rules/instance.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
