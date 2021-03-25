# src/tls_wrappers/wolfssl-sgx/Makefile
#

Topdir ?= $(shell readlink -f ../../..)

Enclave_Tls_Instance_Name := wolfssl-sgx
Enclave_Tls_Instance_Type := tls-wrapper
Enclave_C_Files := ecalls.c
Enclave_Static_Lib_Name := wolfssl_sgx

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
CFLAGS += -I$(Topdir)/samples/sgx-stub-enclave

include $(Topdir)/rules/sgx_env.mk
include $(Topdir)/rules/wolfssl_env.mk

Enclave_Tls_Instance_Extra_Files := ocalls.c ../../enclave_quotes/ecdsa/ocall.c
Enclave_Tls_Extra_Ldflags :=  -L/opt/intel/sgxsgk/lib64 -lsgx_uae_service -lsgx_urts -lsgx_dcap_ql -lsgx_dcap_quoteverify

include $(Topdir)/rules/instance.mk
include $(Topdir)/rules/wolfssl_rules.mk
include $(Topdir)/rules/sgx_rules.mk
ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
