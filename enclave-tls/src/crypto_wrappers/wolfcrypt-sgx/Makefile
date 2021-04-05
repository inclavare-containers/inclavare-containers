# src/crypto_wrappers/wolfcrypt-sgx/Makefile
#
# [IN,OPTIONAL] Topdir: specify the location of enclave-tls source code tree

Topdir ?= $(shell readlink -f ../../..)

ifneq ($(__Build_Env_Imported),1)
  include $(Topdir)/rules/build_env.mk
endif
CFLAGS += -I$(Topdir)/samples/sgx-stub-enclave

Enclave_Tls_Instance_Name := wolfcrypt-sgx
include $(Topdir)/rules/sgx_env.mk

include $(Topdir)/rules/wolfssl_env.mk

Enclave_Tls_Instance_Type := crypto-wrapper
Enclave_Tls_Instance_Extra_Files := \
  ../../enclave_quotes/sgx-ecdsa/ocall.c \
  ../../tls_wrappers/wolfssl-sgx/ocalls.c
Enclave_Tls_Extra_Ldflags := \
  -L/opt/intel/sgxsgk/lib64 -lsgx_uae_service -lsgx_urts \
  -lsgx_dcap_ql -lsgx_dcap_quoteverify
include $(Topdir)/rules/instance.mk

include $(Topdir)/rules/wolfssl_rules.mk

Enclave_C_Files := ecalls.c
Enclave_Static_Lib_Name := wolfcrypt_sgx
include $(Topdir)/rules/sgx_rules.mk

ifneq ($(__Build_Rules_Imported),1)
  include $(Topdir)/rules/build_rules.mk
endif
