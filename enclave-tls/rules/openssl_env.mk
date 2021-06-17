# rules/openssl_env.mk
#
# The following variables are required as the inputs.
#
# - Topdir (OPTIONAL): used to distinguish the build from in-tree or out-of-tree
# - Enclave_Tls_Root (OPTIONAL): specify the location of enclave-tls source code tree
# - Sgx_Enclave (OPTIONAL): indicate whether building with SGX enclave support
# - ENCLAVE_C_FILES (REQUIRED): the C source files for enclave
# - ENCLAVE_CXX_FILES (REQUIRED): the C++ source files for enclave
# - ENCLAVE_EXTRA_INCDIR (OPTIONAL): the extra include paths for header files used by enclave
# - SGX_Debug (OPTIONAL): This is the default.
#
# In addition, the caller must prepare well the following input materials:
# - $(APP)_enclave.xml: the enclave configiration file
# - $(APP)_enclave.lds: the enclave linker script file
# - $(APP)_enclave.pem: the enclave signing key file
# - $(APP).edl: the EDL file for the definitions of ECALLs and OCALLs
#
# The resulting outputs include:

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

ifeq ($(Openssl_Root),)
  ifeq ($(Enclave_Tls_Srcdir),)
    $(error "Please define Openssl_Root first!")
  else
    Openssl_Root := $(Enclave_Tls_Srcdir)/external/openssl
  endif
endif

Openssl_Extra_Cflags ?=
Openssl_Cflags ?=
ifneq ($(Sgx_Enclave),1)
  Openssl_Cflags += -Wno-stringop-truncation
endif
Openssl_Cflags += $(CFLAGS) $(Openssl_Extra_Cflags)

Openssl_Extra_Ldflags := -lssl -lcrypto
Openssl_Ldflags := $(LDFLAGS) $(Openssl_Extra_Ldflags)
Openssl_Sgx_Ldflags := $(Enclave_Ldflags) $(Openssl_Ldflags)

ifeq ($(Sgx_Enclave),1)
  #Dependencies += $(Build_Libdir)/libopenssl_sgx.a
endif

Tls_Openssl := 1
