# rules/wolfssl_env.mk
#
# The following variables are required as the inputs.
#
# - Topdir (OPTIONAL): used to distinguish the build from in-tree or out-of-tree
# - Wolfssl_Root (REQUIRED): specify the location of wolfssl source code tree
# - Enclave_Tls_Root (OPTIONAL): specify the location of enclave-tls source code tree
# - Sgx_Enclave (OPTIONAL): indicate whether building with SGX enclave support
# - Wolfssl_Extra_Cflags (OPTIONAL): the extra CFLAGS used to build wolfssl
# - Wolfssl_Extra_Cflags (OPTIONAL): the extra paths for header files used by application
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

ifeq ($(Wolfssl_Root),)
  ifeq ($(Enclave_Tls_Srcdir),)
    $(error "Please define Wolfssl_Root first!")
  else
    Wolfssl_Root := $(Enclave_Tls_Srcdir)/external/wolfssl
  endif
endif

Wolfssl_Extra_Cflags ?=
# Add --enable-debug to ./configure for debug build
# WOLFSSL_ALWAYS_VERIFY_CB: Always call certificate verification callback, even if verification succeeds
# KEEP_OUR_CERT: Keep the certificate around after the handshake
# --enable-tlsv10: required by libcurl
Wolfssl_Cflags := \
  -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT -Wno-stringop-truncation \
  -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN \
  -DWOLFSSL_CERT_EXT -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT \
  -DWOLFSSL_TEST_CERT -DWOLFSSL_SMALL_CERT_VERIFY
Wolfssl_Sgx_Cflags := \
  $(App_Cflags) $(Wolfssl_Cflags) -DUSER_TIME -DWOLFSSL_SGX -DFP_MAX_BITS=8192
  #$(App_Cflags) $(Wolfssl_Cflags) -DWOLFSSL_SGX -DUSER_TIME -DFP_MAX_BITS=8192
ifneq ($(Sgx_Enclave),1)
  Wolfssl_Cflags += -Wno-stringop-truncation
endif
Wolfssl_Cflags += $(CFLAGS) $(Wolfssl_Extra_Cflags)

Wolfssl_Extra_Ldflags ?=
Wolfssl_Ldflags := $(LDFLAGS) $(Wolfssl_Extra_Ldflags)
Wolfssl_Sgx_Ldflags := $(Enclave_Ldflags) $(Wolfssl_Ldflags)

Dependencies += $(Build_Libdir)/libwolfssl.so
ifeq ($(Sgx_Enclave),1)
  Dependencies += $(Build_Libdir)/libwolfssl_sgx.a
endif

Tls_Wolfssl := 1
