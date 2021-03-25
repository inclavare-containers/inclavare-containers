######## Intel(R) SGX SDK Settings ########
TOPDIR ?= $(shell readlink -f ../../../../../)
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_DEBUG ?= 1
SGX_ARCH ?= x64
WOLFSSL_ROOT ?= $(TOPDIR)/src/external/wolfssl
SGX_WOLFSSL_LIB ?= $(TOPDIR)/src/lib/.build/lib

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -ggdb -DSGX_DEBUG
else
        SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Wolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT
Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt \
	-I$(TOPDIR)build/include

Wolfssl_Enclave_C_Files := wolfssl_enclave.c
Wolfssl_Enclave_Include_Paths := -I. $(Wolfssl_Include_Paths) \
	-I$(SGX_SDK)/include/stlport \
	-I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(TOPDIR)/src/lib/.build/include \
	-I$(TOPDIR)/src/include \
	-I/opt/enclave-tls/include \
	-I$(TOPDIR)/src/lib/enclave_quotes/sgx

ifeq ($(HAVE_WOLFSSL_TEST), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/test
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_TEST
endif

ifeq ($(HAVE_WOLFSSL_BENCHMARK), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/benchmark
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_BENCHMARK
endif

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Wolfssl_Enclave_Include_Paths) -fno-builtin -fno-builtin-printf -I.
Wolfssl_Enclave_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags)

Wolfssl_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib \
	-nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-L$(SGX_WOLFSSL_LIB) -ltls_wrapper_wolfssl_sgx -lwolfssl.sgx.static.lib \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=wolfssl_enclave.lds

Wolfssl_Enclave_C_Objects := $(Wolfssl_Enclave_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

.PHONY: all run pre-install

ifeq ($(Build_Mode), HW_RELEASE)
all: wolfssl_enclave_u.o wolfssl_enclave.so
	@echo "Build enclave Wolfssl_Enclave.so [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the Wolfssl_Enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo
else
all: wolfssl_enclave_u.o wolfssl_enclave.signed.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Wolfssl_Enclave Objects ########

wolfssl_enclave_t.c wolfssl_enclave_t.h: $(SGX_EDGER8R) wolfssl_enclave.edl
	@$(SGX_EDGER8R) --trusted wolfssl_enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

wolfssl_enclave_t.o: wolfssl_enclave_t.c
	@$(CC) $(Wolfssl_Enclave_C_Flags) -c $< -o $@ -I$(SGX_SDK)/include
	@echo "CC   <=  $<"

#%_t.o: %_t.c
#	@echo $(CC) $(Wolfssl_Enclave_C_Flags) -c $< -o $@
#	@$(CC) $(Wolfssl_Enclave_C_Flags) -c $< -o $@
#	@echo "CC   <=  $<"

App_Include_Paths := -I$(SGX_SDK)/include -I$(shell readlink -f .) -I$(TOPDIR)/src/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -shared -Wno-attributes -Wall -Wno-unused-const-variable $(App_Include_Paths)

wolfssl_enclave_u.c wolfssl_enclave_u.h: $(SGX_EDGER8R) wolfssl_enclave.edl
	$(SGX_EDGER8R) --untrusted wolfssl_enclave.edl --search-path $(SGX_SDK)/include

wolfssl_enclave_u.o: wolfssl_enclave_u.c wolfssl_enclave_u.h
	@$(CC) $(App_C_Flags) -c $< -o $@ -I$(SGX_SDK)/include
	@echo "CC   <=  $<"

$(Wolfssl_Enclave_C_Objects): $(Wolfssl_Enclave_C_Files)
	@$(CC) $(Wolfssl_Enclave_C_Flags) -c $< -o $@ -I$(SGX_SDK)/include
	@echo "CC   <=  $<"

wolfssl_enclave.so: wolfssl_enclave_t.o $(Wolfssl_Enclave_C_Objects)
	@echo $(Wolfssl_Enclave_Link_Flags)@
	@$(CXX) $^ -o $@ $(Wolfssl_Enclave_Link_Flags)
	@echo "LINK =>  $@"

wolfssl_enclave.signed.so: wolfssl_enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key wolfssl_enclave_private.pem -enclave wolfssl_enclave.so -out $@ -config wolfssl_enclave.config.xml
	@echo "SIGN =>  $@"

pre-install: wolfssl_enclave_u.c
	@$(CC) $(App_C_Flags) -c wolfssl_enclave_u.c -o wolfssl_enclave_u.o -I./

clean:
	@rm -f *.so wolfssl_enclave_t.* wolfssl_enclave_u.* $(Wolfssl_Enclave_C_Objects)
