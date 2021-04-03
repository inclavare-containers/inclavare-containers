# rules/sgx_env.mk
#
# The following variables are required as the inputs.
#
# - TOPDIR (OPTIONAL): used to distinguish the build from in-tree or out-of-tree
# - APP (REQUIRED): specify the output filename of untrusted application
# - APP_C_FILES (REQUIRED): the C source files for application
# - APP_CXX_FILES (REQUIRED): the C++ source files for application
# - APP_EXTRA_INCDIR (OPTIONAL): the extra include paths for header files used by application
# - ENCLAVE_C_FILES (REQUIRED): the C source files for enclave
# - ENCLAVE_CXX_FILES (REQUIRED): the C++ source files for enclave
# - ENCLAVE_EXTRA_INCDIR (OPTIONAL): the extra include paths for header files used by enclave
# - SGX_DEBUG (OPTIONAL): This is the default.
# - SGX_PRERELEASE (OPTIONAL):
# - SGX_MODE (OPTIONAL):
# - SGX_ARCH (OPTIONAL):
#
# In addition, the caller must prepare well the following input materials:
# - $(APP)_enclave.xml: the enclave configiration file
# - $(APP)_enclave.lds: the enclave linker script file
# - $(APP)_enclave.pem: the enclave signing key file
# - $(APP).edl: the EDL file for the definitions of ECALLs and OCALLs
#
# The resulting outputs include:
# - $(APP): the output application binary
# - $(APP)_enclave.so: the output unsigned enclave image
# - $(APP)_enclave.signed.so: the output signed enclave image

ifneq ($(__Build_Env_Imported),1)
  $(error "Please import build_env.mk first!")
endif

# Decide whether to compile the complete untrusted application plus enclave image
# or just the trusted static library.
ifeq ($(App_Name),)
  ifeq ($(Enclave_Tls_Instance_Name),)
    $(error "Invalid settings for building SGX stuffs!")
  else
    App_Name := $(subst -,_,$(Enclave_Tls_Instance_Name))
  endif

  no_app := 1
endif

enclave_name = $(App_Name)_enclave
enclave_config_file = $(enclave_name).xml
enclave_linker_script = $(enclave_name).lds
enclave_signing_key = $(enclave_name).pem
#enclave_static_lib = $(enclave_name).a
app_edl = $(App_Name).edl

SGX_DEBUG ?= $(DEBUG)
SGX_PRERELEASE ?=

ifeq ($(SGX_DEBUG), 1)
  ifeq ($(SGX_PRERELEASE), 1)
    $(error "Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!")
  endif
endif

SGX_SDK ?= /opt/intel/sgxsdk

SGX_MODE ?= HW
ifeq ($(SGX_MODE), HW)
  urts_lib := sgx_urts
  trts_lib:= sgx_trts
  service_lib:= sgx_tservice
else
  urts_lib:= sgx_urts_sim
  trts_lib:= sgx_trts_sim
  service_lib:= sgx_tservice_sim
endif
crypto_lib := sgx_tcrypto

ifeq ($(SGX_MODE), HW)
  ifeq ($(SGX_DEBUG), 1)
    build_mode = HW_DEBUG
  else ifeq ($(SGX_PRERELEASE), 1)
    build_mode = HW_PRERELEASE
  else
    build_mode = HW_RELEASE
  endif
else
  ifeq ($(SGX_DEBUG), 1)
    build_Mode = SIM_DEBUG
  else ifeq ($(SGX_PRERELEASE), 1)
    build_mode = SIM_PRERELEASE
  else
    build_mode = SIM_RELEASE
  endif
endif

SGX_ARCH ?= x64
ifeq ($(shell getconf LONG_BIT), 32)
  SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
  SGX_ARCH := x86
endif

# sgx_common_flags defines the common flags for both enclave and application.
# sgx_libdir defines SGX related library directory for both enclave and application.
ifeq ($(SGX_ARCH), x86)
  sgx_common_flags := -m32
  sgx_common_libdir := $(SGX_SDK)/lib
else
  sgx_common_flags := -m64
  sgx_common_libdir := $(SGX_SDK)/lib64
endif
ifeq ($(SGX_DEBUG), 1)
  sgx_common_flags += -O0 -g
else
  sgx_common_flags += -O2
endif
sgx_common_flags += \
  -DSGX_ENCLAVE -I$(SGX_SDK)/include \
  -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
  -Waddress -Wsequence-point -Wformat-security \
  -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
  -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
  #-Wwrite-strings -Wlogical-op
# Add any possible header files, e.g, wolfssl, enclave-tls and so on.
sgx_common_flags += $(addprefix -I,$(Build_Incdir) $(Enclave_Tls_Incdir))
# Define the CFLAGS for both enclave and application
sgx_common_cflags := \
  $(sgx_common_flags) \
  -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants \
  -std=gnu11
# Define the CXXFLAGS for both enclave and application
sgx_common_cxxflags := \
  $(sgx_common_flags) \
  -Wnon-virtual-dtor -std=c++11

# The objects of instance requre the header files from Intel SGX SDK
#Enclave_Tls_Incdir += $(SGX_SDK)/include

# Define the common flags for application
app_common_flags := \
  -fPIC -Wno-attributes
# Three configuration modes - Debug, prerelease, release
# - Debug: Macro DEBUG enabled
# - Prerelease: Macro NDEBUG and EDEBUG enabled
# - Release: Macro NDEBUG enabled
ifeq ($(SGX_DEBUG), 1)
  app_common_flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
  app_common_flags += -DNDEBUG -DEDEBUG -UDEBUG
else
  app_common_flags += -DNDEBUG -UEDEBUG -UDEBUG
endif
# Define the CFLAGS for application
App_Cflags := $(CFLAGS) $(sgx_common_cflags) $(app_common_flags) $(App_Extra_Cflags)
# Define the CXXFLAGS for application
App_Cxxflags := $(CXXFLAGS) $(sgx_common_cxxflags) $(app_common_flags) $(App_Extra_Cxxflags)
# Define the LDFLAGS for application
App_Ldflags := $(LDFLAGS) -L$(sgx_common_libdir) -l$(urts_lib) -lpthread $(App_Extra_Ldflags)

# Define the common flags for enclave
enclave_common_flags := \
  $(addprefix -I,$(SGX_SDK)/include/tlibc $(SGX_SDK)/include/libcxx) \
  -nostdinc -ffreestanding -fvisibility=hidden -fpie -ffunction-sections -fdata-sections
  #$(MITIGATION_CFLAGS)
is_gcc_less_than_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(is_gcc_less_than_4_9), 1)
  enclave_common_flags += -fstack-protector
else
  enclave_common_flags += -fstack-protector-strong
endif
# Define the CFLAGS for enclave
Enclave_Cflags := \
  $(CFLAGS) $(sgx_common_cflags) $(enclave_common_flags) $(Enclave_Extra_Cflags)
# Define the CXXFLAGS for enclave
Enclave_Cxxflags := \
  $(CXXFLAGS) -nostdinc++ -std=c++11 $(sgx_common_cxxflags) $(enclave_common_flags) $(Enclave_Extra_Cxxflags)

# Define the LDFLAGS for enclave

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
# 1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#    so that the whole content of trts is included in the enclave.
# 2. For other libraries, you just need to pull the required symbols.
#    Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Ldflags := \
  $(LDFLAGS) \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(sgx_common_libdir) \
  $(Enclave_Extra_Ldflags) \
  -Wl,--whole-archive -l$(trts_lib) -Wl,--no-whole-archive \
  -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(crypto_lib) -l$(service_lib) -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
  -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
  -Wl,--version-script=$(enclave_linker_script)
  #$(MITIGATION_LDFLAGS)

Sgx_Enclave := 1
__Sgx_Env_Imported := 1
