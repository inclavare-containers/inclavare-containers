# rules/build_env.mk
#
# The following variables are required as the inputs.
#
# - Topdir (OPTIONAL): used to distinguish the build from in-tree or out-of-tree
#
# Overridable and export variables:
# - DEBUG (OPTIONAL): indicate whether enabling debug build
# - CC (OPTIONAL): specify the C compiler
# - CXX (OPTIONAL): specify the C++ compiler
# - GO (OPTIONAL): specify the Golang compiler
# - INSTALL (OPTIONAL): specify the install program
# - Enclave_Tls_Root: the location of enclave-tls source code tree
# - Enclave_Tls_Root (OPTIONAL): specify the location of enclave-tls source code tree
# - ENCLAVE_C_FILES (REQUIRED): the C source files for enclave
# - ENCLAVE_CXX_FILES (REQUIRED): the C++ source files for enclave
# - ENCLAVE_EXTRA_INCDIR (OPTIONAL): the extra include paths for header files used by enclave
# - SGX_DEBUG (OPTIONAL): This is the default.
#
# In addition, the caller must prepare well the following input materials:
# - $(APP)_enclave.xml: the enclave configiration file
# - $(APP)_enclave.lds: the enclave linker script file
# - $(APP)_enclave.pem: the enclave signing key file
# - $(APP).edl: the EDL file for the definitions of ECALLs and OCALLs
#

ifeq ($(__Build_Env_Imported),1)
  $(error "Please don't import build_env.mk again!")
endif

Enclave_Tls_Root ?= /opt/enclave-tls
Enclave_Tls_Libdir := $(Enclave_Tls_Root)/lib
Enclave_Tls_Lib := $(Enclave_Tls_Libdir)/libenclave_tls.so

# Determine the caller is from in-tree or out-of-tree
ifeq ($(Topdir),)
  # out-of-tree
  is_valid_lib := $(shell [ -L $(Enclave_Tls_Lib) ] && echo 1)
  ifeq ($(is_valid_lib),)
    $(error "Please install enclave-tls SDK, or set Topdir used to specify the location of enclave-tls source code tree!")
  endif

  version := $(shell readlink -f $(Enclave_Tls_Lib) | cut  -d '.' -f3-)
  Enclave_Tls_Srcdir :=
  Topdir := $(shell pwd)
else
  # in-tree
  Enclave_Tls_Srcdir := $(Topdir)/src
  is_valid_src := $(shell [ -f $(Enclave_Tls_Srcdir)/api/enclave_tls_init.c ] && echo 1)
  ifeq ($(is_valid_src),)
    $(error "Please set Topdir correctly, or install enclave-tls SDK!")
  endif

  version := $(shell cat $(Topdir)/VERSION)
endif

Major_Version := $(shell echo $(version) | cut -d '.' -f1)
Minor_Version := $(shell echo $(version) | cut -d '.' -f2)
Patch_Version := $(shell echo $(version) | cut -d '.' -f3)

Debug ?=

CC ?= gcc
CXX ?= g++
LD ?= ld
AR ?= ar
INSTALL ?= install

Build_Dir ?= $(Topdir)/build
Build_Bindir := $(Build_Dir)/bin
Build_Libdir := $(Build_Dir)/lib

Enclave_Tls_Bindir ?= /usr/share/enclave-tls/samples
ifneq ($(Enclave_Tls_Srcdir),)
  # in-tree
  Enclave_Tls_Incdir := $(Enclave_Tls_Srcdir)/include
else
  # out-of-tree
  Enclave_Tls_Incdir := $(Enclave_Tls_Root)/include
endif

CFLAGS ?= -std=gnu11 -fPIC
CXXFLAGS ?= -std=c++11 -fPIC
ifdef OCCLUM
  CFLAGS += -DOCCLUM
  CXXFLAGS += -DOCCLUM
else ifdef SGX
  CFLAGS += -DSGX
  CXXFLAGS += -DSGX
endif
ifeq ($(DEBUG),1)
  CFLAGS += -ggdb -O0
  CXXFLAGS += -ggdb -O0
else
  CFLAGS += -O2
  CXXFLAGS += -O2
endif
Enclave_Tls_Cflags := $(CFLAGS) -I$(Enclave_Tls_Incdir)

LDFLAGS ?=
Enclave_Tls_Ldflags := \
  $(LDFLAGS) -shared -Bsymbolic -rpath=$(Enclave_Tls_Libdir) --enable-new-dtags

Extra_Phonies ?=

# Indicate build_env.mk is already explicitly imported by the caller
__Build_Env_Imported := 1

export Debug CC CXX INSTALL \
  Major_Version Minor_Version Patch_Version \
  Build_Dir Build_Bindir Build_Libdir \
  Enclave_Tls_Root Enclave_Tls_Srcdir Enclave_Tls_Bindir Enclave_Tls_Libdir \
  Enclave_Tls_Incdir Enclave_Tls_Lib \
  CFLAGS CXXFLAGS LDFLAGS Enclave_Tls_Ldflags

.DEFAULT_GOAL := all
