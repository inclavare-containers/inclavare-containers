SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INCLAVARED_VERSION := $(shell cat $(ROOTDIR)/VERSION)
INCLAVARED_MAINTAINER := $(shell head -1 $(ROOTDIR)/MAINTAINERS)

PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
include $(TOP_DIR)/buildenv.mk

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
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

SGX_COMMON_CFLAGS += -fstack-protector

######## CUSTOM Settings ########

CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin

######## EDL Settings ########

Enclave_EDL_Files := enclave/Enclave_t.c enclave/Enclave_t.h app/Enclave_u.c app/Enclave_u.h

######## APP Settings ########

App_Rust_Flags := --release
App_SRC_Files := $(shell find app/ -type f -name '*.rs') $(shell find app/ -type f -name 'Cargo.toml')
App_Include_Paths := -I ./app -I./include -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Rust_Path := ./app/target/release
App_Enclave_u_Object :=lib/libEnclave_u.a
App_Name := bin/inclavared
RUST_SDK := rust-sgx
CUSTOM_COMMON_PATH := $(RUST_SDK)/common

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard ./enclave/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./enclave -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=enclave/Enclave.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave_Name := enclave/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so

.PHONY: all
all: $(RUST_SDK) $(App_Name) $(Signed_RustEnclave_Name)

$(RUST_SDK):
	if [ ! -d "$(RUST_SDK)" ]; then \
		git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git $(RUST_SDK) && \
		cd $(RUST_SDK) && \
		git checkout 2de49915434a98d7669a1a88c2b0845349e93dcc; \
	fi

######## EDL Objects ########

$(Enclave_EDL_Files): $(RUST_SDK) $(SGX_EDGER8R) enclave/Enclave.edl
	$(SGX_EDGER8R) --trusted enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SDK)/edl --trusted-dir enclave
	$(SGX_EDGER8R) --untrusted enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SDK)/edl --untrusted-dir app
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## App Objects ########

app/Enclave_u.o: $(RUST_SDK) $(Enclave_EDL_Files)
	@$(CC) $(App_C_Flags) -I$(RUST_SDK)/edl -c app/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(App_Enclave_u_Object): app/Enclave_u.o
	$(AR) rcsD $@ $^

enclave-tls:
	$(MAKE) -C $(PROJDIR)/enclave-tls SGX=1 install

$(App_Name): enclave-tls $(RUST_SDK) $(App_Enclave_u_Object) $(App_SRC_Files)
	@cd app && SGX_SDK=$(SGX_SDK) RUSTFLAGS="-C link-args=-Wl,-rpath=/opt/enclave-tls/lib,--enable-new-dtags" cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin
	cp $(App_Rust_Path)/inclavared ./bin

######## Enclave Objects ########

enclave/Enclave_t.o: $(RUST_SDK) $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -I$(RUST_SDK)/edl -c enclave/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave enclave/Enclave_t.o
	@$(CXX) enclave/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config enclave/Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave

enclave: $(App_Name)
	$(MAKE) -C ./enclave/


.PHONY: install uninstall package clean

PREFIX := $(DESTDIR)/usr/local
BINDIR := $(PREFIX)/bin

install: $(App_Name)
	@install -D -m0755 $(App_Name) "$(BINDIR)"

uninstall:
	@rm -f $(BINDIR)/inclavared

package:
	$(MAKE) -C dist package INCLAVARED_VERSION="$(INCLAVARED_VERSION)" INCLAVARED_MAINTAINER="$(INCLAVARED_MAINTAINER)"

clean:
	@rm -f $(App_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) enclave/*_t.* app/*_u.* lib/*.a
	@cd enclave && cargo clean && rm -f Cargo.lock
	@cd app && cargo clean && rm -f Cargo.lock
	@rm -f dist/rpm/inclavared.spec dist/deb/debian/changelog
