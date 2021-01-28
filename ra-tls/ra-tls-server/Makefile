TOPDIR := $(shell readlink -f ..)

DEBUG ?=
EXTRA_FLAGS ?=

PREFIX ?= $(TOPDIR)/build
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include

SGX_SDK ?= /opt/intel/sgxsdk
SGX_RA_TLS := $(TOPDIR)/sgx-ra-tls

ifdef ECDSA
  SGX_DCAP ?= SGXDataCenterAttestationPrimitives
  SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc \
		  -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc \
		  -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/ql/inc \
		  -I../build/include/ -I/usr/x86_64-linux-gnu/include \
		  -I$(SGX_DCAP)/QuoteVerification/QVL/Src/AttestationLibrary/include \
		  -I/usr/include/x86_64-linux-gnu
endif

CFLAGS += -std=gnu99 -I$(SGX_RA_TLS) -I$(SGX_SDK)/include -I$(INCDIR) $(SGX_DCAP_INC) -fPIC
CFLAGS += $(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS += -DSGX_GROUP_OUT_OF_DATE
ifdef ECDSA
  CFLAGS += -DRATLS_ECDSA
endif

CC ?= gcc
GO ?= go

all: ra-tls-server 

ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif
ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
# glibc-static is required for the static linkage
GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"

ra-tls-server: lib/libra-tls-server.a
	$(GO_BUILD) -o $@ .

lib/libra-tls-server.a:
	make -C lib 

install: ra-tls-server
	cp -f inclavared $(BINDIR)

clean:
	rm -f *.o ra-tls-server
	$(MAKE) -C lib clean

.PHONY: clean install
