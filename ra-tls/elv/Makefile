TOPDIR := $(shell readlink -f ..)

DEBUG ?=
EXTRA_FLAGS ?=

CC ?= gcc
GO ?= go
PREFIX ?= $(TOPDIR)/build
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include
WOLFSSL_ROOT ?= $(shell readlink -f $(TOPDIR)/wolfssl)
SGX_RA_TLS_ROOT ?= $(shell readlink -f $(TOPDIR)/sgx-ra-tls)

ifdef ECDSA
	SGX_DCAP ?= SGXDataCenterAttestationPrimitives
	SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc
endif

all: elv

ifeq ($(SGX_DEBUG), 1)
       SGX_COMMON_CFLAGS += -O0 -g -ggdb -DSGX_DEBUG
else
       SGX_COMMON_CFLAGS += -O2
endif

Wolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DUSE_WOLFSSL
Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt
App_Include_Paths := $(Wolfssl_Include_Paths) -I$(SGX_SDK)/include -I$(SGX_RA_TLS_ROOT) -I$(INCDIR) $(SGX_DCAP_INC) -I$(shell readlink -f .)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -Wall -Wno-unused-const-variable $(App_Include_Paths) $(Wolfssl_C_Extra_Flags)

ifdef ECDSA
App_C_Flags += -DRATLS_ECDSA
endif

ifdef LA
App_C_Flags += -DLA_REPORT
endif

ra-tls-client.o: ra-tls-client.c
	@echo $(CC) $(App_C_Flags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ra-tls-client.a: ra-tls-client.o
	$(AR) rcs $@ $(filter %.o, $^)

ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif
ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
# glibc-static is required for the static linkage, if elv depends on dynamic library, need to remove '-extldflags -static'
#GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) $(GCFLAGS) $(EXTRA_FLAGS) -tags "$(BUILDTAGS) netgo osusergo" \
        -ldflags "-w -extldflags -static -X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"
GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"

ifdef LA
elv: $(LIBDIR)/liberpal-stub.a ra-tls-client.a $(LIBDIR)/libra-challenger.a $(LIBDIR)/libwolfssl.a
	$(GO_BUILD) -o $@ .
else
elv: ra-tls-client.a $(LIBDIR)/libra-challenger.a $(LIBDIR)/libwolfssl.a
	$(GO_BUILD) -o $@ .
endif

install: elv
	cp -f elv $(BINDIR)

clean:
	rm -f *.o elv ra-tls-client.a

.PHONY: clean install
