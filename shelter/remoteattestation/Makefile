TOPDIR := $(shell readlink -f ../..)

DEBUG ?=
EXTRA_FLAGS ?=

SGX_SDK ?= /opt/intel/sgxsdk

ifdef ECDSA
  SGX_DCAP_URI := https://github.com/intel/SGXDataCenterAttestationPrimitives
  SGX_DCAP_COMMIT ?= 
  SGX_DCAP ?= SGXDataCenterAttestationPrimitives
  SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc -I$(SGX_DCAP)/QuoteVerification/Src/AttestationLibrary/include
endif


CFLAGS += -std=gnu99 -I$(SGX_RA_TLS_INC) -I$(SGX_SDK)/include  -fPIC
#CFLAGSERRORS := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS += -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS += -DSGX_GROUP_OUT_OF_DATE
EXTRA_FLAGS ?=

ifdef ECDSA
  CFLAGS += -DRATLS_ECDSA
endif

CC ?= gcc
GO ?= go

all: remoteattestation.a

ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif

ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif

# glibc-static is required for the static linkage
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")

GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "$(EXTRA_LDFLAGS)"


ratlsclient.o: ratlsclient.c
	@echo $(CC)  $(CFLAGS) -c ratlsclient.c -o ratlsclient.o
	$(CC) $(CFLAGS) -c ratlsclient.c -o ratlsclient.o

%.o :%.go
	@echo $(GO_BUILD) -o $@ .
	$(GO_BUILD) -o $@ . 

remoteattestation.a: ratlsclient.o securitychannel.o  
	@echo $(AR) rcs $@ $^
	$(AR) rcs $@ $^

clean:
	rm -f *.o remoteattestation.a

.PHONY: clean 

