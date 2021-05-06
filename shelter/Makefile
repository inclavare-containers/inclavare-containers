CURRENTDIR := $(shell readlink -f .)
TOPDIR := $(shell readlink -f ..)
SGX_SDK ?= /opt/intel/sgxsdk
SGX_DCAP_INC ?=
INCDIR ?=
DEBUG ?= 0
EXTRA_FLAGS ?=
APP := shelter

#ifdef DEBUG 	
#	@echo $CURRENTDIR
#	@echo $TOPDIR
#	@echo $SGX_SDK
#endif
	
CFLAGS += -std=gnu99 -I$(SGX_SDK)/include -I$(INCDIR) $(SGX_DCAP_INC) -fPIC
#CFLAGSERRORS := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS += $(CFLAGSERRORS) -g -O0 

CC ?= gcc
GO ?= go

all: shelter

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
  -ldflags "$(EXTRA_LDFLAGS)"

# FIXME: Ideally, these two libraries can be built in parallel, but
# it doesn't work. Hence, the dependency forces a serial build.
shelter: enclave-tls $(CURRENTDIR)/verification/verification.a  $(CURRENTDIR)/utils/utils.a $(CURRENTDIR)/remoteattestation/remoteattestation.a $(CURRENTDIR)/racommand.o $(CURRENTDIR)/mrenclaveverifycomand.o $(CURRENTDIR)/main.o
	$(GO_BUILD) -o $@ .

enclave-tls:
	$(MAKE) -C $(TOPDIR)/enclave-tls install

$(CURRENTDIR)/utils/utils.a:
	$(MAKE) -C utils
	
$(CURRENTDIR)/racommand.o: racommand.go
	$(GO_BUILD) -o $@ .

$(CURRENTDIR)/mrenclaveverifycomand.o: mrenclaveverifycomand.go
	$(GO_BUILD) -o $@ .	

$(CURRENTDIR)/main.o: main.go
	$(GO_BUILD) -o $@ .	

$(CURRENTDIR)/verification/verification.a:
	$(MAKE) -C verification

$(CURRENTDIR)/remoteattestation/remoteattestation.a: 
	$(MAKE) -C remoteattestation

PREFIX := $(DESTDIR)/usr/local
BINDIR := $(PREFIX)/bin
install:$(APP)
	@install -D -m0755 $(APP) "$(BINDIR)"

uninstall:
	@rm -f $(BINDIR)/$(APP)

package:
	$(MAKE) -C dist package

clean:
	rm -f *.o shelter
	$(MAKE) -C verification clean
	$(MAKE) -C remoteattestation clean
	$(MAKE) -C utils clean

.PHONY: clean install uninstall package
