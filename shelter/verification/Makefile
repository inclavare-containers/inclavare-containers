TOPDIR := $(shell readlink -f .)

DEBUG ?=
EXTRA_FLAGS ?=


#CFLAGS += -std=gnu99 -I$(SGX_RA_TLS) -I$(SGX_SDK)/include -I$(INCDIR) $(SGX_DCAP_INC) -fPIC
#CFLAGSERRORS := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
#CFLAGS += $(CFLAGSERRORS) -g -O0 

CC ?= gcc
GO ?= go

all: verification.a

ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif

ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif

#App_C_Flags := $VERIFICATION/opensslevp.c

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")

# glibc-static is required for the static linkage
GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "$(EXTRA_LDFLAGS)"


opensslevp.o: opensslevp.c
	@echo $(CC)  $(CFLAGS) -c opensslevp.c -o opensslevp.o
#	$(CC)  $(CFLAGS) -c opensslevp.c -o opensslevp.o
	$(CC)  -c opensslevp.c -o opensslevp.o

%.o: %.go
	@echo $(GO_BUILD) -o $@ .
	$(GO_BUILD) -o $@ .

verification.a: opensslevp.o mrencalve.o  
	@echo $(AR) rcs $@ $^
	$(AR) rcs $@ $^

clean:
	rm -f *.o *.a

.PHONY: clean 