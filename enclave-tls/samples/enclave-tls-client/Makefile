TOPDIR ?= ../..

include $(TOPDIR)/common.mk

DEBUG ?=

CFLAGS += -std=gnu99 -fPIC
CFLAGS += -g -O0

all: elv

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

elv: ra-tls-client.c
	$(GO_BUILD) -o $@ .

install: elv
	$(INSTALL) -d -m 755 $(BINDIR)
	$(INSTALL) -m 755 elv $(BINDIR)

clean:
	rm -f *.o elv

.PHONY: clean install
