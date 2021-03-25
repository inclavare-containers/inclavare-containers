Topdir ?= $(shell readlink -f ../..)

include $(Topdir)/rules/build_env.mk

Targets := $(Build_Bindir)/enclave-tls-client

ifneq ($(GO111MODULE), off)
  mod_vendor := "-mod=vendor"
endif

cflags ?= $(CFLAGS)
ifeq ($(Debug), 1)
  gcflags = -gcflags "-N -l"
endif

commit_no := $(shell git rev-parse HEAD 2> /dev/null || true)
commit ?= $(if $(shell git status --porcelain --untracked-files=no),"$(commit_no)-dirty","$(commit_no)")

EXTRA_GO_FLAGS ?=
EXTRA_GO_LDFLAGS ?=
# glibc-static is required for the static linkage
go_build := \
  CGO_ENABLED=1 $(GO) build $(mod_vendor) -buildmode=pie $(gcflags) $(EXTRA_GO_FLAGS) \
  -ldflags "-X main.gitCommit=$(commit) -X main.version=$(VERSION) $(EXTRA_GO_LDFLAGS)"

Dependencies += $(Build_Libdir)/libenclave_tls.so

$(Targets): ra-tls-client.c $(Build_Libdir)/libenclave_tls.so
	dest=$(dir $@); \
	$(INSTALL) -d -m 0755 $$dest
	$(go_build) -o $@ .

$(Build_Libdir)/libenclave_tls.so:
	make -C $(Enclave_Tls_Srcdir) $@

clean:
	@rm -f *.o $(target)

install: all
	$(INSTALL) -d -m 0755 $(Enclave_Tls_Bindir)
	$(INSTALL) -m 0755 $(Targets) $(Enclave_Tls_Bindir)

uninstall:
	@rm -f $(Enclave_Tls_Bindir)/$(notdir $(target))

include $(Topdir)/rules/build_rules.mk
