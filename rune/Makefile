GO := go

# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
RUNE_VERSION := $(shell cat $(ROOTDIR)/VERSION)
RUNE_MAINTAINER := $(shell head -1 $(ROOTDIR)/MAINTAINERS)

PREFIX := $(DESTDIR)/usr/local
BINDIR := $(PREFIX)/bin

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
BUILDTAGS ?= seccomp selinux apparmor
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
VERSION := $(shell cat ./VERSION)

# TODO: rm -mod=vendor once go 1.13 is unsupported
ifneq ($(GO111MODULE),off)
	MOD_VENDOR := "-mod=vendor"
endif
ifeq ($(DEBUG),1)
	GCFLAGS=-gcflags "-N -l"
endif

PROTO_DIR := libenclave/proto libenclave/intelsgx/proto libenclave/attestation/proto
PROTOS := $(foreach dir,$(PROTO_DIR),$(patsubst %.proto,%.pb.go,$(wildcard $(dir)/*.proto)))

GO_BUILD := $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) -tags "$(BUILDTAGS)" \
	-ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"
GO_BUILD_STATIC := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) $(GCFLAGS) $(EXTRA_FLAGS) -tags "$(BUILDTAGS) netgo osusergo" \
	-ldflags "-extldflags -static -X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"

.DEFAULT: rune

rune: $(PROTOS)
	$(GO_BUILD) -o rune .

%.pb.go: %.proto
	@protoc --proto_path=$(shell dirname $^) --go_out=$(shell dirname $^) $^

all: rune recvtty skeleton

recvtty:
	$(GO_BUILD) -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

skeleton: libenclave/internal/runtime/pal/skeleton/liberpal-skeleton*.so
libenclave/internal/runtime/pal/skeleton/liberpal-skeleton*.so:
	make -C libenclave/internal/runtime/pal/skeleton

static: $(PROTOS)
	$(GO_BUILD_STATIC) -o rune .
	$(GO_BUILD_STATIC) -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

lint:
	$(GO) vet ./...
	$(GO) fmt ./...

install:
	install -D -m0755 rune $(BINDIR)/rune

install-bash:
	install -D -m0644 contrib/completions/bash/rune $(PREFIX)/share/bash-completion/completions/rune

clean:
	rm -f rune rune-*
	rm -f contrib/cmd/recvtty/recvtty
	make -C libenclave/internal/runtime/pal/skeleton clean
	rm -f dist/rpm/rune.spec dist/deb/debian/changelog

uninstall:
	rm -f $(BINDIR)/rune

vendor:
	export GO111MODULE=on \
	$(GO) mod tidy && \
	$(GO) mod vendor && \
	$(GO) mod verify

verify-dependencies: vendor
	@test -z "$$(git status --porcelain -- go.mod go.sum vendor/)" \
		|| (echo -e "git status:\n $$(git status -- go.mod go.sum vendor/)\nerror: vendor/, go.mod and/or go.sum not up to date. Run \"make vendor\" to update"; exit 1) \
		&& echo "all vendor files are up to date."

package:
	$(MAKE) -C dist package RUNE_VERSION="$(RUNE_VERSION)" RUNE_MAINTAINER="$(RUNE_MAINTAINER)"

.PHONY: rune all recvtty static lint install install-bash \
	clean uninstall vendor verify-dependencies skeleton package
