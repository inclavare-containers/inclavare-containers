# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Base path used to install.
DESTDIR ?= /usr/local

# Variables for building rpm
VERSION ?= 0.2.0
RELEASE_TARBALL_URL ?= https://github.com/alibaba/inclavare-containers/archive/v$(VERSION).tar.gz
RPMBUILD_DIR ?= /tmp/inclavare-containers/shim/rpmbuild

ifneq "$(strip $(shell command -v go 2>/dev/null))" ""
	GOOS ?= $(shell go env GOOS)
	GOARCH ?= $(shell go env GOARCH)
else
	ifeq ($(GOOS),)
		# approximate GOOS for the platform if we don't have Go and GOOS isn't
		# set. We leave GOARCH unset, so that may need to be fixed.
		ifeq ($(OS),Windows_NT)
			GOOS = windows
		else
			UNAME_S := $(shell uname -s)
			ifeq ($(UNAME_S),Linux)
				GOOS = linux
			endif
			ifeq ($(UNAME_S),Darwin)
				GOOS = darwin
			endif
			ifeq ($(UNAME_S),FreeBSD)
				GOOS = freebsd
			endif
		endif
	else
		GOOS ?= $$GOOS
		GOARCH ?= $$GOARCH
	endif
endif

# Project binaries.
COMMANDS=containerd-shim-rune-v2

GO_BUILD_FLAGS=
SHIM_CGO_ENABLED ?= 0

BINARIES=$(addprefix bin/,$(COMMANDS))

.PHONY: clean all binaries help install uninstall rpm
.DEFAULT: default

all: binaries

# Build a binary from a cmd.
bin/containerd-shim-rune-v2:
	@echo "bin/containerd-shim-rune-v2"
	@CGO_ENABLED=${SHIM_CGO_ENABLED} GOOS=${GOOS} go build ${GO_BUILD_FLAGS} -o bin/containerd-shim-rune-v2 ./cmd/containerd-shim-rune-v2

binaries: clean $(BINARIES) ## build binaries

clean: ## clean up binaries
	@echo "$@"
	@rm -f $(BINARIES)
	@rm -fr ${RPMBUILD_DIR}

rpm:
	@mkdir -p $(RPMBUILD_DIR)
	@echo "%_topdir $(RPMBUILD_DIR)" >> ~/.rpmmacros
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@wget -P $(RPMBUILD_DIR)/SOURCES $(RELEASE_TARBALL_URL)
	$(MAKE) -C dist/centos rpm RPMBUILD_DIR=$(RPMBUILD_DIR)

install: ## install binaries
	@echo "$@ $(BINARIES)"
	@mkdir -p $(DESTDIR)/bin
	@install $(BINARIES) $(DESTDIR)/bin

uninstall:
	@echo "$@"
	@rm -f $(addprefix $(DESTDIR)/bin/,$(notdir $(BINARIES)))

help: ## this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort
