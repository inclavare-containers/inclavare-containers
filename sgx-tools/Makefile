GO ?= go
EXTRA_FLAGS ?=
EXTRA_LDFLAGS ?=
DESTDIR ?=

# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SGX_TOOLS_VERSION := $(shell cat $(ROOTDIR)/VERSION)
SGX_TOOLS_MAINTAINER := $(shell head -1 $(ROOTDIR)/MAINTAINERS)

APP := sgx-tools
.DEFAULT: $(APP)
.PHONY: clean test lint install uninstall

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"${COMMIT_NO}-dirty","${COMMIT_NO}")

VERSION := ${shell cat ./VERSION}
SOURCES := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')
$(APP): $(SOURCES)
	$(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -o $(APP) .

clean:
	@rm -f $(APP) test/*.token
	@rm -f dist/rpm/sgx-tools.spec dist/deb/debian/changelog

test: $(APP)
	./$(APP) --verbose gen-token --signature test/hello-world.sig

_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)
lint:
	$(GO) vet $(allpackages)
	$(GO) fmt $(allpackages)

PREFIX := $(DESTDIR)/usr/local
BINDIR := $(PREFIX)/bin
install: $(APP)
	@install -D -m0755 $(APP) "$(BINDIR)"

uninstall:
	@rm -f $(BINDIR)/$(APP)

package:
	$(MAKE) -C dist package SGX_TOOLS_VERSION="$(SGX_TOOLS_VERSION)" SGX_TOOLS_MAINTAINER="$(SGX_TOOLS_MAINTAINER)"
