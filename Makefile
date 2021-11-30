# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
RATS_TLS_VERSION := $(shell cat $(ROOTDIR)/VERSION)
RATS_TLS_MAINTAINER := $(shell head -1 $(ROOTDIR)/MAINTAINERS)
Rats_Tls_Libdir := /usr/local/lib/rats-tls
Rats_Tls_Incdir := /usr/local/include/rats-tls
Rats_Tls_Bindir:= /usr/share/rats-tls

all:
	cmake -DBUILD_SAMPLES=on -H. -Bbuild
	make -C build

clean:
	@make -C build clean
	@rm -f dist/rpm/rats_tls.spec dist/deb/debian/changelog

install:
	cmake -DBUILD_SAMPLES=on -H. -Bbuild
	make -C build install

uninstall:
	@rm -rf $(Rats_Tls_Libdir) $(Rats_Tls_Incdir) $(Rats_Tls_Bindir)

package:
	$(MAKE) -C dist package RATS_TLS_VERSION="$(RATS_TLS_VERSION)" RATS_TLS_MAINTAINER="$(RATS_TLS_MAINTAINER)"
