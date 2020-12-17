.PHONY: all install clean uninstall package

export INCLAVARE_CONTAINERS_VERSION := $(shell cat ./VERSION)
components := rune shim epm sgx-tools

all:
	for name in $(components); do \
		$(MAKE) -C $$name || exit 1; \
	done

install:
	for name in $(components); do \
		$(MAKE) -C $$name install || exit 1; \
	done

clean:
	for name in $(components); do \
		$(MAKE) -C $$name clean || exit 1; \
	done

uninstall:
	for name in $(components); do \
		$(MAKE) -C $$name uninstall || exit 1; \
	done

package:
	for name in $(components); do \
		$(MAKE) -C $$name package || exit 1; \
	done
