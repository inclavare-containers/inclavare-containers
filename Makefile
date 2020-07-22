.PHONY: all install clean uninstall rpm

export INCLAVARE_CONTAINERS_VERSION := $(shell cat ./VERSION)
components := rune shim sgx-tools
rpm_release_components := rune shim

all:
	for name in $(components); do \
		$(MAKE) -C $$name; \
	done

install:
	for name in $(components); do \
		$(MAKE) -C $$name install; \
	done

clean:
	for name in $(components); do \
		$(MAKE) -C $$name clean; \
	done

uninstall:
	for name in $(components); do \
		$(MAKE) -C $$name uninstall; \
	done

rpm:
	for name in $(rpm_release_components); do \
		$(MAKE) -C $$name rpm; \
	done
