.PHONY: all install clean uninstall package

export INCLAVARE_CONTAINERS_VERSION := $(shell cat ./VERSION)
stable_components := rune shim epm sgx-tools enclave-tls rats-tls shelter inclavared verdictd
unstable_components :=
components := $(stable_components) $(unstable_components)

all:
	for name in $(stable_components); do \
		$(MAKE) -C $$name || exit 1; \
	done

install:
	for name in $(stable_components); do \
		$(MAKE) -C $$name install || exit 1; \
	done

clean:
	for name in $(stable_components); do \
		$(MAKE) -C $$name clean || exit 1; \
	done

uninstall:
	for name in $(stable_components); do \
		$(MAKE) -C $$name uninstall || exit 1; \
	done

package:
	for name in $(stable_components); do \
		$(MAKE) -C $$name package || exit 1; \
	done
