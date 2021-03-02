TOPDIR := $(shell readlink -f .)

export TOPDIR

include common.mk

all: libenclave_tls.so

libenclave_tls.so:
	make -C $(SRCDIR) all

install:
	make -C $(SRCDIR) install

uninstall:
	rm -rf $(ENCLAVE_TLS_PREFIX)

clean:
	make -C $(SRCDIR) clean
