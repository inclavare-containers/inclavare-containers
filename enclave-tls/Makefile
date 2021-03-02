TOPDIR := $(shell readlink -f .)

export TOPDIR

include common.mk

all: libenclave_tls.so $(BINDIR)/elv

$(BINDIR)/elv: libenclave_tls.so
	make -C $(CLIENT_DIR) && make -C $(CLIENT_DIR) install

libenclave_tls.so:
	make -C $(SRCDIR) all

install:
	make -C $(SRCDIR) install

uninstall:
	rm -rf $(ENCLAVE_TLS_PREFIX)

clean:
	make -C $(SRCDIR) clean
	make -C $(CLIENT_DIR) clean
	rm -rf $(BINDIR)
