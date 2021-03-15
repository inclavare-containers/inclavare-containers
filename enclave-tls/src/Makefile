TOPDIR ?= $(shell readlink -f ..)

include $(TOPDIR)/common.mk

LIBDIR := $(TOPDIR)/src/lib
TLS_WRAPPERS := $(LIBDIR)/tls_wrappers
ENCLAVE_QUOTES := $(LIBDIR)/enclave_quotes
INCDIR := $(TOPDIR)/src/include
COMMONDIR := $(TOPDIR)/src/common

MAJ_VERSION := 1
MIN_VERSION := 0.0

Lib_C_Files :=  $(wildcard $(LIBDIR)/core/*.c) \
	$(wildcard $(ENCLAVE_QUOTES)/api/*.c $(ENCLAVE_QUOTES)/internal/*.c) \
	$(wildcard $(TLS_WRAPPERS)/api/*.c $(TLS_WRAPPERS)/internal/*.c) \
	$(wildcard $(LIBDIR)/api/*.c)
NULL_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/null/*.c)
NULL_ENCLAVE_QUOTE_C_FILES := $(wildcard $(ENCLAVE_QUOTES)/null/*.c)

CFLAGS += -I$(INCDIR) -fPIC

HOST_LDFLAGS := -fPIE -shared -Wl,-Bsymbolic,--rpath=$(ENCLAVE_TLS_LIBDIR),--enable-new-dtags

Lib_C_Objects := $(Lib_C_Files:.c=.o)
NULL_TLS_WRAPPER_C_Objects := $(NULL_TLS_WRAPPER_C_FILES:.c=.o)
NULL_ENCLAVE_QUOTE_C_Objects := $(NULL_ENCLAVE_QUOTE_C_FILES:.c=.o)

all: libenclave_tls.so libtls_wrapper_null.so libenclave_quote_null.so

libenclave_tls.so: $(Lib_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $(Lib_C_Objects) -ldl

libtls_wrapper_null.so: libenclave_tls.so $(NULL_TLS_WRAPPER_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $(NULL_TLS_WRAPPER_C_Objects) libenclave_tls.so

libenclave_quote_null.so: libenclave_tls.so $(NULL_ENCLAVE_QUOTE_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $(NULL_ENCLAVE_QUOTE_C_Objects) libenclave_tls.so

wolfssl:
	make -C $(COMMONDIR) && make -C $(COMMONDIR) install

install:
	$(INSTALL) -d -m 755 $(ENCLAVE_TLS_LIBDIR)
	$(INSTALL) -m 755 libenclave_tls.so $(ENCLAVE_TLS_LIBDIR)
	$(INSTALL) -d -m 755 $(ENCLAVE_TLS_INCDIR)
	$(INSTALL) -m 444 include/enclave-tls/* $(ENCLAVE_TLS_INCDIR)
	$(INSTALL) -d -m 755 $(TLS_WRAPPERS_LIBDIR)
	$(INSTALL) -m 755 libtls_wrapper_null.so $(TLS_WRAPPERS_LIBDIR)
	$(INSTALL) -d -m 755 $(ENCLAVE_QUOTES_LIBDIR)
	$(INSTALL) -m 755 libenclave_quote_null.so $(ENCLAVE_QUOTES_LIBDIR)
	cd $(ENCLAVE_TLS_LIBDIR) && mv libenclave_tls.so libenclave_tls.so.$(MAJ_VERSION).$(MIN_VERSION) && \
	ln -sf libenclave_tls.so.$(MAJ_VERSION).$(MIN_VERSION) libenclave_tls.so.$(MAJ_VERSION) && \
	ln -sf libenclave_tls.so.$(MAJ_VERSION).$(MIN_VERSION) libenclave_tls.so

uninstall:
	rm -rf $(ENCLAVE_TLS_PREFIX)

clean:
	rm -f lib*.so
	rm -f $(Lib_C_Objects) $(NULL_TLS_WRAPPER_C_Objects) $(NULL_ENCLAVE_QUOTE_C_Objects)
	make -C $(COMMONDIR) clean

mrproper:
	make -C $(COMMONDIR) mrproper
