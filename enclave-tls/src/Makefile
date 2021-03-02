TOPDIR ?= ..

include $(TOPDIR)/common.mk

LIBDIR := $(TOPDIR)/src/lib
TLS_WRAPPERS := $(LIBDIR)/tls_wrappers
ENCLAVE_QUOTES := $(LIBDIR)/enclave_quotes
INCDIR := $(TOPDIR)/src/include

Lib_C_Files :=  $(wildcard $(LIBDIR)/core/*.c) \
	$(wildcard $(ENCLAVE_QUOTES)/api/*.c $(ENCLAVE_QUOTES)/internal/*.c) \
	$(wildcard $(TLS_WRAPPERS)/api/*.c $(TLS_WRAPPERS)/internal/*.c) \
	$(wildcard $(LIBDIR)/api/*.c)

CFLAGS := -I$(INCDIR) -fPIC
ifeq ($(DEBUG),1)
  CFLAGS += -g
endif

HOST_LDFLAGS := -fPIE -shared -Wl,-Bsymbolic

Lib_C_Objects := $(Lib_C_Files:.c=.o)

all: libenclave_tls.so

libenclave_tls.so: $(Lib_C_Objects)
	$(CC) $(HOST_LDFLAGS) -o $@ $(Lib_C_Objects) -ldl

install:
	$(INSTALL) -d -m 755 $(ENCLAVE_TLS_LIBDIR)
	$(INSTALL) -m 755 libenclave_tls.so $(ENCLAVE_TLS_LIBDIR)
	$(INSTALL) -d -m 755 $(ENCLAVE_TLS_INCDIR)
	$(INSTALL) -m 444 include/enclave-tls/* $(ENCLAVE_TLS_INCDIR)

uninstall:
	rm -rf $(ENCLAVE_TLS_PREFIX)

clean:
	rm -f lib*.so
	rm -f $(Lib_C_Objects)
