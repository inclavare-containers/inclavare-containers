TOPDIR ?= $(shell readlink -f ..)

include $(TOPDIR)/common.mk

LIBDIR := $(TOPDIR)/src/lib
TLS_WRAPPERS := $(LIBDIR)/tls_wrappers
ENCLAVE_QUOTES := $(LIBDIR)/enclave_quotes
CRYPTO_WRAPPERS := $(LIBDIR)/crypto_wrappers
INCDIR := $(TOPDIR)/src/include
COMMONDIR := $(TOPDIR)/src/external
WOLFSSL_ENCLAVE_DIR := $(TLS_WRAPPERS)/wolfssl-sgx/wolfssl-enclave

MAJ_VERSION := 1
MIN_VERSION := 0.0

Lib_C_Files := $(wildcard $(LIBDIR)/core/*.c) \
	$(wildcard $(ENCLAVE_QUOTES)/api/*.c $(ENCLAVE_QUOTES)/internal/*.c) \
	$(wildcard $(TLS_WRAPPERS)/api/*.c $(TLS_WRAPPERS)/internal/*.c) \
	$(wildcard $(CRYPTO_WRAPPERS)/api/*.c $(CRYPTO_WRAPPERS)/internal/*.c) \
	$(wildcard $(LIBDIR)/api/*.c)
NULL_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/null/*.c)
NULL_ENCLAVE_QUOTE_C_FILES := $(wildcard $(ENCLAVE_QUOTES)/null/*.c)
NULL_CRYPTO_WRAPPER_C_FILES := $(wildcard $(CRYPTO_WRAPPERS)/nullcrypto/*.c)
WOLFSSL_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl/*.c)
WOLFCRYPT_WRAPPER_C_FILES := $(wildcard $(CRYPTO_WRAPPERS)/wolfcrypt/*.c)
WOLFSSL_SGX_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl-sgx/*.c) \
	$(filter-out main.c, $(wildcard $(TLS_WRAPPERS)/wolfssl/*.c))
WOLFSSL_SGX_ENCLAVE_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl-sgx/wolfssl-enclave/*.c)

CFLAGS += -I$(INCDIR) -fPIC

HOST_LDFLAGS := -fPIE -shared -Wl,-Bsymbolic,-rpath=$(ENCLAVE_TLS_LIBDIR),--enable-new-dtags

Lib_C_Objects := $(Lib_C_Files:.c=.o)
NULL_TLS_WRAPPER_C_Objects := $(NULL_TLS_WRAPPER_C_FILES:.c=.o)
NULL_ENCLAVE_QUOTE_C_Objects := $(NULL_ENCLAVE_QUOTE_C_FILES:.c=.o)
NULL_CRYPTO_WRAPPER_C_Objects := $(NULL_CRYPTO_WRAPPER_C_FILES:.c=.o)
WOLFSSL_TLS_WRAPPER_C_Objects := $(patsubst %.c, %.o, $(WOLFSSL_TLS_WRAPPER_C_FILES))
WOLFCRYPT_WRAPPER_C_Objects := $(patsubst %.c, %.o, $(WOLFCRYPT_WRAPPER_C_FILES))
WOLFSSL_SGX_TLS_WRAPPER_C_Objects := $(patsubst %.c, %.o, $(WOLFSSL_SGX_TLS_WRAPPER_C_FILES))
WOLFSSL_SGX_ENCLAVE_WRAPPER_C_Objects := $(patsubst %.c, %.o, $(WOLFSSL_SGX_ENCLAVE_WRAPPER_C_FILES))

objs := $(WOLFSSL_ENCLAVE_DIR)/wolfssl_enclave_u.o
tlibs:= libtls_wrapper_wolfssl_sgx.a wolfssl_enclave.signed.so
all: wolfssl $(objs) $(tlibs) libenclave_tls.so libtls_wrapper_null.so libenclave_quote_null.so libcrypto_wrapper_nullcrypto.so libtls_wrapper_wolfssl.so libcrypto_wrapper_wolfcrypt.so libtls_wrapper_wolfssl_sgx.so

libenclave_tls.so: $(Lib_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $(Lib_C_Objects) -ldl

libtls_wrapper_null.so: libenclave_tls.so $(NULL_TLS_WRAPPER_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $^

libenclave_quote_null.so: libenclave_tls.so $(NULL_ENCLAVE_QUOTE_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $^

libcrypto_wrapper_nullcrypto.so: libenclave_tls.so $(NULL_CRYPTO_WRAPPER_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $^

libtls_wrapper_wolfssl.so: libenclave_tls.so $(WOLFSSL_TLS_WRAPPER_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $^ -L$(LIBDIR)/.build/lib -lwolfssl

libcrypto_wrapper_wolfcrypt.so: libenclave_tls.so $(WOLFCRYPT_WRAPPER_C_Objects)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $^ -L$(LIBDIR)/.build/lib -lwolfssl

libtls_wrapper_wolfssl_sgx.so: libenclave_tls.so $(WOLFSSL_SGX_TLS_WRAPPER_C_Objects) $(objs)
	$(CC) $(HOST_LDFLAGS),-soname=$@.$(MAJ_VERSION) -o $@ $^ -L$(BUILDDIR)/lib -lwolfssl -lsgx_urts

libtls_wrapper_wolfssl_sgx.a:
	make -C $(TLS_WRAPPERS)/wolfssl-sgx

wolfssl_enclave.signed.so: libtls_wrapper_wolfssl_sgx.a
	make -C $(WOLFSSL_ENCLAVE_DIR)

$(WOLFSSL_ENCLAVE_DIR)/wolfssl_enclave_u.o:
	make -C $(WOLFSSL_ENCLAVE_DIR) pre-install

$(Lib_C_Objects): %.o: %.c
	$(CC) -c $(CFLAGS) -I$(LIBDIR)/.build/include -o $@ $<

$(WOLFSSL_TLS_WRAPPER_C_Objects) $(WOLFCRYPT_WRAPPER_C_Objects) $(WOLFSSL_SGX_TLS_WRAPPER_C_Objects): %.o: %.c
	$(CC) -c $(CFLAGS) -I$(LIBDIR)/.build/include -I$(WOLFSSL_ENCLAVE_DIR) -I/opt/intel/sgxsdk/include -o $@ $<

wolfssl:
	make -C $(COMMONDIR) && make -C $(COMMONDIR) install

install:
	$(INSTALL) -d -m 755 $(ENCLAVE_TLS_LIBDIR)
	$(INSTALL) -m 755 libenclave_tls.so $(ENCLAVE_TLS_LIBDIR)
	$(INSTALL) -d -m 755 $(ENCLAVE_TLS_INCDIR)
	$(INSTALL) -m 444 include/enclave-tls/* $(ENCLAVE_TLS_INCDIR)
	$(INSTALL) -d -m 755 $(TLS_WRAPPERS_LIBDIR)
	$(INSTALL) -m 755 libtls_wrapper_*.so $(TLS_WRAPPERS_LIBDIR)
	$(INSTALL) -d -m 755 $(ENCLAVE_QUOTES_LIBDIR)
	$(INSTALL) -m 755 libenclave_quote_null.so $(ENCLAVE_QUOTES_LIBDIR)
	$(INSTALL) -d -m 755 $(CRYPTO_WRAPPERS_LIBDIR)
	$(INSTALL) -m 755 libcrypto_wrapper_*.so $(CRYPTO_WRAPPERS_LIBDIR)
	cd $(ENCLAVE_TLS_LIBDIR) && \
	  mv libenclave_tls.so libenclave_tls.so.$(MAJ_VERSION).$(MIN_VERSION) && \
	  ln -sf libenclave_tls.so.$(MAJ_VERSION).$(MIN_VERSION) libenclave_tls.so.$(MAJ_VERSION) && \
	  ln -sf libenclave_tls.so.$(MAJ_VERSION).$(MIN_VERSION) libenclave_tls.so
	cp -df $(LIBDIR)/.build/lib/*so* $(ENCLAVE_TLS_LIBDIR)

uninstall:
	rm -rf $(ENCLAVE_TLS_PREFIX)

clean:
	rm -f lib*.so
	rm -f $(Lib_C_Objects) $(NULL_TLS_WRAPPER_C_Objects) \
	  $(NULL_ENCLAVE_QUOTE_C_Objects) $(NULL_CRYPTO_WRAPPER_C_Objects) \
	  $(WOLFSSL_TLS_WRAPPER_C_Objects) $(WOLFCRYPT_WRAPPER_C_Objects) \
	  $(WOLFSSL_SGX_TLS_WRAPPER_C_Objects)
	make -C $(COMMONDIR) clean
	make -C $(WOLFSSL_ENCLAVE_DIR) clean
	make -C $(TLS_WRAPPERS)/wolfssl-sgx clean

mrproper:
	make -C $(COMMONDIR) mrproper
