TOPDIR ?= $(shell readlink -f ../../../../)

LIBDIR := $(TOPDIR)/src/lib
TLS_WRAPPERS := $(LIBDIR)/tls_wrappers
WOLFSSL_ENCLAVE_DIR := $(TLS_WRAPPERS)/wolfssl-sgx/wolfssl-enclave
WOLFSSL_BUILD := $(LIBDIR)/.build
WOLFSSL_BUILD_LIB := $(WOLFSSL_BUILD)/lib
 INCDIR := $(TOPDIR)/src/include

WOLFSSL_TLS_WRAPPER_C_FILES := $(wildcard $(TLS_WRAPPERS)/wolfssl/*.c)
WOLFSSL_TLS_WRAPPER_C_Objects := $(patsubst %.c, %.o, $(WOLFSSL_TLS_WRAPPER_C_FILES))

CFLAGS +=  -I$(INCDIR) -fPIC -DSGX_ENCLAVE

libtls_wrapper_wolfssl_sgx.a: $(filter-out un_negotiate.o, $(WOLFSSL_TLS_WRAPPER_C_Objects))
	ar rcs $@ $^
	mv $@ $(WOLFSSL_BUILD_LIB)

$(WOLFSSL_TLS_WRAPPER_C_Objects): %.o: %.c
	$(CC) -c $(CFLAGS) -I$(LIBDIR)/.build/include -I$(WOLFSSL_ENCLAVE_DIR) -I/opt/intel/sgxsdk/include -o $@ $<

clean:
	rm -rf $(WOLFSSL_BUILD_LIB)/libtls_wrapper_wolfssl_sgx.a
