TOPDIR ?= $(shell readlink -f ../..)

include $(TOPDIR)/common.mk

LIBDIR := $(TOPDIR)/src/lib
WOLFSSL_BUILD := $(LIBDIR)/.build
WOLFSSL_BUILD_LIB := $(WOLFSSL_BUILD)/lib

all: wolfssl libwolfssl.sgx.static.lib.a

ifdef DEBUG
  WOLFSSL_CONFFLAGS += --enable-debug
endif
WOLFSSL_CONFIGURE_FLAGS := --prefix=$(shell readlink -f $(WOLFSSL_BUILD)) \
	--enable-writedup --enable-shared  --enable-keygen --enable-certgen \
	--enable-certext --with-pic --disable-examples --disable-crypttests \
	--enable-aesni --enable-tlsv10 $(WOLFSSL_CONFFLAGS)

wolfssl: $(WOLFSSL_BUILD)
	if [ ! -d "./wolfssl" ]; then \
                git clone -b v4.6.0-stable https://github.com/wolfSSL/wolfssl && \
                cd wolfssl && git apply ../patch/wolfssl.patch && \
                ./autogen.sh && CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS) || true; \
	fi

libwolfssl.sgx.static.lib.a: $(WOLFSSL_BUILD_LIB)
	cd wolfssl/IDE/LINUX-SGX && \
		make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192" && \
		cp -f libwolfssl.sgx.static.lib.a $(WOLFSSL_BUILD_LIB)/

$(WOLFSSL_BUILD):
	mkdir -p "$(WOLFSSL_BUILD)"

$(WOLFSSL_BUILD_LIB):
	mkdir -p "$(WOLFSSL_BUILD_LIB)"

install:
	cd ./wolfssl && make install

clean:
	rm -rf $(WOLFSSL_BUILD)

mrproper:
	rm -rf wolfssl
