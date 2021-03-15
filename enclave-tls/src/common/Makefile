TOPDIR ?= $(shell readlink -f ../..)

include $(TOPDIR)/common.mk

LIBDIR := $(TOPDIR)/src/lib
WOLFSSL_BUILD := $(LIBDIR)/.build

all: wolfssl

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

$(WOLFSSL_BUILD):
	mkdir -p "$(WOLFSSL_BUILD)"

install:
	cd ./wolfssl && make install

clean:
	rm -rf $(WOLFSSL_BUILD)

mrproper:
	rm -rf wolfssl
