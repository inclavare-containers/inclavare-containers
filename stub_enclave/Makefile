BINDIR := $(PREFIX)/usr/lib

all: stub_enclave

stub_enclave: ra_tls_options.c deps/local/lib/libwolfssl.sgx.static.lib.a deps/local/lib/libcurl-wolfssl.a libsgx_ra_tls_wolfssl.a
	$(MAKE) -ef sgx_u.mk all
	$(MAKE) -ef sgx_t.mk all

ra_tls_options.c: ra_tls_options.c.sh
	bash $^ > $@

deps/local/lib/libcrypto.a: deps/openssl/config
	cd deps/openssl && $(MAKE) && $(MAKE) -j1 install

deps/wolfssl/configure:
	mkdir -p deps && cd deps && git clone https://github.com/wolfSSL/wolfssl
	cd deps/wolfssl && git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
	cd deps/wolfssl && patch -p1 < ../../wolfssl.patch
	cd deps/wolfssl && ./autogen.sh

# Add --enable-debug to ./configure for debug build
# WOLFSSL_ALWAYS_VERIFY_CB ... Always call certificate verification callback, even if verification succeeds
# KEEP_OUR_CERT ... Keep the certificate around after the handshake
# --enable-tlsv10 ... required by libcurl
# 2019-03-19 removed --enable-intelasm configure flag. The Celeron NUC I am developing this, does not support AVX.

WOLFSSL_CFLAGS+=-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT
WOLFSSL_CONFIGURE_FLAGS+=--prefix=$(shell readlink -f deps/local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni --enable-tlsv10
ifdef DEBUG
WOLFSS_CFLAGS+=--enable-debug
endif

deps/local/lib/libwolfssl.a: CFLAGS+= $(WOLFSSL_CFLAGS)
deps/local/lib/libwolfssl.a: deps/wolfssl/configure
# Later versions of gcc report errors on this version of wolfSSL.
# TODO: Upgrade to more recent version of wolfSSL.
	cd deps/wolfssl && CC=gcc CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS)
	cd deps/wolfssl && $(MAKE) install

# Ideally, deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a and
# deps/local/lib/libwolfssl.a could be built in parallel. Does not
# work however. Hence, the dependency forces a serial build.
#
# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a
	cd deps/wolfssl/IDE/LINUX-SGX && make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192"

deps/local/lib/libwolfssl.sgx.static.lib.a: deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a deps/local/lib/libwolfssl.a
	mkdir -p deps/local/lib && cp deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a deps/local/lib

deps/curl/configure:
	cd deps && git clone https://github.com/curl/curl.git
	cd deps/curl && git checkout curl-7_47_0
	cd deps/curl && ./buildconf

CURL_CONFFLAGS=--prefix=$(shell readlink -f deps/local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --disable-ldap --disable-ldaps --disable-shared
ifdef DEBUG
CURL_CONFFLAGS+=--enable-debug
endif

deps/local/lib/libcurl-wolfssl.a: deps/curl/configure deps/local/lib/libwolfssl.a
	cp -a deps/curl deps/curl-wolfssl
	cd deps/curl-wolfssl && CFLAGS="-fPIC" ./configure $(CURL_CONFFLAGS) --without-ssl --with-cyassl=$(shell readlink -f deps/local)
	cd deps/curl-wolfssl && $(MAKE)
	cp deps/curl-wolfssl/lib/.libs/libcurl.a deps/local/lib/libcurl-wolfssl.a

libsgx_ra_tls_wolfssl.a:
	make -f ratls-wolfssl.mk
	rm -f wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o

install:
	install -D -m0755 liberpal-sgxsdk.so $(BINDIR)/liberpal-sgxsdk.so

uninstall:
	rm -f $(BINDIR)/liberpal-sgxsdk.so

clean:
	rm -f ra_tls_options.c ra_tls_u.o
	rm -rf deps/curl-wolfssl deps/local 
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean
	$(MAKE) -ef ratls-wolfssl.mk clean

.PHONY: stub_enclave clean install uninstall
