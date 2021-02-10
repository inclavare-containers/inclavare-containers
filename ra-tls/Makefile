TOPDIR := $(shell readlink -f .)
export TOPDIR

DEBUG ?= 1
SGX_DEBUG ?= 1

PREFIX ?= $(TOPDIR)/build
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
INCDIR := $(PREFIX)/include

SGX_SDK ?= /opt/intel/sgxsdk
SGX_RA_TLS := $(TOPDIR)/sgx-ra-tls
WOLFSSL := $(TOPDIR)/wolfssl
ELV := $(TOPDIR)/elv
RA_TLS_SERVER := $(TOPDIR)/ra-tls-server

ifdef ECDSA
  SGX_DCAP_URI := https://github.com/intel/SGXDataCenterAttestationPrimitives
  SGX_DCAP_COMMIT := bfab1376480f760757738092399d0d99b22f4dfd
  SGX_DCAP ?= SGXDataCenterAttestationPrimitives
  SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc \
		  -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc \
		  -I$(SGX_DCAP)/QuoteVerification/QVL/Src/AttestationLibrary/include \
		  -I$(SGX_DCAP)/QuoteVerification/dcap_quoteverify/inc
endif

CFLAGS += -std=gnu99 -I$(SGX_RA_TLS) -I$(SGX_SDK)/include -I$(INCDIR) -I$(WOLFSSL) $(SGX_DCAP_INC) -fPIC
CFLAGS += $(CFLAGSERRORS) -g -ggdb -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS += -DSGX_GROUP_OUT_OF_DATE

ifdef ECDSA
	CFLAGS += -DRATLS_ECDSA
endif

ifdef LA
	CFLAGS += -DLA_REPORT
endif

CC ?= gcc

export DEBUG PREFIX BINDIR LIBDIR INCDIR SGX_SDK SGX_RA_TLS WOLFSSL CC

deps := $(LIBDIR)/libwolfssl.a $(LIBDIR)/libwolfssl.sgx.static.lib.a $(LIBDIR)/libsgx_ra_tls_wolfssl.a $(LIBDIR)/libcurl-wolfssl.a $(LIBDIR)/liberpal-stub.a
all: $(deps) $(BINDIR)/elv $(BINDIR)/ra-tls-server $(BINDIR)/Wolfssl_Enclave.signed.so

ifdef LA
$(BINDIR)/elv: $(BINDIR) $(LIBDIR)/libra-challenger.a $(LIBDIR)/libwolfssl.a $(LIBDIR)/liberpal-stub.a
	make -C $(ELV) LA=1 && cp -f $(ELV)/elv $@
else
$(BINDIR)/elv: $(BINDIR) $(LIBDIR)/libra-challenger.a $(LIBDIR)/libwolfssl.a $(LIBDIR)/liberpal-stub.a
	make -C $(ELV) && cp -f $(ELV)/elv $@
endif

$(BINDIR)/ra-tls-server: $(BINDIR) $(LIBDIR)/libcurl-wolfssl.a $(LIBDIR)/libwolfssl.a
	make -C $(RA_TLS_SERVER) && cp -f $(RA_TLS_SERVER)/ra-tls-server $@

$(BINDIR)/Wolfssl_Enclave.signed.so: $(BINDIR)
	$(MAKE) -C stub-enclave && \
	  cp -f stub-enclave/Wolfssl_Enclave.signed.so "$@"


# Add --enable-debug to ./configure for debug build
# WOLFSSL_ALWAYS_VERIFY_CB: Always call certificate verification callback, even if verification succeeds
# KEEP_OUR_CERT: Keep the certificate around after the handshake
# --enable-tlsv10: required by libcurl
# 2019-03-19 removed --enable-intelasm configure flag. The Celeron NUC I am developing this, does not support AVX.
WOLFSSL_CFLAGS := -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT -Wno-stringop-truncation
ifdef DEBUG
	WOLFSSL_CONFFLAGS += --enable-debug
endif
$(LIBDIR)/libwolfssl.a: CFLAGS += $(WOLFSSL_CFLAGS)
$(LIBDIR)/libwolfssl.a: $(LIBDIR) wolfssl
	cd wolfssl && $(MAKE) install

wolfssl: WOLFSSL_CONFIGURE_FLAGS := --prefix=$(shell readlink -f $(PREFIX)) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni --enable-tlsv10 $(WOLFSSL_CONFFLAGS)
# To avoid unneccessary macro definition to be wrote into options.h. If make ECDSA=1(compiling attestation based on ECDSA) firstly,
# then RATLS_ECDSA will be wrote into options.h, even just make(compiling attestation based on EPID), the RATLS_ECDSA will still be in
# options.h. So it needs be reconfigured before compiling, options.h will be re-generated according to new configuration.
wolfssl:
	if [ -d "./wolfssl" ]; then \
		cd wolfssl && ./autogen.sh && CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS) || true; \
	fi
	if [ ! -d "./wolfssl" ]; then \
		git clone -b v4.6.0-stable https://github.com/wolfSSL/wolfssl && \
		cd wolfssl && git apply ../patch/wolfssl.patch && \
		./autogen.sh && CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS) || true; \
	fi

$(SGX_RA_TLS)/wolfssl-ra-challenger.o: $(SGX_RA_TLS)/wolfssl-ra-challenger.c
	@echo $(CC) $(CFLAGS) -c $< -o $@
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

#ifdef LA
#	ra-challenger_deps = $(LIBDIR) $(LIBDIR)/libwolfssl.a $(SGX_RA_TLS)/ra.o $(SGX_RA_TLS)/wolfssl-ra-challenger.o $(SGX_RA_TLS)/wolfssl-ra.o $(SGX_RA_TLS)/ra-challenger.o $(SGX_RA_TLS)/ias_sign_ca_cert.o $(SGX_RA_TLS)/wolfssl-la-challenger.o pal/Wolfssl_Enclave_u.o pal/App.o
#else
#	ra-challenger_deps = $(LIBDIR) $(LIBDIR)/libwolfssl.a $(SGX_RA_TLS)/ra.o $(SGX_RA_TLS)/wolfssl-ra-challenger.o $(SGX_RA_TLS)/wolfssl-ra.o $(SGX_RA_TLS)/ra-challenger.o $(SGX_RA_TLS)/ias_sign_ca_cert.o pal/Wolfssl_Enclave_u.o pal/App.o
#endif

ifdef LA
# sgx-ra-tls needs the header files from wolfssl.
$(LIBDIR)/libra-challenger.a: $(LIBDIR) $(LIBDIR)/libwolfssl.a $(SGX_RA_TLS)/ra.o $(SGX_RA_TLS)/wolfssl-ra-challenger.o $(SGX_RA_TLS)/wolfssl-ra.o $(SGX_RA_TLS)/ra-challenger.o $(SGX_RA_TLS)/ias_sign_ca_cert.o $(SGX_RA_TLS)/wolfssl-la-challenger.o pal/Wolfssl_Enclave_u.o pal/App.o
	$(AR) rcs "$@" $(filter %.o, $^)
else
# sgx-ra-tls needs the header files from wolfssl.
$(LIBDIR)/libra-challenger.a: $(LIBDIR) $(LIBDIR)/libwolfssl.a $(SGX_RA_TLS)/ra.o $(SGX_RA_TLS)/wolfssl-ra-challenger.o $(SGX_RA_TLS)/wolfssl-ra.o $(SGX_RA_TLS)/ra-challenger.o $(SGX_RA_TLS)/ias_sign_ca_cert.o pal/Wolfssl_Enclave_u.o pal/App.o
	$(AR) rcs "$@" $(filter %.o, $^)
endif

# Ideally, libwolfssl.sgx.static.lib.a and libwolfssl.a could be built
# in parallel. Does not work however. Hence, the dependency forces a
# serial build.
#
# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
$(LIBDIR)/libwolfssl.sgx.static.lib.a: $(LIBDIR) $(LIBDIR)/libsgx_ra_tls_wolfssl.a $(LIBDIR)/libwolfssl.a
ifdef LA
	cd wolfssl/IDE/LINUX-SGX && \
	  make -f sgx_t_static.mk CFLAGS="-DLA_REPORT -DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192" && \
	  cp -f libwolfssl.sgx.static.lib.a "$@"
else
	cd wolfssl/IDE/LINUX-SGX && \
	  make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192" && \
	  cp -f libwolfssl.sgx.static.lib.a "$@"
endif

$(LIBDIR)/libsgx_ra_tls_wolfssl.a: $(LIBDIR)
# Previous Makefile compiles these .o files with incorrect C flags
# Don't disturb the build of libsgx_ra_tls_wolfssl.a
	rm -f $(SGX_RA_TLS)/wolfssl-ra-challenger.o $(SGX_RA_TLS)/wolfssl-ra.o $(SGX_RA_TLS)/ra-challenger.o $(SGX_RA_TLS)/ias_sign_ca_cert.o
	$(MAKE) -C $(SGX_RA_TLS) && \
	  mv -f $(SGX_RA_TLS)/libsgx_ra_tls_wolfssl.a "$@"
# Don't disturb the build of libra-challenger.a
	rm -f $(SGX_RA_TLS)/wolfssl-ra-challenger.o $(SGX_RA_TLS)/wolfssl-ra.o $(SGX_RA_TLS)/ra-challenger.o $(SGX_RA_TLS)/ias_sign_ca_cert.o

$(LIBDIR)/libcurl-wolfssl.a: $(LIBDIR) curl-wolfssl $(LIBDIR)/libwolfssl.a
	cd curl-wolfssl && $(MAKE) && \
	  cp -f lib/.libs/libcurl.a "$@"

$(LIBDIR)/liberpal-stub.a:
	$(MAKE) -C pal && \
	mv -f pal/liberpal-stub.a "$@"

CURL_CONFFLAGS := --prefix=$(shell readlink -f $(PREFIX)) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --disable-ldap --disable-ldaps --disable-shared
ifdef DEBUG
CURL_CONFFLAGS += --enable-debug
endif
curl-wolfssl:
	git clone https://github.com/curl/curl.git -b curl-7_47_0 curl-wolfssl && \
	  cd curl-wolfssl && ./buildconf && \
	  CFLAGS="-fPIC" ./configure $(CURL_CONFFLAGS) --without-ssl --with-cyassl=$(shell readlink -f $(PREFIX))

$(LIBDIR)/libra-attester.a: wolfssl wolfssl-ra-attester.o wolfssl-ra.o ias-ra.o
	$(AR) rcs $@ $(filter %.o, $^)

$(BINDIR):
	mkdir -p "$(BINDIR)"

$(LIBDIR):
	mkdir -p "$(LIBDIR)"

clean:
	rm -rf $(PREFIX)
	[ -d curl-wolfssl ] && $(MAKE) clean -C curl-wolfssl || true
	[ -d wolfssl ] && $(MAKE) clean -C wolfssl || true
	$(MAKE) -C stub-enclave clean
	$(MAKE) -C $(SGX_RA_TLS) clean
	$(MAKE) -C $(ELV) clean
	$(MAKE) -C $(RA_TLS_SERVER) clean
	$(MAKE) -C pal clean
	rm -f wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a

mrproper:
	$(MAKE) clean
	rm -rf curl-wolfssl wolfssl

.PHONY: all clean mrproper wolfssl
