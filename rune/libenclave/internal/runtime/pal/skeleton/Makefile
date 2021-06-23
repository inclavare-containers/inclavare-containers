ifndef OBJCOPY
OBJCOPY := $(CROSS_COMPILE)objcopy
endif

OUTPUT ?= ./
SGX_SDK ?= /opt/intel/sgxsdk
Enclave_Tls_Src := ../../../../../../enclave-tls
SGX_Stub_Enclave := $(Enclave_Tls_Src)/samples/sgx-stub-enclave
Enclave_Tls_Root ?= /opt/enclave-tls
Enclave_Tls_Libdir := $(Enclave_Tls_Root)/lib
Enclave_Tls_Incdir := $(Enclave_Tls_Root)/include
TLS_SERVER ?=
PROTOBUF_VERSION := $(shell protoc-c --version | grep libprotoc | awk '{print $$2}' | awk -F '.' '{print $$1}')

HOST_CFLAGS := -Wall -Werror -g -fPIC -z noexecstack \
	       -Wno-unused-const-variable -std=gnu11 -I../kvmtool/include \
	       -I$(SGX_SDK)/include -I$(Enclave_Tls_Incdir)
ifdef TLS_SERVER
HOST_CFLAGS += -DTLS_SERVER
endif

ENCL_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIC \
	       -fno-stack-protector -mrdrnd -std=gnu11
HOST_LDFLAGS := -fPIC -shared -Wl,-Bsymbolic,-rpath=$(Enclave_Tls_Libdir),-enable-new-dtags \
		-Wl,-start-group -lprotobuf-c -lutil -lbfd -lpthread -Wl,-end-group

ifdef TLS_SERVER
HOST_LDFLAGS += -L$(Enclave_Tls_Libdir) -lenclave_tls -lm
endif

PRODUCT_ENCLAVE ?=

TEST_CUSTOM_PROGS := $(OUTPUT)/encl.bin \
		     $(OUTPUT)/encl.ss \
		     $(OUTPUT)/aesm.pb-c.c \
		     $(OUTPUT)/liberpal-skeleton-v1.so \
		     $(OUTPUT)/liberpal-skeleton-v2.so \
		     $(OUTPUT)/liberpal-skeleton-v3.so \
		     $(OUTPUT)/signing_key.pem

all: $(TEST_CUSTOM_PROGS)

libvmm:
	$(MAKE) -C ../kvmtool all

../kvmtool/libvmm.a: libvmm

ifdef TLS_SERVER
TLS_SERVER_OBJS := $(OUTPUT)/tls-server.o $(SGX_Stub_Enclave)/sgx_stub_u.o

$(SGX_Stub_Enclave)/sgx_stub_u.o:
	make -C $(SGX_Stub_Enclave)
endif

$(OUTPUT)/liberpal-skeleton-v1.so: $(OUTPUT)/sgx_call.o $(OUTPUT)/liberpal-skeleton-v1.o \
				   $(OUTPUT)/liberpal-skeleton.o $(OUTPUT)/sgxutils.o \
				   $(OUTPUT)/aesm.o $(OUTPUT)/aesm.pb-c.o \
				   ../kvmtool/libvmm.a
	$(CC) $^ $(HOST_LDFLAGS) -o $@

$(OUTPUT)/liberpal-skeleton-v1.o: liberpal-skeleton-v1.c liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/liberpal-skeleton-v2.so: $(OUTPUT)/sgx_call.o $(OUTPUT)/liberpal-skeleton-v2.o \
				   $(OUTPUT)/liberpal-skeleton.o $(OUTPUT)/sgxutils.o \
				   $(OUTPUT)/aesm.o $(OUTPUT)/aesm.pb-c.o \
				   ../kvmtool/libvmm.a
	$(CC) $^ $(HOST_LDFLAGS) -o $@

$(OUTPUT)/liberpal-skeleton-v2.o: liberpal-skeleton-v2.c liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/liberpal-skeleton.o: liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/liberpal-skeleton-v3.so: $(OUTPUT)/sgx_call.o $(OUTPUT)/liberpal-skeleton-v3.o \
				   $(OUTPUT)/liberpal-skeleton.o $(OUTPUT)/sgxutils.o \
				   $(OUTPUT)/aesm.o $(OUTPUT)/aesm.pb-c.o \
				   ../kvmtool/libvmm.a $(TLS_SERVER_OBJS)
	$(CC) $^ $(HOST_LDFLAGS) -o $@

$(OUTPUT)/liberpal-skeleton-v3.o: liberpal-skeleton-v3.c liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/tls-server.o: tls-server.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/aesm.o: aesm.c $(OUTPUT)/aesm.pb-c.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/aesm.pb-c.o: $(OUTPUT)/aesm.pb-c.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/aesm.pb-c.c: aesm.proto2 aesm.proto3
ifeq ($(PROTOBUF_VERSION),2)
	@cp aesm.proto2 aesm.proto
else ifeq ($(PROTOBUF_VERSION),3)
	@cp aesm.proto3 aesm.proto
else
	@echo "Unsupported protobuf version"
endif
	@protoc-c --c_out=. aesm.proto
	@rm aesm.proto

$(OUTPUT)/sgx_call.o: sgx_call.S
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/sgxutils.o: sgxutils.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/encl.bin: $(OUTPUT)/encl.elf $(OUTPUT)/sgxsign
	$(OBJCOPY) -O binary $< $@

$(OUTPUT)/encl.elf: encl.lds encl.c encl_bootstrap.S
	$(CC) $(ENCL_CFLAGS) -T $^ -o $@

$(OUTPUT)/signing_key.pem:
	openssl genrsa -3 -out $@ 3072

# If you want to prohibit enclave debug function, you need add '-N' argument in sgxsign.
# In addition, for Intel SGX1 without FLC, please replace signing_key with the product
# signing key applied to Intel.
ifeq ($(NO_DEBUGGER),1)
        NO_DEBUGGER_OPT := -N
else
        NO_DEBUGGER_OPT :=
endif

$(OUTPUT)/encl.ss: $(OUTPUT)/encl.bin $(OUTPUT)/signing_key.pem
	$(OUTPUT)/sgxsign $(NO_DEBUGGER_OPT) signing_key.pem $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss

$(OUTPUT)/sgxsign: sgxsign.c sgxutils.c
	$(CC) -I../include -o $@ $^ -lcrypto

EXTRA_CLEAN := \
	$(OUTPUT)/encl.bin \
	$(OUTPUT)/encl.elf \
	$(OUTPUT)/encl.ss \
	$(OUTPUT)/sgx_call.o \
	$(OUTPUT)/aesm.o \
	$(OUTPUT)/aesm.pb-c* \
	$(OUTPUT)/sgxutils.o \
	$(OUTPUT)/sgxsign \
	$(OUTPUT)/liberpal-skeleton*.o \
	$(OUTPUT)/tls-server.o \
	$(OUTPUT)/liberpal-skeleton*.so \
	$(OUTPUT)/signing_key.pem

DIRS_TO_CLEAN := ../kvmtool
ifdef TLS_SERVER
DIRS_TO_CLEAN += $(SGX_Stub_Enclave)
endif

clean:
	rm -f ${EXTRA_CLEAN}
	$(MAKE) -C $(DIRS_TO_CLEAN) clean

.PHONY: clean all
