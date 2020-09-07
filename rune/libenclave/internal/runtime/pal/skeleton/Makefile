ifndef OBJCOPY
OBJCOPY := $(CROSS_COMPILE)objcopy
endif

OUTPUT ?= ./
HOST_CFLAGS := -Wall -Werror -g -fPIC -z noexecstack \
	       -Wno-unused-const-variable -std=gnu11
ENCL_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIC \
	       -fno-stack-protector -mrdrnd -std=gnu11
HOST_LDFLAGS := -fPIC -shared -Wl,-Bsymbolic

IS_SGX_FLC ?= $(shell if lscpu | grep -q sgx_lc; then echo "1"; else echo "0"; fi;)

PRODUCT_ENCLAVE ?=

TEST_CUSTOM_PROGS := $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss $(OUTPUT)/liberpal-skeleton-v1.so $(OUTPUT)/liberpal-skeleton-v2.so $(OUTPUT)/liberpal-skeleton-v3.so $(OUTPUT)/signing_key.pem

ifeq ($(IS_SGX_FLC),0)
        TEST_CUSTOM_PROGS += $(OUTPUT)/encl.token
endif

all: $(TEST_CUSTOM_PROGS)

$(OUTPUT)/liberpal-skeleton-v1.so: $(OUTPUT)/sgx_call.o $(OUTPUT)/liberpal-skeleton-v1.o $(OUTPUT)/liberpal-skeleton.o $(OUTPUT)/sgxutils.o
	$(CC) $(HOST_LDFLAGS) -o $@ $^

$(OUTPUT)/liberpal-skeleton-v1.o: liberpal-skeleton-v1.c liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/liberpal-skeleton-v2.so: $(OUTPUT)/sgx_call.o $(OUTPUT)/liberpal-skeleton-v2.o $(OUTPUT)/liberpal-skeleton.o $(OUTPUT)/sgxutils.o
	$(CC) $(HOST_LDFLAGS) -o $@ $^

$(OUTPUT)/liberpal-skeleton-v2.o: liberpal-skeleton-v2.c liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/liberpal-skeleton.o: liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/liberpal-skeleton-v3.so: $(OUTPUT)/sgx_call.o $(OUTPUT)/liberpal-skeleton-v3.o $(OUTPUT)/liberpal-skeleton.o $(OUTPUT)/sgxutils.o
	$(CC) $(HOST_LDFLAGS) -o $@ $^

$(OUTPUT)/liberpal-skeleton-v3.o: liberpal-skeleton-v3.c liberpal-skeleton.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/sgx_call.o: sgx_call.S
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/sgxutils.o: sgxutils.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/encl.bin: $(OUTPUT)/encl.elf $(OUTPUT)/sgxsign
	$(OBJCOPY) -O binary $< $@

$(OUTPUT)/encl.elf: encl.lds encl.c encl_bootstrap.S
	$(CC) $(ENCL_CFLAGS) -T $^ -o $@

# If you want to sign a production encalve, you need add '-p' args in sgxsign. In addition, for Intel SGX1 without FLC, please replace signing_key with the product signature key applied to Intel.
$(OUTPUT)/signing_key.pem:
	openssl genrsa -3 -out $@ 3072

ifeq ($(PRODUCT_ENCLAVE),1)
        PRODUCT_OPT := -p
else
        PRODUCT_OPT :=
endif

$(OUTPUT)/encl.ss: $(OUTPUT)/encl.bin $(OUTPUT)/signing_key.pem
	$(OUTPUT)/sgxsign $(PRODUCT_OPT) signing_key.pem $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss

ifeq ($(IS_SGX_FLC),0)
$(OUTPUT)/encl.token: $(OUTPUT)/encl.ss
	sgx-tools gen-token --signature encl.ss --token $@
endif

$(OUTPUT)/sgxsign: sgxsign.c sgxutils.c
	$(CC) -I../include -o $@ $^ -lcrypto

EXTRA_CLEAN := \
	$(OUTPUT)/encl.bin \
	$(OUTPUT)/encl.elf \
	$(OUTPUT)/encl.ss \
	$(OUTPUT)/sgx_call.o \
	$(OUTPUT)/sgxutils.o \
	$(OUTPUT)/sgxsign \
	$(OUTPUT)/liberpal-skeleton*.o \
	$(OUTPUT)/liberpal-skeleton*.so \
	$(OUTPUT)/signing_key.pem

ifeq ($(IS_SGX_FLC),0)
        EXTRA_CLEAN += $(OUTPUT)/encl.token
endif

clean:
	rm -f ${EXTRA_CLEAN}

.PHONY: clean all
