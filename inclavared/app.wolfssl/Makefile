Rust_App_Name := app
Rust_App_Files := $(wildcard src/*.rs)
SGX_DEBUG ?=

ifneq ($(SGX_DEBUG), 1)
	TARGET_DIR = release
	BUILD_FLAGS = --release
else
	TARGET_DIR = debug
	BUILD_FLAGS =
endif

ifdef ECDSA
	BUILD_FLAGS += --features=RATLS_ECDSA
else ifdef LA
	BUILD_FLAGS += --features=LA_REPORT
else
	BUILD_FLAGS += --features=RATLS_EPID
endif

.PHONY: all

all: $(Rust_App_Name)

$(Rust_App_Name): $(Rust_App_Files)
	cargo build $(BUILD_FLAGS)
	[ ! -d ../bin ] && mkdir ../bin || true
	cp ./target/$(TARGET_DIR)/inclavared ../bin/
	cp ../../ra-tls/build/bin/Wolfssl_Enclave.signed.so ../bin/

clean:
	@cargo clean
	@rm -f Enclave_u.o libEnclave_u.a 
