Rust_App_Name := app
Rust_App_Files := $(wildcard src/*.rs)
SGX_DEBUG ?=

ifdef ECDSA
	BUILD_FLAGS = --features=RATLS_ECDSA
else LA
	BUILD_FLAGS = --features=LA_REPORT
else
	BUILD_FLAGS = --features=RATLS_EPID
endif

.PHONY: all

all: $(Rust_App_Name)

$(Rust_App_Name): $(Rust_App_Files)
ifneq ($(SGX_DEBUG), 1)
	cargo build --release $(BUILD_FLAGS)
else
	cargo build $(BUILD_FLAGS)
endif
	[ ! -d ../bin ] && mkdir ../bin || true
ifneq ($(SGX_DEBUG), 1)
	cp ./target/release/inclavared ../bin/inclavared
else
	cp ./target/debug/inclavared ../bin/inclavared
endif

clean:
	@cargo clean
	@rm -f Enclave_u.o libEnclave_u.a 
