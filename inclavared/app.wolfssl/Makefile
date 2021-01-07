Rust_App_Name := app
Rust_App_Files := $(wildcard src/*.rs)
SGX_DEBUG ?=

.PHONY: all

all: $(Rust_App_Name)

$(Rust_App_Name): $(Rust_App_Files)
ifneq ($(SGX_DEBUG), 1)
	cargo build --release
else
	cargo build
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
