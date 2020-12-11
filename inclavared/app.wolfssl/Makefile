Rust_App_Name := app
Rust_App_Files := $(wildcard src/*.rs)

.PHONY: all

all: $(Rust_App_Name)

$(Rust_App_Name): $(Rust_App_Files)
	cargo build --release
	[ ! -d ../bin ] && mkdir ../bin || true
	cp ./target/release/inclavared ../bin/inclavared

clean:
	@cargo clean
	@rm -f Enclave_u.o libEnclave_u.a 
