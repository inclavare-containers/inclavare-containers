Rust_App_Name := app
Rust_App_Files := $(wildcard src/*.rs)

.PHONY: all

all: $(Rust_App_Name)

$(Rust_App_Name): $(Rust_App_Files)
	cargo build
	[ ! -d ../bin ] && mkdir ../bin || true
	cp ./target/debug/enclaved-wolfssl ../bin/enclaved.wolfssl

clean:
	@cargo clean
	@rm -f Enclave_u.o libEnclave_u.a 
