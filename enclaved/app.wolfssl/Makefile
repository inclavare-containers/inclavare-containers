Rust_App_Name := app
Rust_App_Files := $(wildcard src/*.rs)

.PHONY: all

all: $(Rust_App_Name)

$(Rust_App_Name): $(Rust_App_Files)
	C_INCLUDE_PATH="/opt/intel/sgxsdk/include:../rust-sgx/edl:../../ra-tls/wolfssl:../../ra-tls/sgx-ra-tls" cargo build --release
	cp ./target/release/enclaved-wolfssl ../bin/enclaved.wolfssl

clean:
	@cargo clean
