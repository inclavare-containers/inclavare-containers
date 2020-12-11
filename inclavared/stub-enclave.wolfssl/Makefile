Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
Rust_Target_Path := $(CURDIR)/../../../xargo
SGX_DEBUG ?=

ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
export MITIGATION_CVE_2020_0551=LOAD
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
export MITIGATION_CVE_2020_0551=CF
endif

.PHONY: all

all: $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
ifeq ($(XARGO_SGX), 1)
	RUST_TARGET_PATH=$(Rust_Target_Path) xargo build --target x86_64-unknown-linux-sgx
ifneq ($(SGX_DEBUG), 1)
	cp ./target/x86_64-unknown-linux-sgx/release/libhelloworldsampleenclave.a ../lib/libenclave.a
else
	cp ./target/x86_64-unknown-linux-sgx/debug/libhelloworldsampleenclave.a ../lib/libenclave.a
endif
else
ifneq ($(SGX_DEBUG), 1)
	C_INCLUDE_PATH="../../ra-tls/wolfssl:/opt/intel/sgxsdk/include" cargo build --release
	cp ./target/release/libstubenclave.a ../lib/libenclave.a
else
	C_INCLUDE_PATH="../../ra-tls/wolfssl:/opt/intel/sgxsdk/include" cargo build
	cp ./target/debug/libstubenclave.a ../lib/libenclave.a
endif
endif

test:
	@C_INCLUDE_PATH="../../ra-tls/wolfssl:/opt/intel/sgxsdk/include" cargo test

clean:
	@cargo clean
	@rm -f Enclave_t.o enclave.so

