use std::process::Command;
use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rustc-link-search=native=/opt/enclave-tls/lib");
    println!("cargo:rustc-link-lib=dylib=enclave_tls");

    println!("cargo:rustc-link-search=native=./src/policyEngine/opa");
    println!("cargo:rustc-link-lib=dylib=opa");

    tonic_build::compile_protos("proto/keyprovider.proto");
}
