extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let sdk_dir = env::var("SGX_SDK")
        .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());

    println!("cargo:rustc-link-search=native=../lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native=../../ra-tls/build/lib");
    println!("cargo:rustc-link-lib=static=wolfssl");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");

    println!("cargo:rerun-if-changed=wrapper.h");

    let wolfssl_bindings = bindgen::Builder::default().disable_name_namespacing()
        .rust_target(bindgen::RustTarget::Nightly)
        .raw_line("// Generated wolfssl trusted codes.")
        .clang_args(
            [
                "-I/opt/intel/sgxsdk/include",
                "-I../rust-sgx/edl",
                "-I../../ra-tls/wolfssl",
                "-I../../ra-tls/sgx-ra-tls",
            ]
            .iter(),
        )
        .header("wrapper.h")
        .blacklist_item("IPPORT_RESERVED")
        .blacklist_item("EXTERNAL_SERIAL_SIZE")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from("./src/ratls");

    wolfssl_bindings
        .write_to_file(out_path.join("generated.rs"))
        .expect("Couldn't write bindings!");
}

