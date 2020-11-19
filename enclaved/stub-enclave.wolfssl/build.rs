extern crate bindgen;

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=static=wolfssl.sgx.static.lib");
    println!("cargo:rustc-link-lib=static=sgx_ra");
    println!("cargo:rustc-link-search=native=../../ra-tls/build/lib");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let ratls_bindings = bindgen::Builder::default().disable_name_namespacing()
        .rust_target(bindgen::RustTarget::Nightly)
        .raw_line("// Generated ra-tls trusted codes.")
        // .raw_line("use sgx_tstd as std;")
        // The input header we would like to generate bindings for.
        .header("wrapper.h")
        .blacklist_item("IPPORT_RESERVED")
        .blacklist_item("EXTERNAL_SERIAL_SIZE")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from("./src/ratls");
    ratls_bindings
        .write_to_file(out_path.join("generated.rs"))
        .expect("Couldn't write bindings!");
}


