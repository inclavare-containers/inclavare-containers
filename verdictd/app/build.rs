
fn main() {
    println!("cargo:rustc-link-search=native=/opt/enclave-tls/lib");
    println!("cargo:rustc-link-lib=dylib=enclave_tls");
}