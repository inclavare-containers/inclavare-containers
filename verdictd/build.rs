fn main() -> shadow_rs::SdResult<()> {
    println!("cargo:rustc-link-search=native=/usr/local/lib/rats-tls");
    println!("cargo:rustc-link-lib=dylib=rats_tls");

    println!("cargo:rustc-link-search=native=./src/policy_engine/opa");
    println!("cargo:rustc-link-lib=dylib=opa");

    tonic_build::compile_protos("proto/keyprovider.proto")?;
    tonic_build::compile_protos("proto/clientapi.proto")?;

    shadow_rs::new()
}
