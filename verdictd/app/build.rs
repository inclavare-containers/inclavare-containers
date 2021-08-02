use std::process::Command;
use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rustc-link-search=native=/opt/enclave-tls/lib");
    println!("cargo:rustc-link-lib=dylib=enclave_tls");

    println!("cargo:rustc-link-search=native=./src/policyEngine/opa");
    let os = Command::new("uname").output().unwrap();
    let ext = match String::from_utf8_lossy(os.stdout.as_slice())
        .into_owned()
        .trim_end()
        .as_ref()
    {
        "Darwin" => "dylib",
        _ => "so",
    };

    let root = Path::new("./src/policyEngine/opa");
    env::set_current_dir(&root).unwrap();

    Command::new("go")
        .args(&[
            "build",
            "-o",
            &format!("libopa.{}", ext),
            "-buildmode=c-shared",
            "opaEngine.go",
        ])
        .status()
        .unwrap();

    let root = Path::new("../../../");
    env::set_current_dir(&root).unwrap();

    tonic_build::compile_protos("proto/keyprovider.proto");
}
