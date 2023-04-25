use ttrpc_codegen::Codegen;

extern crate cc;

fn main() {
    let protos = vec!["../src/protocols/protos/aeb.proto"];

    Codegen::new()
        .out_dir("src/sev_aeb")
        .inputs(&protos)
        .include("../src/protocols/protos/")
        .rust_protobuf()
        .run()
        .expect("Generate code failed.");

    cc::Build::new()
        .file("src/do_hypercall.c")
        .compile("do_hypercall.a");
}
