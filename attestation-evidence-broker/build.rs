use ttrpc_codegen::Codegen;
use ttrpc_codegen::Customize;

fn main() {
    let protos = vec!["src/protocols/protos/aeb.proto"];

    Codegen::new()
        .out_dir("src/protocols/aeb")
        .inputs(&protos)
        .include("src/protocols/protos")
        .rust_protobuf()
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .run()
        .expect("Generate code failed.");
}
