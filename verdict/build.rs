fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../verdictd/app/proto/configureprovider.proto")?;
    Ok(())
}
