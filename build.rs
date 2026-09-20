use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let here = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let protos = ["secret.proto", "session_manager.proto", "accounts.proto"];
    for p in protos {
        println!("cargo:rerun-if-changed={}", here.join(p).display());
    }

    // Messages only (no gRPC code) plus a descriptor set, so the tests can pin
    // the RPC surface as well as the field numbers.
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(out.join("descriptor.bin"));
    config.compile_protos(
        &protos.map(|p| here.join(p)),
        &[here.clone()],
    )?;
    Ok(())
}
