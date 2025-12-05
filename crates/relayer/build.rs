// Build script to generate Rust code from Cardano-specific protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the manifest directory (crates/relayer)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let relayer_dir = std::path::PathBuf::from(manifest_dir);
    
    // Navigate up to the root of cardano-ibc-official
    // Path: crates/relayer -> hermes-cardano -> cardano-ibc-official
    let cardano_ibc_root = relayer_dir.parent() // crates
        .and_then(|p| p.parent()) // hermes-cardano (relayer)
        .and_then(|p| p.parent()) // cardano-ibc-official
        .ok_or("Failed to find cardano-ibc-official root")?;
    
    let proto_types_dir = cardano_ibc_root.join("proto-types/protos/ibc-go");
    let cardano_tx_proto = proto_types_dir.join("ibc/cardano/v1/tx.proto");
    
    // Verify the proto file exists
    if !cardano_tx_proto.exists() {
        return Err(format!("Proto file not found: {}", cardano_tx_proto.display()).into());
    }
    
    println!("cargo:rerun-if-changed={}", cardano_tx_proto.display());
    
    // Generate Rust code from the Cardano tx.proto file
    tonic_build::configure()
        .build_server(false) // We're a client, not a server
        .build_client(true)
        .out_dir("src/chain/cardano/generated")
        .compile_protos(&[&cardano_tx_proto], &[&proto_types_dir])?;
    
    Ok(())
}

