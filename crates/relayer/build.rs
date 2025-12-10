// Build script to generate Rust code from Cardano-specific protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the manifest directory (crates/relayer)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let relayer_dir = std::path::PathBuf::from(manifest_dir);
    
    // Navigate up to the root of cardano-ibc-official
    // Path: crates/relayer -> hermes-cardano (relayer) -> cardano-ibc-official
    let cardano_ibc_root = relayer_dir.parent() // crates
        .and_then(|p| p.parent()) // relayer
        .and_then(|p| p.parent()) // cardano-ibc-official
        .ok_or("Failed to find cardano-ibc-official root")?;
    
    let proto_types_dir = cardano_ibc_root.join("proto-types/protos/ibc-go");
    
    // List of proto files to compile
    let proto_files = vec![
        // Cardano-specific transaction service
        proto_types_dir.join("ibc/cardano/v1/tx.proto"),
        
        // Cardano-specific query service (events)
        proto_types_dir.join("ibc/cardano/v1/query.proto"),
        
        // IBC core types (block results, events)
        proto_types_dir.join("ibc/core/types/v1/block.proto"),
        proto_types_dir.join("ibc/core/types/v1/query.proto"),
        
        // IBC core client query service (includes BlockData, LatestHeight)
        proto_types_dir.join("ibc/core/client/v1/query.proto"),
        
        // IBC core client tx service (CreateClient, UpdateClient)
        proto_types_dir.join("ibc/core/client/v1/tx.proto"),
        
        // IBC core connection tx service (ConnectionOpen*)
        proto_types_dir.join("ibc/core/connection/v1/tx.proto"),
        
        // IBC core channel tx service (ChannelOpen*, RecvPacket, Acknowledgement)
        proto_types_dir.join("ibc/core/channel/v1/tx.proto"),
    ];
    
    // Verify all proto files exist
    for proto_file in &proto_files {
        if !proto_file.exists() {
            return Err(format!("Proto file not found: {}", proto_file.display()).into());
        }
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }
    
    // Generate Rust code from all proto files
    tonic_build::configure()
        .build_server(false) // We're a client, not a server
        .build_client(true)
        .out_dir("src/chain/cardano/generated")
        .compile_protos(&proto_files, &[&proto_types_dir])?;
    
    Ok(())
}

