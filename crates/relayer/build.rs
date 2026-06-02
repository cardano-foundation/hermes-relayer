fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc not found");
    std::env::set_var("PROTOC", protoc);

    println!("cargo:rerun-if-changed=proto/stellar_gateway.proto");

    prost_build::compile_protos(&["proto/stellar_gateway.proto"], &["proto"])
        .expect("compile stellar_gateway.proto");
}
