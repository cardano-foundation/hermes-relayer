use thiserror::Error;
use tonic::Code;

#[derive(Debug, Error)]
pub enum StellarError {
    #[error("Gateway client error: {0}")]
    GatewayClient(String),

    #[error("Gateway gRPC error ({code}): {message}")]
    GatewayStatus { code: Code, message: String },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Signer error: {0}")]
    Signer(String),

    #[error("XDR decode error: {0}")]
    Decoding(String),

    #[error("Transaction error: {0}")]
    Encoding(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("IBC error: {0}")]
    Ibc(String),

    #[error("Event attribute error: {0}")]
    EventAttribute(String),

    #[error("Generic error: {0}")]
    Transaction(String),

    #[error("StrKey error: {0}")]
    InvalidStrKey(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

impl From<tonic::Status> for StellarError {
    fn from(err: tonic::Status) -> Self {
        StellarError::GatewayStatus {
            code: err.code(),
            message: err.message().to_string(),
        }
    }
}

impl From<tonic::transport::Error> for StellarError {
    fn from(err: tonic::transport::Error) -> Self {
        StellarError::GatewayClient(err.to_string())
    }
}

impl From<std::io::Error> for StellarError {
    fn from(err: std::io::Error) -> Self {
        StellarError::Generic(err.to_string())
    }
}

impl From<serde_json::Error> for StellarError {
    fn from(err: serde_json::Error) -> Self {
        StellarError::Generic(err.to_string())
    }
}
