//! gRPC client for Cardano Gateway

use super::error::Error;
use super::types::{CardanoClientState, CardanoConsensusState, CardanoHeader};
use ibc_relayer_types::Height;
use tonic::transport::Channel;

/// Client for communicating with Cardano Gateway
#[derive(Clone)]
pub struct GatewayClient {
    endpoint: String,
    #[allow(dead_code)]
    channel: Option<Channel>,
}

impl GatewayClient {
    /// Create a new Gateway client
    pub async fn new(endpoint: String) -> Result<Self, Error> {
        // For now, just store the endpoint
        // Full gRPC client will be implemented once proto definitions are integrated
        tracing::info!("Connecting to Cardano Gateway at {}", endpoint);
        
        Ok(Self {
            endpoint,
            channel: None,
        })
    }

    /// Query the latest block height
    pub async fn query_latest_height(&self) -> Result<Height, Error> {
        // Stub implementation
        tracing::warn!("query_latest_height: using stub implementation");
        Ok(Height::new(0, 1000).map_err(|e| Error::Query(e.to_string()))?)
    }

    /// Query client state
    pub async fn query_client_state(&self, client_id: &str) -> Result<CardanoClientState, Error> {
        // Stub implementation
        tracing::warn!("query_client_state: using stub implementation for {}", client_id);
        Ok(CardanoClientState::new(
            "cardano-test".to_string(),
            Height::new(0, 1000).map_err(|e| Error::Query(e.to_string()))?,
            86400,  // 1 day trusting period
            1814400,  // 21 days unbonding period
            vec![0u8; 32],  // placeholder genesis vkey
        ))
    }

    /// Query consensus state
    pub async fn query_consensus_state(
        &self,
        client_id: &str,
        height: Height,
    ) -> Result<CardanoConsensusState, Error> {
        tracing::warn!(
            "query_consensus_state: using stub implementation for {} at height {}",
            client_id,
            height
        );
        Ok(CardanoConsensusState::new(
            vec![0u8; 32],  // placeholder root
            0,  // timestamp
            0,  // slot
            0,  // epoch
        ))
    }

    /// Query header at a specific height
    pub async fn query_header(&self, height: Height) -> Result<CardanoHeader, Error> {
        tracing::warn!("query_header: using stub implementation for height {}", height);
        Ok(CardanoHeader::new(
            height,
            vec![0u8; 32],  // placeholder block hash
            0,  // timestamp
            0,  // slot
            0,  // epoch
        ))
    }

    /// Build an unsigned transaction
    pub async fn build_transaction(&self, _messages: Vec<u8>) -> Result<Vec<u8>, Error> {
        tracing::warn!("build_transaction: using stub implementation");
        Ok(vec![])
    }

    /// Submit a signed transaction
    pub async fn submit_signed_transaction(&self, signed_tx_cbor: &[u8]) -> Result<String, Error> {
        tracing::warn!(
            "submit_signed_transaction: using stub implementation (tx size: {} bytes)",
            signed_tx_cbor.len()
        );
        Ok("stub_tx_hash".to_string())
    }

    /// Get the Gateway endpoint URL
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gateway_client_creation() {
        let client = GatewayClient::new("http://localhost:3001".to_string())
            .await
            .unwrap();
        assert_eq!(client.endpoint(), "http://localhost:3001");
    }

    #[tokio::test]
    async fn test_stub_queries() {
        let client = GatewayClient::new("http://localhost:3001".to_string())
            .await
            .unwrap();

        // Test that stub implementations don't panic
        let height = client.query_latest_height().await.unwrap();
        assert!(height.revision_height() > 0);

        let client_state = client.query_client_state("test-client").await.unwrap();
        assert_eq!(client_state.chain_id.to_string(), "cardano-test");
    }
}

