use std::sync::Arc;

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, ClientId, PortId};
use ibc_relayer_types::tx_msg::Msg;
use ibc_relayer_types::Height as ICSHeight;
use prost::Message;

use crate::chain::handle::ChainHandle;
use crate::chain::requests::{
    IncludeProof, QueryHeight, QueryPacketAcknowledgementRequest, QueryPacketCommitmentRequest,
    QueryPacketReceiptRequest,
};
use crate::chain::tracking::{TrackedMsgs, TrackingId};
use crate::event::IbcEventWithHeight;
use crate::foreign_client::ForeignClient;

use super::stellar_packet::{
    AckProofSource, ClientUpdater, PacketAbsenceProofSource, PacketProofError, PacketProofSource,
    PacketRelayDestination, SubmitError,
};

pub struct ChainHandleProofSource<H: ChainHandle> {
    handle: Arc<H>,
    port_id: PortId,
}

impl<H: ChainHandle> ChainHandleProofSource<H> {
    pub fn new(handle: Arc<H>) -> Self {
        Self {
            handle,
            port_id: PortId::transfer(),
        }
    }

    pub fn with_port_id(handle: Arc<H>, port_id: PortId) -> Self {
        Self { handle, port_id }
    }
}

impl<H: ChainHandle> PacketAbsenceProofSource for ChainHandleProofSource<H> {
    fn packet_receipt_absence_proof(
        &self,
        dest_client_id: &str,
        sequence: u64,
    ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
        let status = self
            .handle
            .query_application_status()
            .map_err(|e| PacketProofError::QueryFailed(format!("query_application_status: {e}")))?;
        let channel_id: ChannelId = dest_client_id
            .parse()
            .map_err(|e| PacketProofError::QueryFailed(format!("dest_client_id parse: {e}")))?;
        let req = QueryPacketReceiptRequest {
            port_id: self.port_id.clone(),
            channel_id,
            sequence: Sequence::from(sequence),
            height: QueryHeight::Specific(status.height),
        };
        let (receipt, proof) = self
            .handle
            .query_packet_receipt(req, IncludeProof::Yes)
            .map_err(|e| PacketProofError::QueryFailed(format!("query_packet_receipt: {e}")))?;
        if !receipt.is_empty() {
            return Err(PacketProofError::QueryFailed(format!(
                "receipt present at {dest_client_id}/{sequence}: cannot prove absence"
            )));
        }
        let proof = proof.ok_or_else(|| {
            PacketProofError::QueryFailed(
                "chain did not return a non-membership MerkleProof".to_string(),
            )
        })?;
        Ok((encode_merkle_proof(&proof), status.height))
    }
}

impl<H: ChainHandle> PacketProofSource for ChainHandleProofSource<H> {
    fn packet_commitment_proof(
        &self,
        client_id: &str,
        sequence: u64,
    ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
        let status = self
            .handle
            .query_application_status()
            .map_err(|e| PacketProofError::QueryFailed(format!("query_application_status: {e}")))?;

        let channel_id: ChannelId = client_id
            .parse()
            .map_err(|e| PacketProofError::QueryFailed(format!("client_id parse: {e}")))?;
        let req = QueryPacketCommitmentRequest {
            port_id: self.port_id.clone(),
            channel_id,
            sequence: Sequence::from(sequence),
            height: QueryHeight::Specific(status.height),
        };
        let (commitment, proof) = self
            .handle
            .query_packet_commitment(req, IncludeProof::Yes)
            .map_err(|e| PacketProofError::QueryFailed(format!("query_packet_commitment: {e}")))?;

        if commitment.is_empty() {
            return Err(PacketProofError::CommitmentAbsent {
                client_id: client_id.to_string(),
                sequence,
                height: status.height.revision_height(),
            });
        }
        let proof = proof.ok_or_else(|| {
            PacketProofError::QueryFailed("chain did not return a MerkleProof".to_string())
        })?;
        let proof_bytes = encode_merkle_proof(&proof);
        Ok((proof_bytes, status.height))
    }
}

impl<H: ChainHandle> AckProofSource for ChainHandleProofSource<H> {
    fn acknowledgement_proof(
        &self,
        dest_client_id: &str,
        sequence: u64,
    ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
        let status = self
            .handle
            .query_application_status()
            .map_err(|e| PacketProofError::QueryFailed(format!("query_application_status: {e}")))?;

        let channel_id: ChannelId = dest_client_id
            .parse()
            .map_err(|e| PacketProofError::QueryFailed(format!("dest_client_id parse: {e}")))?;
        let req = QueryPacketAcknowledgementRequest {
            port_id: self.port_id.clone(),
            channel_id,
            sequence: Sequence::from(sequence),
            height: QueryHeight::Specific(status.height),
        };
        let (ack, proof) = self
            .handle
            .query_packet_acknowledgement(req, IncludeProof::Yes)
            .map_err(|e| {
                PacketProofError::QueryFailed(format!("query_packet_acknowledgement: {e}"))
            })?;

        if ack.is_empty() {
            return Err(PacketProofError::QueryFailed(format!(
                "acknowledgement absent at {dest_client_id}/{sequence}"
            )));
        }
        let proof = proof.ok_or_else(|| {
            PacketProofError::QueryFailed(
                "chain did not return an acknowledgement MerkleProof".to_string(),
            )
        })?;
        Ok((encode_merkle_proof(&proof), status.height))
    }
}

pub struct ChainHandleDestination<H: ChainHandle> {
    handle: Arc<H>,
}

impl<H: ChainHandle> ChainHandleDestination<H> {
    pub fn new(handle: Arc<H>) -> Self {
        Self { handle }
    }
}

impl<H: ChainHandle> PacketRelayDestination for ChainHandleDestination<H> {
    fn submit(&self, msgs: Vec<Any>) -> Result<Vec<IbcEventWithHeight>, SubmitError> {
        let tracked = TrackedMsgs {
            msgs,
            tracking_id: TrackingId::new_static("stellar-packet-relay"),
        };
        self.handle
            .send_messages_and_wait_commit(tracked)
            .map_err(|e| SubmitError::SubmitFailed(format!("send_messages_and_wait_commit: {e}")))
    }
}

pub struct ForeignClientUpdater<Dst: ChainHandle, Src: ChainHandle> {
    dst: Arc<Dst>,
    src: Arc<Src>,
}

impl<Dst: ChainHandle, Src: ChainHandle> ForeignClientUpdater<Dst, Src> {
    pub fn new(dst: Arc<Dst>, src: Arc<Src>) -> Self {
        Self { dst, src }
    }
}

impl<Dst: ChainHandle, Src: ChainHandle> ClientUpdater for ForeignClientUpdater<Dst, Src> {
    fn build_update(
        &self,
        dest_client_id: &str,
        target_height: ICSHeight,
    ) -> Result<Vec<Any>, String> {
        let client_id: ClientId = dest_client_id
            .parse()
            .map_err(|e| format!("dest client id parse: {e}"))?;

        let foreign_client =
            ForeignClient::restore(client_id, (*self.dst).clone(), (*self.src).clone());

        let msgs = foreign_client
            .build_update_client_with_trusted(target_height, None)
            .map_err(|e| format!("build update client: {e}"))?;

        Ok(msgs.into_iter().map(|m| m.to_any()).collect())
    }
}

fn encode_merkle_proof(proof: &MerkleProof) -> Vec<u8> {
    let raw: RawMerkleProof = proof.clone().into();
    raw.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_proto::ics23::{
        commitment_proof::Proof, CommitmentProof, ExistenceProof, HashOp, LeafOp,
    };

    fn sample_proof() -> MerkleProof {
        let cp = CommitmentProof {
            proof: Some(Proof::Exist(ExistenceProof {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
                leaf: Some(LeafOp {
                    hash: HashOp::Sha256 as i32,
                    prehash_key: HashOp::NoHash as i32,
                    prehash_value: HashOp::NoHash as i32,
                    length: 0,
                    prefix: Vec::new(),
                }),
                path: vec![],
            })),
        };
        MerkleProof { proofs: vec![cp] }
    }

    #[test]
    fn encode_merkle_proof_round_trips() {
        let proof = sample_proof();
        let bytes = encode_merkle_proof(&proof);
        assert!(!bytes.is_empty());

        let decoded = RawMerkleProof::decode(bytes.as_slice()).unwrap();
        let back: MerkleProof = decoded.into();
        assert_eq!(back.proofs.len(), 1);
        match back.proofs[0].proof.as_ref().unwrap() {
            Proof::Exist(e) => {
                assert_eq!(e.key, b"k");
                assert_eq!(e.value, b"v");
            }
            other => panic!("expected ExistenceProof, got {other:?}"),
        }
    }

    #[test]
    fn encode_merkle_proof_empty_proofs_encodes_to_empty_bytes() {
        let empty = MerkleProof { proofs: vec![] };
        let bytes = encode_merkle_proof(&empty);
        assert!(bytes.is_empty(), "empty proofs prost-encodes to zero bytes");
    }
}
