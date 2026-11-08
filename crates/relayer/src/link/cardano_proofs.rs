//! Reuse available Cosmos states for work already ready to reach Cardano.
use super::*;

use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentProofBytes;
use ibc_relayer_types::proofs::Proofs;
use sha2::{Digest, Sha256};

use crate::chain::requests::QueryPacketAcknowledgementRequest;

impl<ChainA: ChainHandle, ChainB: ChainHandle> RelayPath<ChainA, ChainB> {
    pub(super) fn reuse_cardano_proof_heights(&self, operations: &mut VecDeque<OperationalData>) {
        if operations.is_empty()
            || !matches!(self.dst_chain().config(), Ok(ChainConfig::Cardano(_)))
            || !matches!(self.src_chain().config(), Ok(ChainConfig::CosmosSdk(_)))
        {
            return;
        }

        let Some(minimum) = operations
            .iter()
            .filter(|operation| eligible(operation))
            .filter_map(required_query_height)
            .min()
        else {
            return;
        };
        let Ok(source) = self.src_chain().query_application_status() else {
            return;
        };
        let Ok(available_query_height) = source.height.decrement() else {
            return;
        };
        if available_query_height < minimum {
            return;
        }
        let Ok(destination) = self.dst_chain().query_application_status() else {
            return;
        };
        let client = ForeignClient::restore(
            self.dst_client_id().clone(),
            self.dst_chain().clone(),
            self.src_chain().clone(),
        );
        let Ok(retained) = client.retained_proof_heights(minimum.increment(), source.height) else {
            // Discovery is an optimization. Normal dispatch still applies the
            // existing frozen/expired-client and update checks.
            return;
        };
        let mut candidates: Vec<_> = retained.into_iter().map(|height| (height, true)).collect();
        candidates.extend(
            client
                .in_flight_update_heights()
                .into_iter()
                .filter(|height| *height >= minimum.increment() && *height <= source.height)
                .map(|height| (height, false)),
        );
        candidates.push((source.height, false));

        let mut selected = vec![false; operations.len()];
        for (header_height, retained) in candidates {
            let Ok(query_height) = header_height.decrement() else {
                continue;
            };
            for (index, operation) in operations.iter_mut().enumerate() {
                if selected[index]
                    || !eligible(operation)
                    || required_query_height(operation).is_none_or(|minimum| {
                        minimum.revision_number() != query_height.revision_number()
                            || minimum > query_height
                    })
                    // A new root would restart a connection delay. Only reuse
                    // a retained root whose own delay has already elapsed.
                    || (operation.conn_delay_needed() && !retained)
                {
                    continue;
                }
                match self.reprove_cardano_operation(operation, query_height, &destination) {
                    Ok(Some(rebuilt)) => {
                        debug!(from = %operation.proofs_height, to = %query_height,
                            retained, "reusing Cardano packet proof height");
                        *operation = rebuilt;
                        selected[index] = true;
                    }
                    Ok(None) => {}
                    Err(error) => debug!(%error, %query_height,
                        "keeping original packet proofs after reuse failed"),
                }
            }
        }
    }

    fn reprove_cardano_operation(
        &self,
        operation: &OperationalData,
        query_height: Height,
        destination: &ChainStatus,
    ) -> Result<Option<OperationalData>, LinkError> {
        let mut rebuilt = operation.clone();
        rebuilt.proofs_height = query_height;
        if operation.conn_delay_needed() && operation.proofs_height != query_height {
            let processed = Self::update_height(
                self.dst_chain(),
                self.dst_client_id().clone(),
                rebuilt.client_update_height(self)?,
            )?;
            rebuilt.set_update_height(processed);
            rebuilt.set_scheduled_time(self.dst_time_at_height(processed)?);
            if !rebuilt.has_conn_delay_elapsed(
                &|| self.dst_time_latest(),
                &|| self.dst_max_block_time(),
                &|| self.dst_latest_height(),
            )? {
                return Ok(None);
            }
        }

        rebuilt.batch.clear();

        for transit in &operation.batch {
            let (value, proof, expected) = match &transit.event_with_height.event {
                IbcEvent::SendPacket(event) => {
                    if event
                        .packet
                        .timed_out(&destination.timestamp, destination.height)
                        || self.send_packet_event_handled(event)?
                    {
                        return Ok(None);
                    }
                    let (value, proof) = self
                        .src_chain()
                        .query_packet_commitment(
                            QueryPacketCommitmentRequest {
                                port_id: event.packet.source_port.clone(),
                                channel_id: event.packet.source_channel.clone(),
                                sequence: event.packet.sequence,
                                height: QueryHeight::Specific(query_height),
                            },
                            IncludeProof::Yes,
                        )
                        .map_err(LinkError::relayer)?;
                    (value, proof, packet_commitment(&event.packet))
                }
                IbcEvent::WriteAcknowledgement(event) => {
                    if self.write_ack_event_handled(event)? {
                        return Ok(None);
                    }
                    let (value, proof) = self
                        .src_chain()
                        .query_packet_acknowledgement(
                            QueryPacketAcknowledgementRequest {
                                port_id: event.packet.destination_port.clone(),
                                channel_id: event.packet.destination_channel.clone(),
                                sequence: event.packet.sequence,
                                height: QueryHeight::Specific(query_height),
                            },
                            IncludeProof::Yes,
                        )
                        .map_err(LinkError::relayer)?;
                    (value, proof, Sha256::digest(&event.ack).to_vec())
                }
                _ => return Ok(None),
            };
            // A height that covers an event may still have no leaf, for example
            // after commitment deletion or a rollback. Never relabel an old proof.
            let Some(proof) = proof.filter(|_| value == expected) else {
                return Ok(None);
            };
            let proofs = Proofs::new(
                CommitmentProofBytes::try_from(proof).map_err(|error| {
                    LinkError::relayer(crate::error::Error::malformed_proof(error))
                })?,
                None,
                None,
                None,
                None,
                rebuilt.client_update_height(self)?,
            )
            .map_err(|error| LinkError::relayer(crate::error::Error::malformed_proof(error)))?;
            let signer = self.dst_signer()?;
            let msg = match &transit.event_with_height.event {
                IbcEvent::SendPacket(event) => {
                    MsgRecvPacket::new(event.packet.clone(), proofs, signer).to_any()
                }
                IbcEvent::WriteAcknowledgement(event) => MsgAcknowledgement::new(
                    event.packet.clone(),
                    event.ack.clone().into(),
                    proofs,
                    signer,
                )
                .to_any(),
                _ => unreachable!(),
            };
            rebuilt.batch.push(TransitMessage {
                event_with_height: transit.event_with_height.clone(),
                msg,
            });
        }
        Ok(Some(rebuilt))
    }

    /// Give the Cardano adapter all compatible ready ACKs in one request. It
    /// chooses independent lane pairs using the pinned signing policy.
    pub(super) fn pack_cardano_acknowledgements(
        &self,
        operations: VecDeque<OperationalData>,
    ) -> VecDeque<OperationalData> {
        if !self.unordered_channel()
            || !matches!(self.dst_chain().config(), Ok(ChainConfig::Cardano(_)))
        {
            return operations;
        }
        let mut packed: VecDeque<OperationalData> = VecDeque::new();
        for operation in operations {
            if successful_acknowledgements(&operation) {
                if let Some(group) = packed.iter_mut().find(|group| {
                    group.proofs_height == operation.proofs_height
                        && successful_acknowledgements(group)
                }) {
                    group.batch.extend(operation.batch);
                    continue;
                }
            }
            packed.push_back(operation);
        }
        packed
    }
}

fn eligible(operation: &OperationalData) -> bool {
    operation.target == OperationalDataTarget::Destination
        && !operation.batch.is_empty()
        && operation.batch.iter().all(|transit| {
            matches!(
                transit.event_with_height.event,
                IbcEvent::SendPacket(_) | IbcEvent::WriteAcknowledgement(_)
            )
        })
}

fn required_query_height(operation: &OperationalData) -> Option<Height> {
    operation
        .batch
        .iter()
        .map(|transit| transit.event_with_height.height)
        .max()
}

fn successful_acknowledgements(operation: &OperationalData) -> bool {
    eligible(operation)
        && operation.batch.iter().all(|transit| {
            matches!(&transit.event_with_height.event,
                IbcEvent::WriteAcknowledgement(event) if event.ack == b"{\"result\":\"AQ==\"}")
        })
}

fn packet_commitment(packet: &Packet) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(packet.timeout_timestamp.nanoseconds().to_be_bytes());
    let height = packet.timeout_height.commitment_revision_number();
    hash.update(height.to_be_bytes());
    hash.update(
        packet
            .timeout_height
            .commitment_revision_height()
            .to_be_bytes(),
    );
    hash.update(Sha256::digest(&packet.data));
    hash.finalize().to_vec()
}

#[cfg(test)]
#[path = "cardano_proofs_test.rs"]
mod tests;
