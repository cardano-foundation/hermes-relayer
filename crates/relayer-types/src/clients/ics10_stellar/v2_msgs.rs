use ibc_proto::google::protobuf::Any;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

pub const TYPE_URL_REGISTER_COUNTERPARTY: &str = "/ibc.core.client.v2.MsgRegisterCounterparty";
pub const TYPE_URL_RECV_PACKET: &str = "/ibc.core.channel.v2.MsgRecvPacket";
pub const TYPE_URL_ACKNOWLEDGEMENT: &str = "/ibc.core.channel.v2.MsgAcknowledgement";
pub const TYPE_URL_TIMEOUT: &str = "/ibc.core.channel.v2.MsgTimeout";
pub const TYPE_URL_SUBMIT_MISBEHAVIOUR: &str = "/ibc.core.client.v1.MsgSubmitMisbehaviour";

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct Height {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct Payload {
    #[prost(string, tag = "1")]
    pub source_port: String,
    #[prost(string, tag = "2")]
    pub dest_port: String,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(string, tag = "4")]
    pub encoding: String,
    #[prost(bytes = "vec", tag = "5")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct Packet {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(string, tag = "2")]
    pub source_client: String,
    #[prost(string, tag = "3")]
    pub dest_client: String,
    #[prost(uint64, tag = "4")]
    pub timeout_timestamp: u64,
    #[prost(message, repeated, tag = "5")]
    pub payloads: Vec<Payload>,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct MsgRegisterCounterparty {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub counterparty_commitment_prefix: Vec<Vec<u8>>,
    #[prost(string, tag = "3")]
    pub counterparty_client_id: String,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct MsgRecvPacket {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_commitment: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: Option<Height>,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct MsgAcknowledgement {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub acknowledgements: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub proof_acked: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub proof_height: Option<Height>,
    #[prost(string, tag = "5")]
    pub signer: String,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct MsgTimeout {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_unreceived: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: Option<Height>,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct MsgSubmitMisbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(message, optional, tag = "2")]
    pub misbehaviour: Option<Any>,
    #[prost(string, tag = "3")]
    pub signer: String,
}

macro_rules! impl_any_round_trip {
    ($msg:ty, $url:expr) => {
        impl From<$msg> for Any {
            fn from(value: $msg) -> Self {
                Any {
                    type_url: $url.to_string(),
                    value: value.encode_to_vec(),
                }
            }
        }

        impl TryFrom<Any> for $msg {
            type Error = prost::DecodeError;
            fn try_from(any: Any) -> Result<Self, Self::Error> {
                if any.type_url != $url {
                    return Err(prost::DecodeError::new(format!(
                        "type_url mismatch: expected {} got {}",
                        $url, any.type_url
                    )));
                }
                <$msg as prost::Message>::decode(any.value.as_slice())
            }
        }
    };
}

impl_any_round_trip!(MsgRegisterCounterparty, TYPE_URL_REGISTER_COUNTERPARTY);
impl_any_round_trip!(MsgRecvPacket, TYPE_URL_RECV_PACKET);
impl_any_round_trip!(MsgAcknowledgement, TYPE_URL_ACKNOWLEDGEMENT);
impl_any_round_trip!(MsgTimeout, TYPE_URL_TIMEOUT);
impl_any_round_trip!(MsgSubmitMisbehaviour, TYPE_URL_SUBMIT_MISBEHAVIOUR);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_counterparty_round_trips_through_any() {
        let m = MsgRegisterCounterparty {
            client_id: "10-stellar-0".into(),
            counterparty_client_id: "07-tendermint-0".into(),
            counterparty_commitment_prefix: vec![b"ibc".to_vec()],
            signer: "cosmos1abc".into(),
        };
        let any: Any = m.clone().into();
        assert_eq!(any.type_url, TYPE_URL_REGISTER_COUNTERPARTY);
        let back = MsgRegisterCounterparty::try_from(any).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn recv_packet_round_trips_through_any() {
        let m = MsgRecvPacket {
            packet: Some(Packet {
                sequence: 7,
                source_client: "07-tendermint-0".into(),
                dest_client: "10-stellar-0".into(),
                timeout_timestamp: 2_000,
                payloads: vec![Payload {
                    source_port: "transfer".into(),
                    dest_port: "transfer".into(),
                    version: "ics20-2".into(),
                    encoding: "xdr".into(),
                    value: vec![1, 2, 3],
                }],
            }),
            proof_commitment: vec![0xAA; 64],
            proof_height: Some(Height {
                revision_number: 0,
                revision_height: 42,
            }),
            signer: "cosmos1xyz".into(),
        };
        let any: Any = m.clone().into();
        assert_eq!(any.type_url, TYPE_URL_RECV_PACKET);
        let back = MsgRecvPacket::try_from(any).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn acknowledgement_round_trips_through_any() {
        let m = MsgAcknowledgement {
            packet: Some(Packet {
                sequence: 3,
                source_client: "10-stellar-0".into(),
                dest_client: "07-tendermint-0".into(),
                timeout_timestamp: 5_000,
                payloads: vec![],
            }),
            acknowledgements: vec![vec![0x01], vec![0x02]],
            proof_acked: vec![0xBB; 32],
            proof_height: Some(Height {
                revision_number: 0,
                revision_height: 99,
            }),
            signer: String::new(),
        };
        let any: Any = m.clone().into();
        assert_eq!(any.type_url, TYPE_URL_ACKNOWLEDGEMENT);
        assert_eq!(MsgAcknowledgement::try_from(any).unwrap(), m);
    }

    #[test]
    fn timeout_round_trips_through_any() {
        let m = MsgTimeout {
            packet: Some(Packet::default()),
            proof_unreceived: vec![0xCC; 16],
            proof_height: Some(Height::default()),
            signer: "rly".into(),
        };
        let any: Any = m.clone().into();
        assert_eq!(any.type_url, TYPE_URL_TIMEOUT);
        assert_eq!(MsgTimeout::try_from(any).unwrap(), m);
    }

    #[test]
    fn submit_misbehaviour_round_trips_through_any() {
        let m = MsgSubmitMisbehaviour {
            client_id: "10-stellar-0".into(),
            misbehaviour: Some(Any {
                type_url: "/ibc.lightclients.stellar.v1.Misbehaviour".into(),
                value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }),
            signer: "cosmos1m".into(),
        };
        let any: Any = m.clone().into();
        assert_eq!(any.type_url, TYPE_URL_SUBMIT_MISBEHAVIOUR);
        assert_eq!(MsgSubmitMisbehaviour::try_from(any).unwrap(), m);
    }

    #[test]
    fn type_url_mismatch_rejects() {
        let any = Any {
            type_url: "/ibc.core.client.v1.MsgCreateClient".into(),
            value: vec![],
        };
        let err = MsgRecvPacket::try_from(any).unwrap_err();
        assert!(err.to_string().contains("type_url mismatch"));
    }
}
