use serde::Serialize;

#[cfg(feature = "namada")]
use super::NamadaKeyPair;
use super::{Ed25519KeyPair, KeyType, Secp256k1KeyPair, SigningKeyPair};
use crate::chain::cardano::CardanoSigningKeyPair;

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AnySigningKeyPair {
    Secp256k1(Secp256k1KeyPair),
    Ed25519(Ed25519KeyPair),
    #[cfg(feature = "namada")]
    Namada(NamadaKeyPair),
    Cardano(CardanoSigningKeyPair),
}

impl AnySigningKeyPair {
    pub fn account(&self) -> String {
        match self {
            Self::Secp256k1(key_pair) => key_pair.account(),
            Self::Ed25519(key_pair) => key_pair.account(),
            #[cfg(feature = "namada")]
            Self::Namada(key_pair) => key_pair.account(),
            Self::Cardano(key_pair) => key_pair.account(),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Secp256k1(_) => Secp256k1KeyPair::KEY_TYPE,
            Self::Ed25519(_) => Ed25519KeyPair::KEY_TYPE,
            #[cfg(feature = "namada")]
            Self::Namada(_) => NamadaKeyPair::KEY_TYPE,
            Self::Cardano(_) => CardanoSigningKeyPair::KEY_TYPE,
        }
    }

    pub fn downcast<T: Clone + 'static>(&self) -> Option<T> {
        match self {
            Self::Secp256k1(key_pair) => key_pair.as_any(),
            Self::Ed25519(key_pair) => key_pair.as_any(),
            #[cfg(feature = "namada")]
            Self::Namada(key_pair) => key_pair.as_any(),
            Self::Cardano(key_pair) => key_pair.as_any(),
        }
        .downcast_ref::<T>()
        .cloned()
    }
}

impl From<Secp256k1KeyPair> for AnySigningKeyPair {
    fn from(key_pair: Secp256k1KeyPair) -> Self {
        Self::Secp256k1(key_pair)
    }
}

impl From<Ed25519KeyPair> for AnySigningKeyPair {
    fn from(key_pair: Ed25519KeyPair) -> Self {
        Self::Ed25519(key_pair)
    }
}

#[cfg(feature = "namada")]
impl From<NamadaKeyPair> for AnySigningKeyPair {
    fn from(key_pair: NamadaKeyPair) -> Self {
        Self::Namada(key_pair)
    }
}

impl From<CardanoSigningKeyPair> for AnySigningKeyPair {
    fn from(key_pair: CardanoSigningKeyPair) -> Self {
        Self::Cardano(key_pair)
    }
}
