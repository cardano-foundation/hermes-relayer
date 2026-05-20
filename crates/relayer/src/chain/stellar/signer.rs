use sha2::{Digest, Sha256};

use super::error::StellarError;
use super::signing_key_pair::StellarSigningKeyPair;
use crate::keyring::SigningKeyPair;

const ENVELOPE_TYPE_TX: [u8; 4] = [0, 0, 0, 2];

pub fn stellar_tx_hash(network_passphrase: &str, tx_xdr: &[u8]) -> [u8; 32] {
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
    let mut hasher = Sha256::new();
    hasher.update(network_id);
    hasher.update(ENVELOPE_TYPE_TX);
    hasher.update(tx_xdr);
    hasher.finalize().into()
}

pub fn sign_tx(
    key_pair: &StellarSigningKeyPair,
    network_passphrase: &str,
    tx_xdr: &[u8],
) -> Result<([u8; 4], [u8; 64]), StellarError> {
    let hash = stellar_tx_hash(network_passphrase, tx_xdr);
    let sig_bytes = key_pair
        .sign(&hash)
        .map_err(|e| StellarError::Signer(e.to_string()))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| StellarError::Signer("signature is not 64 bytes".to_owned()))?;
    Ok((key_pair.key_hint(), sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN";
    const PASSPHRASE: &str = "Test SDF Network ; September 2015";

    #[test]
    fn sign_tx_produces_valid_output() {
        let kp = StellarSigningKeyPair::from_strkey(SECRET).unwrap();
        let (hint, sig) = sign_tx(&kp, PASSPHRASE, b"fake_tx_xdr").unwrap();
        assert_eq!(hint.len(), 4);
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = stellar_tx_hash(PASSPHRASE, b"tx");
        let h2 = stellar_tx_hash(PASSPHRASE, b"tx");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_passphrase_different_hash() {
        let h1 = stellar_tx_hash("Net A", b"tx");
        let h2 = stellar_tx_hash("Net B", b"tx");
        assert_ne!(h1, h2);
    }
}
