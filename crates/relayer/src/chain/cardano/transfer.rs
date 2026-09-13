use bech32::FromBase32;

/// The transfer validator refunds to a payment key, so packet senders contain
/// its 28-byte hash. The original enterprise address still authorizes the
/// transaction, and the hash resolves to the same enterprise funding wallet.
pub(super) fn packet_sender_payment_key(sender: &str) -> Result<String, String> {
    let sender = sender.trim();
    let (bytes, prefix) = if sender.starts_with("addr") {
        let (prefix, data, variant) = bech32::decode(sender)
            .map_err(|error| format!("invalid Cardano transfer sender: {error}"))?;
        if !matches!(prefix.as_str(), "addr" | "addr_test") || variant != bech32::Variant::Bech32 {
            return Err("invalid Cardano transfer sender address prefix or encoding".to_string());
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|error| format!("invalid Cardano transfer sender payload: {error}"))?;
        (bytes, Some(prefix))
    } else {
        (
            hex::decode(sender)
                .map_err(|error| format!("invalid Cardano transfer sender: {error}"))?,
            None,
        )
    };

    if prefix.is_none() && bytes.len() == 28 {
        return Ok(hex::encode(bytes));
    }
    let header = bytes
        .first()
        .copied()
        .ok_or("Cardano transfer sender is empty")?;
    if let Some(prefix) = prefix {
        if (prefix == "addr") != (header & 0x0f == 1) {
            return Err("Cardano transfer sender prefix disagrees with its network".to_string());
        }
    }
    match (header >> 4, bytes.len()) {
        (6, 29) => Ok(hex::encode(&bytes[1..29])),
        _ => Err(
            "Cardano transfer sender must be a payment key hash or a key enterprise address"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;

    #[test]
    fn transfer_sender_extracts_only_the_payment_key() {
        let key = "ab".repeat(28);
        assert_eq!(packet_sender_payment_key(&key.to_uppercase()).unwrap(), key);
        for header in [0x60, 0x61] {
            let bytes = [vec![header], vec![0xab; 28]].concat();
            let prefix = if header & 0xf == 1 {
                "addr"
            } else {
                "addr_test"
            };
            let bech32 =
                bech32::encode(prefix, bytes.to_base32(), bech32::Variant::Bech32).unwrap();
            assert_eq!(
                packet_sender_payment_key(&hex::encode(&bytes)).unwrap(),
                key
            );
            assert_eq!(packet_sender_payment_key(&bech32).unwrap(), key);
        }
    }

    #[test]
    fn transfer_sender_rejects_scripts_rewards_and_malformed_addresses() {
        for sender in [
            format!("70{}", "ab".repeat(28)),
            format!("10{}", "ab".repeat(56)),
            format!("e0{}", "ab".repeat(28)),
            format!("00{}", "ab".repeat(56)),
            format!("40{}000000", "ab".repeat(28)),
            format!("60{}", "ab".repeat(26)),
            format!("60{}", "ab".repeat(29)),
            "not-hex".to_string(),
            String::new(),
        ] {
            assert!(packet_sender_payment_key(&sender).is_err(), "{sender}");
        }
        let wrong_prefix = bech32::encode(
            "addr",
            [vec![0x60], vec![0xab; 28]].concat().to_base32(),
            bech32::Variant::Bech32,
        )
        .unwrap();
        assert!(packet_sender_payment_key(&wrong_prefix).is_err());
    }
}
