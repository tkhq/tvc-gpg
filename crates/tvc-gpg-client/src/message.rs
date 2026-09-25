//! Reading a PGP message far enough to find the packet the app needs.
//!
//! The app never sees the message. It only sees the one public key encrypted
//! session key (PKESK) packet addressed to the team subkey, so this module
//! walks the packets, keeps the PKESKs, and stops at the encrypted data.

use crate::Result;
use pgp::armor::Dearmor;
use pgp::composed::{Deserializable as _, SignedPublicKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{Packet, PacketParser, PacketTrait as _, PublicKeyEncryptedSessionKey};
use pgp::types::{KeyDetails as _, KeyId, Tag};
use std::borrow::Cow;
use std::io::{Read as _, copy, sink};

/// The first line of an armored PGP message.
const ARMOR_HEADER: &[u8] = b"-----BEGIN PGP MESSAGE-----";

/// What to tell a caller whose message uses AEAD.
const AEAD_MESSAGE: &str = "this message uses AEAD encryption, which the app cannot open. The \
    sender most likely ran gpg with force-ocb or a cipher preference that picks OCB. Ask them to \
    send it again without force-ocb.";

/// The raw packet bytes of `message`, dearmored when the message is armored.
///
/// # Errors
///
/// Returns an error if an armored message does not dearmor.
pub fn packet_bytes(message: &[u8]) -> Result<Cow<'_, [u8]>> {
    let start = message
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(message.len());
    let body = &message[start..];
    if !body.starts_with(ARMOR_HEADER) {
        return Ok(Cow::Borrowed(body));
    }
    let mut packets = Vec::new();
    Dearmor::new(body)
        .read_to_end(&mut packets)
        .map_err(|error| format!("the armored message did not decode: {error}"))?;
    Ok(Cow::Owned(packets))
}

/// Every PKESK packet that stands before the encrypted data of `packets`.
///
/// The walk stops at the encrypted data packet and never reads its body, so a
/// large message costs no more memory than its session key packets.
///
/// # Errors
///
/// Returns an error if the packets do not parse, if the encrypted data uses
/// AEAD, or if there is no encrypted data at all.
pub fn session_key_packets(packets: &[u8]) -> Result<Vec<PublicKeyEncryptedSessionKey>> {
    let mut parser = PacketParser::new(packets);
    let mut found = Vec::new();
    while let Some(body) = parser.next_ref() {
        let mut body = body.map_err(|error| format!("the message did not parse: {error}"))?;
        let header = body.packet_header();
        match header.tag() {
            Tag::PublicKeyEncryptedSessionKey => {
                let packet = Packet::from_reader(header, &mut body)
                    .map_err(|error| format!("a session key packet did not parse: {error}"))?;
                if let Packet::PublicKeyEncryptedSessionKey(pkesk) = packet {
                    found.push(pkesk);
                }
            }
            Tag::SymEncryptedProtectedData => {
                let mut version = [0u8; 1];
                body.read_exact(&mut version)
                    .map_err(|error| format!("the encrypted data did not parse: {error}"))?;
                if version[0] != 1 {
                    return Err(AEAD_MESSAGE.into());
                }
                return Ok(found);
            }
            Tag::GnupgAeadData => return Err(AEAD_MESSAGE.into()),
            Tag::SymEncryptedData => {
                return Err(
                    "this message has no integrity protection, so the app will not open \
                    it"
                    .into(),
                );
            }
            _ => {
                copy(&mut body, &mut sink())
                    .map_err(|error| format!("the message did not parse: {error}"))?;
            }
        }
    }
    Err("this message holds no encrypted data".into())
}

/// The key id of the one encryption subkey in an armored certificate.
///
/// # Errors
///
/// Returns an error if the certificate does not parse or does not carry
/// exactly one encryption subkey.
pub fn encryption_subkey_id(armored: &str) -> Result<KeyId> {
    let (certificate, _headers) = SignedPublicKey::from_string(armored)
        .map_err(|error| format!("the app public key did not parse: {error}"))?;
    let mut subkeys = certificate
        .public_subkeys
        .iter()
        .filter(|subkey| subkey.key.algorithm() == PublicKeyAlgorithm::ECDH);
    let subkey = subkeys
        .next()
        .ok_or("the app public key has no encryption subkey")?;
    if subkeys.next().is_some() {
        return Err("the app public key has more than one encryption subkey".into());
    }
    Ok(subkey.key.legacy_key_id())
}

/// The PKESK packet addressed to `key_id`, serialized with its packet header.
///
/// # Errors
///
/// Returns an error if no packet names `key_id` or the packet does not
/// serialize.
pub fn pkesk_for(packets: &[PublicKeyEncryptedSessionKey], key_id: &KeyId) -> Result<Vec<u8>> {
    let pkesk = packets
        .iter()
        .find(|pkesk| pkesk.id().is_ok_and(|id| id == key_id))
        .ok_or("this message is not encrypted to the app key")?;
    let mut bytes = Vec::new();
    pkesk
        .to_writer_with_header(&mut bytes)
        .map_err(|error| format!("the session key packet did not serialize: {error}"))?;
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pgp::composed::{
        EncryptionCaps, KeyType, RawSessionKey, SecretKeyParamsBuilder, SubkeyParamsBuilder,
    };
    use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::packet::{PacketHeader, PacketTrait, PublicSubkey, SymEncryptedProtectedData};
    use pgp::ser::Serialize as _;

    /// A message a real gpg made, and the hex of its PKESK packet. These come
    /// from the server crate's interop fixtures, so they pin the client's
    /// packet walk to bytes the app is known to accept.
    const GPG_MESSAGE: &[u8] = include_bytes!("../../tvc-gpg/fixtures/message.gpg");
    const GPG_PKESK_HEX: &str = include_str!("../../tvc-gpg/fixtures/message.pkesk.hex");
    const GPG_ARMORED: &str = include_str!("../../tvc-gpg/fixtures/sops-datakey.asc");
    const GPG_ARMORED_PKESK_HEX: &str =
        include_str!("../../tvc-gpg/fixtures/sops-datakey.pkesk.hex");
    const TEAM_PUBLIC: &str = include_str!("../../tvc-gpg/fixtures/team-public.asc");

    /// A throwaway P-256 encryption subkey.
    fn encryption_subkey() -> PublicSubkey {
        let key = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .primary_user_id("Test <test@example.com>".to_owned())
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::P256))
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap();
        key.secret_subkeys[0].public_key().clone()
    }

    fn pkesk_to(subkey: &PublicSubkey) -> PublicKeyEncryptedSessionKey {
        PublicKeyEncryptedSessionKey::from_session_key_v3(
            rand::thread_rng(),
            &RawSessionKey::from(vec![0x11; 32]),
            SymmetricKeyAlgorithm::AES256,
            subkey,
        )
        .unwrap()
    }

    /// Append one packet, header included, to a message body.
    fn push(out: &mut Vec<u8>, packet: &impl PacketTrait) {
        packet.to_writer_with_header(out).unwrap();
    }

    fn seipd_v1() -> SymEncryptedProtectedData {
        SymEncryptedProtectedData::encrypt_seipdv1(
            rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            &[0x11; 32],
            b"hello",
        )
        .unwrap()
    }

    /// A packet of `tag` with a body the walk never reads.
    fn raw_packet(tag: Tag, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        PacketHeader::new_fixed(tag, body.len() as u32)
            .to_writer(&mut out)
            .unwrap();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn the_packet_for_the_named_key_is_picked() {
        let wanted = encryption_subkey();
        let other = encryption_subkey();
        let mut bytes = Vec::new();
        push(&mut bytes, &pkesk_to(&other));
        push(&mut bytes, &pkesk_to(&wanted));
        push(&mut bytes, &seipd_v1());

        let packets = session_key_packets(&bytes).unwrap();

        assert_eq!(packets.len(), 2);
        let picked = pkesk_for(&packets, &wanted.legacy_key_id()).unwrap();
        assert_ne!(picked, pkesk_for(&packets, &other.legacy_key_id()).unwrap());
    }

    #[test]
    fn a_message_for_another_key_is_turned_down() {
        let mut bytes = Vec::new();
        push(&mut bytes, &pkesk_to(&encryption_subkey()));
        push(&mut bytes, &seipd_v1());

        let packets = session_key_packets(&bytes).unwrap();
        let error = pkesk_for(&packets, &encryption_subkey().legacy_key_id()).unwrap_err();

        assert!(error.to_string().contains("not encrypted to the app key"));
    }

    #[test]
    fn an_aead_message_names_force_ocb() {
        let seipd = SymEncryptedProtectedData::encrypt_seipdv2(
            rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
            &[0x11; 32],
            b"hello",
        )
        .unwrap();
        let mut bytes = Vec::new();
        push(&mut bytes, &pkesk_to(&encryption_subkey()));
        push(&mut bytes, &seipd);

        let error = session_key_packets(&bytes).unwrap_err();

        assert!(error.to_string().contains("force-ocb"));
    }

    #[test]
    fn the_older_encrypted_data_packets_are_turned_down() {
        // Tag 20 is GnuPG's own AEAD packet, what force-ocb writes on gpg 2.2
        // and 2.4. Tag 9 is symmetrically encrypted data with no integrity
        // protection. Neither body is ever read, so the bytes can be anything.
        for (tag, wanted) in [
            (Tag::GnupgAeadData, "force-ocb"),
            (Tag::SymEncryptedData, "no integrity protection"),
        ] {
            let mut bytes = Vec::new();
            push(&mut bytes, &pkesk_to(&encryption_subkey()));
            bytes.extend_from_slice(&raw_packet(tag, &[0x01, 0x02, 0x03]));

            let error = session_key_packets(&bytes).unwrap_err();

            assert!(
                error.to_string().contains(wanted),
                "{tag:?} did not name {wanted}"
            );
        }
    }

    #[test]
    fn a_message_with_no_encrypted_data_is_turned_down() {
        let mut bytes = Vec::new();
        push(&mut bytes, &pkesk_to(&encryption_subkey()));

        let error = session_key_packets(&bytes).unwrap_err();

        assert!(error.to_string().contains("no encrypted data"));
    }

    #[test]
    fn a_gpg_made_message_gives_back_the_fixture_packet() {
        let key_id = encryption_subkey_id(TEAM_PUBLIC).unwrap();

        for (message, expected) in [
            (GPG_MESSAGE.to_vec(), GPG_PKESK_HEX),
            (GPG_ARMORED.as_bytes().to_vec(), GPG_ARMORED_PKESK_HEX),
        ] {
            let packets = packet_bytes(&message).unwrap();
            let pkesks = session_key_packets(&packets).unwrap();
            assert_eq!(
                qos_hex::encode(&pkesk_for(&pkesks, &key_id).unwrap()),
                expected.trim(),
                "the client did not rebuild the packet gpg wrote"
            );
        }
    }
}
