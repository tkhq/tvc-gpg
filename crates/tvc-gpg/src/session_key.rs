//! Release of a PGP session key to an allowlisted engineer.
//!
//! A caller signs a small JSON payload with their own GPG key and posts it
//! with the PKESK packet from the message they want to read. The app verifies
//! the signature over the exact bytes it received, checks the payload, opens
//! the PKESK with the team encryption subkey, and hands the session key back
//! wrapped to the caller's one time transport key.
//!
//! Every failure from PKESK parsing onward returns one fixed body, so an
//! allowlisted caller cannot use the error text as a format oracle against the
//! subkey. Earlier steps return their own fixed text, because the caller needs
//! to tell clock skew from a key the app does not know.
//!
//! Two limits on that oracle claim. The bodies are identical but the timing is
//! not: a bad ephemeral point fails before any scalar multiplication, while a
//! bad ciphertext fails after ECDH, the KDF and the AES key unwrap. rPGP's
//! unpad and its session key checksum also exit early on the first mismatched
//! byte, so the spec's constant time comparison in step 8 is not met. The
//! caller is already allowlisted and may ask for the session key of any PKESK
//! addressed to the subkey, so the remaining exposure is small, but the app
//! does not have the property the single body was written to give it.
//!
//! Zeroizing also stops at the rPGP boundary. The wrapped plaintext here is a
//! `Zeroizing<Vec<u8>>` and rPGP's `RawSessionKey` is `ZeroizeOnDrop`, but
//! inside rPGP the ECDH shared secret and the derived key encryption key are
//! plain `Vec<u8>` values that are dropped without wiping.

use crate::allowlist::SigningKey;
use crate::response::AppError;
use crate::router::AppState;
use axum::{Json, body::Bytes, extract::State};
use pgp::composed::PlainSessionKey;
use pgp::crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
use pgp::packet::{
    Packet, PacketParser, Signature, SignatureType, SignatureVersion, SubpacketData,
};
use pgp::types::{DecryptionKey as _, EskType, Password, PkeskBytes, PkeskVersion};
use qos_p256::encrypt::P256EncryptPublic;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Domain string the caller signs.
pub const REQUEST_DOMAIN: &str = "tvc gpg session key request";

/// Domain string in the signed receipt.
pub const RECEIPT_DOMAIN: &str = "tvc gpg session key receipt";

/// Seconds either side of enclave time a request time may sit.
pub const TIME_WINDOW_SECONDS: u64 = 300;

/// Largest request body the route accepts, in bytes.
pub const MAX_BODY_BYTES: usize = 8192;

/// Length of an uncompressed SEC1 P-256 point.
const SEC1_POINT_LEN: usize = 65;

/// First byte of an uncompressed SEC1 point.
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Smallest AES key wrap output: one 8 octet block behind an 8 octet IV.
const MIN_WRAPPED_KEY_LEN: usize = 16;

/// Largest wrapped session key the app entertains.
const MAX_WRAPPED_KEY_LEN: usize = 64;

/// A signed request for a session key.
#[derive(Deserialize)]
pub struct SessionKeyRequest {
    /// The exact JSON string the caller signed.
    pub payload: String,
    /// Hex of the OpenPGP signature packet over `payload`.
    pub signature: String,
}

/// The contents of a session key request payload.
#[derive(Deserialize)]
pub struct SessionKeyPayload {
    /// Must equal [`REQUEST_DOMAIN`].
    pub domain: String,
    /// Must equal the app id this process runs under.
    pub app_id: String,
    /// Hex of the PKESK packet, header included.
    pub pkesk: String,
    /// Hex of the caller's 65 byte uncompressed P-256 transport point.
    pub transport_public_key: String,
    /// Caller clock, in seconds since the epoch.
    pub time: u64,
}

/// A released session key and the receipt that records the release.
#[derive(Serialize)]
pub struct SessionKeyResponse {
    /// Hex of the HPKE envelope holding `algorithm octet || session key`.
    pub wrapped_session_key: String,
    /// The canonical JSON the quorum key signed.
    pub receipt_json: String,
    /// Hex of the quorum key signature over `receipt_json`.
    pub receipt_signature: String,
    /// Hex of the quorum public key, 130 bytes.
    pub quorum_public_key: String,
}

/// The receipt the quorum key signs for every released session key.
#[derive(Serialize)]
struct Receipt<'a> {
    domain: &'a str,
    app_id: &'a str,
    requester: &'a str,
    pkesk_sha256: String,
    transport_public_key: &'a str,
    time: u64,
}

/// Why a session key request was turned down.
///
/// The prose for each reason lives in one place, so tests assert on the
/// variant and a reworded message cannot break them. Every reason from
/// [`RejectReason::Rejected`] onward, that is everything from PKESK parsing,
/// shares one body on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// The body is not a session key request.
    BodyNotRequest,
    /// The signature field is not valid hex.
    SignatureNotHex,
    /// The signature field is not exactly one OpenPGP signature packet.
    SignatureNotOnePacket,
    /// The signature is not version 4.
    SignatureVersion,
    /// The signature type is not binary.
    SignatureType,
    /// The signing key algorithm is not RSA or EdDSA legacy.
    SignatureKeyAlgorithm,
    /// The signature hash is not SHA-256, SHA-384 or SHA-512.
    SignatureHash,
    /// The signature carries a critical subpacket the app does not act on.
    SignatureCriticalSubpacket,
    /// The signing key is not on the allowlist.
    NotOnAllowlist,
    /// The signature does not verify over the payload.
    SignatureInvalid,
    /// The payload is not a session key payload.
    PayloadNotPayload,
    /// The payload domain is not the request domain.
    PayloadDomain,
    /// The payload app id is not this app.
    PayloadAppId,
    /// The payload time is outside the accepted window.
    PayloadTime,
    /// The transport public key is not an uncompressed P-256 point.
    TransportKey,
    /// Anything from PKESK parsing onward.
    Rejected,
}

impl RejectReason {
    /// The body text this reason puts on the wire.
    fn message(self) -> &'static str {
        match self {
            Self::BodyNotRequest => "request body is not a session key request",
            Self::SignatureNotHex => "signature is not valid hex",
            Self::SignatureNotOnePacket => "signature is not one OpenPGP signature packet",
            Self::SignatureVersion => "signature version is not 4",
            Self::SignatureType => "signature type is not binary",
            Self::SignatureKeyAlgorithm => "signature key algorithm is not RSA or EdDSA legacy",
            Self::SignatureHash => "signature hash algorithm is not SHA-256, SHA-384 or SHA-512",
            Self::SignatureCriticalSubpacket => {
                "signature carries a critical subpacket the app does not know"
            }
            Self::NotOnAllowlist => "the signing key is not on the allowlist",
            Self::SignatureInvalid => "the signature does not verify over the payload",
            Self::PayloadNotPayload => "payload is not a session key payload",
            Self::PayloadDomain => "payload domain is not accepted",
            Self::PayloadAppId => "payload app id is not this app",
            Self::PayloadTime => "payload time is outside the accepted window",
            Self::TransportKey => "transport public key is not an uncompressed P-256 point",
            Self::Rejected => "session key request rejected",
        }
    }
}

impl From<RejectReason> for AppError {
    fn from(reason: RejectReason) -> Self {
        Self::bad_request(reason.message())
    }
}

/// Discard any error and turn it down with the one shared body.
fn rejected<E>(_: E) -> RejectReason {
    RejectReason::Rejected
}

/// Handle `POST /session-key`.
///
/// # Errors
///
/// Returns [`AppError`] if the clock cannot be read or the request is not
/// accepted.
pub async fn session_key(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<SessionKeyResponse>, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AppError::internal("the enclave clock is before the epoch"))?;
    release_session_key(&state, &body, now).map(Json)
}

/// Verify a session key request and release the session key it asks for.
///
/// `now` is enclave time in seconds since the epoch. Steps up to the payload
/// checks return their own fixed text. Everything from PKESK parsing onward
/// returns the one fixed rejection.
///
/// # Errors
///
/// Returns [`AppError`] if any step rejects the request.
pub fn release_session_key(
    state: &AppState,
    body: &[u8],
    now: u64,
) -> Result<SessionKeyResponse, AppError> {
    release(state, body, now).map_err(AppError::from)
}

/// The body of [`release_session_key`], with the reason still typed.
fn release(state: &AppState, body: &[u8], now: u64) -> Result<SessionKeyResponse, RejectReason> {
    let request: SessionKeyRequest =
        serde_json::from_slice(body).map_err(|_| RejectReason::BodyNotRequest)?;

    let signature = parse_signature(&request.signature)?;
    check_signature_shape(&signature)?;

    let entry = state
        .allowlist
        .lookup(
            signature.issuer_fingerprint().first().copied(),
            signature.issuer_key_id().first().copied(),
        )
        .ok_or(RejectReason::NotOnAllowlist)?;

    let verified = match entry.verifying_key() {
        SigningKey::Primary(key) => signature.verify(key, request.payload.as_bytes()),
        SigningKey::Subkey(key) => signature.verify(key, request.payload.as_bytes()),
    };
    verified.map_err(|_| RejectReason::SignatureInvalid)?;

    // The signature covers the bytes above. Only now is it safe to read them.
    let payload: SessionKeyPayload =
        serde_json::from_str(&request.payload).map_err(|_| RejectReason::PayloadNotPayload)?;

    if payload.domain != REQUEST_DOMAIN {
        return Err(RejectReason::PayloadDomain);
    }
    if payload.app_id != state.app_id {
        return Err(RejectReason::PayloadAppId);
    }
    if now.abs_diff(payload.time) > TIME_WINDOW_SECONDS {
        return Err(RejectReason::PayloadTime);
    }

    let transport = transport_key(&payload.transport_public_key)?;

    // From here on every failure returns the same body.
    let pkesk_bytes = qos_hex::decode(&payload.pkesk).map_err(rejected)?;
    let values = checked_pkesk(state, &pkesk_bytes)?;

    let plain = state
        .team_key
        .encryption_subkey()
        .decrypt(&Password::empty(), &values, EskType::V3_4)
        .map_err(rejected)?
        .map_err(rejected)?;
    let PlainSessionKey::V3_4 { sym_alg, ref key } = plain else {
        return Err(RejectReason::Rejected);
    };

    let mut wrapped_plaintext = Zeroizing::new(Vec::with_capacity(1 + key.len()));
    wrapped_plaintext.push(u8::from(sym_alg));
    wrapped_plaintext.extend_from_slice(key.as_ref());
    let wrapped_session_key = transport.encrypt(&wrapped_plaintext).map_err(rejected)?;

    let receipt = Receipt {
        domain: RECEIPT_DOMAIN,
        app_id: &state.app_id,
        requester: &entry.primary_fingerprint,
        pkesk_sha256: qos_hex::encode(&Sha256::digest(&pkesk_bytes)),
        transport_public_key: &payload.transport_public_key,
        time: payload.time,
    };
    let receipt_bytes = qos_json::to_vec(&receipt).map_err(rejected)?;
    let receipt_signature = state.quorum_key.sign(&receipt_bytes).map_err(rejected)?;
    let receipt_json = String::from_utf8(receipt_bytes).map_err(rejected)?;

    Ok(SessionKeyResponse {
        wrapped_session_key: qos_hex::encode(&wrapped_session_key),
        receipt_json,
        receipt_signature: qos_hex::encode(&receipt_signature),
        quorum_public_key: qos_hex::encode(&state.quorum_key.public_key().to_bytes()),
    })
}

/// Read the one OpenPGP signature packet in `hex`.
fn parse_signature(hex: &str) -> Result<Signature, RejectReason> {
    let bytes = qos_hex::decode(hex).map_err(|_| RejectReason::SignatureNotHex)?;
    match one_packet(&bytes).ok_or(RejectReason::SignatureNotOnePacket)? {
        Packet::Signature(signature) => Ok(signature),
        _ => Err(RejectReason::SignatureNotOnePacket),
    }
}

/// The one packet in `bytes`, or `None` if there is not exactly one or it does
/// not parse.
fn one_packet(bytes: &[u8]) -> Option<Packet> {
    let mut parser = PacketParser::new(bytes);
    let packet = parser.next()?.ok()?;
    // Exactly one packet, so nothing may follow it. The parser treats a short
    // tail as the end of input, so check the reader rather than ask for a
    // second packet.
    if !parser.into_inner().is_empty() {
        return None;
    }
    Some(packet)
}

/// Check that a signature is one the app accepts before it verifies anything.
fn check_signature_shape(signature: &Signature) -> Result<(), RejectReason> {
    let config = signature.config().ok_or(RejectReason::SignatureVersion)?;
    if signature.version() != SignatureVersion::V4 {
        return Err(RejectReason::SignatureVersion);
    }
    if signature.typ() != Some(SignatureType::Binary) {
        return Err(RejectReason::SignatureType);
    }
    if !matches!(
        config.pub_alg,
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::EdDSALegacy
    ) {
        return Err(RejectReason::SignatureKeyAlgorithm);
    }
    if !matches!(
        signature.hash_alg(),
        Some(HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512)
    ) {
        return Err(RejectReason::SignatureHash);
    }
    // The critical bit asks the reader to fail on anything it does not act on,
    // so "known" is the short list this app honours, not the longer list rPGP
    // can name. SignatureExpirationTime is deliberately out of that list:
    // `payload.time` is what bounds freshness here. The unhashed area is
    // unauthenticated, but a signer that marks something critical there still
    // means it, so scan both areas.
    if config
        .hashed_subpackets()
        .chain(config.unhashed_subpackets())
        .any(|subpacket| {
            subpacket.is_critical
                && !matches!(
                    subpacket.data,
                    SubpacketData::SignatureCreationTime(..)
                        | SubpacketData::IssuerFingerprint(..)
                        | SubpacketData::IssuerKeyId(..)
                )
        })
    {
        return Err(RejectReason::SignatureCriticalSubpacket);
    }
    Ok(())
}

/// Build the caller's transport key from the hex in the payload.
fn transport_key(hex: &str) -> Result<P256EncryptPublic, RejectReason> {
    let bytes = qos_hex::decode(hex).map_err(|_| RejectReason::TransportKey)?;
    if bytes.len() != SEC1_POINT_LEN || bytes.first() != Some(&SEC1_UNCOMPRESSED) {
        return Err(RejectReason::TransportKey);
    }
    P256EncryptPublic::from_bytes(&bytes).map_err(|_| RejectReason::TransportKey)
}

/// Read a PKESK packet meant for the team encryption subkey, check every field
/// the app pins before any decryption runs, and return the values to decrypt.
fn checked_pkesk(state: &AppState, pkesk_bytes: &[u8]) -> Result<PkeskBytes, RejectReason> {
    let Some(Packet::PublicKeyEncryptedSessionKey(pkesk)) = one_packet(pkesk_bytes) else {
        return Err(RejectReason::Rejected);
    };
    if pkesk.version() != PkeskVersion::V3 {
        return Err(RejectReason::Rejected);
    }
    if pkesk.algorithm().map_err(rejected)? != PublicKeyAlgorithm::ECDH {
        return Err(RejectReason::Rejected);
    }
    // A wildcard key id is not accepted: the packet must name the subkey.
    if pkesk.id().map_err(rejected)? != &state.team_key.subkey_key_id() {
        return Err(RejectReason::Rejected);
    }
    let values = pkesk.values().map_err(rejected)?;
    let PkeskBytes::Ecdh {
        public_point,
        encrypted_session_key,
    } = values
    else {
        return Err(RejectReason::Rejected);
    };
    // rPGP rejects an off curve or identity point. Reject a wrong length or a
    // compressed prefix here, so that error path stays ours.
    let point = public_point.as_ref();
    if point.len() != SEC1_POINT_LEN || point.first() != Some(&SEC1_UNCOMPRESSED) {
        return Err(RejectReason::Rejected);
    }
    // rPGP reads this length from one octet with no floor, and AES key unwrap
    // then computes `len - 8` on it, which underflows below 8 bytes. RFC 3394
    // wraps whole 8 octet blocks behind an 8 octet IV, and the largest thing
    // this app ever wraps is a 32 byte key with its algorithm octet and
    // checksum, so 64 bytes is a generous ceiling.
    let wrapped = encrypted_session_key.len();
    if !(MIN_WRAPPED_KEY_LEN..=MAX_WRAPPED_KEY_LEN).contains(&wrapped) || wrapped % 8 != 0 {
        return Err(RejectReason::Rejected);
    }
    Ok(values.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::allowlist::Allowlist;
    use crate::router::router_with_state;
    use crate::team_key::TeamKey;
    use pgp::composed::{
        ArmorOptions, DetachedSignature, KeyType, RawSessionKey, SecretKeyParamsBuilder,
        SignedSecretKey, SubkeyParamsBuilder,
    };
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::packet::{PacketTrait, PublicKeyEncryptedSessionKey, SignatureConfig, Subpacket};
    use pgp::types::{KeyDetails as _, KeyId, Mpi, Timestamp};
    use qos_p256::P256Pair;
    use qos_p256::encrypt::P256EncryptPair;
    use std::sync::LazyLock;

    /// Request time and allowlist clock the tests judge everything at.
    const NOW: u64 = 1_790_000_000;
    /// App id the fixture state runs under.
    const APP_ID: &str = "test-app";
    /// Session key the fixture PKESK carries.
    const SESSION_KEY: [u8; 32] = [0x11; 32];
    /// The generator of secp256k1, a valid point on the wrong curve.
    const SECP256K1_GENERATOR: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    /// Everything the tests share, built once because RSA key generation is
    /// slow in a debug build.
    struct Fixture {
        state: AppState,
        rsa: SignedSecretKey,
        ed25519: SignedSecretKey,
        /// A certify only primary with one signing subkey, the shape 52 of the
        /// 55 real engineer keys have.
        subkey_signer: SignedSecretKey,
        outsider: SignedSecretKey,
        transport: P256EncryptPair,
        transport_hex: String,
        pkesk: PublicKeyEncryptedSessionKey,
        pkesk_hex: String,
    }

    static FIXTURE: LazyLock<Fixture> = LazyLock::new(build_fixture);

    fn generate(key_type: KeyType, user_id: &str) -> SignedSecretKey {
        SecretKeyParamsBuilder::default()
            .key_type(key_type)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap()
    }

    /// A certify only primary that carries one signing subkey.
    fn generate_with_signing_subkey(user_id: &str) -> SignedSecretKey {
        SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(false)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .can_sign(true)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap()
    }

    fn armored_public(key: &SignedSecretKey) -> String {
        key.to_public_key()
            .to_armored_string(ArmorOptions::default())
            .unwrap()
    }

    fn build_fixture() -> Fixture {
        let rsa = generate(KeyType::Rsa(3072), "RSA Engineer <rsa@example.com>");
        let ed25519 = generate(KeyType::Ed25519Legacy, "Ed Engineer <ed@example.com>");
        let subkey_signer = generate_with_signing_subkey("Sub Engineer <sub@example.com>");
        let outsider = generate(KeyType::Ed25519Legacy, "Outsider <out@example.com>");

        let armored = format!(
            "{}{}{}",
            armored_public(&rsa),
            armored_public(&ed25519),
            armored_public(&subkey_signer)
        );
        let allowlist = Allowlist::parse_at(armored.as_bytes(), NOW as u32).unwrap();

        let quorum = P256Pair::from_master_seed(&Zeroizing::new([7u8; 32])).unwrap();
        let team_key = TeamKey::derive(&quorum).unwrap();

        let pkesk = PublicKeyEncryptedSessionKey::from_session_key_v3(
            rand::thread_rng(),
            &RawSessionKey::from(SESSION_KEY.to_vec()),
            SymmetricKeyAlgorithm::AES256,
            team_key.encryption_subkey().public_key(),
        )
        .unwrap();
        let pkesk_hex = packet_hex(&pkesk);

        let transport = P256EncryptPair::generate();
        let transport_hex = qos_hex::encode(&transport.public_key().to_bytes());

        Fixture {
            state: AppState::new(quorum, team_key, allowlist, APP_ID.to_string()),
            rsa,
            ed25519,
            subkey_signer,
            outsider,
            transport,
            transport_hex,
            pkesk,
            pkesk_hex,
        }
    }

    fn packet_hex(packet: &impl PacketTrait) -> String {
        let mut buf = Vec::new();
        packet.to_writer_with_header(&mut buf).unwrap();
        qos_hex::encode(&buf)
    }

    /// A payload built by hand, so the tests sign the exact bytes the app sees.
    fn payload(domain: &str, app_id: &str, pkesk: &str, transport: &str, time: u64) -> String {
        format!(
            r#"{{"domain":"{domain}","app_id":"{app_id}","pkesk":"{pkesk}","transport_public_key":"{transport}","time":{time}}}"#
        )
    }

    fn valid_payload() -> String {
        payload(
            REQUEST_DOMAIN,
            APP_ID,
            &FIXTURE.pkesk_hex,
            &FIXTURE.transport_hex,
            NOW,
        )
    }

    fn sign_binary(key: &SignedSecretKey, payload: &str) -> String {
        let signature = DetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &key.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            payload.as_bytes(),
        )
        .unwrap();
        packet_hex(&signature.signature)
    }

    /// Sign with the first signing subkey of `key`, the way most real
    /// engineer keys sign.
    fn sign_binary_with_subkey(key: &SignedSecretKey, payload: &str) -> String {
        let signature = DetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &key.secret_subkeys[0].key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            payload.as_bytes(),
        )
        .unwrap();
        packet_hex(&signature.signature)
    }

    /// Sign with a hand built config, so a test can pin the type, the hash or
    /// an extra subpacket.
    fn sign_config(
        key: &SignedSecretKey,
        payload: &str,
        typ: SignatureType,
        hash: HashAlgorithm,
        extra: Option<Subpacket>,
    ) -> String {
        let secret = &key.primary_key;
        let mut config = SignatureConfig::v4(typ, secret.algorithm(), hash);
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                NOW as u32,
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(secret.fingerprint())).unwrap(),
        ];
        config.hashed_subpackets.extend(extra);
        config.unhashed_subpackets =
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(secret.legacy_key_id())).unwrap()];
        let signature = config
            .sign(secret, &Password::empty(), payload.as_bytes())
            .unwrap();
        packet_hex(&signature)
    }

    fn body(payload: &str, signature: &str) -> Vec<u8> {
        serde_json::json!({ "payload": payload, "signature": signature })
            .to_string()
            .into_bytes()
    }

    fn attempt(payload: &str, signature: &str) -> Result<SessionKeyResponse, RejectReason> {
        release(&FIXTURE.state, &body(payload, signature), NOW)
    }

    fn rejection(payload: &str, signature: &str) -> RejectReason {
        attempt(payload, signature)
            .err()
            .expect("expected a rejection")
    }

    /// Sign a payload that carries `pkesk` with the RSA signer and see how the
    /// app answers.
    fn rejection_for_pkesk(pkesk: &str) -> RejectReason {
        let payload = payload(REQUEST_DOMAIN, APP_ID, pkesk, &FIXTURE.transport_hex, NOW);
        rejection(&payload, &sign_binary(&FIXTURE.rsa, &payload))
    }

    /// The fixture PKESK rebuilt with different parts.
    fn rebuilt_pkesk(
        new_id: Option<KeyId>,
        new_point: Option<Mpi>,
        new_wrapped: Option<Vec<u8>>,
    ) -> String {
        let PublicKeyEncryptedSessionKey::V3 {
            packet_header,
            id,
            pk_algo,
            values,
        } = FIXTURE.pkesk.clone()
        else {
            panic!("the fixture PKESK is not v3");
        };
        let PkeskBytes::Ecdh {
            public_point,
            encrypted_session_key,
        } = values
        else {
            panic!("the fixture PKESK is not ECDH");
        };
        packet_hex(&PublicKeyEncryptedSessionKey::V3 {
            packet_header,
            id: new_id.unwrap_or(id),
            pk_algo,
            values: PkeskBytes::Ecdh {
                public_point: new_point.unwrap_or(public_point),
                encrypted_session_key: new_wrapped
                    .map_or(encrypted_session_key, pgp::bytes::Bytes::from),
            },
        })
    }

    /// The fixture ephemeral point.
    fn fixture_point() -> Vec<u8> {
        let PkeskBytes::Ecdh { public_point, .. } = FIXTURE.pkesk.values().unwrap() else {
            panic!("the fixture PKESK is not ECDH");
        };
        public_point.as_ref().to_vec()
    }

    /// Wrap raw bytes as a length prefixed MPI.
    fn mpi(bytes: &[u8]) -> Mpi {
        let bits = u16::try_from(bytes.len() * 8).unwrap();
        let mut buf = bits.to_be_bytes().to_vec();
        buf.extend_from_slice(bytes);
        Mpi::try_from_reader(&buf[..]).unwrap()
    }

    fn assert_released(response: &SessionKeyResponse, signer: &SignedSecretKey) {
        let envelope = qos_hex::decode(&response.wrapped_session_key).unwrap();
        let opened = FIXTURE.transport.decrypt(&envelope).unwrap();
        let mut expected = vec![u8::from(SymmetricKeyAlgorithm::AES256)];
        expected.extend_from_slice(&SESSION_KEY);
        assert_eq!(opened.as_slice(), expected.as_slice());

        let signature = qos_hex::decode(&response.receipt_signature).unwrap();
        FIXTURE
            .state
            .quorum_key
            .public_key()
            .verify(response.receipt_json.as_bytes(), &signature)
            .unwrap();
        assert_eq!(
            response.quorum_public_key,
            qos_hex::encode(&FIXTURE.state.quorum_key.public_key().to_bytes())
        );
        assert_eq!(response.quorum_public_key.len(), 260);

        let receipt: serde_json::Value = serde_json::from_str(&response.receipt_json).unwrap();
        assert_eq!(receipt["domain"], RECEIPT_DOMAIN);
        assert_eq!(receipt["app_id"], APP_ID);
        // The receipt names the primary, in upper case hex, even when a
        // subkey signed the request.
        assert_eq!(
            receipt["requester"],
            signer.primary_key.fingerprint().to_string().to_uppercase()
        );
        assert_eq!(receipt["transport_public_key"], FIXTURE.transport_hex);
        // Canonical JSON writes every integer as a base 10 string.
        assert_eq!(receipt["time"], NOW.to_string());
        let pkesk_bytes = qos_hex::decode(&FIXTURE.pkesk_hex).unwrap();
        assert_eq!(
            receipt["pkesk_sha256"],
            qos_hex::encode(&Sha256::digest(&pkesk_bytes))
        );
    }

    #[test]
    fn an_rsa_signer_gets_a_session_key() {
        let payload = valid_payload();
        let response = attempt(&payload, &sign_binary(&FIXTURE.rsa, &payload)).unwrap();
        assert_released(&response, &FIXTURE.rsa);
    }

    #[test]
    fn an_ed25519_signer_gets_a_session_key() {
        let payload = valid_payload();
        let response = attempt(&payload, &sign_binary(&FIXTURE.ed25519, &payload)).unwrap();
        assert_released(&response, &FIXTURE.ed25519);
    }

    #[test]
    fn a_signing_subkey_gets_a_session_key() {
        // The production shape: a certify only primary, one signing subkey.
        let signer = &FIXTURE.subkey_signer;
        let payload = valid_payload();
        let response = attempt(&payload, &sign_binary_with_subkey(signer, &payload)).unwrap();
        assert_released(&response, signer);
    }

    #[test]
    fn the_payload_is_read_as_received_not_re_serialized() {
        // Reordered keys and extra spaces. The signature covers these bytes,
        // so the request must still work.
        let payload = format!(
            r#"{{ "time": {NOW},
  "app_id": "{APP_ID}",
  "transport_public_key": "{}",
  "domain": "{REQUEST_DOMAIN}",
  "pkesk": "{}" }}"#,
            FIXTURE.transport_hex, FIXTURE.pkesk_hex
        );
        let response = attempt(&payload, &sign_binary(&FIXTURE.rsa, &payload)).unwrap();
        assert_released(&response, &FIXTURE.rsa);
    }

    #[test]
    fn a_changed_payload_fails_verification() {
        let payload = valid_payload();
        let signature = sign_binary(&FIXTURE.rsa, &payload);
        let tampered = payload.replace(&format!(r#""time":{NOW}"#), r#""time":1790000001"#);
        assert_ne!(tampered, payload);
        assert_eq!(
            rejection(&tampered, &signature),
            RejectReason::SignatureInvalid
        );
    }

    #[test]
    fn a_wrong_domain_is_rejected() {
        let payload = payload(
            "tvc gpg session key receipt",
            APP_ID,
            &FIXTURE.pkesk_hex,
            &FIXTURE.transport_hex,
            NOW,
        );
        assert_eq!(
            rejection(&payload, &sign_binary(&FIXTURE.rsa, &payload)),
            RejectReason::PayloadDomain
        );
    }

    #[test]
    fn a_wrong_app_id_is_rejected() {
        let payload = payload(
            REQUEST_DOMAIN,
            "another-app",
            &FIXTURE.pkesk_hex,
            &FIXTURE.transport_hex,
            NOW,
        );
        assert_eq!(
            rejection(&payload, &sign_binary(&FIXTURE.rsa, &payload)),
            RejectReason::PayloadAppId
        );
    }

    #[test]
    fn a_time_outside_the_window_is_rejected() {
        for time in [NOW - TIME_WINDOW_SECONDS - 1, NOW + TIME_WINDOW_SECONDS + 1] {
            let payload = payload(
                REQUEST_DOMAIN,
                APP_ID,
                &FIXTURE.pkesk_hex,
                &FIXTURE.transport_hex,
                time,
            );
            assert_eq!(
                rejection(&payload, &sign_binary(&FIXTURE.rsa, &payload)),
                RejectReason::PayloadTime
            );
        }
    }

    #[test]
    fn a_time_at_the_edge_of_the_window_is_accepted() {
        for time in [NOW - TIME_WINDOW_SECONDS, NOW + TIME_WINDOW_SECONDS] {
            let payload = payload(
                REQUEST_DOMAIN,
                APP_ID,
                &FIXTURE.pkesk_hex,
                &FIXTURE.transport_hex,
                time,
            );
            attempt(&payload, &sign_binary(&FIXTURE.rsa, &payload)).unwrap();
        }
    }

    #[test]
    fn an_unknown_signer_is_rejected() {
        let payload = valid_payload();
        assert_eq!(
            rejection(&payload, &sign_binary(&FIXTURE.outsider, &payload)),
            RejectReason::NotOnAllowlist
        );
    }

    #[test]
    fn a_sha1_hash_is_rejected() {
        let payload = valid_payload();
        let signature = sign_config(
            &FIXTURE.rsa,
            &payload,
            SignatureType::Binary,
            HashAlgorithm::Sha1,
            None,
        );
        assert_eq!(rejection(&payload, &signature), RejectReason::SignatureHash);
    }

    #[test]
    fn a_text_signature_type_is_rejected() {
        let payload = valid_payload();
        let signature = sign_config(
            &FIXTURE.rsa,
            &payload,
            SignatureType::Text,
            HashAlgorithm::Sha256,
            None,
        );
        assert_eq!(rejection(&payload, &signature), RejectReason::SignatureType);
    }

    #[test]
    fn an_unknown_critical_subpacket_is_rejected() {
        // rPGP refuses to hash an unknown critical subpacket, so the signature
        // is made with the subpacket type 60 marked regular, then the critical
        // bit in its type octet is set in the serialized packet. The app
        // rejects such a signature before it tries to verify it.
        let payload = valid_payload();
        let extra = Subpacket::regular(SubpacketData::Other(
            60,
            pgp::bytes::Bytes::from_static(b"unknown"),
        ))
        .unwrap();
        let signature = sign_config(
            &FIXTURE.rsa,
            &payload,
            SignatureType::Binary,
            HashAlgorithm::Sha256,
            Some(extra),
        );
        let mut bytes = qos_hex::decode(&signature).unwrap();
        let marker: &[u8] = &[0x08, 0x3C, b'u', b'n', b'k'];
        let at = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("the subpacket is in the signature");
        bytes[at + 1] = 0xBC;
        assert_eq!(
            rejection(&payload, &qos_hex::encode(&bytes)),
            RejectReason::SignatureCriticalSubpacket
        );
    }

    #[test]
    fn a_transport_public_key_of_the_wrong_length_is_rejected() {
        for transport in [
            "04",
            &format!("{}00", FIXTURE.transport_hex),
            &FIXTURE.transport_hex.replace("04", "02"),
        ] {
            let payload = payload(REQUEST_DOMAIN, APP_ID, &FIXTURE.pkesk_hex, transport, NOW);
            assert_eq!(
                rejection(&payload, &sign_binary(&FIXTURE.rsa, &payload)),
                RejectReason::TransportKey
            );
        }
    }

    #[test]
    fn a_pkesk_for_another_key_id_is_rejected() {
        // The second case is the wildcard key id, which rPGP's own
        // `match_identity` would accept. The app does not.
        for id in [KeyId::from([1u8; 8]), KeyId::from([0u8; 8])] {
            let pkesk = rebuilt_pkesk(Some(id), None, None);
            assert_eq!(rejection_for_pkesk(&pkesk), RejectReason::Rejected);
        }
    }

    #[test]
    fn a_bad_ephemeral_point_is_rejected() {
        let good = fixture_point();

        // Wrong prefix, still 65 bytes. Caught by the app's own check.
        let mut compressed = good.clone();
        compressed[0] = 0x02;

        // Off curve: P-256 has b != 0, so x = y = 0 is not on it.
        let zero_point = {
            let mut point = vec![SEC1_UNCOMPRESSED];
            point.extend_from_slice(&[0u8; 64]);
            point
        };

        // Off curve: one byte of Y flipped.
        let mut flipped_y = good.clone();
        let last = flipped_y.len() - 1;
        flipped_y[last] ^= 0x01;

        // The SEC1 identity encoding, and two wrong lengths, and a P-384
        // sized point. All four are caught by the app's length check.
        let identity = vec![0x00];
        let short = good[..33].to_vec();
        let long = {
            let mut point = good.clone();
            point.push(0x00);
            point
        };
        let p384_sized = {
            let mut point = vec![SEC1_UNCOMPRESSED];
            point.extend_from_slice(&[0x01u8; 96]);
            point
        };

        // A valid point on the wrong curve. This is the only case that clears
        // the app's length and prefix checks, so it is the one that pins
        // rPGP's `from_sec1_bytes::<NistP256>` call.
        let secp256k1 = qos_hex::decode(SECP256K1_GENERATOR).unwrap();
        assert_eq!(secp256k1.len(), SEC1_POINT_LEN);

        for point in [
            compressed, zero_point, flipped_y, identity, short, long, p384_sized, secp256k1,
        ] {
            let pkesk = rebuilt_pkesk(None, Some(mpi(&point)), None);
            assert_eq!(rejection_for_pkesk(&pkesk), RejectReason::Rejected);
        }
    }

    #[test]
    fn an_encrypted_session_key_of_a_bad_length_is_rejected() {
        // Below 16 the AES key unwrap in rPGP computes `len - 8` and
        // underflows, so these lengths must never reach it. 72 is above the
        // ceiling, 9 and 20 are not whole 8 octet blocks.
        for length in (0usize..=7).chain([8, 9, 15, 20, 72]) {
            let pkesk = rebuilt_pkesk(None, None, Some(vec![0u8; length]));
            assert_eq!(
                rejection_for_pkesk(&pkesk),
                RejectReason::Rejected,
                "a {length} byte encrypted session key was not rejected"
            );
        }
    }

    #[test]
    fn a_flipped_byte_in_the_encrypted_session_key_is_rejected() {
        let mut bytes = qos_hex::decode(&FIXTURE.pkesk_hex).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            rejection_for_pkesk(&qos_hex::encode(&bytes)),
            RejectReason::Rejected
        );
    }

    #[test]
    fn a_trailing_byte_after_the_pkesk_is_rejected() {
        let pkesk = format!("{}00", FIXTURE.pkesk_hex);
        assert_eq!(rejection_for_pkesk(&pkesk), RejectReason::Rejected);
    }

    #[test]
    fn a_body_that_is_not_a_request_is_rejected() {
        assert_eq!(
            release(&FIXTURE.state, b"not json", NOW).err(),
            Some(RejectReason::BodyNotRequest)
        );
    }

    #[test]
    fn a_signature_that_is_not_a_signature_packet_is_rejected() {
        let payload = valid_payload();
        assert_eq!(
            rejection(&payload, &FIXTURE.pkesk_hex),
            RejectReason::SignatureNotOnePacket
        );
    }

    #[test]
    fn every_pkesk_stage_rejection_shares_one_body() {
        assert_eq!(
            AppError::from(RejectReason::Rejected).message(),
            "session key request rejected"
        );
    }

    #[tokio::test]
    async fn the_route_releases_a_session_key() {
        use axum::body::Body;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        // The route reads the machine clock, so the payload carries it too.
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = payload(
            REQUEST_DOMAIN,
            APP_ID,
            &FIXTURE.pkesk_hex,
            &FIXTURE.transport_hex,
            time,
        );
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/session-key")
            .header("content-type", "application/json")
            .body(Body::from(body(
                &payload,
                &sign_binary(&FIXTURE.rsa, &payload),
            )))
            .unwrap();
        let response = router_with_state(FIXTURE.state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed["wrapped_session_key"].is_string());
    }

    #[tokio::test]
    async fn the_route_caps_the_body_size() {
        use axum::body::Body;
        use tower::ServiceExt as _;

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/session-key")
            .header("content-type", "application/json")
            .body(Body::from(vec![b'x'; MAX_BODY_BYTES + 1]))
            .unwrap();
        let response = router_with_state(FIXTURE.state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }
}
