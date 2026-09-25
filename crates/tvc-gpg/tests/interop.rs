//! Interop tests against fixtures made by stock gpg.
//!
//! Every byte stream here came from an unmodified `gpg`, not from this repo's
//! Rust code. The tests prove two things: the session key route accepts a
//! request signed by a real gpg key and releases the session key gpg itself
//! reported, and that released key opens the gpg made message, both through
//! rPGP and through gpg. See `fixtures/README.md` for how the fixtures are
//! made.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use pgp::composed::{
    Deserializable as _, Message, PlainSessionKey, RawSessionKey, SignedPublicKey,
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::KeyDetails as _;
use qos_p256::encrypt::P256EncryptPair;
use qos_p256::{P256Pair, P256Public};
use std::process::Command;
use tvc_gpg::allowlist::Allowlist;
use tvc_gpg::router::AppState;
use tvc_gpg::session_key::{RECEIPT_DOMAIN, SessionKeyResponse, release_session_key};
use tvc_gpg::team_key::TeamKey;
use zeroize::Zeroizing;

/// Enclave time every test runs at. The fixtures carry this time too.
const NOW: u64 = 1_790_000_000;

/// App id the fixtures were signed for.
const APP_ID: &str = "test-app";

const TEAM_PUBLIC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/team-public.asc"
));
const RSA_SIGNER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/rsa-signer.asc"
));
const ED25519_SIGNER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ed25519-signer.asc"
));
const RSA_SUBKEY_SIGNER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/rsa-subkey-signer.asc"
));
const PAYLOAD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/payload.json"
));
const PAYLOAD_SIG_RSA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/payload.sig.rsa"
));
const PAYLOAD_SIG_ED25519: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/payload.sig.ed25519"
));
const PAYLOAD_SIG_RSA_SUBKEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/payload.sig.rsa-subkey"
));
const SESSION_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/session-key.txt"
));
const TRANSPORT_SECRET: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/transport-secret.hex"
));
const MESSAGE: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/message.gpg"));
const MESSAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/message.gpg");
const SOPS_PAYLOAD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/sops-payload.json"
));
const SOPS_PAYLOAD_SIG_RSA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/sops-payload.sig.rsa"
));
const SOPS_SESSION_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/sops-session-key.txt"
));
const SOPS_DATAKEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/sops-datakey.asc"
));
const SOPS_DATA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/sops-data.bin"
));

/// Build the app state the fixtures were made for: the team key derived from
/// the fixed test seed, and an allowlist of the three gpg signers.
fn state() -> AppState {
    let quorum = P256Pair::from_master_seed(&Zeroizing::new([7u8; 32])).unwrap();
    let team_key = TeamKey::derive(&quorum).unwrap();
    assert_eq!(
        team_key.public_key_armored().unwrap(),
        TEAM_PUBLIC,
        "the derived team key is not the key the fixtures were encrypted to"
    );
    let keys = format!("{RSA_SIGNER}{ED25519_SIGNER}{RSA_SUBKEY_SIGNER}");
    let allowlist = Allowlist::parse_at(keys.as_bytes(), u32::try_from(NOW).unwrap()).unwrap();
    AppState::new(quorum, team_key, allowlist, APP_ID.to_owned())
}

/// The primary fingerprint of an armored certificate, in upper case hex.
fn primary_fingerprint(armored: &str) -> String {
    let (certificate, _headers) = SignedPublicKey::from_armor_single(armored.as_bytes()).unwrap();
    certificate
        .primary_key
        .fingerprint()
        .to_string()
        .to_uppercase()
}

/// Release the session key for a gpg signed payload.
fn release(payload: &str, signature: &[u8]) -> SessionKeyResponse {
    let body = serde_json::json!({
        "payload": payload,
        "signature": qos_hex::encode(signature),
    })
    .to_string();
    release_session_key(&state(), body.as_bytes(), NOW).unwrap()
}

/// Open the wrapped session key with the fixed transport secret. Returns the
/// plaintext, which is the algorithm octet followed by the key bytes.
fn open_wrapped(response: &SessionKeyResponse) -> Vec<u8> {
    let secret = Zeroizing::new(qos_hex::decode(TRANSPORT_SECRET.trim()).unwrap());
    let pair = P256EncryptPair::from_bytes(&secret).unwrap();
    let envelope = qos_hex::decode(&response.wrapped_session_key).unwrap();
    pair.decrypt(&envelope).unwrap().to_vec()
}

/// Read gpg's `<algorithm>:<hex>` session key form into the same algorithm
/// octet followed by key bytes layout. gpg writes `<algorithm>.<mode>` for an
/// AEAD message, so keep only the algorithm.
fn expected_session_key(text: &str) -> Vec<u8> {
    let (algorithm, key) = text.trim().split_once(':').unwrap();
    let algorithm: u8 = algorithm.split('.').next().unwrap().parse().unwrap();
    let mut out = vec![algorithm];
    out.extend_from_slice(&qos_hex::decode(key).unwrap());
    out
}

/// Decrypt a gpg made message with a released session key and return the
/// literal data. Reading to the end is what checks the message integrity.
fn literal_data(message: Message<'_>, session_key: &[u8]) -> Vec<u8> {
    let plain = PlainSessionKey::V3_4 {
        sym_alg: SymmetricKeyAlgorithm::from(session_key[0]),
        key: RawSessionKey::from(session_key[1..].to_vec()),
    };
    let mut opened = message
        .decrypt_with_session_key(plain)
        .unwrap()
        .decompress()
        .unwrap();
    assert!(opened.is_literal(), "the message is not literal data");
    opened.as_data_vec().unwrap()
}

#[test]
fn rsa_signer_releases_the_gpg_session_key() {
    let response = release(PAYLOAD, PAYLOAD_SIG_RSA);

    assert_eq!(
        qos_hex::encode(&open_wrapped(&response)),
        qos_hex::encode(&expected_session_key(SESSION_KEY)),
        "the released key is not the session key gpg reported"
    );
}

#[test]
fn ed25519_signer_releases_the_gpg_session_key() {
    let response = release(PAYLOAD, PAYLOAD_SIG_ED25519);

    assert_eq!(
        qos_hex::encode(&open_wrapped(&response)),
        qos_hex::encode(&expected_session_key(SESSION_KEY)),
        "the released key is not the session key gpg reported"
    );
}

#[test]
fn released_session_key_opens_the_gpg_message() {
    let session_key = open_wrapped(&release(PAYLOAD, PAYLOAD_SIG_RSA));

    let message = Message::from_bytes(MESSAGE).unwrap();

    assert_eq!(literal_data(message, &session_key), b"hello team\n");
}

#[test]
fn a_signing_subkey_releases_the_gpg_session_key() {
    // The certificate's primary is certify only and an RSA signing subkey
    // made the signature. That is the shape almost every engineer key has.
    let response = release(PAYLOAD, PAYLOAD_SIG_RSA_SUBKEY);

    assert_eq!(
        qos_hex::encode(&open_wrapped(&response)),
        qos_hex::encode(&expected_session_key(SESSION_KEY)),
        "the released key is not the session key gpg reported"
    );

    // The receipt names the primary, not the subkey that signed.
    let receipt: serde_json::Value = serde_json::from_str(&response.receipt_json).unwrap();
    assert_eq!(receipt["requester"], primary_fingerprint(RSA_SUBKEY_SIGNER));
}

#[test]
fn an_armored_single_pkesk_message_releases_its_session_key() {
    let response = release(SOPS_PAYLOAD, SOPS_PAYLOAD_SIG_RSA);
    let session_key = open_wrapped(&response);
    assert_eq!(
        qos_hex::encode(&session_key),
        qos_hex::encode(&expected_session_key(SOPS_SESSION_KEY)),
        "the released key is not the session key gpg reported"
    );

    let (message, _headers) = Message::from_string(SOPS_DATAKEY).unwrap();

    assert_eq!(
        literal_data(message, &session_key),
        SOPS_DATA,
        "the opened bytes are not the bytes the script encrypted"
    );
}

#[test]
fn receipt_verifies_with_the_quorum_key() {
    let response = release(PAYLOAD, PAYLOAD_SIG_RSA);

    let quorum_public =
        P256Public::from_bytes(&qos_hex::decode(&response.quorum_public_key).unwrap()).unwrap();
    quorum_public
        .verify(
            response.receipt_json.as_bytes(),
            &qos_hex::decode(&response.receipt_signature).unwrap(),
        )
        .unwrap();

    let receipt: serde_json::Value = serde_json::from_str(&response.receipt_json).unwrap();
    let payload: serde_json::Value = serde_json::from_str(PAYLOAD).unwrap();

    assert_eq!(receipt["domain"], RECEIPT_DOMAIN);
    assert_eq!(receipt["app_id"], APP_ID);
    assert_eq!(receipt["requester"], primary_fingerprint(RSA_SIGNER));
    assert_eq!(
        receipt["transport_public_key"],
        payload["transport_public_key"]
    );
    assert_eq!(receipt["time"], "1790000000");
}

#[test]
fn gpg_opens_the_message_with_the_released_session_key() {
    // This is the only test where stock gpg consumes a released session key,
    // so it must fail loudly rather than skip when gpg is missing.
    Command::new("gpg")
        .arg("--version")
        .output()
        .expect("gpg is required for the interop tests");

    let session_key = open_wrapped(&release(PAYLOAD, PAYLOAD_SIG_RSA));
    let session_key = format!(
        "{}:{}",
        session_key[0],
        qos_hex::encode(&session_key[1..]).to_ascii_uppercase()
    );

    // POSIX only: `sh` is dash on the CI runner. A short GNUPGHOME keeps the
    // agent socket path under the 100 byte limit, and a fresh one keeps this
    // test away from the user's own keyring. The session key goes in on
    // stdin, so it never lands in a file.
    let script = r#"
        set -eu
        home=$(mktemp -d /tmp/tg.XXXX)
        trap 'gpgconf --homedir "$home" --kill all >/dev/null 2>&1; rm -rf "$home"' EXIT
        printf '%s\n' "$2" | GNUPGHOME="$home" gpg --batch --override-session-key-fd 0 -d "$1"
    "#;
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg("sh")
        .arg(MESSAGE_PATH)
        .arg(&session_key)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "gpg exited {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"hello team\n",
        "gpg did not read the message, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
