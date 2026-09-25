//! The signed session key request and the checks on the app's answer.

use crate::Result;
use qos_p256::P256Public;
use qos_p256::encrypt::P256EncryptPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::time::Duration;
use zeroize::Zeroizing;

/// Domain string the caller signs.
pub const REQUEST_DOMAIN: &str = "tvc gpg session key request";

/// Domain string in the signed receipt.
pub const RECEIPT_DOMAIN: &str = "tvc gpg session key receipt";

/// Largest answer the client reads from the app, in bytes. A real answer is a
/// few kilobytes.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// The payload the caller signs.
///
/// The field order here is the byte order on the wire. The app verifies the
/// signature over the bytes it receives, so these bytes are what matter.
#[derive(Serialize)]
struct Payload<'a> {
    domain: &'a str,
    app_id: &'a str,
    pkesk: &'a str,
    transport_public_key: &'a str,
    time: u64,
}

/// A released session key and the receipt that records the release.
#[derive(Deserialize)]
pub struct SessionKeyResponse {
    /// Hex of the HPKE envelope holding `algorithm octet || session key`.
    pub wrapped_session_key: String,
    /// The canonical JSON the quorum key signed.
    pub receipt_json: String,
    /// Hex of the quorum key signature over `receipt_json`.
    pub receipt_signature: String,
}

/// Build the exact payload bytes to sign.
///
/// # Errors
///
/// Returns an error if the payload does not serialize.
pub fn payload_json(
    app_id: &str,
    pkesk: &str,
    transport_public_key: &str,
    time: u64,
) -> Result<String> {
    let payload = Payload {
        domain: REQUEST_DOMAIN,
        app_id,
        pkesk,
        transport_public_key,
        time,
    };
    serde_json::to_string(&payload)
        .map_err(|error| format!("the request payload did not serialize: {error}").into())
}

/// An HTTP agent with a timeout, so a silent app does not hang the client.
///
/// TLS only, and no redirects, so the app URL the caller typed is the only
/// host this client talks to.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .https_only(true)
        .redirects(0)
        .build()
}

/// `app_url` without a trailing slash.
fn base(app_url: &str) -> &str {
    app_url.trim_end_matches('/')
}

/// Turn a ureq failure into a message that keeps the app's own wording.
fn http_error(route: &str, error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(code, response) => {
            let body = response.into_string().unwrap_or_default();
            let reason = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value["error"].as_str().map(str::to_owned))
                .unwrap_or(body);
            format!("{route} answered {code}: {reason}")
        }
        other => format!("{route} could not be reached: {other}"),
    }
}

/// Fetch the app's armored OpenPGP public key.
///
/// # Errors
///
/// Returns an error if the app cannot be reached or does not answer.
pub fn fetch_public_key(app_url: &str) -> Result<String> {
    let url = format!("{}/public-key", base(app_url));
    agent()
        .get(&url)
        .call()
        .map_err(|error| http_error("/public-key", error))?
        .into_string()
        .map_err(|error| format!("/public-key did not send a public key: {error}").into())
}

/// Post a signed session key request and read the answer.
///
/// # Errors
///
/// Returns an error if the app turns the request down or does not answer.
pub fn post_session_key(
    app_url: &str,
    payload: &str,
    signature: &[u8],
) -> Result<SessionKeyResponse> {
    let url = format!("{}/session-key", base(app_url));
    let answer = agent()
        .post(&url)
        .send_json(ureq::json!({
            "payload": payload,
            "signature": qos_hex::encode(signature),
        }))
        .map_err(|error| http_error("/session-key", error))?
        .into_reader()
        .take(MAX_RESPONSE_BYTES);
    serde_json::from_reader(answer)
        .map_err(|error| format!("/session-key did not send a session key: {error}").into())
}

/// Read the quorum public key the caller pinned out of band.
///
/// # Errors
///
/// Returns an error if the hex or the point is not a P-256 public key.
pub fn pinned_quorum_key(quorum_public_key: &str) -> Result<P256Public> {
    let bytes = qos_hex::decode(quorum_public_key.trim())
        .map_err(|_| "the quorum public key is not hex")?;
    P256Public::from_bytes(&bytes)
        .map_err(|error| format!("the quorum public key did not parse: {error:?}").into())
}

/// Check the receipt against the quorum key the caller pinned.
///
/// The signature is checked with `quorum`, the key the caller pinned, never
/// with anything the answer carries. Every mismatch is a failure.
///
/// # Errors
///
/// Returns an error if the receipt does not verify or any field is not the
/// one this run asked for.
pub fn check_response(
    response: &SessionKeyResponse,
    quorum: &P256Public,
    app_id: &str,
    transport_public_key: &str,
    pkesk: &[u8],
) -> Result<()> {
    let signature = qos_hex::decode(&response.receipt_signature)
        .map_err(|_| "the receipt signature is not hex")?;
    quorum
        .verify(response.receipt_json.as_bytes(), &signature)
        .map_err(|error| format!("the receipt signature did not verify: {error:?}"))?;

    // Canonical JSON writes every integer as a string, so read the receipt as
    // a value and compare only the fields the client pinned.
    let receipt: serde_json::Value = serde_json::from_str(&response.receipt_json)
        .map_err(|error| format!("the receipt did not parse: {error}"))?;
    let pkesk_sha256 = qos_hex::encode(&Sha256::digest(pkesk));
    for (field, expected) in [
        ("domain", RECEIPT_DOMAIN),
        ("app_id", app_id),
        ("transport_public_key", transport_public_key),
        ("pkesk_sha256", &pkesk_sha256),
    ] {
        // Exact. Both sides build the hash hex with `qos_hex::encode`.
        if receipt[field].as_str() != Some(expected) {
            return Err(format!("the receipt {field} is not the one asked for").into());
        }
    }
    Ok(())
}

/// Open the wrapped session key with the transport pair.
///
/// The plaintext is the symmetric algorithm octet followed by the key bytes.
///
/// # Errors
///
/// Returns an error if the envelope does not open or is too short.
pub fn open_session_key(
    transport: &P256EncryptPair,
    wrapped_session_key: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let envelope =
        qos_hex::decode(wrapped_session_key).map_err(|_| "the wrapped session key is not hex")?;
    let plain = transport
        .decrypt(&envelope)
        .map_err(|error| format!("the wrapped session key did not open: {error:?}"))?;
    if plain.len() < 2 {
        return Err("the app sent a session key that is too short".into());
    }
    Ok(plain)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use qos_p256::P256Pair;

    const APP_ID: &str = "test-app";
    const TRANSPORT: &str = "0401";
    const TIME: u64 = 1_790_000_000;
    /// The PKESK bytes the fixture receipt is built over.
    const PKESK: &[u8] = b"pkesk";

    /// A payload a real gpg signed and the app accepted. It comes from the
    /// server crate's interop fixtures.
    const GPG_PAYLOAD: &str = include_str!("../../tvc-gpg/fixtures/payload.json");

    fn receipt(app_id: &str, transport: &str, domain: &str, pkesk: &[u8]) -> String {
        let pkesk_sha256 = qos_hex::encode(&Sha256::digest(pkesk));
        format!(
            r#"{{"domain":"{domain}","app_id":"{app_id}","requester":"AA","pkesk_sha256":"{pkesk_sha256}","transport_public_key":"{transport}","time":"{TIME}"}}"#
        )
    }

    /// A receipt for this run, with every field as the client asked for it.
    fn good_receipt() -> String {
        receipt(APP_ID, TRANSPORT, RECEIPT_DOMAIN, PKESK)
    }

    fn response(quorum: &P256Pair, receipt_json: String) -> SessionKeyResponse {
        SessionKeyResponse {
            wrapped_session_key: String::new(),
            receipt_signature: qos_hex::encode(&quorum.sign(receipt_json.as_bytes()).unwrap()),
            receipt_json,
        }
    }

    /// The pinned key of a generated pair, the way the caller passes it in.
    fn pinned(quorum: &P256Pair) -> P256Public {
        pinned_quorum_key(&qos_hex::encode(&quorum.public_key().to_bytes())).unwrap()
    }

    #[test]
    fn the_payload_matches_the_bytes_the_app_has_accepted() {
        let fixture: serde_json::Value = serde_json::from_str(GPG_PAYLOAD).unwrap();
        let field = |name: &str| fixture[name].as_str().unwrap_or_default().to_owned();

        let json = payload_json(
            &field("app_id"),
            &field("pkesk"),
            &field("transport_public_key"),
            fixture["time"].as_u64().unwrap(),
        )
        .unwrap();

        assert_eq!(json, GPG_PAYLOAD.trim_end());
    }

    #[test]
    fn a_receipt_from_the_pinned_quorum_key_is_accepted() {
        let quorum = P256Pair::generate().unwrap();
        let answer = response(&quorum, good_receipt());

        check_response(&answer, &pinned(&quorum), APP_ID, TRANSPORT, PKESK).unwrap();
    }

    #[test]
    fn a_tampered_receipt_is_turned_down() {
        let quorum = P256Pair::generate().unwrap();
        let mut answer = response(&quorum, good_receipt());
        answer.receipt_json = answer.receipt_json.replace(APP_ID, "other-app");

        let error =
            check_response(&answer, &pinned(&quorum), "other-app", TRANSPORT, PKESK).unwrap_err();

        assert!(error.to_string().contains("did not verify"));
    }

    #[test]
    fn a_receipt_field_that_does_not_match_is_turned_down() {
        let quorum = P256Pair::generate().unwrap();

        for (receipt_json, field) in [
            (receipt(APP_ID, TRANSPORT, REQUEST_DOMAIN, PKESK), "domain"),
            (
                receipt("other-app", TRANSPORT, RECEIPT_DOMAIN, PKESK),
                "app_id",
            ),
            (
                receipt(APP_ID, "0402", RECEIPT_DOMAIN, PKESK),
                "transport_public_key",
            ),
            (
                receipt(APP_ID, TRANSPORT, RECEIPT_DOMAIN, b"another packet"),
                "pkesk_sha256",
            ),
        ] {
            let answer = response(&quorum, receipt_json);

            let error =
                check_response(&answer, &pinned(&quorum), APP_ID, TRANSPORT, PKESK).unwrap_err();

            assert!(
                error.to_string().contains(field),
                "a wrong {field} was not named"
            );
        }
    }

    #[test]
    fn a_quorum_public_key_that_is_not_a_key_is_turned_down() {
        for key in ["zz", "04", &"aa".repeat(130)] {
            assert!(pinned_quorum_key(key).is_err(), "{key} was accepted");
        }
    }
}
