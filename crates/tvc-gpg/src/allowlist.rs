//! Allowlist of engineer OpenPGP public keys.
//!
//! The build script joins every armored key in the `allowlist/` directory into
//! one file. This module embeds that file, parses it and indexes the keys that
//! can verify a signature.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::{PublicKey, PublicSubkey, Signature, SignatureType};
use pgp::types::{Fingerprint, KeyDetails, KeyId, KeyVersion, Tag, Timestamp};

/// The joined armored keys, written by the build script.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/allowlist.asc"));

/// First line of an armored public key block.
const ARMOR_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/// Reason an allowlist could not be built.
#[derive(Debug)]
pub enum AllowlistError {
    /// The input is not UTF-8 text.
    NotUtf8,
    /// The input holds no armored public key block.
    NoKeyBlock,
    /// A key block could not be read. Holds the block number, counted from one.
    BadKeyBlock(usize),
    /// No key in the input can verify a signature.
    NoSigningKeys,
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "the allowlist is not UTF-8 text"),
            Self::NoKeyBlock => write!(f, "the allowlist holds no armored public key block"),
            Self::BadKeyBlock(n) => write!(f, "allowlist key block {n} could not be read"),
            Self::NoSigningKeys => write!(f, "the allowlist holds no key that can verify"),
        }
    }
}

impl std::error::Error for AllowlistError {}

/// A key from the allowlist that can verify a signature.
#[derive(Debug, Clone)]
pub enum SigningKey {
    /// The primary key of the certificate.
    Primary(PublicKey),
    /// A signing subkey of the certificate.
    Subkey(PublicSubkey),
}

impl SigningKey {
    /// Fingerprint of this key.
    fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Primary(key) => key.fingerprint(),
            Self::Subkey(key) => key.fingerprint(),
        }
    }

    /// Legacy key id of this key.
    fn key_id(&self) -> KeyId {
        match self {
            Self::Primary(key) => key.legacy_key_id(),
            Self::Subkey(key) => key.legacy_key_id(),
        }
    }
}

/// One signer the app accepts, held once per key that can verify.
#[derive(Debug, Clone)]
pub struct SignerEntry {
    /// Fingerprint of the certificate this key belongs to, in lower case hex.
    pub primary_fingerprint: String,
    /// The whole certificate.
    certificate: Arc<SignedPublicKey>,
    /// The key that verifies signatures from this signer.
    key: SigningKey,
}

impl SignerEntry {
    /// The key that verifies signatures from this signer.
    #[must_use]
    pub fn verifying_key(&self) -> &SigningKey {
        &self.key
    }

    /// The whole certificate the verifying key belongs to.
    #[must_use]
    pub fn certificate(&self) -> &SignedPublicKey {
        &self.certificate
    }
}

/// Engineer public keys the app accepts requests from.
#[derive(Debug, Clone)]
pub struct Allowlist {
    certificates: Vec<Arc<SignedPublicKey>>,
    by_fingerprint: HashMap<Fingerprint, SignerEntry>,
    by_key_id: HashMap<KeyId, Fingerprint>,
}

impl Allowlist {
    /// Build the allowlist from the keys embedded at build time.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded keys cannot be read or hold no key
    /// that can verify.
    pub fn embedded() -> Result<Self, AllowlistError> {
        Self::parse(EMBEDDED)
    }

    /// Build an allowlist from armored public key blocks, using the clock of
    /// this machine to drop expired keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be read or holds no key that can
    /// verify.
    pub fn parse(armored: &[u8]) -> Result<Self, AllowlistError> {
        Self::parse_at(armored, Timestamp::now().as_secs())
    }

    /// Build an allowlist from armored public key blocks, dropping keys that
    /// are expired at `now`, in seconds since the epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be read or holds no key that can
    /// verify at `now`.
    pub fn parse_at(armored: &[u8], now: u32) -> Result<Self, AllowlistError> {
        let certificates = read_certificates(armored)?;

        let mut by_fingerprint = HashMap::new();
        let mut by_key_id: HashMap<KeyId, Fingerprint> = HashMap::new();
        let mut ambiguous_key_ids = Vec::new();

        for certificate in &certificates {
            let primary_fingerprint = certificate.primary_key.fingerprint().to_string();
            let (keys, _defects) = classify(certificate, now);
            for key in keys {
                let fingerprint = key.fingerprint();
                let key_id = key.key_id();
                if let Some(other) = by_key_id.insert(key_id, fingerprint.clone())
                    && other != fingerprint
                {
                    ambiguous_key_ids.push(key_id);
                }
                by_fingerprint.insert(
                    fingerprint,
                    SignerEntry {
                        primary_fingerprint: primary_fingerprint.clone(),
                        certificate: Arc::clone(certificate),
                        key,
                    },
                );
            }
        }

        // A key id is only 8 bytes. If two keys share one, no lookup by key id
        // can tell them apart, so drop the id and keep the fingerprints.
        for key_id in ambiguous_key_ids {
            by_key_id.remove(&key_id);
        }

        if by_fingerprint.is_empty() {
            return Err(AllowlistError::NoSigningKeys);
        }

        Ok(Self {
            certificates,
            by_fingerprint,
            by_key_id,
        })
    }

    /// Find a signer by the fingerprint of its verifying key, or by the legacy
    /// key id if no fingerprint is given or the fingerprint is unknown.
    #[must_use]
    pub fn lookup(
        &self,
        fingerprint: Option<&Fingerprint>,
        key_id: Option<&KeyId>,
    ) -> Option<&SignerEntry> {
        if let Some(fingerprint) = fingerprint
            && let Some(entry) = self.by_fingerprint.get(fingerprint)
        {
            return Some(entry);
        }
        let key_id = key_id?;
        let fingerprint = self.by_key_id.get(key_id)?;
        self.by_fingerprint.get(fingerprint)
    }

    /// One message per key the allowlist cannot use at `now`, in seconds since
    /// the epoch. An empty list means every embedded certificate holds a key
    /// that can verify.
    #[must_use]
    pub fn check(&self, now: u32) -> Vec<String> {
        let mut defects = Vec::new();
        for certificate in &self.certificates {
            let (_keys, found) = classify(certificate, now);
            defects.extend(found);
        }
        defects
    }

    /// How many keys can verify a signature.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_fingerprint.len()
    }

    /// True if no key can verify a signature.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_fingerprint.is_empty()
    }

    /// How many certificates the allowlist holds.
    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }
}

/// Read every armored block in `armored` into a certificate, keeping the first
/// copy of each fingerprint.
fn read_certificates(armored: &[u8]) -> Result<Vec<Arc<SignedPublicKey>>, AllowlistError> {
    let text = std::str::from_utf8(armored).map_err(|_| AllowlistError::NotUtf8)?;

    // rPGP reads one armored block per call, so split the blocks first.
    let mut certificates: Vec<Arc<SignedPublicKey>> = Vec::new();
    let mut seen = Vec::new();
    let mut blocks = 0;
    for rest in text.split(ARMOR_BEGIN).skip(1) {
        blocks += 1;
        let block = format!("{ARMOR_BEGIN}{rest}");
        let (parsed, _headers) = SignedPublicKey::from_armor_many(block.as_bytes())
            .map_err(|_| AllowlistError::BadKeyBlock(blocks))?;
        for certificate in parsed {
            let certificate = certificate.map_err(|_| AllowlistError::BadKeyBlock(blocks))?;
            let fingerprint = certificate.primary_key.fingerprint();
            if seen.contains(&fingerprint) {
                continue;
            }
            seen.push(fingerprint);
            certificates.push(Arc::new(certificate));
        }
    }

    if blocks == 0 {
        return Err(AllowlistError::NoKeyBlock);
    }
    Ok(certificates)
}

/// Return the keys of `certificate` that can verify at `now`, and one message
/// per key the allowlist cannot use.
fn classify(certificate: &SignedPublicKey, now: u32) -> (Vec<SigningKey>, Vec<String>) {
    let primary = &certificate.primary_key;
    let fingerprint = primary.fingerprint();
    let mut keys = Vec::new();
    let mut defects = Vec::new();

    if primary.version() != KeyVersion::V4 {
        defects.push(format!("key {fingerprint} is not version 4"));
        return (keys, defects);
    }
    if !certificate.details.revocation_signatures.is_empty() {
        defects.push(format!("key {fingerprint} is revoked"));
        return (keys, defects);
    }

    let Some((user_id, self_signature)) = newest_self_signature(certificate) else {
        defects.push(format!("key {fingerprint} has no self signature"));
        return (keys, defects);
    };
    if self_signature
        .verify_certification(primary, Tag::UserId, user_id)
        .is_err()
    {
        defects.push(format!(
            "key {fingerprint} failed self signature verification"
        ));
        return (keys, defects);
    }
    if let Some(expires_at) = expires_at(primary.created_at(), self_signature)
        && expires_at <= u64::from(now)
    {
        defects.push(format!("key {fingerprint} expired at {expires_at}"));
        return (keys, defects);
    }

    if self_signature.key_flags().sign() {
        keys.push(SigningKey::Primary(primary.clone()));
    }

    for subkey in &certificate.public_subkeys {
        let Some(binding) = newest_binding(&subkey.signatures) else {
            continue;
        };
        if !binding.key_flags().sign() {
            continue;
        }
        let subkey_fingerprint = subkey.key.fingerprint();
        if subkey
            .signatures
            .iter()
            .any(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation))
        {
            defects.push(format!(
                "signing subkey {subkey_fingerprint} of key {fingerprint} is revoked"
            ));
            continue;
        }
        if let Some(expires_at) = expires_at(subkey.key.created_at(), binding)
            && expires_at <= u64::from(now)
        {
            defects.push(format!(
                "signing subkey {subkey_fingerprint} of key {fingerprint} expired at {expires_at}"
            ));
            continue;
        }
        // This also checks the back signature that a signing subkey must carry.
        if subkey.verify_bindings(primary).is_err() {
            defects.push(format!(
                "signing subkey {subkey_fingerprint} of key {fingerprint} failed binding verification"
            ));
            continue;
        }
        keys.push(SigningKey::Subkey(subkey.key.clone()));
    }

    if keys.is_empty() && defects.is_empty() {
        defects.push(format!("key {fingerprint} has no signing capable key"));
    }
    (keys, defects)
}

/// The newest self certification over a user id of `certificate`, with the user
/// id it covers. Certifications by other people are left out.
fn newest_self_signature(
    certificate: &SignedPublicKey,
) -> Option<(&pgp::packet::UserId, &Signature)> {
    let primary = &certificate.primary_key;
    let fingerprint = primary.fingerprint();
    let key_id = primary.legacy_key_id();
    certificate
        .details
        .users
        .iter()
        .flat_map(|user| user.signatures.iter().map(move |sig| (&user.id, sig)))
        .filter(|(_id, sig)| {
            sig.issuer_fingerprint().iter().any(|f| **f == fingerprint)
                || sig.issuer_key_id().iter().any(|k| **k == key_id)
        })
        .max_by_key(|(_id, sig)| created_at(sig))
}

/// The newest subkey binding signature.
fn newest_binding(signatures: &[Signature]) -> Option<&Signature> {
    signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|sig| created_at(sig))
}

/// Creation time of a signature, zero if it carries none.
fn created_at(signature: &Signature) -> u32 {
    signature.created().map_or(0, Timestamp::as_secs)
}

/// The time a key expires, from its creation time and the expiry in the
/// signature. `None` means it never expires.
fn expires_at(created_at: Timestamp, signature: &Signature) -> Option<u64> {
    let seconds = signature.key_expiration_time()?.as_secs();
    if seconds == 0 {
        return None;
    }
    Some(u64::from(created_at.as_secs()) + u64::from(seconds))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// About 2026-09-21, the time the tests judge expiry at.
    const NOW: u32 = 1_790_000_000;
    /// A time before any key in the allowlist expired.
    const EARLIER: u32 = 1_700_000_000;
    /// Primary key of an engineer whose primary can sign.
    const RICHARD_PRIMARY: &str = "88a9550d2d137e44fc25f6a1691a36a6ddf82062";
    /// Legacy key id of that primary key.
    const RICHARD_KEY_ID: &str = "691a36a6ddf82062";
    /// Primary key of the engineer whose only signing subkey has expired.
    const SEAN_PRIMARY: &str = "2e0583f5860bb222bbfe2bf08f70a64ce3cf9902";
    /// That expired signing subkey.
    const SEAN_SUBKEY: &str = "82837d4bdf846b1e59a923d107ae1e7f9cc5165b";

    fn fingerprint(hex: &str) -> Fingerprint {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        Fingerprint::new(KeyVersion::V4, &bytes).unwrap()
    }

    fn key_id(hex: &str) -> KeyId {
        let mut bytes = [0u8; 8];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        KeyId::new(bytes)
    }

    #[test]
    fn embedded_keys_are_indexed() {
        let allowlist = Allowlist::embedded().unwrap();
        assert!(
            allowlist.len() >= 40,
            "only {} verifying keys from {} certificates",
            allowlist.len(),
            allowlist.certificate_count()
        );
        assert_eq!(
            allowlist.by_key_id.len(),
            allowlist.by_fingerprint.len(),
            "key ids and fingerprints do not match one to one"
        );
    }

    #[test]
    fn check_reports_every_unusable_key() {
        let allowlist = Allowlist::parse_at(EMBEDDED, NOW).unwrap();
        let mut found = allowlist.check(NOW);
        found.sort();
        let mut expected = vec![
            "key b918f47ffef3ae77cf84e4a04d0f3017f57ba1eb has no signing capable key".to_string(),
            "key da4611b79a6e99086b36f6e6dd0d12b258d9a626 has no signing capable key".to_string(),
            format!("signing subkey {SEAN_SUBKEY} of key {SEAN_PRIMARY} expired at 1788546197"),
        ];
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn lookup_finds_a_known_key_and_misses_an_unknown_one() {
        let allowlist = Allowlist::parse_at(EMBEDDED, NOW).unwrap();

        let by_fingerprint = allowlist
            .lookup(Some(&fingerprint(RICHARD_PRIMARY)), None)
            .expect("known primary fingerprint is not in the allowlist");
        assert_eq!(by_fingerprint.primary_fingerprint, RICHARD_PRIMARY);
        assert!(matches!(
            by_fingerprint.verifying_key(),
            SigningKey::Primary(_)
        ));
        assert_eq!(
            by_fingerprint.certificate().primary_key.fingerprint(),
            fingerprint(RICHARD_PRIMARY)
        );

        let by_key_id = allowlist
            .lookup(None, Some(&key_id(RICHARD_KEY_ID)))
            .expect("known key id is not in the allowlist");
        assert_eq!(by_key_id.primary_fingerprint, RICHARD_PRIMARY);

        assert!(
            allowlist
                .lookup(None, Some(&key_id("0123456789abcdef")))
                .is_none()
        );
        assert!(
            allowlist
                .lookup(Some(&fingerprint(&"ab".repeat(20))), None)
                .is_none()
        );
    }

    #[test]
    fn an_expired_signing_subkey_is_not_indexed() {
        let allowlist = Allowlist::parse_at(EMBEDDED, NOW).unwrap();
        assert!(
            allowlist
                .lookup(Some(&fingerprint(SEAN_SUBKEY)), None)
                .is_none()
        );
        // This certificate has a certify only primary, so nothing of it is left.
        assert!(
            allowlist
                .lookup(Some(&fingerprint(SEAN_PRIMARY)), None)
                .is_none()
        );

        // The same subkey is usable before it expired.
        let earlier = Allowlist::parse_at(EMBEDDED, EARLIER).unwrap();
        let entry = earlier
            .lookup(Some(&fingerprint(SEAN_SUBKEY)), None)
            .expect("the subkey is missing before it expired");
        assert_eq!(entry.primary_fingerprint, SEAN_PRIMARY);
        assert!(
            earlier
                .check(EARLIER)
                .iter()
                .all(|d| !d.contains(SEAN_SUBKEY))
        );
    }

    #[test]
    fn input_without_a_key_block_is_rejected() {
        assert!(matches!(
            Allowlist::parse_at(b"no keys here", NOW),
            Err(AllowlistError::NoKeyBlock)
        ));
    }
}
