//! Team OpenPGP key derived from the quorum key.
//!
//! The team key is a v4 ECDSA P-256 primary key that certifies one v4 ECDH
//! P-256 encryption subkey. Both scalars come from the quorum key master seed
//! through HKDF, and every timestamp in the key is pinned to
//! [`KEY_CREATED_AT`], so the same seed always rebuilds the same key bytes.

use pgp::composed::{
    ArmorOptions, DetachedSignature, SignedKeyDetails, SignedSecretKey, SignedSecretSubKey,
};
use pgp::crypto::{
    ecdh, ecdsa, hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm,
};
use pgp::packet::{
    Features, KeyFlags, PubKeyInner, PublicKey, PublicSubkey, RevocationCode, SecretSubkey,
    SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId,
};
use pgp::types::{
    EcdhPublicParams, EcdsaPublicParams, KeyDetails as _, KeyId, KeyVersion, Password,
    PlainSecretParams, PublicParams, SecretParams, Tag, Timestamp,
};
use qos_p256::{MASTER_SEED_LEN, P256Error, P256Pair, derive_secret};
use zeroize::Zeroizing;

/// Creation time stamped on both keys and on every signature in the key.
pub const KEY_CREATED_AT: u32 = 1_790_000_000;

/// User ID certified by the primary key.
pub const USER_ID: &str = "Turnkey Security Team <security@turnkey.io>";

/// Subkey fingerprint this build must produce, if the build pins one.
pub const EXPECTED_SUBKEY_FINGERPRINT: Option<&str> = None;

/// HKDF salt for the primary signing key.
const PRIMARY_PATH: &[u8] = b"tvc_gpg_primary";

/// HKDF salt for the encryption subkey.
const SUBKEY_PATH: &[u8] = b"tvc_gpg_encrypt";

/// Reason text in the revocation certificate.
const REVOCATION_REASON: &str = "key retired";

/// Error returned when the team key cannot be derived or exported.
#[derive(Debug)]
pub enum TeamKeyError {
    /// HKDF derivation from the quorum key master seed failed.
    Derive(P256Error),
    /// No counter byte gave a scalar in range for P-256.
    DerivationExhausted,
    /// An OpenPGP packet, signature or armor operation failed.
    Pgp(pgp::errors::Error),
}

impl std::fmt::Display for TeamKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Derive(e) => write!(f, "failed to derive from the quorum seed: {e:?}"),
            Self::DerivationExhausted => write!(f, "no counter byte gave a valid P-256 scalar"),
            Self::Pgp(e) => write!(f, "OpenPGP operation failed: {e}"),
        }
    }
}

impl std::error::Error for TeamKeyError {}

impl From<P256Error> for TeamKeyError {
    fn from(e: P256Error) -> Self {
        Self::Derive(e)
    }
}

impl From<pgp::errors::Error> for TeamKeyError {
    fn from(e: pgp::errors::Error) -> Self {
        Self::Pgp(e)
    }
}

/// The team OpenPGP key held by this app.
pub struct TeamKey {
    secret: SignedSecretKey,
}

impl TeamKey {
    /// Derive the team key from the quorum key.
    ///
    /// # Errors
    ///
    /// Returns [`TeamKeyError`] if HKDF derivation fails, if no counter byte
    /// gives a valid P-256 scalar, or if rPGP rejects the packets.
    pub fn derive(quorum: &P256Pair) -> Result<Self, TeamKeyError> {
        let seed = quorum.to_master_seed();
        let created_at = Timestamp::from_secs(KEY_CREATED_AT);

        let primary_scalar = derive_scalar(seed, PRIMARY_PATH)?;
        let primary_public = PublicKey::from_inner(PubKeyInner::new(
            KeyVersion::V4,
            PublicKeyAlgorithm::ECDSA,
            created_at,
            None,
            PublicParams::ECDSA(EcdsaPublicParams::P256 {
                key: primary_scalar.public_key(),
            }),
        )?)?;
        let primary = pgp::packet::SecretKey::new(
            primary_public,
            SecretParams::Plain(PlainSecretParams::ECDSA(ecdsa::SecretKey::P256(
                primary_scalar,
            ))),
        )?;

        let subkey_scalar = derive_scalar(seed, SUBKEY_PATH)?;
        let subkey_public = PublicSubkey::from_inner(PubKeyInner::new(
            KeyVersion::V4,
            PublicKeyAlgorithm::ECDH,
            created_at,
            None,
            PublicParams::ECDH(EcdhPublicParams::P256 {
                p: subkey_scalar.public_key(),
                hash: HashAlgorithm::Sha256,
                alg_sym: SymmetricKeyAlgorithm::AES128,
            }),
        )?)?;
        let subkey = SecretSubkey::new(
            subkey_public,
            SecretParams::Plain(PlainSecretParams::ECDH(ecdh::SecretKey::P256 {
                secret: subkey_scalar,
            })),
        )?;

        let self_signature = certify_user_id(&primary, created_at)?;
        let binding = bind_subkey(&primary, &subkey, created_at)?;

        let user_id = user_id()?;
        let details = SignedKeyDetails::new(
            vec![],
            vec![],
            vec![user_id.into_signed(self_signature)],
            vec![],
        );
        let secret = SignedSecretKey::new(
            primary,
            details,
            vec![],
            vec![SignedSecretSubKey::new(subkey, vec![binding])],
        );

        Ok(Self { secret })
    }

    /// The encryption subkey, used to unwrap session keys.
    #[must_use]
    pub fn encryption_subkey(&self) -> &SecretSubkey {
        // `derive` always builds exactly one subkey.
        &self.secret.secret_subkeys[0].key
    }

    /// Fingerprint of the encryption subkey, as 40 upper case hex characters.
    #[must_use]
    pub fn subkey_fingerprint(&self) -> String {
        qos_hex::encode(self.encryption_subkey().fingerprint().as_bytes()).to_uppercase()
    }

    /// Key ID of the encryption subkey.
    #[must_use]
    pub fn subkey_key_id(&self) -> KeyId {
        self.encryption_subkey().legacy_key_id()
    }

    /// The public half of the team key, in armored form.
    ///
    /// # Errors
    ///
    /// Returns [`TeamKeyError::Pgp`] if rPGP cannot serialize the key.
    pub fn public_key_armored(&self) -> Result<String, TeamKeyError> {
        Ok(self
            .secret
            .to_public_key()
            .to_armored_string(ArmorOptions::default())?)
    }

    /// A revocation certificate for the primary key, in armored form.
    ///
    /// # Errors
    ///
    /// Returns [`TeamKeyError::Pgp`] if rPGP cannot build or serialize the
    /// signature.
    pub fn revocation_certificate_armored(&self) -> Result<String, TeamKeyError> {
        let primary = &self.secret.primary_key;
        let mut config = SignatureConfig::v4(
            SignatureType::KeyRevocation,
            PublicKeyAlgorithm::ECDSA,
            HashAlgorithm::Sha256,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                KEY_CREATED_AT,
            )))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
            Subpacket::regular(SubpacketData::RevocationReason(
                RevocationCode::KeyRetired,
                REVOCATION_REASON.into(),
            ))?,
        ];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            primary.legacy_key_id(),
        ))?];

        let signature = config.sign_key(primary, &Password::empty(), primary.public_key())?;
        Ok(DetachedSignature::new(signature).to_armored_string(ArmorOptions::default())?)
    }
}

/// Build the certified user ID packet.
fn user_id() -> Result<UserId, TeamKeyError> {
    Ok(UserId::from_str(Default::default(), USER_ID)?)
}

/// Derive a P-256 scalar from the master seed at `path`.
///
/// HKDF output that is zero or at or above the group order is rejected. A
/// counter byte is then appended to the salt and the derivation is repeated.
fn derive_scalar(
    seed: &Zeroizing<[u8; MASTER_SEED_LEN]>,
    path: &[u8],
) -> Result<p256::SecretKey, TeamKeyError> {
    let mut salt = path.to_vec();
    for counter in 0..=u8::MAX {
        if counter > 0 {
            salt.truncate(path.len());
            salt.push(counter);
        }
        let bytes = derive_secret(seed, &salt)?;
        if let Ok(scalar) = p256::SecretKey::from_slice(&bytes[..]) {
            return Ok(scalar);
        }
    }
    Err(TeamKeyError::DerivationExhausted)
}

/// Self certify the user ID with the primary key.
///
/// `KeyDetails::sign` hard codes `Timestamp::now()`, so the signature is built
/// from a `SignatureConfig` here to pin the creation time.
fn certify_user_id(
    primary: &pgp::packet::SecretKey,
    created_at: Timestamp,
) -> Result<pgp::packet::Signature, TeamKeyError> {
    let mut flags = KeyFlags::default();
    flags.set_certify(true);

    let mut features = Features::new();
    features.set_seipd_v1(true);

    let mut config = SignatureConfig::v4(
        SignatureType::CertPositive,
        PublicKeyAlgorithm::ECDSA,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created_at))?,
        Subpacket::regular(SubpacketData::KeyFlags(flags))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
            vec![SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128].into(),
        ))?,
        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
            vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512].into(),
        ))?,
        Subpacket::regular(SubpacketData::Features(features))?,
        Subpacket::regular(SubpacketData::IsPrimary(true))?,
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
        primary.legacy_key_id(),
    ))?];

    Ok(config.sign_certification(
        primary,
        primary.public_key(),
        &Password::empty(),
        Tag::UserId,
        &user_id()?,
    )?)
}

/// Bind the encryption subkey to the primary key.
///
/// `PublicSubkey::sign` hard codes `Timestamp::now()`, so the signature is
/// built from a `SignatureConfig` here to pin the creation time.
fn bind_subkey(
    primary: &pgp::packet::SecretKey,
    subkey: &SecretSubkey,
    created_at: Timestamp,
) -> Result<pgp::packet::Signature, TeamKeyError> {
    let mut flags = KeyFlags::default();
    flags.set_encrypt_comms(true);
    flags.set_encrypt_storage(true);

    let mut config = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        PublicKeyAlgorithm::ECDSA,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created_at))?,
        Subpacket::regular(SubpacketData::KeyFlags(flags))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
        primary.legacy_key_id(),
    ))?];

    Ok(config.sign_subkey_binding(
        primary,
        primary.public_key(),
        &Password::empty(),
        subkey.public_key(),
    )?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pgp::composed::{Deserializable, SignedPublicKey};

    fn team_key(seed: u8) -> TeamKey {
        let quorum = P256Pair::from_master_seed(&Zeroizing::new([seed; MASTER_SEED_LEN]))
            .expect("failed to build the quorum key");
        TeamKey::derive(&quorum).expect("failed to derive the team key")
    }

    #[test]
    fn same_seed_gives_the_same_key() {
        let first = team_key(7);
        let second = team_key(7);

        assert_eq!(
            first.public_key_armored().unwrap(),
            second.public_key_armored().unwrap()
        );
        assert_eq!(first.subkey_fingerprint(), second.subkey_fingerprint());
        assert_eq!(
            first.revocation_certificate_armored().unwrap(),
            second.revocation_certificate_armored().unwrap()
        );
    }

    #[test]
    fn different_seeds_give_different_fingerprints() {
        assert_ne!(
            team_key(7).subkey_fingerprint(),
            team_key(9).subkey_fingerprint()
        );
    }

    #[test]
    fn fingerprint_is_forty_upper_hex_characters() {
        let fingerprint = team_key(7).subkey_fingerprint();
        assert_eq!(fingerprint.len(), 40);
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
        );
    }

    #[test]
    fn armored_key_parses_and_verifies() {
        let armored = team_key(7).public_key_armored().unwrap();
        let (parsed, _) = SignedPublicKey::from_string(&armored).unwrap();

        parsed.verify_bindings().unwrap();
        assert_eq!(parsed.primary_key.algorithm(), PublicKeyAlgorithm::ECDSA);
        assert_eq!(
            parsed.primary_key.created_at(),
            Timestamp::from_secs(KEY_CREATED_AT)
        );
        assert_eq!(parsed.details.users.len(), 1);
        assert_eq!(parsed.details.users[0].id.as_str(), Some(USER_ID));

        assert_eq!(parsed.public_subkeys.len(), 1);
        let subkey = &parsed.public_subkeys[0].key;
        assert_eq!(subkey.algorithm(), PublicKeyAlgorithm::ECDH);
        assert_eq!(subkey.created_at(), Timestamp::from_secs(KEY_CREATED_AT));
        match subkey.public_params() {
            PublicParams::ECDH(EcdhPublicParams::P256 { hash, alg_sym, .. }) => {
                assert_eq!(*hash, HashAlgorithm::Sha256);
                assert_eq!(*alg_sym, SymmetricKeyAlgorithm::AES128);
            }
            other => panic!("unexpected subkey params: {other:?}"),
        }
    }

    #[test]
    fn signatures_carry_the_fixed_creation_time() {
        let armored = team_key(7).public_key_armored().unwrap();
        let (parsed, _) = SignedPublicKey::from_string(&armored).unwrap();

        let fixed = Timestamp::from_secs(KEY_CREATED_AT);
        for signature in &parsed.details.users[0].signatures {
            assert_eq!(signature.created(), Some(fixed));
        }
        for signature in &parsed.public_subkeys[0].signatures {
            assert_eq!(signature.created(), Some(fixed));
        }
    }

    #[test]
    fn revocation_certificate_verifies_against_the_primary() {
        let key = team_key(7);
        let armored = key.revocation_certificate_armored().unwrap();
        let (parsed, _) = DetachedSignature::from_string(&armored).unwrap();

        assert_eq!(parsed.signature.typ(), Some(SignatureType::KeyRevocation));

        let public = SignedPublicKey::from_string(&key.public_key_armored().unwrap())
            .unwrap()
            .0;
        parsed.signature.verify_key(&public.primary_key).unwrap();
    }

    #[test]
    fn subkey_key_id_matches_the_fingerprint_tail() {
        let key = team_key(7);
        let key_id = qos_hex::encode(key.subkey_key_id().as_ref()).to_uppercase();
        assert!(key.subkey_fingerprint().ends_with(&key_id));
    }

    /// Run `gpg` in a throw away home directory. The path stays short because
    /// the gpg agent socket path has a low length limit.
    fn gpg(home: &str, args: &[&str]) -> std::process::Output {
        std::process::Command::new("gpg")
            .args(["--batch", "--no-tty", "--homedir", home])
            .args(args)
            .output()
            .expect("failed to run gpg")
    }

    #[test]
    fn gpg_reads_the_exported_key() {
        if std::process::Command::new("which")
            .arg("gpg")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("gpg is not on PATH, skipping the interop check");
            return;
        }

        let made = std::process::Command::new("mktemp")
            .args(["-d", "/tmp/tg.XXXXXX"])
            .output()
            .expect("failed to run mktemp");
        let home = String::from_utf8(made.stdout)
            .expect("mktemp printed invalid utf8")
            .trim()
            .to_string();

        let key_path = format!("{home}/team.asc");
        std::fs::write(&key_path, team_key(7).public_key_armored().unwrap())
            .expect("failed to write the armored key");

        let imported = gpg(&home, &["--import", &key_path]);
        let listed = gpg(&home, &["--list-keys", "--with-colons"]);
        let colons = String::from_utf8_lossy(&listed.stdout).to_string();

        drop(
            std::process::Command::new("gpgconf")
                .args(["--homedir", &home, "--kill", "all"])
                .output(),
        );
        drop(std::fs::remove_dir_all(&home));

        assert!(imported.status.success(), "gpg --import failed");

        let field = |line: &str, index: usize| -> String {
            line.split(':').nth(index).unwrap_or_default().to_string()
        };
        let pubs: Vec<&str> = colons.lines().filter(|l| l.starts_with("pub:")).collect();
        let subs: Vec<&str> = colons.lines().filter(|l| l.starts_with("sub:")).collect();

        assert_eq!(pubs.len(), 1, "expected one pub line in {colons}");
        assert_eq!(subs.len(), 1, "expected one sub line in {colons}");
        assert_eq!(field(pubs[0], 3), "19", "primary is not ECDSA");
        assert_eq!(field(subs[0], 3), "18", "subkey is not ECDH");
        assert_eq!(field(pubs[0], 16), "nistp256");
        assert_eq!(field(subs[0], 16), "nistp256");
        assert_eq!(field(subs[0], 4).to_uppercase(), {
            let key = team_key(7);
            qos_hex::encode(key.subkey_key_id().as_ref()).to_uppercase()
        });
    }
}
