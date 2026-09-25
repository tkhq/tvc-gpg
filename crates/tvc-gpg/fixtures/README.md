# tvc-gpg stock-gpg interop fixtures

These files exercise the server's OpenPGP decode and verify logic against
byte streams that a real, unmodified `gpg` produced. They are not signed
by any Rust code in this repo.

## Regenerating

```
crates/tvc-gpg/scripts/make-fixtures.sh
```

Run it from anywhere. It finds the repo root from its own path. It
needs `gpg` 2.5+ and `cargo` on `PATH`, and the `cryptography` Python
package (used only for the transport test key). The script checks its
own output: if `fixtures/team-public.asc` already exists, it compares
the freshly built key against it byte for byte and stops on a mismatch.

### What stays the same, what does not

Only `team-public.asc` is deterministic. The fixed test seed
(`[7u8; 32]`, 64 hex `07` bytes) and the fixed `KEY_CREATED_AT` produce
the same key bytes every run, and the script checks that on every run
(see above).

Every other file is fresh on each run: the RSA and Ed25519 signer keys,
the helper key, both session keys, the sops random bytes, the transport
key pair, and every signature. Regenerating changes those bytes even
though the fixture shapes stay the same. Do not assert byte-for-byte
equality on anything but `team-public.asc` in tests that regenerate
fixtures.

## Files

- `team-public.asc`: the team OpenPGP public key, printed by the
  `tvc_gpg` binary itself (`--quorum-file <seed> --app-id test-app
  --print-public-key`) from the seed above. This is the only key file
  in this directory with no matching secret key anywhere: the server
  derives it from the seed at start-up and never writes it to disk.
- `rsa-signer.asc`, `ed25519-signer.asc`: public keys for a throwaway
  RSA-4096 and a throwaway Ed25519 signer, both of which sign with the
  primary key itself.
- `rsa-subkey-signer.asc`: a throwaway RSA-4096 certify only primary
  with one RSA-4096 signing subkey. That is the shape 52 of the 55 real
  engineer keys in `allowlist/` have, so it covers the branch almost
  every caller takes. All three signers are allowlisted by the interop
  test.
- `message.gpg`: `hello team\n` encrypted to the team key, binary
  (not armored). Starts with one PKESK packet (version 3, algorithm
  18, the team subkey's key id) followed by one SEIPD packet.
- `message.pkesk.hex`: hex of that PKESK packet (header and body).
- `session-key.txt`: the message's OpenPGP session key, in gpg's own
  `<cipher-algo-id>:<hex>` form (see "How the session keys were read"
  below).
- `sops-data.bin`: the 32 random bytes inside `sops-datakey.asc`, kept
  so a test can compare what it opened against what was encrypted.
- `sops-datakey.asc`: those 32 random bytes encrypted to the team key,
  in the same single-PKESK-then-SEIPD shape as `message.gpg` but ASCII
  armored, the shape `sops` uses for its PGP-wrapped data key. This is
  a shape fixture only. It does not run `sops` or the gpg shim.
- `sops-datakey.pkesk.hex`: hex of that file's PKESK packet, extracted
  after dearmoring.
- `sops-session-key.txt`: that file's session key, same format as
  `session-key.txt`.
- `transport-secret.hex`: a 32-byte P-256 scalar, the fixed test
  transport secret (see "Transport key" below).
- `payload.json`: the exact bytes the interop test should sign, an
  object with keys in the order `domain`, `app_id`, `pkesk`,
  `transport_public_key`, `time`, no inserted whitespace, no trailing
  newline. `pkesk` is `message.pkesk.hex`. `transport_public_key` is
  the 65-byte uncompressed point matching `transport-secret.hex`.
- `payload.sig.rsa`, `payload.sig.ed25519`,
  `payload.sig.rsa-subkey`: detached signatures over `payload.json`'s
  exact bytes, from the three signers above. The RSA ones are pinned to
  SHA-256, which is what those keys would pick anyway. The Ed25519 one
  carries no `--digest-algo`, so gpg picks SHA-512 for it, which is what
  a real engineer's `gpg --detach-sign` emits and what proves the app
  accepts more than SHA-256.
- `sops-payload.json`: the same shape as `payload.json`, but `pkesk`
  is `sops-datakey.pkesk.hex`, to exercise the sops PKESK path.
- `sops-payload.sig.rsa`: detached RSA signature over
  `sops-payload.json`.

## How the session keys were read

The team key has no local `gpg` secret half. It lives only inside the
enclave binary, derived from the seed. To read the OpenPGP session key
of a message encrypted to the team key, the script also encrypts to a
throwaway "helper" gpg key in the same call. Multi-recipient OpenPGP
encryption wraps one shared session key per recipient, so the helper's
PKESK and the team's PKESK wrap the same key. The script decrypts with
the helper's secret key (`gpg --show-session-key -d`) to read that
session key, then parses the packet stream, keeps only the PKESK whose
key id matches the team subkey, and drops the helper's PKESK. The
result is `message.gpg` and `sops-datakey.asc` as they appear above:
a single PKESK addressed to the team key, followed by the encrypted
data. The helper's secret key never leaves the script's ephemeral
`GNUPGHOME` and is never exported or printed.

The script confirms this stripped file is still correct by decrypting
it with `gpg --override-session-key <key> -d`, which decrypts straight
from the session key without needing any secret key, and checking the
plaintext matches.

## Transport key

The request payload's `transport_public_key` is a P-256 point used
with `qos_p256::P256EncryptPublic::encrypt`. There is no shell path to
generate a `qos_p256` key pair directly, so the fixture uses a fixed,
documented raw P-256 scalar instead: `transport-secret.hex` holds 32
bytes generated with Python's `cryptography` library, and
`payload.json`'s `transport_public_key` holds the matching 65-byte
uncompressed point (`04` followed by X and Y, big-endian).

`qos_p256`'s normal key pairs derive their scalar from a master seed
through HKDF. A test that wants to reconstruct this exact pair must
build it from the raw scalar instead, not from a seed. `qos_p256`
0.14.1 supports this directly:
`P256EncryptPair::from_bytes(bytes: &Zeroizing<Vec<u8>>)` at
`~/.cargo/registry/src/*/qos_p256-0.14.1/src/encrypt.rs:112` builds a
pair straight from a raw 32-byte scalar slice, via
`SecretKey::from_slice`, with no HKDF step. This constructor exists in
0.14.1 and is the one to use here.
