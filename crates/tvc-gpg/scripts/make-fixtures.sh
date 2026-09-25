#!/usr/bin/env bash
# Build stock-gpg interop fixtures for the tvc-gpg crate.
#
# The team OpenPGP key never has a local gpg secret half: it lives only
# inside the enclave binary, derived from the quorum seed. To learn the
# OpenPGP session key of a message encrypted to the team key, this script
# also encrypts to a throwaway "helper" gpg recipient in the same call
# (both PKESK packets wrap the same session key), decrypts with the
# helper's secret key to read that session key, then strips the helper's
# PKESK packet out of the fixture so the file matches the single-recipient
# shape the server expects. The helper's secret key never leaves the
# ephemeral GNUPGHOME and is never exported.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/tvc-gpg"
FIXTURES_DIR="$CRATE_DIR/fixtures"
mkdir -p "$FIXTURES_DIR"

export PATH="$HOME/.cargo/bin:$PATH"

GNUPGHOME="$(mktemp -d /tmp/tg.XXXXXX)"
chmod 700 "$GNUPGHOME"
export GNUPGHOME
WORKDIR="$(mktemp -d /tmp/tgw.XXXXXX)"

cleanup() {
  gpgconf --kill all >/dev/null 2>&1 || true
  rm -rf "$GNUPGHOME" "$WORKDIR"
}
trap cleanup EXIT

GPG=(gpg --batch --yes --pinentry-mode loopback --passphrase '')

# ---------------------------------------------------------------------------
# Packet-header parser: reads the OpenPGP packet stream in a binary file,
# writes the hex of the packet whose PKESK key id matches $2 to $4, and
# writes the remaining bytes with only that PKESK kept (matched packet plus
# every non-PKESK packet, in original order) to $3.
# ---------------------------------------------------------------------------
cat > "$WORKDIR/strip_pkesk.py" <<'PYEOF'
import sys

def packets(data):
    i, n, out = 0, len(data), []
    while i < n:
        start = i
        first = data[i]
        i += 1
        if first & 0x40:
            tag = first & 0x3F
            o = data[i]
            i += 1
            if o < 192:
                length = o
            elif o < 224:
                length = ((o - 192) << 8) + data[i] + 192
                i += 1
            else:
                length = int.from_bytes(data[i:i + 4], "big")
                i += 4
        else:
            tag = (first >> 2) & 0x0F
            size = {0: 1, 1: 2, 2: 4}[first & 0x03]
            length = int.from_bytes(data[i:i + size], "big")
            i += size
        body = data[i:i + length]
        i += length
        out.append((tag, data[start:i], body))
    return out

data = open(sys.argv[1], "rb").read()
keyid_hex = sys.argv[2].lower()
match, rest = None, b""
for tag, full, body in packets(data):
    if tag == 1:
        if body[1:9].hex() == keyid_hex:
            if body[9] != 18:
                sys.exit(f"key id matched but algo {body[9]} != 18")
            match = full
    else:
        rest += full
if match is None:
    sys.exit(f"no PKESK packet matched key id {keyid_hex}")
open(sys.argv[3], "wb").write(match + rest)
open(sys.argv[4], "w").write(match.hex())
PYEOF

first_packet_is_team_ecdh() {
  # gpg exits non-zero here because it cannot decrypt without a secret key.
  # Only the listing on stdout matters, so capture it without pipefail.
  local listing
  listing=$(gpg --list-packets "$1" 2>/dev/null || true)
  printf '%s\n' "$listing" | sed -n '2p' | grep -q "version 3, algo 18"
}

# ---------------------------------------------------------------------------
# encrypt_show_strip <plain-file> <stripped-out> <pkesk-hex-out> <tag>
#
# Encrypts <plain-file> to the team key and the helper, reads the shared
# session key through the helper's secret key, checks the helper's plaintext,
# strips the helper's PKESK, checks the stripped file still decrypts from the
# session key alone, and prints the session key on stdout. <tag> only names
# the step in error messages.
# ---------------------------------------------------------------------------
encrypt_show_strip() {
  local plain="$1" stripped="$2" pkesk_hex="$3" tag="$4"
  local two_recipients="$WORKDIR/$tag.2r.gpg"
  local helper_plain="$WORKDIR/$tag.helper.bin"
  local stderr="$WORKDIR/$tag.sk.stderr"
  local final="$WORKDIR/$tag.final.bin"
  local session_key

  gpg --batch --trust-model always --auto-key-locate local \
    -r security@turnkey.io -r helper@example.invalid \
    -e -o "$two_recipients" "$plain"

  "${GPG[@]}" --show-session-key -d "$two_recipients" \
    > "$helper_plain" 2> "$stderr"
  session_key=$(sed -n "s/.*session key: '\(.*\)'.*/\1/p" "$stderr")
  [ -n "$session_key" ] || { echo "failed to read the $tag session key" >&2; exit 1; }
  cmp -s "$helper_plain" "$plain" || {
    echo "helper decrypt of $tag did not match the plaintext" >&2; exit 1;
  }

  python3 "$WORKDIR/strip_pkesk.py" "$two_recipients" "$TEAM_KEYID" \
    "$stripped" "$pkesk_hex"

  first_packet_is_team_ecdh "$stripped" || {
    echo "$tag does not start with a version 3, algo 18 PKESK" >&2; exit 1;
  }
  gpg --batch --override-session-key "$session_key" -d "$stripped" > "$final"
  cmp -s "$final" "$plain" || {
    echo "stripped $tag does not decrypt to the original bytes" >&2; exit 1;
  }

  printf '%s' "$session_key"
}

# ---------------------------------------------------------------------------
# 1. Team public key: run the binary with the fixed test seed [7u8; 32].
# ---------------------------------------------------------------------------
python3 -c "print('07' * 32)" > "$WORKDIR/seed.hex"

(cd "$REPO_ROOT" && cargo run -q --bin tvc_gpg -- \
  --quorum-file "$WORKDIR/seed.hex" --app-id test-app --print-public-key \
  > "$WORKDIR/team-public.asc")

# team-public.asc must be byte-identical across runs: same seed, same
# KEY_CREATED_AT, no randomness in key derivation or the self signature.
if [ -f "$FIXTURES_DIR/team-public.asc" ]; then
  cmp -s "$WORKDIR/team-public.asc" "$FIXTURES_DIR/team-public.asc" || {
    echo "team-public.asc changed across a regeneration; investigate before overwriting" >&2
    exit 1
  }
fi
cp "$WORKDIR/team-public.asc" "$FIXTURES_DIR/team-public.asc"

gpg --batch --import "$FIXTURES_DIR/team-public.asc"
TEAM_KEYID=$(gpg --with-colons --list-keys security@turnkey.io \
  | awk -F: '$1=="sub"{print $5}' | tr 'A-Z' 'a-z')
[ -n "$TEAM_KEYID" ] || { echo "could not find team subkey id" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2. Signers and the throwaway helper recipient.
# ---------------------------------------------------------------------------
"${GPG[@]}" --quick-gen-key 'RSA Signer <rsa@example.invalid>' rsa4096 sign 0
"${GPG[@]}" --quick-gen-key 'Ed Signer <ed@example.invalid>' ed25519 sign 0
"${GPG[@]}" --quick-gen-key 'Helper <helper@example.invalid>' rsa2048 encrypt 0

# A certify only primary with one RSA signing subkey. That is the shape 52
# of the 55 real engineer keys have, so it is the branch most callers use.
"${GPG[@]}" --quick-gen-key 'Sub Signer <sub@example.invalid>' rsa4096 cert 0
SUB_FPR=$(gpg --with-colons --list-keys sub@example.invalid \
  | awk -F: '$1=="fpr"{print $10; exit}')
[ -n "$SUB_FPR" ] || { echo "could not find the subkey signer fingerprint" >&2; exit 1; }
"${GPG[@]}" --quick-add-key "$SUB_FPR" rsa4096 sign 0

gpg --armor --export rsa@example.invalid > "$FIXTURES_DIR/rsa-signer.asc"
gpg --armor --export ed@example.invalid > "$FIXTURES_DIR/ed25519-signer.asc"
gpg --armor --export sub@example.invalid > "$FIXTURES_DIR/rsa-subkey-signer.asc"

# ---------------------------------------------------------------------------
# 3. message.gpg: encrypt to team + helper, read the session key via the
#    helper's secret key, then strip the helper's PKESK out.
# ---------------------------------------------------------------------------
printf 'hello team\n' > "$WORKDIR/plain.txt"
SESSION_KEY=$(encrypt_show_strip "$WORKDIR/plain.txt" \
  "$FIXTURES_DIR/message.gpg" "$FIXTURES_DIR/message.pkesk.hex" message)
printf '%s' "$SESSION_KEY" > "$FIXTURES_DIR/session-key.txt"

# ---------------------------------------------------------------------------
# 4. sops-datakey.asc: same shape, armored, over 32 random bytes.
# ---------------------------------------------------------------------------
openssl rand 32 > "$FIXTURES_DIR/sops-data.bin"
SOPS_SESSION_KEY=$(encrypt_show_strip "$FIXTURES_DIR/sops-data.bin" \
  "$WORKDIR/sops-data-team.gpg" "$FIXTURES_DIR/sops-datakey.pkesk.hex" sops)
printf '%s' "$SOPS_SESSION_KEY" > "$FIXTURES_DIR/sops-session-key.txt"

gpg --enarmor < "$WORKDIR/sops-data-team.gpg" > "$WORKDIR/sops-data-team.enarmor"
sed 's/ARMORED FILE/MESSAGE/' "$WORKDIR/sops-data-team.enarmor" > "$FIXTURES_DIR/sops-datakey.asc"

gpg --dearmor --output "$WORKDIR/sops-dearmored.gpg" < "$FIXTURES_DIR/sops-datakey.asc"
cmp -s "$WORKDIR/sops-dearmored.gpg" "$WORKDIR/sops-data-team.gpg" || {
  echo "dearmored sops-datakey.asc does not match the stripped binary" >&2; exit 1;
}

# ---------------------------------------------------------------------------
# 5. Transport test key pair: a fixed, documented raw P-256 scalar.
# ---------------------------------------------------------------------------
TRANSPORT_PUBLIC_KEY=$(FIXTURES_DIR="$FIXTURES_DIR" python3 <<'PYEOF'
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

key = ec.generate_private_key(ec.SECP256R1())
priv = key.private_numbers().private_value.to_bytes(32, "big")
pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
out_path = os.path.join(os.environ["FIXTURES_DIR"], "transport-secret.hex")
with open(out_path, "w") as f:
    f.write(priv.hex())
print(pub.hex())
PYEOF
)
[ -f "$FIXTURES_DIR/transport-secret.hex" ] || {
  echo "transport-secret.hex was not written" >&2; exit 1;
}

# ---------------------------------------------------------------------------
# 6. Payloads, signed by both stock-gpg signers.
# ---------------------------------------------------------------------------
build_payload() {
  python3 -c "
import json, sys
domain, app_id, pkesk_hex, pub_hex, t, out = sys.argv[1:7]
obj = {'domain': domain, 'app_id': app_id, 'pkesk': pkesk_hex,
       'transport_public_key': pub_hex, 'time': int(t)}
open(out, 'wb').write(json.dumps(obj, separators=(',', ':')).encode())
" "$1" "$2" "$3" "$4" "$5" "$6"
}

MESSAGE_PKESK=$(cat "$FIXTURES_DIR/message.pkesk.hex")
SOPS_PKESK=$(cat "$FIXTURES_DIR/sops-datakey.pkesk.hex")

build_payload "tvc gpg session key request" "test-app" "$MESSAGE_PKESK" \
  "$TRANSPORT_PUBLIC_KEY" "1790000000" "$FIXTURES_DIR/payload.json"
build_payload "tvc gpg session key request" "test-app" "$SOPS_PKESK" \
  "$TRANSPORT_PUBLIC_KEY" "1790000000" "$FIXTURES_DIR/sops-payload.json"

"${GPG[@]}" --local-user rsa@example.invalid --digest-algo SHA256 \
  --detach-sign -o "$FIXTURES_DIR/payload.sig.rsa" "$FIXTURES_DIR/payload.json"
# No --digest-algo here. The Ed25519 key picks SHA-512 by itself, which is
# what a real engineer's `gpg --detach-sign` emits and what proves the app
# accepts more than SHA-256.
"${GPG[@]}" --local-user ed@example.invalid \
  --detach-sign -o "$FIXTURES_DIR/payload.sig.ed25519" "$FIXTURES_DIR/payload.json"
"${GPG[@]}" --local-user sub@example.invalid --digest-algo SHA256 \
  --detach-sign -o "$FIXTURES_DIR/payload.sig.rsa-subkey" "$FIXTURES_DIR/payload.json"
"${GPG[@]}" --local-user rsa@example.invalid --digest-algo SHA256 \
  --detach-sign -o "$FIXTURES_DIR/sops-payload.sig.rsa" "$FIXTURES_DIR/sops-payload.json"

gpg --verify "$FIXTURES_DIR/payload.sig.rsa" "$FIXTURES_DIR/payload.json"
gpg --verify "$FIXTURES_DIR/payload.sig.ed25519" "$FIXTURES_DIR/payload.json"
gpg --verify "$FIXTURES_DIR/payload.sig.rsa-subkey" "$FIXTURES_DIR/payload.json"
gpg --verify "$FIXTURES_DIR/sops-payload.sig.rsa" "$FIXTURES_DIR/sops-payload.json"

echo "Fixtures written to $FIXTURES_DIR"
