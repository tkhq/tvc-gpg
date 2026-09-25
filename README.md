# tvc-gpg

A [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com) enclave app.
It holds a team OpenPGP key derived from the quorum key and releases PGP
session keys to allowlisted engineers. The build embeds the allowlist of
engineer GPG public keys into the binary, so only those engineers can read
messages encrypted to the team key.

## Endpoints

`GET /health`, `GET /public-key`, and `GET /revocation-certificate` take no
input.

```sh
$ curl localhost:44020/health
{"status":"healthy"}

$ curl localhost:44020/public-key
-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----

$ curl localhost:44020/revocation-certificate
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

`POST /session-key` takes a JSON body:

```json
{
  "payload": "<the exact JSON string the caller signed>",
  "signature": "<hex, OpenPGP detached signature packet over payload>"
}
```

`payload` is the caller's canonical JSON of:

```json
{
  "domain": "tvc gpg session key request",
  "app_id": "<TVC app id>",
  "pkesk": "<hex, the full PKESK packet including header>",
  "transport_public_key": "<hex, 65 byte uncompressed P-256 point>",
  "time": 1790000000
}
```

The app checks the signature and the payload, then unwraps the PKESK with
the team key and re-wraps the session key to the caller's transport key. On
success it returns:

```json
{
  "wrapped_session_key": "<hex, HPKE envelope>",
  "receipt_json": "<canonical JSON string>",
  "receipt_signature": "<hex>",
  "quorum_public_key": "<hex, 130 bytes>"
}
```

Every check up to and including the payload checks (body shape, signature
shape, unknown signer, bad signature, wrong domain or app id, a clock too
far off) returns its own fixed message, so a caller can tell those apart.
Every check from PKESK parsing onward returns one fixed body,
`{"error":"session key request rejected"}`, with status 400. The gpg shim
is the intended client. It signs the payload with `gpg --detach-sign` and
builds the PKESK from the message it wants to read.

The app also serves `/metrics` in Prometheus text format.

## Development

```
make run    # start the server on http://127.0.0.1:44020
make test   # run unit and end-to-end tests
make lint   # run clippy
```

`make run` writes a random local quorum key to
`/tmp/tvc-gpg-local-enclave/qos.quorum.key` on first run, then starts the
server with `--app-id local`. It does not use a real TVC enclave, so the
team key it derives is a throwaway key for local testing only.

## Allowlist refresh

The allowlist lives in `allowlist/`. Only files from `team/gpg/*.asc` in
`tkhq/keys` belong there. Never add a key from `shared/gpg`.

To add or remove an engineer:

1. Copy the updated `team/gpg/*.asc` files from a clean checkout of
   `tkhq/keys` into `allowlist/`.
2. Write the new `tkhq/keys` commit hash into `allowlist/KEYS_COMMIT`.
3. Rebuild the image (see below).
4. Create a new TVC deployment and approve it.

## Building OCI containers

This repository uses [StageX](https://stagex.tools) to build OCI containers,
with Docker >= 26 and containerd:

```sh
make out/tvc-gpg/index.json
```

The CI stagex workflow builds the same image, pushes it to
`ghcr.io/tkhq/tvc-gpg`, and prints the image URL, digest, and expected
pivot binary digest to deploy.

## Deploying to TVC

The dev deployment is reachable at
`https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering`. Deploy with:

```sh
tvc deploy create --app-id <APP_ID> --qos-version 0.12.1 \
  --pivot-image-url <image url with digest from the stagex job summary> \
  --expected-pivot-digest <binary sha256 from the job summary> \
  --pivot-path /tvc_app --pivot-args=--app-id,<APP_ID> \
  --public-ingress-port 44020 --health-check-port 44020 --replicas 1
tvc deploy approve --deploy-id <DEPLOYMENT_ID>
```

Use the equals form of `--pivot-args`. Its value starts with `--`, and the
CLI cannot parse that as a separate argument.

The dev app uses the well known bootstrap quorum key, so its team key is for
testing only. Do not treat it as a real team key.

### Genesis build

The app checks its own subkey fingerprint at startup against
`EXPECTED_SUBKEY_FINGERPRINT` in `crates/tvc-gpg/src/team_key.rs`. The first
build leaves that constant unset, because the fingerprint is only knowable
once the app has derived it from the live quorum key. Bringing up a new app
therefore takes two builds:

1. Build and deploy with `EXPECTED_SUBKEY_FINGERPRINT` set to `None`.
2. Read the fingerprint from `/public-key` on the running app, set the
   constant to that value, then rebuild and deploy again.

After the second build, a mismatched fingerprint at startup means the
running binary does not match the quorum key, and the app exits before it
opens its port.
