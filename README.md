# tvc-gpg

A [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com) enclave app.
It holds a team OpenPGP key derived from the quorum key and releases PGP
session keys to allowlisted engineers.

## Endpoints

```sh
$ curl localhost:44020/health
{"status":"healthy"}
```
Also serves `/metrics` in Prometheus text format.

## Development

```
make run    # start the server on http://127.0.0.1:44020
make test   # run unit and end-to-end tests
make lint   # run clippy
```

## Building OCI containers

This repository uses [StageX](https://stagex.tools) to build OCI containers,
with Docker >= 26 and containerd:

```sh
make out/tvc-gpg/index.json
```
