# spiffile

**A files profile for SPIFFE — and libraries that implement it.**

[![test](https://github.com/PeterSR/spiffile/actions/workflows/test.yml/badge.svg)](https://github.com/PeterSR/spiffile/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## The hole

[SPIFFE](https://spiffe.io) standardizes workload identity beautifully: IDs,
JWT/X.509 identity documents, trust bundles. Those specs are small,
technology-neutral, and easy to implement.

Then there's the delivery side. The only specified way for a workload to
*receive* its identity is the [Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
— which mandates gRPC, a local agent socket, and in practice an
attestation/rotation control plane like [SPIRE](https://spiffe.io/docs/latest/spire-about/).
That's the right machinery at a certain scale. Below that scale, there's a
gap the spec never filled: **a minimal profile where SVIDs and trust bundles
are simply files on disk**, put there by whatever infrastructure you already
trust — a secrets operator, a mounted Secret, a deploy script, your dev
tooling.

The ecosystem clearly wants this layer to exist:
[spiffe-helper](https://github.com/spiffe/spiffe-helper) is an official tool
whose only job is bridging the Workload API *to files*, because that's what
real applications can actually consume. The files side just never got
written down as a profile of its own.

spiffile writes it down — and implements it.

## What's here

1. **[PROFILE.md](PROFILE.md)** — the missing page of spec: a file layout
   for identity material, a bundle document format, and verification rules.
   Language-neutral, a few pages, implementable in an afternoon.
2. **Libraries** that implement it, so partaking in trusted
   service-to-service communication is a few lines of glue. To get the idea:

```python
from spiffile import Identity

identity = Identity.from_env()

# outbound: prove who you are
token = identity.token(audience="spiffe://example.org/billing")

# inbound: know who's calling
caller = identity.verify(token_from_request)
caller.id  # spiffe://example.org/orders — cryptographically verified
```

3. **Provisioning primitives** — generate keypairs, maintain bundles,
   rotate, revoke — so your own tooling (CLIs, operators, scripts) stays
   thin glue over a tested core.

| Language | Install | Usage docs |
|---|---|---|
| Python | `pip install spiffile` | [python/README.md](python/README.md) |
| TypeScript | `npm install spiffile` (zero runtime deps) | [ts/README.md](ts/README.md) |
| Go | `go get github.com/PeterSR/spiffile/go` | [go/README.md](go/README.md) |

All implementations cover the full surface — mint, verify, provision — and
are pinned to a shared [conformance suite](conformance/): same validation
rules, same thumbprints, and every implementation's tokens verify in every
other.

## Getting started

Identities are files, so trying it takes one library and a directory.
Provision a local trust root with two services — each gets a keypair, the
bundle collects everyone's public keys:

```python
from spiffile.provision import init_root, add_service, service_env

root = init_root("./identity", trust_domain="example.org")
add_service(root, "orders")
add_service(root, "billing")

service_env(root, "orders")
# {"SPIFFILE_ID_FILE":     "./identity/services/orders/id",
#  "SPIFFILE_KEY_FILE":    "./identity/services/orders/key.pem",
#  "SPIFFILE_BUNDLE_FILE": "./identity/bundle.json"}
```

Run each service with its three environment variables and add the few lines
from above: `Identity.from_env()` at startup, `identity.token(...)` as a
Bearer header on the way out, `identity.verify(...)` on the way in. The
verified caller ID is what you authorize against. Same flow in every
language; the per-language READMEs have copy-pasteable framework sketches
(FastAPI, Express) and the full provisioning surface.

That's the whole system. Production differs only in *who writes the files*
— see below.

## What you get

- **No new runtime components.** Nothing to deploy or page anyone about.
  Verification is offline against a local file; the bundle hot-reloads on
  change, so rotation needs no restarts.
- **No shared secrets.** Each service holds its own private key; everyone
  else sees only public keys. A verifier can *verify* you — never
  *impersonate* you.
- **Short-lived, audience-bound tokens** (JWT-SVIDs): a captured token dies
  in about a minute and only ever worked against one target.
- **A trust root you already operate.** Whoever writes the bundle file
  controls identity — typically your secrets store, guarded like every other
  credential you have.
- **Identical code path in dev and prod.** Identities are files, so a dev
  machine generates keys into a directory and runs the same verification as
  production. No `if dev: skip_auth()`.

## Relation to the SPIFFE standards

| Standard | spiffile |
|---|---|
| [SPIFFE-ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) | implemented |
| [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) | implemented |
| [Trust bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md) | implemented; distribution is files (the spec leaves distribution out of scope) |
| [Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) | intentionally not — that's the gap this project routes around |

One deliberate extension: without a central issuer, each workload signs its
own tokens, so the spiffile bundle binds keys **per identity** rather than
per trust domain — the property that makes self-issued tokens safe. If you
later move to SPIRE, your services' identity model doesn't change;
spiffe-helper already delivers SPIRE-issued material as files.

## Getting the files there

Anything that writes files is a producer:

- **Kubernetes** — [spiffile-operator](https://github.com/PeterSR/spiffile-operator)
  turns CRDs into mounted identity files: `ServiceIdentity` mints and
  rotates keys in-cluster, `ServiceIdentityClaim` delivers
  externally-managed material, and an optional webhook injects the volume
  and `SPIFFILE_*` environment variables into your pods.
- **Secrets operator** (e.g. [External Secrets Operator](https://external-secrets.io)):
  private key in each service's secret path, bundle in a shared path synced
  everywhere. Rotation and revocation become secret updates.
- **Plain Kubernetes Secrets** mounted as volumes.
- **Your own scripts/CLI** over the provisioning primitives.
- **SPIRE + spiffe-helper**, when you graduate to full attestation.

## Status

The profile is **v0** — stable in shape, pre-release in label; feedback on
it is the most valuable contribution there is. The Python, TypeScript and Go
implementations cover the full surface and are kept interchangeable by the
[conformance suite](conformance/), which CI runs on every change. Expect
minor API movement before 1.0. Ports to other languages are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing & security

Contributions welcome — [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and
the cross-implementation parity contract. Please report suspected
vulnerabilities privately per [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
