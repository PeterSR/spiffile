# The spiffile Profile

Version: 0 (pre-release, subject to change)

This document specifies a minimal, agentless profile for delivering and
consuming [SPIFFE](https://github.com/spiffe/spiffe/tree/main/standards)
identities **as files**. It defines:

1. the file layout a workload reads its identity material from,
2. the trust bundle document format,
3. token (JWT-SVID) requirements, and
4. verification rules.

It deliberately does **not** define how files get where they are. Any
mechanism that can place files in front of a process — a secrets operator, a
mounted Kubernetes Secret, a configuration management tool, a development
script, [spiffe-helper](https://github.com/spiffe/spiffe-helper) — is a
conformant producer. (The SPIFFE Trust Domain and Bundle standard explicitly
leaves bundle distribution out of scope; this profile inherits that stance.)

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
RFC 2119.

---

## 1. Identity material

Each workload is configured with three inputs:

| Input | Content |
|---|---|
| **identity file** | the workload's own SPIFFE ID, UTF-8, single line, trailing whitespace ignored |
| **key file** | the workload's private key, PEM-encoded PKCS#8 |
| **bundle file** | the trust bundle document (section 2) |

### 1.1 Environment configuration

Implementations MUST support configuration via environment variables:

```
SPIFFILE_ID_FILE      path to the identity file
SPIFFILE_KEY_FILE     path to the key file
SPIFFILE_BUNDLE_FILE  path to the bundle file
```

Implementations MUST also support the single-directory shorthand:

```
SPIFFILE_DIR          directory containing  id / key.pem / bundle.json
```

If both are set, the explicit file variables take precedence (per variable).

### 1.2 Keys

Profile version 0 uses **EC P-256** keys and **ES256** signatures
exclusively. Verifiers MUST reject any other algorithm. (A future profile
version may widen this; a single mandatory algorithm maximizes
interoperability and eliminates downgrade surface.)

The private key MUST be readable only by the workload it identifies
(e.g. mode `0600`, delivered through a path only that workload can access).

### 1.3 Reloading

Workloads SHOULD re-read the bundle file when it changes (mtime/size check
on access is sufficient) so that rotation and revocation propagate without
restarts. Producers replace the bundle file atomically (write + rename —
Kubernetes secret mounts already behave this way).

---

## 2. The trust bundle document

A JSON document binding each SPIFFE ID in the trust domain to the public
keys that may sign for it:

```json
{
  "trust_domain": "example.org",
  "spiffile_version": 1,
  "identities": {
    "spiffe://example.org/orders": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "…",
          "y": "…",
          "kid": "…",
          "use": "jwt-svid",
          "alg": "ES256"
        }
      ]
    },
    "spiffe://example.org/billing": { "keys": [ "…" ] }
  }
}
```

- `trust_domain` — the SPIFFE trust domain name. Every identity in the
  document MUST belong to it.
- `spiffile_version` — integer, currently `1`. Consumers MUST reject
  documents with an unknown version.
- `identities` — maps SPIFFE IDs to RFC 7517 JWK Sets. Each JWK:
  - MUST carry a `kid`; the RFC 7638 thumbprint is RECOMMENDED,
  - SHOULD carry `use: "jwt-svid"` (per the SPIFFE bundle standard),
  - MUST be a public key only.

An identity MAY have multiple keys (rotation overlap, section 5).

### 2.1 Why per-identity keys (difference from the SPIFFE bundle format)

The standard SPIFFE bundle is a flat JWKS for the whole trust domain. That
format assumes a **central issuer**: any domain key vouches for any `sub`,
because only the issuer holds signing keys.

This profile is agentless — each workload signs its own tokens. A flat JWKS
would let any workload's key validate a token claiming *any* identity,
i.e. workload A could mint tokens as workload B. Binding keys per identity
closes this: a key may only validate tokens whose `sub` it is explicitly
bound to.

A producer backed by a central issuer (e.g. SPIRE via spiffe-helper) MAY
express that by binding the issuer's keys to every identity it issues for,
or by a future profile version supporting domain-level keys.

---

## 3. Tokens

Tokens are [JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
Profile requirements:

- Header: `alg: ES256` (section 1.2); `kid` MUST be present and reference a
  key bound to the token's `sub`; `typ` SHOULD be `JWT`.
- Claims: `sub` (the sender's SPIFFE ID), `aud` (the intended receiver's
  SPIFFE ID), and `exp` are REQUIRED; `iat` is RECOMMENDED.
- `aud` MUST be a single string: the SPIFFE ID of the one service the token
  is intended for. Verifiers MUST reject multi-valued (array) audiences.
  Audience-per-target is the profile's replay containment: a token captured
  by (or legitimately sent to) one service is useless against any other.
- Lifetime SHOULD be short — 60 seconds is the reference default; senders
  mint per request or per small time window. Lifetimes over 300 seconds are
  NOT RECOMMENDED.

---

## 4. Verification

To verify an inbound token, a receiver:

1. Parses the JWT header and unverified claims; rejects tokens without
   `sub`, `aud`, or `exp`, and tokens whose `aud` is not a single string.
2. Parses `sub` as a SPIFFE ID and looks it up in `identities` in the
   current bundle. Unknown identity → reject.
3. Selects the bound key matching the header `kid` (falling back to trying
   all keys bound to that identity).
4. Validates the signature with algorithm allow-list `["ES256"]` — never
   the token's own `alg` —, the audience (the receiver's own SPIFFE ID
   unless explicitly configured otherwise), and `exp`/`iat` with a small
   clock-skew leeway (30 seconds RECOMMENDED).
5. The verified `sub` is the caller's identity, usable for authorization
   decisions.

Steps 2–3 are the heart of the profile: **key lookup is scoped by the
claimed identity**, never global.

---

## 5. Rotation and revocation

- **Rotation:** add the new public key to the identity's `keys` (old key
  remains during overlap), distribute the bundle, switch the workload's key
  file, then drop the old key from the bundle.
- **Revocation:** remove the identity's entry (or a specific key) from the
  bundle and distribute. Revocation latency equals bundle distribution
  latency — with a secrets-operator producer, typically the operator's
  refresh interval. Deployments MUST treat this latency as part of their
  threat model (short token lifetimes do most of the practical work here).

---

## 6. Security considerations

- **Trust root = file delivery.** Whoever can write a workload's bundle file
  controls who that workload trusts; whoever can write private-key files can
  mint identities. This profile intentionally delegates that to the
  deployment's existing secret-delivery machinery and its access control.
  State this dependency explicitly in your deployment docs.
- **No transport security included.** Tokens authenticate; they do not
  encrypt. Run TLS (ingress or mesh) underneath when traffic crosses
  untrusted networks.
- **Audience discipline.** Verifiers MUST check `aud` against their own
  identity. Accepting wildcard or shared audiences re-opens token replay
  between services.
- **Clock skew.** Short-lived tokens require loosely synchronized clocks;
  the RECOMMENDED 30s leeway tolerates normal NTP drift. Monitor clock
  health if you tighten it.
- **Algorithm pinning.** Verifiers MUST ignore the token's `alg` header for
  algorithm selection and use the profile allow-list, eliminating
  alg-confusion attacks.
