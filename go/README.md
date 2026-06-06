# spiffile (Go)

Go implementation of the [spiffile profile](../PROFILE.md) — SPIFFE
identities delivered as files. Full surface: mint/verify JWT-SVIDs,
trust bundles, and provisioning primitives. Used by
[spiffile-operator](https://github.com/PeterSR/spiffile-operator).
Only dependency: `golang-jwt/jwt`.

## Use

```go
import spiffile "github.com/PeterSR/spiffile/go"

identity, err := spiffile.FromEnv() // SPIFFILE_DIR or the three SPIFFILE_*_FILE vars

// outbound: prove who you are (mint per request, ~60s TTL)
token, err := identity.Token("spiffe://example.org/billing", 0)

// inbound: know who's calling (audience "" = my own ID)
caller, err := identity.Verify(tokenFromRequest, "", 0)
caller.ID.String() // "spiffe://example.org/orders" — cryptographically verified
```

Both the bundle **and the private key** are hot-reloaded on change, so key
rotation needs no restarts.

## Provisioning

Building blocks for producers — dev tooling, scripts, operators:

```go
spiffile.InitRoot(root, "example.org")
spiffile.AddService(root, "orders")           // keypair + bundle entry (idempotent)
spiffile.ServiceEnv(root, "orders")           // the three SPIFFILE_* env vars
spiffile.RotateService(root, "orders", true)  // new key, old kept for overlap
spiffile.RotateService(root, "orders", false) // new key, old revoked
spiffile.RemoveService(root, "orders")        // full revocation
```

Producer primitives are also exposed directly: `GeneratePrivateKeyPEM`,
`PublicJWKFromPEM` (RFC 7638 thumbprint kids), `ParseBundle` (resilient:
skips invalid entries with warnings), `MarshalBundle`, `ParseSpiffeID`.

## Development

```bash
go test ./...
```

The test suite is pinned to the shared conformance fixtures
(`../conformance/fixtures.json`): same validation rules, same thumbprints,
and a token minted by the Python reference implementation must verify here.
