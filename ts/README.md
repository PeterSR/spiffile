# spiffile (TypeScript)

TypeScript/Node implementation of the [spiffile profile](../PROFILE.md) —
SPIFFE identities delivered as files. **Zero runtime dependencies**
(`node:crypto` does the work). See the [project README](../README.md) for
the why.

## Install

```bash
npm install spiffile
```

Node ≥ 18.

## Configure

```bash
SPIFFILE_ID_FILE=/identity/id               # my SPIFFE ID
SPIFFILE_KEY_FILE=/identity/key.pem         # my private key
SPIFFILE_BUNDLE_FILE=/identity/bundle.json  # everyone's public keys
# — or the single-directory shorthand —
SPIFFILE_DIR=/identity
```

Both the bundle **and the private key** are hot-reloaded on change, so key
rotation needs no restarts.

## Use

```typescript
import { Identity, InvalidTokenError, UnknownIdentityError } from "spiffile"

const identity = Identity.fromEnv()

// outbound: prove who you are (mint per request, ~60s TTL)
const token = identity.token("spiffe://example.org/billing")
await fetch(url, { headers: { Authorization: `Bearer ${token}` } })

// inbound: know who's calling
try {
  const caller = identity.verify(tokenFromRequest) // audience defaults to my own ID
  caller.id.toString() // "spiffe://example.org/orders" — cryptographically verified
} catch (error) {
  if (error instanceof InvalidTokenError || error instanceof UnknownIdentityError) {
    // 401
  }
}
```

### Express sketch

```typescript
function requireCaller(...allowed: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers.authorization ?? ""
    if (!auth.startsWith("Bearer ")) return res.status(401).end()
    try {
      const caller = identity.verify(auth.slice("Bearer ".length))
      if (!allowed.includes(caller.id.toString())) return res.status(403).end()
      next()
    } catch {
      res.status(401).end()
    }
  }
}

app.use("/management", requireCaller("spiffe://example.org/control-plane"))
```

## Provisioning (`provision`)

Building blocks for producers — dev tooling, scripts, operators:

```typescript
import { provision } from "spiffile"

const root = provision.initRoot("/tmp/identity", "example.org")
provision.addService(root, "orders")                 // keypair + bundle entry (idempotent)
provision.serviceEnv(root, "orders")                 // the three SPIFFILE_* env vars
provision.rotateService(root, "orders")              // new key, old kept for overlap
provision.rotateService(root, "orders", false)       // new key, old revoked
provision.removeService(root, "orders")              // full revocation
```

## Errors

All errors extend `SpiffileError`: `InvalidSpiffeIdError`,
`InvalidBundleError`, `UnknownIdentityError`, `InvalidTokenError`.

## Development

```bash
npm install
npm test    # builds + runs node:test, including cross-implementation fixtures
```

The test suite pins JWKs/thumbprints and verifies a token minted by the
Python reference implementation, so implementations can't drift.
