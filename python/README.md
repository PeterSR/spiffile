# spiffile (Python)

Python implementation of the [spiffile profile](../PROFILE.md) — SPIFFE
identities delivered as files. See the [project README](../README.md) for
the why.

## Install

```bash
pip install spiffile
```

Only dependency: `PyJWT[crypto]`.

## Configure

Point a service at its identity material with environment variables:

```bash
SPIFFILE_ID_FILE=/identity/id               # my SPIFFE ID
SPIFFILE_KEY_FILE=/identity/key.pem         # my private key
SPIFFILE_BUNDLE_FILE=/identity/bundle.json  # everyone's public keys
# — or the single-directory shorthand —
SPIFFILE_DIR=/identity                      # containing id, key.pem, bundle.json
```

Both the bundle **and the private key** are hot-reloaded on change, so key
rotation and revocation propagate without restarts.

## Use

### Load once at startup

```python
from spiffile import Identity

identity = Identity.from_env()
# or explicitly:
identity = Identity.from_files("id", "key.pem", "bundle.json")
```

### Outbound — prove who you are

Mint a short-lived token per request, audience-bound to the one service
you're calling:

```python
import httpx

token = identity.token(audience="spiffe://example.org/billing")  # ~60s TTL
httpx.post(url, headers={"Authorization": f"Bearer {token}"})
```

### Inbound — know who's calling

```python
from spiffile import InvalidTokenError, UnknownIdentityError

try:
    caller = identity.verify(token)   # audience defaults to my own ID
except (InvalidTokenError, UnknownIdentityError):
    ...  # 401

caller.id      # SpiffeId of the verified peer
caller.claims  # full verified JWT claims
```

Authorization stays yours — compare `caller.id` against whatever policy the
route demands.

### FastAPI sketch

```python
from fastapi import Depends, HTTPException, Request

def require_caller(*allowed: str):
    def dependency(request: Request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(401)
        try:
            caller = identity.verify(auth.removeprefix("Bearer "))
        except (InvalidTokenError, UnknownIdentityError):
            raise HTTPException(401)
        if str(caller.id) not in allowed:
            raise HTTPException(403)
        return caller
    return dependency

router = APIRouter(
    prefix="/management",
    dependencies=[Depends(require_caller("spiffe://example.org/control-plane"))],
)
```

## Provisioning (`spiffile.provision`)

Building blocks for producers — your dev tooling, scripts, or operator stay
thin glue:

```python
from spiffile.provision import (
    init_root, add_service, rotate_service, remove_service, service_env,
)

root = init_root("/tmp/identity", trust_domain="example.org")
add_service(root, "orders")          # keypair + bundle entry (idempotent)
add_service(root, "billing")

service_env(root, "orders")
# {"SPIFFILE_ID_FILE": ".../services/orders/id",
#  "SPIFFILE_KEY_FILE": ".../services/orders/key.pem",
#  "SPIFFILE_BUNDLE_FILE": ".../bundle.json"}

rotate_service(root, "orders")                  # new key, old kept for overlap
rotate_service(root, "orders", keep_old=False)  # new key, old revoked
remove_service(root, "orders")                  # full revocation
```

The resulting layout:

```
<root>/
  bundle.json                # distribute to every service
  services/<name>/id         # the service's SPIFFE ID
  services/<name>/key.pem    # deliver only to that service (0600)
```

In production you'd typically not use these helpers on a box — generate keys
into your secrets store and let your delivery machinery (secrets operator,
mounted Secrets) place the same three files. The consumer code never knows
the difference.

## Errors

All exceptions derive from `spiffile.SpiffileError`:

- `InvalidSpiffeIdError` — malformed SPIFFE ID
- `InvalidBundleError` — malformed/incompatible bundle document
- `UnknownIdentityError` — claimed caller has no keys in the bundle
- `InvalidTokenError` — signature/audience/expiry/claims failure

## Development

```bash
cd python
uv sync
uv run pytest
uv run ruff check src tests && uv run ruff format --check src tests
```
