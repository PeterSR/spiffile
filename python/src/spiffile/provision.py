"""Provisioning primitives: create, rotate and revoke identities.

These functions are the building blocks for producers — provisioning scripts,
development tooling, operators. They generate keypairs and maintain the trust
bundle; consumers only ever read the resulting files via
:class:`spiffile.Identity`.

A provisioned root directory looks like::

    <root>/
      bundle.json                  # the trust bundle (distribute to everyone)
      services/<name>/id           # the service's SPIFFE ID
      services/<name>/key.pem      # the service's private key (deliver only to it)

The per-service directory plus the shared bundle map directly onto the
``SPIFFILE_ID_FILE`` / ``SPIFFILE_KEY_FILE`` / ``SPIFFILE_BUNDLE_FILE``
environment variables (see :func:`service_env`).
"""

from __future__ import annotations

import json
from pathlib import Path

from .bundle import Bundle, FileBundleSource
from .errors import SpiffileError
from .identity import ENV_BUNDLE_FILE, ENV_ID_FILE, ENV_KEY_FILE, Identity
from .keys import generate_private_key, private_key_to_pem, public_jwk
from .spiffe_id import SpiffeId

BUNDLE_FILENAME = "bundle.json"
SERVICES_DIRNAME = "services"
ID_FILENAME = "id"
KEY_FILENAME = "key.pem"


def init_root(root: str | Path, trust_domain: str) -> Path:
    """Create an empty provisioning root with an empty bundle."""
    root = Path(root)
    bundle_path = root / BUNDLE_FILENAME
    if bundle_path.exists():
        raise SpiffileError(f"already initialized: {bundle_path}")
    (root / SERVICES_DIRNAME).mkdir(parents=True, exist_ok=True)
    _write_bundle(bundle_path, Bundle(trust_domain=trust_domain, identities={}))
    return root


def add_service(root: str | Path, name: str) -> SpiffeId:
    """Generate a keypair for a service and register its public key in the bundle.

    Idempotent on re-add: a service that already has a key keeps it.
    """
    root = Path(root)
    bundle = _read_bundle(root)
    spiffe_id = SpiffeId.parse(f"spiffe://{bundle.trust_domain}/{name}")

    service_dir = root / SERVICES_DIRNAME / name
    key_path = service_dir / KEY_FILENAME
    if key_path.exists():
        return spiffe_id

    service_dir.mkdir(parents=True, exist_ok=True)
    private_key = generate_private_key()
    key_path.write_bytes(private_key_to_pem(private_key))
    key_path.chmod(0o600)
    (service_dir / ID_FILENAME).write_text(f"{spiffe_id}\n")

    _set_keys(root, bundle, str(spiffe_id), [public_jwk(private_key)])
    return spiffe_id


def rotate_service(root: str | Path, name: str, keep_old: bool = True) -> SpiffeId:
    """Generate a new keypair for a service.

    With ``keep_old=True`` (the default) the previous public key stays in the
    bundle so in-flight tokens and not-yet-refreshed bundle copies keep
    working; prune it later with ``keep_old=False`` on a subsequent rotation
    or by editing the bundle.
    """
    root = Path(root)
    bundle = _read_bundle(root)
    spiffe_id = SpiffeId.parse(f"spiffe://{bundle.trust_domain}/{name}")

    service_dir = root / SERVICES_DIRNAME / name
    key_path = service_dir / KEY_FILENAME
    if not key_path.exists():
        raise SpiffileError(f"unknown service {name!r}: {key_path} does not exist")

    private_key = generate_private_key()
    new_jwk = public_jwk(private_key)
    existing = bundle.identities.get(str(spiffe_id), []) if keep_old else []
    keys = [new_jwk] + [j for j in existing if j.get("kid") != new_jwk["kid"]]

    key_path.write_bytes(private_key_to_pem(private_key))
    key_path.chmod(0o600)
    _set_keys(root, bundle, str(spiffe_id), keys)
    return spiffe_id


def remove_service(root: str | Path, name: str) -> None:
    """Remove a service's keys from the bundle (revocation) and its directory."""
    root = Path(root)
    bundle = _read_bundle(root)
    spiffe_id = f"spiffe://{bundle.trust_domain}/{name}"

    identities = dict(bundle.identities)
    identities.pop(spiffe_id, None)
    _write_bundle(root / BUNDLE_FILENAME, Bundle(trust_domain=bundle.trust_domain, identities=identities))

    service_dir = root / SERVICES_DIRNAME / name
    for filename in (ID_FILENAME, KEY_FILENAME):
        (service_dir / filename).unlink(missing_ok=True)
    if service_dir.exists():
        service_dir.rmdir()


def service_env(root: str | Path, name: str) -> dict[str, str]:
    """The environment variables that point a consumer at its identity files."""
    root = Path(root)
    service_dir = root / SERVICES_DIRNAME / name
    return {
        ENV_ID_FILE: str(service_dir / ID_FILENAME),
        ENV_KEY_FILE: str(service_dir / KEY_FILENAME),
        ENV_BUNDLE_FILE: str(root / BUNDLE_FILENAME),
    }


def load_identity(root: str | Path, name: str) -> Identity:
    """Load a provisioned service's :class:`Identity` directly (tests, tooling)."""
    env = service_env(root, name)
    return Identity.from_files(env[ENV_ID_FILE], env[ENV_KEY_FILE], env[ENV_BUNDLE_FILE])


# -- internals --------------------------------------------------------------


def _read_bundle(root: Path) -> Bundle:
    return FileBundleSource(root / BUNDLE_FILENAME).get()


def _set_keys(root: Path, bundle: Bundle, spiffe_id: str, keys: list[dict]) -> None:
    identities = dict(bundle.identities)
    identities[spiffe_id] = keys
    _write_bundle(root / BUNDLE_FILENAME, Bundle(trust_domain=bundle.trust_domain, identities=identities))


def _write_bundle(path: Path, bundle: Bundle) -> None:
    path.write_text(json.dumps(bundle.to_dict(), indent=2) + "\n")
