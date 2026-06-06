"""Key generation, JWK encoding and RFC 7638 thumbprints.

Profile v0 uses EC P-256 keys with ES256 signatures exclusively.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

JWT_SVID_USE = "jwt-svid"  # per the SPIFFE Trust Domain and Bundle standard
ALGORITHM = "ES256"

_COORD_LENGTH = 32  # P-256 coordinate length in bytes


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_pem(pem: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"expected an EC private key, got {type(key).__name__}")
    return key


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    """The public JWK (with RFC 7638 thumbprint as ``kid``) for a private key."""
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(_COORD_LENGTH, "big")),
        "y": _b64url(numbers.y.to_bytes(_COORD_LENGTH, "big")),
    }
    jwk["kid"] = jwk_thumbprint(jwk)
    jwk["use"] = JWT_SVID_USE
    jwk["alg"] = ALGORITHM
    return jwk


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url)."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())
