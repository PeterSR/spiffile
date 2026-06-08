import time

import jwt as pyjwt
import pytest

from spiffile import InvalidTokenError, UnknownIdentityError, unverified_audience
from spiffile.keys import private_key_from_pem
from spiffile.provision import (
    add_service,
    init_root,
    load_identity,
    remove_service,
    rotate_service,
    service_env,
)

TRUST_DOMAIN = "example.org"


@pytest.fixture()
def root(tmp_path):
    root = tmp_path / "identity"
    init_root(root, TRUST_DOMAIN)
    add_service(root, "orders")
    add_service(root, "billing")
    return root


def test_roundtrip(root):
    orders = load_identity(root, "orders")
    billing = load_identity(root, "billing")

    token = orders.token(audience=str(billing.id))
    caller = billing.verify(token)

    assert str(caller.id) == f"spiffe://{TRUST_DOMAIN}/orders"


def test_wrong_audience_rejected(root):
    orders = load_identity(root, "orders")
    billing = load_identity(root, "billing")

    token = orders.token(audience=f"spiffe://{TRUST_DOMAIN}/someone-else")
    with pytest.raises(InvalidTokenError):
        billing.verify(token)


def test_unverified_audience(root):
    orders = load_identity(root, "orders")
    billing = load_identity(root, "billing")

    token = orders.token(audience=str(billing.id))
    assert unverified_audience(token) == str(billing.id)

    # malformed input is rejected
    with pytest.raises(InvalidTokenError):
        unverified_audience("not.a.jwt")

    # an array aud is rejected, not silently coerced
    orders_key = private_key_from_pem((root / "services" / "orders" / "key.pem").read_bytes())
    now = int(time.time())
    multi = pyjwt.encode(
        {"sub": str(orders.id), "aud": [str(billing.id), "x"], "iat": now, "exp": now + 60},
        key=orders_key,
        algorithm="ES256",
    )
    with pytest.raises(InvalidTokenError):
        unverified_audience(multi)

    # a token with no aud returns None
    no_aud = pyjwt.encode(
        {"sub": str(orders.id), "iat": now, "exp": now + 60},
        key=orders_key,
        algorithm="ES256",
    )
    assert unverified_audience(no_aud) is None


def test_multi_audience_rejected(root):
    """aud must be a single string — an array containing the right audience still fails."""
    billing = load_identity(root, "billing")
    orders_key = private_key_from_pem((root / "services" / "orders" / "key.pem").read_bytes())

    now = int(time.time())
    multi = pyjwt.encode(
        {
            "sub": f"spiffe://{TRUST_DOMAIN}/orders",
            "aud": [str(billing.id), f"spiffe://{TRUST_DOMAIN}/other"],
            "iat": now,
            "exp": now + 60,
        },
        key=orders_key,
        algorithm="ES256",
    )
    with pytest.raises(InvalidTokenError):
        billing.verify(multi)


def test_unknown_caller_rejected(root, tmp_path):
    # A service provisioned in a DIFFERENT root (not in the receiver's bundle).
    other_root = tmp_path / "other"
    init_root(other_root, TRUST_DOMAIN)
    add_service(other_root, "intruder")
    intruder = load_identity(other_root, "intruder")

    billing = load_identity(root, "billing")
    token = intruder.token(audience=str(billing.id))
    with pytest.raises(UnknownIdentityError):
        billing.verify(token)


def test_impersonation_rejected(root):
    """orders' key must not validate a token claiming sub=billing."""
    billing = load_identity(root, "billing")
    orders_key = private_key_from_pem((root / "services" / "orders" / "key.pem").read_bytes())

    now = int(time.time())
    forged = pyjwt.encode(
        {
            "sub": f"spiffe://{TRUST_DOMAIN}/billing",  # claiming to be billing
            "aud": str(billing.id),
            "iat": now,
            "exp": now + 60,
        },
        key=orders_key,  # ...signed with orders' key
        algorithm="ES256",
    )
    with pytest.raises(InvalidTokenError):
        billing.verify(forged)


def test_expired_rejected(root):
    billing = load_identity(root, "billing")
    orders_key = private_key_from_pem((root / "services" / "orders" / "key.pem").read_bytes())
    long_ago = int(time.time()) - 3600
    expired = pyjwt.encode(
        {
            "sub": f"spiffe://{TRUST_DOMAIN}/orders",
            "aud": str(billing.id),
            "iat": long_ago,
            "exp": long_ago + 60,
        },
        key=orders_key,
        algorithm="ES256",
    )
    with pytest.raises(InvalidTokenError):
        billing.verify(expired)


def test_rotation_with_overlap(root):
    billing = load_identity(root, "billing")
    orders_before = load_identity(root, "orders")
    token_old_key = orders_before.token(audience=str(billing.id))

    rotate_service(root, "orders", keep_old=True)

    orders_after = load_identity(root, "orders")
    token_new_key = orders_after.token(audience=str(billing.id))

    # Bundle hot-reload: billing picks up the rotated bundle automatically.
    assert str(billing.verify(token_new_key).id) == str(orders_after.id)
    # Old key kept during overlap, so in-flight tokens still verify.
    assert str(billing.verify(token_old_key).id) == str(orders_before.id)


def test_rotation_without_overlap_revokes_old_key(root):
    billing = load_identity(root, "billing")
    orders_before = load_identity(root, "orders")
    token_old_key = orders_before.token(audience=str(billing.id))

    rotate_service(root, "orders", keep_old=False)

    with pytest.raises(InvalidTokenError):
        billing.verify(token_old_key)


def test_remove_service_revokes(root):
    billing = load_identity(root, "billing")
    orders = load_identity(root, "orders")
    token = orders.token(audience=str(billing.id))

    remove_service(root, "orders")

    with pytest.raises(UnknownIdentityError):
        billing.verify(token)


def test_signing_key_hot_reload(root):
    """A long-running process must sign with the NEW key after rotation."""
    billing = load_identity(root, "billing")
    orders = load_identity(root, "orders")  # loaded BEFORE rotation

    token_before = orders.token(audience=str(billing.id))
    kid_before = pyjwt.get_unverified_header(token_before)["kid"]

    rotate_service(root, "orders", keep_old=False)

    token_after = orders.token(audience=str(billing.id))  # same Identity object
    kid_after = pyjwt.get_unverified_header(token_after)["kid"]

    assert kid_after != kid_before
    assert str(billing.verify(token_after).id) == str(orders.id)


def test_bundle_skips_invalid_entries(root, caplog):
    """One malformed bundle entry must not break verification for the rest."""
    import json

    bundle_path = root / "bundle.json"
    doc = json.loads(bundle_path.read_text())
    doc["identities"]["spiffe://example.org/bad~path"] = {"keys": [{"kty": "EC"}]}
    doc["identities"]["spiffe://example.org/no-keys"] = {"keys": []}
    bundle_path.write_text(json.dumps(doc))

    billing = load_identity(root, "billing")
    orders = load_identity(root, "orders")
    token = orders.token(audience=str(billing.id))
    assert str(billing.verify(token).id) == str(orders.id)  # still works


def test_service_env_and_from_env(root, monkeypatch):
    from spiffile import Identity

    for key, value in service_env(root, "orders").items():
        monkeypatch.setenv(key, value)
    identity = Identity.from_env()
    assert str(identity.id) == f"spiffe://{TRUST_DOMAIN}/orders"
