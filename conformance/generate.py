"""Regenerate fixtures.json from its pinned inputs.

The private keys and the SPIFFE-ID validation vectors are inputs and are
preserved verbatim; the JWKs, the bundle document and the token are derived
from them by the Python reference implementation. Run via the python project
so PyJWT/cryptography are available:

    cd python && uv sync && uv run python ../conformance/generate.py

Only regenerate when the profile deliberately changes — the derived values
are pinned by all test suites.
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "python" / "src"))

import jwt  # noqa: E402
from spiffile.keys import private_key_from_pem, public_jwk  # noqa: E402

FIXTURES = HERE / "fixtures.json"
TRUST_DOMAIN = "example.org"
IAT = 1_750_000_000
EXP = 2_051_222_400  # 2035 — far future on purpose: the fixture token must not expire


def main() -> None:
    data = json.loads(FIXTURES.read_text())

    keys = {}
    identities = {}
    for service in ("orders", "billing"):
        key = private_key_from_pem(data[f"{service}_private_key_pem"].encode())
        jwk = public_jwk(key)
        data[f"{service}_jwk"] = jwk
        identities[f"spiffe://{TRUST_DOMAIN}/{service}"] = {"keys": [jwk]}
        keys[service] = (key, jwk)

    data["bundle"] = {
        "trust_domain": TRUST_DOMAIN,
        "spiffile_version": 1,
        "identities": identities,
    }

    orders_key, orders_jwk = keys["orders"]
    data["token_orders_to_billing_exp_2035"] = jwt.encode(
        {
            "sub": f"spiffe://{TRUST_DOMAIN}/orders",
            "aud": f"spiffe://{TRUST_DOMAIN}/billing",
            "iat": IAT,
            "exp": EXP,
        },
        orders_key,
        algorithm="ES256",
        headers={"kid": orders_jwk["kid"], "typ": "JWT"},
    )

    # aud is an ARRAY containing the right audience — every implementation
    # must REJECT this: the profile requires aud to be a single string.
    data["token_orders_to_billing_multi_aud_exp_2035"] = jwt.encode(
        {
            "sub": f"spiffe://{TRUST_DOMAIN}/orders",
            "aud": [f"spiffe://{TRUST_DOMAIN}/billing", f"spiffe://{TRUST_DOMAIN}/other"],
            "iat": IAT,
            "exp": EXP,
        },
        orders_key,
        algorithm="ES256",
        headers={"kid": orders_jwk["kid"], "typ": "JWT"},
    )

    FIXTURES.write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {FIXTURES}")


if __name__ == "__main__":
    main()
