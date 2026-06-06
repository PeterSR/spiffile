"""Parity CLI: mint or verify a token using the Python implementation.

Usage:
  python cli.py provision <root>                      # init + add orders,billing
  python cli.py mint <root> <service> <aud-service>   # token to stdout
  python cli.py verify <root> <service> <token> <expected-sub-service>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python" / "src"))

from spiffile import Identity  # noqa: E402
from spiffile.provision import add_service, init_root, load_identity  # noqa: E402

TRUST_DOMAIN = "parity.test"


def main() -> None:
    command, root = sys.argv[1], sys.argv[2]
    if command == "provision":
        init_root(root, TRUST_DOMAIN)
        add_service(root, "orders")
        add_service(root, "billing")
        print("provisioned")
    elif command == "mint":
        service, audience = sys.argv[3], sys.argv[4]
        identity = load_identity(root, service)
        print(identity.token(f"spiffe://{TRUST_DOMAIN}/{audience}"), end="")
    elif command == "verify":
        service, token, expected = sys.argv[3], sys.argv[4], sys.argv[5]
        identity: Identity = load_identity(root, service)
        caller = identity.verify(token)
        assert str(caller.id) == f"spiffe://{TRUST_DOMAIN}/{expected}", str(caller.id)
        print(f"python verified caller={caller.id}")
    else:
        raise SystemExit(f"unknown command {command!r}")


if __name__ == "__main__":
    main()
