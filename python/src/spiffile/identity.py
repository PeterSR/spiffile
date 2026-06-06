"""Workload identity: mint and verify JWT-SVIDs from file-delivered material."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

from .bundle import FileBundleSource
from .errors import InvalidTokenError, SpiffileError
from .keys import ALGORITHM, private_key_from_pem, public_jwk
from .spiffe_id import SpiffeId

DEFAULT_TTL_SECONDS = 60
DEFAULT_LEEWAY_SECONDS = 30

# Profile v0: ES256 only. A verifier MUST reject anything else.
ALLOWED_ALGORITHMS = [ALGORITHM]

ENV_DIR = "SPIFFILE_DIR"
ENV_ID_FILE = "SPIFFILE_ID_FILE"
ENV_KEY_FILE = "SPIFFILE_KEY_FILE"
ENV_BUNDLE_FILE = "SPIFFILE_BUNDLE_FILE"

DIR_ID_FILENAME = "id"
DIR_KEY_FILENAME = "key.pem"
DIR_BUNDLE_FILENAME = "bundle.json"


@dataclass(frozen=True)
class Caller:
    """The verified peer of an inbound request."""

    id: SpiffeId
    claims: dict


class _StaticKeySource:
    """A fixed in-memory private key (direct construction, tests)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._key = private_key
        self._kid = public_jwk(private_key)["kid"]

    def get(self) -> tuple[ec.EllipticCurvePrivateKey, str]:
        return self._key, self._kid


class _FileKeySource:
    """Reads the private key from a file, hot-reloading when it changes.

    Key rotation replaces the key file (e.g. a kubelet secret sync); signing
    must pick the new key up without a process restart — otherwise tokens
    break once the rotated-out public key is pruned from peers' bundles.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._stat: tuple[float, int] | None = None
        self._key: ec.EllipticCurvePrivateKey | None = None
        self._kid = ""

    def get(self) -> tuple[ec.EllipticCurvePrivateKey, str]:
        stat = os.stat(self._path)
        current = (stat.st_mtime, stat.st_size)
        if self._key is None or current != self._stat:
            self._key = private_key_from_pem(self._path.read_bytes())
            self._kid = public_jwk(self._key)["kid"]
            self._stat = current
        return self._key, self._kid


class Identity:
    """A service's own identity plus the trust bundle to verify peers against."""

    def __init__(
        self,
        id: SpiffeId,
        private_key: ec.EllipticCurvePrivateKey | _FileKeySource,
        bundle_source: FileBundleSource,
    ):
        self.id = id
        if isinstance(private_key, _FileKeySource):
            self._key_source: _StaticKeySource | _FileKeySource = private_key
        else:
            self._key_source = _StaticKeySource(private_key)
        self._bundle_source = bundle_source

    # -- construction ------------------------------------------------------

    @classmethod
    def from_files(cls, id_file: str | Path, key_file: str | Path, bundle_file: str | Path) -> Identity:
        spiffe_id = SpiffeId.parse(Path(id_file).read_text().strip())
        return cls(id=spiffe_id, private_key=_FileKeySource(key_file), bundle_source=FileBundleSource(bundle_file))

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Identity:
        """Load identity from environment configuration.

        Either ``SPIFFILE_DIR`` (a directory containing ``id``, ``key.pem``
        and ``bundle.json``) or the three explicit file variables
        ``SPIFFILE_ID_FILE``/``SPIFFILE_KEY_FILE``/``SPIFFILE_BUNDLE_FILE``.
        Explicit file variables take precedence over the directory.
        """
        env = env if env is not None else dict(os.environ)
        directory = env.get(ENV_DIR)
        id_file = env.get(ENV_ID_FILE) or (directory and Path(directory) / DIR_ID_FILENAME)
        key_file = env.get(ENV_KEY_FILE) or (directory and Path(directory) / DIR_KEY_FILENAME)
        bundle_file = env.get(ENV_BUNDLE_FILE) or (directory and Path(directory) / DIR_BUNDLE_FILENAME)
        if not (id_file and key_file and bundle_file):
            raise SpiffileError(
                f"identity not configured: set {ENV_DIR}, or {ENV_ID_FILE} + {ENV_KEY_FILE} + {ENV_BUNDLE_FILE}"
            )
        return cls.from_files(id_file, key_file, bundle_file)

    # -- outbound ----------------------------------------------------------

    def token(self, audience: str | SpiffeId, ttl: int = DEFAULT_TTL_SECONDS) -> str:
        """Mint a JWT-SVID for a single target audience."""
        audience_id = audience if isinstance(audience, SpiffeId) else SpiffeId.parse(audience)
        private_key, kid = self._key_source.get()
        now = int(time.time())
        claims = {
            "sub": str(self.id),
            "aud": str(audience_id),
            "iat": now,
            "exp": now + ttl,
        }
        return pyjwt.encode(
            claims,
            key=private_key,
            algorithm=ALGORITHM,
            headers={"kid": kid, "typ": "JWT"},
        )

    # -- inbound -----------------------------------------------------------

    def verify(
        self,
        token: str,
        audience: str | SpiffeId | None = None,
        leeway: float = DEFAULT_LEEWAY_SECONDS,
    ) -> Caller:
        """Verify an inbound JWT-SVID and return the verified caller.

        ``audience`` defaults to this identity's own SPIFFE ID — the common
        case of "this token must have been minted for me".

        Raises :class:`UnknownIdentityError` if the claimed identity has no
        keys in the bundle, :class:`InvalidTokenError` for everything else.
        """
        expected_audience = str(audience) if audience is not None else str(self.id)

        try:
            header = pyjwt.get_unverified_header(token)
            unverified = pyjwt.decode(token, options={"verify_signature": False})
        except pyjwt.exceptions.PyJWTError as e:
            raise InvalidTokenError(f"malformed token: {e}") from e

        claimed_sub = unverified.get("sub")
        if not claimed_sub:
            raise InvalidTokenError("token has no sub claim")
        claimed_id = SpiffeId.parse(claimed_sub)

        # The profile requires aud to be a single string. PyJWT would happily
        # match the expected audience inside a list, so reject arrays here.
        claimed_aud = unverified.get("aud")
        if claimed_aud is not None and not isinstance(claimed_aud, str):
            raise InvalidTokenError("token rejected: aud must be a single string audience")

        # The security pivot of the profile: only keys bound to the claimed
        # identity in the bundle may validate it. May raise UnknownIdentityError.
        bound_jwks = self._bundle_source.get().keys_for(str(claimed_id))

        kid = header.get("kid")
        candidates = [j for j in bound_jwks if j.get("kid") == kid] or bound_jwks

        last_error: Exception | None = None
        for jwk in candidates:
            try:
                key = pyjwt.PyJWK.from_dict(jwk).key
            except pyjwt.exceptions.PyJWKError as e:
                last_error = e
                continue
            try:
                claims = pyjwt.decode(
                    token,
                    key=key,
                    algorithms=ALLOWED_ALGORITHMS,
                    audience=expected_audience,
                    leeway=leeway,
                    options={"require": ["sub", "aud", "exp"]},
                )
            except pyjwt.exceptions.InvalidSignatureError as e:
                last_error = e
                continue
            except pyjwt.exceptions.PyJWTError as e:
                raise InvalidTokenError(f"token rejected: {e}") from e
            return Caller(id=claimed_id, claims=claims)

        raise InvalidTokenError(
            f"signature does not match any key bound to {claimed_sub!r}"
            + (f" (last error: {last_error})" if last_error else "")
        )
