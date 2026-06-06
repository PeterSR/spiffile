"""Trust bundle: the document binding SPIFFE IDs to their public keys.

The spiffile bundle is a JSON document mapping each identity to a standard
JWKS. The per-identity binding is what makes the self-issued model safe:
a key may only validate tokens whose ``sub`` it is bound to. See PROFILE.md.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from .errors import InvalidBundleError, InvalidSpiffeIdError, UnknownIdentityError
from .spiffe_id import SpiffeId

logger = logging.getLogger("spiffile")

BUNDLE_VERSION = 1


@dataclass(frozen=True)
class Bundle:
    trust_domain: str
    identities: dict[str, list[dict]]  # SPIFFE ID -> JWKs

    @classmethod
    def from_dict(cls, doc: dict) -> Bundle:
        try:
            trust_domain = doc["trust_domain"]
            version = doc["spiffile_version"]
            identities_doc = doc["identities"]
        except (KeyError, TypeError) as e:
            raise InvalidBundleError(f"bundle is missing required member: {e}") from e
        if version != BUNDLE_VERSION:
            raise InvalidBundleError(f"unsupported spiffile_version: {version!r}")

        # A malformed entry must not take down verification for everyone
        # else in the bundle: skip it (loudly) instead of failing the parse.
        identities: dict[str, list[dict]] = {}
        for raw_id, jwks in identities_doc.items():
            try:
                spiffe_id = SpiffeId.parse(raw_id)
            except InvalidSpiffeIdError as e:
                logger.warning("skipping invalid bundle entry %r: %s", raw_id, e)
                continue
            if spiffe_id.trust_domain != trust_domain:
                logger.warning("skipping bundle entry %r: not in trust domain %r", raw_id, trust_domain)
                continue
            keys = jwks.get("keys") if isinstance(jwks, dict) else None
            if not isinstance(keys, list) or not keys:
                logger.warning("skipping bundle entry %r: no keys", raw_id)
                continue
            identities[str(spiffe_id)] = keys

        return cls(trust_domain=trust_domain, identities=identities)

    def to_dict(self) -> dict:
        return {
            "trust_domain": self.trust_domain,
            "spiffile_version": BUNDLE_VERSION,
            "identities": {spiffe_id: {"keys": keys} for spiffe_id, keys in self.identities.items()},
        }

    def keys_for(self, spiffe_id: str) -> list[dict]:
        try:
            return self.identities[spiffe_id]
        except KeyError:
            raise UnknownIdentityError(f"no keys in trust bundle for {spiffe_id!r}") from None


class FileBundleSource:
    """Reads a bundle from a file, hot-reloading when the file changes.

    Change detection is mtime+size based, so updates written by ESO/kubelet
    secret syncs (which replace the file) are picked up without restarts.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._stat: tuple[float, int] | None = None
        self._bundle: Bundle | None = None

    @property
    def path(self) -> Path:
        return self._path

    def get(self) -> Bundle:
        stat = os.stat(self._path)
        current = (stat.st_mtime, stat.st_size)
        if self._bundle is None or current != self._stat:
            try:
                doc = json.loads(self._path.read_text())
            except (OSError, json.JSONDecodeError) as e:
                raise InvalidBundleError(f"cannot read bundle at {self._path}: {e}") from e
            self._bundle = Bundle.from_dict(doc)
            self._stat = current
        return self._bundle
