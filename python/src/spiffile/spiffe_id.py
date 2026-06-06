"""SPIFFE ID parsing and validation.

Implements the SPIFFE-ID standard:
https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
"""

from __future__ import annotations

import string
from dataclasses import dataclass

from .errors import InvalidSpiffeIdError

_SCHEME = "spiffe://"
_TRUST_DOMAIN_CHARS = set(string.ascii_lowercase + string.digits + "._-")
_PATH_SEGMENT_CHARS = set(string.ascii_letters + string.digits + "._-")


@dataclass(frozen=True)
class SpiffeId:
    """A validated SPIFFE ID, e.g. ``spiffe://example.org/tenant-manager``."""

    trust_domain: str
    path: str  # empty string, or starts with "/"

    @classmethod
    def parse(cls, value: str) -> SpiffeId:
        if not isinstance(value, str) or not value.startswith(_SCHEME):
            raise InvalidSpiffeIdError(f"not a SPIFFE ID (missing {_SCHEME!r} scheme): {value!r}")

        rest = value[len(_SCHEME) :]
        trust_domain, slash, path = rest.partition("/")

        if not trust_domain:
            raise InvalidSpiffeIdError(f"empty trust domain: {value!r}")
        if not set(trust_domain) <= _TRUST_DOMAIN_CHARS:
            raise InvalidSpiffeIdError(
                f"trust domain may only contain lowercase letters, digits, '.', '_' and '-': {value!r}"
            )

        if slash:
            if not path:
                raise InvalidSpiffeIdError(f"trailing slash is not allowed: {value!r}")
            for segment in path.split("/"):
                if not segment:
                    raise InvalidSpiffeIdError(f"empty path segment: {value!r}")
                if segment in (".", ".."):
                    raise InvalidSpiffeIdError(f"relative path segment {segment!r} is not allowed: {value!r}")
                if not set(segment) <= _PATH_SEGMENT_CHARS:
                    raise InvalidSpiffeIdError(
                        f"path segments may only contain letters, digits, '.', '_' and '-': {value!r}"
                    )

        return cls(trust_domain=trust_domain, path=f"/{path}" if slash else "")

    def __str__(self) -> str:
        return f"{_SCHEME}{self.trust_domain}{self.path}"
