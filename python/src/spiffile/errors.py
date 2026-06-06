"""spiffile exception hierarchy."""

from __future__ import annotations


class SpiffileError(Exception):
    """Base class for all spiffile errors."""


class InvalidSpiffeIdError(SpiffileError):
    """A string is not a valid SPIFFE ID."""


class InvalidBundleError(SpiffileError):
    """A bundle document is malformed or does not match the profile."""


class UnknownIdentityError(SpiffileError):
    """The claimed identity has no keys in the trust bundle."""


class InvalidTokenError(SpiffileError):
    """A token failed verification (signature, audience, expiry, claims)."""
