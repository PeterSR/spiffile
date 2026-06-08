"""spiffile — SPIFFE identities delivered as files, no agents.

Implements the SPIFFE identity documents (SPIFFE-ID, JWT-SVID, trust
bundles); SVID material and bundles arrive as files written by whatever
infrastructure you already trust (a secrets operator, mounted Secrets, a
dev tool). See PROFILE.md for the file layout and bundle format.
"""

from .bundle import Bundle, FileBundleSource
from .errors import (
    InvalidBundleError,
    InvalidSpiffeIdError,
    InvalidTokenError,
    SpiffileError,
    UnknownIdentityError,
)
from .identity import Caller, Identity, unverified_audience
from .spiffe_id import SpiffeId

__version__ = "0.1.0"

__all__ = [
    "Bundle",
    "Caller",
    "FileBundleSource",
    "Identity",
    "InvalidBundleError",
    "InvalidSpiffeIdError",
    "InvalidTokenError",
    "SpiffeId",
    "SpiffileError",
    "UnknownIdentityError",
    "__version__",
    "unverified_audience",
]
