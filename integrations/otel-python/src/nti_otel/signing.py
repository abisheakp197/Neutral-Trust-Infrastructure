"""Optional ML-DSA-87 signing through the NTI reference engine.

Signing is optional: the chain is already tamper-evident without it. It stops
being optional once the log has to leave the machine that produced it, because
an unsigned chain proves internal consistency and says nothing about authorship.

Two limits of the engine at 0.2.1 apply here, and neither is worked around:

- `PqcKeyPair` can only be created by `generate()`, so a key cannot be persisted
  and therefore cannot survive a process restart. A fresh key per process would
  silently invalidate every earlier signature.
- `PqcKeyPair.verify()` is an instance method and there is no constructor from a
  public key, so a third party holding only the public key cannot verify a
  signature at all.

Consequently this module offers in-process signing only. It does not claim
non-repudiation, and records it produces must not be described as NTI
authorization receipts: that claim needs a receipt bound to the engine's
verdict, which is NTI-1 RFC 0001. Both engine gaps are work items there.
"""

from __future__ import annotations

import sys
from typing import Callable

ENV_KEY = "NTI_OTEL_SIGNING_KEY"

_warned = False


def _warn_once(message: str) -> None:
    global _warned
    if not _warned:
        print(f"nti-otel: {message}", file=sys.stderr)
        _warned = True


def generate_signer() -> tuple[Callable[[str], str] | None, str | None]:
    """Return (signer, public_key_hex) using a fresh in-memory engine keypair.

    Returns (None, None) when the engine is not installed, so that tracing a
    request never fails because telemetry signing is unavailable. Publish the
    returned public key next to the log: a signature with no published key is
    not evidence of anything.
    """
    try:
        from ube_foundation import PqcKeyPair
    except ImportError:
        _warn_once("ube-foundation is not installed; records will be unsigned")
        return None, None

    key = PqcKeyPair()  # #[new] is the generator: generate() is not exposed
    public_key_hex = key.public_key_hex()

    def _sign(record_hash: str) -> str:
        return "ml-dsa-87:" + bytes(key.sign_bytes(record_hash.encode("ascii"))).hex()

    return _sign, public_key_hex


def signer_from_env() -> Callable[[str], str] | None:
    """Honour NTI_OTEL_SIGNING_KEY only to explain why it cannot be used yet.

    Silently ignoring the variable would let a deployment believe its records
    are signed when they are not, which is worse than refusing.
    """
    import os

    if not os.environ.get(ENV_KEY):
        return None
    _warn_once(
        f"{ENV_KEY} is set, but ube-foundation 0.2.1 cannot load a keypair from "
        "disk, so records will be unsigned. Use generate_signer() in a "
        "long-lived process until the engine supports key persistence."
    )
    return None
