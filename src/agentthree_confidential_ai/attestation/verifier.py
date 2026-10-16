"""Verify attestation quotes and map them to IAM-eligible identities."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from agentthree_confidential_ai.attestation.quote import (
    AttestationQuote,
    _DEMO_HARDWARE_ROOT,
)


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str
    quote: AttestationQuote | None = None


def verify_quote(
    quote: AttestationQuote,
    *,
    expected_nonce: str | None = None,
    max_age_seconds: int = 300,
) -> VerificationResult:
    """Verify signature, freshness, and optional nonce binding (aTLS-style)."""
    expected_sig = hmac.new(
        _DEMO_HARDWARE_ROOT, quote.to_bytes(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, quote.signature):
        return VerificationResult(
            ok=False,
            reason="QUOTE_SIGNATURE_INVALID: hardware root of trust rejected quote",
            quote=quote,
        )

    age = int(time.time()) - quote.issued_at
    if age < 0 or age > max_age_seconds:
        return VerificationResult(
            ok=False,
            reason=f"QUOTE_EXPIRED: age={age}s exceeds {max_age_seconds}s",
            quote=quote,
        )

    if expected_nonce is not None and quote.nonce != expected_nonce:
        return VerificationResult(
            ok=False,
            reason="QUOTE_NONCE_MISMATCH: possible replay",
            quote=quote,
        )

    if quote.tee_type in ("none", "untrusted", ""):
        return VerificationResult(
            ok=False,
            reason="TEE_ABSENT: workload is not running in a confidential VM/enclave",
            quote=quote,
        )

    return VerificationResult(ok=True, reason="ATTESTED", quote=quote)
