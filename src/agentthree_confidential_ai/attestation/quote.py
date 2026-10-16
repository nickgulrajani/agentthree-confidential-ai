"""Hardware quote simulation (AMD SEV-SNP / Intel TDX / Nitro PCR stand-in).

Production mapping:
  GCP Confidential Space → attestation token (OIDC) from the TEE
  AWS Nitro Enclaves     → NSM attestation document (PCRs)
  Azure CC               → MAA / SEV-SNP attestation report
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from typing import Any


# Demo root-of-trust secret. In production this is the CPU vendor / platform key.
_DEMO_HARDWARE_ROOT = b"agentthree-demo-hardware-root-of-trust-not-for-production"


@dataclass(frozen=True)
class AttestationQuote:
    """Cryptographically bound evidence that a workload runs in a measured TEE."""

    workload_id: str
    image_digest: str
    tee_type: str  # sev-snp | tdx | nitro | simulated
    measurement: str
    nonce: str
    issued_at: int
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_bytes(self) -> bytes:
        payload = {k: v for k, v in self.to_dict().items() if k != "signature"}
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _measurement(workload_id: str, image_digest: str, tee_type: str) -> str:
    raw = f"{tee_type}|{workload_id}|{image_digest}".encode()
    return hashlib.sha256(raw).hexdigest()


def _sign(payload: bytes) -> str:
    return hmac.new(_DEMO_HARDWARE_ROOT, payload, hashlib.sha256).hexdigest()


def issue_quote(
    *,
    workload_id: str,
    image_digest: str,
    tee_type: str = "simulated-sev-snp",
    nonce: str | None = None,
) -> AttestationQuote:
    """Issue a signed quote as if from the Hardware Root of Trust."""
    nonce = nonce or hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:16]
    measurement = _measurement(workload_id, image_digest, tee_type)
    draft = AttestationQuote(
        workload_id=workload_id,
        image_digest=image_digest,
        tee_type=tee_type,
        measurement=measurement,
        nonce=nonce,
        issued_at=int(time.time()),
        signature="",
    )
    signature = _sign(draft.to_bytes())
    return AttestationQuote(
        workload_id=draft.workload_id,
        image_digest=draft.image_digest,
        tee_type=draft.tee_type,
        measurement=draft.measurement,
        nonce=draft.nonce,
        issued_at=draft.issued_at,
        signature=signature,
    )


def forge_untrusted_claim(
    *,
    workload_id: str,
    image_digest: str = "sha256:untrusted",
) -> AttestationQuote:
    """Produce a quote-shaped object that will fail signature verification."""
    return AttestationQuote(
        workload_id=workload_id,
        image_digest=image_digest,
        tee_type="none",
        measurement="0" * 64,
        nonce="forged",
        issued_at=int(time.time()),
        signature="deadbeef" * 8,
    )
