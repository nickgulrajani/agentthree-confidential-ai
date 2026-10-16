"""Confidential AI control plane: aTLS-style gate → IAM → KMS → audit.

Mirrors the architecture diagram:
  User Client → Cube Proxy (untrusted) → Attestation Agent (TEE) → KMS unwrap → LLM
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentthree_confidential_ai.attestation.quote import AttestationQuote
from agentthree_confidential_ai.attestation.verifier import verify_quote
from agentthree_confidential_ai.audit.trail import AuditEvent, AuditTrail
from agentthree_confidential_ai.iam.policy import AccessPolicy
from agentthree_confidential_ai.kms.local_kms import EncryptedBlob, LocalKMS


@dataclass
class AccessAttemptResult:
    allowed: bool
    plaintext: bytes | None
    reason: str
    attestation_ok: bool
    decision_details: dict[str, Any]


class ConfidentialControlPlane:
    """Policy enforcement point for protected data access."""

    def __init__(
        self,
        policy: AccessPolicy,
        kms: LocalKMS,
        audit: AuditTrail,
    ) -> None:
        self.policy = policy
        self.kms = kms
        self.audit = audit

    @classmethod
    def from_paths(
        cls,
        policy_path: str | Path,
        audit_path: str | Path,
    ) -> ConfidentialControlPlane:
        return cls(
            policy=AccessPolicy.from_yaml(policy_path),
            kms=LocalKMS(),
            audit=AuditTrail(audit_path),
        )

    def seal_sample(
        self,
        plaintext: bytes,
        *,
        data_class: str,
    ) -> EncryptedBlob:
        dc = self.policy._data_classes[data_class]
        kms_key = dc.get("kms_key") or "projects/demo/locations/global/keyRings/cai/cryptoKeys/public"
        blob = self.kms.encrypt(plaintext, data_class=data_class, kms_key=kms_key)
        self.audit.record(
            AuditEvent.create(
                action="KMS_ENCRYPT",
                outcome="ALLOW",
                reason="Envelope encrypted under classification key",
                data_class=data_class,
                details={"kms_key": blob.kms_key},
            )
        )
        return blob

    def request_decrypt(
        self,
        blob: EncryptedBlob,
        *,
        quote: AttestationQuote,
        purpose: str,
        expected_nonce: str | None = None,
    ) -> AccessAttemptResult:
        """Full gate: verify quote → evaluate IAM → unwrap DEK or deny."""
        verification = verify_quote(quote, expected_nonce=expected_nonce)
        decision = self.policy.evaluate(
            quote=quote,
            data_class=blob.data_class,
            purpose=purpose,
            attestation_ok=verification.ok,
        )

        details = {
            "attestation": verification.reason,
            "iam": decision.reason,
            "tee_type": quote.tee_type,
            "image_digest": quote.image_digest,
            "kms_key": blob.kms_key,
        }

        if not decision.allow:
            self.audit.record(
                AuditEvent.create(
                    action="PROTECTED_DATA_ACCESS",
                    outcome="DENY",
                    reason=decision.reason,
                    workload_id=quote.workload_id,
                    data_class=blob.data_class,
                    purpose=purpose,
                    details=details,
                )
            )
            return AccessAttemptResult(
                allowed=False,
                plaintext=None,
                reason=decision.reason,
                attestation_ok=verification.ok,
                decision_details=details,
            )

        try:
            plaintext = self.kms.decrypt(
                blob,
                allow=True,
                deny_reason=decision.reason,
            )
        except PermissionError as exc:
            self.audit.record(
                AuditEvent.create(
                    action="PROTECTED_DATA_ACCESS",
                    outcome="DENY",
                    reason=str(exc),
                    workload_id=quote.workload_id,
                    data_class=blob.data_class,
                    purpose=purpose,
                    details=details,
                )
            )
            return AccessAttemptResult(
                allowed=False,
                plaintext=None,
                reason=str(exc),
                attestation_ok=verification.ok,
                decision_details=details,
            )

        self.audit.record(
            AuditEvent.create(
                action="PROTECTED_DATA_ACCESS",
                outcome="ALLOW",
                reason=decision.reason,
                workload_id=quote.workload_id,
                data_class=blob.data_class,
                purpose=purpose,
                details=details,
            )
        )
        return AccessAttemptResult(
            allowed=True,
            plaintext=plaintext,
            reason=decision.reason,
            attestation_ok=verification.ok,
            decision_details=details,
        )
