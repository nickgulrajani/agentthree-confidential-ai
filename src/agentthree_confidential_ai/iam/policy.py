"""IAM-style policy evaluation over attested workload identity.

Production mapping:
  GCP → IAM Conditions + Confidential Space principal attributes
  AWS → KMS key policies conditioned on Nitro PCR values
  Azure → Key Vault access policies + attestation claims
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentthree_confidential_ai.attestation.quote import AttestationQuote


@dataclass(frozen=True)
class AccessDecision:
    allow: bool
    reason: str
    kms_key: str | None = None
    workload_id: str | None = None


class AccessPolicy:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._attested = {
            w["workload_id"]: w for w in config.get("attested_workloads", [])
        }
        self._deny = {w["workload_id"]: w for w in config.get("deny_workloads", [])}
        self._data_classes = config.get("data_classes", {})

    @classmethod
    def from_yaml(cls, path: str | Path) -> AccessPolicy:
        with open(path, encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    def evaluate(
        self,
        *,
        quote: AttestationQuote,
        data_class: str,
        purpose: str,
        attestation_ok: bool,
    ) -> AccessDecision:
        wid = quote.workload_id

        if wid in self._deny:
            return AccessDecision(
                allow=False,
                reason=f"IAM_DENY_LIST: {self._deny[wid].get('reason', 'denied')}",
                workload_id=wid,
            )

        dc = self._data_classes.get(data_class)
        if dc is None:
            return AccessDecision(
                allow=False,
                reason=f"UNKNOWN_DATA_CLASS: {data_class}",
                workload_id=wid,
            )

        if dc.get("require_attestation") and not attestation_ok:
            return AccessDecision(
                allow=False,
                reason="IAM_CONDITION_FAILED: attestation required but quote invalid",
                workload_id=wid,
            )

        if not dc.get("require_attestation"):
            return AccessDecision(
                allow=True,
                reason="PUBLIC_DATA: no attestation required",
                kms_key=dc.get("kms_key"),
                workload_id=wid,
            )

        allowed = self._attested.get(wid)
        if allowed is None:
            return AccessDecision(
                allow=False,
                reason="IAM_NO_BINDING: workload not in attested allow-list",
                workload_id=wid,
            )

        if allowed.get("image_digest") != quote.image_digest:
            return AccessDecision(
                allow=False,
                reason="IAM_IMAGE_MISMATCH: measurement does not match approved digest",
                workload_id=wid,
            )

        if purpose not in allowed.get("allowed_purposes", []):
            return AccessDecision(
                allow=False,
                reason=f"IAM_PURPOSE_DENIED: purpose '{purpose}' not authorized",
                workload_id=wid,
            )

        required_purpose = dc.get("require_purpose")
        if required_purpose and purpose != required_purpose:
            return AccessDecision(
                allow=False,
                reason=f"IAM_DATA_PURPOSE_MISMATCH: need '{required_purpose}'",
                workload_id=wid,
            )

        return AccessDecision(
            allow=True,
            reason="IAM_ALLOW: attested identity satisfies policy conditions",
            kms_key=dc.get("kms_key") or allowed.get("kms_key"),
            workload_id=wid,
        )
