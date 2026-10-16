"""Core portfolio proof: attested ALLOW, untrusted DENY."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentthree_confidential_ai.attestation.quote import (
    forge_untrusted_claim,
    issue_quote,
)
from agentthree_confidential_ai.control_plane import ConfidentialControlPlane

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "policy.yaml"

PHI = b"SYNTHETIC PHI: MRN-TEST-99 | Dx: hypertension"


@pytest.fixture()
def plane(tmp_path: Path) -> ConfidentialControlPlane:
    audit = tmp_path / "access.jsonl"
    return ConfidentialControlPlane.from_paths(POLICY, audit)


def test_attested_workload_can_decrypt(plane: ConfidentialControlPlane) -> None:
    blob = plane.seal_sample(PHI, data_class="PHI")
    quote = issue_quote(
        workload_id="llm-inference-vllm",
        image_digest="sha256:demo-attested-vllm-0001",
    )
    result = plane.request_decrypt(blob, quote=quote, purpose="inference")
    assert result.allowed is True
    assert result.plaintext == PHI
    assert result.attestation_ok is True


def test_untrusted_workload_is_denied(plane: ConfidentialControlPlane) -> None:
    blob = plane.seal_sample(PHI, data_class="PHI")
    quote = forge_untrusted_claim(workload_id="rogue-notebook")
    result = plane.request_decrypt(blob, quote=quote, purpose="inference")
    assert result.allowed is False
    assert result.plaintext is None
    assert result.attestation_ok is False


def test_wrong_image_digest_denied(plane: ConfidentialControlPlane) -> None:
    blob = plane.seal_sample(PHI, data_class="PHI")
    quote = issue_quote(
        workload_id="llm-inference-vllm",
        image_digest="sha256:tampered-image",
    )
    result = plane.request_decrypt(blob, quote=quote, purpose="inference")
    assert result.allowed is False
    assert "IMAGE_MISMATCH" in result.reason


def test_wrong_purpose_denied(plane: ConfidentialControlPlane) -> None:
    blob = plane.seal_sample(PHI, data_class="PHI")
    quote = issue_quote(
        workload_id="llm-inference-vllm",
        image_digest="sha256:demo-attested-vllm-0001",
    )
    result = plane.request_decrypt(blob, quote=quote, purpose="model_exfil")
    assert result.allowed is False
    assert "PURPOSE" in result.reason


def test_audit_records_allow_and_deny(plane: ConfidentialControlPlane) -> None:
    blob = plane.seal_sample(PHI, data_class="PHI")
    ok_quote = issue_quote(
        workload_id="llm-inference-vllm",
        image_digest="sha256:demo-attested-vllm-0001",
    )
    bad_quote = forge_untrusted_claim(workload_id="plain-gce-vm")
    plane.request_decrypt(blob, quote=ok_quote, purpose="inference")
    plane.request_decrypt(blob, quote=bad_quote, purpose="inference")

    events = plane.audit.read_all()
    access = [e for e in events if e["action"] == "PROTECTED_DATA_ACCESS"]
    outcomes = {e["outcome"] for e in access}
    assert "ALLOW" in outcomes
    assert "DENY" in outcomes
