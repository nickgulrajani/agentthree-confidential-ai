"""Append-only audit trail for regulated access decisions.

Production mapping:
  GCP → Cloud Audit Logs + Confidential Computing attestation events
  AWS → CloudTrail + KMS Decrypt events
  Azure → Azure Monitor / Key Vault diagnostic logs
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    event_id: str
    timestamp: float
    action: str
    outcome: str  # ALLOW | DENY | ERROR
    workload_id: str | None
    data_class: str | None
    purpose: str | None
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        action: str,
        outcome: str,
        reason: str,
        workload_id: str | None = None,
        data_class: str | None = None,
        purpose: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            action=action,
            outcome=outcome,
            workload_id=workload_id,
            data_class=data_class,
            purpose=purpose,
            reason=reason,
            details=details or {},
        )


class AuditTrail:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def record(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), sort_keys=True) + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return []
        events: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events
