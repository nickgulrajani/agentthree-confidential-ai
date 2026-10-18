# AgentThree Confidential AI

**Signature technical specialization:** Confidential AI architecture for regulated industries (healthcare, banking, security-sensitive inference).

An attested TEE workload receives permission to decrypt sensitive data. An untrusted workload is denied. IAM, KMS, and audit trails enforce and record the decision.

Companion browser lab: [Confidential Computing & Trusted AI](https://agentthree.ai/solutions/confidential-computing)

> **Non-billable portfolio demo.** Run everything locally with zero cloud cost. GCP Confidential Space / Confidential GKE are the primary *documented* production path; AWS Nitro Enclaves and Azure Confidential Computing are comparison architectures. Optional Terraform is scaffolding only — not required for the demo.

---

## Status

**Last verified:** 2026-10-18 · suite green via [`make verify`](https://github.com/nickgulrajani/agentthree-ai-engineering-portfolio#verify-everything) in the [AI Engineering Portfolio](https://github.com/nickgulrajani/agentthree-ai-engineering-portfolio) monorepo ([CI](https://github.com/nickgulrajani/agentthree-ai-engineering-portfolio/actions/workflows/verify.yml)).


## Implementation status

| Area | Status | Notes |
|------|--------|-------|
| Attestation → IAM → KMS unwrap → audit control flow | **Implemented (local simulation)** | ALLOW for attested; DENY for untrusted / bad digest / debug / expired |
| Simulated SEV-SNP-style quotes | **Implemented (local)** | Forged, debug-mode, and expired tokens fail closed |
| Local KMS + DEK unwrap | **Implemented (local crypto)** | Simulates cloud KMS policy binding |
| JSONL audit trail | **Implemented** | ALLOW and DENY both recorded |
| Multi-cloud architecture docs (GCP primary) | **Documented** | AWS Nitro / Azure CC comparison |
| Terraform (`terraform/gcp/`) | **Optional scaffolding only** | Billable **only if you `apply`** — not used by demo |
| Live Confidential Space / GKE / Nitro / ACC | **Not deployed** | Production mapping in docs — no cloud project required |

**Simulated vs cloud:** The runnable demo proves the *control plane* (attest → authorize → decrypt → audit) with local crypto. Hardware quotes, Cloud KMS, and Confidential VMs are **not** provisioned; see [docs/architecture-overview.md](docs/architecture-overview.md).

Architecture diagram: [docs/architecture-overview.md](docs/architecture-overview.md)

---

## Key Points

```text
Attested  llm-inference-vllm  →  ALLOW  (KMS unwrap succeeds inside TEE path)
Untrusted rogue-notebook      →  DENY   (forged quote / deny-list / no TEE)
Wrong image digest            →  DENY   (IAM_IMAGE_MISMATCH)
Debug mode TEE                →  DENY   (TEE_DEBUG_MODE — no key release)
Expired attestation token     →  DENY   (QUOTE_EXPIRED)
```

Plus a written multi-cloud map: **GCP (primary) · AWS Nitro · Azure CC**.

## Architecture (trust zones)

```text
 User Client          Untrusted Host           Trusted Execution Env         Hardware RoT
 ┌──────────┐        ┌─────────────┐          ┌─────────────────────┐       ┌───────────┐
 │ Encrypted│───────►│ Cube Proxy  │──aTLS───►│ Attestation Agent   │──────►│ AMD/Intel │
 │ request  │        │ (ciphertext │          │ Encrypted buffer    │ quote │ CPU       │
 │          │◄───────│  only)      │◄─────────│ vLLM inference      │◄──────│ Signed    │
 └──────────┘        └─────────────┘          └─────────────────────┘       └───────────┘
```

See [docs/architecture-overview.md](docs/architecture-overview.md) for the full control flow.

## Quick start (local, free)

```bash
cd agentthree-confidential-ai
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh
```

Or manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
agentthree-cai demo
agentthree-cai audit-show
pytest -q
```

### Reproducible tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
agentthree-cai demo
agentthree-cai audit-show
```

Expected: pytest proves attested **ALLOW** and deny paths (untrusted, wrong digest, debug mode, expired token, wrong purpose); demo prints ALLOW/DENY; `audit-show` lists matching JSONL events. No GCP/AWS/Azure credentials required.

## Repository layout

| Path | Purpose |
|------|---------|
| `src/agentthree_confidential_ai/` | Attestation, IAM policy, local KMS, audit, control plane, CLI |
| `configs/policy.yaml` | Attested allow-list, deny-list, data classifications |
| `docs/` | GCP primary + AWS/Azure comparison + regulated-industry narrative |
| `terraform/gcp/` | **Optional** KMS/IAM stubs (billable only if you `apply`) |
| `tests/` | Proof: attested ALLOW + deny paths (digest, debug, expiry, purpose) |

## Documentation index

- [Architecture overview](docs/architecture-overview.md)
- [GCP Confidential Space](docs/gcp-confidential-space.md) (primary)
- [GCP Confidential GKE](docs/gcp-confidential-gke.md)
- [AWS Nitro Enclaves](docs/aws-nitro-enclaves.md) (comparison)
- [Azure Confidential Computing](docs/azure-confidential-computing.md) (comparison)
- [Regulated industries](docs/regulated-industries.md)

## Design principles

1. **Fail closed** — no valid attestation ⇒ no DEK.
2. **Measurement is identity** — image digest / PCR / attestation claims bind IAM.
3. **Proxy is untrusted** — plaintext exists only on the attested path.
4. **Audit is mandatory** — ALLOW and DENY are both first-class evidence.
5. **Honest scope** — local crypto simulates cloud KMS; production mappings are documented, not pretended.

## License

MIT — see [LICENSE](LICENSE).
