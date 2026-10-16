# AgentThree Confidential AI

**Signature technical specialization:** Confidential AI architecture for regulated industries (healthcare, banking, security-sensitive inference).

An attested TEE workload receives permission to decrypt sensitive data. An untrusted workload is denied. IAM, KMS, and audit trails enforce and record the decision.

> **Non-billable portfolio demo.** Run everything locally with zero cloud cost. GCP Confidential Space / Confidential GKE are the primary *documented* production path; AWS Nitro Enclaves and Azure Confidential Computing are comparison architectures. Optional Terraform is scaffolding only — not required for the demo.

---

## What you can show in an interview

```text
Attested  llm-inference-vllm  →  ALLOW  (KMS unwrap succeeds inside TEE path)
Untrusted rogue-notebook      →  DENY   (forged quote / deny-list / no TEE)
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

## Repository layout

| Path | Purpose |
|------|---------|
| `src/agentthree_confidential_ai/` | Attestation, IAM policy, local KMS, audit, control plane, CLI |
| `configs/policy.yaml` | Attested allow-list, deny-list, data classifications |
| `docs/` | GCP primary + AWS/Azure comparison + regulated-industry narrative |
| `terraform/gcp/` | **Optional** KMS/IAM stubs (billable only if you `apply`) |
| `tests/` | Proof: attested ALLOW, untrusted DENY |

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
