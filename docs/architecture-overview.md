# Architecture Overview — Confidential AI for Regulated Industries

**AgentThree Confidential AI** demonstrates how an LLM workload can decrypt sensitive data **only after remote attestation proves it is running inside a Trusted Execution Environment (TEE)**, with IAM, KMS, and audit trails enforcing and recording every decision.

This repository is a **portfolio / interview specialization artifact**. The runnable demo is a **local simulation** (zero cloud billing). Cloud sections document how the same control flow maps onto production platforms.

## Trust zones (matches reference diagram)

```
┌─────────────┐    encrypted     ┌──────────────────┐   aTLS    ┌─────────────────────────────┐
│ User Client │ ───────────────► │ Untrusted Host   │ ────────► │ Trusted Execution Env (CVM) │
│             │ ◄─────────────── │ Cube / Edge Proxy│ ◄──────── │ Attestation Agent           │
│             │  inference out   │ (cannot see PT)  │           │ Encrypted buffer → vLLM     │
└─────────────┘                  └──────────────────┘           └──────────────┬──────────────┘
                                                                               │ Get Signed Quote
                                                                               ▼
                                                                    ┌──────────────────────┐
                                                                    │ Hardware Root of Trust│
                                                                    │ AMD SEV-SNP / Intel   │
                                                                    │ TDX / Nitro NSM       │
                                                                    └──────────────────────┘
```

| Zone | Trust | Role |
|------|-------|------|
| User Client | User device | Sends encrypted request; receives inference result |
| Untrusted cloud host / proxy | Operator can see ciphertext only | Terminates outer TLS; forwards to TEE via **attested TLS (aTLS)** |
| Confidential VM / Enclave | Measured code + memory encryption | Attestation agent, decrypt buffer, vLLM inference |
| Hardware root of trust | CPU vendor silicon | Issues **signed quote** of measurements |

## Control flow this repo implements

1. **Seal** — Sensitive payload (synthetic PHI) is envelope-encrypted under a classification KMS key.
2. **Attest** — Workload presents a hardware-bound quote (simulated locally; real quote/token in cloud).
3. **Verify** — Control plane checks signature, freshness, nonce (replay resistance).
4. **IAM** — Policy binds `workload_id` + `image_digest` + `purpose` + data class.
5. **KMS** — DEK unwrap succeeds **only** if IAM allows; otherwise `PermissionError` / DENY.
6. **Audit** — Every ALLOW/DENY is appended to an immutable-style JSONL trail.

### Signature demo outcomes

| Workload | Attestation | Result |
|----------|-------------|--------|
| `llm-inference-vllm` (approved digest) | Valid simulated SEV-SNP quote | **ALLOW** — plaintext available inside TEE path |
| `rogue-notebook` / `plain-gce-vm` | Forged / no TEE | **DENY** — KMS refuses unwrap |

## Multi-cloud specialization map

| Concern | GCP (primary) | AWS (comparison) | Azure (comparison) |
|---------|---------------|------------------|--------------------|
| TEE / CVM | Confidential Space, Confidential GKE (SEV/TDX) | Nitro Enclaves, Nitro TPM | Confidential VMs, ACC, SEV-SNP |
| Attestation | Attestation token → workload identity | NSM attestation doc (PCRs) | Microsoft Azure Attestation (MAA) |
| Keys | Cloud KMS + IAM conditions | KMS key policy + PCR conditions | Key Vault + managed HSM |
| Identity | Workload Identity / service accounts | IAM roles + enclave identity | Managed identities |
| Audit | Cloud Audit Logs | CloudTrail | Azure Monitor / diagnostic logs |

Deep dives: [GCP Confidential Space](gcp-confidential-space.md) · [Confidential GKE](gcp-confidential-gke.md) · [AWS Nitro](aws-nitro-enclaves.md) · [Azure CC](azure-confidential-computing.md) · [Regulated industries](regulated-industries.md)

## What is deliberately *not* billable

- No required GCP/AWS/Azure project to run `scripts/run_demo.sh`
- No live KMS, GKE, or Confidential Space dependency for CI/tests
- Terraform under `terraform/gcp/` is **optional scaffolding** for when you choose to deploy — not invoked by the demo

## Interview talking points

1. **Memory encryption ≠ access control** — You still need attestation-bound IAM on KMS.
2. **Proxy is untrusted** — aTLS ensures the client/proxy talks to the *measured* workload, not a lookalike.
3. **Image digest is policy** — Same binary on a plain VM must fail; only the attested measurement unlocks PHI.
4. **Audit is the product for regulated buyers** — Healthcare and banking care about who decrypted what, when, and under which measurement.
