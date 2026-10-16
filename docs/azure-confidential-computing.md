# Azure Confidential Computing — Comparison Architecture

Documented comparison for multi-cloud interviews. Not required to run the local demo.

## Mental model vs GCP

| Concept | Azure | GCP |
|---------|-------|-----|
| CVM | Confidential VMs (AMD SEV-SNP / Intel TDX) | Confidential VMs / Confidential Space |
| Attestation | Microsoft Azure Attestation (MAA) | Confidential Space attestation token |
| Keys | Azure Key Vault / Managed HSM | Cloud KMS |
| K8s | AKS confidential node pools / confidential containers | Confidential GKE |
| Audit | Azure Monitor, Key Vault diagnostics, Activity Log | Cloud Audit Logs |

## Architecture (comparison)

```
Client ──► Azure Front Door / App Gateway ──► Confidential VM / ACC container
                                                 ├── Attestation → MAA
                                                 ├── Release policy → Key Vault secure key release
                                                 └── vLLM / ONNX inference
 Key Vault unwrap only if attestation claims match release policy
```

## Secure Key Release pattern

Azure’s distinctive portfolio talking point: **secure key release** — Key Vault releases a key only when MAA validates the attestation report against a configured policy (signer, SVN, measurements).

That is isomorphic to this repo’s:

```
verify_quote → AccessPolicy.evaluate → LocalKMS.decrypt(allow=True|False)
```

## AKS confidential containers

For platform teams:

- Confidential node pools isolate memory of node workloads
- Confidential containers / enclave-aware runtimes tighten the trust boundary around the inference pod
- Pair with Azure Policy to deny deployments that are not on confidential SKUs

## Interview contrast line

> “Azure’s MAA + Key Vault secure key release is the analogue of GCP Confidential Space attestation-conditioned KMS IAM. I’d pick Azure when the enterprise estate is already Entra ID + Key Vault–centric; GCP when Artifact Registry + Confidential Space is the standard.”
