# GCP Confidential GKE — Cluster-Scale Variant

Use **Confidential GKE** when you need Kubernetes orchestration (autoscaling vLLM replicas, GPU/TPU node pools where available, service mesh) while keeping nodes as Confidential VMs.

## When to prefer Confidential GKE over Confidential Space

| Use Confidential Space | Use Confidential GKE |
|------------------------|----------------------|
| Single purpose attested container | Multi-service AI platform on K8s |
| Minimal ops surface | Need Deployments, HPA, Ingress, mesh |
| Strongest “one image = one policy” story | Team already standardized on GKE |

Both still rely on the same security thesis: **attestation-bound KMS**, not just disk/memory encryption.

## Topology sketch

```
GKE Autopilot / Standard
└── Confidential nodes (SEV-SNP / TDX)
    ├── Namespace: cai-inference
    │   ├── Deployment: vllm (attested image digest)
    │   ├── Sidecar / init: attestation token → KMS unwrap
    │   └── NetworkPolicy: deny egress except KMS + model registry
    ├── Workload Identity → GSA with conditional KMS decrypt
    └── Audit: GKE + Cloud Audit Logs → SIEM
```

## Policy binding on GKE

1. Pin Deployment `image` to digest (`@sha256:...`), not mutable tags.
2. Map Kubernetes SA → Google SA via Workload Identity.
3. Put **IAM Conditions** on `roles/cloudkms.cryptoKeyDecrypter` referencing attestation attributes / approved principals.
4. Deny by default: any pod on a *non-confidential* node pool must not receive the decrypt role.

**Local demo analogue:** deny list entries `plain-gce-vm` and `rogue-notebook`.

## GPU note (interview honesty)

Confidential computing + GPU TEE availability varies by region and generation. For portfolio narratives:

- CPU TEE for **prompt/PHI decryption and pre/post-processing**
- Document GPU path as “accelerated inference with complementary controls” when full GPU attestation is not yet available in the target region

Architects who acknowledge this gap read as production-credible.

## Mapping to repo modules

| Repo module | GKE production counterpart |
|-------------|----------------------------|
| `attestation/` | Node TEE + workload attestation token |
| `iam/policy.yaml` | IAM Conditions + Binary Authorization |
| `kms/local_kms.py` | Cloud KMS CMEK |
| `audit/trail.py` | Cloud Audit Logs + Security Command Center |
