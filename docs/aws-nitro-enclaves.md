# AWS Nitro Enclaves — Comparison Architecture

Documented comparison for multi-cloud interviews. Not required to run the local demo.

## Mental model vs GCP Confidential Space

| Concept | AWS Nitro Enclaves | GCP Confidential Space |
|---------|-------------------|------------------------|
| Isolation unit | Enclave (isolated VM partition, no persistent storage/networking by default) | Confidential VM + attested container |
| Evidence | Attestation document from Nitro Security Module (NSM); **PCR** measurements | Attestation token with image/hardware claims |
| Parent | EC2 instance (untrusted relative to enclave) | Host/proxy untrusted relative to CVM |
| Keys | AWS KMS decrypt conditioned on PCR policy | Cloud KMS + IAM conditions on attestation |
| Typical AI pattern | Parent runs proxy; enclave runs decrypt + inference stub | Single attested container with vLLM |

## Architecture (comparison)

```
Client ──► ALB / API Gateway ──► EC2 parent (Nitro)
                                   ├── vsock ──► Nitro Enclave
                                   │              ├── verify / hold DEK
                                   │              └── run inference logic
                                   └── AWS KMS ◄── key policy: PCR0/PCR1/... match
 CloudTrail records KMS Decrypt allow/deny
```

## Attestation-gated decrypt (AWS-shaped)

1. Enclave requests attestation document from NSM (includes PCRs + optional public key).
2. Document is presented to KMS (or a broker that calls KMS).
3. KMS key policy `Condition` requires PCR values matching the approved enclave image.
4. Parent EC2 **without** matching PCRs cannot Decrypt — same outcome as our `rogue-notebook` DENY.

**Local demo mapping:** `image_digest` ≈ PCR set; `forge_untrusted_claim` ≈ parent trying KMS without enclave evidence.

## LLM considerations on Nitro

- Enclaves have **no direct network**; parent proxies bytes over vsock (aligns with “Cube Proxy” untrusted zone).
- Large vLLM footprints may push you toward **Nitro TPM / confidential EC2** patterns or hybrid: decrypt PHI in enclave, pass minimized features to a larger inference service with compensating controls.
- Still valuable for: tokenization of PHI, claim extraction, crypto key release, policy decision points.

## Interview contrast line

> “On AWS I’d bind KMS to Nitro PCRs over vsock; on GCP I’d bind Cloud KMS to Confidential Space attestation tokens. Same control objective: unattested compute never sees the DEK.”
