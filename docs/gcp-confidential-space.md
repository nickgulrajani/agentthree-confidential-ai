# GCP Confidential Space — Primary Production Architecture

Confidential Space is Google Cloud’s opinionated path for **attested container workloads** that consume secrets from Cloud KMS / Secret Manager only after the TEE proves its identity.

This document maps the AgentThree local demo onto a real GCP design suitable for healthcare/banking AI inference.

## Why Confidential Space for LLM inference

- Workload runs in a **Confidential VM** (AMD SEV-SNP or Intel TDX depending on machine series).
- An **attestation token** (OIDC-style) is minted from hardware measurements + image digest.
- Cloud IAM can condition `cloudkms.cryptoKeyDecrypter` on attestation claims.
- Fits the diagram: untrusted host/proxy outside; decrypt + vLLM inside the attested container.

## Reference topology

```
Client ──TLS──► HTTPS Load Balancer / Envoy (untrusted)
                      │
                      │ aTLS / mTLS to attested endpoint
                      ▼
            Confidential Space (container)
            ├── Attestation agent / launcher
            ├── Sidecar: fetch KMS-wrapped DEK after token exchange
            └── vLLM (or TGI) serving OpenAI-compatible API
                      │
                      ▼
            Cloud KMS (CMEK)  ◄── IAM condition: attestation.sub / image digest
            Cloud Audit Logs  ◄── every Decrypt + Deny
```

## Attestation → IAM → KMS (production pattern)

1. Workload starts; Confidential Space launcher obtains an **attestation token**.
2. Workload exchanges token for a short-lived credential (Workload Identity Federation pattern) or presents claims to a broker.
3. IAM policy on the PHI crypto key includes a condition such as:
   - approved `image_digest`
   - expected audience / issuer for Confidential Space tokens
4. Only then does `Decrypt` succeed for the wrapped DEK.
5. Plaintext exists solely in encrypted memory of the CVM; responses leave as model outputs (minimize raw PHI egress).

**Local demo analogue:** `issue_quote` + `AccessPolicy.evaluate` + `LocalKMS.decrypt(allow=...)`.

## Suggested GCP resources (non-billable until applied)

| Resource | Purpose |
|----------|---------|
| Artifact Registry image (pinned digest) | Measured container = policy input |
| Confidential Space workload | TEE + attestation |
| Cloud KMS key ring `cai` / key `phi-dek` | Envelope encryption for PHI |
| Service account + IAM conditions | Bind decrypt to attested identity |
| Cloud Audit Logs sinks → BigQuery | 7-year retention signal for HIPAA/SOC2 narratives |
| VPC-SC (optional) | Reduce data exfil surface for regulated tenants |

See `terraform/gcp/` for starter HCL (apply only when you intentionally accept cloud cost).

## aTLS notes

Attested TLS binds the TLS handshake to the attestation evidence so a malicious proxy cannot MITM a non-attested process. In GCP designs this is often:

- custom handshake with attestation token in the first application messages, or
- mTLS where the certificate is issued only after attestation verification by a broker.

The local demo models nonce-bound quote verification as the aTLS freshness property.

## LLM-specific controls

- Prefer **egress allow-lists** from the Confidential Space workload (model weights in, PHI out only as approved response schema).
- Separate keys for **model weights** vs **customer PHI** (different blast radius).
- Log **measurement + purpose**, never raw PHI, in audit trails.
- Use synthetic data in demos; production PHI stays in customer CMEK projects.
