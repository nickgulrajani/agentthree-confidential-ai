# Regulated Industries — Why This Architecture Matters

Confidential AI is a **control narrative** buyers in healthcare, banking, and national-security-adjacent sectors recognize.

## Healthcare (HIPAA / HITRUST narratives)

| Risk | Confidential AI control |
|------|-------------------------|
| PHI exposure on shared cloud hosts | Memory encryption + decrypt only in attested TEE |
| Insider / operator access | Host/proxy cannot unwrap DEK without attestation |
| Auditability | Every decrypt attempt ALLOW/DENY in immutable logs |
| Minimum necessary | Purpose-bound IAM (`inference` vs broad admin) |

Demo data in this repo is **synthetic**. Never commit real PHI.

## Banking / financial services

| Risk | Confidential AI control |
|------|-------------------------|
| Customer PII / transaction features in prompts | Classification-keyed envelope encryption (`PII_BANKING`) |
| Model-hosting in multi-tenant cloud | Attestation-bound key release to approved digests only |
| Exam / SOC evidence | Audit trail of denied untrusted workloads |

## Security-sensitive AI architecture roles

Hiring managers look for people who can:

1. Draw the trust-boundary diagram (client / proxy / TEE / root of trust)
2. Explain why **KMS policy** is the enforcement point, not “we used a confidential VM”
3. Compare GCP / AWS / Azure attestation mechanics without vendor lock-in naivety
4. Show a **fail-closed** demo (untrusted path denied)

This repository is designed to support those four points in an interview or architecture review.

## Non-goals (portfolio honesty)

- Not a HIPAA certification
- Not a production BAA-ready SaaS
- Not a billable cloud deployment by default
- Not a substitute for legal / compliance review
