# OPTIONAL — scaffolding only. Applying creates billable GCP resources.
# Local demo does not use this file.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project ID (set only when you intend to apply)."
}

variable "region" {
  type    = string
  default = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_kms_key_ring" "cai" {
  name     = "cai"
  location = "global"
}

resource "google_kms_crypto_key" "phi_dek" {
  name            = "phi-dek"
  key_ring        = google_kms_key_ring.cai.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

# Bind decrypt to a dedicated SA. In production, add IAM Conditions
# that require Confidential Space attestation claims / approved digests.
resource "google_service_account" "attested_inference" {
  account_id   = "cai-attested-inference"
  display_name = "Confidential AI attested inference"
}

resource "google_kms_crypto_key_iam_member" "phi_decrypt" {
  crypto_key_id = google_kms_crypto_key.phi_dek.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.attested_inference.email}"
}

output "phi_key_id" {
  value       = google_kms_crypto_key.phi_dek.id
  description = "Use as CMEK for PHI envelope encryption"
}

output "attested_sa_email" {
  value = google_service_account.attested_inference.email
}
