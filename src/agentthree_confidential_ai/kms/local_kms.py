"""Local envelope-encryption KMS stand-in for Cloud KMS / AWS KMS / Azure Key Vault.

Demonstrates: DEK wrap/unwrap is gated by an upstream attestation+IAM decision.
Plaintext keys never leave this module except after an allow decision.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptedBlob:
    data_class: str
    ciphertext_b64: str
    nonce_b64: str
    wrapped_dek_b64: str
    kms_key: str


class LocalKMS:
    """Simulates a cloud KMS that only unwraps after policy allows."""

    def __init__(self, master_key: bytes | None = None) -> None:
        # Deterministic demo master key so ciphertext is reproducible in tests.
        self._master = master_key or hashlib.sha256(
            b"agentthree-demo-kms-master-key"
        ).digest()

    def _kek_for(self, kms_key: str) -> bytes:
        return hashlib.sha256(self._master + kms_key.encode()).digest()

    def encrypt(
        self,
        plaintext: bytes,
        *,
        data_class: str,
        kms_key: str,
    ) -> EncryptedBlob:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ct = AESGCM(dek).encrypt(nonce, plaintext, data_class.encode())

        kek = self._kek_for(kms_key)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(kek).encrypt(wrap_nonce, dek, kms_key.encode())

        return EncryptedBlob(
            data_class=data_class,
            ciphertext_b64=base64.b64encode(ct).decode(),
            nonce_b64=base64.b64encode(nonce).decode(),
            wrapped_dek_b64=base64.b64encode(wrap_nonce + wrapped).decode(),
            kms_key=kms_key,
        )

    def decrypt(
        self,
        blob: EncryptedBlob,
        *,
        allow: bool,
        deny_reason: str = "KMS_DENY",
    ) -> bytes:
        if not allow:
            raise PermissionError(
                f"{deny_reason}: KMS refused unwrap for key {blob.kms_key}"
            )

        packed = base64.b64decode(blob.wrapped_dek_b64)
        wrap_nonce, wrapped = packed[:12], packed[12:]
        kek = self._kek_for(blob.kms_key)
        dek = AESGCM(kek).decrypt(wrap_nonce, wrapped, blob.kms_key.encode())

        nonce = base64.b64decode(blob.nonce_b64)
        ct = base64.b64decode(blob.ciphertext_b64)
        return AESGCM(dek).decrypt(nonce, ct, blob.data_class.encode())
