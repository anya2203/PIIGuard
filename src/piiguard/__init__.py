"""PIIGuard: Offline PII Detection and Pseudonymization Pipeline.

Core pipeline modules for deterministic regex extraction, synthetic pseudonymization,
and secure encrypted vault storage.
"""

from src.stage1_regex import (
    LABEL_AADHAAR,
    LABEL_EMAIL,
    LABEL_IP_ADDRESS,
    LABEL_PAN,
    LABEL_PHONE,
    PIIEntity,
    RegexPIIExtractor,
    extract_pii,
)
from src.stage3_pseudonym import Pseudonymizer
from src.vault import (
    CorruptedVaultError,
    DecryptionError,
    EncryptedVault,
    KeyVaultError,
    Vault,
    VaultError,
    generate_key,
    load_key,
    save_key,
)

__all__ = [
    "LABEL_AADHAAR",
    "LABEL_EMAIL",
    "LABEL_IP_ADDRESS",
    "LABEL_PAN",
    "LABEL_PHONE",
    "PIIEntity",
    "RegexPIIExtractor",
    "extract_pii",
    "Pseudonymizer",
    "EncryptedVault",
    "Vault",
    "generate_key",
    "save_key",
    "load_key",
    "VaultError",
    "KeyVaultError",
    "DecryptionError",
    "CorruptedVaultError",
]
