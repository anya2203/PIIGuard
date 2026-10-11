"""Encrypted Offline Mapping Vault.

Module: vault
Part of the PIIGuard Offline PII Detection and Pseudonymization Pipeline.

CRITICAL SECURITY & KEY LOSS WARNING:
    This vault uses Fernet symmetric authenticated cryptography (AES-128-CBC + HMAC-SHA256).
    If the encryption key is lost, recovery of the encrypted PII mapping is
    MATHEMATICALLY AND COMPUTATIONALLY IMPOSSIBLE. There is NO backdoor, master key,
    or key-recovery mechanism. Always back up keys in a dedicated secure secret store.

ZERO-LEAKAGE DESIGN:
    - Encryption keys MUST ALWAYS be stored separately from encrypted vault files (.enc).
    - Vault files (.enc) and key files (.key) MUST NEVER be committed to Git or public repositories.
    - Plaintext PII mappings are NEVER written to unencrypted disks.

IMPORTANT NOTICE ON LOCAL STORAGE:
    Configuring .gitignore only prevents files from being tracked in Git. It does NOT
    protect or restrict access to files stored on the local filesystem. Protect key files
    and encrypted vaults using operating-system access controls (file permissions).
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


def _opener_restrictive(file_path: str, flags: int) -> int:
    """Opener for file creation with 0o600 permissions where supported by OS."""
    return os.open(file_path, flags, 0o600)


class VaultError(Exception):
    """Base exception for all PIIGuard vault operations."""


class KeyVaultError(VaultError):
    """Raised when an encryption key is missing, unreadable, or invalid."""


class DecryptionError(VaultError):
    """Raised when decryption fails due to an invalid key or tampered ciphertext."""


class CorruptedVaultError(VaultError):
    """Raised when the decrypted payload cannot be parsed as valid JSON."""


def generate_key() -> bytes:
    """Generate a cryptographically secure URL-safe 32-byte Fernet key.

    Returns:
        Generated Fernet key bytes.
    """
    return Fernet.generate_key()


def save_key(key: bytes, key_path: str | Path, overwrite: bool = False) -> None:
    """Save an encryption key to a local file with restrictive permissions.

    When overwrite=False, performs atomic exclusive creation ('xb' mode with O_EXCL / CREATE_NEW)
    to guarantee that concurrent writes cannot silently replace an existing key.
    When overwrite=True, writes to a process-unique temporary file and replaces atomically.

    Args:
        key: Fernet key bytes.
        key_path: Destination path for the .key file.
        overwrite: If True, overwrite an existing key file. Defaults to False
            to prevent accidental destruction of unrecoverable keys.

    Raises:
        KeyVaultError: If the key already exists and overwrite is False, or if write fails.
    """
    path = Path(key_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise KeyVaultError(f"Failed to create parent directory for '{path}': {exc}") from exc

    if not overwrite:
        # Kernel-enforced atomic exclusive creation: O_EXCL on POSIX, CREATE_NEW on Windows
        created = False
        try:
            with open(path, "xb", opener=_opener_restrictive) as f:
                created = True
                f.write(key)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except FileExistsError as exc:
            raise KeyVaultError(
                f"Key file '{path}' already exists. Refusing to overwrite to prevent irreversible data loss. "
                "Pass overwrite=True if you explicitly intend to replace this key."
            ) from exc
        except Exception as exc:
            # Clean up incomplete file only if it was newly created in this call
            if created and path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
            raise KeyVaultError(f"Failed to save encryption key to '{path}': {exc}") from exc
    else:
        # Atomic replacement via unique temporary file
        temp_path = path.with_suffix(f"{path.suffix}.tmp_{os.getpid()}_{uuid.uuid4().hex[:8]}")
        try:
            with open(temp_path, "wb", opener=_opener_restrictive) as f:
                f.write(key)
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            os.replace(temp_path, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except Exception as exc:
            raise KeyVaultError(f"Failed to save encryption key to '{path}': {exc}") from exc
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass


def load_key(key_path: str | Path) -> bytes:
    """Load a Fernet encryption key from a local file.

    Args:
        key_path: Path to the .key file.

    Returns:
        Fernet key bytes.

    Raises:
        KeyVaultError: If the key file does not exist, cannot be read, or is empty.
    """
    path = Path(key_path)
    if not path.is_file():
        raise KeyVaultError(f"Encryption key file not found: '{path}'")

    try:
        key_bytes = path.read_bytes().strip()
        if not key_bytes:
            raise KeyVaultError(f"Encryption key file is empty: '{path}'")
        # Validate that the key is recognized by Fernet
        Fernet(key_bytes)
        return key_bytes
    except KeyVaultError:
        raise
    except Exception as exc:
        raise KeyVaultError(f"Invalid Fernet key format in '{path}': {exc}") from exc


class EncryptedVault:
    """Secure offline vault for storing pseudonymization mappings encrypted with Fernet."""

    def __init__(self, key: bytes | str) -> None:
        """Initialize the vault with a Fernet encryption key.

        Args:
            key: 32-byte URL-safe base64-encoded Fernet key (as bytes or string).

        Raises:
            KeyVaultError: If the provided key is invalid.
        """
        if isinstance(key, str):
            key = key.encode("utf-8")

        try:
            self._fernet = Fernet(key)
            self._key = key
        except Exception as exc:
            raise KeyVaultError(f"Invalid Fernet encryption key: {exc}") from exc

    @property
    def key(self) -> bytes:
        """Get the underlying encryption key."""
        return self._key

    @classmethod
    def generate(cls) -> tuple[EncryptedVault, bytes]:
        """Generate a new vault instance with a freshly generated key.

        Returns:
            Tuple of (EncryptedVault, key_bytes).
        """
        new_key = generate_key()
        return cls(new_key), new_key

    @classmethod
    def from_key_file(cls, key_path: str | Path) -> EncryptedVault:
        """Create a vault instance by loading an existing key file.

        Args:
            key_path: Path to the .key file.

        Returns:
            Configured EncryptedVault instance.
        """
        key_bytes = load_key(key_path)
        return cls(key_bytes)

    def encrypt_mapping(self, mapping: dict[str, Any]) -> bytes:
        """Serialize and encrypt a dictionary mapping into Fernet ciphertext bytes.

        Args:
            mapping: Dictionary mapping entity keys to surrogates or metadata.

        Returns:
            Encrypted ciphertext bytes.
        """
        if not isinstance(mapping, dict):
            raise VaultError("Mapping to encrypt must be a dictionary")

        try:
            serialized_json = json.dumps(mapping, ensure_ascii=False, indent=2)
            raw_bytes = serialized_json.encode("utf-8")
            return self._fernet.encrypt(raw_bytes)
        except Exception as exc:
            raise VaultError(f"Failed to serialize and encrypt mapping: {exc}") from exc

    def decrypt_mapping(self, encrypted_bytes: bytes) -> dict[str, Any]:
        """Decrypt ciphertext bytes and deserialize the enclosed mapping dictionary.

        Args:
            encrypted_bytes: Fernet ciphertext bytes.

        Returns:
            Decrypted dictionary mapping.

        Raises:
            DecryptionError: If decryption fails (wrong key or corrupted/tampered bytes).
            CorruptedVaultError: If decrypted bytes cannot be parsed as valid JSON dictionary.
        """
        if not isinstance(encrypted_bytes, (bytes, bytearray)):
            raise DecryptionError("Encrypted data must be bytes")

        try:
            decrypted_raw = self._fernet.decrypt(encrypted_bytes)
        except InvalidToken as exc:
            raise DecryptionError(
                "Decryption failed: invalid key or corrupted/tampered ciphertext. "
                "Ensure you are using the correct secret key."
            ) from exc
        except Exception as exc:
            raise DecryptionError(f"Unexpected decryption error: {exc}") from exc

        try:
            payload = json.loads(decrypted_raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise CorruptedVaultError("Decrypted vault payload is not a dictionary")
            return payload
        except json.JSONDecodeError as exc:
            raise CorruptedVaultError(f"Decrypted payload contains invalid JSON: {exc}") from exc

    def save_vault(
        self,
        mapping: dict[str, Any],
        vault_path: str | Path,
        overwrite: bool = False,
    ) -> None:
        """Encrypt and export the mapping dictionary to a .enc file on disk.

        When overwrite=False, performs atomic exclusive creation ('xb' mode with O_EXCL / CREATE_NEW)
        to guarantee that concurrent writes cannot silently replace an existing vault file.
        When overwrite=True, writes to a process-unique temporary file and replaces atomically.

        Args:
            mapping: The entity mapping dictionary to protect.
            vault_path: Destination filepath (should end in .enc).
            overwrite: If True, overwrite an existing vault file. Defaults to False
                to prevent accidental data loss.

        Raises:
            VaultError: If vault already exists and overwrite is False, or if write fails.
        """
        path = Path(vault_path)
        ciphertext = self.encrypt_mapping(mapping)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise VaultError(f"Failed to create parent directory for '{path}': {exc}") from exc

        if not overwrite:
            # Kernel-enforced atomic exclusive creation: O_EXCL on POSIX, CREATE_NEW on Windows
            created = False
            try:
                with open(path, "xb", opener=_opener_restrictive) as f:
                    created = True
                    f.write(ciphertext)
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            except FileExistsError as exc:
                raise VaultError(
                    f"Vault file '{path}' already exists. Refusing to overwrite to prevent data loss. "
                    "Pass overwrite=True if you explicitly intend to replace this vault."
                ) from exc
            except Exception as exc:
                # Clean up incomplete file only if it was newly created in this call
                if created and path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        pass
                raise VaultError(f"Failed to save encrypted vault to '{path}': {exc}") from exc
        else:
            # Atomic replacement via unique temporary file
            temp_path = path.with_suffix(f"{path.suffix}.tmp_{os.getpid()}_{uuid.uuid4().hex[:8]}")
            try:
                with open(temp_path, "wb", opener=_opener_restrictive) as f:
                    f.write(ciphertext)
                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass
                os.replace(temp_path, path)
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            except Exception as exc:
                raise VaultError(f"Failed to save encrypted vault to '{path}': {exc}") from exc
            finally:
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass

    def load_vault(self, vault_path: str | Path) -> dict[str, Any]:
        """Load and decrypt an encrypted .enc vault file from disk.

        Args:
            vault_path: Path to the .enc file.

        Returns:
            Decrypted mapping dictionary.

        Raises:
            VaultError: If the file is missing or unreadable.
            DecryptionError: If the key does not match or data is corrupted.
            CorruptedVaultError: If the payload is malformed.
        """
        path = Path(vault_path)
        if not path.is_file():
            raise VaultError(f"Encrypted vault file not found: '{path}'")

        try:
            ciphertext = path.read_bytes()
        except Exception as exc:
            raise VaultError(f"Failed to read vault file '{path}': {exc}") from exc

        return self.decrypt_mapping(ciphertext)


# Convenient alias
Vault = EncryptedVault

