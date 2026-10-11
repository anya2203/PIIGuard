"""Comprehensive pytest test suite for PIIGuard pipeline modules.

Covers:
- Deterministic regex extraction (stage1_regex.py)
- Span management & pseudonymization (stage3_pseudonym.py)
- Encrypted offline vault & key protection (vault.py)
- Zero-leakage terminal output verification (main.py)
- Offline isolation and file permission checks

NOTE: All test data used herein is strictly FICTIONAL / SYNTHETIC.
      Approved fictional identities (Jordan Lee, Northstar Research Labs, etc.)
      are used exclusively.
"""

from __future__ import annotations

import concurrent.futures
import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

import main
from src.stage1_regex import (
    LABEL_AADHAAR,
    LABEL_EMAIL,
    LABEL_IP_ADDRESS,
    LABEL_PAN,
    LABEL_PHONE,
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


# =====================================================================
# 1. Regex PII Extraction Tests (Stage 1)
# =====================================================================

class TestRegexExtraction:
    """Tests for deterministic regex extraction engine."""

    def test_email_detection(self) -> None:
        """Test extraction of various standard and synthetic email formats."""
        text = (
            "Contact jordan.lee@example.org for inquiries, or send copies to "
            "developer+nlp@example.com and test_admin@sub.domain.org."
        )
        entities = extract_pii(text)
        labels = [e["label"] for e in entities]
        emails = [e["text"] for e in entities]

        assert labels == [LABEL_EMAIL, LABEL_EMAIL, LABEL_EMAIL]
        assert "jordan.lee@example.org" in emails
        assert "developer+nlp@example.com" in emails
        assert "test_admin@sub.domain.org" in emails

    def test_email_rejection_of_invalid_formats(self) -> None:
        """Verify non-emails are not falsely detected."""
        text = "This is not an email: user@, @domain.com, user@domain, or just text."
        entities = extract_pii(text)
        assert entities == []

    def test_phone_detection_various_formats(self) -> None:
        """Test extraction of Indian mobile numbers with +91, spaces, hyphens, and 10 digits."""
        samples = [
            ("+91 98765 43210", "+91 98765 43210"),
            ("+91-9876543210", "+91-9876543210"),
            ("+919876543210", "+919876543210"),
            ("9876543210", "9876543210"),
            ("98765 43210", "98765 43210"),
            ("98765-43210", "98765-43210"),
            ("09876543210", "09876543210"),
            ("+91-987-654-3210", "+91-987-654-3210"),
        ]

        for sample_text, expected_number in samples:
            text = f"Candidate phone number is {sample_text}."
            entities = extract_pii(text)
            assert len(entities) == 1, f"Failed for {sample_text}"
            assert entities[0]["label"] == LABEL_PHONE
            assert entities[0]["text"] == expected_number

    def test_phone_rejection_of_invalid_numbers(self) -> None:
        """Verify non-mobile numbers or wrong length numbers are rejected."""
        # Starts with 1 (not 6-9), or only 8 digits, or 13 digits
        text = "Call 1234567890 or 98765432 or 9876543210123 for assistance."
        entities = extract_pii(text)
        phone_matches = [e for e in entities if e["label"] == LABEL_PHONE]
        assert phone_matches == []

    def test_pan_detection(self) -> None:
        """Test detection of standard 10-character PAN patterns."""
        text = "Taxpayers with PAN ABCDE1234F and pan bnzkp9876l must verify records."
        entities = extract_pii(text)
        pan_entities = [e for e in entities if e["label"] == LABEL_PAN]

        assert len(pan_entities) == 2
        assert pan_entities[0]["text"] == "ABCDE1234F"
        assert pan_entities[1]["text"] == "bnzkp9876l"

    def test_pan_rejection_of_invalid_patterns(self) -> None:
        """Verify malformed PAN patterns are ignored."""
        text = "Invalid PANs: ABC1234F (short), ABCDEF1234F (6 letters), ABCDE12345 (no end letter)."
        entities = extract_pii(text)
        pan_entities = [e for e in entities if e["label"] == LABEL_PAN]
        assert pan_entities == []

    def test_aadhaar_detection_formats(self) -> None:
        """Test detection of 12-digit Aadhaar formats with spaces, hyphens, or continuous."""
        samples = [
            ("1234 5678 9012", "1234 5678 9012"),
            ("1234-5678-9012", "1234-5678-9012"),
            ("123456789012", "123456789012"),
            ("9876 5432 1098", "9876 5432 1098"),
        ]

        for sample_text, expected_match in samples:
            text = f"Resident Aadhaar is {sample_text}."
            entities = extract_pii(text)
            aadhaar_matches = [e for e in entities if e["label"] == LABEL_AADHAAR]
            assert len(aadhaar_matches) == 1, f"Failed for {sample_text}"
            assert aadhaar_matches[0]["text"] == expected_match

    def test_ipv4_detection_valid_addresses(self) -> None:
        """Test valid IPv4 address detection, including documentation RFC 5737 ranges."""
        text = "Nodes running on 192.0.2.10, 10.0.0.1, and 255.255.255.255 are active."
        entities = extract_pii(text)
        ip_entities = [e for e in entities if e["label"] == LABEL_IP_ADDRESS]

        assert len(ip_entities) == 3
        assert [e["text"] for e in ip_entities] == ["192.0.2.10", "10.0.0.1", "255.255.255.255"]

    def test_ipv4_rejection_of_invalid_octets(self) -> None:
        """Test strict rejection of IPv4 candidates with octets outside [0, 255]."""
        text = (
            "Invalid addresses: 999.123.45.6, 192.168.1.300, 256.0.0.1, and 10.400.1.2. "
            "Only 192.0.2.10 is genuine."
        )
        entities = extract_pii(text)
        ip_entities = [e for e in entities if e["label"] == LABEL_IP_ADDRESS]

        # Only 192.0.2.10 should be detected; all octet > 255 candidates must be rejected
        assert len(ip_entities) == 1
        assert ip_entities[0]["text"] == "192.0.2.10"

    def test_exact_span_offsets(self) -> None:
        """Verify that returned character offsets exactly slice the target entity from text."""
        text = (
            "Auditor profile: Email jordan.lee@example.org, Phone +91 98765 43210, "
            "Aadhaar 1234 5678 9012, PAN ABCDE1234F, Host 192.0.2.10."
        )
        entities = extract_pii(text)

        assert len(entities) == 5
        for entity in entities:
            start = entity["start"]
            end = entity["end"]
            expected_text = entity["text"]
            # Character slice MUST match exactly
            assert text[start:end] == expected_text
            assert start >= 0
            assert start < end
            assert end <= len(text)

        # Offsets must be sorted
        for i in range(len(entities) - 1):
            assert entities[i]["start"] <= entities[i + 1]["start"]

    def test_clean_text_with_no_pii(self) -> None:
        """Verify clean text without any PII returns an empty list."""
        clean_text = (
            "The Natural Language Processing project is evaluated at Northstar Research Labs on Thursday. "
            "All model weights are stored locally without external cloud dependencies."
        )
        entities = extract_pii(clean_text)
        assert entities == []


# =====================================================================
# 2. Pseudonymization and Span Management Tests (Stage 3)
# =====================================================================

class TestPseudonymizer:
    """Tests for Pseudonymizer class and span replacement."""

    def test_clean_text_unchanged(self) -> None:
        """Verify clean text is returned completely identical."""
        text = "Pure NLP text with no sensitive data whatsoever."
        pseudonymizer = Pseudonymizer()
        result = pseudonymizer.pseudonymize(text, [])
        assert result == text

    def test_repeated_entity_consistency(self) -> None:
        """Verify repeated occurrences of the same entity receive identical surrogates."""
        text = (
            "First mention: jordan.lee@example.org. "
            "Second mention: jordan.lee@example.org. "
            "Third mention in uppercase: JORDAN.LEE@EXAMPLE.ORG."
        )
        entities = extract_pii(text)
        pseudonymizer = Pseudonymizer(seed=123)
        result = pseudonymizer.pseudonymize(text, entities)

        # Original email must not be in the output
        assert "jordan.lee@example.org" not in result
        assert "JORDAN.LEE@EXAMPLE.ORG" not in result

        # The mapping table must contain only 1 key for this normalized email
        assert len(pseudonymizer.mapping) == 1
        surrogate = list(pseudonymizer.mapping.values())[0]

        # The surrogate must appear 3 times in the output text
        assert result.count(surrogate) == 3

    def test_phone_normalization_consistency(self) -> None:
        """Verify different formats of the same phone number map to the same surrogate."""
        text = "Call +91 98765 43210 or alternate 98765-43210."
        entities = extract_pii(text)
        pseudonymizer = Pseudonymizer(seed=456)
        result = pseudonymizer.pseudonymize(text, entities)

        # Both represent phone 9876543210
        assert "PHONE:9876543210" in pseudonymizer.mapping
        assert len(pseudonymizer.mapping) == 1
        surrogate = pseudonymizer.mapping["PHONE:9876543210"]
        assert "+91 98765 43210" not in result
        assert "98765-43210" not in result

    def test_multiple_replacements_in_one_sentence(self) -> None:
        """Verify sentence with email, phone, Aadhaar, PAN, and IP replaced right-to-left."""
        text = (
            "Operator (email: jordan.lee@example.org, mobile: +91 98765 43210, "
            "Aadhaar: 1234 5678 9012, PAN: ABCDE1234F) deployed server at 192.0.2.10."
        )
        entities = extract_pii(text)
        assert len(entities) == 5

        pseudonymizer = Pseudonymizer(seed=789)
        pseudonymized = pseudonymizer.pseudonymize(text, entities)

        # None of the original PII tokens must be present
        assert "jordan.lee@example.org" not in pseudonymized
        assert "+91 98765 43210" not in pseudonymized
        assert "1234 5678 9012" not in pseudonymized
        assert "ABCDE1234F" not in pseudonymized
        assert "192.0.2.10" not in pseudonymized

        # Surrounding text and punctuation must be preserved exactly
        assert pseudonymized.startswith("Operator (email: ")
        assert ", mobile: " in pseudonymized
        assert ", Aadhaar: " in pseudonymized
        assert ", PAN: " in pseudonymized
        assert ") deployed server at " in pseudonymized
        assert pseudonymized.endswith(".")

    def test_overlapping_spans_safe_handling(self) -> None:
        """Verify that overlapping or corrupt spans are safely skipped without crash."""
        text = "Sensitive data snippet here."
        # Fabricate deliberately overlapping spans: [0, 9) and [5, 14)
        overlapping_entities = [
            {"text": "Sensitive", "label": "LABEL_A", "start": 0, "end": 9},
            {"text": "tive data", "label": "LABEL_B", "start": 5, "end": 14},
        ]
        pseudonymizer = Pseudonymizer()
        # Must not raise IndexError or corrupt text
        result = pseudonymizer.pseudonymize(text, overlapping_entities)
        assert isinstance(result, str)
        # One span must be replaced, and the overlapping one skipped safely
        assert "Sensitive" not in result

    def test_invalid_span_indices_skipped(self) -> None:
        """Verify spans with invalid or out-of-bounds indices are ignored."""
        text = "Short text."
        invalid_entities = [
            {"text": "out", "label": "EMAIL", "start": 50, "end": 60},  # out of bounds
            {"text": "neg", "label": "PHONE", "start": -5, "end": 5},   # negative
            {"text": "inv", "label": "PAN", "start": 8, "end": 4},      # start > end
            {"text": "bad", "label": "IP", "start": 0, "end": 5},       # text mismatch
        ]
        pseudonymizer = Pseudonymizer()
        result = pseudonymizer.pseudonymize(text, invalid_entities)
        # Since all spans were invalid, original text remains completely untouched
        assert result == text

    def test_fictional_sample_identity_pseudonymization(self) -> None:
        """Verify detection and pseudonymization using standard fictional sample values."""
        sample_text = (
            "Record: Jordan Lee from Northstar Research Labs. "
            "Contact: jordan.lee@example.org, phone: +91 98765 43210. "
            "Tax PAN: ABCDE1234F, Aadhaar: 1234 5678 9012, IP: 192.0.2.10."
        )
        entities = extract_pii(sample_text)
        assert len(entities) == 5

        pseudonymizer = Pseudonymizer(seed=101)
        safe = pseudonymizer.pseudonymize(sample_text, entities)

        assert "jordan.lee@example.org" not in safe
        assert "+91 98765 43210" not in safe
        assert "ABCDE1234F" not in safe
        assert "1234 5678 9012" not in safe
        assert "192.0.2.10" not in safe


# =====================================================================
# 3. Offline Encrypted Vault Tests (vault.py)
# =====================================================================

class TestEncryptedVault:
    """Tests for offline Fernet-encrypted mapping vault."""

    def test_vault_round_trip_in_memory(self) -> None:
        """Test encryption and decryption of mapping dictionary in memory."""
        key = generate_key()
        vault = EncryptedVault(key)

        original_mapping = {
            "EMAIL:jordan.lee@example.org": "surrogate.email@fake.org",
            "PHONE:9876543210": "+91 99999 88888",
            "PAN:ABCDE1234F": "XYZAB9876L",
        }

        encrypted_bytes = vault.encrypt_mapping(original_mapping)
        assert isinstance(encrypted_bytes, bytes)
        assert encrypted_bytes != json.dumps(original_mapping).encode("utf-8")

        decrypted_mapping = vault.decrypt_mapping(encrypted_bytes)
        assert decrypted_mapping == original_mapping

    def test_vault_file_export_and_import(self, tmp_path: Path) -> None:
        """Test exporting encrypted bytes to .enc file and loading with separate key."""
        key_path = tmp_path / "secret.key"
        vault_path = tmp_path / "mapping.enc"

        # Generate key and save separately
        key = generate_key()
        save_key(key, key_path)

        # Create vault and save encrypted file
        vault = EncryptedVault.from_key_file(key_path)
        sample_mapping = {
            "AADHAAR:123456789012": "987654321098",
            "IP_ADDRESS:192.0.2.10": "198.51.100.22",
        }
        vault.save_vault(sample_mapping, vault_path)

        # Verify .enc file is indeed encrypted ciphertext (not plain JSON)
        raw_on_disk = vault_path.read_bytes()
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw_on_disk.decode("utf-8"))

        # Load vault in a fresh instance using loaded key
        loaded_vault = EncryptedVault.from_key_file(key_path)
        restored_mapping = loaded_vault.load_vault(vault_path)
        assert restored_mapping == sample_mapping

    def test_save_key_overwrite_protection(self, tmp_path: Path) -> None:
        """Verify save_key refuses to overwrite an existing key file unless overwrite=True."""
        key_path = tmp_path / "protected.key"
        key_1 = generate_key()
        key_2 = generate_key()

        # Initial write should succeed
        save_key(key_1, key_path)
        assert key_path.read_bytes() == key_1

        # Second write with overwrite=False must raise KeyVaultError
        with pytest.raises(KeyVaultError) as exc_info:
            save_key(key_2, key_path, overwrite=False)
        assert "Refusing to overwrite" in str(exc_info.value)
        assert key_path.read_bytes() == key_1  # Preserved original

        # Write with overwrite=True succeeds
        save_key(key_2, key_path, overwrite=True)
        assert key_path.read_bytes() == key_2

    def test_save_vault_overwrite_protection(self, tmp_path: Path) -> None:
        """Verify save_vault refuses to overwrite an existing vault file unless overwrite=True."""
        vault, _ = EncryptedVault.generate()
        vault_path = tmp_path / "protected.enc"
        mapping_1 = {"EMAIL:jordan.lee@example.org": "surrogate_1@example.org"}
        mapping_2 = {"EMAIL:jordan.lee@example.org": "surrogate_2@example.org"}

        # Initial write should succeed
        vault.save_vault(mapping_1, vault_path)
        assert vault.load_vault(vault_path) == mapping_1

        # Second write with overwrite=False must raise VaultError
        with pytest.raises(VaultError) as exc_info:
            vault.save_vault(mapping_2, vault_path, overwrite=False)
        assert "Refusing to overwrite" in str(exc_info.value)
        assert vault.load_vault(vault_path) == mapping_1  # Preserved original

        # Write with overwrite=True succeeds
        vault.save_vault(mapping_2, vault_path, overwrite=True)
        assert vault.load_vault(vault_path) == mapping_2

    def test_save_vault_concurrent_race_condition_no_clobber(self, tmp_path: Path) -> None:
        """Verify that concurrent writes with overwrite=False cannot silently clobber existing vault files.

        Simulates race condition across multiple threads writing simultaneously to the same path.
        Atomic exclusive creation ('xb' mode with O_EXCL / CREATE_NEW) guarantees that exactly
        one caller succeeds, and all other callers raise VaultError.
        """
        vault, _ = EncryptedVault.generate()
        vault_path = tmp_path / "concurrent_test.enc"

        num_threads = 10
        mappings = [{f"KEY_{i}": f"surrogate_val_{i}"} for i in range(num_threads)]

        results: list[Exception | str] = []

        def worker(idx: int) -> None:
            try:
                vault.save_vault(mappings[idx], vault_path, overwrite=False)
                results.append("success")
            except VaultError as exc:
                results.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            concurrent.futures.wait(futures)

        successes = [r for r in results if r == "success"]
        failures = [r for r in results if isinstance(r, VaultError)]

        # Exactly ONE thread must win the exclusive file creation
        assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"
        assert len(failures) == num_threads - 1, f"Expected {num_threads - 1} failures, got {len(failures)}"

        # The winner's data must be preserved and decryptable without corruption
        saved_data = vault.load_vault(vault_path)
        assert saved_data in mappings

    def test_save_key_concurrent_race_condition_no_clobber(self, tmp_path: Path) -> None:
        """Verify that concurrent key writes with overwrite=False cannot silently clobber an existing key."""
        key_path = tmp_path / "concurrent_key.key"
        num_threads = 10
        keys = [generate_key() for _ in range(num_threads)]

        results: list[Exception | str] = []

        def worker(idx: int) -> None:
            try:
                save_key(keys[idx], key_path, overwrite=False)
                results.append("success")
            except KeyVaultError as exc:
                results.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            concurrent.futures.wait(futures)

        successes = [r for r in results if r == "success"]
        failures = [r for r in results if isinstance(r, KeyVaultError)]

        assert len(successes) == 1
        assert len(failures) == num_threads - 1

        saved_key = load_key(key_path)
        assert saved_key in keys

    def test_save_vault_preserves_existing_file_on_rejection(self, tmp_path: Path) -> None:
        """Verify that an existing vault file is never modified or corrupted when overwrite=False rejects a write."""
        vault, _ = EncryptedVault.generate()
        vault_path = tmp_path / "preserve_test.enc"
        original_mapping = {"INIT:entry": "original_payload"}
        vault.save_vault(original_mapping, vault_path)

        original_bytes = vault_path.read_bytes()

        with pytest.raises(VaultError) as exc_info:
            vault.save_vault({"NEW:entry": "attempted_overwrite"}, vault_path, overwrite=False)
        assert "Refusing to overwrite" in str(exc_info.value)

        # File contents must remain byte-for-byte identical
        assert vault_path.read_bytes() == original_bytes
        assert vault.load_vault(vault_path) == original_mapping

    def test_decryption_with_wrong_key_raises_error(self) -> None:
        """Test that attempting decryption with an incorrect key raises DecryptionError."""
        key_correct = generate_key()
        key_wrong = generate_key()

        vault_correct = EncryptedVault(key_correct)
        vault_wrong = EncryptedVault(key_wrong)

        mapping = {"EMAIL:jordan.lee@example.org": "anon@fake.org"}
        encrypted = vault_correct.encrypt_mapping(mapping)

        with pytest.raises(DecryptionError) as exc_info:
            vault_wrong.decrypt_mapping(encrypted)
        assert "Decryption failed" in str(exc_info.value)

    def test_corrupted_ciphertext_raises_error(self) -> None:
        """Test that tampered or corrupted ciphertext bytes raise DecryptionError."""
        vault, _ = EncryptedVault.generate()
        mapping = {"PAN:ABCDE1234F": "PQRMN5678X"}
        encrypted = vault.encrypt_mapping(mapping)

        # Corrupt the ciphertext by flipping bytes
        corrupted = bytearray(encrypted)
        corrupted[15] = (corrupted[15] + 1) % 256
        corrupted_bytes = bytes(corrupted)

        with pytest.raises(DecryptionError):
            vault.decrypt_mapping(corrupted_bytes)

    def test_non_json_payload_raises_corrupted_error(self) -> None:
        """Test that valid Fernet payload with invalid JSON raises CorruptedVaultError."""
        key = generate_key()
        fernet = Fernet(key)
        vault = EncryptedVault(key)

        # Encrypt non-JSON raw bytes
        non_json_bytes = fernet.encrypt(b"This is not JSON text")

        with pytest.raises(CorruptedVaultError):
            vault.decrypt_mapping(non_json_bytes)

    def test_missing_files_error_handling(self, tmp_path: Path) -> None:
        """Test appropriate exceptions when key or vault files do not exist."""
        non_existent_key = tmp_path / "missing.key"
        non_existent_vault = tmp_path / "missing.enc"

        with pytest.raises(KeyVaultError):
            load_key(non_existent_key)

        vault, _ = EncryptedVault.generate()
        with pytest.raises(VaultError):
            vault.load_vault(non_existent_vault)

    def test_vault_exceptions_do_not_leak_plaintext(self) -> None:
        """Verify that vault exception strings do not expose decrypted mappings or secrets."""
        key = generate_key()
        vault = EncryptedVault(key)
        secret_canary = "confidential-canary-data-xyz"

        # Cause a DecryptionError
        with pytest.raises(DecryptionError) as exc_info:
            vault.decrypt_mapping(b"corrupted-invalid-ciphertext")
        assert secret_canary not in str(exc_info.value)


# =====================================================================
# 4. Privacy, Security & Isolation Auditing Tests
# =====================================================================

class TestPrivacyAndIsolation:
    """Security audit tests verifying terminal privacy, offline isolation, and git hygiene."""

    def test_terminal_output_privacy_no_leakage(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Verify that normal execution of main.py never prints original PII or mapping keys to stdout or stderr.

        Uses multiple unique synthetic canaries across all 5 supported PII entity types and
        asserts zero leakage across both terminal streams.
        """
        canary_email = "audit.canary.email@example.org"
        canary_phone = "+91 98765 43210"
        canary_pan = "WXYZK9876Q"
        canary_aadhaar = "8765 4321 0987"
        canary_ip = "198.51.100.99"

        sensitive_text = (
            f"Confidential employee record: Jordan Lee. "
            f"Email: {canary_email}, Phone: {canary_phone}, "
            f"PAN: {canary_pan}, Aadhaar: {canary_aadhaar}, Workstation IP: {canary_ip}."
        )

        main.run_pipeline_demo(sensitive_text, save_results=False)
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err

        # Verify stderr is completely clean
        assert captured.err == "", f"Unexpected output in stderr: {captured.err}"

        # Raw synthetic canaries across all 5 PII types must NEVER appear in terminal output
        assert canary_email not in combined_output, "CRITICAL: Raw canary email leaked to terminal!"
        assert canary_phone not in combined_output, "CRITICAL: Raw canary phone leaked to terminal!"
        assert canary_pan not in combined_output, "CRITICAL: Raw canary PAN leaked to terminal!"
        assert canary_aadhaar not in combined_output, "CRITICAL: Raw canary Aadhaar leaked to terminal!"
        assert canary_ip not in combined_output, "CRITICAL: Raw canary IP leaked to terminal!"

        # Normalized mapping keys containing original raw PII must NEVER appear
        assert f"EMAIL:{canary_email}" not in combined_output, "CRITICAL: Original email mapping key leaked!"
        assert "PHONE:9876543210" not in combined_output, "CRITICAL: Original phone mapping key leaked!"
        assert f"PAN:{canary_pan}" not in combined_output, "CRITICAL: Original PAN mapping key leaked!"
        assert "AADHAAR:876543210987" not in combined_output, "CRITICAL: Original Aadhaar mapping key leaked!"
        assert f"IP_ADDRESS:{canary_ip}" not in combined_output, "CRITICAL: Original IP mapping key leaked!"

        # Legitimate privacy summary information SHOULD appear
        assert "PII Category" in captured.out
        assert "SAFE PSEUDONYMIZED OUTPUT TEXT" in captured.out
        assert "Zero-leakage policy" in captured.out

    def test_terminal_output_privacy_with_persisted_vault(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Verify that persisting vault files to disk does not leak canaries or raw keys to terminal or ciphertext."""
        monkeypatch.chdir(tmp_path)

        canary_email = "vault.canary.test@example.org"
        canary_phone = "+91 91234 56789"
        canary_pan = "PQRSK5678L"
        canary_aadhaar = "9988 7766 5544"
        canary_ip = "192.0.2.77"

        text = (
            f"Confidential record: email={canary_email}, phone={canary_phone}, "
            f"pan={canary_pan}, aadhaar={canary_aadhaar}, ip={canary_ip}."
        )
        main.run_pipeline_demo(text, save_results=True)

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err

        # Assert no canary leakage to stdout or stderr across all entity types
        assert canary_email not in combined_output
        assert canary_phone not in combined_output
        assert canary_pan not in combined_output
        assert canary_aadhaar not in combined_output
        assert canary_ip not in combined_output
        assert f"EMAIL:{canary_email}" not in combined_output
        assert "PHONE:9123456789" not in combined_output
        assert f"PAN:{canary_pan}" not in combined_output
        assert "AADHAAR:998877665544" not in combined_output
        assert f"IP_ADDRESS:{canary_ip}" not in combined_output

        # Verify output files exist
        vault_file = tmp_path / "results" / "demo_vault.enc"
        key_file = tmp_path / "results" / "demo_vault.key"
        assert vault_file.is_file()
        assert key_file.is_file()

        # Secret Fernet key bytes must NEVER be printed to terminal output
        secret_key_str = key_file.read_bytes().decode("ascii").strip()
        assert secret_key_str not in combined_output, "CRITICAL: Secret Fernet key printed to terminal!"

        # Ciphertext on disk must NOT contain plaintext canary strings
        ciphertext_bytes = vault_file.read_bytes()
        assert canary_email.encode("utf-8") not in ciphertext_bytes, "CRITICAL: Plaintext PII found in .enc file!"
        assert canary_pan.encode("utf-8") not in ciphertext_bytes
        assert b"998877665544" not in ciphertext_bytes

    def test_offline_isolation_no_network_calls(self) -> None:
        """Verify that regex extraction and pseudonymization make zero outbound network connections."""
        test_text = "Audit: jordan.lee@example.org, +91 98765 43210, ABCDE1234F."

        # Monkeypatch socket to intercept any socket creation or connect attempts
        def guard_socket(*args: object, **kwargs: object) -> None:
            raise RuntimeError("CRITICAL PRIVACY VIOLATION: Outbound network socket attempted!")

        with patch.object(socket, "socket", side_effect=guard_socket):
            entities = extract_pii(test_text)
            assert len(entities) >= 1
            p = Pseudonymizer()
            safe = p.pseudonymize(test_text, entities)
            assert isinstance(safe, str)

    def test_gitignore_excludes_sensitive_files(self) -> None:
        """Verify that .gitignore properly covers keys, vaults, and virtual environments."""
        gitignore_path = Path(".gitignore")
        assert gitignore_path.is_file(), ".gitignore must exist"
        content = gitignore_path.read_text(encoding="utf-8")

        required_patterns = ["*.key", "*.enc", ".venv", "__pycache__"]
        for pattern in required_patterns:
            assert pattern in content, f".gitignore missing essential security pattern: {pattern}"
