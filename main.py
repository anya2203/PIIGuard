"""PIIGuard — Offline PII Detection and Pseudonymization Pipeline.

Demonstrates:
  1. Deterministic Regex Extraction (Stage 1)
  2. Span Management & Pseudonymization (Stage 3)
  3. Offline Encrypted Mapping Vault (Stage 4)

CRITICAL PRIVACY RULE:
  All demonstration data is purely SYNTHETIC. Raw input text, original PII values,
  mapping keys, and secret encryption keys are NEVER logged or printed to the terminal.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from src.stage1_regex import extract_pii
from src.stage3_pseudonym import Pseudonymizer
from src.vault import EncryptedVault, generate_key, save_key

# Approved fictional demonstration corpus
DEFAULT_SYNTHETIC_TEXT = (
    "SYSTEM AUDIT RECORD (SYNTHETIC SAMPLE):\n"
    "User Identity: Jordan Lee (Northstar Research Labs)\n"
    "Primary Contact Email: jordan.lee@example.org\n"
    "Alternate Support Email: support@example.org\n"
    "Registered Contact Mobile: +91 98765 43210\n"
    "Secondary Phone Format: 98765-43210\n"
    "Identity Document (Aadhaar format): 1234 5678 9012\n"
    "Tax Identification (PAN format): ABCDE1234F\n"
    "Internal Cluster IPv4: 192.0.2.10\n"
    "Malformed Network Octet (rejected): 999.300.1.1\n\n"
    "Operational Note: Direct correspondence regarding security logs to jordan.lee@example.org."
)


def run_pipeline_demo(input_text: str, save_results: bool = True) -> str:
    """Execute the full end-to-end pipeline demonstration in a privacy-preserving manner.

    This function enforces zero terminal leakage:
    - Raw input text containing potential PII is NEVER printed.
    - Original mapping keys containing plaintext identifiers are NEVER printed.
    - Only aggregate metadata, category counts, and safe synthetic output are displayed.

    Args:
        input_text: Input text containing synthetic or raw text.
        save_results: Whether to save demo vault files to the results/ directory.

    Returns:
        The safe pseudonymized string.
    """
    separator = "=" * 74
    subsep = "-" * 74

    print(separator)
    print("  PIIGuard: Offline PII Detection & Pseudonymization Pipeline")
    print("  Deterministic Pattern Extraction, Pseudonymization & Encrypted Vault")
    print(separator)
    print()

    # -------------------------------------------------------------
    # 1. Input Ingestion (Privacy-Safe: Zero Echo)
    # -------------------------------------------------------------
    print("[1] INPUT STATUS")
    print(subsep)
    print(f"Status: Ingested {len(input_text)} characters for offline processing.")
    print("Privacy: Raw input text is withheld from terminal output to prevent leakage.")
    print(subsep)
    print()

    # -------------------------------------------------------------
    # 2. Stage 1: Deterministic Regex Extraction (Summary Only)
    # -------------------------------------------------------------
    print("[2] STAGE 1: DETERMINISTIC REGEX EXTRACTION (METRICS)")
    print(subsep)
    entities = extract_pii(input_text)
    total_found = len(entities)
    label_counts = Counter(e["label"] for e in entities)

    print(f"Total candidate spans matched and resolved: {total_found}")
    print()
    print(f"{'PII Category':<20} | {'Detections Count':<18} | Validation Mode")
    print("-" * 20 + "-+-" + "-" * 18 + "-+-" + "-" * 20)

    for label, count in sorted(label_counts.items()):
        print(f"{label:<20} | {count:<18} | Syntactic Pattern")

    print(subsep)
    print("NOTE: Syntactic matching verifies format, not authenticity or issuance.")
    print("NOTE: Original matched substrings and span offsets are kept in-memory only.")
    print()

    # -------------------------------------------------------------
    # 3. Stage 3: Pseudonymization & Span Management
    # -------------------------------------------------------------
    print("[3] STAGE 3: PSEUDONYMIZATION & SPAN MANAGEMENT")
    print(subsep)
    pseudonymizer = Pseudonymizer(seed=42)
    safe_output = pseudonymizer.pseudonymize(input_text, entities)

    print("SAFE PSEUDONYMIZED OUTPUT TEXT (Surrogate Values Only):")
    print(subsep)
    print(safe_output.strip())
    print(subsep)
    print()

    print("PROCESSING SUMMARY:")
    print(f"  - Total substitutions performed : {total_found}")
    print(f"  - Unique entity mapping keys    : {len(pseudonymizer.mapping)}")
    print("  - Consistency                   : Repeated mentions mapped to identical surrogates.")
    print("  - Offset integrity              : Right-to-left replacement preserved character indices.")
    print("  - Zero-leakage policy           : Original mapping keys are withheld from stdout.")
    print()

    # -------------------------------------------------------------
    # 4. Stage 4: Secure Encrypted Mapping Vault
    # -------------------------------------------------------------
    print("[4] STAGE 4: OFFLINE ENCRYPTED MAPPING VAULT")
    print(subsep)

    if save_results:
        results_dir = Path("results")
        results_dir.mkdir(parents=True, exist_ok=True)
        key_file = results_dir / "demo_vault.key"
        vault_file = results_dir / "demo_vault.enc"

        # Generate fresh Fernet key and save separately with overwrite=True for demo runs
        raw_key = generate_key()
        save_key(raw_key, key_file, overwrite=True)
        print("[OK] Generated 256-bit Fernet encryption key.")
        print(f"     Key file location    : {key_file} (Ignored by Git)")

        # Create vault and export encrypted mapping
        vault = EncryptedVault(raw_key)
        vault.save_vault(pseudonymizer.mapping, vault_file, overwrite=True)
        print(f"[OK] Exported encrypted vault: {vault_file} (Ignored by Git)")
        print(f"     Ciphertext payload   : {vault_file.stat().st_size} bytes")

        # Demonstrate offline decryption round trip without exposing decrypted mapping
        loaded_vault = EncryptedVault.from_key_file(key_file)
        restored_mapping = loaded_vault.load_vault(vault_file)

        assert restored_mapping == pseudonymizer.mapping, "Integrity verification failed!"
        print(f"[OK] Offline round-trip verified: {len(restored_mapping)} entries restored successfully.")
        print()
        print("SECURITY SUMMARY:")
        print("  - Authenticated encryption : AES-128-CBC with HMAC-SHA256 (Fernet).")
        print("  - Key isolation            : Secret key stored separately from encrypted vault.")
        print("  - Irreversible recovery    : Losing the key prevents recovering original mappings.")
        print("  - Version control hygiene  : Neither keys nor vaults should be committed to Git.")

    print(separator)
    print("  PIIGuard Pipeline Execution Completed Successfully!")
    print(separator)

    return safe_output


def main() -> None:
    """Entry point for CLI execution."""
    parser = argparse.ArgumentParser(
        description="PIIGuard — Offline PII Detection & Pseudonymization Pipeline",
        epilog=(
            "Security note: Passing sensitive data via the --text CLI argument may expose "
            "it to local process tables and shell history. Use --file or stdin for sensitive input."
        ),
    )
    parser.add_argument(
        "--text",
        type=str,
        default=None,
        help="Input text string (Warning: may be logged in shell history).",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Path to input text file to pseudonymize offline.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Run in-memory without persisting demo vault files to results/.",
    )

    args = parser.parse_args()

    if args.file:
        if not args.file.is_file():
            print(f"Error: File not found: '{args.file}'", file=sys.stderr)
            sys.exit(1)
        input_text = args.file.read_text(encoding="utf-8")
    elif args.text:
        input_text = args.text
    else:
        # Default fictional sample
        input_text = DEFAULT_SYNTHETIC_TEXT

    run_pipeline_demo(input_text, save_results=not args.no_save)


if __name__ == "__main__":
    main()
