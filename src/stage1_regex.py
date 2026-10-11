"""Deterministic Regex-based PII Extraction Engine.

Module: stage1_regex
Part of the PIIGuard Offline PII Detection and Pseudonymization Pipeline.

CRITICAL DISCLAIMER:
    Matching an identifier pattern (such as an Aadhaar number, PAN card number,
    phone number, or IP address) only validates syntactic pattern conformance.
    It does NOT establish, verify, or guarantee that the identifier is genuine,
    legitimate, active, officially issued by UIDAI/ITD/authorities, or belongs
    to a real living person.

SECURITY & PRIVACY NOTICE:
    In compliance with strict offline privacy design, this module operates purely
    locally in-memory and never logs, prints, persists, or transmits raw PII to
    external systems or cloud services.
"""

from __future__ import annotations

import re
from typing import Any, Final, TypedDict

# Canonical Entity Labels
LABEL_EMAIL: Final[str] = "EMAIL"
LABEL_PHONE: Final[str] = "PHONE"
LABEL_AADHAAR: Final[str] = "AADHAAR"
LABEL_PAN: Final[str] = "PAN"
LABEL_IP_ADDRESS: Final[str] = "IP_ADDRESS"

ALL_LABELS: Final[tuple[str, ...]] = (
    LABEL_EMAIL,
    LABEL_PHONE,
    LABEL_AADHAAR,
    LABEL_PAN,
    LABEL_IP_ADDRESS,
)


class PIIEntity(TypedDict):
    """Exact return format dictionary for detected PII entities."""
    text: str
    label: str
    start: int
    end: int


# Precompiled regular expressions for maximum execution efficiency
# 1. Email address pattern (RFC 5322 compliant subset)
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# 2. Indian mobile numbers:
# Optional country code (+91, 91, or 0) followed by optional spaces/hyphens,
# then 10 digits starting with 6, 7, 8, or 9 (with optional 5-5 or 3-3-4 formatting).
PHONE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<!\w)(?:(?:\+91[\s-]?|91[\s-]|0[\s-]?)?[6-9](?:\d{4}[\s-]?\d{5}|\d{2}[\s-]?\d{3}[\s-]?\d{4}|\d{9}))(?!\d)"
)

# 3. Aadhaar-like 12-digit formats:
# Either 4-4-4 formatted with spaces/hyphens (e.g. 1234 5678 9012 or 1234-5678-9012)
# or 12 contiguous digits.
AADHAAR_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?:\d{4}[\s-]\d{4}[\s-]\d{4}|\d{12})(?!\d)"
)

# 4. PAN-like formats:
# 5 letters, 4 digits, 1 letter (case-insensitive for real-world user inputs).
PAN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b"
)

# 5. IPv4 candidate pattern (dots and 1-3 digits per octet):
# Uses lookbehinds and lookaheads to reject 5+ octets or extra digits
# while properly handling sentence-terminating punctuation.
IPV4_CANDIDATE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)"
)


def _validate_ipv4_octets(candidate: str) -> bool:
    """Validate whether all four octets of an IPv4 candidate string are between 0 and 255.

    Args:
        candidate: Candidate string matched by IPV4_CANDIDATE_PATTERN.

    Returns:
        True if all 4 octets are valid integers in [0, 255], False otherwise.
    """
    octets = candidate.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        try:
            val = int(octet)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False
    return True


def _spans_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    """Check whether two half-open spans [start_a, end_a) and [start_b, end_b) overlap."""
    return max(start_a, start_b) < min(end_a, end_b)


class RegexPIIExtractor:
    """Deterministic regex-based PII extractor for sensitive Indian entity types."""

    def __init__(self) -> None:
        # Precompiled patterns are defined at module level for reuse
        pass

    def extract(self, text: str) -> list[PIIEntity]:
        """Extract PII entities from input text using deterministic regex patterns.

        Args:
            text: Raw input string to analyze.

        Returns:
            List of detected entities sorted by start and end offsets:
            [{"text": str, "label": str, "start": int, "end": int}, ...]
        """
        if not text or not isinstance(text, str):
            return []

        candidates: list[PIIEntity] = []

        # 1. Extract Emails
        for match in EMAIL_PATTERN.finditer(text):
            candidates.append({
                "text": match.group(),
                "label": LABEL_EMAIL,
                "start": match.start(),
                "end": match.end(),
            })

        # 2. Extract PANs
        for match in PAN_PATTERN.finditer(text):
            candidates.append({
                "text": match.group(),
                "label": LABEL_PAN,
                "start": match.start(),
                "end": match.end(),
            })

        # 3. Extract Aadhaar-like numbers
        for match in AADHAAR_PATTERN.finditer(text):
            candidates.append({
                "text": match.group(),
                "label": LABEL_AADHAAR,
                "start": match.start(),
                "end": match.end(),
            })

        # 4. Extract Indian Mobile Numbers
        for match in PHONE_PATTERN.finditer(text):
            candidates.append({
                "text": match.group(),
                "label": LABEL_PHONE,
                "start": match.start(),
                "end": match.end(),
            })

        # 5. Extract IPv4 addresses with octet range validation (0-255)
        for match in IPV4_CANDIDATE_PATTERN.finditer(text):
            candidate_text = match.group()
            if _validate_ipv4_octets(candidate_text):
                candidates.append({
                    "text": candidate_text,
                    "label": LABEL_IP_ADDRESS,
                    "start": match.start(),
                    "end": match.end(),
                })

        # Deduplicate and resolve overlapping spans:
        # Sort candidates prioritising longer spans first, then earlier start offsets.
        # This ensures that e.g. a complete phone/Aadhaar number takes precedence over
        # any accidental partial sub-span.
        sorted_by_priority = sorted(
            candidates,
            key=lambda c: (-(c["end"] - c["start"]), c["start"]),
        )

        accepted_spans: list[PIIEntity] = []
        for candidate in sorted_by_priority:
            # Check if this candidate overlaps with any already accepted span
            has_overlap = any(
                _spans_overlap(candidate["start"], candidate["end"], acc["start"], acc["end"])
                for acc in accepted_spans
            )
            if not has_overlap:
                accepted_spans.append(candidate)

        # Requirements: Sort final results strictly by start and end offsets
        accepted_spans.sort(key=lambda item: (item["start"], item["end"]))

        return accepted_spans


def extract_pii(text: str) -> list[PIIEntity]:
    """Module-level helper to extract PII entities from text.

    Args:
        text: Raw input string to analyze.

    Returns:
        List of detected entities sorted by start and end offsets.
    """
    extractor = RegexPIIExtractor()
    return extractor.extract(text)
