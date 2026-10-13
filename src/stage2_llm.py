"""Stage 2: Contextual Named Entity Recognition via Local Open-Source LLMs (Ollama).

Extracts ambiguous or unstructured entities (PERSON, LOCATION,
ORGANIZATION) and resolves overlaps against Stage 1 deterministic regex spans.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List
import requests

logger = logging.getLogger(__name__)

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "granite4.1:3b"

# Strict JSON Schema to prevent formatting breakdown
ENTITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "label": {
                        "type": "string",
                        "enum": ["PERSON", "LOCATION", "ORGANIZATION"],
                    },
                },
                "required": ["text", "label"],
            },
        }
    },
    "required": ["entities"],
}


def extract_llm_entities(
    text: str,
    model: str = DEFAULT_MODEL,
    endpoint: str = OLLAMA_ENDPOINT,
    timeout: int = 30,
) -> list[dict[str, Any]]:
    """Extract contextual PII entities from text using local Ollama model."""
    if not text.strip():
        return []

    prompt = f"""You are a sensitive PII extraction engine. Identify only:
- PERSON: Names of individuals.
- LOCATION: Cities, street addresses, residential or office places.
- ORGANIZATION: Companies, employers, institutions.

Do not extract calendar months, common nouns, or generic words.

Input text:
\"\"\"{text}\"\"\""""

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": ENTITY_SCHEMA,
        "options": {"temperature": 0.0},
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=timeout)
        response.raise_for_status()
        raw_output = response.json().get("response", "{}")
        parsed = json.loads(raw_output)
        raw_entities = parsed.get("entities", [])

        resolved: list[dict[str, Any]] = []
        for ent in raw_entities:
            val = ent.get("text", "").strip()
            label = ent.get("label", "PERSON")
            if not val:
                continue

            # Resolve character coordinate spans in the original text
            start = 0
            while True:
                idx = text.find(val, start)
                if idx == -1:
                    break
                resolved.append(
                    {
                        "text": val,
                        "label": label,
                        "start": idx,
                        "end": idx + len(val),
                        "source": "llm",
                    }
                )
                start = idx + len(val)

        return resolved
    except Exception as e:
        logger.warning(
            "Local LLM extraction failed or timed out: %s. Returning empty span set.",
            e,
        )
        return []


def resolve_hybrid_spans(
    regex_spans: list[dict[str, Any]], llm_spans: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merges regex and LLM spans with strict priority given to deterministic regex."""
    merged = list(regex_spans)

    for l_span in llm_spans:
        has_overlap = False
        for r_span in regex_spans:
            # Overlap: max(start1, start2) < min(end1, end2)
            if (
                max(l_span["start"], r_span["start"])
                < min(l_span["end"], r_span["end"])
            ):
                has_overlap = True
                break
        if not has_overlap:
            merged.append(l_span)

    # Sort reverse by start position for right-to-left pseudonymization
    return sorted(merged, key=lambda x: x["start"], reverse=True)