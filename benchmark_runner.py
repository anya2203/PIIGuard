"""Automated Comparative Benchmark Suite (AAT CO4 Alignment).

Benchmarks 4 approaches across 4 real-world test cases on:
- Precision
- Recall (Coverage)
- Macro F1-Score
- Unmasked PII Leaks (FN)
- Execution Latency (seconds)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Set, Tuple
import spacy
from tabulate import tabulate

from src.stage1_regex import extract_pii as extract_regex_entities
from src.stage2_llm import extract_llm_entities, resolve_hybrid_spans

nlp = spacy.load("en_core_web_sm")

BENCHMARK_CASES = [
    {
        "id": "TC-1 (Financial / Statutory ID Spill)",
        "input": (
            "Kindly credit consulting fees to Rahul Sharma, PAN: ABCDE1234F, "
            "Aadhaar: 9876 5432 1098. Contact rahul.sharma@corp.in or +91 9845012345."
        ),
        "ground_truth": {
            "Rahul Sharma",
            "ABCDE1234F",
            "9876 5432 1098",
            "rahul.sharma@corp.in",
            "+91 9845012345",
        },
    },
    {
        "id": "TC-2 (Ambiguous Contextual Proper Nouns)",
        "input": (
            "Tell May that the executive meeting is scheduled in August at our "
            "Bengaluru office with Chase Bank representatives."
        ),
        "ground_truth": {"May", "Bengaluru", "Chase Bank"},
    },
    {
        "id": "TC-3 (Support Ticket / Infrastructure Leak)",
        "input": (
            "Critical telemetry error from IP 192.168.1.45. Customer Vikramaditya Verma "
            "(vverma@techsolutions.com, 7829100234) is awaiting resolution in Mysuru."
        ),
        "ground_truth": {
            "192.168.1.45",
            "Vikramaditya Verma",
            "vverma@techsolutions.com",
            "7829100234",
            "Mysuru",
        },
    },
    {
        "id": "TC-4 (Clean Negative Baseline)",
        "input": (
            "The transformer multi-head self-attention module computes dynamic "
            "contextual representations across tokenized sequences."
        ),
        "ground_truth": set(),
    },
]


def extract_spacy_baseline(text: str) -> list[dict[str, Any]]:
    doc = nlp(text)
    return [
        {"text": ent.text, "label": ent.label_}
        for ent in doc.ents
        if ent.label_ in {"PERSON", "GPE", "LOC", "ORG"}
    ]


def compute_metrics(
    pred: set[str], truth: set[str]
) -> tuple[float, float, float, int]:
    if not truth and not pred:
        return 1.0, 1.0, 1.0, 0
    if not truth and pred:
        return 0.0, 1.0, 0.0, 0
    if truth and not pred:
        return 0.0, 0.0, 0.0, len(truth)

    tp = len(pred.intersection(truth))
    fp = len(pred - truth)
    fn = len(truth - pred)

    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
    return p, r, f1, fn


def run_benchmark():
    approaches = [
        "1. Pure Regex",
        "2. Statistical spaCy NER",
        "3. Zero-Shot Local LLM",
        "4. PIIGuard (Hybrid Pipeline)",
    ]
    summary_rows = []

    print("\nExecuting 4-way comparative evaluation across benchmark test cases...")

    for approach in approaches:
        precisions: list[float] = []
        recalls: list[float] = []
        f1s: list[float] = []
        latencies: list[float] = []
        total_leaks = 0

        for tc in BENCHMARK_CASES:
            text = tc["input"]
            truth = tc["ground_truth"]

            t0 = time.perf_counter()
            if approach == "1. Pure Regex":
                ents = extract_regex_entities(text)
            elif approach == "2. Statistical spaCy NER":
                ents = extract_spacy_baseline(text)
            elif approach == "3. Zero-Shot Local LLM":
                ents = extract_llm_entities(text)
            elif approach == "4. PIIGuard (Hybrid Pipeline)":
                r_ents = extract_regex_entities(text)
                l_ents = extract_llm_entities(text)
                ents = resolve_hybrid_spans(r_ents, l_ents)
            lat = time.perf_counter() - t0

            extracted = {e["text"] for e in ents}
            p, r, f1, leaks = compute_metrics(extracted, truth)

            precisions.append(p)
            recalls.append(r)
            f1s.append(f1)
            latencies.append(lat)
            total_leaks += leaks

        n = len(BENCHMARK_CASES)
        summary_rows.append(
            [
                approach,
                f"{sum(precisions) / n:.4f}",
                f"{sum(recalls) / n:.4f}",
                f"{sum(f1s) / n:.4f}",
                total_leaks,
                f"{sum(latencies) / n:.4f} s",
            ]
        )

    headers = [
        "Approach (CO4)",
        "Precision",
        "Recall",
        "Macro F1",
        "PII Leaks",
        "Avg Latency",
    ]
    print("\n" + tabulate(summary_rows, headers=headers, tablefmt="github") + "\n")


if __name__ == "__main__":
    run_benchmark()