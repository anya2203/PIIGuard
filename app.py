"""PIIGuard Visual Demonstration Dashboard (Streamlit).

An interactive UI demonstrating the end-to-end hybrid PII pipeline,
syllabus concept mappings (Units 1, 2, 3, 5), and offline encrypted storage.
"""

from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from src.stage1_regex import extract_pii
from src.stage2_llm import extract_llm_entities, resolve_hybrid_spans
from src.stage3_pseudonym import Pseudonymizer
from src.vault import EncryptedVault, generate_key, save_key

# Page Configuration
st.set_page_config(
    page_title="PIIGuard | Hybrid PII & Privacy Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for Badges and Spans
st.markdown(
    """
<style>
    .concept-badge {
        display: inline-block;
        padding: 3px 9px;
        margin: 2px 4px;
        border-radius: 12px;
        font-size: 0.80rem;
        font-weight: 600;
        background-color: #21262d;
        color: #58a6ff;
        border: 1px solid #30363d;
    }
    .entity-regex {
        background-color: rgba(255, 165, 0, 0.25);
        border-bottom: 2px solid orange;
        padding: 2px 4px;
        border-radius: 4px;
    }
    .entity-llm {
        background-color: rgba(0, 150, 255, 0.25);
        border-bottom: 2px solid #0096ff;
        padding: 2px 4px;
        border-radius: 4px;
    }
    .highlight-card {
        padding: 1.2rem;
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        font-family: monospace;
        white-space: pre-wrap;
        word-break: break-word;
        font-size: 0.95rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Sidebar Controls
st.sidebar.title("🛡️ PIIGuard Controls")
st.sidebar.markdown("**Course:** 24AM7PCLLM (NLP for LLMs)")
st.sidebar.markdown("**Alignment:** SDG 9.5 Infrastructure & Responsible AI")

model_choice = st.sidebar.selectbox(
    "Local LLM Model (Stage 2)",
    options=["granite4.1:3b", "llama3.2:3b", "qwen2.5:7b"],
    index=0,
)

run_pseudonym = st.sidebar.checkbox("Enable Indian Pseudonymization (Stage 3)", value=True)
encrypt_vault = st.sidebar.checkbox("Persist Encrypted Mapping Vault (Stage 4)", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("Syllabus Concept Legend")
st.sidebar.markdown(
    """
- <span class="concept-badge">Unit 1: Regex & Patterns</span>
- <span class="concept-badge">Unit 2: Lexical Semantics</span>
- <span class="concept-badge">Unit 3: Prompt & LLM Inference</span>
- <span class="concept-badge">Unit 5: Responsible AI & Security</span>
""",
    unsafe_allow_html=True,
)

# Main Title & Overview
st.title("PIIGuard: Offline Hybrid PII Extraction & Pseudonymization")
st.caption(
    "Demonstrating deterministic pattern matching, contextual local LLM extraction, and reversible offline encryption."
)

default_text = (
    "SYSTEM AUDIT REPORT (SYNTHETIC SAMPLE):\n"
    "User Identity: Rahul Sharma (Northstar Research Labs)\n"
    "Primary Contact Email: rahul.sharma@example.org\n"
    "Registered Contact Mobile: +91 98450 12345\n"
    "Tax Identification (PAN): ABCDE1234F\n"
    "Internal Cluster Gateway IPv4: 192.0.2.45\n"
    "Operational Note: Direct escalation regarding Bengaluru office to rahul.sharma@example.org."
)

input_text = st.text_area("Input Document Text (Raw / Unsanitized)", value=default_text, height=180)

if st.button("🚀 Run Full PIIGuard Pipeline", type="primary"):
    with st.spinner("Executing Stage 1 (Regex) & Stage 2 (Local LLM Inference)..."):
        # 1. Deterministic Extraction
        regex_spans = extract_pii(input_text)

        # 2. Contextual Local LLM Extraction
        llm_spans = extract_llm_entities(input_text, model=model_choice)

        # 3. Hybrid Conflict Resolution
        final_spans = resolve_hybrid_spans(regex_spans, llm_spans)

    st.markdown("---")

    # ==========================================
    # CONCEPT & PIPELINE VISUALIZATION TABS
    # ==========================================
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "1️⃣ Stage 1 & 2: Entity Detections",
    "2️⃣ Hybrid Span Resolution",
    "3️⃣ Stage 3: Pseudonymized Text",
    "4️⃣ Stage 4: Encrypted Offline Vault",
    "5️⃣ 📊 4-Way Benchmark Evaluation (CO4)"
])


    with tab1:
        st.subheader("Stage 1 & 2 Entity Breakdown")
        st.markdown(
            """
        - <span class="concept-badge">Unit 1: Regular Expressions & Text Normalization</span> Captures syntactic IDs (Email, Phone, PAN, IP).
        - <span class="concept-badge">Unit 3: Instruction Inference</span> Disambiguates contextual names, locations, and organizations.
        """,
            unsafe_allow_html=True,
        )

        col_r, col_l = st.columns(2)
        with col_r:
            st.markdown(f"#### Deterministic Regex ({len(regex_spans)} found)")
            if regex_spans:
                st.dataframe(
                    [{"Text": s["text"], "Label": s["label"], "Span": f"[{s['start']}:{s['end']}]"} for s in regex_spans],
                    use_container_width=True,
                )
            else:
                st.info("No deterministic regex patterns matched.")

        with col_l:
            st.markdown(f"#### Local LLM ({len(llm_spans)} found via `{model_choice}`)")
            if llm_spans:
                st.dataframe(
                    [{"Text": s["text"], "Label": s["label"], "Span": f"[{s['start']}:{s['end']}]"} for s in llm_spans],
                    use_container_width=True,
                )
            else:
                st.info("No contextual entities extracted by the local model.")

    with tab2:
        st.subheader("Hybrid Conflict Resolution & Span Merging")
        st.markdown(
            """
        - <span class="concept-badge">Unit 5: Model Optimization & Lifecycle</span> 
        Resolves boundary overlap by enforcing strict priority to verified deterministic syntax over probabilistic LLM boundaries.
        """,
            unsafe_allow_html=True,
        )

        # Build Highlighted HTML
        sorted_for_highlight = sorted(final_spans, key=lambda x: x["start"])
        highlighted_html = ""
        last_idx = 0

        for sp in sorted_for_highlight:
            # Append non-entity text
            highlighted_html += input_text[last_idx : sp["start"]]
            # Append styled entity
            css_class = "entity-regex" if sp.get("source") != "llm" else "entity-llm"
            highlighted_html += (
                f'<span class="{css_class}" title="{sp["label"]} ({sp.get("source", "regex")})">'
                f'{sp["text"]} <sup>[{sp["label"]}]</sup></span>'
            )
            last_idx = sp["end"]
        highlighted_html += input_text[last_idx:]

        st.markdown("##### Annotated Document View (Orange = Regex | Blue = LLM):")
        st.markdown(f'<div class="highlight-card">{highlighted_html}</div>', unsafe_allow_html=True)

    with tab3:
        st.subheader("Stage 3: Consistent Right-to-Left Pseudonymization")
        st.markdown(
            """
        - <span class="concept-badge">Unit 2: Lexical Semantics & Word Representation</span> 
        - <span class="concept-badge">Unit 5: Responsible AI & Demographic Neutrality</span>
        Substitutes real identifiers with realistic Indian locale surrogates (`Faker en_IN`), preserving syntactic coherence without index drift.
        """,
            unsafe_allow_html=True,
        )

        if run_pseudonym:
            pseudonymizer = Pseudonymizer(seed=42)
            safe_text = pseudonymizer.pseudonymize(input_text, final_spans)

            col_before, col_after = st.columns(2)
            with col_before:
                st.markdown("##### Raw Text (Before Sanitization)")
                st.text_area("", value=input_text, height=220, disabled=True, key="raw_view")
            with col_after:
                st.markdown("##### Sanitized Text (After Pseudonymization)")
                st.text_area("", value=safe_text, height=220, disabled=True, key="safe_view")

            st.markdown("##### Persistent Entity Mapping Key Table (In-Memory)")
            st.json(pseudonymizer.mapping)
        else:
            st.warning("Pseudonymization disabled in sidebar.")

    with tab4:
        st.subheader("Stage 4: Encrypted Offline Vault")
        st.markdown(
            """
        - <span class="concept-badge">Unit 5: Air-Gapped Security & Zero Data Exfiltration</span>
        Secures the reverse mapping table using authenticated symmetric encryption (`Fernet AES-128-CBC + HMAC-SHA256`).
        """,
            unsafe_allow_html=True,
        )

        if encrypt_vault and run_pseudonym and pseudonymizer.mapping:
            results_dir = Path("results")
            results_dir.mkdir(parents=True, exist_ok=True)
            key_file = results_dir / "demo_vault.key"
            vault_file = results_dir / "demo_vault.enc"

            raw_key = generate_key()
            save_key(raw_key, key_file, overwrite=True)
            vault = EncryptedVault(raw_key)
            vault.save_vault(pseudonymizer.mapping, vault_file, overwrite=True)

            col_sec1, col_sec2 = st.columns(2)
            with col_sec1:
                st.success("✅ Vault Persisted & Verified")
                st.markdown(f"- **Key File:** `{key_file}` (Isolated on disk)")
                st.markdown(f"- **Encrypted Vault:** `{vault_file}`")
                st.markdown(f"- **Ciphertext Size:** `{vault_file.stat().st_size}` bytes")

            with col_sec2:
                st.markdown("##### Raw Encrypted Ciphertext Payload (`.enc` preview)")
                enc_bytes = vault_file.read_bytes()[:160]
                st.code(enc_bytes.hex(), language="text")

            # Round trip verification test
            loaded_vault = EncryptedVault.from_key_file(key_file)
            restored = loaded_vault.load_vault(vault_file)
            st.info(f"🔒 Decryption Round-Trip Verified: {len(restored)} keys restored successfully.")
        else:
            st.info("Vault encryption not triggered (no mappings or toggle disabled).")
    with tab5:
        st.subheader("4-Way Comparative Model Evaluation")
        st.markdown("""
        - **Benchmark Approaches:** Pure Regex vs. spaCy Statistical NER vs. Zero-Shot Local LLM (`granite4.1:3b`) vs. PIIGuard Hybrid Pipeline.
        - **Evaluation Metrics:** Precision, Recall (Coverage), Macro F1, Unmasked PII Leaks, and Execution Latency.
        """)
        if st.button("Run Comparative Evaluation Suite"):
            with st.spinner("Benchmarking all 4 architectures across ground-truth test cases..."):
                from benchmark_runner import BENCHMARK_CASES, extract_spacy_baseline, compute_metrics
                import time

                approaches = ["1. Pure Regex", "2. Statistical spaCy NER", "3. Zero-Shot Local LLM", "4. PIIGuard (Hybrid)"]
                rows = []
                for approach in approaches:
                    precisions, recalls, f1s, latencies = [], [], [], []
                    total_leaks = 0
                    for tc in BENCHMARK_CASES:
                        text, truth = tc["input"], tc["ground_truth"]
                        t0 = time.perf_counter()
                        if approach == "1. Pure Regex":
                            ents = extract_pii(text)
                        elif approach == "2. Statistical spaCy NER":
                            ents = extract_spacy_baseline(text)
                        elif approach == "3. Zero-Shot Local LLM":
                            ents = extract_llm_entities(text, model=model_choice)
                        else:
                            r_ents = extract_pii(text)
                            l_ents = extract_llm_entities(text, model=model_choice)
                            ents = resolve_hybrid_spans(r_ents, l_ents)
                        lat = time.perf_counter() - t0

                        extracted = {e["text"] for e in ents}
                        p, r, f1, leaks = compute_metrics(extracted, truth)
                        precisions.append(p); recalls.append(r); f1s.append(f1); latencies.append(lat)
                        total_leaks += leaks

                    n = len(BENCHMARK_CASES)
                    rows.append({
                        "Approach": approach,
                        "Precision": round(sum(precisions) / n, 4),
                        "Recall": round(sum(recalls) / n, 4),
                        "Macro F1": round(sum(f1s) / n, 4),
                        "PII Leaks (FN)": total_leaks,
                        "Avg Latency": f"{sum(latencies) / n:.3f} s"
                    })
                st.dataframe(rows, use_container_width=True)
                st.success("Comparative evaluation completed successfully.")