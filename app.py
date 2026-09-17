"""
ZeroSight Web Application.
Privacy-Preserving Homomorphic Eligibility Engine built with Streamlit.
"""

import io
import os
import json
import time
from typing import Dict, Any

import streamlit as st
import pandas as pd

from bee.config import (
    DEFAULT_KEY_SIZE,
    FALLBACK_KEY_SIZE,
    MAX_FILE_SIZE_BYTES,
)
from bee.policy import load_policy, compute_policy_hash
from bee.parser import parse_file
from bee.extractor import extract_and_normalize_fields
from bee.validator import validate_extracted_data
from bee.crypto_utils import (
    generate_keypair,
    encrypt_fields,
    decrypt_score,
    compute_public_key_fingerprint,
)
from bee.evaluator import evaluate_encrypted, evaluate_plaintext
from bee.comparison import compare_results
from bee.audit import generate_verification_receipt, format_receipt_as_markdown
from bee.serializer import serialize_public_key, serialize_encrypted_dict

# Configure page metadata
st.set_page_config(
    page_title="ZeroSight | Homomorphic Eligibility Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-Aesthetic Styling
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Main Container */
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
    }
    
    /* Animations */
    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(12px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .hero-card {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 24px 32px;
        margin-bottom: 24px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }
    
    .hero-card:hover {
        transform: translateY(-2px) scale(1.005);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
    }

    .trust-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #F1F5F9;
        border: 1px solid #E2E8F0;
        color: #475569;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 500;
        margin-right: 8px;
    }

    .trust-badge-green {
        background: #F0FDF4;
        border: 1px solid #BBF7D0;
        color: #166534;
    }

    .trust-badge-purple {
        background: #FAF5FF;
        border: 1px solid #E9D5FF;
        color: #6B21A8;
    }

    .result-banner-eligible {
        background-color: #F0FDF4;
        border: 1px solid #BBF7D0;
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    .result-banner-ineligible {
        background-color: #FEF2F2;
        border: 1px solid #FECACA;
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    .stat-box {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
        animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }
    
    .stat-box:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.04);
    }

    .stat-label {
        font-size: 0.75rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #64748B;
        margin-bottom: 4px;
    }

    .stat-val {
        font-size: 1.5rem;
        font-weight: 600;
        color: #0F172A;
    }

    /* Buttons */
    .stButton>button {
        border-radius: 8px;
        font-weight: 500;
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }
    
    .stButton>button:hover {
        transform: scale(1.02);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
    
    .stButton>button:active {
        transform: scale(0.97);
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# Initialize Session State
def init_session():
    if "data" not in st.session_state:
        st.session_state.data = None
    if "raw_filename" not in st.session_state:
        st.session_state.raw_filename = None
    if "keys" not in st.session_state:
        st.session_state.keys = None  # (pub, priv)
    if "encrypted_fields" not in st.session_state:
        st.session_state.encrypted_fields = None
    if "evaluation_result" not in st.session_state:
        st.session_state.evaluation_result = None
    if "selected_fields" not in st.session_state:
        st.session_state.selected_fields = []
    if "receipt" not in st.session_state:
        st.session_state.receipt = None


init_session()


# Sidebar Configuration
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.svg",
        width=48,
    )
    st.title("ZeroSight Core")
    st.caption("Privacy-Preserving Computation")

    st.markdown("---")
    st.subheader("🛡️ Cryptographic Settings")

    key_choice = st.radio(
        "Paillier Modulus Size",
        options=[2048, 1024],
        index=0,
        help="2048-bit meets NIST SP 800-57 security guidelines. 1024-bit is for low-latency testing.",
    )

    if key_choice == 1024:
        st.warning("⚠️ 1024-bit key selected: intended for demonstration speed only.")

    privacy_mode = st.toggle(
        "Demonstration Parity Mode",
        value=True,
        help="When enabled, runs local unencrypted calculation to visually verify homomorphic correctness.",
    )

    st.markdown("---")
    st.subheader("📜 Certified Policy")
    try:
        policy = load_policy("community_welfare_v1")
        st.markdown(f"**{policy.get('title')}** (v{policy.get('version')})")
        st.markdown(f"*Threshold:* `{policy['threshold']}` points")
        st.markdown(f"*Base Score:* `{policy['base_score']}`")

        with st.expander("Formula Weights"):
            for k, w in policy["weights"].items():
                st.code(f"{k}: {w:+d} pts")

        st.caption(f"Canonical SHA-256 Digest:")
        st.code(f"{policy['_hash'][:18]}...", language="text")
    except Exception as e:
        st.error(f"Failed to load policy: {e}")
        policy = {}

    st.markdown("---")
    if st.button("🔄 Reset Session State", use_container_width=True):
        st.session_state.clear()
        st.rerun()


# Top Banner / Trust Header
st.markdown(
    """
    <div class="hero-card">
        <h1 style="margin: 0 0 8px 0; font-weight: 600; font-size: 1.75rem; color: #0F172A;">
            ZeroSight <span style="font-weight: 400; color: #64748B;">| Blind Eligibility Engine</span>
        </h1>
        <p style="margin: 0 0 16px 0; color: #475569; font-size: 1rem;">
            Verify welfare subsidies, scholarships, and grants without revealing private records to the evaluator.
        </p>
        <div>
            <span class="trust-badge">Paillier PHE</span>
            <span class="trust-badge trust-badge-green">Zero Plaintext Leakage</span>
            <span class="trust-badge trust-badge-purple">SHA-256 Verified</span>
            <span class="trust-badge">In-Memory Processing</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Trust Boundary Diagram
with st.expander("🔍 Architecture & Privacy Boundary Model", expanded=False):
    col_a, col_b, col_c = st.columns([1.2, 0.4, 1.2])
    with col_a:
        st.markdown(
            """
            **Applicant Domain (Your Local Browser / Device)**
            - Local document upload & memory parsing
            - Sensitive values: Income, Children, Disability, Senior
            - **Private Key ($p, q$) retained strictly here**
            - Encryption performed locally before any data leaves
            """
        )
    with col_b:
        st.markdown(
            """
            <div style="text-align: center; padding-top: 30px;">
                <span style="font-size: 1.8rem; color: #38BDF8;">➔</span><br>
                <code style="font-size: 0.7rem; color: #34D399;">CIPHERTEXTS ONLY</code>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_c:
        st.markdown(
            """
            **Evaluator Domain (Subsidy Authority)**
            - Receives: Encrypted ciphertexts ($c_i$) + Certified Public Key ($n$)
            - Computes: $\\text{Enc}(S) = \\text{Enc}(B) \\oplus \\sum w_i \\odot \\text{Enc}(x_i)$
            - **Zero access to plaintext data or private keys**
            - Returns encrypted result $\\text{Enc}(S)$
            """
        )

st.write("")

# -------------------------------------------------------------
# STEP 1: DOCUMENT INGESTION
# -------------------------------------------------------------
st.markdown("### Step 1: Ingest Eligibility Declaration")
tab_upload, tab_samples = st.tabs(["📁 Upload Document (JSON / TXT / PDF)", "⚡ Quick Demo Samples"])

with tab_upload:
    uploaded_file = st.file_uploader(
        "Choose an applicant declaration file",
        type=["json", "txt", "pdf"],
        help="Files are processed in-memory and never written to permanent disk storage.",
    )

    if uploaded_file is not None:
        if uploaded_file.size > MAX_FILE_SIZE_BYTES:
            st.error(f"File size exceeds maximum threshold of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.")
        else:
            ext = uploaded_file.name.split(".")[-1]
            content = uploaded_file.read()
            try:
                raw_parsed = parse_file(content, ext)
                normalized = extract_and_normalize_fields(raw_parsed)
                st.session_state.data = normalized
                st.session_state.raw_filename = uploaded_file.name
                st.success(f"Parsed `{uploaded_file.name}` successfully. Found {len(normalized)} normalized fields.")
            except Exception as e:
                st.error(f"Parsing error: {e}")

with tab_samples:
    st.write("Or load one of the certified test cases to evaluate instantly:")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        if st.button("📄 Sample Eligible (JSON)", use_container_width=True):
            with open("sample_files/sample.json", "r") as f:
                st.session_state.data = extract_and_normalize_fields(json.load(f))
            st.session_state.raw_filename = "sample.json"
            st.rerun()
    with c2:
        if st.button("📄 Not Eligible (JSON)", use_container_width=True):
            with open("sample_files/sample_not_eligible.json", "r") as f:
                st.session_state.data = extract_and_normalize_fields(json.load(f))
            st.session_state.raw_filename = "sample_not_eligible.json"
            st.rerun()
    with c3:
        if st.button("📄 Boundary 30k (JSON)", use_container_width=True):
            with open("sample_files/sample_boundary.json", "r") as f:
                st.session_state.data = extract_and_normalize_fields(json.load(f))
            st.session_state.raw_filename = "sample_boundary.json"
            st.rerun()
    with c4:
        if st.button("📄 Sample Doc (PDF)", use_container_width=True):
            with open("sample_files/sample.pdf", "rb") as f:
                raw = parse_file(f.read(), "pdf")
                st.session_state.data = extract_and_normalize_fields(raw)
            st.session_state.raw_filename = "sample.pdf"
            st.rerun()

st.write("")

# -------------------------------------------------------------
# STEP 2: FIELD SELECTION & VALIDATION
# -------------------------------------------------------------
if st.session_state.data is not None:
    st.markdown("### Step 2: Review Extracted Fields & Confirm Selection")

    data = st.session_state.data
    required_fields = set(policy.get("required_fields", []))
    all_fields = sorted(list(data.keys()))

    col_preview, col_editor = st.columns([1.5, 1])

    with col_preview:
        st.write("**Extracted Applicant Attributes:**")
        selected_fields_dict = {}

        # Form check list
        cols = st.columns(len(all_fields) if all_fields else 1)
        for i, fld in enumerate(all_fields):
            is_req = fld in required_fields
            val = data[fld]
            req_label = "*(Required)*" if is_req else "*(Optional)*"

            is_selected = st.checkbox(
                f"**{fld.replace('_', ' ').title()}** {req_label}",
                value=True,
                disabled=is_req,  # Required fields must be included
                key=f"chk_{fld}",
            )
            if is_selected or is_req:
                selected_fields_dict[fld] = val

    with col_editor:
        st.write("**Manual Calibration / Value Override:**")
        st.caption("Adjust values if original document was scanned imperfectly:")
        calibrated_data = {}
        for fld, val in selected_fields_dict.items():
            if fld in ("disability", "senior", "unemployment_status"):
                calibrated_data[fld] = st.selectbox(
                    f"{fld.title()} (Binary)",
                    options=[0, 1],
                    index=0 if val == 0 else 1,
                    key=f"val_{fld}",
                )
            else:
                calibrated_data[fld] = st.number_input(
                    f"{fld.title()}",
                    value=int(val),
                    min_value=0,
                    step=1000 if fld in ("income", "rent") else 1,
                    key=f"val_{fld}",
                )

    st.session_state.data = calibrated_data
    st.session_state.selected_fields = list(calibrated_data.keys())

    # Validation
    val_errors = validate_extracted_data(calibrated_data, policy)
    if val_errors:
        st.error("Validation issues encountered:")
        for err in val_errors:
            st.write(f"- {err}")
    else:
        st.success("✓ All required policy fields present and within cryptographic bounds.")

    st.write("")

    # -------------------------------------------------------------
    # STEP 3: ENCRYPTION & INSPECTOR
    # -------------------------------------------------------------
    st.markdown("### Step 3: Local Homomorphic Encryption")

    btn_encrypt = st.button("🔐 Encrypt Selected Fields with Paillier PHE", type="primary")

    if btn_encrypt or st.session_state.encrypted_fields is not None:
        if st.session_state.keys is None or btn_encrypt:
            with st.spinner(f"Generating {key_choice}-bit Paillier keypair and blinding ciphertexts..."):
                t0 = time.perf_counter()
                pub, priv = generate_keypair(key_size=key_choice)
                enc_data = encrypt_fields(pub, calibrated_data)
                t_total = time.perf_counter() - t0

                st.session_state.keys = (pub, priv)
                st.session_state.encrypted_fields = enc_data
                st.session_state.keygen_time = t_total

        pub, priv = st.session_state.keys
        enc_data = st.session_state.encrypted_fields
        pub_fingerprint = compute_public_key_fingerprint(pub)

        st.markdown(
            f"""
            <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; font-size: 0.9rem;">
                <span style="color: #475569; font-weight: 600;">Public Key Fingerprint:</span> <code style="color: #0F172A; background: transparent;">{pub_fingerprint}</code>
                &nbsp;|&nbsp;
                <span style="color: #64748B;">Modulus Size:</span> <code style="color: #0F172A; background: transparent;">{key_choice}-bit</code>
                &nbsp;|&nbsp;
                <span style="color: #64748B;">Status:</span> <span style="color: #166534; font-weight: 600;">Encrypted Locally</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander("Cryptographic Ciphertext Inspector (What the Evaluator Sees)", expanded=True):
            inspector_data = []
            for k, enc_num in enc_data.items():
                c_str = str(enc_num.ciphertext())
                inspector_data.append({
                    "Field": k,
                    "Plaintext": str(calibrated_data[k]) if privacy_mode else "HIDDEN (Privacy Active)",
                    "Paillier Ciphertext (c mod n²)": f"{c_str[:24]}...{c_str[-24:]}",
                    "Digits": len(c_str),
                })
            st.dataframe(pd.DataFrame(inspector_data), use_container_width=True)

        st.write("")

        # -------------------------------------------------------------
        # STEP 4: BLIND EVALUATION
        # -------------------------------------------------------------
        st.markdown("### Step 4: Dispatch to Evaluator Engine")
        st.caption("The evaluator calculates the formula using homomorphic arithmetic without learning your inputs.")

        btn_eval = st.button("🚀 Evaluate Eligibility Homomorphically", type="primary")

        if btn_eval or st.session_state.evaluation_result is not None:
            if btn_eval or st.session_state.evaluation_result is None:
                with st.spinner("Computing homomorphic scalar multiplications and additions..."):
                    t0 = time.perf_counter()
                    enc_score = evaluate_encrypted(pub, enc_data, policy)
                    t_eval = time.perf_counter() - t0

                    # Local Decryption
                    t0_dec = time.perf_counter()
                    dec_score = decrypt_score(priv, enc_score)
                    t_dec = time.perf_counter() - t0_dec

                    # Plaintext local verification
                    pt_score = evaluate_plaintext(calibrated_data, policy)
                    comparison = compare_results(pt_score, dec_score, policy)

                    # Generate verifiable audit receipt
                    receipt = generate_verification_receipt(
                        policy=policy,
                        public_key_fingerprint=pub_fingerprint,
                        key_size=key_choice,
                        evaluated_fields=list(calibrated_data.keys()),
                        decrypted_score=dec_score,
                        result=comparison["encrypted_result"],
                        is_match=comparison["is_match"],
                    )

                    st.session_state.evaluation_result = {
                        "comparison": comparison,
                        "t_eval": t_eval,
                        "t_dec": t_dec,
                        "receipt": receipt,
                    }

            res = st.session_state.evaluation_result
            comp = res["comparison"]
            receipt = res["receipt"]
            is_eligible = comp["encrypted_result"] == "Eligible"

            # Render Big Result Banner
            banner_class = "result-banner-eligible" if is_eligible else "result-banner-ineligible"
            status_text = "ELIGIBLE FOR BENEFIT" if is_eligible else "NOT ELIGIBLE FOR BENEFIT"
            banner_color = "#10B981" if is_eligible else "#EF4444"

            st.markdown(
                f"""
                <div class="{banner_class}">
                    <div style="font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: {banner_color}; font-weight: 600; margin-bottom: 4px;">
                        Evaluation Outcome
                    </div>
                    <div style="font-size: 2rem; font-weight: 700; color: {banner_color}; margin-bottom: 8px;">
                        {status_text}
                    </div>
                    <div style="font-size: 1rem; color: #475569;">
                        Decrypted Eligibility Score: <b>{comp['encrypted_decrypted_score']}</b> &nbsp;|&nbsp;
                        Required Threshold: <b>{comp['threshold']}</b>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.write("")

            # Telemetry Metrics
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.markdown(
                    f"""
                    <div class="stat-box">
                        <div class="stat-label">Final Score</div>
                        <div class="stat-val">{comp['encrypted_decrypted_score']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with m2:
                st.markdown(
                    f"""
                    <div class="stat-box">
                        <div class="stat-label">Threshold</div>
                        <div class="stat-val">{comp['threshold']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with m3:
                st.markdown(
                    f"""
                    <div class="stat-box">
                        <div class="stat-label">Evaluation Latency</div>
                        <div class="stat-val">{res['t_eval']*1000:.1f} ms</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with m4:
                st.markdown(
                    f"""
                    <div class="stat-box">
                        <div class="stat-label">Decryption Latency</div>
                        <div class="stat-val">{res['t_dec']*1000:.1f} ms</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.write("")

            # Parity Comparison Table
            if privacy_mode:
                st.markdown("### Step 5: Cryptographic Parity Verification")
                st.caption(
                    "Demonstrating that homomorphic operations over ciphertexts produce results 100% mathematically identical to plaintext calculations."
                )

                parity_table = [
                    {
                        "Method": "Plaintext Local Calculation (Simulation)",
                        "Score": comp["plaintext_score"],
                        "Result": comp["plaintext_result"],
                        "Evaluator Knowledge": "❌ Zero (Computed strictly locally)",
                    },
                    {
                        "Method": "Paillier Homomorphic Evaluation (Actual)",
                        "Score": comp["encrypted_decrypted_score"],
                        "Result": comp["encrypted_result"],
                        "Evaluator Knowledge": "🔒 Ciphertexts Only (No Plaintext)",
                    },
                ]
                st.dataframe(pd.DataFrame(parity_table), use_container_width=True)

                if comp["is_match"]:
                    st.success("✓ Cryptographic Parity Verified: Plaintext and Homomorphic results match exactly.")
                else:
                    st.error("⚠️ Parity discrepancy detected.")

            st.write("")

            # Downloadable Cryptographic Proof Receipt
            st.markdown("### Step 6: Verifiable Proof Certificate")
            col_rec1, col_rec2 = st.columns([2, 1])

            with col_rec1:
                st.code(format_receipt_as_markdown(receipt), language="markdown")

            with col_rec2:
                st.write("**Export Cryptographic Receipt:**")
                st.caption("Proof that evaluation adhered to policy without leaking private data.")

                receipt_md = format_receipt_as_markdown(receipt)
                receipt_json = json.dumps(receipt, indent=2)

                st.download_button(
                    "📥 Download Certificate (.md)",
                    data=receipt_md,
                    file_name=f"{receipt['receipt_id']}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )

                st.download_button(
                    "📥 Download JSON Proof (.json)",
                    data=receipt_json,
                    file_name=f"{receipt['receipt_id']}.json",
                    mime="application/json",
                    use_container_width=True,
                )
else:
    st.info("👆 Please upload an applicant document or select a sample file above to begin the evaluation workflow.")

st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; color: #64748B; font-size: 0.85rem;">
        ZeroSight Blind Eligibility Engine • Built with Paillier Partially Homomorphic Encryption (PHE)<br>
        All rights reserved. Secure Privacy-Preserving Computing Architecture.
    </div>
    """,
    unsafe_allow_html=True,
)
