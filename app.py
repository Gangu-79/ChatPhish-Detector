"""
ChatPhishDetector - Interactive Application (Module 7)
IEEE Access 2024: "ChatPhishDetector: Detecting Phishing Sites Using Large Language Models"
Authors: Takashi Koide, Hiroki Nakano, Daiki Chiba (NTT Security & NTT Corp)
"""

import os
import streamlit as st
import pandas as pd
from PIL import Image
import io

from security import validate_url, defang_url
from crawler import ChromeDevToolsCrawler, find_chrome_executable
from processor import simplify_html, count_tokens, MAX_HTML_TOKENS
from ocr_engine import OCREngine, simplify_ocr_text
from detector import PhishingDetector, YOUDENS_J_CUTOFFS
from evaluation import (
    evaluate_chatphishdetector,
    get_paper_benchmark_dataframe,
    SAMPLE_BENCHMARK_DATASET,
)

# Page configuration
st.set_page_config(
    page_title="ChatPhishDetector - IEEE Research Implementation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished aesthetics
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .verdict-box-phish {
        background-color: #FEE2E2;
        border-left: 6px solid #DC2626;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    .verdict-box-legit {
        background-color: #DCFCE7;
        border-left: 6px solid #16A34A;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    .verdict-box-unknown {
        background-color: #FEF3C7;
        border-left: 6px solid #D97706;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    /* Hide Streamlit default Deploy button, toolbar, and header (not in base paper) */
    .stDeployButton, [data-testid="stToolbar"], #MainMenu, header, footer {
        display: none !important;
        visibility: hidden !important;
    }
</style>
""", unsafe_allow_html=True)


def main():
    # Sidebar: Mode, Environment & Model Controls
    st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.sidebar.title("Configuration")

    st.sidebar.markdown("### Detection Mode")
    mode = st.sidebar.radio(
        "Select Pipeline Mode:",
        options=["Normal Mode", "Vision Mode", "Simple Mode"],
        help="Normal: URL + Simplified HTML + OCR Text. Vision: URL + Simplified HTML + Screenshot. Simple: URL only.",
    )

    st.sidebar.markdown("### Crawler Environment (Section III-A)")
    environment = st.sidebar.selectbox(
        "Emulated Environment:",
        options=["chrome_windows", "safari_iphone"],
        format_func=lambda x: "Google Chrome on Windows" if x == "chrome_windows" else "Safari on iPhone",
    )

    st.sidebar.markdown("### LLM Model (Section V-A1)")
    model_choice = st.sidebar.selectbox(
        "Model:",
        options=["gpt-4o", "gpt-4", "gpt-3.5-turbo", "Local Heuristic Engine"],
        help="Select LLM model. Uses OpenAI API if key is provided, or the Local Heuristic Engine implementing Section V-G rules.",
    )

    api_key_input = st.sidebar.text_input(
        "OpenAI API Key (Optional):",
        value=os.getenv("OPENAI_API_KEY", ""),
        type="password",
        help="Leave blank to use the offline/heuristic engine that evaluates Section V-G rules.",
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "**Paper Reference:**  \n"
        "[IEEE Access 2024 Paper](https://doi.org/10.1109/ACCESS.2024.3483905)  \n"
        "*Koide, Nakano, & Chiba*"
    )

    # Top Header
    st.markdown('<div class="main-title">🛡️ ChatPhishDetector</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Detecting Phishing Sites Using Large Language Models (IEEE Access 2024)</div>',
        unsafe_allow_html=True,
    )

    # Navigation Tabs (Only the Paper's Scanner and Evaluation Benchmark)
    tab_scan, tab_benchmarks = st.tabs([
        "🔍 Live Website Scanner",
        "📊 Paper Benchmarks & Evaluation",
    ])

    # ==========================================================================
    # TAB 1: Live Website Scanner
    # ==========================================================================
    with tab_scan:
        st.markdown("#### Enter Target Website to Inspect")
        col_url, col_btn = st.columns([4, 1])

        with col_url:
            input_url = st.text_input(
                "Website URL",
                value="https://example.com",
                placeholder="https://suspicious-login.example.com",
                label_visibility="collapsed",
            )

        with col_btn:
            scan_clicked = st.button("🚀 Analyze Site", use_container_width=True, type="primary")

        # Quick sample links
        st.caption("Quick test targets: `https://example.com` (Benign) | `https://en.wikipedia.org` (Benign) | Custom URL")

        if scan_clicked:
            if not input_url:
                st.error("Please enter a valid URL.")
                return

            status_placeholder = st.empty()
            progress_bar = st.progress(0)

            # Step 1: Security Validation
            status_placeholder.info("Step 1/5: Enforcing SSRF & Security Validation...")
            progress_bar.progress(20)
            is_safe, canonical_url, sec_err = validate_url(input_url)

            if not is_safe:
                progress_bar.progress(100)
                status_placeholder.empty()
                st.error(f"🛑 Security Block: {sec_err}")
                st.warning("The crawler blocked this request to protect your local network (SSRF Defense).")
                return

            # Step 2: Browser Crawl
            status_placeholder.info(f"Step 2/5: Automating Chrome via Chrome DevTools Protocol ({environment})...")
            progress_bar.progress(40)

            chrome_exe = find_chrome_executable()
            if not chrome_exe:
                st.error("Google Chrome executable not found. Please install Chrome or configure CHROME_PATH.")
                return

            crawler = ChromeDevToolsCrawler(chrome_exe)
            crawl_res = crawler.crawl(
                canonical_url,
                environment=environment,
                timeout=30,
                settle_delay=3.0,
            )

            if crawl_res.error:
                progress_bar.progress(100)
                status_placeholder.empty()
                st.error(f"Crawler Error: {crawl_res.error}")
                return

            # Step 3: HTML Simplification (Algorithm 1)
            status_placeholder.info("Step 3/5: Applying Algorithm 1 HTML Simplification (≤ 2,500 tokens)...")
            progress_bar.progress(60)

            simplified_html = simplify_html(crawl_res.html, max_tokens=MAX_HTML_TOKENS)
            html_tokens = count_tokens(simplified_html)

            # Step 4: OCR & Screenshot Processing
            status_placeholder.info("Step 4/5: Processing Screenshot & OCR Extraction...")
            progress_bar.progress(80)

            ocr_engine = OCREngine()
            ocr_blocks = ocr_engine.extract_text_blocks(crawl_res.screenshot_bytes)
            simplified_ocr = simplify_ocr_text(ocr_blocks, max_tokens=500)

            # Step 5: LLM Detection
            status_placeholder.info("Step 5/5: Querying LLM Chain-of-Thought Detection Engine...")
            progress_bar.progress(95)

            selected_mode = (
                "vision" if mode == "Vision Mode"
                else "simple" if mode == "Simple Mode"
                else "normal"
            )

            detector = PhishingDetector(
                api_key=api_key_input if api_key_input else None,
                default_model=model_choice,
            )

            if selected_mode == "vision":
                result = detector.detect_vision_mode(
                    url=crawl_res.final_url,
                    raw_html=simplified_html,
                    screenshot_bytes=crawl_res.screenshot_bytes,
                    model=model_choice if "Heuristic" not in model_choice else None,
                )
            elif selected_mode == "simple":
                result = detector.detect_simple_mode(
                    url=crawl_res.final_url,
                    model=model_choice if "Heuristic" not in model_choice else None,
                )
            else:
                result = detector.detect_normal_mode(
                    url=crawl_res.final_url,
                    raw_html=simplified_html,
                    ocr_blocks=ocr_blocks,
                    model=model_choice if "Heuristic" not in model_choice else None,
                )

            progress_bar.progress(100)
            status_placeholder.empty()

            # Display Results Dashboard
            st.markdown("---")
            st.markdown("### Detection Findings")

            # Classification Banner
            if result.classification_label == "phishing":
                st.markdown(
                    f"""
                    <div class="verdict-box-phish">
                        <h2 style="color: #991B1B; margin: 0;">🚨 PHISHING SITE DETECTED</h2>
                        <p style="margin-top: 0.5rem; color: #7F1D1D; font-size: 1.05rem;">
                            Decision Rule: <code>(phishing == True) OR (suspicious_domain == True)</code> triggered.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            elif result.classification_label == "legitimate":
                st.markdown(
                    f"""
                    <div class="verdict-box-legit">
                        <h2 style="color: #166534; margin: 0;">✅ LEGITIMATE (NON-PHISHING) SITE</h2>
                        <p style="margin-top: 0.5rem; color: #14532D; font-size: 1.05rem;">
                            Decision Rule: <code>(phishing == False) AND (suspicious_domain == False)</code> satisfied.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div class="verdict-box-unknown">
                        <h2 style="color: #92400E; margin: 0;">⚠️ UNKNOWN / INSUFFICIENT EVIDENCE</h2>
                        <p style="margin-top: 0.5rem; color: #78350F; font-size: 1.05rem;">
                            Model could not reach a definitive conclusion from available web cues.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Metrics Cards
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric(
                    "Phishing Risk Score",
                    f"{result.phishing_score} / 10",
                    delta=f"Cutoff: ≥ {result.youden_cutoff}",
                    delta_color="inverse" if result.score_based_verdict else "normal",
                )
            with m2:
                st.metric("Identified Brand", result.brands or "None / Generic")
            with m3:
                st.metric(
                    "Suspicious Domain Flag",
                    "TRUE" if result.raw_suspicious_domain_key else "FALSE",
                )
            with m4:
                st.metric(
                    "Redirected Destination",
                    "YES" if crawl_res.is_redirected else "NO",
                )

            # Details & Artifacts
            st.markdown("#### Evidence & Reasoning")
            with st.expander("📝 Chain-of-Thought (CoT) Explanation", expanded=True):
                st.markdown(result.reasoning)

            with st.expander("📦 Raw JSON Model Output (Subtask 4)"):
                st.json(result.to_dict())

            # Side-by-side Inspection of Crawled Artifacts
            col_shot, col_code = st.columns([1, 1])

            with col_shot:
                st.markdown("#### Captured Screenshot")
                if crawl_res.screenshot_bytes:
                    image = Image.open(io.BytesIO(crawl_res.screenshot_bytes))
                    st.image(image, caption=f"Screenshot ({environment})", use_column_width=True)
                else:
                    st.info("No screenshot captured.")

            with col_code:
                st.markdown(f"#### Simplified HTML ({html_tokens} tokens / limit: 2500)")
                st.code(simplified_html[:2000] + ("\n... [truncated for display]" if len(simplified_html) > 2000 else ""), language="html")

                if simplified_ocr:
                    st.markdown("#### Simplified OCR Text (≤ 500 tokens)")
                    st.text_area("OCR Text", simplified_ocr, height=120)

    # ==========================================================================
    # TAB 2: Paper Benchmarks & Evaluation
    # ==========================================================================
    with tab_benchmarks:
        st.markdown("### IEEE Paper Published Results (Table 1 & Table 2)")
        st.markdown(
            "This table reproduces the exact experimental results reported in the IEEE Access paper "
            "across 2,000 tested websites (1,000 phishing and 1,000 legitimate)."
        )

        df_bench = get_paper_benchmark_dataframe()
        st.dataframe(df_bench, use_container_width=True)

        st.markdown("---")
        st.markdown("### Run Live Benchmark on Curated Test Suite")
        st.write("Evaluates the current implementation against representative test samples (Section IV distribution):")

        eval_model = st.selectbox("Benchmark Model:", ["gpt-4", "gpt-3.5-turbo", "Local Heuristic Engine"])
        eval_mode = st.radio("Benchmark Mode:", ["normal", "simple"], horizontal=True)

        if st.button("▶️ Execute Benchmark Suite", type="primary"):
            with st.spinner("Running evaluation over 10 benchmark test samples..."):
                metrics, details = evaluate_chatphishdetector(
                    mode=eval_mode,
                    model=eval_model,
                )

                st.success("Benchmark completed successfully!")

                # Metric Cards
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Accuracy", f"{metrics['Accuracy']}%")
                c2.metric("Precision", f"{metrics['Precision']}%")
                c3.metric("Recall", f"{metrics['Recall']}%")
                c4.metric("F-measure", f"{metrics['F-measure']}%")

                st.write(f"**Confusion Matrix:** TP={metrics['TP']}, TN={metrics['TN']}, FP={metrics['FP']}, FN={metrics['FN']}")

                df_details = pd.DataFrame(details)
                st.dataframe(
                    df_details[["url", "category", "ground_truth", "prediction", "correct", "phishing_score", "brands"]],
                    use_container_width=True,
                )


if __name__ == "__main__":
    main()
