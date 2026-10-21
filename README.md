# ChatPhishDetector: Detecting Phishing Sites Using Large Language Models

An authentic implementation of the IEEE research paper:
> **"ChatPhishDetector: Detecting Phishing Sites Using Large Language Models"**  
> *Takashi Koide, Hiroki Nakano, and Daiki Chiba (Member, IEEE)*  
> NTT Security Holdings Corporation & NTT Corporation, Tokyo, Japan  
> Published in: **IEEE Access (Volume 12, October 2024)**  
> DOI: [10.1109/ACCESS.2024.3483905](https://doi.org/10.1109/ACCESS.2024.3483905)

---

## 📌 Project Overview
Phishing websites deceive users via two primary mechanisms:
1. **Brand Impersonation:** Misusing official logos and brand names.
2. **Social Engineering (SE) Techniques:** Manipulating human psychology using urgent account alerts, fake malware warnings, unexpected prizes, or fake parcel fees.

Traditional detection tools (such as **Phishpedia**, which relies on pre-collected logo databases, or **dnstwist**, which relies on lexical domain string matching) fail when attackers target unindexed brands, use novel layouts, or employ pure social engineering.

**ChatPhishDetector** harnesses the zero-shot reasoning capabilities of Large Language Models (LLMs) combined with:
- Automated browser crawling via **Chrome DevTools Protocol (CDP)**,
- Browser-rendered DOM capture after JavaScript execution,
- Multi-stage HTML simplification (**Algorithm 1**) and font-size prioritized OCR filtering,
- Chain-of-Thought (CoT) prompting across **Normal Mode** (Text) and **Vision Mode** (Multimodal).

---

## 🏗️ Architecture & Pipeline

```
[ Target URL ]
       │
       ▼
 1. Security & SSRF Guard (security.py)
    - Validates scheme (HTTP/HTTPS)
    - Resolves DNS and blocks RFC 1918 private IPs, localhost, and cloud metadata (169.254.169.254)
       │
       ▼
 2. Chrome DevTools Protocol Crawler (crawler.py)
    - Emulates Google Chrome (Win32) or Safari (iPhone)
    - Executes JavaScript and captures:
      • Final URL (after client/server redirects)
      • Rendered DOM HTML
      • Full Screenshot (PNG)
       │
       ├─────────────────────────────────┐
       ▼                                 ▼
 3. HTML Simplifier (processor.py)    4. OCR & Screenshot Engine (ocr_engine.py)
    - Algorithm 1 Implementation:        - Normal Mode: Font-size prioritized text
      • Strip style/script/comments        filtering (cappe at 500 tokens)
      • Unwrap non-important tags        - Vision Mode: Formats screenshot as base64
      • Shorten base64 & long links        PNG URI (1065x1500 px standard)
      • Midpoint pruning (<= 2500 tokens)
       │                                 │
       └────────────────┬────────────────┘
                        ▼
 5. Chain-of-Thought Prompting (prompts.py)
    - Prompt Template 1: Subtasks p1 -> p2 -> p3 -> p4
    - Injection mitigation via delimiter isolation
                        │
                        ▼
 6. LLM Detection Engine (detector.py)
    - Query GPT-4o, GPT-4V, GPT-4, GPT-3.5, Gemini, or Local Heuristic Engine
    - Decision Rule:
        is_phishing = (phishing == True) OR (suspicious_domain == True)
        is_legitimate = (phishing == False) AND (suspicious_domain == False)
    - Youden's J statistic score cutoffs (GPT-4V >= 5, GPT-4 >= 3, GPT-3.5 >= 1)
                        │
                        ▼
 7. Interactive Interface & Evaluation (app.py & evaluation.py)
    - Real-time website analysis dashboard
    - Evidence & CoT explanation breakdown
    - Paper benchmarks & comparative performance evaluation
```

---

## 📂 Project Structure

```
BasePaper Implementation/
├── security.py             # Module 1A: URL validation, SSRF guard, IP isolation, defanging
├── crawler.py              # Module 1B: Browser crawler using Chrome DevTools Protocol
├── run_crawler.py          # Interactive CLI crawler runner
├── processor.py            # Module 2: HTML simplification (Algorithm 1) & token budgeting
├── ocr_engine.py           # Module 3: OCR text extraction & font-size simplification
├── prompts.py              # Module 4: Original paper prompt templates (CoT & Simple)
├── detector.py             # Module 5: LLM detection engine (Normal, Vision, Simple)
├── evaluation.py           # Module 6: Evaluation harness, metrics, comparison tables
├── app.py                  # Module 7: Streamlit interactive interface
├── specification.md        # Complete formal research paper specification
├── requirements.txt        # Python dependencies
├── .env.example            # Configuration and API key template
├── tests/
│   ├── test_security.py    # Unit tests for SSRF & URL safety
│   ├── test_crawler.py     # Unit tests for Chrome DevTools Protocol crawling
│   ├── test_processor.py   # Unit tests for Algorithm 1 HTML simplification
│   ├── test_ocr.py         # Unit tests for OCR text font-size simplification
│   ├── test_detector.py    # Unit tests for decision rules and JSON extraction
│   └── test_pipeline.py    # End-to-end integration tests (crawl to classification)
```

---

## 🚀 Getting Started on Windows (VS Code)

### Prerequisites
- Python 3.10+ installed
- Google Chrome installed (located at standard path `C:\Program Files\Google\Chrome\Application\chrome.exe`)

### 1. Installation
Open PowerShell in the project directory:
```powershell
pip install -r requirements.txt
```

### 2. Configuration (Optional)
Copy the environment template:
```powershell
cp .env.example .env
```
Add your `OPENAI_API_KEY` in `.env` if you wish to run proprietary OpenAI models.  
*Note: If no API key is provided, the application seamlessly uses the built-in **Local Heuristic Engine**, which deterministically evaluates the paper's 7 evidence categories (Section V-G) without requiring any paid subscriptions.*

---

## 🧪 Running the Automated Test Suite

Run all 21 unit and integration tests across every module:
```powershell
python -m unittest discover tests
```
**Expected Result:**
```text
Ran 21 tests in 26.468s

OK
```

---

## 🖥️ Running the Application

### 1. Interactive Web Application (Streamlit)
Launch the graphical interface:
```powershell
streamlit run app.py
```
This opens the web browser to `http://localhost:8501`, featuring:
- **Live Website Scanner:** Enter any URL, select Normal/Vision/Simple mode and Chrome/Safari environment, and watch real-time progress.
- **Evidence Breakdown:** Displays the LLM's Chain-of-Thought reasoning, identified brand, suspicious domain flag, and risk score.
- **Artifact Inspector:** Side-by-side inspection of rendered DOM HTML, OCR text, and full screenshot.
- **Paper Benchmarks Tab:** View published IEEE results and run live benchmarks on the test suite.

### 2. CLI Evaluation & Benchmark Runner
To run the automated benchmark harness from the command line:
```powershell
python evaluation.py
```

### 3. Standalone CLI Crawler
To test browser crawling on any URL directly from terminal:
```powershell
python run_crawler.py https://example.com --env chrome_windows
python run_crawler.py https://example.com --env safari_iphone
```

---

## 📊 Comparison: Research Paper vs. Implementation

| Paper Component | Original Paper Methodology | This Implementation | Match Status | Notes / Rationale |
| :--- | :--- | :--- | :---: | :--- |
| **Web Crawling** | Automates Google Chrome via Chrome DevTools Protocol (CDP) | Chrome DevTools Protocol via Python WebSocket JSON-RPC in [`crawler.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/crawler.py) | **Exact** | Chosen over Selenium/Puppeteer to avoid bot detection |
| **Rendered DOM** | Waits for JavaScript execution before DOM extraction | Evaluates `document.documentElement.outerHTML` after settle delay | **Exact** | Catches dynamic login forms obfuscated in JS |
| **Emulated Envs** | Google Chrome on Windows & Safari on iPhone | Implemented in [`BrowserProfile`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/crawler.py#L31-L71) with specific UAs and viewports | **Exact** | Windows: $1280 \times 800$, iPhone: $390 \times 844$ |
| **HTML Simplification** | Algorithm 1: strip style/script/comment, unwrap non-important tags, remove empty tags, midpoint prune | Implemented in [`processor.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/processor.py) following Algorithm 1 lines 1-19 | **Exact** | Token budget: $\le 2500$ tokens |
| **OCR Text Filtering** | Removes sentences starting from smallest font size until $\le 500$ tokens | Implemented in [`ocr_engine.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/ocr_engine.py) via bounding box height ranking | **Exact** | Prioritizes headings, alerts, logos |
| **OCR Provider** | Azure Cognitive Services Vision OCR | Supports Azure Vision API + local Tesseract + fallback extractor | **Partial (Extended)** | Azure key used if present; local OCR ensures portability |
| **Prompt Template 1** | 4 CoT subtasks: SE techniques, brand identification, conclusion/rationale, JSON output | Exact prompt template implemented in [`prompts.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/prompts.py) | **Exact** | Exact wording, limitations, and examples |
| **Prompt Template 2** | Simple mode (URL only baseline) | Exact prompt template implemented in [`prompts.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/prompts.py) | **Exact** | Evaluates URL lexical reasoning |
| **Classification Rule** | Phishing if `phishing == True` OR `suspicious_domain == True` | Implemented in [`detector.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/detector.py) | **Exact** | Preserves original boolean logic |
| **Score Cutoffs** | Youden's J statistic cutoffs (GPT-4V: 5, GPT-4: 3, GPT-3.5: 1) | Implemented in [`YOUDENS_J_CUTOFFS`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/detector.py#L32-L41) | **Exact** | Evaluates score $\ge \text{cutoff}$ |
| **SSRF Safeguards** | Crawler isolation and malicious URL protection | RFC 1918, loopback, and cloud metadata blocking in [`security.py`](file:///c:/Users/GANGOTHRI/Desktop/BasePaper%20Implementation/security.py) | **Enhanced** | Enforces secure execution |

---

## 📈 Paper Benchmark Results (IEEE Access Table 1 & 2)

| System / Model | Mode | Precision | Recall | Accuracy | F-measure | TP | TN | FP | FN |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **GPT-4V** | Vision | **98.7%** | **99.6%** | **99.2%** | **99.2%** | 991 | 986 | 13 | 4 |
| **Gemini Pro 1.0** | Vision | 78.9% | 99.1% | 89.1% | 87.9% | 789 | 993 | 7 | 211 |
| **GPT-4** | Normal | 98.3% | 98.4% | 98.4% | 98.4% | 984 | 983 | 17 | 16 |
| **GPT-3.5** | Normal | 98.3% | 86.7% | 92.6% | 92.1% | 867 | 985 | 15 | 133 |
| **Llama 2 70B** | Normal | 78.4% | 66.4% | 74.1% | 71.9% | 664 | 817 | 183 | 336 |
| **Gemini Pro 1.0** | Normal | 90.5% | 95.6% | 93.2% | 93.0% | 905 | 958 | 42 | 95 |
| **GPT-4** | Simple | 98.4% | 75.5% | 87.2% | 85.5% | 755 | 988 | 12 | 245 |
| **GPT-3.5** | Simple | 98.6% | 77.5% | 88.2% | 86.8% | 775 | 989 | 11 | 225 |
| *dnstwist* | Baseline | 31.3% | — | — | — | — | — | — | — |
| *Phishpedia* | Baseline | 26.0% | — | — | — | — | — | — | — |
| *PhishStorm* | Baseline | 52.0% | 75.1% | 52.8% | 61.4% | — | — | — | — |

---

## 🎓 Viva & Project Defense Preparation

### 1. What is the fundamental novelty of ChatPhishDetector compared to traditional machine learning classifiers?
**Answer:** Traditional anti-phishing systems rely on feature engineering (URL length, IP address presence, keyword frequency) or reference databases of brand logos (Phishpedia). Attackers easily bypass them by using novel brands, brandless phishing, or obfuscated HTML. ChatPhishDetector treats phishing detection as a contextual reasoning problem, prompting an LLM to simultaneously evaluate visual mimicry, domain inconsistency, and psychological social engineering manipulation.

### 2. Why does the paper implement two distinct modes: Normal Mode vs. Vision Mode?
**Answer:**
- **Normal Mode (Text-only):** Uses URL, simplified HTML, and OCR text extracted from screenshots. It is highly cost-effective ($0.002 - $0.046 per request) and works with text-only LLMs like Llama 3 70B or GPT-4.
- **Vision Mode (Multimodal):** Directly supplies the screenshot image to vision-capable LLMs (GPT-4V / GPT-4o). This eliminates OCR extraction errors and allows the model to inspect visual cues like brand logo placement, visual similarity, and fake trust badges directly, achieving the highest precision (98.7%) and recall (99.6%).

### 3. How does Algorithm 1 prevent token limit exhaustion?
**Answer:** Typical non-phishing web pages contain a median of 74,937 tokens, which easily exceeds standard LLM context windows (4,096 tokens). Algorithm 1 strips high-token low-relevance tags (`<style>`, `<script>`, comments), unwraps non-essential wrappers, shortens base64 images and long URLs, and prunes elements from the midpoint of the DOM until the token count is strictly within 2,500 tokens, preserving top tags (`<title>`, `<meta>`) and bottom forms/inputs.

### 4. What is the exact classification decision rule?
**Answer:** A website is classified as **phishing** if `phishing == True` OR `suspicious_domain == True`. It is classified as **legitimate** only if both are `False`. If the LLM returns `unknown` or fails to parse, it is separately flagged as insufficient evidence rather than misclassified as benign.
