# ChatPhishDetector: Research Paper Implementation Specification

**Based on IEEE Access Paper (Volume 12, October 2024):**  
*"ChatPhishDetector: Detecting Phishing Sites Using Large Language Models"*  
**Authors:** Takashi Koide, Hiroki Nakano, Daiki Chiba (NTT Security Holdings Corporation & NTT Corporation)  
**Digital Object Identifier (DOI):** [10.1109/ACCESS.2024.3483905](https://doi.org/10.1109/ACCESS.2024.3483905)

---

## 1. Executive Summary & Problem Formulation

### 1.1 Problem Statement
Phishing sites deceive web users by:
1. **Brand Impersonation:** Mimicking official brand logos, styling, and service names.
2. **Social Engineering (SE) Techniques:** Creating artificial urgency, fake security alerts, unexpected prizes/rewards, or fabricated account suspension issues to manipulate user behavior.

### 1.2 Limitations of Existing Approaches
* **Logo/Reference Matching (e.g., Phishpedia):** Requires pre-compiled databases of brand logos. Fails against phishing sites that do not use official logos or target obscure/unindexed brands (17.2% of phishing sites in the paper's dataset had no visual resemblance to the real site).
* **Domain Squatting Rules (e.g., dnstwist):** Limited to lexical string similarity; fails when attackers use completely unrelated domains (e.g., cloud platforms, bulletproof hosters) or when legitimate brands operate non-standard domains.
* **URL Lexical Classifiers (e.g., PhishStorm):** Reliant purely on URL strings and domain features, missing on-page visual and textual manipulation context.
* **Supervised Machine Learning:** Demands continuous, large-scale retraining and labelling across thousands of fast-evolving brands.

### 1.3 Proposed ChatPhishDetector Solution
ChatPhishDetector harnesses Large Language Models (LLMs) as zero-shot reasoning classifiers. By combining:
* Automated headless browser crawling with Chrome DevTools Protocol (CDP),
* Browser-rendered DOM capture after JavaScript execution,
* Multi-stage HTML simplification and OCR extraction,
* Chain-of-Thought (CoT) prompting,

it accurately detects brand impersonation, domain inconsistencies, and psychological social engineering manipulation without needing model fine-tuning.

### 1.4 Mathematical Formulation (Section III)
Let $W = \{w_1, w_2, \dots, w_n\}$ be the set of inspected websites. Each website $w_i$ is represented as a tuple:
$$w_i = (u_i, h_i, s_i)$$
where:
* $u_i \in U$: Website URL (including final redirected destination)
* $h_i \in H$: Browser-rendered HTML content after JavaScript execution
* $s_i \in S$: Full-page screenshot image

Phishing detection is framed as a binary classification function:
$$f : W \to \{0, 1\}$$
where $1$ denotes a **phishing website** and $0$ denotes a **legitimate (non-phishing) website**.

---

## 2. System Architecture & Workflow

```
[ Input URL ]
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Web Crawler (Chrome DevTools Protocol - CDP)             │
│    - Emulate Google Chrome (Win) & Safari (iPhone)          │
│    - Wait for JavaScript Execution                          │
│    - Capture: Final URL, Rendered HTML, Screenshot Image    │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
     [ Rendered HTML ]                   [ Screenshot ]
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│ 2. HTML Simplifier (Alg. 1)  │ │ 3. OCR Engine              │
│    - Strip style, script,    │ │    - Multilingual OCR      │
│      comments                │ │    - Filter text by font   │
│    - Unwrap non-important tag│ │      size (descending)     │
│    - Truncate mid-DOM nodes  │ │    - Cap at 500 tokens     │
│    - Cap at 2,500 tokens     │ └────────────┬───────────────┘
└──────────────┬───────────────┘              │
               │                              │
               ▼                              ▼
      [ Simplified HTML ]              [ OCR Text ] (Normal Mode)
               │                              │
               │                              │  OR  [ Screenshot Image ] (Vision Mode)
               ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Chain-of-Thought (CoT) Prompt Generator                  │
│    - Subtask 1: Analyze SE Techniques                       │
│    - Subtask 2: Identify Brand & Match Legitimate Domain    │
│    - Subtask 3: State Phishing Conclusion & Rationale       │
│    - Subtask 4: Output JSON Schema                          │
│    - Triple backtick injection protection                   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Large Language Model (LLM) Inference                     │
│    - Normal Mode: GPT-4, GPT-3.5, Llama-2/3, Gemini Pro     │
│    - Vision Mode: GPT-4V, GPT-4o, Gemini Pro Vision         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Classification & Decision Engine                         │
│    Decision Rule:                                           │
│      Phishing = (phishing == True) OR                       │
│                 (suspicious_domain == True)                 │
│      Legitimate = (phishing == False) AND                   │
│                   (suspicious_domain == False)              │
│      Scores: phishing_score (0 - 10)                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Component Specifications

### Module 1: Web Crawling (Section III-A)
* **Technology:** Automates Google Chrome via **Chrome DevTools Protocol (CDP)**.
  * *Reason in paper:* Mitigates bot detection compared to Selenium or standard Puppeteer.
  * Captures DOM **after JavaScript execution** because modern phishing kits utilize obfuscated JS to construct login forms dynamically.
* **Captured Artifacts:**
  1. `final_url`: The reached web page URL after all HTTP/JS redirects.
  2. `rendered_html`: Full DOM tree (`document.documentElement.outerHTML`).
  3. `screenshot`: Full-page or viewport PNG capture.
* **Environments Emulated:**
  1. **Google Chrome on Windows:**
     * User-Agent: Chrome / Windows NT 10.0
     * Browser viewport: Desktop standard (1280×800 or 1920×1080)
  2. **Safari on iPhone:**
     * User-Agent: Safari / Mobile iPhone OS
     * Browser viewport: Mobile standard (390×844)

### Module 2: HTML Simplification (Section III-C & Algorithm 1)
* **Objective:** Compress typical web pages (median 74,937 tokens for benign, 8,275 for phishing) to fit strict token constraints ($\le 2,500$ tokens) while preserving critical phishing signals.
* **Algorithm 1 Steps:**
  1. Parse input HTML.
  2. Remove `<style>`, `<script>`, and HTML comment `<!-- ... -->` nodes.
  3. Check: If `lengthToken(processedHTML) < 2500` tokens, return `processedHTML`.
  4. **Unwrap** elements except for important tags:
     * Allowed important tags: `head`, `title`, `meta`, `body`, `h1`, `h2`, `h3`, `h4`, `h5`, `h6`, `p`, `strong`, `a`, `img`, `hr`, `table`, `tbody`, `tr`, `th`, `td`, `ol`, `ul`, `li`, `ruby`, `label`.
     * Non-important tags (e.g. `div`, `span`, `section`, `nav`) are unwrapped (outer tags removed, children retained).
  5. Remove elements without enclosed text content (except essential self-closing elements).
  6. Shorten base64-encoded `src` in `<img>` tags (`data:image/...;base64,...` $\to$ `[base64_image]`).
  7. Shorten lengthy `href` attributes in `<a>` tags.
  8. Check: If `lengthToken(processedHTML) < 2500` tokens, return `processedHTML`.
  9. **Midpoint Pruning:** While `lengthToken(processedHTML) > 2500`:
     * Remove an HTML element from the middle of the document tree.
  10. Return `processedHTML`.

### Module 3: OCR & Screenshot Processing (Section III-D)
* **Normal Mode (Text-only):**
  * Extracts visible text from the page screenshot using OCR (paper used Azure Cognitive Service Vision OCR for multilingual support; we implement an abstracted engine supporting Tesseract / EasyOCR / Azure Vision).
  * Measures bounding boxes / font sizes of recognized text.
  * **Simplification Rule:** If OCR token count $> 500$, progressively drop sentences starting from the **smallest font size** until `lengthToken(ocrText) <= 500`. (Rationale: Larger text represents brand names, main headings, and alerts; smaller text is footer/disclaimers).
* **Vision Mode (Multimodal):**
  * Directly feeds the screenshot image to the multimodal LLM (GPT-4V / GPT-4o / Gemini Vision).
  * Eliminates OCR errors and allows the vision LLM to inspect logos, layout mimicry, and visual trust seals directly.

### Module 4: Token Budgeting & Allocation (Section III-B & III-C)
Designed to accommodate standard 4k token context windows:

| Component | Token Limit | Description |
|:---|:---|:---|
| **Prompt Template Instructions** | 362 tokens | Chain-of-Thought instructions & guidelines |
| **Target URL** | 300 tokens | Visited and final redirected URL |
| **Simplified HTML** | 2,500 tokens | Output of Algorithm 1 |
| **OCR Text (Normal Mode)** | 500 tokens | Font-filtered text from screenshot |
| **Vision Screenshot (Vision Mode)** | ~1,105 tokens | Calculated for ~1065×1500 px images |
| **LLM Output Reservation** | 300 tokens | JSON response + reasoning |
| **Total Prompt Budget** | ~3,662 tokens | Safely within 4,096 tokens |

### Module 5: Prompt Engineering (Section III-B & Prompt Templates 1 & 2)

#### Prompt Template 1 (Full Normal & Vision Mode)
```text
You are a web programmer and security expert tasked with examining a web page to determine if it is a phishing site or a legitimate site. To complete this task, follow these sub-tasks:
1. Analyze the HTML, URL, and [OCR-extracted text / screenshot image] for any SE techniques often used in phishing attacks. Point out any suspicious elements found in the HTML, URL, or text.
2. Identify the brand name. If the HTML appears to resemble a legitimate web page, verify if the URL matches the legitimate domain name associated with the brand, if known.
3. State your conclusion on whether the site is a phishing site or a legitimate one, and explain your reasoning. If there is insufficient evidence to make a determination, answer "unknown".
4. Submit your findings as JSON-formatted output with the following keys:
- phishing_score: int (indicates phishing risk on a scale of 0 to 10)
- brands: str (identified brand name or None if not applicable)
- phishing: boolean (whether the site is a phishing site or a legitimate site)
- suspicious_domain: boolean (whether the domain name is suspected to be not legitimate)
Limitations:
- The HTML may be shortened and simplified.
- The OCR-extracted text may not always be accurate. [Normal mode only]
Examples of social engineering techniques:
- Alerting the user to a problem with their account
- Offering unexpected rewards
- Informing the user of a missing package or additional payment required
- Displaying fake security warnings
URL:
{URL}
HTML:
```
{Browser-rendered HTML}
```
Text extracted using OCR: [Normal mode only]
```
{OCR-extracted text}
```
```

#### Prompt Template 2 (Simple Baseline Mode - URL Only)
```text
You are a web programmer and security expert tasked with examining a URL to determine if it is a phishing site or a legitimate site.
Submit your findings as JSON-formatted output with the following keys:
- phishing_score: int (indicates phishing risk on a scale of 0 to 10)
- brands: str (identified brand name or None if not applicable)
- phishing: boolean (whether the site is a phishing site or a legitimate site)
- suspicious_domain: boolean (whether the domain name is suspected to be not legitimate)

URL:
{URL}
```

### Module 6: Phishing Classification Rule (Section III-B & Table 1)
Given LLM output fields `phishing` and `suspicious_domain`:
$$\text{Class} = \begin{cases} 
\text{Phishing (1)}, & \text{if } \text{phishing} = \text{True} \lor \text{suspicious\_domain} = \text{True} \\
\text{Legitimate (0)}, & \text{if } \text{phishing} = \text{False} \land \text{suspicious\_domain} = \text{False} \\
\text{Unknown / Error}, & \text{if insufficient evidence or unparseable}
\end{cases}$$

Additionally, the paper explores classification via thresholding on `phishing_score` $\in [0, 10]$ using Youden's J statistic ($J = \text{Sensitivity} + \text{Specificity} - 1$):
* Optimal Cutoffs:
  * GPT-4V: $\ge 5$
  * Gemini Pro Vision: $\ge 1$
  * GPT-4: $\ge 3$
  * GPT-3.5: $\ge 1$
  * Llama 2: $\ge 6$
  * Gemini Pro: $\ge 4$

---

## 4. Benchmark Performance Reported in Paper

### Performance Comparison (Paper Table 1 & Table 2)

| System / Model | Mode | Precision | Recall | Accuracy | F-measure | TP | TN | FP | FN |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **GPT-4V** | Vision | **98.7%** | **99.6%** | **99.2%** | **99.2%** | 991 | 986 | 13 | 4 |
| **Gemini Pro 1.0** | Vision | 78.9% | 99.1% | 89.1% | 87.9% | 789 | 993 | 7 | 211 |
| **GPT-4** | Normal | 98.3% | 98.4% | 98.4% | 98.4% | 984 | 983 | 17 | 16 |
| **GPT-3.5** | Normal | 98.3% | 86.7% | 92.6% | 92.1% | 867 | 985 | 15 | 133 |
| **Llama 2 70B** | Normal | 78.4% | 66.4% | 74.1% | 71.9% | 664 | 817 | 183 | 336 |
| **Gemini Pro 1.0**| Normal | 90.5% | 95.6% | 93.2% | 93.0% | 905 | 958 | 42 | 95 |
| **GPT-4** | Simple | 98.4% | 75.5% | 87.2% | 85.5% | 755 | 988 | 12 | 245 |
| **GPT-3.5** | Simple | 98.6% | 77.5% | 88.2% | 86.8% | 775 | 989 | 11 | 225 |
| *dnstwist* | Baseline | 31.3% | - | - | - | - | - | - | - |
| *Phishpedia* | Baseline | 26.0% | - | - | - | - | - | - | - |
| *PhishStorm* | Baseline | 52.0% | 75.1% | 52.8% | 61.4% | - | - | - | - |

---

## 5. Implementation Roadmap & File Structure

```
BasePaper Implementation/
├── security.py          # Module 1A: URL validation, SSRF guard, IP isolation
├── crawler.py           # Module 1B: Browser crawler using Chrome DevTools Protocol
├── processor.py         # Module 2: HTML simplification (Algorithm 1) & token budgeting
├── ocr_engine.py        # Module 3: OCR text extraction & font-size simplification
├── prompts.py           # Module 4: Original paper prompt templates (CoT & Simple)
├── detector.py          # Module 5: LLM detection engine (Normal, Vision, Simple)
├── evaluation.py        # Module 6: Evaluation harness, metrics, comparison tables
├── app.py               # Module 7: Streamlit interactive interface
├── tests/
│   ├── test_security.py
│   ├── test_crawler.py
│   ├── test_processor.py
│   ├── test_ocr.py
│   └── test_detector.py
├── requirements.txt     # Python dependencies
├── .env.example         # Configuration and API key template
└── README.md            # Execution and verification guide
```

---

## 6. Detailed Plan for First Module: Security & Web Crawling

### Module 1 Goals:
1. `security.py`:
   * Validate scheme (`http`, `https`).
   * Prevent SSRF: resolve hostname and verify destination IP is not in RFC 1918 private subnets, loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, AWS/cloud metadata, or IPv6 equivalents.
   * Defang/refang utility for safe display of phishing links.
2. `crawler.py`:
   * Directly launch/connect to Google Chrome via Chrome DevTools Protocol (`--remote-debugging-port`).
   * Emulate `chrome_windows` and `safari_iphone` with realistic User-Agents and viewports.
   * Execute JavaScript and wait for DOM stabilization.
   * Extract: Final redirected URL, browser-rendered DOM HTML, and PNG screenshot.
   * Provide comprehensive timeout and error handling.
