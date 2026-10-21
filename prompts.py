"""
ChatPhishDetector - Prompt Engineering Subsystem (Module 4)
Implements Prompt Template 1 (Normal & Vision modes) and Prompt Template 2 (Simple mode)
strictly as presented in Section III-B, III-D, and Section V-A1 of the IEEE base paper.
Includes prompt injection mitigation via delimiter isolation (Section VI-A).
"""

from typing import Optional


# ==============================================================================
# Prompt Template 1: Normal Mode (Text-based, with simplified HTML & OCR text)
# ==============================================================================
PROMPT_TEMPLATE_1_NORMAL = """You are a web programmer and security expert tasked with examining a web page to determine if it is a phishing site or a legitimate site. To complete this task, follow these sub-tasks:
1. Analyze the HTML, URL, and OCR-extracted text for any SE techniques often used in phishing attacks. Point out any suspicious elements found in the HTML, URL, or text.
2. Identify the brand name. If the HTML appears to resemble a legitimate web page, verify if the URL matches the legitimate domain name associated with the brand, if known.
3. State your conclusion on whether the site is a phishing site or a legitimate one, and explain your reasoning. If there is insufficient evidence to make a determination, answer "unknown".
4. Submit your findings as JSON-formatted output with the following keys:
- phishing_score: int (indicates phishing risk on a scale of 0 to 10)
- brands: str (identified brand name or None if not applicable)
- phishing: boolean (whether the site is a phishing site or a legitimate site)
- suspicious_domain: boolean (whether the domain name is suspected to be not legitimate)
Limitations:
- The HTML may be shortened and simplified.
- The OCR-extracted text may not always be accurate.
Examples of social engineering techniques:
- Alerting the user to a problem with their account
- Offering unexpected rewards
- Informing the user of a missing package or additional payment required
- Displaying fake security warnings
URL:
{url}
HTML:
```
{html}
```
Text extracted using OCR:
```
{ocr_text}
```"""


# ==============================================================================
# Prompt Template 1: Vision Mode (Multimodal, with simplified HTML & Screenshot)
# ==============================================================================
PROMPT_TEMPLATE_1_VISION = """You are a web programmer and security expert tasked with examining a web page to determine if it is a phishing site or a legitimate site. To complete this task, follow these sub-tasks:
1. Analyze the HTML, URL, and screenshot image for any SE techniques often used in phishing attacks. Point out any suspicious elements found in the HTML, URL, or text.
2. Identify the brand name. If the HTML appears to resemble a legitimate web page, verify if the URL matches the legitimate domain name associated with the brand, if known.
3. State your conclusion on whether the site is a phishing site or a legitimate one, and explain your reasoning. If there is insufficient evidence to make a determination, answer "unknown".
4. Submit your findings as JSON-formatted output with the following keys:
- phishing_score: int (indicates phishing risk on a scale of 0 to 10)
- brands: str (identified brand name or None if not applicable)
- phishing: boolean (whether the site is a phishing site or a legitimate site)
- suspicious_domain: boolean (whether the domain name is suspected to be not legitimate)
Limitations:
- The HTML may be shortened and simplified.
Examples of social engineering techniques:
- Alerting the user to a problem with their account
- Offering unexpected rewards
- Informing the user of a missing package or additional payment required
- Displaying fake security warnings
URL:
{url}
HTML:
```
{html}
```"""


# ==============================================================================
# Prompt Template 2: Simple Baseline Mode (URL Only, Section V-A1)
# ==============================================================================
PROMPT_TEMPLATE_2_SIMPLE = """You are a web programmer and security expert tasked with examining a URL to determine if it is a phishing site or a legitimate site.
Submit your findings as JSON-formatted output with the following keys:
- phishing_score: int (indicates phishing risk on a scale of 0 to 10)
- brands: str (identified brand name or None if not applicable)
- phishing: boolean (whether the site is a phishing site or a legitimate site)
- suspicious_domain: boolean (whether the domain name is suspected to be not legitimate)

URL:
{url}"""


def sanitize_for_prompt(text: str) -> str:
    """
    Mitigates indirect prompt injection attacks (Section VI-A).
    Replaces triple backticks to prevent untrusted website DOM from escaping
    the markdown code enclosure.
    """
    if not text:
        return ""
    # Defuse triple backticks inside content
    return text.replace("```", "'''")


def build_normal_mode_prompt(url: str, simplified_html: str, simplified_ocr_text: str) -> str:
    """Constructs Prompt Template 1 for Normal Mode."""
    clean_html = sanitize_for_prompt(simplified_html)
    clean_ocr = sanitize_for_prompt(simplified_ocr_text)
    return PROMPT_TEMPLATE_1_NORMAL.format(
        url=url.strip(),
        html=clean_html.strip(),
        ocr_text=clean_ocr.strip(),
    )


def build_vision_mode_prompt(url: str, simplified_html: str) -> str:
    """Constructs Prompt Template 1 for Vision Mode (screenshot image passed separately)."""
    clean_html = sanitize_for_prompt(simplified_html)
    return PROMPT_TEMPLATE_1_VISION.format(
        url=url.strip(),
        html=clean_html.strip(),
    )


def build_simple_mode_prompt(url: str) -> str:
    """Constructs Prompt Template 2 for Simple Mode (URL only)."""
    return PROMPT_TEMPLATE_2_SIMPLE.format(
        url=url.strip(),
    )
