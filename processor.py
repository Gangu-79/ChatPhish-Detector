"""
ChatPhishDetector - HTML Simplification Subsystem (Module 2)
Implements Algorithm 1 ("Simplifying HTML") from Section III-C of the IEEE base paper.
Limits HTML to 2,500 tokens while preserving crucial phishing and brand identification cues.
"""

import re
from typing import Set, Optional
from bs4 import BeautifulSoup, Comment, Tag
import tiktoken


# Token limit specified in Section III-C and Algorithm 1
MAX_HTML_TOKENS = 2500

# Important tags preserved according to Section III-C:
# "head, title, meta, body, h1, h2, h3, h4, h5, h6, p, strong, a, img, hr, 
# table, tbody, tr, th, td, ol, ul, li, ruby, and label"
IMPORTANT_TAGS: Set[str] = {
    "html",  # document container
    "head",
    "title",
    "meta",
    "body",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "strong",
    "a",
    "img",
    "hr",
    "table",
    "tbody",
    "tr",
    "th",
    "td",
    "ol",
    "ul",
    "li",
    "ruby",
    "label",
    "form",   # Mentioned in text: "Additionally, the form element used for inputting login information... are crucial"
    "input",  # preserved within login forms for credential theft analysis
}

# Self-closing or void tags that naturally do not contain inner text
VOID_OR_STANDALONE_TAGS: Set[str] = {"img", "hr", "meta", "input"}


class TokenCounter:
    """Calculates token counts matching the LLM tokenizers (tiktoken cl100k_base)."""

    def __init__(self, encoding_name: str = "cl100k_base"):
        try:
            self._encoder = tiktoken.get_encoding(encoding_name)
        except Exception:
            self._encoder = None

    def count(self, text: str) -> int:
        """Returns the number of tokens in the given text."""
        if not text:
            return 0
        if self._encoder:
            try:
                return len(self._encoder.encode(text, disallowed_special=()))
            except Exception:
                pass
        # Fallback estimation: average ~4 characters per token
        return max(1, len(text) // 4)


# Global tokenizer instance
_tokenizer = TokenCounter()


def count_tokens(text: str) -> int:
    """Public helper to count tokens in a string."""
    return _tokenizer.count(text)


def shorten_attribute_values(soup: BeautifulSoup, max_url_len: int = 80) -> None:
    """
    Step 9 of Algorithm 1:
    - Shortens src attribute in img elements encoded in base64.
    - Shortens href attribute in a elements containing lengthy URLs.
    """
    # 1. Shorten base64 src in img tags
    for img in soup.find_all("img"):
        src = img.get("src", "")
        if isinstance(src, str) and "data:image" in src and "base64" in src:
            # Replace long base64 string with compact indicator
            mime = src.split(";")[0] if ";" in src else "data:image/png"
            img["src"] = f"{mime};base64,[shortened_base64_data]"

    # 2. Shorten lengthy href in a tags
    for a in soup.find_all("a"):
        href = a.get("href", "")
        if isinstance(href, str) and len(href) > max_url_len:
            # Preserve protocol and domain/path prefix, truncate long query string
            prefix = href[:max_url_len // 2]
            suffix = href[-15:] if len(href) > max_url_len // 2 + 15 else ""
            a["href"] = f"{prefix}...{suffix}"


def remove_elements_without_text(soup: BeautifulSoup) -> None:
    """
    Step 8 of Algorithm 1:
    Removes HTML elements that do not contain text enclosed within tags
    (except standalone/void elements like img, hr, meta, input).
    """
    # Bottom-up traversal to safely remove empty container tags
    for tag in list(soup.find_all()):
        if tag.name not in VOID_OR_STANDALONE_TAGS:
            text = tag.get_text(strip=True)
            # If element has no text and no essential child tags (like img or input)
            if not text:
                has_essential_child = any(
                    child.name in VOID_OR_STANDALONE_TAGS 
                    for child in tag.find_all() 
                    if isinstance(child, Tag)
                )
                if not has_essential_child:
                    tag.decompose()


def unwrap_unimportant_elements(soup: BeautifulSoup) -> None:
    """
    Step 7 of Algorithm 1:
    Unwrap elements except for important tags.
    Unimportant elements are eliminated, and their child elements are
    incorporated into their parent elements.
    """
    for tag in list(soup.find_all()):
        if tag.name not in IMPORTANT_TAGS:
            # tag.unwrap() replaces the tag with its contents
            tag.unwrap()


def prune_midpoint_element(soup: BeautifulSoup) -> bool:
    """
    Step 15 of Algorithm 1:
    Removes an HTML element from the midpoint of the processed HTML.
    Returns True if an element was removed, False if no elements could be pruned.
    """
    elements = soup.find_all(lambda t: t.name not in ("html", "head", "body", "title"))
    if not elements:
        return False

    midpoint_idx = len(elements) // 2
    target = elements[midpoint_idx]
    target.decompose()
    return True


def simplify_html(input_html: str, max_tokens: int = MAX_HTML_TOKENS) -> str:
    """
    Implements Algorithm 1 ("Simplifying HTML") from Section III-C.
    
    Args:
        input_html: Raw browser-rendered HTML string.
        max_tokens: Maximum allowed token count (default: 2,500).
        
    Returns:
        Simplified HTML string guaranteed to satisfy T(S(H)) <= max_tokens.
    """
    if not input_html or not isinstance(input_html, str):
        return ""

    # Normalize whitespace before parsing
    cleaned_html = re.sub(r"\r\n", "\n", input_html)

    # 1. Parse HTML
    try:
        soup = BeautifulSoup(cleaned_html, "html.parser")
    except Exception:
        soup = BeautifulSoup(cleaned_html, "html5lib")

    # 2. Remove style, script, and comment elements (Line 2 of Alg. 1)
    for tag in soup.find_all(["style", "script", "noscript", "svg", "canvas"]):
        tag.decompose()

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    # Clean intermediate string
    processed_html = str(soup)

    # 3. Check token budget (Line 4)
    if count_tokens(processed_html) < max_tokens:
        return processed_html

    # 4. Unwrap elements except for important tags (Line 7)
    unwrap_unimportant_elements(soup)

    # 5. Remove elements without text content (Line 8)
    remove_elements_without_text(soup)

    # 6. Shorten href in a tags and src in img tags (Line 9)
    shorten_attribute_values(soup)

    processed_html = str(soup)

    # 7. Check token budget (Line 11)
    if count_tokens(processed_html) < max_tokens:
        return processed_html

    # 8. While lengthToken(processedHTML) > max_tokens do midpoint pruning (Lines 14-17)
    iterations = 0
    max_iterations = 500  # safeguard against infinite loop
    while count_tokens(processed_html) > max_tokens and iterations < max_iterations:
        success = prune_midpoint_element(soup)
        if not success:
            # If no more elements can be removed individually, truncate inner text safely
            break
        processed_html = str(soup)
        iterations += 1

    # Emergency fallback if still exceeding max_tokens
    if count_tokens(processed_html) > max_tokens:
        lines = processed_html.splitlines()
        mid = len(lines) // 2
        while count_tokens(processed_html) > max_tokens and len(lines) > 4:
            mid = len(lines) // 2
            lines.pop(mid)
            processed_html = "\n".join(lines)

    return processed_html
