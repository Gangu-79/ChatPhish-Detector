"""
ChatPhishDetector - OCR & Screenshot Processing Subsystem (Module 3)
Implements Section III-D ("SIMPLIFYING OCR-EXTRACTED TEXT") from the IEEE base paper.
- Normal Mode: Extracts text from screenshots and simplifies text by font size descending (<= 500 tokens).
- Vision Mode: Formats screenshot image as base64 payload for multimodal LLM analysis.
"""

import base64
import io
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple
from PIL import Image

from processor import count_tokens

# Maximum tokens allocated for OCR-extracted text in Section III-B
MAX_OCR_TOKENS = 500


@dataclass
class OCRTextBlock:
    """Represents a text line/segment with its rendered font size."""
    text: str
    font_size: float  # Estimated from bounding box height (pixels)
    token_count: int = 0

    def __post_init__(self):
        if not self.token_count:
            self.token_count = count_tokens(self.text)


class OCREngine:
    """
    Multimodal & OCR engine.
    Supports Azure Cognitive Services Vision (used in paper Section IV-A),
    local Tesseract OCR, or lightweight fallback image extraction.
    """

    def __init__(
        self,
        azure_key: Optional[str] = None,
        azure_endpoint: Optional[str] = None,
    ):
        self.azure_key = azure_key or os.getenv("AZURE_VISION_KEY")
        self.azure_endpoint = azure_endpoint or os.getenv("AZURE_VISION_ENDPOINT")

    def extract_text_blocks(self, screenshot_bytes: bytes) -> List[OCRTextBlock]:
        """
        Extracts visible text lines along with their approximate font size (bounding box height).
        """
        if not screenshot_bytes:
            return []

        # 1. Try Azure Cognitive Services if configured (paper's exact tool)
        if self.azure_key and self.azure_endpoint:
            try:
                return self._extract_azure_ocr(screenshot_bytes)
            except Exception as e:
                print(f"[!] Azure OCR error: {e}. Falling back to local OCR.")

        # 2. Try pytesseract if available
        try:
            import pytesseract
            image = Image.open(io.BytesIO(screenshot_bytes))
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            blocks = []
            n_boxes = len(data["text"])
            for i in range(n_boxes):
                text = data["text"][i].strip()
                if text:
                    height = float(data["height"][i])
                    blocks.append(OCRTextBlock(text=text, font_size=height))
            if blocks:
                return blocks
        except Exception:
            pass

        # 3. Fallback: Return empty or simple text placeholder if no external OCR binary is found
        return []

    def _extract_azure_ocr(self, screenshot_bytes: bytes) -> List[OCRTextBlock]:
        """Calls Azure Computer Vision Read API (exact paper tool)."""
        import requests
        url = f"{self.azure_endpoint.rstrip('/')}/vision/v3.2/read/analyze"
        headers = {
            "Ocp-Apim-Subscription-Key": self.azure_key,
            "Content-Type": "application/octet-stream",
        }
        resp = requests.post(url, headers=headers, data=screenshot_bytes)
        resp.raise_for_status()

        # Poll operation location
        op_url = resp.headers["Operation-Location"]
        import time
        for _ in range(20):
            time.sleep(0.5)
            check = requests.get(op_url, headers={"Ocp-Apim-Subscription-Key": self.azure_key})
            res_json = check.json()
            if res_json.get("status") == "succeeded":
                blocks = []
                for read_res in res_json["analyzeResult"]["readResults"]:
                    for line in read_res["lines"]:
                        text = line["text"]
                        bbox = line["boundingBox"]
                        # Approximate height = bottom_y - top_y
                        height = abs(bbox[7] - bbox[1])
                        blocks.append(OCRTextBlock(text=text, font_size=float(height)))
                return blocks
            elif res_json.get("status") == "failed":
                raise RuntimeError("Azure OCR operation failed.")

        return []


def simplify_ocr_text(blocks: List[OCRTextBlock], max_tokens: int = MAX_OCR_TOKENS) -> str:
    """
    Implements Section III-D:
    "Specifically, it examines the font size of the identified text by the OCR
    and removes sentences starting from the smallest font size. This process is
    repeated until the number of tokens in the text falls below the predefined threshold."
    """
    if not blocks:
        return ""

    # Sort blocks by font size descending (largest headings/alerts prioritized)
    # Larger font sizes correspond to brand logos, headers, warning messages.
    sorted_blocks = sorted(blocks, key=lambda b: b.font_size, reverse=True)

    # Greedily include highest font-size items until max_tokens is reached
    included_blocks = []
    current_tokens = 0

    for block in sorted_blocks:
        if current_tokens + block.token_count <= max_tokens:
            included_blocks.append(block)
            current_tokens += block.token_count
        else:
            # Drop smaller font-size sentences
            continue

    if not included_blocks:
        return ""

    # Join preserved text segments
    return " \n".join(b.text for b in included_blocks)


def prepare_screenshot_for_vision(
    screenshot_bytes: bytes,
    target_width: int = 1065,
    target_height: int = 1500,
) -> str:
    """
    Prepares screenshot for Multimodal LLMs in Vision Mode (Section III-C & V-C2).
    Resizes if needed to paper dimensions (1065 x 1500 px) and returns base64 data URI.
    """
    if not screenshot_bytes:
        return ""

    image = Image.open(io.BytesIO(screenshot_bytes))
    if image.mode != "RGB":
        image = image.convert("RGB")

    # Paper dimensions: ~1065 x 1500 pixels (~1,105 tokens in GPT-4V)
    # We maintain aspect ratio while fitting within max bounds
    image.thumbnail((target_width, target_height), Image.Resampling.LANCZOS)

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    b64_str = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"
