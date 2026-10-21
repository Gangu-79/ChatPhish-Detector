"""
Unit tests for Module 3: OCR & Screenshot Processing (ocr_engine.py)
Verifies Section III-D font-size based simplification and Vision Mode formatting.
"""

import io
import unittest
from PIL import Image
from ocr_engine import (
    OCRTextBlock,
    simplify_ocr_text,
    prepare_screenshot_for_vision,
    MAX_OCR_TOKENS,
)
from processor import count_tokens


class TestOCREngine(unittest.TestCase):
    """Verifies OCR text font-size filtering and image preparation."""

    def test_font_size_simplification(self):
        # Create blocks with varying font sizes
        header_block = OCRTextBlock(text="URGENT: BANK OF AMERICA SECURITY ALERT", font_size=42.0)
        subhead_block = OCRTextBlock(text="Your account has been temporarily locked due to suspicious activity.", font_size=24.0)
        
        # Create many small footer blocks (low font size: 8.0)
        footer_blocks = [
            OCRTextBlock(text=f"Legal disclaimer terms of use paragraph number {i} with privacy notices.", font_size=8.0)
            for i in range(100)
        ]

        all_blocks = [header_block] + footer_blocks + [subhead_block]

        # Prioritize with small token budget (e.g., 50 tokens)
        simplified = simplify_ocr_text(all_blocks, max_tokens=50)

        # High font-size blocks must be retained
        self.assertIn("BANK OF AMERICA", simplified)
        self.assertIn("temporarily locked", simplified)
        
        # Total tokens must be within budget
        self.assertLessEqual(count_tokens(simplified), 50)

    def test_prepare_screenshot_for_vision(self):
        # Create a mock screenshot image (2000 x 2000 px)
        img = Image.new("RGB", (2000, 2000), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_bytes = buf.getvalue()

        data_uri = prepare_screenshot_for_vision(raw_bytes, target_width=1065, target_height=1500)

        self.assertTrue(data_uri.startswith("data:image/png;base64,"))
        self.assertGreater(len(data_uri), 100)


if __name__ == "__main__":
    unittest.main()
