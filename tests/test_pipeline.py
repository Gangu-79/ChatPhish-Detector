"""
Integration tests for complete ChatPhishDetector end-to-end pipeline:
Crawler (CDP) -> HTML Simplification -> OCR / Screenshot Prep -> LLM Phishing Detector
"""

import unittest
from crawler import ChromeDevToolsCrawler, find_chrome_executable
from processor import simplify_html, count_tokens, MAX_HTML_TOKENS
from ocr_engine import OCREngine, simplify_ocr_text, prepare_screenshot_for_vision
from detector import PhishingDetector
from security import validate_url


class TestEndToEndPipeline(unittest.TestCase):
    """Verifies complete multi-module pipeline execution."""

    def setUp(self):
        self.chrome_exe = find_chrome_executable()
        self.assertIsNotNone(self.chrome_exe, "Chrome must be installed for end-to-end test.")
        self.crawler = ChromeDevToolsCrawler(self.chrome_exe)
        self.detector = PhishingDetector()
        self.ocr_engine = OCREngine()

    def test_full_pipeline_normal_mode(self):
        target_url = "https://example.com"

        # 1. Security Validation
        is_safe, canonical_url, err = validate_url(target_url)
        self.assertTrue(is_safe)
        self.assertIsNone(err)

        # 2. Browser Crawl via Chrome DevTools Protocol
        crawl_res = self.crawler.crawl(canonical_url, environment="chrome_windows", settle_delay=2.0)
        self.assertEqual(crawl_res.status_code, 200)
        self.assertIn("Example Domain", crawl_res.html)

        # 3. HTML Simplification (Algorithm 1)
        simplified_html = simplify_html(crawl_res.html, max_tokens=MAX_HTML_TOKENS)
        self.assertLessEqual(count_tokens(simplified_html), MAX_HTML_TOKENS)

        # 4. OCR Extraction & Font-size Simplification
        ocr_blocks = self.ocr_engine.extract_text_blocks(crawl_res.screenshot_bytes)
        simplified_ocr = simplify_ocr_text(ocr_blocks, max_tokens=500)
        self.assertLessEqual(count_tokens(simplified_ocr), 500)

        # 5. Phishing Detection (Normal Mode)
        result = self.detector.detect_normal_mode(
            url=crawl_res.final_url,
            raw_html=simplified_html,
            ocr_blocks=ocr_blocks,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.classification_label, "legitimate")
        self.assertFalse(result.is_phishing)
        self.assertLessEqual(result.phishing_score, 3)
        self.assertTrue(len(result.reasoning) > 10)

    def test_full_pipeline_vision_mode(self):
        target_url = "https://example.com"
        crawl_res = self.crawler.crawl(target_url, environment="chrome_windows", settle_delay=2.0)
        self.assertEqual(crawl_res.status_code, 200)

        # Vision Mode detection
        result = self.detector.detect_vision_mode(
            url=crawl_res.final_url,
            raw_html=crawl_res.html,
            screenshot_bytes=crawl_res.screenshot_bytes,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.mode, "vision")
        self.assertEqual(result.classification_label, "legitimate")
        self.assertFalse(result.is_phishing)


if __name__ == "__main__":
    unittest.main()
