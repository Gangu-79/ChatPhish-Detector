"""
Unit tests for Module 5: LLM Detection Engine (detector.py)
Verifies:
  - Decision Rule: Phishing if phishing=True OR suspicious_domain=True
  - Separation of Chain-of-Thought (CoT) reasoning and JSON parsing
  - Detection across Normal, Vision, and Simple modes
"""

import unittest
from detector import (
    extract_json_from_response,
    apply_paper_classification_rule,
    PhishingDetector,
)
from ocr_engine import OCRTextBlock


class TestDetector(unittest.TestCase):
    """Tests the ChatPhishDetector decision logic and classification engine."""

    def test_extract_json_from_response(self):
        sample_response = """
        1. Analyze elements: The HTML exhibits a fake account suspension alert.
        2. Brand name: The brand is PayPal. The domain is paypal-update.com, which is not paypal.com.
        3. Conclusion: This is definitely a phishing site designed to steal user passwords.
        4. JSON-formatted output:
        ```json
        {
            "phishing_score": 9,
            "brands": "PayPal",
            "phishing": true,
            "suspicious_domain": true
        }
        ```
        """
        reasoning, data = extract_json_from_response(sample_response)
        self.assertIn("The HTML exhibits a fake account suspension alert", reasoning)
        self.assertEqual(data.get("phishing_score"), 9)
        self.assertEqual(data.get("brands"), "PayPal")
        self.assertTrue(data.get("phishing"))
        self.assertTrue(data.get("suspicious_domain"))

    def test_classification_decision_rule(self):
        # Rule Case 1: phishing=True, suspicious_domain=False -> Phishing
        label1, is_p1, _, _, _, _, _ = apply_paper_classification_rule(
            {"phishing": True, "suspicious_domain": False, "phishing_score": 7}
        )
        self.assertEqual(label1, "phishing")
        self.assertTrue(is_p1)

        # Rule Case 2: phishing=False, suspicious_domain=True -> Phishing
        label2, is_p2, _, _, _, _, _ = apply_paper_classification_rule(
            {"phishing": False, "suspicious_domain": True, "phishing_score": 6}
        )
        self.assertEqual(label2, "phishing")
        self.assertTrue(is_p2)

        # Rule Case 3: phishing=False, suspicious_domain=False -> Legitimate
        label3, is_p3, _, _, _, _, _ = apply_paper_classification_rule(
            {"phishing": False, "suspicious_domain": False, "phishing_score": 1}
        )
        self.assertEqual(label3, "legitimate")
        self.assertFalse(is_p3)

    def test_phishing_scenario_detection(self):
        detector = PhishingDetector()
        phishing_url = "https://paypal-verify-account.security-update.com/login"
        phishing_html = """
        <html>
            <head><title>PayPal - Security Alert</title></head>
            <body>
                <h1>Your PayPal Account Has Been Suspended!</h1>
                <p>We detected unauthorized activity. Please enter your password and credit card number immediately.</p>
                <form action="/steal">
                    <input type="password" name="pwd" />
                    <input type="text" name="cc" />
                </form>
            </body>
        </html>
        """
        ocr_blocks = [
            OCRTextBlock("PayPal Security Alert", font_size=32.0),
            OCRTextBlock("Your PayPal Account Has Been Suspended", font_size=24.0),
        ]

        result = detector.detect_normal_mode(
            url=phishing_url,
            raw_html=phishing_html,
            ocr_blocks=ocr_blocks,
        )

        self.assertTrue(result.is_phishing)
        self.assertEqual(result.classification_label, "phishing")
        self.assertEqual(result.brands, "PayPal")
        self.assertGreaterEqual(result.phishing_score, 5)
        self.assertIn("PayPal", result.reasoning)

    def test_legitimate_scenario_detection(self):
        detector = PhishingDetector()
        benign_url = "https://example.com"
        benign_html = """
        <html>
            <head><title>Example Domain</title></head>
            <body>
                <h1>Example Domain</h1>
                <p>This domain is for use in illustrative examples in documents.</p>
            </body>
        </html>
        """
        result = detector.detect_normal_mode(
            url=benign_url,
            raw_html=benign_html,
        )

        self.assertFalse(result.is_phishing)
        self.assertEqual(result.classification_label, "legitimate")
        self.assertLessEqual(result.phishing_score, 3)


if __name__ == "__main__":
    unittest.main()
