"""
Tests for Module 1: Security Validation and Chrome DevTools Protocol Crawler
Verifies SSRF defense, Chrome CDP automation, rendered HTML capture, and screenshot extraction.
"""

import os
import unittest
from security import validate_url, defang_url, refang_url, extract_domain
from crawler import ChromeDevToolsCrawler, find_chrome_executable


class TestSecurityValidation(unittest.TestCase):
    """Verifies security filtering against SSRF and private resources."""

    def test_safe_public_url(self):
        is_safe, canonical, err = validate_url("https://example.com")
        self.assertTrue(is_safe)
        self.assertIsNone(err)
        self.assertEqual(canonical, "https://example.com")

    def test_block_localhost_names(self):
        is_safe, _, err = validate_url("http://localhost:8080/admin")
        self.assertFalse(is_safe)
        self.assertIn("localhost", err.lower())

    def test_block_loopback_ip(self):
        is_safe, _, err = validate_url("http://127.0.0.1:5000")
        self.assertFalse(is_safe)
        self.assertIn("localhost", err.lower())

    def test_block_private_rfc1918_ip(self):
        is_safe, _, err = validate_url("http://192.168.1.1/router")
        self.assertFalse(is_safe)
        self.assertIn("blocked/private ip", err.lower())

        is_safe_10, _, _ = validate_url("http://10.0.0.5")
        self.assertFalse(is_safe_10)

    def test_block_cloud_metadata(self):
        is_safe, _, err = validate_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)
        self.assertIn("blocked/private ip", err.lower())

    def test_block_disallowed_scheme(self):
        is_safe, _, err = validate_url("file:///etc/passwd")
        self.assertFalse(is_safe)
        self.assertIn("disallowed scheme", err.lower())

        is_safe_ftp, _, _ = validate_url("ftp://example.com/file.txt")
        self.assertFalse(is_safe_ftp)

    def test_defang_and_refang(self):
        url = "https://secure-login.paypal.com/verify"
        defanged = defang_url(url)
        self.assertIn("[.]", defanged)
        self.assertIn("hxxps://", defanged)
        
        refanged = refang_url(defanged)
        self.assertEqual(refanged, url)


class TestChromeDevToolsCrawler(unittest.TestCase):
    """Verifies Chrome DevTools Protocol browser automation."""

    def setUp(self):
        self.chrome_exe = find_chrome_executable()
        self.assertIsNotNone(self.chrome_exe, "Google Chrome must be installed for CDP crawling.")

    def test_chrome_windows_crawl(self):
        crawler = ChromeDevToolsCrawler(self.chrome_exe)
        target = "https://example.com"
        result = crawler.crawl(target, environment="chrome_windows", timeout=20, settle_delay=2.0)

        self.assertIsNone(result.error, f"Crawl failed with error: {result.error}")
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.final_url.startswith("http"))
        self.assertIn("Example Domain", result.html)
        self.assertIn("<html", result.html.lower())

        # Check screenshot PNG header
        self.assertTrue(len(result.screenshot_bytes) > 1000)
        self.assertTrue(result.screenshot_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

        # Save test output
        os.makedirs("test_output", exist_ok=True)
        result.save_screenshot("test_output/example_desktop.png")
        result.save_html("test_output/example_desktop.html")
        self.assertTrue(os.path.exists("test_output/example_desktop.png"))
        self.assertTrue(os.path.exists("test_output/example_desktop.html"))

    def test_safari_iphone_crawl(self):
        crawler = ChromeDevToolsCrawler(self.chrome_exe)
        target = "https://example.com"
        result = crawler.crawl(target, environment="safari_iphone", timeout=20, settle_delay=2.0)

        self.assertIsNone(result.error, f"Crawl failed with error: {result.error}")
        self.assertEqual(result.environment, "safari_iphone")
        self.assertTrue(len(result.screenshot_bytes) > 1000)

        os.makedirs("test_output", exist_ok=True)
        result.save_screenshot("test_output/example_mobile.png")
        self.assertTrue(os.path.exists("test_output/example_mobile.png"))


if __name__ == "__main__":
    unittest.main()
