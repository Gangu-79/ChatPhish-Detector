"""
Unit tests for Module 2: HTML Simplification (processor.py)
Verifies implementation of Algorithm 1 from Section III-C of the IEEE base paper.
"""

import unittest
from bs4 import BeautifulSoup
from processor import simplify_html, count_tokens, MAX_HTML_TOKENS


class TestHTMLProcessor(unittest.TestCase):
    """Tests Algorithm 1 implementation."""

    def test_strip_scripts_styles_comments(self):
        html = """
        <html>
            <head>
                <style>body { color: red; }</style>
                <script>alert("phishing");</script>
                <!-- This is a secret attacker comment -->
                <title>Secure Banking Login</title>
            </head>
            <body>
                <h1>Welcome to Bank</h1>
            </body>
        </html>
        """
        simplified = simplify_html(html)
        self.assertNotIn("body { color: red; }", simplified)
        self.assertNotIn("alert(", simplified)
        self.assertNotIn("secret attacker comment", simplified)
        self.assertIn("Secure Banking Login", simplified)
        self.assertIn("Welcome to Bank", simplified)

    def test_unwrap_unimportant_elements(self):
        # div, span, nav should be unwrapped if above token limit, leaving important tags intact
        padding = " ".join([f"<span>word_{i}</span>" for i in range(300)])
        html = f"""
        <html>
            <body>
                <div class="wrapper">
                    <section class="banner">
                        <p>Please enter your <strong>password</strong></p>
                    </section>
                </div>
                {padding}
            </body>
        </html>
        """
        # Set max_tokens to 1000: larger than unwrapped result, but smaller than original if input was large
        simplified = simplify_html(html, max_tokens=1000)
        self.assertNotIn('<div class="wrapper">', simplified)
        self.assertNotIn('<section class="banner">', simplified)
        self.assertIn("password", simplified)

    def test_shorten_base64_and_long_urls(self):
        huge_base64 = "data:image/png;base64," + "A" * 6000
        long_url = "https://phishing.example.com/login?token=" + "x" * 200
        padding = " ".join([f"<p>Disclaimer line {i}</p>" for i in range(200)])
        html = f"""
        <html>
            <body>
                <img src="{huge_base64}" alt="Bank Logo" />
                <a href="{long_url}">Click here to verify account</a>
                {padding}
            </body>
        </html>
        """
        # html exceeds 2500 tokens, triggering shortening
        simplified = simplify_html(html, max_tokens=1500)
        self.assertNotIn("A" * 500, simplified)
        self.assertIn("[shortened_base64_data]", simplified)
        self.assertIn("...", simplified)
        self.assertIn("Click here to verify account", simplified)

    def test_large_html_midpoint_pruning_token_limit(self):
        # Generate an HTML document with 500 paragraphs (~10,000 tokens)
        paragraphs = "\n".join([f"<p>Account transaction notice number {i} regarding verification.</p>" for i in range(500)])
        huge_html = f"""
        <html>
            <head><title>Account Center</title></head>
            <body>
                <h1>Account Notification Hub</h1>
                {paragraphs}
            </body>
        </html>
        """
        initial_tokens = count_tokens(huge_html)
        self.assertGreater(initial_tokens, 3000)

        simplified = simplify_html(huge_html, max_tokens=MAX_HTML_TOKENS)
        final_tokens = count_tokens(simplified)

        self.assertLessEqual(final_tokens, MAX_HTML_TOKENS)
        self.assertIn("Account Center", simplified)
        self.assertIn("Account Notification Hub", simplified)


if __name__ == "__main__":
    unittest.main()
