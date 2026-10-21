"""
Interactive CLI Runner for Module 1: Website Crawler (Chrome DevTools Protocol)
Allows testing crawling on any URL with either 'chrome_windows' or 'safari_iphone' emulation.

Usage:
    python run_crawler.py https://example.com
    python run_crawler.py https://example.com --env safari_iphone
"""

import argparse
import os
import sys
from crawler import ChromeDevToolsCrawler, PROFILES
from security import validate_url, defang_url


def main():
    parser = argparse.ArgumentParser(
        description="ChatPhishDetector - Module 1: Chrome DevTools Protocol Crawler"
    )
    parser.add_argument("url", help="Target URL to crawl (e.g. https://example.com)")
    parser.add_argument(
        "--env",
        choices=["chrome_windows", "safari_iphone"],
        default="chrome_windows",
        help="Emulation environment profile (default: chrome_windows)",
    )
    parser.add_argument(
        "--output-dir",
        default="crawled_data",
        help="Directory where HTML and screenshots will be saved (default: crawled_data)",
    )
    parser.add_argument(
        "--settle-delay",
        type=float,
        default=3.0,
        help="Delay in seconds to allow JavaScript execution (default: 3.0)",
    )

    args = parser.parse_args()

    print("=" * 70)
    print(" ChatPhishDetector - Module 1: Web Crawler (Chrome DevTools Protocol)")
    print("=" * 70)
    print(f"[*] Target URL       : {args.url}")
    print(f"[*] Environment      : {args.env}")
    print(f"[*] Output Directory : {args.output_dir}")
    print("-" * 70)

    # 1. Security Check
    print("[1/3] Validating URL security & verifying SSRF safety...")
    is_safe, canonical_url, err = validate_url(args.url)
    if not is_safe:
        print(f"[!] SECURITY BLOCK: {err}")
        print("Crawler aborted to prevent unsafe network request.")
        sys.exit(1)
    print(f"[+] Security check PASSED for: {canonical_url}")

    # 2. Browser Crawl
    print(f"[2/3] Automating Chrome via Chrome DevTools Protocol ({args.env})...")
    crawler = ChromeDevToolsCrawler()
    result = crawler.crawl(
        canonical_url,
        environment=args.env,
        settle_delay=args.settle_delay,
    )

    if result.error:
        print(f"[!] Crawling Failed: {result.error}")
        sys.exit(1)

    # 3. Save Artifacts
    os.makedirs(args.output_dir, exist_ok=True)
    domain_clean = result.final_url.split("//")[-1].replace("/", "_").replace(":", "_")[:50]
    html_path = os.path.join(args.output_dir, f"{domain_clean}_{args.env}.html")
    img_path = os.path.join(args.output_dir, f"{domain_clean}_{args.env}.png")

    result.save_html(html_path)
    result.save_screenshot(img_path)

    print("-" * 70)
    print("[3/3] Crawl Completed Successfully!")
    print(f"[+] Final URL Reached  : {result.final_url}")
    print(f"[+] Defanged URL       : {defang_url(result.final_url)}")
    print(f"[+] Redirected?        : {'Yes' if result.is_redirected else 'No'}")
    print(f"[+] Rendered DOM Size  : {len(result.html):,} characters")
    print(f"[+] Screenshot Size    : {len(result.screenshot_bytes):,} bytes")
    print(f"[+] Saved HTML File    : {html_path}")
    print(f"[+] Saved Screenshot   : {img_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
