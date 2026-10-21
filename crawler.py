"""
ChatPhishDetector - Web Crawler Subsystem (Module 1)
Implements browser automation using Chrome DevTools Protocol (CDP) as specified in Section III-A.
Collects:
  1. Final reached URL after redirects
  2. Browser-rendered HTML after JavaScript execution
  3. Screenshot image (PNG bytes)
Emulates two environments:
  - Google Chrome on Windows
  - Safari on iPhone
"""

import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
import requests
import websockets

from security import validate_url, extract_domain


@dataclass
class BrowserProfile:
    name: str
    user_agent: str
    width: int
    height: int
    mobile: bool
    platform: str
    scale_factor: float = 1.0


# Environment Profiles specified in Section III-A
PROFILES: Dict[str, BrowserProfile] = {
    "chrome_windows": BrowserProfile(
        name="chrome_windows",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        width=1280,
        height=800,
        mobile=False,
        platform="Win32",
        scale_factor=1.0,
    ),
    "safari_iphone": BrowserProfile(
        name="safari_iphone",
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.4 Mobile/15E148 Safari/604.1"
        ),
        width=390,
        height=844,
        mobile=True,
        platform="iPhone",
        scale_factor=3.0,
    ),
}


@dataclass
class CrawlResult:
    """Represents the tuple (u_i, h_i, s_i) described in Section III."""
    input_url: str
    final_url: str
    html: str
    screenshot_bytes: bytes
    environment: str
    is_redirected: bool
    status_code: int = 200
    error: Optional[str] = None

    def save_screenshot(self, filepath: str) -> None:
        """Helper to save the captured screenshot to disk."""
        if self.screenshot_bytes:
            with open(filepath, "wb") as f:
                f.write(self.screenshot_bytes)

    def save_html(self, filepath: str) -> None:
        """Helper to save the rendered HTML to disk."""
        if self.html:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self.html)


def find_chrome_executable() -> Optional[str]:
    """Locates the Google Chrome binary on Windows or system PATH."""
    env_path = os.getenv("CHROME_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    standard_paths = [
        # Windows paths
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe"),
        # Linux / Cloud Hosting (Render, Debian, Ubuntu) paths
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ]
    for p in standard_paths:
        if os.path.exists(p):
            return p

    # Check PATH
    sh_chrome = (
        shutil.which("google-chrome") or 
        shutil.which("chrome") or 
        shutil.which("chromium") or 
        shutil.which("chromium-browser")
    )
    return sh_chrome


def find_free_port() -> int:
    """Finds an unused localhost TCP port for the CDP server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ChromeDevToolsCrawler:
    """
    Crawls websites via Chrome DevTools Protocol (CDP).
    Automates Google Chrome directly without Selenium or standard Puppeteer
    to reduce bot-detection footprints as per paper Section III-A.
    """

    def __init__(self, chrome_path: Optional[str] = None):
        self.chrome_path = chrome_path or find_chrome_executable()
        if not self.chrome_path or not os.path.exists(self.chrome_path):
            raise FileNotFoundError(
                f"Google Chrome executable not found at '{self.chrome_path}'. "
                "Please verify Chrome is installed or set CHROME_PATH in .env"
            )

    async def _send_cdp(self, ws, method: str, params: Optional[Dict[str, Any]] = None, msg_id: int = 1) -> Dict[str, Any]:
        """Sends a JSON-RPC message over WebSocket to Chrome DevTools Protocol."""
        payload = {"id": msg_id, "method": method, "params": params or {}}
        await ws.send(json.dumps(payload))
        
        while True:
            resp_raw = await ws.recv()
            resp = json.loads(resp_raw)
            if resp.get("id") == msg_id:
                if "error" in resp:
                    raise RuntimeError(f"CDP Error on '{method}': {resp['error']}")
                return resp.get("result", {})

    async def _crawl_cdp(
        self,
        url: str,
        profile: BrowserProfile,
        timeout: int = 30,
        settle_delay: float = 3.0,
    ) -> CrawlResult:
        """Performs CDP crawl via WebSocket connection to Chrome."""
        port = find_free_port()
        temp_dir = tempfile.mkdtemp(prefix="chatphish_cdp_")
        
        chrome_args = [
            self.chrome_path,
            "--headless=new",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={temp_dir}",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-extensions",
            "--mute-audio",
            "--hide-scrollbars",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "about:blank",
        ]

        proc = subprocess.Popen(
            chrome_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        ws_url = None
        try:
            # Poll for CDP endpoint readiness
            start_poll = time.time()
            while time.time() - start_poll < 10:
                try:
                    r = requests.get(f"http://127.0.0.1:{port}/json/version", timeout=1)
                    if r.status_code == 200:
                        ws_url = r.json().get("webSocketDebuggerUrl")
                        break
                except Exception:
                    await asyncio.sleep(0.2)

            if not ws_url:
                raise TimeoutError(f"Could not connect to Chrome CDP endpoint on port {port}.")

            # Connect to browser WebSocket
            async with websockets.connect(ws_url, max_size=50 * 1024 * 1024) as ws:
                # 1. Create a new target page
                new_page_res = await self._send_cdp(ws, "Target.createTarget", {"url": "about:blank"}, msg_id=1)
                target_id = new_page_res.get("targetId")
                
                # Fetch page's specific webSocketDebuggerUrl
                targets = requests.get(f"http://127.0.0.1:{port}/json").json()
                page_ws_url = None
                for t in targets:
                    if t.get("id") == target_id:
                        page_ws_url = t.get("webSocketDebuggerUrl")
                        break

                if not page_ws_url:
                    page_ws_url = f"ws://127.0.0.1:{port}/devtools/page/{target_id}"

                # Connect directly to page CDP session
                async with websockets.connect(page_ws_url, max_size=50 * 1024 * 1024) as page_ws:
                    # 2. Enable domains
                    await self._send_cdp(page_ws, "Page.enable", msg_id=2)
                    await self._send_cdp(page_ws, "Network.enable", msg_id=3)
                    await self._send_cdp(page_ws, "Runtime.enable", msg_id=4)

                    # 3. Configure Emulated Environment (User-Agent & Viewport)
                    await self._send_cdp(
                        page_ws,
                        "Network.setUserAgentOverride",
                        {
                            "userAgent": profile.user_agent,
                            "acceptLanguage": "en-US,en;q=0.9",
                            "platform": profile.platform,
                        },
                        msg_id=5,
                    )

                    await self._send_cdp(
                        page_ws,
                        "Emulation.setDeviceMetricsOverride",
                        {
                            "width": profile.width,
                            "height": profile.height,
                            "deviceScaleFactor": profile.scale_factor,
                            "mobile": profile.mobile,
                        },
                        msg_id=6,
                    )

                    # 4. Navigate to Target URL
                    await self._send_cdp(page_ws, "Page.navigate", {"url": url}, msg_id=7)

                    # 5. Wait for page load and JavaScript execution
                    # Allow JS execution and dynamic DOM elements to render
                    await asyncio.sleep(settle_delay)

                    # 6. Extract Final Reached URL (handling client/server redirects)
                    eval_url = await self._send_cdp(
                        page_ws,
                        "Runtime.evaluate",
                        {"expression": "window.location.href"},
                        msg_id=8,
                    )
                    final_url = eval_url.get("result", {}).get("value", url)

                    # 7. Extract Rendered HTML (Browser-rendered HTML after JS execution)
                    eval_html = await self._send_cdp(
                        page_ws,
                        "Runtime.evaluate",
                        {"expression": "document.documentElement.outerHTML"},
                        msg_id=9,
                    )
                    rendered_html = eval_html.get("result", {}).get("value", "")

                    # 8. Capture Screenshot Image
                    shot_res = await self._send_cdp(
                        page_ws,
                        "Page.captureScreenshot",
                        {"format": "png", "fromSurface": True},
                        msg_id=10,
                    )
                    base64_data = shot_res.get("data", "")
                    screenshot_bytes = base64.b64decode(base64_data) if base64_data else b""

                    is_redirected = (
                        extract_domain(url).lower() != extract_domain(final_url).lower() or
                        url.rstrip("/") != final_url.rstrip("/")
                    )

                    return CrawlResult(
                        input_url=url,
                        final_url=final_url,
                        html=rendered_html,
                        screenshot_bytes=screenshot_bytes,
                        environment=profile.name,
                        is_redirected=is_redirected,
                        status_code=200,
                        error=None,
                    )

        finally:
            # Terminate Chrome process & clean temp directory
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    def crawl(
        self,
        url: str,
        environment: str = "chrome_windows",
        timeout: int = 30,
        settle_delay: float = 3.0,
    ) -> CrawlResult:
        """
        Synchronous public crawling entry point.
        
        Args:
            url: Target URL to crawl.
            environment: 'chrome_windows' or 'safari_iphone'.
            timeout: Maximum crawling duration in seconds.
            settle_delay: Time in seconds to wait for JavaScript to execute.
        
        Returns:
            CrawlResult containing final_url, html, and screenshot_bytes.
        """
        # Step 1: Security Validation & SSRF Prevention
        is_safe, canonical_url, err = validate_url(url)
        if not is_safe:
            return CrawlResult(
                input_url=url,
                final_url=url,
                html="",
                screenshot_bytes=b"",
                environment=environment,
                is_redirected=False,
                status_code=403,
                error=f"Security Validation Block: {err}",
            )

        if environment not in PROFILES:
            profile = PROFILES["chrome_windows"]
        else:
            profile = PROFILES[environment]

        # Step 2: Execute browser crawl
        try:
            return asyncio.run(
                self._crawl_cdp(
                    canonical_url,
                    profile,
                    timeout=timeout,
                    settle_delay=settle_delay,
                )
            )
        except Exception as e:
            return CrawlResult(
                input_url=canonical_url,
                final_url=canonical_url,
                html="",
                screenshot_bytes=b"",
                environment=environment,
                is_redirected=False,
                status_code=500,
                error=f"Crawling Error: {str(e)}",
            )
