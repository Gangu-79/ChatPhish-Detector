"""
ChatPhishDetector - Security & URL Validation Subsystem
Provides SSRF protection, IP blacklisting, URL sanitization, and defanging.
Implements security safeguards required when crawling potentially malicious phishing domains.
"""

import ipaddress
import socket
from typing import Tuple, Optional
from urllib.parse import urlparse


# Disallowed IPv4 and IPv6 network blocks (SSRF Protection)
DISALLOWED_NETWORKS = [
    # IPv4 Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # IPv4 Private Networks (RFC 1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Cloud Metadata & Link-Local (AWS, Azure, GCP metadata: 169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    # Current network / Broadcast / Multicast / Reserved
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"), # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("240.0.0.0/4"),    # Reserved
    # IPv6 Loopback & Link-local / ULA
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
]


def is_ip_disallowed(ip_str: str) -> bool:
    """
    Check if an IP address string belongs to any private, loopback, or reserved network block.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # Check standard properties
        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            ip_obj.is_multicast or 
            ip_obj.is_reserved or 
            ip_obj.is_unspecified):
            return True

        # Check explicit network definitions
        for net in DISALLOWED_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True


def validate_url(url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates a URL before the crawler navigates to it.
    
    Checks:
    1. Must use http or https scheme.
    2. Hostname must be present and syntactically valid.
    3. Hostname must not resolve to localhost, private IP, or cloud metadata endpoints.
    
    Returns:
        (is_safe, canonical_url, error_message)
    """
    if not url or not isinstance(url, str):
        return False, "", "Empty or invalid URL provided."

    url = url.strip()
    
    # If no scheme is present (e.g. "example.com" or "paypal.com/login"), default to https://
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, url, f"Malformed URL: {e}"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, url, f"Disallowed scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, url, "URL missing valid hostname."

    # Reject explicit localhost names
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return False, url, "Access to localhost/loopback is strictly prohibited."

    # DNS Resolution & SSRF check
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
        # Resolve address records
        addr_info = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
        
        resolved_ips = set()
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            resolved_ips.add(ip)

        if not resolved_ips:
            return False, url, f"Could not resolve hostname '{hostname}'."

        for ip in resolved_ips:
            if is_ip_disallowed(ip):
                return False, url, f"Hostname '{hostname}' resolved to blocked/private IP ({ip}). SSRF attempt prevented."

    except socket.gaierror as e:
        return False, url, f"DNS resolution failed for '{hostname}': {e}"
    except Exception as e:
        return False, url, f"Security verification error: {e}"

    return True, url, None


def defang_url(url: str) -> str:
    """
    Defangs a URL or domain to prevent accidental clicks when displaying in threat reports.
    Example: 'https://paypal.com-login.xyz' -> 'hxxps://paypal[.]com-login[.]xyz'
    """
    if not url:
        return ""
    d = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    d = d.replace(".", "[.]")
    return d


def refang_url(defanged_url: str) -> str:
    """
    Restores a defanged URL back to standard URL format.
    """
    if not defanged_url:
        return ""
    r = defanged_url.replace("hxxps://", "https://").replace("hxxp://", "http://")
    r = r.replace("[.]", ".")
    return r


def extract_domain(url: str) -> str:
    """
    Extracts the fully qualified domain name (FQDN) from a URL.
    """
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""
