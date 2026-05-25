# SPDX-License-Identifier: MIT
# Copyright (c) 2026 chethanakash67
"""
URL Feature Extraction for ML Model
Mirrors the TypeScript urlAnalyzer.ts logic but adds extra features
that are expensive to compute in the browser.

Feature vector (16 features — must match mlModel.ts FEATURE_ORDER):
  0  url_length
  1  dot_count
  2  subdomain_count
  3  has_ip_address        (0/1)
  4  suspicious_keyword_count
  5  suspicious_tld        (0/1)
  6  has_suspicious_port   (0/1)
  7  path_depth
  8  query_param_count
  9  https                 (0/1)
  10 digit_ratio           fraction of digits in hostname
  11 hyphen_count          hyphens in hostname
  12 at_symbol            (0/1)
  13 double_slash_in_path (0/1)
  14 brand_squatting       (0/1)  known brand in suspicious context
  15 entropy              Shannon entropy of hostname
"""

import re
import math
from typing import List
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Constants (keep in sync with src/core/constants.ts)
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "account", "banking",
    "paypal", "signin", "password", "confirm", "authenticate",
    "validation", "suspended", "unusual", "activity", "wallet",
    "crypto", "free", "prize", "winner", "claim", "urgent",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "info", "tk", "ml", "ga", "cf",
    "gq", "buzz", "loan", "win", "download", "zip", "review",
    "country", "kim", "science", "work", "party", "gdn",
}

SUSPICIOUS_PORTS = {8080, 3000, 4000, 5000, 8000, 8888, 9090, 1080}

KNOWN_BRANDS = {
    "paypal", "amazon", "google", "facebook", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
}

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")


# ---------------------------------------------------------------------------
# Individual feature helpers
# ---------------------------------------------------------------------------

def _is_ip(hostname: str) -> bool:
    return bool(IPV4_RE.match(hostname) or IPV6_RE.match(hostname))


def _tld(hostname: str) -> str:
    parts = hostname.split(".")
    return parts[-1] if parts else ""


def _subdomain_count(hostname: str) -> int:
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def _suspicious_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _digit_ratio(hostname: str) -> float:
    if not hostname:
        return 0.0
    digits = sum(1 for c in hostname if c.isdigit())
    return digits / len(hostname)


def _brand_squatting(hostname: str) -> bool:
    """True when a known brand name appears in the hostname but is NOT
    the registered domain (e.g. paypal-secure.xyz, amazon-login.com)."""
    parts = hostname.split(".")
    if len(parts) < 2:
        return False
    # registered domain = second-to-last part (rough heuristic)
    registered = parts[-2].lower()
    # If the registered domain exactly matches a brand → legitimate
    if registered in KNOWN_BRANDS:
        return False
    # If a brand keyword appears anywhere else → squatting signal
    full = hostname.lower()
    return any(brand in full for brand in KNOWN_BRANDS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "dot_count",
    "subdomain_count",
    "has_ip_address",
    "suspicious_keyword_count",
    "suspicious_tld",
    "has_suspicious_port",
    "path_depth",
    "query_param_count",
    "https",
    "digit_ratio",
    "hyphen_count",
    "at_symbol",
    "double_slash_in_path",
    "brand_squatting",
    "entropy",
]


def extract_features(url: str) -> List[float]:
    """
    Extract the 16-dimensional feature vector for a URL.
    Returns a list of floats (already scaled / binary).
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return [0.0] * len(FEATURE_NAMES)

    # parsed.port can raise ValueError on malformed URLs
    try:
        port_raw = parsed.port
        port_str = str(port_raw) if port_raw else ""
    except Exception:
        port_str = ""

    pathname = parsed.path or ""

    # ---- compute individual features ----
    url_length = float(len(url))
    dot_count = float(url.count("."))
    subdomain_count = float(_subdomain_count(hostname))
    has_ip = 1.0 if _is_ip(hostname) else 0.0
    kw_count = float(_suspicious_keyword_count(url))
    tld = _tld(hostname)
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    try:
        port_num = int(port_str) if port_str else 0
    except ValueError:
        port_num = 0
    has_suspicious_port = 1.0 if port_num in SUSPICIOUS_PORTS else 0.0

    path_segments = [s for s in pathname.split("/") if s]
    path_depth = float(len(path_segments))

    try:
        query_params = parse_qs(parsed.query)
        query_param_count = float(len(query_params))
    except Exception:
        query_param_count = 0.0

    https = 1.0 if parsed.scheme == "https" else 0.0
    digit_ratio = _digit_ratio(hostname)
    hyphen_count = float(hostname.count("-"))
    at_symbol = 1.0 if "@" in url else 0.0
    double_slash = 1.0 if "//" in pathname else 0.0
    brand_sq = 1.0 if _brand_squatting(hostname) else 0.0
    entropy = _entropy(hostname)

    return [
        url_length,
        dot_count,
        subdomain_count,
        has_ip,
        kw_count,
        suspicious_tld,
        has_suspicious_port,
        path_depth,
        query_param_count,
        https,
        digit_ratio,
        hyphen_count,
        at_symbol,
        double_slash,
        brand_sq,
        entropy,
    ]


def features_as_dict(url: str) -> dict:
    return dict(zip(FEATURE_NAMES, extract_features(url)))
