# SPDX-License-Identifier: MIT
# Copyright (c) 2026 chethanakash67
"""
Synthetic dataset generator for phishing / malicious URL detection.

Generates a balanced dataset of benign and malicious URLs with realistic
characteristics. For production use, replace / augment with real datasets:
  - PhishTank:   https://www.phishtank.com/developer_info.php
  - OpenPhish:   https://openphish.com/
  - Alexa/Tranco top-1M for benign
  - ISCX-URL2016: https://www.unb.ca/cic/datasets/url-2016.html

Usage:
    python generate_dataset.py            # writes dataset.csv
    python generate_dataset.py --size 20000
"""

import argparse
import random
import string
import csv
from pathlib import Path

# ---------------------------------------------------------------------------
# Seed for reproducibility
# ---------------------------------------------------------------------------
random.seed(42)

# ---------------------------------------------------------------------------
# Pools
# ---------------------------------------------------------------------------
BENIGN_DOMAINS = [
    "google.com", "youtube.com", "amazon.com", "facebook.com", "twitter.com",
    "linkedin.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "reddit.com", "apple.com", "microsoft.com", "netflix.com", "spotify.com",
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "medium.com",
    "dev.to", "hashnode.dev", "cloudflare.com", "fastly.com", "akamai.com",
]

BENIGN_PATHS = [
    "/", "/about", "/contact", "/blog", "/news", "/products",
    "/search?q=python", "/docs/api", "/user/profile", "/settings",
    "/dashboard", "/faq", "/pricing", "/features", "/support",
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "banking",
    "paypal", "signin", "password", "confirm", "authenticate",
    "validation", "suspended", "unusual-activity", "wallet", "claim-prize",
]

MALICIOUS_TLDS = ["xyz", "top", "click", "tk", "ml", "ga", "cf", "gq",
                  "buzz", "loan", "win", "download", "zip"]

BRAND_NAMES = ["paypal", "amazon", "google", "facebook", "apple",
               "microsoft", "netflix", "instagram", "twitter", "bankofamerica"]

SUSPICIOUS_PORTS = [8080, 3000, 4000, 5000, 8000, 8888]


def _rand_str(n: int, chars: str = string.ascii_lowercase) -> str:
    return "".join(random.choices(chars, k=n))


# ---------------------------------------------------------------------------
# Benign URL generators
# ---------------------------------------------------------------------------

def gen_benign_simple() -> str:
    domain = random.choice(BENIGN_DOMAINS)
    path = random.choice(BENIGN_PATHS)
    return f"https://{domain}{path}"


def gen_benign_subdomain() -> str:
    sub = random.choice(["www", "mail", "blog", "shop", "api", "cdn"])
    domain = random.choice(BENIGN_DOMAINS)
    path = random.choice(BENIGN_PATHS)
    return f"https://{sub}.{domain}{path}"


def gen_benign_with_params() -> str:
    domain = random.choice(BENIGN_DOMAINS)
    key = _rand_str(random.randint(3, 6))
    val = _rand_str(random.randint(4, 10))
    return f"https://{domain}/search?{key}={val}"


# ---------------------------------------------------------------------------
# Malicious URL generators
# ---------------------------------------------------------------------------

def gen_phishing_brand_squatting() -> str:
    brand = random.choice(BRAND_NAMES)
    suffix = random.choice(["-secure", "-login", "-verify", "-update", "-official"])
    tld = random.choice(MALICIOUS_TLDS)
    kw = random.choice(PHISHING_KEYWORDS)
    return f"http://{brand}{suffix}.{tld}/{kw}"


def gen_phishing_ip() -> str:
    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    kw = random.choice(PHISHING_KEYWORDS)
    token = _rand_str(12, string.ascii_lowercase + string.digits)
    return f"http://{ip}/{kw}?token={token}"


def gen_phishing_long_url() -> str:
    brand = random.choice(BRAND_NAMES)
    domain = random.choice(BENIGN_DOMAINS)
    path = "/".join(_rand_str(random.randint(4, 8)) for _ in range(random.randint(4, 7)))
    kw = random.choice(PHISHING_KEYWORDS)
    token = _rand_str(32, string.ascii_lowercase + string.digits)
    return f"http://{brand}.{domain}/{path}/{kw}?redirect={token}&source=email&campaign=urgent"


def gen_phishing_subdomain_abuse() -> str:
    brand = random.choice(BRAND_NAMES)
    subs = ".".join(_rand_str(random.randint(3, 6)) for _ in range(random.randint(2, 4)))
    tld = random.choice(MALICIOUS_TLDS)
    kw = random.choice(PHISHING_KEYWORDS)
    return f"http://{brand}.{subs}.{tld}/{kw}"


def gen_phishing_suspicious_port() -> str:
    port = random.choice(SUSPICIOUS_PORTS)
    domain = f"{_rand_str(6)}.{random.choice(MALICIOUS_TLDS)}"
    kw = random.choice(PHISHING_KEYWORDS)
    return f"http://{domain}:{port}/{kw}"


def gen_phishing_at_symbol() -> str:
    fake = _rand_str(8)
    real = random.choice(BRAND_NAMES)
    tld = random.choice(MALICIOUS_TLDS)
    return f"http://{real}.com@{fake}.{tld}/login"


def gen_phishing_double_slash() -> str:
    domain = f"{_rand_str(6)}.{random.choice(MALICIOUS_TLDS)}"
    brand = random.choice(BRAND_NAMES)
    return f"http://{domain}//redirect//{brand}.com/login"


# ---------------------------------------------------------------------------
# Dataset assembly
# ---------------------------------------------------------------------------

BENIGN_GENERATORS = [gen_benign_simple, gen_benign_subdomain, gen_benign_with_params]
MALICIOUS_GENERATORS = [
    gen_phishing_brand_squatting,
    gen_phishing_ip,
    gen_phishing_long_url,
    gen_phishing_subdomain_abuse,
    gen_phishing_suspicious_port,
    gen_phishing_at_symbol,
    gen_phishing_double_slash,
]


def generate_dataset(n_each: int = 5000) -> list[tuple[str, int]]:
    """Return list of (url, label) where label 0=benign 1=malicious."""
    rows: list[tuple[str, int]] = []

    for _ in range(n_each):
        rows.append((random.choice(BENIGN_GENERATORS)(), 0))

    for _ in range(n_each):
        rows.append((random.choice(MALICIOUS_GENERATORS)(), 1))

    random.shuffle(rows)
    return rows


def save_csv(rows: list[tuple[str, int]], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"✅ Saved {len(rows)} rows → {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=5000,
                        help="Number of samples PER class (default 5000)")
    parser.add_argument("--out", default="dataset.csv",
                        help="Output CSV file path")
    args = parser.parse_args()

    out_path = Path(__file__).parent / args.out
    rows = generate_dataset(n_each=args.size)
    save_csv(rows, out_path)
