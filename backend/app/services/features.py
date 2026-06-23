from __future__ import annotations

import math
import re
import socket
from difflib import SequenceMatcher
from urllib.parse import urlparse

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None

try:
    import whois
except Exception:  # pragma: no cover
    whois = None


SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "account", "update", "bank", "confirm",
    "password", "signin", "payment", "support", "wallet", "unlock", "billing",
    "invoice", "limited", "alert", "security", "validate", "auth", "bonus",
}

BRANDS = {
    "paypal", "google", "facebook", "microsoft", "apple", "amazon", "netflix",
    "maybank", "cimb", "rhb", "tng", "touchngo", "shopee", "lazada",
    "instagram", "whatsapp", "telegram", "bankislam", "publicbank",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "s.id", "rb.gy", "shorturl.at", "lnkd.in",
    "bitly.com", "tiny.cc", "soo.gd", "v.gd", "qrco.de",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "icu", "cyou", "buzz", "tk", "ml",
    "ga", "gq", "cf", "work", "support", "rest", "cam", "quest",
}


def normalize_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned
    return cleaned


def hostname_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
    except Exception:
        return ""


def has_ip_address(value: str) -> int:
    pattern = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    return int(bool(re.fullmatch(pattern, value or "")))


def domain_parts(hostname: str) -> tuple[str, str]:
    parts = [part for part in hostname.split(".") if part]
    if len(parts) < 2:
        return hostname, ""
    return parts[-2], parts[-1]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(char) / len(text) for char in set(text)]
    return round(-sum(p * math.log2(p) for p in probabilities), 4)


def count_subdomains(hostname: str) -> int:
    if not hostname or has_ip_address(hostname):
        return 0
    return max(len([p for p in hostname.split(".") if p]) - 2, 0)


def brand_features(url: str, domain: str) -> tuple[int, int]:
    lower_url = url.lower()
    direct_brand_count = sum(1 for brand in BRANDS if brand in lower_url)
    impersonation = int(direct_brand_count > 0 and domain not in BRANDS)
    typosquat = 0
    for brand in BRANDS:
        ratio = SequenceMatcher(None, domain, brand).ratio()
        if domain != brand and ratio >= 0.78:
            typosquat = 1
            break
    return impersonation, typosquat


def optional_network_features(hostname: str) -> dict[str, int]:
    values = {
        "dns_has_a_record": 0,
        "dns_lookup_failed": 0,
        "whois_lookup_failed": 0,
        "whois_domain_age_days": 0,
        "whois_recent_domain": 0,
    }
    if not hostname or has_ip_address(hostname):
        values["dns_lookup_failed"] = 1
        values["whois_lookup_failed"] = 1
        return values

    try:
        socket.setdefaulttimeout(1.5)
        socket.gethostbyname(hostname)
        values["dns_has_a_record"] = 1
    except Exception:
        values["dns_lookup_failed"] = 1

    if whois is None:
        values["whois_lookup_failed"] = 1
        return values

    try:
        record = whois.whois(hostname)
        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            from datetime import datetime, timezone

            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = max((datetime.now(timezone.utc) - creation).days, 0)
            values["whois_domain_age_days"] = int(age_days)
            values["whois_recent_domain"] = int(age_days < 90)
    except Exception:
        values["whois_lookup_failed"] = 1
    return values


def extract_features(url: str, include_network: bool = False) -> dict[str, float | int]:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = hostname_from_url(normalized)
    domain, tld = domain_parts(hostname)
    lower_url = normalized.lower()
    path_query = (parsed.path or "") + (parsed.query or "")

    digits = sum(ch.isdigit() for ch in normalized)
    letters = sum(ch.isalpha() for ch in normalized)
    special = sum(not ch.isalnum() for ch in normalized)
    suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in lower_url)
    brand_impersonation, typosquat = brand_features(normalized, domain)

    features: dict[str, float | int] = {
        "url_length": len(normalized),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path or ""),
        "query_length": len(parsed.query or ""),
        "count_dot": normalized.count("."),
        "count_hyphen": normalized.count("-"),
        "count_at": normalized.count("@"),
        "count_question": normalized.count("?"),
        "count_equal": normalized.count("="),
        "count_percent": normalized.count("%"),
        "count_slash": normalized.count("/"),
        "count_ampersand": normalized.count("&"),
        "count_digits": digits,
        "count_letters": letters,
        "count_special_chars": special,
        "digit_ratio": digits / max(len(normalized), 1),
        "special_char_ratio": special / max(len(normalized), 1),
        "url_entropy": shannon_entropy(normalized),
        "has_https": int(parsed.scheme == "https"),
        "has_ip": has_ip_address(hostname),
        "subdomain_count": count_subdomains(hostname),
        "suspicious_word_count": suspicious_count,
        "is_shortened_url": int(hostname in SHORTENERS),
        "has_double_slash_redirect": int("//" in path_query),
        "hostname_has_hyphen": int("-" in hostname),
        "has_punycode": int("xn--" in hostname),
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "brand_impersonation": brand_impersonation,
        "typosquatting_similarity": typosquat,
        "has_encoded_chars": int(any(token in lower_url for token in ("%2f", "%3d", "%40", "%2e"))),
        "has_port_number": int(":" in parsed.netloc.replace(hostname, "", 1)),
        "has_many_dots": int(normalized.count(".") >= 5),
        "domain_length": len(domain),
        "tld_length": len(tld),
    }

    if include_network:
        features.update(optional_network_features(hostname))
    else:
        features.update({
            "dns_has_a_record": 0,
            "dns_lookup_failed": 0,
            "whois_lookup_failed": 0,
            "whois_domain_age_days": 0,
            "whois_recent_domain": 0,
        })
    return features


def explain_indicators(features: dict[str, float | int]) -> list[str]:
    checks = [
        ("has_ip", "IP address is used instead of a normal domain name"),
        ("is_shortened_url", "URL shortener service is used"),
        ("has_punycode", "Punycode pattern suggests possible homograph attack"),
        ("typosquatting_similarity", "Domain resembles a known brand name"),
        ("brand_impersonation", "Brand name appears outside the registered domain"),
        ("has_suspicious_tld", "Top-level domain is commonly abused in suspicious campaigns"),
        ("has_encoded_chars", "Encoded characters may hide redirects or symbols"),
        ("has_double_slash_redirect", "URL contains a double-slash redirect pattern"),
        ("has_port_number", "URL includes an explicit port number"),
        ("has_many_dots", "URL contains unusually many dots"),
        ("whois_recent_domain", "WHOIS indicates a recently created domain"),
    ]
    indicators = [message for key, message in checks if int(features.get(key, 0)) == 1]
    if int(features.get("has_https", 1)) == 0:
        indicators.append("HTTPS is not used")
    if features.get("subdomain_count", 0) >= 3:
        indicators.append("URL contains many subdomains")
    if features.get("suspicious_word_count", 0) >= 2:
        indicators.append("URL contains multiple suspicious keywords")
    if features.get("url_length", 0) >= 90:
        indicators.append("URL is unusually long")
    if features.get("count_hyphen", 0) >= 3:
        indicators.append("URL contains many hyphens")
    return indicators
