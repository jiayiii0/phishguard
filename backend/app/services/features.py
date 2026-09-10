from __future__ import annotations

import ipaddress
import math
import re
import socket
import unicodedata
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from urllib.parse import unquote, urljoin, urlparse, urlsplit, urlunsplit

import requests

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
    "instagram", "whatsapp", "telegram", "bankislam", "publicbank", "adobe",
    "github", "zoom", "canva", "dropbox", "cloudflare", "linkedin",
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

KNOWN_PLATFORM_DOMAINS = {
    "google.com", "google.com.my", "forms.gle", "microsoft.com", "microsoftonline.com",
    "live.com", "office.com", "sharepoint.com", "onedrive.com", "apple.com",
    "icloud.com", "amazon.com", "paypal.com", "github.com", "github.io",
    "zoom.us", "canva.com", "dropbox.com", "cloudflare.com", "linkedin.com",
    "maybank2u.com.my", "maybank.com", "cimb.com.my", "publicbank.com.my",
    "pbebank.com", "touchngo.com.my", "shopee.com.my", "lazada.com.my",
    "utar.edu.my",
}

SHARED_HOSTING_DOMAINS = {
    "github.io", "pages.dev", "netlify.app", "vercel.app", "web.app",
    "firebaseapp.com", "blogspot.com", "wixsite.com", "wordpress.com",
}

DOCUMENTATION_HOST_TOKENS = {
    "docs", "doc", "developer", "developers", "learn", "support", "help",
    "api", "reference", "guides", "developer-docs",
}

EDUCATION_GOV_SUFFIXES = {
    "edu", "gov", "edu.my", "gov.my", "ac.uk", "gov.uk", "edu.au",
    "gc.ca", "gouv.fr", "gov.sg", "edu.sg",
}

MULTI_LABEL_SUFFIXES = {
    "com.my", "edu.my", "gov.my", "net.my", "org.my", "co.uk", "com.au",
    "com.br", "co.in", "co.jp", "com.sg",
}


HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "Α": "a", "А": "a", "ɑ": "a",
    "е": "e", "Ε": "e", "Е": "e",
    "і": "i", "Ι": "i", "І": "i", "ı": "i",
    "ο": "o", "Ο": "o", "О": "o", "0": "o",
    "р": "p", "Ρ": "p", "Р": "p",
    "с": "c", "ϲ": "c", "С": "c",
    "у": "y", "Υ": "y", "У": "y",
    "х": "x", "Χ": "x", "Х": "x",
    "ᴡ": "w", "ԝ": "w",
    "ӏ": "l", "ⅼ": "l", "Ι": "l",
})


@dataclass
class PreprocessedURL:
    original_url: str
    normalized_url: str
    analysis_url: str
    expanded_url: str
    redirect_chain: list[str]
    redirect_count: int
    redirect_domains: list[str]
    final_destination_domain: str
    final_domain_differs: bool
    redirect_domain_changes: int
    redirect_loop_detected: bool
    security_blocked: bool
    encoded_characters_detected: bool
    unicode_char_count: int
    decoded_domain: str
    evasion_techniques: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def normalize_url(url: str) -> str:
    return canonicalize_url(url)


def canonicalize_url(url: str) -> str:
    cleaned = unicodedata.normalize("NFKC", (url or "").strip())
    if not cleaned:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned
    encoded_detected = bool(re.search(r"%[0-9a-fA-F]{2}", cleaned))
    decoded = unquote(cleaned) if encoded_detected else cleaned
    parsed = urlsplit(decoded)
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = re.sub(r"/{2,}", "/", parsed.path or "")
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def hostname_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_blocked_network_url(url: str) -> bool:
    parsed = urlparse(normalize_url(url))
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return True
    if hostname in {"localhost", "0.0.0.0"} or hostname.endswith(".localhost") or hostname.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def has_ip_address(value: str) -> int:
    pattern = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    return int(bool(re.fullmatch(pattern, value or "")))


def domain_parts(hostname: str) -> tuple[str, str]:
    parts = [part for part in hostname.split(".") if part]
    if len(parts) < 2:
        return hostname, ""
    return parts[-2], parts[-1]


def registered_domain_from_hostname(hostname: str) -> str:
    hostname = (hostname or "").lower().strip(".")
    if not hostname or has_ip_address(hostname):
        return hostname
    parts = [part for part in hostname.split(".") if part]
    if len(parts) < 2:
        return hostname
    suffix = ".".join(parts[-2:])
    if suffix in MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def is_shared_hosting_hostname(hostname: str) -> int:
    registered_domain = registered_domain_from_hostname(hostname)
    return int(registered_domain in SHARED_HOSTING_DOMAINS)


def is_known_platform_hostname(hostname: str) -> int:
    registered_domain = registered_domain_from_hostname(hostname)
    if registered_domain in SHARED_HOSTING_DOMAINS:
        return 0
    return int(registered_domain in KNOWN_PLATFORM_DOMAINS)


def has_documentation_hostname_context(hostname: str) -> int:
    labels = {part for part in (hostname or "").lower().split(".") if part}
    return int(bool(labels & DOCUMENTATION_HOST_TOKENS))


def has_education_or_government_domain(hostname: str) -> int:
    hostname = (hostname or "").lower().strip(".")
    parts = [part for part in hostname.split(".") if part]
    if not parts:
        return 0
    suffixes = {parts[-1]}
    if len(parts) >= 2:
        suffixes.add(".".join(parts[-2:]))
    return int(bool(suffixes & EDUCATION_GOV_SUFFIXES))


def decode_punycode_hostname(hostname: str) -> str:
    try:
        return hostname.encode("ascii").decode("idna").lower()
    except Exception:
        return hostname.lower()


def skeletonize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "").lower()
    return normalized.translate(HOMOGLYPH_MAP)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(char) / len(text) for char in set(text)]
    return round(-sum(p * math.log2(p) for p in probabilities), 4)


def count_subdomains(hostname: str) -> int:
    if not hostname or has_ip_address(hostname):
        return 0
    return max(len([p for p in hostname.split(".") if p]) - 2, 0)


def brand_analysis(url: str, domain: str, hostname: str = "") -> dict[str, float | int | str]:
    lower_url = url.lower()
    skeleton_domain = re.sub(r"[^a-z0-9]", "", skeletonize(domain))
    skeleton_host = re.sub(r"[^a-z0-9]", "", skeletonize(hostname or domain))
    direct_brand_count = sum(1 for brand in BRANDS if brand in lower_url or brand in skeleton_host)
    best_brand = ""
    best_score = 0.0
    for brand in BRANDS:
        ratio = SequenceMatcher(None, skeleton_domain, brand).ratio()
        if ratio > best_score:
            best_brand = brand
            best_score = ratio
    exact_brand_domain = skeleton_domain in BRANDS
    impersonation = int(direct_brand_count > 0 and not exact_brand_domain)
    typosquat = int(not exact_brand_domain and best_score >= 0.78)
    return {
        "brand_impersonation": impersonation,
        "typosquatting_similarity": typosquat,
        "brand_keyword_detected": int(direct_brand_count > 0),
        "domain_similarity_score": round(best_score, 4),
        "brand_impersonation_score": round(max(best_score if impersonation or typosquat else 0.0, 0.0), 4),
        "matched_brand": best_brand,
    }


def brand_features(url: str, domain: str) -> tuple[int, int]:
    analysis = brand_analysis(url, domain)
    return int(analysis["brand_impersonation"]), int(analysis["typosquatting_similarity"])


def request_redirect(session, url: str, timeout: float):
    headers = {"User-Agent": "PhishGuard-URL-Resolver/1.0"}
    try:
        return session.head(url, allow_redirects=False, timeout=(timeout, timeout), headers=headers)
    except Exception:
        return session.get(url, allow_redirects=False, timeout=(timeout, timeout), headers=headers)


def request_redirect_with_deadline(session, url: str, timeout: float):
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(request_redirect, session, url, timeout)
    try:
        return future.result(timeout=timeout + 0.5)
    except TimeoutError:
        future.cancel()
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def resolve_shortened_url(
    normalized_url: str,
    timeout: float = 2.0,
    max_redirects: int = 5,
    session=None,
) -> dict[str, object]:
    session = session or requests.Session()
    if hasattr(session, "trust_env"):
        session.trust_env = False
    chain = [normalized_url]
    domains = [hostname_from_url(normalized_url)]
    current = normalized_url
    visited = {current}
    loop_detected = False
    security_blocked = False

    for _ in range(max_redirects):
        if is_blocked_network_url(current):
            security_blocked = True
            break
        try:
            response = request_redirect_with_deadline(session, current, timeout)
        except Exception:
            break
        if response is None:
            break
        location = response.headers.get("Location") or response.headers.get("location")
        if not location or int(getattr(response, "status_code", 0)) not in range(300, 400):
            break
        next_url = canonicalize_url(urljoin(current, location))
        if is_blocked_network_url(next_url):
            security_blocked = True
            break
        if next_url in visited:
            loop_detected = True
            break
        visited.add(next_url)
        chain.append(next_url)
        domains.append(hostname_from_url(next_url))
        current = next_url

    original_domain = domains[0] if domains else ""
    final_domain = domains[-1] if domains else original_domain
    domain_changes = sum(1 for previous, current_domain in zip(domains, domains[1:]) if previous != current_domain)
    return {
        "expanded_url": current if not security_blocked else normalized_url,
        "redirect_chain": chain if not security_blocked else [normalized_url],
        "redirect_count": max(len(chain) - 1, 0) if not security_blocked else 0,
        "redirect_domains": domains if not security_blocked else [original_domain],
        "final_destination_domain": final_domain if not security_blocked else original_domain,
        "final_domain_differs": bool(original_domain and final_domain and original_domain != final_domain and not security_blocked),
        "redirect_domain_changes": domain_changes if not security_blocked else 0,
        "redirect_loop_detected": loop_detected,
        "security_blocked": security_blocked,
    }


def preprocess_url(
    url: str,
    expand_shorteners: bool = False,
    timeout: float = 2.0,
    max_redirects: int = 5,
    session=None,
) -> PreprocessedURL:
    original = (url or "").strip()
    encoded_detected = bool(re.search(r"(%[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}|\\u[0-9a-fA-F]{4})", original))
    normalized = canonicalize_url(original)
    original_host = hostname_from_url(normalized)
    shortened = original_host in SHORTENERS
    redirect_data = {
        "expanded_url": normalized,
        "redirect_chain": [normalized] if normalized else [],
        "redirect_count": 0,
        "redirect_domains": [original_host] if original_host else [],
        "final_destination_domain": original_host,
        "final_domain_differs": False,
        "redirect_domain_changes": 0,
        "redirect_loop_detected": False,
        "security_blocked": False,
    }
    if expand_shorteners and shortened and normalized and not is_blocked_network_url(normalized):
        redirect_data = resolve_shortened_url(normalized, timeout=timeout, max_redirects=max_redirects, session=session)

    analysis_url = str(redirect_data["expanded_url"])
    final_host = hostname_from_url(analysis_url)
    decoded_domain = decode_punycode_hostname(final_host)
    unicode_count = sum(1 for char in decoded_domain if ord(char) > 127)
    techniques = []
    if shortened:
        techniques.append("shortened_url")
    if encoded_detected:
        techniques.append("percent_encoding")
    if "xn--" in final_host:
        techniques.append("punycode")
    if unicode_count:
        techniques.append("unicode_domain")
    if redirect_data["redirect_count"]:
        techniques.append("redirect_chain")
    if redirect_data["final_domain_differs"]:
        techniques.append("domain_change_redirect")
    if redirect_data["redirect_loop_detected"]:
        techniques.append("redirect_loop")
    if redirect_data["security_blocked"]:
        techniques.append("blocked_private_redirect")

    return PreprocessedURL(
        original_url=original,
        normalized_url=normalized,
        analysis_url=analysis_url,
        expanded_url=analysis_url,
        redirect_chain=list(redirect_data["redirect_chain"]),
        redirect_count=int(redirect_data["redirect_count"]),
        redirect_domains=list(redirect_data["redirect_domains"]),
        final_destination_domain=str(redirect_data["final_destination_domain"]),
        final_domain_differs=bool(redirect_data["final_domain_differs"]),
        redirect_domain_changes=int(redirect_data["redirect_domain_changes"]),
        redirect_loop_detected=bool(redirect_data["redirect_loop_detected"]),
        security_blocked=bool(redirect_data["security_blocked"]),
        encoded_characters_detected=encoded_detected,
        unicode_char_count=unicode_count,
        decoded_domain=decoded_domain,
        evasion_techniques=techniques,
    )


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


def extract_features(
    url: str,
    include_network: bool = False,
    preprocessed: PreprocessedURL | None = None,
) -> dict[str, float | int]:
    preprocessed = preprocessed or preprocess_url(url, expand_shorteners=False)
    normalized = preprocessed.analysis_url
    parsed = urlparse(normalized)
    hostname = hostname_from_url(normalized)
    decoded_hostname = preprocessed.decoded_domain or decode_punycode_hostname(hostname)
    domain, tld = domain_parts(hostname)
    decoded_domain, _ = domain_parts(decoded_hostname)
    registered_domain = registered_domain_from_hostname(hostname)
    lower_url = normalized.lower()
    original_lower = preprocessed.original_url.lower()
    decoded_original = unquote(preprocessed.original_url)
    path_query = (parsed.path or "") + (parsed.query or "")

    digits = sum(ch.isdigit() for ch in normalized)
    letters = sum(ch.isalpha() for ch in normalized)
    special = sum(not ch.isalnum() for ch in normalized)
    suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in lower_url)
    brand_domain = decoded_domain or domain
    if registered_domain in SHARED_HOSTING_DOMAINS:
        host_parts = [part for part in decoded_hostname.split(".") if part]
        registered_parts = [part for part in registered_domain.split(".") if part]
        if len(host_parts) > len(registered_parts):
            brand_domain = host_parts[-len(registered_parts) - 1]
    brand = brand_analysis(normalized, brand_domain, decoded_hostname)
    brand_impersonation = int(brand["brand_impersonation"])
    typosquat = int(brand["typosquatting_similarity"])
    embedded_starts = [match.start() for match in re.finditer(r"https?://", decoded_original, flags=re.IGNORECASE)]
    embedded_urls = [decoded_original[start:] for start in embedded_starts[1:]]
    embedded_url_count = len(embedded_urls)
    embedded_external_count = 0
    embedded_same_registered_domain = 0
    for embedded_url in embedded_urls:
        embedded_host = hostname_from_url(embedded_url)
        if not embedded_host:
            continue
        embedded_registered = registered_domain_from_hostname(embedded_host)
        if embedded_registered and embedded_registered == registered_domain:
            embedded_same_registered_domain += 1
        else:
            embedded_external_count += 1
    long_random_string_count = sum(
        1
        for token in re.findall(r"[A-Za-z0-9]{18,}", decoded_original)
        if shannon_entropy(token) >= 3.4
    )
    has_hex_encoding = int(bool(re.search(r"(%[0-9a-fA-F]{2}|0x[0-9a-fA-F]{2,})", preprocessed.original_url)))
    has_unicode_escape = int(bool(re.search(r"(%u[0-9a-fA-F]{4}|\\u[0-9a-fA-F]{4})", preprocessed.original_url)))
    has_at_symbol_abuse = int("@" in parsed.netloc)
    multiple_consecutive_slashes = int(bool(re.search(r"(?<!:)/{2,}", decoded_original)))
    excessive_hyphens = int(normalized.count("-") >= 4 or hostname.count("-") >= 3)
    excessive_special_chars = int((special / max(len(normalized), 1)) >= 0.28)
    unicode_char_count = int(preprocessed.unicode_char_count + sum(1 for char in normalized if ord(char) > 127))
    homoglyph_detected = int(
        unicode_char_count > 0
        and (
            float(brand["domain_similarity_score"]) >= 0.8
            or skeletonize(decoded_hostname) != decoded_hostname
        )
    )
    obfuscation_flags = [
        has_at_symbol_abuse,
        multiple_consecutive_slashes,
        excessive_hyphens,
        int(preprocessed.encoded_characters_detected),
        int(embedded_url_count > 0),
        has_hex_encoding,
        has_unicode_escape,
        int(has_ip_address(hostname)),
        int(long_random_string_count > 0),
        excessive_special_chars,
        homoglyph_detected,
        int("xn--" in hostname),
    ]
    obfuscation_score = round(min(sum(obfuscation_flags) / max(len(obfuscation_flags), 1), 1.0), 4)
    is_shared_hosting = is_shared_hosting_hostname(hostname)
    is_known_platform = is_known_platform_hostname(hostname)
    documentation_context = has_documentation_hostname_context(hostname)
    education_gov_context = has_education_or_government_domain(hostname)
    safe_structured_context = int(
        parsed.scheme == "https"
        and (documentation_context or education_gov_context)
        and not has_ip_address(hostname)
        and "xn--" not in hostname
        and not brand_impersonation
        and not has_at_symbol_abuse
        and embedded_external_count == 0
        and tld not in SUSPICIOUS_TLDS
        and obfuscation_score <= 0.25
    )
    brand_matches_registered_domain = int(is_known_platform and bool(brand["brand_keyword_detected"]) and not brand_impersonation)
    credential_terms_on_unrelated_domain = int(
        suspicious_count > 0
        and bool(brand["brand_keyword_detected"])
        and not brand_matches_registered_domain
    )

    features: dict[str, float | int] = {
        "url_length": len(normalized),
        "hostname_length": len(hostname),
        "registered_domain_length": len(registered_domain),
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
        "url_was_shortened": int(hostname in SHORTENERS or "shortened_url" in preprocessed.evasion_techniques),
        "redirect_count": preprocessed.redirect_count,
        "redirect_domain_changes": preprocessed.redirect_domain_changes,
        "redirect_loop_detected": int(preprocessed.redirect_loop_detected),
        "final_domain_differs": int(preprocessed.final_domain_differs),
        "redirect_external_domain_count": len(set(preprocessed.redirect_domains)),
        "has_double_slash_redirect": int("//" in path_query or multiple_consecutive_slashes),
        "hostname_has_hyphen": int("-" in hostname),
        "has_punycode": int("xn--" in hostname),
        "punycode_detected": int("xn--" in hostname),
        "homoglyph_detected": homoglyph_detected,
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "suspicious_tld_flag": int(tld in SUSPICIOUS_TLDS),
        "brand_impersonation": brand_impersonation,
        "typosquatting_similarity": typosquat,
        "brand_keyword_detected": int(brand["brand_keyword_detected"]),
        "brand_matches_registered_domain": brand_matches_registered_domain,
        "known_platform_domain": is_known_platform,
        "shared_hosting_domain": is_shared_hosting,
        "documentation_hostname_context": documentation_context,
        "education_or_government_domain": education_gov_context,
        "safe_structured_context": safe_structured_context,
        "credential_terms_on_unrelated_domain": credential_terms_on_unrelated_domain,
        "domain_similarity_score": float(brand["domain_similarity_score"]),
        "brand_impersonation_score": float(brand["brand_impersonation_score"]),
        "has_encoded_chars": int(preprocessed.encoded_characters_detected or any(token in original_lower for token in ("%2f", "%3d", "%40", "%2e"))),
        "url_encoding_detected": int(preprocessed.encoded_characters_detected),
        "has_at_symbol_abuse": has_at_symbol_abuse,
        "multiple_consecutive_slashes": multiple_consecutive_slashes,
        "excessive_hyphens": excessive_hyphens,
        "embedded_url_count": embedded_url_count,
        "embedded_external_url_count": embedded_external_count,
        "embedded_same_registered_domain_count": embedded_same_registered_domain,
        "has_hex_encoding": has_hex_encoding,
        "has_unicode_escape": has_unicode_escape,
        "long_random_string_count": long_random_string_count,
        "excessive_special_chars": excessive_special_chars,
        "obfuscation_score": obfuscation_score,
        "ip_address_flag": has_ip_address(hostname),
        "unicode_char_count": unicode_char_count,
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
        ("final_domain_differs", "Shortened URL redirects to a different final domain"),
        ("redirect_loop_detected", "Redirect loop was detected"),
        ("has_at_symbol_abuse", "URL uses @ symbol user-info obfuscation"),
        ("has_punycode", "Punycode pattern suggests possible homograph attack"),
        ("homoglyph_detected", "Unicode or homoglyph characters resemble a trusted brand"),
        ("typosquatting_similarity", "Domain resembles a known brand name"),
        ("brand_impersonation", "Brand name appears outside the registered domain"),
        ("credential_terms_on_unrelated_domain", "Credential-related terms appear on a brand-mismatched domain"),
        ("has_suspicious_tld", "Top-level domain is commonly abused in suspicious campaigns"),
        ("has_encoded_chars", "Encoded characters may hide redirects or symbols"),
        ("embedded_url_count", "URL contains an embedded URL inside the path or query"),
        ("has_hex_encoding", "URL contains hexadecimal-style encoding"),
        ("has_unicode_escape", "URL contains Unicode escape-style encoding"),
        ("has_double_slash_redirect", "URL contains a double-slash redirect pattern"),
        ("has_port_number", "URL includes an explicit port number"),
        ("has_many_dots", "URL contains unusually many dots"),
        ("long_random_string_count", "URL contains long high-entropy random-looking text"),
        ("excessive_special_chars", "URL contains an excessive special-character ratio"),
        ("whois_recent_domain", "WHOIS indicates a recently created domain"),
    ]
    indicators = [message for key, message in checks if int(features.get(key, 0)) == 1]
    if features.get("redirect_count", 0) >= 2:
        indicators.append("URL follows multiple redirects before the final destination")
    if features.get("obfuscation_score", 0) >= 0.25:
        indicators.append("URL contains multiple obfuscation techniques")
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
