from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

from .features import hostname_from_url, normalize_url


FEED_URLS = (
    (
        "Phishing.Database links",
        "url",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    ),
    (
        "Phishing.Database active today",
        "url",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-today/phishing-links-ACTIVE-today1.txt",
    ),
    (
        "Phishing.Database new today",
        "url",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today/phishing-links-NEW-today1.txt",
    ),
    (
        "Phishing.Database domains",
        "domain",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    ),
)

_CACHE_TTL_SECONDS = 15 * 60
_cache: dict[str, object] = {
    "loaded_at": 0.0,
    "urls": set(),
    "domains": set(),
    "source": "Phishing.Database",
}


def _clean_url(value: str) -> str:
    cleaned = normalize_url(value.strip())
    return cleaned.rstrip("/")


def _clean_domain(value: str) -> str:
    value = value.strip().lower()
    if not value or value.startswith("#"):
        return ""
    if "://" in value:
        return hostname_from_url(value)
    return value.split("/")[0].strip()


def _load_feeds(timeout: float = 2.0) -> dict[str, object]:
    now = time.time()
    if now - float(_cache["loaded_at"]) < _CACHE_TTL_SECONDS:
        return _cache

    urls: set[str] = set()
    domains: set[str] = set()
    for _, feed_type, feed_url in FEED_URLS:
        try:
            response = requests.get(feed_url, timeout=(timeout, timeout))
            response.raise_for_status()
        except requests.RequestException:
            continue

        for line in response.text.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if feed_type == "url":
                urls.add(_clean_url(value))
                domain = _clean_domain(value)
                if domain:
                    domains.add(domain)
            else:
                domain = _clean_domain(value)
                if domain:
                    domains.add(domain)

    if urls or domains:
        _cache.update({"loaded_at": now, "urls": urls, "domains": domains})
    return _cache


def lookup_threat_feed(url: str, hostname: str, timeout: float = 2.0) -> dict[str, object]:
    feeds = _load_feeds(timeout=timeout)
    normalized = _clean_url(url)
    host = _clean_domain(hostname or url)
    urls = feeds["urls"]
    domains = feeds["domains"]

    if normalized in urls:
        return {"matched": True, "source": feeds["source"], "match_type": "URL"}
    if host and any(host == domain or host.endswith(f".{domain}") for domain in domains):
        return {"matched": True, "source": feeds["source"], "match_type": "domain"}
    return {"matched": False, "source": feeds["source"], "match_type": ""}
