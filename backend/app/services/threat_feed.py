from __future__ import annotations

import csv
import time
from pathlib import Path

import requests

from .features import hostname_from_url, normalize_url


BASE_DIR = Path(__file__).resolve().parents[3]
LOCAL_FEED_FILES = (
    (BASE_DIR / "backend" / "ml" / "data" / "phishing_database_urls.csv", "url", "Phishing.Database local snapshot"),
    (BASE_DIR / "backend" / "ml" / "data" / "openphish_urls.csv", "url", "OpenPhish local snapshot"),
)
REMOTE_FEED_URLS = (
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

_CACHE_TTL_SECONDS = 6 * 60 * 60
_cache: dict[str, object] = {
    "loaded_at": 0.0,
    "urls": set(),
    "domains": set(),
    "source": "",
    "status": "not_loaded",
}


def _clean_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")
    cleaned = normalize_url(value)
    return cleaned.rstrip("/")


def _clean_domain(value: str) -> str:
    value = value.strip().lower()
    if not value or value.startswith("#"):
        return ""
    if "://" in value:
        return hostname_from_url(value)
    return value.split("/")[0].strip()


def _add_value(value: str, feed_type: str, urls: set[str], domains: set[str]) -> None:
    if feed_type == "url":
        cleaned = _clean_url(value)
        if cleaned:
            urls.add(cleaned)
        domain = _clean_domain(value)
        if domain:
            domains.add(domain)
        return
    domain = _clean_domain(value)
    if domain:
        domains.add(domain)


def _load_local_feeds() -> tuple[set[str], set[str], list[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    sources: list[str] = []
    for path, feed_type, source_name in LOCAL_FEED_FILES:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                sample = handle.read(2048)
                handle.seek(0)
                if "," in sample.splitlines()[0]:
                    reader = csv.DictReader(handle)
                    for row in reader:
                        value = str(row.get("url") or "").strip()
                        if value:
                            _add_value(value, feed_type, urls, domains)
                else:
                    for line in handle:
                        value = line.strip()
                        if value and not value.startswith("#"):
                            _add_value(value, feed_type, urls, domains)
            sources.append(source_name)
        except OSError:
            continue
    return urls, domains, sources


def _load_remote_feeds(timeout: float) -> tuple[set[str], set[str], list[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    sources: list[str] = []
    for source_name, feed_type, feed_url in REMOTE_FEED_URLS:
        try:
            response = requests.get(feed_url, timeout=(timeout, timeout))
            response.raise_for_status()
        except requests.RequestException:
            continue
        for line in response.text.splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                _add_value(value, feed_type, urls, domains)
        sources.append(source_name)
    return urls, domains, sources


def _load_feeds(timeout: float = 2.0) -> dict[str, object]:
    now = time.time()
    if now - float(_cache["loaded_at"]) < _CACHE_TTL_SECONDS:
        return _cache

    urls, domains, sources = _load_local_feeds()
    status = "local_snapshot"
    if not urls and not domains:
        urls, domains, sources = _load_remote_feeds(timeout=timeout)
        status = "remote_snapshot" if urls or domains else "unavailable"

    _cache.update({
        "loaded_at": now,
        "urls": urls,
        "domains": domains,
        "source": ", ".join(sources) if sources else "No threat feed available",
        "status": status,
    })
    return _cache


def warm_threat_feed_cache(timeout: float = 2.0) -> dict[str, object]:
    return _load_feeds(timeout=timeout)


def lookup_threat_feed(url: str, hostname: str, timeout: float = 2.0) -> dict[str, object]:
    feeds = _load_feeds(timeout=timeout)
    normalized = _clean_url(url)
    host = _clean_domain(hostname or url)
    urls = feeds["urls"]
    domains = feeds["domains"]

    if normalized in urls:
        return {
            "matched": True,
            "source": feeds["source"],
            "match_type": "URL",
            "status": feeds["status"],
        }
    if host and any(host == domain or host.endswith(f".{domain}") for domain in domains):
        return {
            "matched": True,
            "source": feeds["source"],
            "match_type": "domain",
            "status": feeds["status"],
        }
    return {
        "matched": False,
        "source": feeds["source"],
        "match_type": "",
        "status": feeds["status"],
    }
