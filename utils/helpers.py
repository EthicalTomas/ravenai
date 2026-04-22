import datetime
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable, TypeVar
from urllib.parse import urlparse


T = TypeVar("T")


def generate_fingerprint(data: str | bytes) -> str:
    """Generate a stable SHA-256 hash for a given piece of data."""
    raw = data if isinstance(data, bytes) else str(data).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_string(text: str, remove_whitespace: bool = True) -> str:
    """Lowercase and clean a string for use as a stable key."""
    if not text:
        return ""
    
    cleaned = text.strip().lower()
    if remove_whitespace:
        cleaned = re.sub(r"\s+", "_", cleaned)
        
    # Remove non-alphanumeric chars (keep underscores)
    return re.sub(r"[^a-z0-9_]+", "", cleaned)


def safe_truncate(text: str, max_length: int = 1024) -> str:
    """Truncate the text to a max_length while adding an ellipsis."""
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length] + "... [TRUNCATED]"


def setup_logging(level: str = "INFO") -> None:
    """Configure the global logging format and level."""
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    
    # Map string level to logging constants
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def normalize_url(url: str) -> str:
    """Standardize a URL for deduplication purposes."""
    if not url:
        return ""
    
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    
    # Remove trailing slashes for root paths
    if path == "/":
        path = ""
    
    # Sort and include query parameters if present
    query = ""
    if parsed.query:
        params = sorted([kv.split("=") for kv in parsed.query.split("&") if "=" in kv])
        query = "?" + "&".join([f"{k}={v}" for k, v in params])
        
    return f"{scheme}://{netloc}{path}{query}"


def extract_domain(url: str) -> str:
    """Cleanly extract the hostname (domain) from a URL string."""
    if not url:
        return ""
    
    # Handle cases without scheme (e.g. example.com)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def get_current_iso_timestamp() -> str:
    """Return the current time in ISO 8601 format (UTC)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def chunk_list(items: list[T], size: int) -> Iterable[list[T]]:
    """Split a list into smaller chunks of a specific size."""
    for i in range(0, len(items), size):
        yield items[i : i + size]


def sanitize_filename(name: str) -> str:
    """Transform a string into a safe filename (remove slashes, dots, etc.)."""
    return re.sub(r"[ :/\\]+", "_", name).lower()
