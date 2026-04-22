"""data/storage.py

In-memory caching layer for the Raven AI pipeline.

Design decisions
----------------
* **dict + SHA-256 hash keys** as required by the DATA STRUCTURE RULE.
  Every cache key is deterministically derived from the serialised structured
  object, so the same endpoint/target always hits the same slot.
* **Three namespaces** kept in separate dicts to prevent key collisions
  across different structured types:
    - ``endpoint_scans``  — Endpoint → ScanResult
    - ``recon_targets``   — Target (domain+subdomains+endpoints) → Target
    - ``scan_results``    — Target domain → ScanResult (full pipeline output)
* **TTL** — entries older than ``ttl_seconds`` are treated as cache misses;
  expired slots are lazily evicted on next access and eagerly on ``evict_expired()``.
* **Max-size LRU eviction** — when ``max_size`` is reached the least-recently
  used entry is removed before inserting.  Implemented with an ``OrderedDict``
  which provides O(1) move-to-end and O(1) popitem(last=False).
* **Thread safety** — a single ``threading.Lock`` per cache instance; all
  mutating and reading operations acquire it, making the cache safe to use
  from concurrent scanner threads.
* **No raw strings at module boundaries** — all public methods accept and
  return structured objects (Endpoint, Target, ScanResult).
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from data.models import Endpoint, ScanResult, Target


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration (populated from YAML — no hardcoded values in this module)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CacheConfig:
    """Runtime configuration for all cache namespaces.

    All values must be loaded from ``configs/settings.yaml``
    via :func:`build_cache_config`.

    Attributes
    ----------
    ttl_seconds:
        How long a cached entry remains valid.  0 means entries never expire.
    max_size:
        Maximum number of entries per namespace before LRU eviction kicks in.
        0 means unbounded.
    enabled:
        When False the cache always misses and never writes — useful for
        debugging or forced fresh scans.
    """

    ttl_seconds: float
    max_size: int
    enabled: bool


# ---------------------------------------------------------------------------
# Cache-hit outcome (structured, never raw strings)
# ---------------------------------------------------------------------------


class CacheOutcome(Enum):
    HIT = auto()
    MISS = auto()
    DISABLED = auto()
    EXPIRED = auto()


@dataclass(frozen=True, slots=True)
class CacheLookup:
    """Result of a cache get operation — always a structured object."""

    outcome: CacheOutcome
    key: str
    value: object | None = None

    def hit(self) -> bool:
        return self.outcome is CacheOutcome.HIT


# ---------------------------------------------------------------------------
# Internal entry — stored in each namespace dict
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _CacheEntry:
    key: str
    value: object
    stored_at: float  # monotonic seconds


# ---------------------------------------------------------------------------
# Core generic cache (all namespaces share this implementation)
# ---------------------------------------------------------------------------


class _Cache:
    """Thread-safe, TTL-aware, LRU-evicting in-memory dict cache.

    Keys are opaque SHA-256 hex strings.  Values are structured objects.
    """

    def __init__(self, config: CacheConfig, namespace: str) -> None:
        self._config = config
        self._namespace = namespace
        self._store: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> CacheLookup:
        """Return a :class:`CacheLookup` for *key*."""
        if not self._config.enabled:
            return CacheLookup(outcome=CacheOutcome.DISABLED, key=key)

        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                LOGGER.debug(
                    "[%s] cache miss key=%s", self._namespace, _short(key)
                )
                return CacheLookup(outcome=CacheOutcome.MISS, key=key)

            if self._is_expired(entry):
                del self._store[key]
                self._misses += 1
                LOGGER.debug(
                    "[%s] cache expired key=%s", self._namespace, _short(key)
                )
                return CacheLookup(outcome=CacheOutcome.EXPIRED, key=key)

            # Move to end (most recently used)
            self._store.move_to_end(key)
            self._hits += 1
            LOGGER.debug(
                "[%s] cache hit key=%s", self._namespace, _short(key)
            )
            return CacheLookup(outcome=CacheOutcome.HIT, key=key, value=entry.value)

    def put(self, key: str, value: object) -> None:
        """Store *value* under *key*, applying LRU eviction if needed."""
        if not self._config.enabled:
            return

        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._store[key] = _CacheEntry(
                    key=key, value=value, stored_at=time.monotonic()
                )
                LOGGER.debug(
                    "[%s] cache updated key=%s", self._namespace, _short(key)
                )
                return

            if self._config.max_size > 0 and len(self._store) >= self._config.max_size:
                evicted_key, _ = self._store.popitem(last=False)
                LOGGER.debug(
                    "[%s] LRU evicted key=%s", self._namespace, _short(evicted_key)
                )

            self._store[key] = _CacheEntry(
                key=key, value=value, stored_at=time.monotonic()
            )
            LOGGER.debug(
                "[%s] cache stored key=%s size=%d",
                self._namespace,
                _short(key),
                len(self._store),
            )

    def invalidate(self, key: str) -> bool:
        """Remove a single entry.  Returns True if the key existed."""
        with self._lock:
            existed = key in self._store
            if existed:
                del self._store[key]
                LOGGER.debug(
                    "[%s] cache invalidated key=%s", self._namespace, _short(key)
                )
            return existed

    def evict_expired(self) -> int:
        """Remove all entries whose TTL has elapsed.  Returns count removed."""
        if not self._config.enabled or self._config.ttl_seconds == 0:
            return 0

        with self._lock:
            expired_keys = [
                key
                for key, entry in self._store.items()
                if self._is_expired(entry)
            ]
            for key in expired_keys:
                del self._store[key]
                LOGGER.debug(
                    "[%s] evict_expired removed key=%s",
                    self._namespace,
                    _short(key),
                )

        if expired_keys:
            LOGGER.info(
                "[%s] evict_expired removed %d expired entries",
                self._namespace,
                len(expired_keys),
            )
        return len(expired_keys)

    def clear(self) -> None:
        """Remove all entries from this namespace."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
        LOGGER.info("[%s] cache cleared (%d entries removed)", self._namespace, count)

    def stats(self) -> CacheStats:
        """Return a snapshot of current cache statistics."""
        with self._lock:
            size = len(self._store)
        return CacheStats(
            namespace=self._namespace,
            size=size,
            hits=self._hits,
            misses=self._misses,
            max_size=self._config.max_size,
            ttl_seconds=self._config.ttl_seconds,
            enabled=self._config.enabled,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_expired(self, entry: _CacheEntry) -> bool:
        if self._config.ttl_seconds == 0:
            return False
        return (time.monotonic() - entry.stored_at) > self._config.ttl_seconds


# ---------------------------------------------------------------------------
# Structured statistics object (never raw strings)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CacheStats:
    """Snapshot of cache metrics for one namespace."""

    namespace: str
    size: int
    hits: int
    misses: int
    max_size: int
    ttl_seconds: float
    enabled: bool

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "size": self.size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hit_rate, 4),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds,
            "enabled": self.enabled,
        }


# ---------------------------------------------------------------------------
# Public ScanCache — typed interface over the three namespaces
# ---------------------------------------------------------------------------


class ScanCache:
    """Typed caching layer for the Raven AI pipeline.

    Three namespaces
    ----------------
    * ``endpoint_scans``: cache scan results per (scanner, endpoint) pair.
      Key = SHA-256 of ``(scanner_name, Endpoint)``.
    * ``recon_targets``: cache discovered Target after the Recon stage.
      Key = SHA-256 of the normalised target domain.
    * ``scan_results``: cache the final ScanResult for a full target run.
      Key = SHA-256 of the normalised target domain.

    Usage
    -----
    ::

        cache = ScanCache(config=cache_config)

        # Before scanning an endpoint:
        key = cache.endpoint_key(scanner_name="XSSScanner", endpoint=ep)
        lookup = cache.get_endpoint_scan(key)
        if lookup.hit():
            return lookup.value  # type: ignore[return-value]

        result = scanner.scan_endpoint(ep)
        cache.put_endpoint_scan(key, result)
        return result
    """

    def __init__(self, config: CacheConfig) -> None:
        self._endpoint_cache = _Cache(config=config, namespace="endpoint_scans")
        self._recon_cache = _Cache(config=config, namespace="recon_targets")
        self._result_cache = _Cache(config=config, namespace="scan_results")

    # ------------------------------------------------------------------
    # Key derivation — deterministic, collision-resistant SHA-256 hashes
    # ------------------------------------------------------------------

    @staticmethod
    def endpoint_key(scanner_name: str, endpoint: Endpoint) -> str:
        """Derive a cache key for a (scanner, endpoint) scan.

        The key encodes: scanner class name, URL, HTTP method, sorted params,
        and sorted headers — anything that would produce a different scan
        outcome gets a different key.
        """
        payload: dict[str, Any] = {
            "scanner": scanner_name,
            "url": endpoint.url,
            "method": endpoint.method,
            "params": sorted(endpoint.params),
            "headers": dict(sorted(endpoint.headers.items())),
        }
        return _sha256_of(payload)

    @staticmethod
    def target_recon_key(domain: str) -> str:
        """Derive a cache key for a recon target by normalised domain."""
        return _sha256_of({"domain": domain.strip().lower()})

    @staticmethod
    def scan_result_key(domain: str) -> str:
        """Derive a cache key for a full-pipeline ScanResult by domain."""
        return _sha256_of({"domain": domain.strip().lower(), "ns": "scan_result"})

    # ------------------------------------------------------------------
    # Endpoint scan namespace
    # ------------------------------------------------------------------

    def get_endpoint_scan(self, key: str) -> CacheLookup:
        """Look up a previously cached ScanResult for an endpoint."""
        return self._endpoint_cache.get(key)

    def put_endpoint_scan(self, key: str, result: ScanResult) -> None:
        """Store a ScanResult for an endpoint under *key*."""
        self._endpoint_cache.put(key, result)

    def invalidate_endpoint_scan(self, key: str) -> bool:
        """Remove a single endpoint cache entry.  Returns True if it existed."""
        return self._endpoint_cache.invalidate(key)

    # ------------------------------------------------------------------
    # Recon target namespace
    # ------------------------------------------------------------------

    def get_recon_target(self, key: str) -> CacheLookup:
        """Look up a previously cached Target from Recon."""
        return self._recon_cache.get(key)

    def put_recon_target(self, key: str, target: Target) -> None:
        """Store a discovered Target under *key*."""
        self._recon_cache.put(key, target)

    def invalidate_recon_target(self, key: str) -> bool:
        """Remove a single recon cache entry.  Returns True if it existed."""
        return self._recon_cache.invalidate(key)

    # ------------------------------------------------------------------
    # Full scan-result namespace
    # ------------------------------------------------------------------

    def get_scan_result(self, key: str) -> CacheLookup:
        """Look up a previously cached full ScanResult for a domain."""
        return self._result_cache.get(key)

    def put_scan_result(self, key: str, result: ScanResult) -> None:
        """Store a full ScanResult for a domain under *key*."""
        self._result_cache.put(key, result)

    def invalidate_scan_result(self, key: str) -> bool:
        """Remove a single scan-result cache entry.  Returns True if it existed."""
        return self._result_cache.invalidate(key)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def evict_expired(self) -> dict[str, int]:
        """Evict expired entries from all namespaces.

        Returns a dict mapping namespace name → number of entries evicted.
        """
        return {
            "endpoint_scans": self._endpoint_cache.evict_expired(),
            "recon_targets": self._recon_cache.evict_expired(),
            "scan_results": self._result_cache.evict_expired(),
        }

    def clear_all(self) -> None:
        """Wipe all namespaces — use for testing or full re-scan."""
        self._endpoint_cache.clear()
        self._recon_cache.clear()
        self._result_cache.clear()
        LOGGER.info("ScanCache: all namespaces cleared")

    def all_stats(self) -> list[CacheStats]:
        """Return statistics for all three namespaces."""
        return [
            self._endpoint_cache.stats(),
            self._recon_cache.stats(),
            self._result_cache.stats(),
        ]


# ---------------------------------------------------------------------------
# Config loader — builds CacheConfig from a raw YAML sub-mapping
# ---------------------------------------------------------------------------


def build_cache_config(raw: dict[str, object]) -> CacheConfig:
    """Build a :class:`CacheConfig` from the ``cache`` sub-mapping in YAML.

    Expected YAML shape::

        cache:
          ttl_seconds: 3600.0
          max_size: 1000
          enabled: true

    Parameters
    ----------
    raw:
        The ``cache`` sub-mapping extracted from the full settings dict.
    """
    if not isinstance(raw, dict):
        raise TypeError("cache config must be a YAML mapping")

    ttl_seconds = _require_non_negative_float(raw, "ttl_seconds")
    max_size = _require_non_negative_int(raw, "max_size")
    enabled = _require_bool(raw, "enabled")

    return CacheConfig(
        ttl_seconds=ttl_seconds,
        max_size=max_size,
        enabled=enabled,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _sha256_of(payload: dict[str, Any]) -> str:
    """Return a lowercase hex SHA-256 digest of a deterministically serialised dict."""
    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def _short(key: str) -> str:
    """Return the first 12 characters of a hash key for concise log lines."""
    return key[:12]


def _require_non_negative_float(mapping: dict[str, object], key: str) -> float:
    value = mapping.get(key)
    if isinstance(value, bool):
        raise TypeError(f"cache config '{key}' must be a float or int")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise TypeError(f"cache config '{key}' must be a float or int, got {value!r}")
    if value < 0:
        raise ValueError(f"cache config '{key}' must be >= 0, got {value}")
    return value


def _require_non_negative_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"cache config '{key}' must be an integer, got {value!r}")
    if value < 0:
        raise ValueError(f"cache config '{key}' must be >= 0, got {value}")
    return value


def _require_bool(mapping: dict[str, object], key: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"cache config '{key}' must be a boolean, got {value!r}")
    return value
