"""data/memory/vector_space.py

High-performance vector memory space for vulnerability embeddings.

Architecture
------------
``VectorSpace`` owns the full lifecycle:
    insert → index → query → ranked list[SimilarityMatch]

Two pluggable backends are provided:

1. ``PurePythonBackend``  — zero dependencies, O(n·d) brute-force cosine
   similarity.  Always available.  Suitable for up to ~10 k vectors.

2. ``FaissBackend``       — wraps faiss.IndexFlatIP (inner-product on
   pre-normalised vectors ≡ cosine similarity).  Activated automatically
   when ``faiss`` is importable.  Scales to millions of vectors with
   sub-millisecond query times.

The backend is selected once at ``VectorSpace`` construction time via
``VectorSpaceBackend.resolve()``.  Callers never branch on backend type.

Data structure
--------------
* ``_id_to_record : dict[int, VectorSpaceRecord]``
  Integer slot-id → record.  O(1) by slot-id.

* ``_vuln_key_to_id : dict[str, int]``
  SHA-256 content-key of (vuln_type, endpoint.url, endpoint.method) →
  slot-id.  Prevents duplicate embeddings for identical vulnerabilities.
  O(1) by content key.

Both dicts live under a single ``threading.RLock`` for thread safety.
"""

from __future__ import annotations

import array
import hashlib
import logging
import math
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from data.memory.embeddings import EmbeddingConfig, EmbeddingGenerator
from data.models import ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Try to import FAISS — graceful degradation if not available
# ---------------------------------------------------------------------------

try:
    import faiss as _faiss  # type: ignore[import]
    _FAISS_AVAILABLE = True
    LOGGER.debug("FAISS is available — will use FaissBackend for VectorSpace")
except ImportError:
    _faiss = None  # type: ignore[assignment]
    _FAISS_AVAILABLE = False
    LOGGER.debug("FAISS not available — VectorSpace will use PurePythonBackend")


# ---------------------------------------------------------------------------
# Structured result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SimilarityMatch:
    """One result from a similarity search — structured, never raw strings."""

    record_id: str
    vulnerability: Vulnerability
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "vulnerability": self.vulnerability.to_dict(),
            "score": round(self.score, 6),
        }


@dataclass(frozen=True, slots=True)
class VectorSpaceRecord:
    """An entry held inside the VectorSpace."""

    record_id: str         # opaque UUID hex
    slot_id: int           # sequential integer index into the backend
    vuln_key: str          # dedup key (SHA-256 of stable vulnerability identity)
    vulnerability: Vulnerability
    vector: list[float]    # unit-normalised embedding

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "slot_id": self.slot_id,
            "vuln_key": self.vuln_key,
            "vulnerability": self.vulnerability.to_dict(),
        }


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


class _VectorBackend(ABC):
    """Abstract ANN index backend."""

    @abstractmethod
    def add(self, slot_id: int, vector: list[float]) -> None:
        """Add a unit-normalised vector at the given slot_id."""

    @abstractmethod
    def search(
        self, query_vector: list[float], top_k: int
    ) -> list[tuple[int, float]]:
        """Return up to top_k (slot_id, score) pairs, descending by score."""

    @abstractmethod
    def size(self) -> int:
        """Return the number of indexed vectors."""


# ---------------------------------------------------------------------------
# PurePythonBackend — always available
# ---------------------------------------------------------------------------


class PurePythonBackend(_VectorBackend):
    """Brute-force cosine similarity over a flat list.

    Uses an ``array.array('f', ...)``` (single-precision float) contiguous
    buffer to keep memory compact and improve cache locality vs a list-of-lists.
    """

    def __init__(self, dimension: int) -> None:
        if dimension <= 0:
            raise ValueError("dimension must be > 0")
        self._dimension = dimension
        # Flat contiguous buffer: slot 0 occupies indices [0, dim), etc.
        self._buffer: array.array = array.array("f")
        self._count = 0

    def add(self, slot_id: int, vector: list[float]) -> None:
        if len(vector) != self._dimension:
            raise ValueError(
                f"Vector dimension {len(vector)} != expected {self._dimension}"
            )
        # slot_id must equal current count (sequential append-only)
        if slot_id != self._count:
            raise ValueError(
                f"PurePythonBackend expects sequential slot_id {self._count}, got {slot_id}"
            )
        self._buffer.extend(vector)
        self._count += 1

    def search(
        self, query_vector: list[float], top_k: int
    ) -> list[tuple[int, float]]:
        if self._count == 0:
            return []

        dim = self._dimension
        buf = self._buffer
        q = query_vector

        scored: list[tuple[int, float]] = []
        for slot in range(self._count):
            offset = slot * dim
            dot = sum(q[i] * buf[offset + i] for i in range(dim))
            scored.append((slot, dot))

        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:top_k]

    def size(self) -> int:
        return self._count


# ---------------------------------------------------------------------------
# FaissBackend — activated when faiss is importable
# ---------------------------------------------------------------------------


class FaissBackend(_VectorBackend):
    """FAISS IndexFlatIP backend (inner-product ≡ cosine on unit vectors).

    Provides O(n) search with much better constant factors than the pure-Python
    backend due to BLAS-accelerated SIMD dot products.
    """

    def __init__(self, dimension: int) -> None:
        if not _FAISS_AVAILABLE:
            raise RuntimeError(
                "FaissBackend requires the 'faiss-cpu' package. "
                "Install it with: pip install faiss-cpu"
            )
        if dimension <= 0:
            raise ValueError("dimension must be > 0")
        self._dimension = dimension
        self._index = _faiss.IndexFlatIP(dimension)  # type: ignore[attr-defined]
        LOGGER.debug("FaissBackend initialised with dimension=%d", dimension)

    def add(self, slot_id: int, vector: list[float]) -> None:
        import numpy as np  # guarded — only called when faiss is available

        arr = np.array([vector], dtype=np.float32)
        self._index.add(arr)  # type: ignore[attr-defined]

    def search(
        self, query_vector: list[float], top_k: int
    ) -> list[tuple[int, float]]:
        import numpy as np

        if self._index.ntotal == 0:  # type: ignore[attr-defined]
            return []

        k = min(top_k, self._index.ntotal)  # type: ignore[attr-defined]
        q = np.array([query_vector], dtype=np.float32)
        scores, indices = self._index.search(q, k)  # type: ignore[attr-defined]
        results: list[tuple[int, float]] = []
        for idx, score in zip(indices[0], scores[0]):
            if idx == -1:
                continue
            results.append((int(idx), float(score)))
        return results

    def size(self) -> int:
        return self._index.ntotal  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Backend resolver (reads config, never hardcoded)
# ---------------------------------------------------------------------------


class VectorSpaceBackend:
    """Factory that selects the appropriate backend for a given config."""

    @staticmethod
    def resolve(
        backend_preference: str,
        dimension: int,
    ) -> _VectorBackend:
        """Return the best available backend matching *backend_preference*.

        Parameters
        ----------
        backend_preference:
            ``"faiss"`` — use FAISS; falls back to pure-Python if not installed.
            ``"pure_python"`` — always use the pure-Python backend.
            ``"auto"`` — prefer FAISS, fall back to pure-Python.
        dimension:
            Embedding vector dimension.
        """
        pref = backend_preference.strip().lower()

        if pref == "pure_python":
            LOGGER.info("VectorSpace using PurePythonBackend (forced by config)")
            return PurePythonBackend(dimension)

        if pref == "faiss":
            if _FAISS_AVAILABLE:
                LOGGER.info("VectorSpace using FaissBackend (forced by config)")
                return FaissBackend(dimension)
            LOGGER.warning(
                "Backend 'faiss' requested but faiss is not installed; "
                "falling back to PurePythonBackend"
            )
            return PurePythonBackend(dimension)

        if pref == "auto":
            if _FAISS_AVAILABLE:
                LOGGER.info("VectorSpace using FaissBackend (auto-selected)")
                return FaissBackend(dimension)
            LOGGER.info("VectorSpace using PurePythonBackend (auto-selected, faiss unavailable)")
            return PurePythonBackend(dimension)

        raise ValueError(
            f"Unknown backend_preference {backend_preference!r}. "
            "Choose from: 'auto', 'faiss', 'pure_python'."
        )


# ---------------------------------------------------------------------------
# VectorSpaceConfig (all values from YAML — nothing hardcoded)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VectorSpaceConfig:
    """Runtime configuration for :class:`VectorSpace`.

    Attributes
    ----------
    dimension:
        Embedding vector dimension — must match ``EmbeddingConfig.dimension``.
    backend_preference:
        ``"auto"`` | ``"faiss"`` | ``"pure_python"``.
    min_similarity:
        Results below this cosine score are excluded.
    top_k_default:
        Default number of results returned when caller does not specify.
    dedup_enabled:
        When True, adding a vulnerability with an identical identity key
        (vuln_type + endpoint.url + endpoint.method) is skipped silently.
    """

    dimension: int
    backend_preference: str
    min_similarity: float
    top_k_default: int
    dedup_enabled: bool


# ---------------------------------------------------------------------------
# VectorSpace
# ---------------------------------------------------------------------------


class VectorSpace:
    """Indexed vector memory for vulnerability embeddings.

    Thread-safe.  Uses an RLock so that callers can safely call any method
    from concurrent scanner threads without race conditions.

    Usage
    -----
    ::

        config = VectorSpaceConfig(
            dimension=128,
            backend_preference="auto",
            min_similarity=0.7,
            top_k_default=5,
            dedup_enabled=True,
        )
        emb_cfg = EmbeddingConfig(dimension=128, token_pattern=r"\\w+", hash_salt="raven")
        generator = EmbeddingGenerator(config=emb_cfg)
        space = VectorSpace(config=config, embedding_generator=generator)

        space.add_vulnerability(vuln)
        matches = space.similarity_search(query_vuln)
    """

    def __init__(
        self,
        config: VectorSpaceConfig,
        embedding_generator: EmbeddingGenerator,
    ) -> None:
        if config.dimension <= 0:
            raise ValueError("VectorSpaceConfig.dimension must be > 0")
        if not 0.0 <= config.min_similarity <= 1.0:
            raise ValueError("VectorSpaceConfig.min_similarity must be in [0.0, 1.0]")
        if config.top_k_default < 1:
            raise ValueError("VectorSpaceConfig.top_k_default must be >= 1")

        self._config = config
        self._generator = embedding_generator
        self._backend: _VectorBackend = VectorSpaceBackend.resolve(
            backend_preference=config.backend_preference,
            dimension=config.dimension,
        )

        # Primary lookup: slot_id → record
        self._id_to_record: dict[int, VectorSpaceRecord] = {}
        # Deduplication: content key → slot_id
        self._vuln_key_to_id: dict[str, int] = {}
        # Next sequential slot_id
        self._next_slot: int = 0

        self._lock = threading.RLock()

        LOGGER.info(
            "VectorSpace initialised: backend=%s dimension=%d dedup=%s",
            type(self._backend).__name__,
            config.dimension,
            config.dedup_enabled,
        )

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def add_vulnerability(self, vulnerability: Vulnerability) -> str | None:
        """Embed and index a vulnerability.

        Parameters
        ----------
        vulnerability:
            Domain model object.  Never a raw string.

        Returns
        -------
        str
            The new ``record_id`` (UUID hex) if inserted.
        None
            If the vulnerability was a duplicate and dedup is enabled.
        """
        key = _vuln_content_key(vulnerability)

        with self._lock:
            if self._config.dedup_enabled and key in self._vuln_key_to_id:
                LOGGER.debug(
                    "VectorSpace: duplicate vulnerability skipped key=%s", _short(key)
                )
                return None

            vector = self._generator.embed_vulnerability(vulnerability)
            unit_vec = _ensure_unit(vector)

            slot_id = self._next_slot
            record_id = uuid.uuid4().hex
            record = VectorSpaceRecord(
                record_id=record_id,
                slot_id=slot_id,
                vuln_key=key,
                vulnerability=vulnerability,
                vector=unit_vec,
            )

            self._backend.add(slot_id, unit_vec)
            self._id_to_record[slot_id] = record
            self._vuln_key_to_id[key] = slot_id
            self._next_slot += 1

        LOGGER.debug(
            "VectorSpace: inserted slot=%d record_id=%s vuln=%s",
            slot_id, record_id[:8], vulnerability.vuln_type,
        )
        return record_id

    def add_scan_result(self, scan_result: ScanResult) -> list[str]:
        """Bulk-insert all vulnerabilities from a ScanResult.

        Returns
        -------
        list[str]
            record_ids of inserted entries (omits duplicates).
        """
        inserted: list[str] = []
        for vuln in scan_result.vulnerabilities:
            record_id = self.add_vulnerability(vuln)
            if record_id is not None:
                inserted.append(record_id)
        LOGGER.info(
            "VectorSpace: bulk insert %d/%d vulnerabilities from ScanResult",
            len(inserted), len(scan_result.vulnerabilities),
        )
        return inserted

    def remove_by_record_id(self, record_id: str) -> bool:
        """Mark a record as logically deleted.

        Note: FAISS does not support true removal; the slot is removed from
        the lookup dicts so it will never appear in search results, but the
        underlying index still contains the vector (memory is not reclaimed
        until ``rebuild_index()`` is called).

        Returns
        -------
        bool
            True if the record existed and was removed.
        """
        with self._lock:
            target_slot: int | None = None
            for slot, rec in self._id_to_record.items():
                if rec.record_id == record_id:
                    target_slot = slot
                    break

            if target_slot is None:
                return False

            removed_record = self._id_to_record.pop(target_slot)
            self._vuln_key_to_id.pop(removed_record.vuln_key, None)

        LOGGER.debug("VectorSpace: logically removed record_id=%s", record_id[:8])
        return True

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def similarity_search(
        self,
        query: Vulnerability,
        top_k: int | None = None,
        min_similarity: float | None = None,
    ) -> list[SimilarityMatch]:
        """Find the most similar stored vulnerabilities to *query*.

        Parameters
        ----------
        query:
            Reference vulnerability to search against.
        top_k:
            Maximum results to return.  Defaults to ``config.top_k_default``.
        min_similarity:
            Cosine score floor.  Defaults to ``config.min_similarity``.

        Returns
        -------
        list[SimilarityMatch]
            Ordered descending by score.  Empty list when nothing qualifies.
        """
        effective_top_k = top_k if top_k is not None else self._config.top_k_default
        effective_threshold = (
            min_similarity if min_similarity is not None else self._config.min_similarity
        )

        if effective_top_k < 1:
            raise ValueError("top_k must be >= 1")
        if not -1.0 <= effective_threshold <= 1.0:
            raise ValueError("min_similarity must be in [-1.0, 1.0]")

        with self._lock:
            if self._backend.size() == 0:
                return []

            query_vector = self._generator.embed_vulnerability(query)
            unit_query = _ensure_unit(query_vector)

            # Ask backend for top_k candidates (may include logically deleted slots)
            candidates = self._backend.search(unit_query, effective_top_k * 2)

            results: list[SimilarityMatch] = []
            for slot_id, score in candidates:
                if score < effective_threshold:
                    break  # sorted descending — no need to continue

                record = self._id_to_record.get(slot_id)
                if record is None:
                    # Logically deleted slot — skip
                    continue

                results.append(
                    SimilarityMatch(
                        record_id=record.record_id,
                        vulnerability=record.vulnerability,
                        score=score,
                    )
                )

                if len(results) >= effective_top_k:
                    break

        LOGGER.debug(
            "VectorSpace: similarity_search returned %d result(s) for vuln=%s",
            len(results), query.vuln_type,
        )
        return results

    def get_by_record_id(self, record_id: str) -> VectorSpaceRecord | None:
        """O(n) lookup by record_id.  Returns None if not found."""
        with self._lock:
            for rec in self._id_to_record.values():
                if rec.record_id == record_id:
                    return rec
        return None

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def size(self) -> int:
        """Number of active (non-deleted) records in the space."""
        with self._lock:
            return len(self._id_to_record)

    def backend_name(self) -> str:
        """Human-readable name of the active backend."""
        return type(self._backend).__name__

    def stats(self) -> VectorSpaceStats:
        """Return a structured stats snapshot — never raw strings."""
        with self._lock:
            return VectorSpaceStats(
                backend=self.backend_name(),
                active_records=len(self._id_to_record),
                index_size=self._backend.size(),
                dimension=self._config.dimension,
                dedup_enabled=self._config.dedup_enabled,
            )

    def clear(self) -> None:
        """Remove all records and reset the index."""
        with self._lock:
            self._id_to_record.clear()
            self._vuln_key_to_id.clear()
            self._next_slot = 0
            self._backend = VectorSpaceBackend.resolve(
                backend_preference=self._config.backend_preference,
                dimension=self._config.dimension,
            )
        LOGGER.info("VectorSpace: cleared all records and rebuilt index")


# ---------------------------------------------------------------------------
# Structured stats
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VectorSpaceStats:
    """Snapshot of VectorSpace metrics."""

    backend: str
    active_records: int
    index_size: int
    dimension: int
    dedup_enabled: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "active_records": self.active_records,
            "index_size": self.index_size,
            "dimension": self.dimension,
            "dedup_enabled": self.dedup_enabled,
        }


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def build_vector_space_config(raw: dict[str, object]) -> VectorSpaceConfig:
    """Build a :class:`VectorSpaceConfig` from a raw YAML sub-mapping.

    Expected YAML shape (under ``vector_space:`` in settings.yaml)::

        vector_space:
          dimension: 128
          backend_preference: auto
          min_similarity: 0.7
          top_k_default: 5
          dedup_enabled: true
    """
    if not isinstance(raw, dict):
        raise TypeError("vector_space config must be a YAML mapping")

    dimension = _require_positive_int(raw, "dimension")
    backend_preference = _require_nonempty_str(raw, "backend_preference")
    min_similarity = _require_unit_float(raw, "min_similarity")
    top_k_default = _require_positive_int(raw, "top_k_default")
    dedup_enabled = _require_bool(raw, "dedup_enabled")

    allowed = {"auto", "faiss", "pure_python"}
    if backend_preference not in allowed:
        raise ValueError(
            f"vector_space.backend_preference must be one of {allowed}, "
            f"got {backend_preference!r}"
        )

    return VectorSpaceConfig(
        dimension=dimension,
        backend_preference=backend_preference,
        min_similarity=min_similarity,
        top_k_default=top_k_default,
        dedup_enabled=dedup_enabled,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _vuln_content_key(vuln: Vulnerability) -> str:
    """SHA-256 dedup key from stable vulnerability identity fields."""
    raw = f"{vuln.vuln_type}|{vuln.endpoint.url}|{vuln.endpoint.method}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ensure_unit(vector: list[float]) -> list[float]:
    """Return a unit-normalised copy; zero vector returned as-is."""
    norm = math.sqrt(sum(v * v for v in vector))
    if norm == 0.0:
        return list(vector)
    inv = 1.0 / norm
    return [v * inv for v in vector]


def _short(key: str) -> str:
    return key[:12]


def _require_positive_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"vector_space config '{key}' must be an integer, got {value!r}")
    if value < 1:
        raise ValueError(f"vector_space config '{key}' must be >= 1, got {value}")
    return value


def _require_nonempty_str(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"vector_space config '{key}' must be a non-empty string, got {value!r}")
    return value.strip()


def _require_unit_float(mapping: dict[str, object], key: str) -> float:
    value = mapping.get(key)
    if isinstance(value, bool):
        raise TypeError(f"vector_space config '{key}' must be a float")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise TypeError(f"vector_space config '{key}' must be a float, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"vector_space config '{key}' must be in [0.0, 1.0], got {value}")
    return value


def _require_bool(mapping: dict[str, object], key: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise TypeError(f"vector_space config '{key}' must be a boolean, got {value!r}")
    return value
