from __future__ import annotations

import logging
import math
import threading
import uuid
from dataclasses import dataclass, field

from data.memory.embeddings import EmbeddingGenerator
from data.models import ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SimilarityMatch:
    record_id: str
    vulnerability: Vulnerability
    score: float

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "vulnerability": self.vulnerability.to_dict(),
            "score": self.score,
        }


@dataclass(slots=True)
class VectorRecord:
    record_id: str
    vector: list[float]
    vulnerability: Vulnerability

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "vector": list(self.vector),
            "vulnerability": self.vulnerability.to_dict(),
        }


@dataclass(slots=True)
class VectorStore:
    embedding_generator: EmbeddingGenerator
    records: dict[str, VectorRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_vulnerability(self, vulnerability: Vulnerability) -> str:
        vector = self.embedding_generator.embed_vulnerability(vulnerability)
        record_id = uuid.uuid4().hex
        record = VectorRecord(record_id=record_id, vector=vector, vulnerability=vulnerability)

        with self._lock:
            self.records[record_id] = record

        LOGGER.debug("Stored vulnerability in vector memory with record_id=%s", record_id)
        return record_id

    def add_scan_result(self, scan_result: ScanResult) -> list[str]:
        inserted_ids: list[str] = []
        for vulnerability in scan_result.vulnerabilities:
            inserted_ids.append(self.add_vulnerability(vulnerability))
        LOGGER.info("Stored %d vulnerabilities from scan result", len(inserted_ids))
        return inserted_ids

    def similarity_search(
        self,
        query_vulnerability: Vulnerability,
        top_k: int,
        min_similarity: float,
    ) -> list[SimilarityMatch]:
        if top_k <= 0:
            raise ValueError("top_k must be greater than 0")
        if min_similarity < -1.0 or min_similarity > 1.0:
            raise ValueError("min_similarity must be between -1.0 and 1.0")

        query_vector = self.embedding_generator.embed_vulnerability(query_vulnerability)

        with self._lock:
            snapshot = list(self.records.values())

        scored: list[SimilarityMatch] = []
        for record in snapshot:
            score = self._cosine_similarity(query_vector, record.vector)
            if score < min_similarity:
                continue
            scored.append(
                SimilarityMatch(
                    record_id=record.record_id,
                    vulnerability=record.vulnerability,
                    score=score,
                )
            )

        scored.sort(key=lambda match: match.score, reverse=True)
        return scored[:top_k]

    def _cosine_similarity(self, left: list[float], right: list[float]) -> float:
        if len(left) != len(right):
            raise ValueError("Embedding dimensions do not match")

        numerator = sum(a * b for a, b in zip(left, right))
        left_norm = math.sqrt(sum(value * value for value in left))
        right_norm = math.sqrt(sum(value * value for value in right))

        if left_norm == 0.0 or right_norm == 0.0:
            return 0.0
        return numerator / (left_norm * right_norm)