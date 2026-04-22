from __future__ import annotations

import hashlib
import logging
import math
import re
from dataclasses import dataclass

from data.models import Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EmbeddingConfig:
	dimension: int
	token_pattern: str
	hash_salt: str


@dataclass(slots=True)
class EmbeddingGenerator:
	config: EmbeddingConfig

	def embed_vulnerability(self, vulnerability: Vulnerability) -> list[float]:
		text = self.serialize_vulnerability(vulnerability)
		return self.embed_text(text)

	def embed_text(self, text: str) -> list[float]:
		if self.config.dimension <= 0:
			raise ValueError("Embedding dimension must be greater than 0")

		tokens = self._tokenize(text)
		if not tokens:
			return [0.0 for _ in range(self.config.dimension)]

		vector = [0.0 for _ in range(self.config.dimension)]
		for token in tokens:
			index, value = self._token_projection(token)
			vector[index] += value

		return self._normalize(vector)

	def serialize_vulnerability(self, vulnerability: Vulnerability) -> str:
		endpoint = vulnerability.endpoint
		params = ",".join(sorted(endpoint.params))
		headers = ",".join(f"{key}:{value}" for key, value in sorted(endpoint.headers.items()))
		payloads = " | ".join(vulnerability.payloads)
		evidence = " | ".join(vulnerability.evidence)

		return "\n".join(
			[
				f"vuln_type={vulnerability.vuln_type}",
				f"severity={vulnerability.severity}",
				f"confidence={vulnerability.confidence}",
				f"endpoint_url={endpoint.url}",
				f"endpoint_method={endpoint.method}",
				f"params={params}",
				f"headers={headers}",
				f"payloads={payloads}",
				f"evidence={evidence}",
			]
		)

	def _tokenize(self, text: str) -> list[str]:
		compiled = re.compile(self.config.token_pattern)
		return [token.lower() for token in compiled.findall(text)]

	def _token_projection(self, token: str) -> tuple[int, float]:
		digest = hashlib.sha256(f"{self.config.hash_salt}:{token}".encode("utf-8")).digest()
		integer_value = int.from_bytes(digest, "big")
		index = integer_value % self.config.dimension

		magnitude_seed = int.from_bytes(digest[:8], "big")
		magnitude = 1.0 + (magnitude_seed % self.config.dimension) / max(1, self.config.dimension)
		return index, magnitude

	def _normalize(self, vector: list[float]) -> list[float]:
		norm = math.sqrt(sum(value * value for value in vector))
		if norm == 0.0:
			LOGGER.debug("Generated a zero norm embedding vector")
			return vector
		return [value / norm for value in vector]
