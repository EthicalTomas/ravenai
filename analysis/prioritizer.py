"""analysis/prioritizer.py

Prioritization of target endpoints based on path keywords, parameter 
complexity, and response metadata to optimize scanning effort.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from data.models import Endpoint, Target


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class EndpointPrioritizer:
	"""Scores and prioritizes endpoints for targeted fuzzing and analysis."""

	# Keywords that typically indicate higher-value targets
	_HIGH_VALUE_KEYWORDS: set[str] = field(default_factory=lambda: {
		"admin", "api", "auth", "login", "v1", "v2", "config", "debug", "private"
	})
	
	# Keywords that might indicate lower value (e.g., static assets)
	_LOW_VALUE_KEYWORDS: set[str] = field(default_factory=lambda: {
		"static", "assets", "img", "css", "js", "fonts", "favicon"
	})

	def prioritize(self, endpoints: set[Endpoint]) -> None:
		"""Calculate and update priority for each endpoint in-place."""
		if not endpoints:
			return

		for endpoint in endpoints:
			score = 0.5  # Baseline
			
			# 1. Path keywords scoring
			score += self._score_keywords(endpoint.url)
			
			# 2. Parameter complexity scoring
			score += self._score_parameters(endpoint)
			
			# 3. Method weight
			if endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
				score += 0.15
			
			# Final Clamp
			endpoint.priority = max(0.1, min(1.0, score))

		LOGGER.info("Prioritized %d endpoints", len(endpoints))

	def _score_keywords(self, url: str) -> float:
		"""Weighted scoring based on high and low value keywords in path."""
		adjustment = 0.0
		url_lower = url.lower()
		
		for kw in self._HIGH_VALUE_KEYWORDS:
			if kw in url_lower:
				adjustment += 0.1
				
		for kw in self._LOW_VALUE_KEYWORDS:
			if kw in url_lower:
				adjustment -= 0.15
				
		return adjustment

	def _score_parameters(self, endpoint: Endpoint) -> float:
		"""Adjust priority based on the number and type of parameters."""
		param_count = len(endpoint.params)
		if param_count == 0:
			return 0.0
		
		# More parameters = higher attack surface
		adjustment = min(0.3, param_count * 0.05)
		
		# Specific parameter name weight
		sensitive_params = {"id", "url", "file", "path", "token", "key", "cmd"}
		for p in endpoint.params:
			if p.lower() in sensitive_params:
				adjustment += 0.05
				
		return adjustment
