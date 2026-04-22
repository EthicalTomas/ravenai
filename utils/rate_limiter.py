"""utils/rate_limiter.py

Advanced, thread-safe rate limiting with per-domain throttling, 
intra-request delays, and dedicated headless browser limits.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Optional


LOGGER = logging.getLogger(__name__)


class RateLimiter:
	"""Thread-safe rate limiter using a sliding window for individual surfaces."""

	def __init__(self, rps: float, min_delay_seconds: float = 0.0) -> None:
		self.rps = max(0.1, rps)
		self.period = 1.0
		self.max_calls = int(self.rps) if self.rps >= 1 else 1
		self.period = 1.0 / self.rps if self.rps < 1 else 1.0
		self.min_delay = min_delay_seconds
		
		self._lock = threading.Lock()
		self._calls: deque[float] = deque()
		self._last_call = 0.0

	def allow(self) -> bool:
		"""Non-blocking check for limit compliance."""
		now = time.monotonic()
		with self._lock:
			# Enforce minimum delay between calls
			if now - self._last_call < self.min_delay:
				return False
				
			# Remove expired entries
			while self._calls and self._calls[0] <= now - self.period:
				self._calls.popleft()
				
			if len(self._calls) < self.max_calls:
				self._calls.append(now)
				self._last_call = now
				return True
			return False

	def wait(self, timeout: float | None = None) -> bool:
		"""Blocking wait until request is allowed or timeout reached."""
		start = time.monotonic()
		while not self.allow():
			if timeout is not None and (time.monotonic() - start) >= timeout:
				return False
			time.sleep(0.05)
		return True


class GlobalRateLimiter:
	"""Orchestrator for managing domain-specific and tool-specific limits."""

	def __init__(self, default_rps: float = 5.0, headless_rps: float = 1.0, min_delay_ms: int = 100) -> None:
		self.default_rps = default_rps
		self.headless_rps = headless_rps
		self.min_delay = min_delay_ms / 1000.0
		
		self._domain_limiters: dict[str, RateLimiter] = {}
		self._headless_limiter = RateLimiter(rps=headless_rps, min_delay_seconds=self.min_delay * 2)
		self._lock = threading.Lock()

	def get_limiter_for_domain(self, domain: str) -> RateLimiter:
		"""Retrieve or create a dedicated limiter for a specific host."""
		with self._lock:
			if domain not in self._domain_limiters:
				LOGGER.debug("Created new rate limiter for domain: %s (RPS: %.1f)", domain, self.default_rps)
				self._domain_limiters[domain] = RateLimiter(rps=self.default_rps, min_delay_seconds=self.min_delay)
			return self._domain_limiters[domain]

	def get_headless_limiter(self) -> RateLimiter:
		"""Retrieve the dedicated limiter for crawler-based browsing."""
		return self._headless_limiter

	def wait_for_domain(self, domain: str, timeout: float | None = None) -> bool:
		"""Stealth-friendly request gateway for a standard target."""
		return self.get_limiter_for_domain(domain).wait(timeout)

	def wait_for_headless(self, timeout: float | None = None) -> bool:
		"""Resource-friendly request gateway for chromium browsing."""
		return self.get_headless_limiter().wait(timeout)
