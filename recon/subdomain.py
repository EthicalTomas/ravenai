from __future__ import annotations

import logging
import socket
from dataclasses import dataclass

from data.models import Target


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SubdomainDiscoverer:
	candidate_labels: set[str]
	dns_timeout_seconds: float

	def discover(self, target: Target) -> Target:
		if self.dns_timeout_seconds <= 0:
			raise ValueError("dns_timeout_seconds must be greater than 0")

		if not self.candidate_labels:
			LOGGER.info("No candidate subdomain labels provided; skipping discovery")
			return target

		previous_timeout = socket.getdefaulttimeout()
		socket.setdefaulttimeout(self.dns_timeout_seconds)
		try:
			for label in self.candidate_labels:
				fqdn = f"{label.strip().lower()}.{target.domain}"
				if fqdn in target.subdomains:
					continue

				try:
					socket.gethostbyname(fqdn)
					target.subdomains.add(fqdn)
					LOGGER.debug("Discovered subdomain: %s", fqdn)
				except socket.gaierror:
					LOGGER.debug("Subdomain not resolvable: %s", fqdn)
				except TimeoutError:
					LOGGER.warning("DNS lookup timed out for subdomain: %s", fqdn)
		finally:
			socket.setdefaulttimeout(previous_timeout)

		LOGGER.info("Subdomain discovery complete. Total subdomains: %d", len(target.subdomains))
		return target
