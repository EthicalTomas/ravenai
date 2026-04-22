"""integrations/burp.py

Interoperability module for Burp Suite Professional.

Functionality
-------------
* Ingests Burp Suite XML reports.
* Maps Burp "Issues" to Raven AI Vulnerability objects.
* Extracts unique Endpoints for subsequent automated fuzzing.
* Sanitizes and normalizes Burp's severity and confidence levels.
"""

from __future__ import annotations

import base64
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from data.models import Endpoint, ScanResult, Vulnerability


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class BurpMessageParser:
	"""Parses raw HTTP messages (request/response) from Burp Suite into models.

	Useful for manual copy-pasting of interactions into the pipeline.
	"""

	def parse_raw_request(self, raw_request: str, secure: bool = True) -> Endpoint:
		"""Parse a raw HTTP request string into a structured Endpoint.

		Parameters
		----------
		raw_request:
			The raw request string (e.g. from Burp's 'Copy as Request').
		secure:
			Whether to assume https (True) or http (False).
		"""
		lines = raw_request.strip().splitlines()
		if not lines:
			raise ValueError("Empty raw request")

		# 1. Parse request line (e.g. GET /path?id=1 HTTP/1.1)
		request_line = lines[0].split()
		if len(request_line) < 3:
			raise ValueError(f"Malformed request line: {lines[0]}")

		method = request_line[0].upper()
		full_path = request_line[1]

		# 2. Parse headers
		headers: dict[str, str] = {}
		body_start_idx = -1
		for i, line in enumerate(lines[1:], start=1):
			if not line.strip():
				body_start_idx = i + 1
				break
			if ":" in line:
				key, value = line.split(":", 1)
				headers[key.strip()] = value.strip()

		# 3. Determine Host and Scheme
		host = headers.get("Host", "localhost")
		scheme = "https" if secure else "http"
		url = f"{scheme}://{host}{full_path}"

		# 4. Extract parameters (query + body for POST)
		params: set[str] = set()
		if "?" in full_path:
			query = full_path.split("?", 1)[1]
			params.update(self._extract_params_from_query(query))

		if method == "POST" and body_start_idx != -1 and body_start_idx < len(lines):
			body = "\n".join(lines[body_start_idx:])
			params.update(self._extract_params_from_query(body))

		return Endpoint(url=url, method=method, params=params, headers=headers)

	def parse_raw_response(self, raw_response: str, endpoint: Endpoint) -> ScanResult:
		"""Parse a raw HTTP response into a structured ScanResult."""
		lines = raw_response.strip().splitlines()
		if not lines:
			return ScanResult(metadata={"endpoint": endpoint.to_dict(), "source": "burp_message"})

		# 1. Extract body
		body_lines: list[str] = []
		is_body = False
		for line in lines[1:]:
			if not line.strip() and not is_body:
				is_body = True
				continue
			if is_body:
				body_lines.append(line)

		body = "\n".join(body_lines)

		return ScanResult(
			vulnerabilities=[],
			raw_outputs=[raw_response],
			metadata={"endpoint": endpoint.to_dict(), "body_length": len(body), "source": "burp_message"},
		)

	def parse_interaction(self, raw_request: str, raw_response: str) -> tuple[Endpoint, ScanResult]:
		"""Convenience method to parse both request and response in one call."""
		endpoint = self.parse_raw_request(raw_request)
		result = self.parse_raw_response(raw_response, endpoint)
		return endpoint, result

	def _extract_params_from_query(self, query: str) -> set[str]:
		"""Simple parser for key=value pairs in query strings or bodies."""
		params: set[str] = set()
		for pair in query.split("&"):
			if "=" in pair:
				params.add(pair.split("=", 1)[0])
		return params


@dataclass(slots=True)
class BurpImporter:
    """Importer for Burp Suite Professional XML findings.

    Processes an XML file exported from Burp's "Target" or "Issues" tab.
    """

    def import_xml(self, xml_content: str) -> list[Vulnerability]:
        """Parse Burp XML and return a list of structured Vulnerabilities."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            LOGGER.error("Failed to parse Burp XML: %s", exc)
            return []

        vulnerabilities: list[Vulnerability] = []
        
        # Burp XML structure: <issues><issue>...</issue></issues>
        for issue_node in root.findall("issue"):
            try:
                vuln = self._parse_issue(issue_node)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as exc:
                LOGGER.warning("Failed to parse individual Burp issue node: %s", exc)
                continue

        LOGGER.info("Successfully imported %d vulnerabilities from Burp XML", len(vulnerabilities) or 0)
        return vulnerabilities

    def _parse_issue(self, node: ET.Element) -> Vulnerability | None:
        """Extract fields from a single <issue> element."""
        # Identification
        name = node.findtext("name", "Unknown Burp Finding")
        type_id = node.findtext("type", "0")
        
        # Location
        host = node.findtext("host", "")
        path = node.findtext("path", "/")
        ip = node.findtext("host", "") # May be an IP address
        
        # Build an Endpoint object
        # Note: Burp doesn't explicitly separate params in the XML overview, 
        # so we leave them empty for the initial discovery.
        url = f"https://{host}{path}"
        endpoint = Endpoint(
            url=url,
            method="GET", # Default for Burp issue overview
            params=set(),
            headers={}
        )

        # Content
        severity = node.findtext("severity", "Information").lower()
        confidence = node.findtext("confidence", "Certain").lower()
        
        # Map Burp confidence strings to float scores
        confidence_map = {
            "certain": 1.0,
            "firm": 0.8,
            "tentative": 0.4,
        }
        score = confidence_map.get(confidence, 0.5)

        # Evidence / Description
        issue_detail = node.findtext("issueDetail", "")
        request_response = []
        
        # Extract base64 encoded request/response if present
        for rr in node.findall("requestresponse"):
            req_node = rr.find("request")
            if req_node is not None and req_node.get("base64") == "true":
                try:
                    request_response.append(base64.b64decode(req_node.text or "").decode("utf-8", errors="ignore"))
                except Exception:
                    pass

        return Vulnerability(
            vuln_type=f"burp/{type_id}_{name.replace(' ', '_').lower()}",
            endpoint=endpoint,
            severity=self._map_severity(severity),
            payloads=[],
            evidence=[issue_detail] + request_response[:1],
            confidence=score,
        )

    def _map_severity(self, burp_severity: str) -> str:
        """Map Burp's custom severity strings to Raven AI standards."""
        mapping = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "information": "low",
        }
        return mapping.get(burp_severity, "low")
