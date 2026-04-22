import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ParsedURL:
    """Fully decomposed URL structure."""

    raw: str
    scheme: str
    host: str
    port: int | None
    path: str
    query_string: str
    fragment: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query_string,
        }


@dataclass(frozen=True, slots=True)
class ParsedQuery:
    """Structured container for query parameters."""

    raw_query: str
    parameters: dict[str, list[str]] = field(default_factory=dict)

    @property
    def keys(self) -> set[str]:
        return set(self.parameters.keys())

    def get_first(self, key: str, default: str | None = None) -> str | None:
        values = self.parameters.get(key)
        return values[0] if values else default


@dataclass(frozen=True, slots=True)
class FormInfo:
    """Structured information extracted from an HTML form."""

    action: str
    method: str
    parameters: set[str]


class ResponseParser:
    """Unified parser for extracting structural data from various response types."""

    def parse_url(self, url: str) -> ParsedURL:
        """Decompose a URL into a structured ParsedURL object."""
        parsed = urlparse(url)
        return ParsedURL(
            raw=url,
            scheme=parsed.scheme or "https",
            host=parsed.hostname or "",
            port=parsed.port,
            path=parsed.path or "/",
            query_string=parsed.query,
            fragment=parsed.fragment,
        )

    def parse_query(self, query: str) -> ParsedQuery:
        """Parse a query string into a structured ParsedQuery object."""
        params = parse_qs(query, keep_blank_values=True)
        return ParsedQuery(raw_query=query, parameters=params)

    def parse_json_response(self, json_content: str) -> dict[str, Any] | list[Any]:
        """Safely parse a JSON string into a structured dict or list."""
        try:
            return json.loads(json_content)
        except json.JSONDecodeError as exc:
            LOGGER.debug("JSON parsing failed: %s", exc)
            return {}

    def extract_links(self, html_content: str, base_url: str) -> set[ParsedURL]:
        """Find all absolute URLs in link and resource tags, returned as ParsedURLs."""
        links: set[ParsedURL] = set()
        
        # Regex for common href and src attributes
        # (Using regex instead of BeautifulSoup to minimize external dependencies)
        patterns = [
            r'href=["\'](.*?)["\']',
            r'src=["\'](.*?)["\']',
            r'action=["\'](.*?)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for raw_link in matches:
                absolute = self._make_absolute(raw_link.strip(), base_url)
                if absolute:
                    links.add(self.parse_url(absolute))
                    
        return links

    def extract_forms(self, html_content: str, base_url: str) -> list[FormInfo]:
        """Extract form metadata and parameter names from a page."""
        forms: list[FormInfo] = []
        
        # Identify <form> blocks
        form_blocks = re.findall(r'<form\b[^>]*>(.*?)</form>', html_content, re.DOTALL | re.IGNORECASE)
        for i, block in enumerate(form_blocks):
            # Extract form attributes (action, method)
            # Find the opening tag corresponding to this block
            # (Crude but effective for non-nested forms)
            form_tag_match = re.search(r'<form\b([^>]*)>', html_content[:html_content.find(block)], re.IGNORECASE)
            form_attrs = form_tag_match.group(1) if form_tag_match else ""
            
            action_match = re.search(r'action=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
            method_match = re.search(r'method=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
            
            action = self._make_absolute(action_match.group(1) if action_match else "", base_url) or base_url
            method = (method_match.group(1).upper() if method_match else "GET")
            
            # Extract parameter names from <input>, <select>, <textarea>
            params: set[str] = set()
            input_names = re.findall(r'name=["\'](.*?)["\']', block, re.IGNORECASE)
            for name in input_names:
                if name.strip():
                    params.add(name.strip())
            
            forms.append(FormInfo(action=action, method=method, parameters=params))
            
        return forms

    def extract_json_keys(self, json_content: str) -> set[str]:
        """Recursively find all unique keys in a JSON structure."""
        keys: set[str] = set()
        
        try:
            data = json.loads(json_content)
            self._recurse_json(data, keys)
        except (json.JSONDecodeError, TypeError):
            pass
            
        return keys

    def _recurse_json(self, data: Any, keys: set[str]) -> None:
        """Helper to walk the JSON tree and collect unique property names."""
        if isinstance(data, dict):
            for key, value in data.items():
                keys.add(str(key))
                self._recurse_json(value, keys)
        elif isinstance(data, list):
            for item in data:
                self._recurse_json(item, keys)

    def _make_absolute(self, url: str, base: str) -> str | None:
        """Standardize a link into an absolute URL."""
        if not url or url.startswith(("javascript:", "mailto:", "#")):
            return None
            
        try:
            absolute = urljoin(base, url)
            # Basic validation
            parsed = urlparse(absolute)
            if parsed.scheme and parsed.netloc:
                return absolute
        except Exception:
            pass
            
        return None
