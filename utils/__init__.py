"""utils/__init__.py

Data parsers, HTTP clients, and core developer utilities.
"""

from . import helpers, http_client, parser
from .helpers import (
    generate_fingerprint,
    normalize_string,
    normalize_url,
    safe_truncate,
    setup_logging,
    setup_logging as logger,
)
from .http_client import HTTPClient, HTTPClientConfig
from .parser import FormInfo, ParsedQuery, ParsedURL, ResponseParser


__all__ = [
    "FormInfo",
    "HTTPClient",
    "HTTPClientConfig",
    "ParsedQuery",
    "ParsedURL",
    "ResponseParser",
    "generate_fingerprint",
    "helpers",
    "http_client",
    "logger",
    "normalize_string",
    "normalize_url",
    "parser",
    "safe_truncate",
    "setup_logging",
]
