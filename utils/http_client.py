"""utils/http_client.py

Robust HTTP client wrapper for scanners and crawlers.

Functionality
-------------
* Unified requests.Session management with connection pooling.
* Intelligent retry logic with exponential backoff on transient failures.
* Global header management (User-Agent, auth, etc.).
* Automated timeout enforcement for all requests.
* Response normalization and error handling.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class HTTPClientConfig:
    """Settings for the robust HTTPClient."""

    max_retries: int = 3
    backoff_factor: float = 0.5
    timeout_seconds: float = 10.0
    user_agent: str = "raven-ai-client/1.0"
    proxies: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = False  # Often needed for local intercept proxies or self-signed targets


class HTTPClient:
    """A persistent HTTP session wrapper with automated retry and timeout support.

    Parameters
    ----------
    config:
        An instance of HTTPClientConfig defining retry and timeout behaviors.
    """

    def __init__(self, config: HTTPClientConfig) -> None:
        self._config = config
        self._session = requests.Session()
        
        # Configure adaptive retry strategy
        retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        
        # Apply global headers
        self._session.headers.update({
            "User-Agent": config.user_agent,
            "Accept": "*/*",
        })
        
        # Apply proxies if any
        self._session.proxies.update(config.proxies)
        self._session.verify = config.verify_tls

    def request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        allow_redirects: bool = True,
    ) -> requests.Response:
        """Perform a robust HTTP request.

        Parameters
        ----------
        method:
            HTTP verb (GET, POST, etc.).
        url:
            Target URL.
        params:
            Query string parameters for GET.
        data:
            Form-encoded body data for POST.
        json:
            JSON-encoded body data for POST.
        headers:
            Request-specific headers to override session defaults.
        timeout:
            Override config timeout for this specific call.
        allow_redirects:
            Whether simple redirects (3xx) should be followed.

        Returns
        -------
        requests.Response
            The final response object from the session.

        Raises
        ------
        requests.exceptions.RequestException
            If the request fails after all retries.
        """
        request_timeout = timeout if timeout is not None else self._config.timeout_seconds
        
        try:
            response = self._session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                timeout=request_timeout,
                allow_redirects=allow_redirects,
            )
            return response
            
        except requests.exceptions.RequestException as exc:
            LOGGER.debug("HTTP request failed for URL %s: %s", url, exc)
            raise

    def close(self) -> None:
        """Close the underlying session and release connections."""
        self._session.close()

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
