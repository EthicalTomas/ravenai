"""scanner/__init__.py

Detection engines for XSS, SQLi, SSRF, and template-based scanning.
"""

from .auth_scanner import AuthScanner
from .fuzzing_engine import FuzzingEngine
from .idor_scanner import IDORScanner
from .nuclei_wrapper import NucleiScanner, NucleiScanner as NucleiWrapper
from .sqli_scanner import SQLiScanner
from .ssrf_scanner import SSRFScanner
from .xss_scanner import XSSScanner


__all__ = [
    "AuthScanner",
    "FuzzingEngine",
    "IDORScanner",
    "NucleiScanner",
    "NucleiWrapper",
    "SQLiScanner",
    "SSRFScanner",
    "XSSScanner",
]
