"""configs/__init__.py

Package entry-point for loading system settings and payloads.
"""

from core.config import build_settings as load_config


__all__ = ["load_config"]
