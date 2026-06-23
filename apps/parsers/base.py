"""Base class for all vendor-specific parsers.

Each vendor parser should inherit from BaseParser and implement
the parse() method, returning a structured dictionary.
"""

from abc import ABC, abstractmethod


class BaseParser(ABC):
    """Abstract base class for configuration parsers."""

    vendor = "generic"

    def __init__(self, raw_config: str):
        self.raw_config = raw_config

    @abstractmethod
    def parse(self) -> dict:
        """Parse the raw configuration and return a structured dictionary.

        The returned dictionary must have at least the following structure:
        {
            "vendor": "vendor_name",
            "blocks": [...],
            "interfaces": [...],
            "routing": {...},
            "raw": "...",  # original text
        }

        Returns:
            dict: Structured representation of the parsed configuration.
        """
        ...

    def detect_vendor(self, raw_config: str) -> str:
        """Detect vendor from configuration text."""
        raw_lower = raw_config.lower()
        if any(token in raw_lower for token in ("zxa10", "zte", "gpon-olt_", "gpon-onu_")):
            return "zte"
        if "sysname" in raw_lower[:500]:
            return "huawei"
        if "hostname" in raw_lower[:500]:
            return "cisco"
        return "unknown"
