"""Parser registry.

Maps vendor identifiers to their parser classes.
Central point for discovering which parsers are available.
"""

from apps.parsers.cisco import CiscoIOSParser
from apps.parsers.huawei import HuaweiVRPParser
from apps.parsers.zte import ZTEOLTParser

# Known vendor aliases mapped to canonical vendor name and parser class
PARSER_REGISTRY: dict[str, tuple[str, type]] = {
    "huawei": ("huawei", HuaweiVRPParser),
    "huawei_vrp": ("huawei", HuaweiVRPParser),
    "vrp": ("huawei", HuaweiVRPParser),
    "cisco": ("cisco", CiscoIOSParser),
    "cisco_ios": ("cisco", CiscoIOSParser),
    "cisco_ios_xe": ("cisco", CiscoIOSParser),
    "ios": ("cisco", CiscoIOSParser),
    "ios_xe": ("cisco", CiscoIOSParser),
    "zte": ("zte", ZTEOLTParser),
    "zte_olt": ("zte", ZTEOLTParser),
    "zxa10": ("zte", ZTEOLTParser),
    "c300": ("zte", ZTEOLTParser),
    "c320": ("zte", ZTEOLTParser),
    "c600": ("zte", ZTEOLTParser),
}


def get_parser_for_vendor(vendor: str) -> tuple[str, type]:
    """Resolve a vendor string to a (canonical_name, parser_class) pair.

    Args:
        vendor: Vendor identifier (e.g. 'huawei', 'huawei_vrp', 'vrp').

    Returns:
        Tuple of (canonical_vendor_name, parser_class).

    Raises:
        KeyError: If the vendor is not supported.
    """
    vendor_lower = vendor.strip().lower()
    if vendor_lower not in PARSER_REGISTRY:
        supported = sorted({k for k in PARSER_REGISTRY})
        raise KeyError(
            f"Parser para vendor '{vendor}' não encontrado. "
            f"Vendores suportados: {', '.join(supported)}"
        )
    return PARSER_REGISTRY[vendor_lower]


def list_supported_vendors() -> list[str]:
    """Return a sorted list of all supported canonical vendor names."""
    return sorted({v[0] for v in PARSER_REGISTRY.values()})
