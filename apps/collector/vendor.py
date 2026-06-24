import re

VENDOR_MAP = {
    "huawei": {
        "netmiko_device_type": "huawei",
        "collect_command": "display current-configuration",
        "sysdescr_patterns": ["huawei", "vrp", "quidway", "ne40", "s series", "s5700", "s7700", "s12700"],
    },
    "cisco": {
        "netmiko_device_type": "cisco_ios",
        "collect_command": "show running-config",
        "sysdescr_patterns": ["cisco", "ios", "ios-xe", "ios-xr", "nx-os"],
    },
    "zte": {
        "netmiko_device_type": "zte_zxros",
        "collect_command": "show running-config",
        "sysdescr_patterns": ["zte", "zxros", "zxa10", "c300", "c320", "c600"],
    },
}

UNKNOWN_VENDOR = "unknown"


OID_VENDOR_MAP = {
    "1.3.6.1.4.1.2011": "huawei",
    "1.3.6.1.4.1.9": "cisco",
    "1.3.6.1.4.1.3901": "zte",
    "1.3.6.1.4.1.4242": "zte",
}


def detect_vendor_from_sysdescr(sysdescr, sysobjectid=None):
    if not sysdescr and not sysobjectid:
        return UNKNOWN_VENDOR
    if sysobjectid:
        for oid_prefix, vendor in OID_VENDOR_MAP.items():
            if sysobjectid.startswith(oid_prefix):
                return vendor
    text = (sysdescr or "") + " " + (sysobjectid or "")
    text_lower = text.lower()
    for vendor, info in VENDOR_MAP.items():
        for pattern in info["sysdescr_patterns"]:
            if pattern in text_lower:
                return vendor
    return UNKNOWN_VENDOR


def get_netmiko_device_type(vendor):
    info = VENDOR_MAP.get(vendor)
    if info:
        return info["netmiko_device_type"]
    return None


def get_collect_command(vendor):
    info = VENDOR_MAP.get(vendor)
    if info:
        return info["collect_command"]
    return None


def is_supported_vendor(vendor):
    return vendor in VENDOR_MAP
