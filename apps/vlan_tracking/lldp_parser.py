import csv
import io
import re

HUAWEI_LLDP_LINE_RE = re.compile(
    r"^(\S+)\s+(\d+)\s+(\S+)\s+(.+)$"
)
CISCO_LLDP_LINE_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(\S+(?:\s+\S+)?)\s+(\S+)$"
)
GENERIC_LLDP_LINE_RE = re.compile(
    r"^(\S+)\s+\S+\s+(\S+)\s+(\S+)$"
)


def parse_lldp_neighbors(raw_text: str, vendor: str = None) -> list[dict]:
    if not raw_text or not raw_text.strip():
        return []
    if vendor == "huawei" or _looks_like_huawei(raw_text):
        return parse_huawei_lldp_brief(raw_text)
    elif vendor == "cisco" or _looks_like_cisco(raw_text):
        return parse_cisco_lldp_neighbors(raw_text)
    else:
        return parse_generic_lldp_table(raw_text)


def _looks_like_huawei(text: str) -> bool:
    first = text.strip().split("\n")[0].lower() if text.strip() else ""
    return "local interface" in first or "exptime" in first


def _looks_like_cisco(text: str) -> bool:
    first = text.strip().split("\n")[0].lower() if text.strip() else ""
    return "device id" in first and "local intf" in first


def parse_huawei_lldp_brief(raw_text: str) -> list[dict]:
    """Parse Huawei 'display lldp neighbor brief' output."""
    results = []
    lines = raw_text.strip().split("\n")
    header_found = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if "local interface" in low and "exptime" in low:
            header_found = True
            continue
        if header_found and re.match(r"^[-=]+$", stripped):
            continue
        if not header_found:
            continue
        m = HUAWEI_LLDP_LINE_RE.match(stripped)
        if m:
            results.append({
                "local_interface": normalize_interface_name(m.group(1)),
                "holdtime": int(m.group(2)) if m.group(2).isdigit() else 0,
                "remote_interface": normalize_interface_name(m.group(3)),
                "remote_device": m.group(4),
                "raw_line": stripped,
            })
    return results


def parse_cisco_lldp_neighbors(raw_text: str) -> list[dict]:
    """Parse Cisco 'show lldp neighbors' output."""
    results = []
    lines = raw_text.strip().split("\n")
    header_found = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if "device id" in low and "local intf" in low:
            header_found = True
            continue
        if header_found and re.match(r"^[-=]+$", stripped):
            continue
        if not header_found:
            continue
        m = CISCO_LLDP_LINE_RE.match(stripped)
        if m:
            results.append({
                "remote_device": m.group(1),
                "local_interface": normalize_interface_name(m.group(2)),
                "holdtime": int(m.group(3)) if m.group(3).isdigit() else 0,
                "capability": m.group(4).strip(),
                "remote_interface": normalize_interface_name(m.group(5)),
                "raw_line": stripped,
            })
    return results


def parse_generic_lldp_table(raw_text: str) -> list[dict]:
    """Parse generic LLDP table format: local_if remote_if remote_device."""
    results = []
    lines = raw_text.strip().split("\n")
    for line in lines:
        stripped = line.strip()
        if not stripped or re.match(r"^[-=]+$", stripped):
            continue
        parts = stripped.split()
        if len(parts) >= 3:
            results.append({
                "local_interface": normalize_interface_name(parts[0]),
                "remote_device": parts[-1],
                "remote_interface": normalize_interface_name(parts[-2] if len(parts) > 2 else ""),
                "raw_line": stripped,
            })
    return results


def parse_adjacency_csv(raw_text: str) -> list[dict]:
    """Parse CSV with columns: local_device,local_interface,remote_device,remote_interface[,method,confidence]."""
    results = []
    reader = csv.DictReader(io.StringIO(raw_text))
    for row in reader:
        local_dev = (row.get("local_device") or "").strip()
        local_iface = (row.get("local_interface") or "").strip()
        remote_dev = (row.get("remote_device") or "").strip()
        remote_iface = (row.get("remote_interface") or "").strip()
        method = (row.get("method") or "manual").strip()
        confidence = (row.get("confidence") or "high").strip()
        if not local_dev or not local_iface or not remote_dev or not remote_iface:
            results.append({
                "error": "csv_invalid_row",
                "row": row,
                "message": "Campos obrigatórios ausentes",
            })
            continue
        results.append({
            "local_device": local_dev,
            "local_interface": normalize_interface_name(local_iface),
            "remote_device": remote_dev,
            "remote_interface": normalize_interface_name(remote_iface),
            "method": method if method in ("manual", "lldp", "csv") else "manual",
            "confidence": confidence if confidence in ("high", "medium", "low") else "high",
            "raw_line": str(row),
        })
    return results


_INTERFACE_SHORTEN = {
    "GigabitEthernet": "GE",
    "XGigabitEthernet": "XGE",
    "FastEthernet": "FE",
    "FortyGigabitEthernet": "40GE",
    "HundredGigabitEthernet": "100GE",
    "Ethernet": "Eth",
    "Serial": "Serial",
    "LoopBack": "LoopBack",
    "Vlanif": "Vlanif",
    "Eth-Trunk": "Eth-Trunk",
}


def normalize_interface_name(name: str) -> str:
    if not name:
        return name
    name = name.strip()
    for full, short in _INTERFACE_SHORTEN.items():
        if name.lower().startswith(full.lower()):
            return short + name[len(full):]
    return name
