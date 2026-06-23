import ipaddress
import re
from typing import Optional

from .models import DeviceLink

SUBNET_PATTERNS = [
    (30, "high"),
    (31, "high"),
    (29, "low"),
]
DESCRIPTION_PATTERNS = [
    re.compile(r"LINK\s*:\s*(\S+)\s*[:\-]\s*(\S+)", re.IGNORECASE),
    re.compile(r"LINK\s+(\S+)\s+(\S+)", re.IGNORECASE),
    re.compile(r"UPLINK\s+(\S+)\s+(\S+)", re.IGNORECASE),
    re.compile(r"TO[-\s](\S+)[-\s](\S+)", re.IGNORECASE),
]


def _normalize_ip(ip_str: str) -> Optional[str]:
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    if "/" in ip_str:
        return ip_str
    parts = ip_str.replace(",", " ").split()
    if len(parts) == 2:
        try:
            return f"{parts[0]}/{parts[1]}"
        except Exception:
            pass
    return None


def _collect_l3_interfaces(session):
    devices_ip_map = {}
    for td in session.track_devices.select_related("device", "parsed_config"):
        pc = td.parsed_config
        if not pc or not pc.parsed_data:
            continue
        device = td.device
        interfaces = pc.parsed_data.get("interfaces", [])
        for iface in interfaces:
            ip = iface.get("ip_address")
            normalized = _normalize_ip(ip)
            if not normalized:
                continue
            try:
                net = ipaddress.IPv4Interface(normalized).network
            except ValueError:
                continue
            devices_ip_map.setdefault(device, []).append({
                "interface": iface["name"],
                "network": net,
                "ip": normalized,
            })
    return devices_ip_map


def discover_links_by_subnet(session):
    if not session.track_devices.exists():
        return []
    devices_ip_map = _collect_l3_interfaces(session)
    device_list = list(devices_ip_map.items())
    created = []
    for i in range(len(device_list)):
        dev_a, ifaces_a = device_list[i]
        for j in range(i + 1, len(device_list)):
            dev_b, ifaces_b = device_list[j]
            for ia in ifaces_a:
                for ib in ifaces_b:
                    if ia["network"] == ib["network"]:
                        mask = ia["network"].prefixlen
                        confidence = "high" if mask in (30, 31) else "medium"
                        link, _ = DeviceLink.objects.get_or_create(
                            session=session,
                            device_a=dev_a,
                            interface_a=ia["interface"],
                            device_b=dev_b,
                            interface_b=ib["interface"],
                            defaults={
                                "discovery_method": "subnet",
                                "confidence": "high" if mask in (30, 31) else "low",
                                "status": "discovered",
                            },
                        )
                        if _is_not_duplicate(link, created):
                            created.append(link)
    return created


def discover_links_by_description(session):
    created = []
    for td in session.track_devices.select_related("device", "parsed_config"):
        pc = td.parsed_config
        if not pc or not pc.parsed_data:
            continue
        device = td.device
        for iface in pc.parsed_data.get("interfaces", []):
            desc = (iface.get("description") or "").strip()
            if not desc:
                continue
            for pat in DESCRIPTION_PATTERNS:
                m = pat.search(desc)
                if m:
                    target_device_name = m.group(1)
                    target_interface = m.group(2)
                    target_device = _find_device_in_session(session, target_device_name)
                    if target_device and target_device != device:
                        link, _ = DeviceLink.objects.get_or_create(
                            session=session,
                            device_a=device,
                            interface_a=iface["name"],
                            device_b=target_device,
                            interface_b=target_interface,
                            defaults={
                                "discovery_method": "description",
                                "confidence": "medium",
                                "status": "discovered",
                            },
                        )
                        if _is_not_duplicate(link, created):
                            created.append(link)
                    break
    return created


def discover_links(session):
    subnet_links = discover_links_by_subnet(session)
    desc_links = discover_links_by_description(session)
    return subnet_links + desc_links


def _find_device_in_session(session, name_or_substring):
    for td in session.track_devices.select_related("device"):
        if name_or_substring.upper() in td.device.name.upper():
            return td.device
    return None


def _is_not_duplicate(link, existing_links):
    for existing in existing_links:
        if link.device_a_id == existing.device_a_id and link.interface_a == existing.interface_a:
            if link.device_b_id == existing.device_b_id and link.interface_b == existing.interface_b:
                return False
        if link.device_a_id == existing.device_b_id and link.interface_a == existing.interface_b:
            if link.device_b_id == existing.device_a_id and link.interface_b == existing.interface_a:
                return False
    return True


def normalize_device_link(session):
    links = DeviceLink.objects.filter(session=session)
    for link in links:
        a_id = link.device_a_id
        b_id = link.device_b_id
        if a_id > b_id or (a_id == b_id and link.interface_a > link.interface_b):
            link.device_a_id, link.device_b_id = link.device_b_id, link.device_a_id
            link.interface_a, link.interface_b = link.interface_b, link.interface_a
            link.save()
