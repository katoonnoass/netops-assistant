import ipaddress
import re
from typing import Optional

from django.utils import timezone

from .lldp_parser import normalize_interface_name, parse_adjacency_csv, parse_lldp_neighbors
from .models import DeviceLink, TopologyEvidence, VlanTrackingIssue

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


def _match_interface_in_device(device, interface_name):
    """Check if an interface name exists in a device's parsed data."""
    for td in device.vlan_track_entries.all():
        pc = getattr(td, "parsed_config", None)
        if pc and pc.parsed_data:
            for iface in pc.parsed_data.get("interfaces", []):
                stored_name = iface.get("name", "")
                if normalize_interface_name(stored_name) == normalize_interface_name(interface_name):
                    return True
    return False


def _find_device_by_hostname(session, hostname):
    for td in session.track_devices.select_related("device"):
        name = td.device.name
        host = getattr(td.device, "hostname", "") or name
        if hostname.upper().replace("_", "-") in name.upper().replace("_", "-"):
            return td.device
        if hostname.upper().replace("_", "-") in host.upper().replace("_", "-"):
            return td.device
    return None


def discover_links_by_lldp(session):
    created = []
    for evidence in session.evidences.filter(evidence_type="lldp"):
        device = evidence.device
        if not device:
            continue
        neighbors = parse_lldp_neighbors(evidence.raw_text)
        for nb in neighbors:
            remote_dev = _find_device_by_hostname(session, nb["remote_device"])
            if not remote_dev:
                VlanTrackingIssue.objects.create(
                    session=session,
                    device=device,
                    interface_name=nb["local_interface"],
                    severity="medium",
                    code="lldp_remote_device_not_found",
                    title=f"Vizinho LLDP '{nb['remote_device']}' não encontrado na sessão",
                    description=f"Dispositivo remoto declarado no LLDP de {device.name} não está na sessão.",
                )
                continue
            remote_iface = nb.get("remote_interface", "")
            if remote_iface and not _match_interface_in_device(remote_dev, remote_iface):
                VlanTrackingIssue.objects.create(
                    session=session,
                    device=remote_dev,
                    interface_name=remote_iface,
                    severity="low",
                    code="lldp_remote_interface_not_found",
                    title=f"Interface remota '{remote_iface}' não encontrada no parsed_data de {remote_dev.name}",
                )
            link = create_or_update_link_from_evidence(
                session=session,
                device_a=device, interface_a=nb["local_interface"],
                device_b=remote_dev, interface_b=remote_iface or nb["local_interface"],
                discovery_method="lldp",
                evidence=evidence,
                raw_evidence=nb.get("raw_line", ""),
                remote_hostname=nb["remote_device"],
                remote_interface=remote_iface,
            )
            if link and _is_not_duplicate(link, created):
                created.append(link)
    return created


def discover_links_by_csv_evidence(session):
    created = []
    for evidence in session.evidences.filter(evidence_type="csv"):
        rows = parse_adjacency_csv(evidence.raw_text)
        for row in rows:
            if "error" in row:
                VlanTrackingIssue.objects.create(
                    session=session,
                    severity="low",
                    code="csv_invalid_row",
                    title="Linha CSV inválida",
                    description=row.get("message", ""),
                    metadata=row,
                )
                continue
            local_dev = _find_device_by_hostname(session, row["local_device"])
            remote_dev = _find_device_by_hostname(session, row["remote_device"])
            if not local_dev or not remote_dev:
                VlanTrackingIssue.objects.create(
                    session=session,
                    severity="medium",
                    code="csv_device_not_found",
                    title=f"Dispositivo CSV '{row.get('local_device') or row.get('remote_device')}' não encontrado",
                )
                continue
            link = create_or_update_link_from_evidence(
                session=session,
                device_a=local_dev, interface_a=row["local_interface"],
                device_b=remote_dev, interface_b=row["remote_interface"],
                discovery_method=row.get("method", "manual"),
                evidence=evidence,
                raw_evidence=row.get("raw_line", ""),
                confidence=row.get("confidence", "high"),
            )
            if link and _is_not_duplicate(link, created):
                created.append(link)
    return created


def create_or_update_link_from_evidence(session, device_a, interface_a, device_b, interface_b,
                                        discovery_method="lldp", evidence=None, raw_evidence="",
                                        remote_hostname="", remote_interface="", confidence=""):
    if device_a == device_b:
        return None
    defaults = {
        "discovery_method": "lldp" if discovery_method in ("lldp", "csv", "manual") else discovery_method,
        "status": "confirmed" if discovery_method == "manual" else "discovered",
        "raw_evidence": raw_evidence,
        "remote_hostname": remote_hostname,
        "remote_interface": remote_interface,
        "last_seen_at": timezone.now(),
    }
    if confidence:
        defaults["confidence"] = confidence
    if evidence:
        defaults["evidence"] = evidence
    link, created = DeviceLink.objects.get_or_create(
        session=session,
        device_a=device_a, interface_a=interface_a,
        device_b=device_b, interface_b=interface_b,
        defaults=defaults,
    )
    if not created:
        changed = False
        if evidence and not link.evidence_id:
            link.evidence = evidence
            changed = True
        if raw_evidence and not link.raw_evidence:
            link.raw_evidence = raw_evidence
            changed = True
        if remote_hostname and not link.remote_hostname:
            link.remote_hostname = remote_hostname
            changed = True
        if confidence and link.confidence != confidence:
            link.confidence = confidence
            changed = True
        if discovery_method == "lldp" and link.discovery_method == "subnet":
            link.discovery_method = "lldp"
            link.confidence = "high"
            VlanTrackingIssue.objects.create(
                session=session,
                severity="info",
                code="topology_link_confirmed_by_lldp",
                title=f"Link {link} confirmado por LLDP",
            )
            changed = True
        if changed:
            link.save(update_fields=["evidence", "raw_evidence", "remote_hostname",
                                     "confidence", "discovery_method", "last_seen_at"])
    return link


def discover_links(session):
    lldp_links = discover_links_by_lldp(session)
    csv_links = discover_links_by_csv_evidence(session)
    subnet_links = discover_links_by_subnet(session)
    desc_links = discover_links_by_description(session)
    return lldp_links + csv_links + subnet_links + desc_links


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
