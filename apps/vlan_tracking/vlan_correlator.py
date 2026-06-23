import ipaddress
import re

from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

from .models import (
    DeviceLink,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackingIssue,
)
from .topology import discover_links, normalize_device_link

EXPAND_VLAN_RE = re.compile(r"(?:vlan\s+batch\s+)?")


def _expand_vlan_list(vlan_str):
    if not vlan_str or not isinstance(vlan_str, str):
        return []
    vlan_str = vlan_str.strip().replace(",", " ")
    parts = vlan_str.split()
    vlans = set()
    i = 0
    while i < len(parts):
        if parts[i].lower() == "to" and i > 0 and i + 1 < len(parts):
            try:
                start = int(parts[i - 1])
                end = int(parts[i + 1])
                vlans.update(range(start, end + 1))
                parts.pop(i)
                parts.pop(i)
                continue
            except ValueError:
                pass
        elif "-" in parts[i]:
            try:
                a, b = parts[i].split("-", 1)
                vlans.update(range(int(a), int(b) + 1))
                parts.pop(i)
                continue
            except ValueError:
                pass
        try:
            vlans.add(int(parts[i]))
        except (ValueError, IndexError):
            pass
        i += 1
    return sorted(v for v in vlans if 1 <= v <= 4094)


def extract_vlan_interfaces_from_device(track_device):
    pc = track_device.parsed_config
    if not pc or not pc.parsed_data:
        return []
    results = []
    interfaces = pc.parsed_data.get("interfaces", [])
    for iface in interfaces:
        name = iface.get("name", "")
        desc = iface.get("description", "")
        port_mode = iface.get("port_mode", "")

        # Access port
        if port_mode == "access":
            vlan = iface.get("access_vlan")
            if vlan and vlan.isdigit():
                results.append({
                    "interface_name": name, "vlan_id": int(vlan),
                    "port_mode": "access", "tagged": False, "pvid": True,
                    "source": "access_vlan", "description": desc,
                })

        # Trunk port
        if port_mode == "trunk":
            allowed = iface.get("trunk_allowed_vlans", "")
            for v in _expand_vlan_list(allowed):
                pvid = iface.get("trunk_pvid", "")
                is_pvid = pvid.isdigit() and int(pvid) == v
                results.append({
                    "interface_name": name, "vlan_id": v,
                    "port_mode": "trunk", "tagged": True, "pvid": is_pvid,
                    "source": "trunk_allowed", "description": desc,
                })

        # Hybrid port
        if port_mode == "hybrid":
            tagged = iface.get("hybrid_tagged_vlans", "")
            untagged = iface.get("hybrid_untagged_vlans", "")
            pvid = iface.get("hybrid_pvid", "")
            for v in _expand_vlan_list(tagged):
                results.append({
                    "interface_name": name, "vlan_id": v,
                    "port_mode": "hybrid", "tagged": True,
                    "pvid": pvid.isdigit() and int(pvid) == v,
                    "source": "hybrid_tagged", "description": desc,
                })
            for v in _expand_vlan_list(untagged):
                results.append({
                    "interface_name": name, "vlan_id": v,
                    "port_mode": "hybrid", "tagged": False,
                    "pvid": pvid.isdigit() and int(pvid) == v,
                    "source": "hybrid_untagged", "description": desc,
                })

        # Subinterface dot1q
        vlan_type = iface.get("vlan_type")
        if vlan_type == "dot1q":
            vid = iface.get("vlan_id")
            if vid and str(vid).isdigit():
                results.append({
                    "interface_name": name, "vlan_id": int(vid),
                    "port_mode": "subinterface", "tagged": True, "pvid": False,
                    "source": "dot1q", "description": desc,
                })

        # QinQ
        if vlan_type == "qinq_termination":
            pe = iface.get("pe_vid")
            ce = iface.get("ce_vid")
            if pe and str(pe).isdigit():
                results.append({
                    "interface_name": name, "vlan_id": int(pe),
                    "port_mode": "qinq", "tagged": True, "pvid": False,
                    "source": "qinq", "description": desc,
                })

        # L2VPN VSI
        if vlan_type == "l2binding":
            vsi = iface.get("vsi_name", "")
            results.append({
                "interface_name": name, "vlan_id": 0,
                "port_mode": "l2vpn", "tagged": True, "pvid": False,
                "source": "vsi", "description": f"VSI: {vsi}",
            })

        # BAS user-vlan
        user_vlan = iface.get("user_vlan")
        if user_vlan and str(user_vlan).isdigit():
            results.append({
                "interface_name": name, "vlan_id": int(user_vlan),
                "port_mode": "bas", "tagged": True, "pvid": False,
                "source": "bas_user_vlan", "description": desc,
            })

    return results


def build_vlan_definitions(session):
    existing_ids = set(VlanDefinition.objects.filter(session=session).values_list("vlan_id", flat=True))
    found_ids = set()
    for td in session.track_devices.select_related("device", "parsed_config"):
        pc = td.parsed_config
        if not pc or not pc.parsed_data:
            continue
        vlans_data = pc.parsed_data.get("vlans", [])
        for v in vlans_data:
            vid = v.get("vlan_id")
            if not vid:
                continue
            found_ids.add(vid)
            if vid not in existing_ids:
                VlanDefinition.objects.create(
                    session=session,
                    vlan_id=vid,
                    name=v.get("name", ""),
                    description=v.get("description", ""),
                    first_seen_device=td.device,
                )
                existing_ids.add(vid)

    # Also create definitions for VLANs found via interfaces
    vlan_interfaces = VlanInterface.objects.filter(session=session)
    for vi in vlan_interfaces:
        if vi.vlan_id and vi.vlan_id not in existing_ids:
            VlanDefinition.objects.create(
                session=session,
                vlan_id=vi.vlan_id,
                first_seen_device=vi.device,
            )
            existing_ids.add(vi.vlan_id)


def build_vlan_interfaces(session):
    for td in session.track_devices.select_related("device", "snapshot", "parsed_config"):
        extracted = extract_vlan_interfaces_from_device(td)
        for item in extracted:
            VlanInterface.objects.create(
                session=session,
                device=td.device,
                snapshot=td.snapshot,
                interface_name=item["interface_name"],
                vlan_id=item["vlan_id"],
                port_mode=item["port_mode"],
                tagged=item["tagged"],
                pvid=item["pvid"],
                source=item["source"],
                description=item["description"],
            )


def build_vlan_endpoints(session):
    for vdef in VlanDefinition.objects.filter(session=session):
        # Access ports and BAS are endpoints
        vlan_ifaces = VlanInterface.objects.filter(
            session=session, vlan_id=vdef.vlan_id
        )

        for vi in vlan_ifaces:
            ep_type = _infer_endpoint_type(vi)
            if ep_type:
                VlanEndpoint.objects.create(
                    session=session,
                    vlan_definition=vdef,
                    device=vi.device,
                    interface_name=vi.interface_name,
                    endpoint_type=ep_type,
                    description=vi.description,
                )


def _infer_endpoint_type(vi):
    if vi.port_mode == "access" and not vi.tagged:
        return "access"
    if vi.port_mode == "subinterface":
        return "subinterface_l3"
    if vi.port_mode == "l2vpn":
        return "l2vpn_vsi"
    if vi.port_mode == "bas":
        return "bas"
    if vi.port_mode == "qinq":
        return "qinq_edge"
    return None


def build_vlan_paths(session):
    links = DeviceLink.objects.filter(
        session=session, status__in=("discovered", "confirmed")
    )
    for link in links:
        vlan_a = set(
            VlanInterface.objects.filter(
                session=session, device=link.device_a, interface_name=link.interface_a
            ).values_list("vlan_id", flat=True)
        )
        vlan_b = set(
            VlanInterface.objects.filter(
                session=session, device=link.device_b, interface_name=link.interface_b
            ).values_list("vlan_id", flat=True)
        )
        common = vlan_a & vlan_b

        for vid in common:
            vdef = VlanDefinition.objects.filter(session=session, vlan_id=vid).first()
            if not vdef:
                continue
            VlanPath.objects.create(
                session=session,
                vlan_definition=vdef,
                from_device=link.device_a,
                from_interface=link.interface_a,
                to_device=link.device_b,
                to_interface=link.interface_b,
                via_link=link,
                tagged=True,
                status="active",
            )

        # VLANs no trunk de um lado mas ausentes do outro geram issue
        only_a = vlan_a - vlan_b
        only_b = vlan_b - vlan_a
        for vid in only_a:
            _create_missing_neighbor_issue(session, vid, link, link.device_a, link.device_b)
        for vid in only_b:
            _create_missing_neighbor_issue(session, vid, link, link.device_b, link.device_a)


def _create_missing_neighbor_issue(session, vid, link, present_device, missing_device):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vid).first()
    VlanTrackingIssue.objects.create(
        session=session,
        vlan_definition=vdef,
        device=present_device,
        interface_name=link.interface_a if present_device == link.device_a else link.interface_b,
        severity="medium",
        code="vlan_on_trunk_missing_on_neighbor",
        title=f"VLAN {vid} presente no trunk de {present_device.name} mas ausente em {missing_device.name}",
        description="A VLAN está configurada no trunk de um dispositivo mas não no outro lado do enlace.",
    )


def build_tracking_issues(session):
    # Endpoints without path
    for ep in VlanEndpoint.objects.filter(session=session):
        has_path = VlanPath.objects.filter(
            session=session,
            vlan_definition=ep.vlan_definition,
        ).exists()
        if not has_path:
            VlanTrackingIssue.objects.create(
                session=session,
                vlan_definition=ep.vlan_definition,
                device=ep.device,
                interface_name=ep.interface_name,
                severity="low",
                code="vlan_endpoint_without_path",
                title=f"{ep.get_endpoint_type_display()} na VLAN {ep.vlan_definition.vlan_id} sem caminho",
                description="Endpoint existe mas não há caminho L2 conectando a outros dispositivos.",
            )

    # VLAN defined but not used
    for vdef in VlanDefinition.objects.filter(session=session):
        iface_count = VlanInterface.objects.filter(
            session=session, vlan_id=vdef.vlan_id
        ).count()
        if iface_count == 0:
            VlanTrackingIssue.objects.create(
                session=session,
                vlan_definition=vdef,
                severity="info",
                code="vlan_defined_but_not_used",
                title=f"VLAN {vdef.vlan_id} definida mas não usada",
                description="A VLAN está definida no equipamento mas não é usada em nenhuma interface.",
            )

    # VLAN used but not defined
    for vdef in VlanDefinition.objects.filter(session=session, name="", description="",
                                              first_seen_device__isnull=False):
        used_in_vlan_def = VlanInterface.objects.filter(
            session=session, vlan_id=vdef.vlan_id
        ).exclude(device=vdef.first_seen_device).exists()
        if not used_in_vlan_def:
            # Check if it came from interface extraction, not vlan block
            pass

    # Subinterface VLAN without L2 path
    for vi in VlanInterface.objects.filter(session=session, port_mode="subinterface"):
        vdef = VlanDefinition.objects.filter(session=session, vlan_id=vi.vlan_id).first()
        if not vdef:
            continue
        has_l2_path = VlanPath.objects.filter(
            session=session, vlan_definition=vdef
        ).exists()
        if not has_l2_path:
            VlanTrackingIssue.objects.create(
                session=session,
                vlan_definition=vdef,
                device=vi.device,
                interface_name=vi.interface_name,
                severity="medium",
                code="subinterface_vlan_without_l2_path",
                title=f"VLAN {vi.vlan_id} em subinterface sem caminho L2",
                description="A VLAN está presente em subinterface roteada mas não há caminho L2 até ela.",
            )


def run_vlan_correlation(session):
    _clean_derived_data(session)
    normalize_device_link(session)
    discover_links(session)
    build_vlan_interfaces(session)
    build_vlan_definitions(session)
    build_vlan_endpoints(session)
    build_vlan_paths(session)
    build_tracking_issues(session)
    _update_counts(session)


def _clean_derived_data(session):
    VlanDefinition.objects.filter(session=session).delete()
    VlanInterface.objects.filter(session=session).delete()
    VlanEndpoint.objects.filter(session=session).delete()
    VlanPath.objects.filter(session=session).delete()
    VlanTrackingIssue.objects.filter(session=session).delete()

    # Remove auto-discovered links only; preserve manual links
    DeviceLink.objects.filter(
        session=session, discovery_method__in=("subnet", "description")
    ).delete()


def _update_counts(session):
    for vdef in VlanDefinition.objects.filter(session=session):
        ifaces = VlanInterface.objects.filter(session=session, vlan_id=vdef.vlan_id)
        vdef.interface_count = ifaces.count()
        vdef.device_count = ifaces.values("device").distinct().count()
        vdef.save(update_fields=["interface_count", "device_count"])
