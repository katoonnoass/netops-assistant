"""Serviço de busca técnica global determinística.

Busca em dispositivos, snapshots, dados parseados (interfaces, rotas, BGP),
circuitos, serviços, issues e texto bruto das configurações.

Não usa IA — apenas consultas ao banco e análise de dados existentes.
"""

import ipaddress
import re
from collections.abc import Sequence
from typing import Any

from django.db.models import Q, QuerySet

from apps.analysis.models import (
    AnalysisIssue,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

# ── helpers ────────────────────────────────────────────────────────────────


def _normalize_query(query: str) -> str:
    """Remove leading 'AS' or 'vlan ' prefix for more flexible matching."""
    q = query.strip()
    # "AS64520" → "64520"
    if q.upper().startswith("AS") and len(q) > 2 and q[2:].strip().isdigit():
        return q[2:].strip()
    # "vlan 1234" → "1234"
    lower = q.lower()
    if lower.startswith("vlan ") and len(q) > 5:
        return q[5:].strip()
    return q


def _bgp_net_to_cidr(net: str) -> str | None:
    """Convert BGP network format 'X mask Y' to CIDR 'X/Y'."""
    m = re.match(r"^(\S+)\s+mask\s+(\S+)$", net)
    if not m:
        return None
    ip_str, mask_str = m.group(1), m.group(2)
    try:
        net_obj = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
        return str(net_obj)
    except ValueError:
        return None


def _exact_ip(s: str) -> str | None:
    """Return the string if it looks like an IPv4 address, else None."""
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return s
    return None


# ── classification ─────────────────────────────────────────────────────────


def classify_search_query(query: str) -> dict[str, Any]:
    """Detect the type of search query.

    Returns a dict with at least the key ``type``:

    - ``ip``         — exact IPv4 address (e.g. ``10.255.123.2``)
    - ``prefix``     — CIDR prefix (e.g. ``200.200.200.0/30``)
    - ``vlan``       — numeric VLAN id (e.g. ``1234``)
    - ``interface``  — interface name (e.g. ``Eth-Trunk100.1234``)
    - ``asn``        — Autonomous System Number (e.g. ``64520`` or ``AS64520``)
    - ``text``       — anything else
    """
    q = query.strip()

    # --- IP address ---
    ip_val = _exact_ip(q)
    if ip_val:
        try:
            ipaddress.ip_address(ip_val)
            return {"type": "ip", "value": ip_val, "query": query}
        except ValueError:
            pass

    # --- CIDR prefix ---
    if "/" in q:
        try:
            net = ipaddress.ip_network(q, strict=False)
            return {"type": "prefix", "value": str(net), "network": net, "query": query}
        except ValueError:
            pass

    norm = _normalize_query(q)

    # --- VLAN (purely numeric, or starts with keyword "vlan ") ---
    # "vlan 1234" after normalize → "1234"
    if norm.isdigit():
        val = int(norm)
        # ASN range: 1-65535 (16-bit) or 1-4294967295 (32-bit).
        # But VLAN is 1-4094. Numbers above 4094 are likely ASN.
        if 1 <= val <= 4094:
            return {"type": "vlan", "value": norm, "query": query}
        # Numbers > 4094 may be ASN
        return {"type": "asn", "value": norm, "query": query}

    # --- ASN with "AS" prefix ---
    if q.upper().startswith("AS") and norm.isdigit():
        return {"type": "asn", "value": norm, "query": query}

    # --- Interface pattern ---
    # Match common interface names: Eth-Trunk, GigabitEthernet, etc.
    if re.match(
        r"^(Eth-Trunk|GigabitEthernet|XGigabitEthernet|40GE|100GE|"
        r"LoopBack|Vlanif|Serial|POS|Bridge|NULL|NVE)\d+",
        q,
        re.IGNORECASE,
    ):
        return {"type": "interface", "value": q, "query": query}

    # --- Eth-Trunk subinterface pattern ---
    if re.match(r"^Eth-Trunk\d+(\.\d+)?$", q, re.IGNORECASE):
        return {"type": "interface", "value": q, "query": query}

    # --- ISIS / MPLS / LDP keyword ---
    if q.lower() in ("isis", "mpls", "ldp"):
        return {"type": "text", "value": q, "query": query}

    return {"type": "text", "value": q, "query": query}


# ── matching helpers ────────────────────────────────────────────────────────


def _ip_in_net(ip_str: str, net_str: str) -> bool:
    """Check if ip_str falls within net_str."""
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(net_str, strict=False)
        return ip in net
    except ValueError:
        return False


def _net_overlaps(a: str, b: str) -> bool:
    """Check if two CIDR prefixes overlap."""
    try:
        na = ipaddress.ip_network(a, strict=False)
        nb = ipaddress.ip_network(b, strict=False)
        return na.overlaps(nb)
    except ValueError:
        return False


def _get_evidence_lines(raw_text: str, query: str, context: int = 2) -> list[str]:
    """Return matching lines from raw text with surrounding context.

    Only returns a limited number of matches to avoid exposing the full config.
    Maximum 5 matches, each with up to ``context`` lines before/after.
    """
    lines = raw_text.splitlines()
    matches: list[str] = []
    seen_indices: set[int] = set()

    for i, line in enumerate(lines):
        if query.lower() in line.lower():
            if i in seen_indices:
                continue
            seen_indices.add(i)
            start = max(0, i - context)
            end = min(len(lines), i + context + 1)
            snippet = "\n".join(lines[start:end])
            matches.append(snippet)
            if len(matches) >= 5:
                break

    return matches


def _score_result(
    classification: dict, fields: list[tuple[str, str]]
) -> float:
    """Simple scoring: 1.0 for exact match, 0.7 for substring, 0.4 for partial."""
    query_lower = classification["query"].lower()
    qtype = classification["type"]
    best = 0.0
    for field_name, field_value in fields:
        if not field_value:
            continue
        fv = str(field_value).lower()
        # Exact match
        if query_lower == fv:
            return 1.0
        # Substring match
        if query_lower in fv:
            best = max(best, 0.7)
        # Word boundary match
        if re.search(rf"\b{re.escape(query_lower)}\b", fv):
            best = max(best, 0.8)
    # For IP/VLAN/ASN numeric types, try exact numeric comparison
    if qtype in ("vlan", "asn", "ip") and classification.get("value"):
        val = classification["value"]
        for _, field_value in fields:
            if field_value and str(field_value) == val:
                return 1.0
            if field_value and val in str(field_value):
                best = max(best, 0.7)
    return best


# ── searchers ──────────────────────────────────────────────────────────────


def _search_devices(
    classification: dict, filters: dict | None
) -> list[dict]:
    """Search in Device model."""
    q = classification["query"]
    qs = Device.objects.all()

    # Apply filters
    if filters:
        if filters.get("vendor"):
            qs = qs.filter(vendor=filters["vendor"])
        if filters.get("device"):
            qs = qs.filter(name__icontains=filters["device"])
        # last_snapshot_only is irrelevant for devices

    # Build filter: search name, hostname, ip, description, vendor
    qs = qs.filter(
        Q(name__icontains=q)
        | Q(hostname__icontains=q)
        | Q(ip_address__icontains=q)
        | Q(description__icontains=q)
        | Q(vendor__icontains=q)
    )

    results = []
    for dev in qs:
        score = _score_result(
            classification,
            [
                ("name", dev.name),
                ("hostname", dev.hostname),
                ("ip", str(dev.ip_address or "")),
                ("description", dev.description),
                ("vendor", dev.vendor),
            ],
        )
        results.append(
            {
                "type": "device",
                "title": dev.name,
                "description": f"{dev.get_vendor_display()} — {dev.ip_address or 'sem IP'}",
                "device": dev.name,
                "device_pk": dev.pk,
                "snapshot": None,
                "parsed_config": None,
                "url": f"/devices/{dev.pk}/",
                "score": score,
                "metadata": {
                    "vendor": dev.vendor,
                    "ip": str(dev.ip_address or ""),
                    "hostname": dev.hostname,
                },
            }
        )
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def _search_snapshots(
    classification: dict, filters: dict | None
) -> list[dict]:
    """Search in ConfigSnapshot model — raw_config + vendor + device."""
    q = classification["query"]
    qs = ConfigSnapshot.objects.select_related("device").all()

    if filters:
        if filters.get("vendor"):
            qs = qs.filter(vendor=filters["vendor"])
        if filters.get("device"):
            qs = qs.filter(device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only"):
            # Only last snapshot per device
            from django.db.models import Max

            latest_ids = (
                qs.values("device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            qs = qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for snap in qs:
        score = _score_result(
            classification,
            [
                ("vendor", snap.vendor),
                ("source", snap.source),
                ("notes", snap.notes),
                ("device", snap.device.name if snap.device else ""),
            ],
        )

        # Check raw_config for evidence
        evidence = _get_evidence_lines(snap.raw_config, q)
        if evidence:
            score = max(score, 0.6)

        if score == 0.0:
            continue

        # Get parsed_config if exists
        parsed = ParsedConfig.objects.filter(snapshot=snap).first()
        parsed_pk = parsed.pk if parsed else None

        results.append(
            {
                "type": "snapshot",
                "title": f"Snapshot #{snap.pk} — {snap.device.name if snap.device else '(sem dispositivo)'}",
                "description": f"{snap.vendor} | {snap.created_at:%d/%m/%Y %H:%M}",
                "device": snap.device.name if snap.device else "",
                "device_pk": snap.device.pk if snap.device else None,
                "snapshot": snap.pk,
                "parsed_config": parsed_pk,
                "url": f"/analysis/{parsed_pk}/" if parsed_pk else f"/configs/",
                "score": score,
                "metadata": {
                    "vendor": snap.vendor,
                    "source": snap.source,
                    "notes": snap.notes,
                    "created_at": snap.created_at.isoformat(),
                },
                "evidence": evidence[:3] if evidence else [],
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]


def _search_interfaces(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search interfaces inside ParsedConfig.parsed_data."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max

            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        interfaces = parsed.parsed_data.get("interfaces", [])
        if not interfaces:
            continue
        for iface in interfaces:
            score = _search_interfaces_score(classification, iface)
            if score == 0.0:
                continue

            ip_str = iface.get("ip_address", "")
            vlan_id = str(iface.get("vlan_id") or "")
            desc = iface.get("description", "")
            name = iface.get("name", "")

            evidence = []
            raw = iface.get("raw", "")
            if raw:
                lines = raw.splitlines()
                for line in lines:
                    if q.lower() in line.lower():
                        evidence.append(line)

            results.append(
                {
                    "type": "interface",
                    "title": name,
                    "description": desc or "(sem descrição)",
                    "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                    "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "metadata": {
                        "name": name,
                        "type": iface.get("type", ""),
                        "ip": ip_str,
                        "vlan_id": vlan_id,
                        "description": desc,
                        "vsi_name": iface.get("vsi_name", ""),
                    },
                    "evidence": evidence[:3],
                }
            )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:30]


def _search_interfaces_score(classification: dict, iface: dict) -> float:
    """Calculate relevance score for an interface against the classification."""
    qtype = classification["type"]
    qval = classification.get("value", classification["query"])

    name = iface.get("name", "")
    desc = iface.get("description", "")
    ip = iface.get("ip_address", "")
    vlan_id = str(iface.get("vlan_id") or "")
    second_vlan = str(iface.get("second_vlan_id") or "")
    pe_vid = str(iface.get("pe_vid") or "")
    ce_vid = str(iface.get("ce_vid") or "")
    vsi = iface.get("vsi_name", "")

    # Interface name match
    if qval.lower() == name.lower():
        return 1.0
    if qval.lower() in name.lower():
        return 0.9

    # Description match
    if qval.lower() == desc.lower():
        return 1.0
    if qval.lower() in desc.lower():
        return 0.8

    # VLAN match
    if qtype in ("vlan", "asn"):
        if vlan_id and str(qval) == vlan_id:
            return 1.0
        if second_vlan and str(qval) == second_vlan:
            return 0.9
        if pe_vid and str(qval) == pe_vid:
            return 0.9
        if ce_vid and str(qval) == ce_vid:
            return 0.9

    # IP match
    if qtype == "ip" and ip:
        if qval in ip:
            return 1.0

    # Prefix match — check if interface IP is within queried prefix
    if qtype == "prefix" and ip:
        net = classification.get("network")
        if net and "/" in str(ip):
            iface_ip = ip.split()[0] if ip else ""
            if iface_ip and _ip_in_net(iface_ip, str(net)):
                return 0.9

    # VSI match
    if vsi and qval.lower() in vsi.lower():
        return 0.9

    return 0.0


def _search_static_routes(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search static routes inside ParsedConfig.parsed_data."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max

            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        routes = parsed.parsed_data.get("static_routes", [])
        if not routes:
            continue
        for route in routes:
            score = _search_static_route_score(classification, route)
            if score == 0.0:
                continue

            dest = route.get("network", "")
            nh = route.get("next_hop", "")
            desc = route.get("description", "")
            vpn = route.get("vpn_instance", "")
            raw = route.get("raw", "")

            results.append(
                {
                    "type": "static_route",
                    "title": f"{dest} → {nh}",
                    "description": desc or f"via {nh}",
                    "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                    "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "metadata": {
                        "destination": dest,
                        "netmask": route.get("netmask", ""),
                        "next_hop": nh,
                        "vpn_instance": vpn or "",
                        "description": desc,
                    },
                    "evidence": [raw] if raw else [],
                }
            )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]


def _search_static_route_score(classification: dict, route: dict) -> float:
    """Score a static route against the classification."""
    qtype = classification["type"]
    qval = classification.get("value", classification["query"])
    qquery = classification["query"]

    dest = route.get("network", "")
    nh = route.get("next_hop", "")
    desc = route.get("description", "")
    vpn = route.get("vpn_instance", "")
    raw = route.get("raw", "")

    # Exact destination match
    if qval.lower() == dest.lower():
        return 1.0
    if qquery.lower() in dest.lower():
        return 0.9

    # Exact next-hop match
    if qtype == "ip" and nh and qval == nh:
        return 1.0

    # Next-hop within queried prefix
    if qtype == "prefix" and nh:
        net = classification.get("network")
        if net and _ip_in_net(nh, str(net)):
            return 0.9

    # Destination within queried prefix
    if qtype == "prefix" and dest:
        net = classification.get("network")
        if net and _net_overlaps(dest, str(net)):
            return 0.8

    # Description match
    if desc and qquery.lower() in desc.lower():
        return 0.8

    # Raw text match
    if raw and qquery.lower() in raw.lower():
        return 0.7

    # VPN instance match
    if vpn and qquery.lower() in vpn.lower():
        return 0.6

    return 0.0


def _search_bgp(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search BGP peers and networks inside ParsedConfig.parsed_data."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max

            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        bgp_blocks = parsed.parsed_data.get("bgp", [])
        if not bgp_blocks:
            continue
        for bgp in bgp_blocks:
            local_as = bgp.get("as_number", "")

            # Score local AS
            if qtype in ("asn", "vlan") and qval == local_as:
                results.append(
                    {
                        "type": "bgp",
                        "title": f"BGP AS {local_as}",
                        "description": "Local AS",
                        "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                        "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                        "snapshot": parsed.snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": 0.9,
                        "metadata": {"local_as": local_as, "remote_as": "", "peer_ip": ""},
                        "evidence": [bgp.get("raw", "")[:200]],
                    }
                )

            # Search peers
            for peer in bgp.get("peers", []):
                score = _search_bgp_peer_score(classification, peer, local_as)
                if score == 0.0:
                    continue

                peer_ip = peer.get("ip", "")
                remote_as = peer.get("remote_as", "")
                desc = peer.get("description", "")
                rp_import = peer.get("route_policy_import", "")
                rp_export = peer.get("route_policy_export", "")

                results.append(
                    {
                        "type": "bgp",
                        "title": f"Peer {peer_ip} (AS {remote_as})",
                        "description": desc or f"local AS {local_as}",
                        "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                        "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                        "snapshot": parsed.snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": score,
                        "metadata": {
                            "local_as": local_as,
                            "remote_as": remote_as,
                            "peer_ip": peer_ip,
                            "description": desc,
                            "route_policy_import": rp_import or "",
                            "route_policy_export": rp_export or "",
                        },
                        "evidence": [bgp.get("raw", "")[:300]],
                    }
                )

            # Search networks
            for net in bgp.get("networks", []):
                net_cidr = _bgp_net_to_cidr(net) or net
                match_found = False
                if qtype == "prefix" and classification.get("network"):
                    # Compare CIDR forms
                    query_net = classification["network"]
                    try:
                        net_obj = ipaddress.ip_network(net_cidr, strict=False)
                        if query_net.overlaps(net_obj) or query_net == net_obj:
                            match_found = True
                            score = 0.9
                    except ValueError:
                        pass
                if not match_found and q.lower() in net.lower():
                    match_found = True
                    score = 0.6
                if match_found:
                    results.append(
                        {
                            "type": "bgp",
                            "title": f"Rede {net} (AS {local_as})",
                            "description": "BGP network advertisement",
                            "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                            "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                            "snapshot": parsed.snapshot.pk,
                            "parsed_config": parsed.pk,
                            "url": f"/analysis/{parsed.pk}/",
                            "score": score,
                            "metadata": {
                                "local_as": local_as,
                                "network": net,
                                "remote_as": "",
                                "peer_ip": "",
                            },
                            "evidence": [bgp.get("raw", "")[:200]],
                        }
                    )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]



def _search_policies(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search route-policies, ip-prefixes, ACLs, as-path/community filters."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)
    q_upper = q.upper() if q else ""
    q_lower = q.lower() if q else ""

    # Smart matching: strip common prefixes for broader matching
    q_stripped = q
    q_stripped_upper = q_upper
    q_stripped_lower = q_lower
    for prefix in ["acl ", "route-policy ", "ip-prefix ", "as-path-filter ", "community-filter "]:
        if q_lower.startswith(prefix):
            q_stripped = q[len(prefix):]
            q_stripped_upper = q_stripped.upper()
            q_stripped_lower = q_stripped.lower()
            break

    # For prefix queries, extract just the IP part for matching prefix field
    q_ip_only = qval.split("/")[0] if qtype == "prefix" and "/" in qval else q_lower

    def _name_matches(name: str) -> bool:
        """Check if query matches a policy/filter name, with smart stripping."""
        name_upper = name.upper()
        return (q_upper in name_upper or q_stripped_upper in name_upper
                or q_lower in name.lower() or q_stripped_lower in name.lower())

    # Detect generic type-only queries: "route-policy", "ip-prefix", "acl", etc.
    # When user searches for a generic type keyword, match ALL items of that type.
    q_type_only = q_lower.strip()
    is_route_policy_query = q_type_only in ("route-policy", "route-policies", "route policy", "route policies")
    is_ip_prefix_query = q_type_only in ("ip-prefix", "ip-prefixes", "ip prefix", "ip prefixes", "prefix-list", "prefix-lists")
    is_acl_query = q_type_only in ("acl", "acls", "access-list", "access-lists")
    is_as_path_query = q_type_only in ("as-path-filter", "as-path-filters", "as path filter", "as path filters")
    is_community_query = q_type_only in ("community-filter", "community-filters", "community filter", "community filters")

    def _get_evidence_for(parsed, q_lower_str: str) -> list[str]:
        """Extract evidence lines from raw config."""
        raw = parsed.snapshot.raw_config or ""
        return _get_evidence_lines(raw, q_lower_str)[:3]

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        pd = parsed.parsed_data
        device_name = parsed.snapshot.device.name if parsed.snapshot.device else ""
        device_pk = parsed.snapshot.device.pk if parsed.snapshot.device else None

        # Pre-compute evidence once per ParsedConfig
        evidence_cache: dict[str, list[str]] = {}

        def _get_ev(query_str: str) -> list[str]:
            if query_str not in evidence_cache:
                evidence_cache[query_str] = _get_evidence_for(parsed, query_str)
            return evidence_cache[query_str]

        base_result = {
            "device": device_name,
            "device_pk": device_pk,
            "snapshot": parsed.snapshot.pk,
            "parsed_config": parsed.pk,
            "url": f"/analysis/{parsed.pk}/",
        }

        # Route-policies
        for rp in pd.get("route_policies", []):
            rp_name = rp.get("name", "")
            if _name_matches(rp_name) or (is_route_policy_query and rp_name):
                # Build description with if-match and apply details
                desc_parts = [f"Node {rp.get('node')} ({rp.get('action')})"]
                if_match = rp.get("if_match", [])
                if if_match:
                    match_summary = "; ".join(
                        f"{im.get('type')} {im.get('name')}" for im in if_match
                    )
                    desc_parts.append(f"match: {match_summary}")
                apply_acts = rp.get("apply", [])
                if apply_acts:
                    apply_summary = "; ".join(
                        f"{a.get('type')} {a.get('value')}" for a in apply_acts
                    )
                    desc_parts.append(f"apply: {apply_summary}")
                description = " | ".join(desc_parts)
                results.append(dict(base_result, **{
                    "type": "route_policy",
                    "title": f"Route-policy: {rp_name}",
                    "description": description,
                    "score": 0.9,
                    "metadata": {"policy_name": rp_name, "node": rp.get("node")},
                    "evidence": _get_ev(rp_name),
                }))

        # IP prefix-lists
        for pp in pd.get("prefix_lists", []):
            pp_name = pp.get("name", "")
            if _name_matches(pp_name) or (is_ip_prefix_query and pp_name):
                results.append(dict(base_result, **{
                    "type": "ip_prefix",
                    "title": f"IP prefix-list: {pp_name}",
                    "description": f"{len(pp.get('rules', []))} regra(s)",
                    "score": 0.9,
                    "metadata": {"prefix_name": pp_name},
                    "evidence": _get_ev(pp_name),
                }))
            for rule in pp.get("rules", []):
                rule_prefix = rule.get("prefix", "")
                # Match by prefix IP (handles prefix-type queries with /mask)
                if q_ip_only in rule_prefix or q_lower in rule_prefix:
                    results.append(dict(base_result, **{
                        "type": "ip_prefix",
                        "title": f"IP prefix-rule: {pp_name}",
                        "description": f"Index {rule.get('index')}: {rule.get('action')} {rule.get('prefix')}/{rule.get('mask_length')}",
                        "score": 0.85,
                        "metadata": {"prefix_name": pp_name, "rule": rule},
                        "evidence": _get_ev(rule.get("raw", rule_prefix)),
                    }))

        # ACLs
        for acl in pd.get("acls", []):
            acl_name = acl.get("name", "")
            acl_number = acl.get("number", "")
            if _name_matches(acl_name) or (acl_number and _name_matches(acl_number)) or (is_acl_query and acl_name):
                results.append(dict(base_result, **{
                    "type": "acl",
                    "title": f"ACL: {acl_name}",
                    "description": f"{len(acl.get('rules', []))} regra(s) ({acl.get('type', '')})",
                    "score": 0.9,
                    "metadata": {"acl_name": acl_name, "acl_type": acl.get("type")},
                    "evidence": _get_ev(acl_name),
                }))
            for rule in acl.get("rules", []):
                if q_lower in rule.get("raw", "").lower() or q_stripped_lower in rule.get("raw", "").lower():
                    results.append(dict(base_result, **{
                        "type": "acl",
                        "title": f"ACL rule: {acl_name}",
                        "description": rule.get("raw", "")[:120],
                        "score": 0.8,
                        "metadata": {"acl_name": acl_name, "raw": rule.get("raw")},
                        "evidence": _get_ev(rule.get("raw", "")),
                    }))

        # AS-path filters
        for af in pd.get("as_path_filters", []):
            af_name = af.get("name", "")
            if _name_matches(af_name) or (is_as_path_query and af_name):
                results.append(dict(base_result, **{
                    "type": "as_path_filter",
                    "title": f"AS-path filter: {af_name}",
                    "description": f"{len(af.get('rules', []))} regra(s)",
                    "score": 0.9,
                    "metadata": {"filter_name": af_name},
                    "evidence": _get_ev(af_name),
                }))
            for rule in af.get("rules", []):
                if q_lower in rule.get("pattern", "").lower() or q_lower in rule.get("raw", "").lower() or q_stripped_lower in rule.get("raw", "").lower():
                    results.append(dict(base_result, **{
                        "type": "as_path_filter",
                        "title": f"AS-path rule: {af_name}",
                        "description": f"{rule.get('action')} {rule.get('pattern')}",
                        "score": 0.85,
                        "metadata": {"filter_name": af_name, "rule": rule},
                        "evidence": _get_ev(rule.get("raw", "")),
                    }))

        # Community filters
        for cf in pd.get("community_filters", []):
            cf_name = cf.get("name", "")
            if _name_matches(cf_name) or (is_community_query and cf_name):
                results.append(dict(base_result, **{
                    "type": "community_filter",
                    "title": f"Community-filter: {cf_name}",
                    "description": f"{len(cf.get('rules', []))} regra(s) ({cf.get('type', 'basic')})",
                    "score": 0.9,
                    "metadata": {"filter_name": cf_name},
                    "evidence": _get_ev(cf_name),
                }))
            for rule in cf.get("rules", []):
                rule_value = rule.get("value", "")
                rule_raw = rule.get("raw", "")
                if q_lower in rule_value or q_lower in rule_raw.lower() or q_stripped_lower in rule_raw.lower():
                    index_str = f"Index {rule.get('index')}: " if rule.get("index") is not None else ""
                    results.append(dict(base_result, **{
                        "type": "community_filter",
                        "title": f"Community rule: {cf_name}",
                        "description": f"{index_str}{rule.get('action')} {rule_value}",
                        "score": 0.85,
                        "metadata": {"filter_name": cf_name, "rule": rule},
                        "evidence": _get_ev(rule_raw),
                    }))

        # BGP peer → route-policy dependencies
        for bgp in pd.get("bgp", []):
            for peer in bgp.get("peers", []):
                for direction in ("import", "export"):
                    rp_name = peer.get(f"route_policy_{direction}")
                    if rp_name and _name_matches(rp_name):
                        results.append(dict(base_result, **{
                            "type": "bgp_policy_dependency",
                            "title": f"BGP peer {peer.get('ip')} {direction}: {rp_name}",
                            "description": f"AS {peer.get('remote_as')}",
                            "score": 0.8,
                            "metadata": {"peer": peer.get("ip"), "direction": direction, "route_policy": rp_name},
                            "evidence": _get_ev(peer.get("ip", "")),
                        }))

    return results

def _search_bgp_peer_score(classification: dict, peer: dict, local_as: str) -> float:
    """Score a BGP peer against the classification."""
    qtype = classification["type"]
    qval = classification.get("value", classification["query"])
    qquery = classification["query"]

    peer_ip = peer.get("ip", "")
    remote_as = peer.get("remote_as", "")
    desc = peer.get("description", "")
    rp_import = peer.get("route_policy_import", "")
    rp_export = peer.get("route_policy_export", "")

    # ASN match (local or remote)
    if qtype in ("asn", "vlan") and qval in (local_as, remote_as):
        return 1.0

    # Peer IP match
    if qtype == "ip" and qval == peer_ip:
        return 1.0

    # Peer IP within queried prefix
    if qtype == "prefix":
        net = classification.get("network")
        if net and _ip_in_net(peer_ip, str(net)):
            return 0.9

    # Description match
    if desc and qquery.lower() in desc.lower():
        return 0.8

    # Route-policy name match
    if rp_import and qquery.lower() in rp_import.lower():
        return 0.7
    if rp_export and qquery.lower() in rp_export.lower():
        return 0.7

    # Substring match in any peer field
    if qquery.lower() in peer_ip.lower():
        return 0.7
    if qquery.lower() in remote_as:
        return 0.7

    return 0.0


def _search_isis(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search ISIS processes and interfaces inside ParsedConfig.parsed_data."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max

            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        isis_blocks = parsed.parsed_data.get("isis", [])
        if not isis_blocks:
            continue

        for isis in isis_blocks:
            process_id = isis.get("process_id", "")
            network_entity = isis.get("network_entity", "")
            is_level = isis.get("is_level", "")

            score = 0.0
            if q.lower() == process_id.lower():
                score = 1.0
            elif q.lower() in process_id.lower():
                score = 0.9
            elif network_entity and q.lower() in network_entity.lower():
                score = 0.9
            elif is_level and q.lower() in is_level.lower():
                score = 0.8
            elif q.lower() in str(isis.get("raw", "")).lower():
                score = 0.6

            if score == 0.0:
                continue

            results.append(
                {
                    "type": "isis",
                    "title": f"ISIS Process {process_id}",
                    "description": f"NET: {network_entity or '-'} | Level: {is_level or '-'}",
                    "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                    "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "metadata": {
                        "process_id": process_id,
                        "network_entity": network_entity or "",
                        "is_level": is_level or "",
                    },
                    "evidence": [isis.get("raw", "")[:300]] if isis.get("raw") else [],
                }
            )

        # Also search in interfaces for isis_enabled
        for iface in parsed.parsed_data.get("interfaces", []):
            if not iface.get("isis_enabled"):
                continue
            iface_name = iface.get("name", "")
            iface_process = iface.get("isis_process_id", "")
            iface_circuit = iface.get("isis_circuit_type", "")

            score = 0.0
            if q.lower() == iface_name.lower():
                score = 1.0
            elif q.lower() in iface_name.lower():
                score = 0.9
            elif iface_process and q.lower() in iface_process.lower():
                score = 0.9
            elif iface_circuit and q.lower() in iface_circuit.lower():
                score = 0.7

            if score == 0.0:
                continue

            results.append(
                {
                    "type": "isis_interface",
                    "title": f"ISIS on {iface_name}",
                    "description": f"Process: {iface_process or '-'} | Circuit: {iface_circuit or '-'} | Cost: {iface.get('isis_cost', '-')}",
                    "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                    "device_pk": parsed.snapshot.device.pk if parsed.snapshot.device else None,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "metadata": {
                        "interface": iface_name,
                        "isis_process_id": iface_process or "",
                        "isis_circuit_type": iface_circuit or "",
                        "isis_cost": iface.get("isis_cost"),
                    },
                    "evidence": [],
                }
            )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]


def _search_core(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search MPLS and MPLS LDP inside ParsedConfig.parsed_data."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max

            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        mpls = parsed.parsed_data.get("mpls", {})
        ldp = parsed.parsed_data.get("mpls_ldp", {})
        device_name = parsed.snapshot.device.name if parsed.snapshot.device else ""
        device_pk = parsed.snapshot.device.pk if parsed.snapshot.device else None

        # MPLS global info
        lsr_id = mpls.get("lsr_id", "")
        mpls_enabled = mpls.get("enabled", False)

        if mpls_enabled:
            score = 0.0
            if q.lower() == "mpls":
                score = 0.7
            elif lsr_id and q.lower() == lsr_id.lower():
                score = 1.0
            elif lsr_id and q.lower() in lsr_id.lower():
                score = 0.9
            elif q.lower() in str(mpls.get("raw_lines", [])).lower():
                score = 0.6

            if score > 0.0:
                results.append(
                    {
                        "type": "mpls",
                        "title": f"MPLS — LSR-ID: {lsr_id or '(não configurado)'}",
                        "description": f"TE: {'sim' if mpls.get('te_enabled') else 'não'}",
                        "device": device_name,
                        "device_pk": device_pk,
                        "snapshot": parsed.snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": score,
                        "metadata": {
                            "lsr_id": lsr_id or "",
                            "te_enabled": mpls.get("te_enabled", False),
                            "enabled": mpls_enabled,
                        },
                        "evidence": mpls.get("raw_lines", [])[:3],
                    }
                )

        # MPLS LDP info
        ldp_enabled = ldp.get("enabled", False)
        if ldp_enabled:
            score = 0.0
            if q.lower() == "ldp":
                score = 0.7
            elif q.lower() in str(ldp.get("raw_lines", [])).lower():
                score = 0.6

            if score > 0.0:
                results.append(
                    {
                        "type": "mpls_ldp",
                        "title": "MPLS LDP",
                        "description": f"Graceful Restart: {'sim' if ldp.get('graceful_restart') else 'não'}",
                        "device": device_name,
                        "device_pk": device_pk,
                        "snapshot": parsed.snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": score,
                        "metadata": {
                            "enabled": True,
                            "graceful_restart": ldp.get("graceful_restart", False),
                        },
                        "evidence": ldp.get("raw_lines", [])[:3],
                    }
                )

        # LDP remote peers
        for peer in ldp.get("remote_peers", []):
            peer_name = peer.get("name", "")
            peer_ip = peer.get("remote_ip", "")

            score = 0.0
            if q.lower() == peer_name.lower():
                score = 1.0
            elif q.lower() in peer_name.lower():
                score = 0.9
            elif qtype == "ip" and peer_ip and qval == peer_ip:
                score = 1.0
            elif peer_ip and q.lower() in peer_ip:
                score = 0.8

            if score == 0.0:
                continue

            results.append(
                {
                    "type": "mpls_ldp_peer",
                    "title": f"LDP Remote Peer: {peer_name}",
                    "description": f"Remote IP: {peer_ip or '-'}",
                    "device": device_name,
                    "device_pk": device_pk,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "metadata": {
                        "peer_name": peer_name,
                        "remote_ip": peer_ip or "",
                    },
                    "evidence": peer.get("raw_lines", [])[:3],
                }
            )

        # Search interfaces with mpls_enabled
        if q.lower() not in ("mpls", "ldp"):
            for iface in parsed.parsed_data.get("interfaces", []):
                if not iface.get("mpls_enabled"):
                    continue
                iface_name = iface.get("name", "")
                score = 0.0
                if q.lower() == iface_name.lower():
                    score = 1.0
                elif q.lower() in iface_name.lower():
                    score = 0.9
                else:
                    continue
                results.append(
                    {
                        "type": "mpls_interface",
                        "title": f"MPLS on {iface_name}",
                        "description": f"MTU: {iface.get('mpls_mtu', '-')}",
                        "device": device_name,
                        "device_pk": device_pk,
                        "snapshot": parsed.snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": score,
                        "metadata": {
                            "interface": iface_name,
                            "mpls_mtu": iface.get("mpls_mtu"),
                        },
                        "evidence": [],
                    }
                )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]


def _search_circuits(
    classification: dict, filters: dict | None
) -> list[dict]:
    """Search in DetectedCircuit model."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    qs = DetectedCircuit.objects.select_related("snapshot__device").all()

    if filters:
        if filters.get("vendor"):
            qs = qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            qs = qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only"):
            from django.db.models import Max

            latest_ids = (
                qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            qs = qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for circuit in qs:
        score = _search_circuit_score(classification, circuit)
        if score == 0.0:
            continue

        details = circuit.details or {}
        iface = details.get("interface", "")
        vlan = details.get("vlan_id", "") or details.get("pe_vid", "")

        results.append(
            {
                "type": "circuit",
                "title": f"{circuit.get_circuit_type_display()} — {iface}",
                "description": circuit.description
                or details.get("routed_prefix", "")
                or details.get("vsi_name", "")
                or "",
                "device": circuit.snapshot.device.name if circuit.snapshot.device else "",
                "device_pk": circuit.snapshot.device.pk if circuit.snapshot.device else None,
                "snapshot": circuit.snapshot.pk,
                "parsed_config": None,
                "url": f"/circuits/{circuit.pk}/",
                "score": score,
                "metadata": {
                    "circuit_type": circuit.circuit_type,
                    "interface": iface,
                    "vlan": str(vlan),
                    "routed_prefix": details.get("routed_prefix", ""),
                    "vsi_name": details.get("vsi_name", ""),
                    "local_ip": details.get("local_ip", ""),
                    "remote_ip": details.get("remote_ip", ""),
                    "transit_network": details.get("transit_network", ""),
                },
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:30]


def _search_circuit_score(classification: dict, circuit: DetectedCircuit) -> float:
    """Score a circuit against the classification."""
    qtype = classification["type"]
    qval = classification.get("value", classification["query"])
    qquery = classification["query"]

    details = circuit.details or {}
    iface = details.get("interface", "")
    vlan = str(details.get("vlan_id") or "")
    pe_vid = str(details.get("pe_vid") or "")
    ce_vid = str(details.get("ce_vid") or "")
    second_vlan = str(details.get("second_dot1q") or "")
    routed_prefix = str(details.get("routed_prefix", ""))
    transit_network = str(details.get("transit_network", ""))
    local_ip = str(details.get("local_ip", ""))
    remote_ip = str(details.get("remote_ip", ""))
    vsi_name = str(details.get("vsi_name", ""))
    desc = circuit.description or ""

    # Interface exact match
    if qval.lower() == iface.lower():
        return 1.0
    if qval.lower() in iface.lower():
        return 0.9

    # VLAN exact match
    if qtype in ("vlan", "asn"):
        if vlan == qval or pe_vid == qval or ce_vid == qval or second_vlan == qval:
            return 1.0

    # IP exact match
    if qtype == "ip":
        if qval == local_ip or qval == remote_ip:
            return 1.0

    # IP within prefix
    if qtype == "prefix":
        net = classification.get("network")
        if net:
            if routed_prefix and _net_overlaps(routed_prefix, str(net)):
                return 1.0
            if transit_network and _net_overlaps(transit_network, str(net)):
                return 0.9
            if local_ip and _ip_in_net(local_ip, str(net)):
                return 0.8
            if remote_ip and _ip_in_net(remote_ip, str(net)):
                return 0.8

    # Routed prefix match
    if qtype in ("ip", "prefix"):
        if qval == routed_prefix:
            return 1.0
        if routed_prefix and qquery.lower() in routed_prefix.lower():
            return 0.8

    # VSI match
    if vsi_name and qval.lower() in vsi_name.lower():
        return 1.0

    # Description match
    if desc and qquery.lower() in desc.lower():
        return 0.8

    # Substring in any field
    for field_val in [iface, vlan, pe_vid, routed_prefix, local_ip, remote_ip, vsi_name]:
        if qquery.lower() in str(field_val).lower():
            return 0.7

    return 0.0


def _search_services(
    classification: dict, filters: dict | None
) -> list[dict]:
    """Search in DetectedService model."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)

    qs = DetectedService.objects.select_related("snapshot__device").all()

    if filters:
        if filters.get("vendor"):
            qs = qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            qs = qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only"):
            from django.db.models import Max

            latest_ids = (
                qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            qs = qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for svc in qs:
        score = 0.0
        name = svc.name or ""

        # Name/description match
        if q.lower() == name.lower():
            score = 1.0
        elif name and q.lower() in name.lower():
            score = 0.9
        elif svc.description and q.lower() in svc.description.lower():
            score = 0.7
        elif q.lower() in svc.service_type:
            score = 0.6

        # Metadata custom fields
        meta = svc.metadata or {}
        for key, val in meta.items():
            if isinstance(val, str) and q.lower() in val.lower():
                score = max(score, 0.7)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and q.lower() in item.lower():
                        score = max(score, 0.7)

        if score == 0.0:
            continue

        results.append(
            {
                "type": "service",
                "title": f"{svc.get_service_type_display()} — {name or '(sem nome)'}",
                "description": svc.description or "",
                "device": svc.snapshot.device.name if svc.snapshot.device else "",
                "device_pk": svc.snapshot.device.pk if svc.snapshot.device else None,
                "snapshot": svc.snapshot.pk,
                "parsed_config": None,
                "url": f"/services/{svc.pk}/",
                "score": score,
                "metadata": {"service_type": svc.service_type, "name": name},
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]


def _search_issues(
    classification: dict, filters: dict | None
) -> list[dict]:
    """Search in AnalysisIssue model."""
    q = classification["query"]

    qs = AnalysisIssue.objects.select_related("snapshot__device").all()

    if filters:
        if filters.get("vendor"):
            qs = qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            qs = qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only"):
            from django.db.models import Max

            latest_ids = (
                qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            qs = qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for issue in qs:
        score = 0.0
        if q.lower() in issue.title.lower():
            score = max(score, 0.9)
        if q.lower() in issue.code.lower():
            score = max(score, 1.0)
        if q.lower() in issue.description.lower():
            score = max(score, 0.7)
        if q.lower() in issue.severity:
            score = max(score, 0.5)

        meta = issue.metadata or {}
        for key, val in meta.items():
            if isinstance(val, str) and q.lower() in val.lower():
                score = max(score, 0.6)

        if score == 0.0:
            continue

        results.append(
            {
                "type": "issue",
                "title": f"[{issue.get_severity_display()}] {issue.title}",
                "description": issue.description or issue.code,
                "device": issue.snapshot.device.name if issue.snapshot.device else "",
                "device_pk": issue.snapshot.device.pk if issue.snapshot.device else None,
                "snapshot": issue.snapshot.pk,
                "parsed_config": None,
                "url": f"/issues/{issue.pk}/",
                "score": score,
                "metadata": {
                    "severity": issue.severity,
                    "code": issue.code,
                    "category": issue.category,
                },
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:20]


def _search_raw_matches(
    classification: dict, filters: dict | None
) -> list[dict]:
    """Search raw config text for matching lines."""
    q = classification["query"]

    qs = ConfigSnapshot.objects.select_related("device").all()

    if filters:
        if filters.get("vendor"):
            qs = qs.filter(vendor=filters["vendor"])
        if filters.get("device"):
            qs = qs.filter(device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only"):
            from django.db.models import Max

            latest_ids = (
                qs.values("device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            qs = qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for snap in qs:
        evidence = _get_evidence_lines(snap.raw_config, q)
        if not evidence:
            continue

        results.append(
            {
                "type": "raw_match",
                "title": f"Ocorrência em \"{snap.device.name if snap.device else '(sem dispositivo)'}\"",
                "description": f"Snapshot #{snap.pk} — {snap.created_at:%d/%m/%Y %H:%M}",
                "device": snap.device.name if snap.device else "",
                "device_pk": snap.device.pk if snap.device else None,
                "snapshot": snap.pk,
                "parsed_config": ParsedConfig.objects.filter(snapshot=snap).first().pk
                if ParsedConfig.objects.filter(snapshot=snap).exists()
                else None,
                "url": None,
                "score": 0.6,
                "metadata": {"vendor": snap.vendor},
                "evidence": evidence[:3],
            }
        )

    return results[:20]


# ── public API ──────────────────────────────────────────────────────────────


def global_network_search(
    query: str, filters: dict | None = None
) -> dict[str, Any]:
    """Execute a global deterministic search across the entire network database.

    Parameters
    ----------
    query : str
        Free-text search string (VLAN, IP, prefix, interface, ASN, text…).
    filters : dict | None
        Optional filtering:
        - ``vendor``: str — filter by vendor
        - ``device``: str — filter by device name substring
        - ``last_snapshot_only``: bool — only consider the most recent
          snapshot per device

    Returns
    -------
    dict
        Keys:
        - ``classification`` — result of ``classify_search_query``
        - ``summary`` — dict with total result counts per section
        - ``devices``, ``snapshots``, ``interfaces``, ``circuits``,
          ``services``, ``issues``, ``static_routes``, ``bgp_peers``,
          ``raw_matches`` — each a list of result dicts
    """
    classification = classify_search_query(query)

    # Unless last_snapshot_only is explicit, default to True for performance
    effective_filters = dict(filters or {})
    only_last = effective_filters.pop("last_snapshot_only", None)
    if only_last is None:
        # Default: include all snapshots (no filter)
        pass

    # Also support "last_snapshot_only" as a separate keyword arg
    only_last_snapshot = only_last or False

    devices = _search_devices(classification, effective_filters)
    snapshots = _search_snapshots(classification, effective_filters)
    interfaces = _search_interfaces(
        classification, effective_filters, only_last_snapshot
    )
    circuits = _search_circuits(classification, effective_filters)
    services = _search_services(classification, effective_filters)
    issues = _search_issues(classification, effective_filters)
    static_routes = _search_static_routes(
        classification, effective_filters, only_last_snapshot
    )
    bgp_peers = _search_bgp(
        classification, effective_filters, only_last_snapshot
    )
    raw_matches = _search_raw_matches(classification, effective_filters)
    policies = _search_policies(
        classification, effective_filters, only_last_snapshot
    )
    isis_results = _search_isis(
        classification, effective_filters, only_last_snapshot
    )
    core_results = _search_core(
        classification, effective_filters, only_last_snapshot
    )

    summary_counts: dict[str, int] = {
        "devices": len(devices),
        "snapshots": len(snapshots),
        "interfaces": len(interfaces),
        "circuits": len(circuits),
        "services": len(services),
        "issues": len(issues),
        "static_routes": len(static_routes),
        "bgp_peers": len(bgp_peers),
        "policies": len(policies),
        "isis": len(isis_results),
        "core": len(core_results),
        "raw_matches": len(raw_matches),
    }

    total = sum(summary_counts.values())

    return {
        "classification": classification,
        "summary": {"total": total, **summary_counts},
        "devices": devices,
        "snapshots": snapshots,
        "interfaces": interfaces,
        "circuits": circuits,
        "services": services,
        "issues": issues,
        "static_routes": static_routes,
        "bgp_peers": bgp_peers,
        "policies": policies,
        "isis": isis_results,
        "core": core_results,
        "raw_matches": raw_matches,
    }
