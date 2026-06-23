"""Serviço de busca técnica global determinística.

Busca em dispositivos, snapshots, dados parseados (interfaces, rotas, BGP),
circuitos, serviços, issues e texto bruto das configurações.

Não usa IA — apenas consultas ao banco e análise de dados existentes.
"""

import ipaddress
import re
from collections.abc import Sequence
from typing import Any

from django.db.models import Prefetch, Q, QuerySet

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
    qs = ConfigSnapshot.objects.select_related("device").prefetch_related(
        Prefetch(
            "parsed_configs",
            queryset=ParsedConfig.objects.only("pk", "snapshot_id"),
            to_attr="search_parsed_configs",
        )
    )

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

        parsed_pk = (
            snap.search_parsed_configs[0].pk
            if snap.search_parsed_configs
            else None
        )
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

    qs = ConfigSnapshot.objects.select_related("device").prefetch_related(
        Prefetch(
            "parsed_configs",
            queryset=ParsedConfig.objects.only("pk", "snapshot_id"),
            to_attr="search_parsed_configs",
        )
    )

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

        parsed_config_id = (
            snap.search_parsed_configs[0].pk
            if snap.search_parsed_configs
            else None
        )
        results.append(
            {
                "type": "raw_match",
                "title": f"Ocorrência em \"{snap.device.name if snap.device else '(sem dispositivo)'}\"",
                "description": f"Snapshot #{snap.pk} — {snap.created_at:%d/%m/%Y %H:%M}",
                "device": snap.device.name if snap.device else "",
                "device_pk": snap.device.pk if snap.device else None,
                "snapshot": snap.pk,
                "parsed_config": parsed_config_id,
                "url": None,
                "score": 0.6,
                "metadata": {"vendor": snap.vendor},
                "evidence": evidence[:3],
            }
        )

    return results[:20]


# ── QoS search ────────────────────────────────────────────────────────────


def _search_qos(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search QoS / Traffic Policy / CAR data in parsed snapshots."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)
    q_lower = q.lower()
    results: list[dict] = []

    is_qos_keyword = q_lower in ("qos", "traffic-policy", "traffic policy", "car", "qos-profile")

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        qos = parsed.parsed_data.get("qos", {})
        if not qos and not is_qos_keyword:
            continue
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"

        # Search policies
        for p in qos.get("traffic_policies", []):
            score = 0.0
            if is_qos_keyword:
                score = 0.6
            elif q_lower and q_lower == p["name"].lower():
                score = 1.0
            elif q_lower and q_lower in p["name"].lower():
                score = 0.8
            if score > 0:
                results.append({
                    "type": "traffic_policy",
                    "title": f"Traffic-policy {p['name']}",
                    "name": p["name"],
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": [],
                })

        # Search classifiers
        for cl in qos.get("traffic_classifiers", []):
            score = 0.0
            if is_qos_keyword:
                score = 0.5
            elif q_lower and q_lower == cl["name"].lower():
                score = 1.0
            elif q_lower and q_lower in cl["name"].lower():
                score = 0.8
            if score > 0:
                results.append({
                    "type": "traffic_classifier",
                    "title": f"Classifier {cl['name']}",
                    "name": cl["name"],
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": [],
                })

            # Search ACL refs in classifier
            for im in cl.get("if_match", []):
                if im["type"] == "acl" and q_lower and q_lower == im["value"].lower():
                    results.append({
                        "type": "qos_acl_ref",
                        "title": f"Classifier {cl['name']} -> ACL {im['value']}",
                        "acl": im["value"],
                        "classifier": cl["name"],
                        "device": device_name,
                        "snapshot": snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": 0.7,
                        "evidence": [],
                    })

        # Search behaviors
        for bh in qos.get("traffic_behaviors", []):
            score = 0.0
            if is_qos_keyword:
                score = 0.5
            elif q_lower and q_lower == bh["name"].lower():
                score = 1.0
            elif q_lower and q_lower in bh["name"].lower():
                score = 0.8
            if score == 0.0 and qtype == "asn" and qval:
                car = bh.get("car", {})
                if car and (str(car.get("cir", "")) == qval or str(car.get("pir", "")) == qval):
                    score = 0.7
            if score > 0:
                results.append({
                    "type": "traffic_behavior",
                    "title": f"Behavior {bh['name']}",
                    "name": bh["name"],
                    "car": bh.get("car"),
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": [],
                })

        # Search qos-profiles
        for qp in qos.get("qos_profiles", []):
            score = 0.0
            if is_qos_keyword:
                score = 0.5
            elif q_lower and q_lower == qp["name"].lower():
                score = 1.0
            elif q_lower and q_lower in qp["name"].lower():
                score = 0.8
            if score > 0:
                results.append({
                    "type": "qos_profile",
                    "title": f"QoS-profile {qp['name']}",
                    "name": qp["name"],
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": [],
                })

        # Search interfaces with QoS
        for iface in parsed.parsed_data.get("interfaces", []):
            has_qos = iface.get("traffic_policies_applied") or iface.get("qos_profiles_applied") or iface.get("qos_car")
            if not has_qos:
                continue
            score = 0.0
            if is_qos_keyword:
                score = 0.4
            elif q_lower and q_lower in iface["name"].lower():
                score = 0.7
            if score > 0:
                results.append({
                    "type": "qos_interface",
                    "title": f"Interface com QoS: {iface['name']}",
                    "interface": iface["name"],
                    "policies": [tp["name"] for tp in iface.get("traffic_policies_applied", [])],
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": [],
                })

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('name', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)

    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique[:20]


# ── NAT search ────────────────────────────────────────────────────────────


def _search_bng(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search BNG/AAA/RADIUS/IP pool data."""
    q = classification["query"]
    q_lower = q.lower()
    results: list[dict] = []
    is_bng_keyword = any(k in q_lower for k in ("bng", "bas", "aaa", "radius", "pool", "domain", "subscriber", "authentication", "accounting"))

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        data = parsed.parsed_data
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"

        # BAS interfaces
        for iface in data.get("interfaces", []):
            bas = iface.get("bas")
            if not bas or not bas.get("enabled"):
                continue
            score = 0.5 if is_bng_keyword else 0.0
            if q_lower and q_lower in iface["name"].lower():
                score = 0.9
            if q_lower and bas.get("default_domain") and q_lower in bas["default_domain"].lower():
                score = 0.8
            if q_lower and bas.get("authentication_method") and q_lower in bas["authentication_method"].lower():
                score = 0.8
            if q_lower and iface.get("user_vlan") and q_lower == iface["user_vlan"]:
                score = 0.8
            if score:
                results.append({"type": "bas_interface", "title": f"BAS {iface['name']}", "device": device_name, "score": score, "snapshot": snapshot.pk})

            # Subscriber VLAN
            if q_lower and iface.get("user_vlan") and q_lower == iface["user_vlan"]:
                results.append({"type": "bas_user_vlan", "title": f"User VLAN {iface['user_vlan']} em {iface['name']}", "device": device_name, "score": 0.9, "snapshot": snapshot.pk})

        # RADIUS groups
        for rg in data.get("radius_servers", []):
            score = 0.5 if is_bng_keyword else 0.0
            if q_lower and q_lower == rg["name"].lower():
                score = 1.0
            elif q_lower and q_lower in rg["name"].lower():
                score = 0.8
            for srv in rg.get("authentication_servers", []):
                if q_lower and q_lower in srv.get("ip", ""):
                    score = max(score, 0.9)
            for srv in rg.get("accounting_servers", []):
                if q_lower and q_lower in srv.get("ip", ""):
                    score = max(score, 0.9)
            if score:
                results.append({"type": "radius_group", "title": f"RADIUS group {rg['name']}", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # IP pools
        for pool in data.get("ip_pools", []):
            score = 0.5 if is_bng_keyword else 0.0
            if q_lower and q_lower == pool["name"].lower():
                score = 1.0
            elif q_lower and q_lower in pool["name"].lower():
                score = 0.8
            elif pool.get("gateway") and q_lower in pool["gateway"]:
                score = 0.8
            if score:
                results.append({"type": "ip_pool", "title": f"IP pool {pool['name']}", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # Domains
        seen_domains = set()
        for ab in data.get("aaa", []):
            for d in ab.get("domains", []):
                name = d["name"]
                if name in seen_domains:
                    continue
                seen_domains.add(name)
                score = 0.5 if is_bng_keyword else 0.0
                if q_lower and q_lower == name.lower():
                    score = 1.0
                elif q_lower and q_lower in name.lower():
                    score = 0.8
                if score:
                    results.append({"type": "subscriber_domain", "title": f"Domínio {name}", "device": device_name, "score": score, "snapshot": snapshot.pk})
        for d in data.get("aaa_domains", []):
            name = d["name"]
            if name in seen_domains:
                continue
            seen_domains.add(name)
            score = 0.5 if is_bng_keyword else 0.0
            if q_lower and q_lower == name.lower():
                score = 1.0
            elif q_lower and q_lower in name.lower():
                score = 0.8
            if score:
                results.append({"type": "subscriber_domain", "title": f"Domínio {name}", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # AAA schemes
        for ab in data.get("aaa", []):
            for s in ab.get("authentication_schemes", []):
                if q_lower and q_lower == s["name"].lower():
                    results.append({"type": "aaa_scheme", "title": f"Auth-scheme {s['name']}", "device": device_name, "score": 0.9, "snapshot": snapshot.pk})
            for s in ab.get("accounting_schemes", []):
                if q_lower and q_lower == s["name"].lower():
                    results.append({"type": "aaa_scheme", "title": f"Acct-scheme {s['name']}", "device": device_name, "score": 0.9, "snapshot": snapshot.pk})

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique


def _search_pppoe(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search PPPoE / Virtual-Template data."""
    q = classification["query"]
    q_lower = q.lower()
    results: list[dict] = []
    is_pppoe_keyword = any(k in q_lower for k in ("pppoe", "virtual-template", "vt", "ppp", "chap", "pap", "max-session"))

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        data = parsed.parsed_data
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"

        # PPPoE interfaces
        for iface in data.get("interfaces", []):
            pppoe = iface.get("pppoe_server")
            if not pppoe or not pppoe.get("enabled"):
                continue
            score = 0.5 if is_pppoe_keyword else 0.0
            iface_name = iface.get("name", "")
            if q_lower and (q_lower in iface_name.lower() or q_lower in pppoe.get("virtual_template", "").lower()):
                score = 0.9
            if q_lower and "pppoe" in iface_name.lower():
                score = max(score, 0.9)
            if score:
                results.append({
                    "type": "pppoe_interface",
                    "title": f"PPPoE {iface_name} -> {pppoe.get('virtual_template', '?')}",
                    "device": device_name,
                    "score": score,
                    "snapshot": snapshot.pk,
                    "interface": iface_name,
                    "virtual_template": pppoe.get("virtual_template"),
                    "max_sessions": pppoe.get("max_sessions"),
                    "user_vlan": iface.get("user_vlan"),
                    "description": iface.get("description", ""),
                })

            # Virtual-Templates
            name = iface.get("name", "")
            if not name.lower().startswith("virtual-template"):
                continue
            score = 0.5 if is_pppoe_keyword else 0.0
            if q_lower and q_lower in name.lower():
                score = 0.9
            if score:
                modes = iface.get("ppp_authentication_modes", [])
                results.append({
                    "type": "virtual_template",
                    "title": f"Virtual-Template {name} (auth: {', '.join(modes) if modes else 'N/A'})",
                    "device": device_name,
                    "score": score,
                    "snapshot": snapshot.pk,
                    "name": name,
                    "ppp_authentication_modes": modes,
                    "remote_address_pool": iface.get("remote_address_pool"),
                    "mtu": iface.get("mtu"),
                })

            # PPP authentication modes
            for mode in iface.get("ppp_authentication_modes", []):
                if q_lower and q_lower == mode.lower():
                    results.append({
                        "type": "ppp_authentication",
                        "title": f"PPP auth-mode {mode} em {name}",
                        "device": device_name,
                        "score": 0.9,
                        "snapshot": snapshot.pk,
                    })

            # max-sessions
            ms = (iface.get("pppoe_server") or {}).get("max_sessions")
            if ms and q_lower and str(ms) in q:
                results.append({
                    "type": "pppoe_interface",
                    "title": f"PPPoE {iface_name} max-sessions {ms}",
                    "device": device_name,
                    "score": 0.85,
                    "snapshot": snapshot.pk,
                })

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique


def _search_ha(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search HA/BFD/GR/NSR data."""
    q = classification["query"]
    q_lower = q.lower()
    results: list[dict] = []
    is_ha_keyword = any(k in q_lower for k in ("bfd", "graceful-restart", "graceful", "nsr", "non-stop", "ha"))

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        data = parsed.parsed_data
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"
        ha = data.get("ha", {})
        bfd = ha.get("bfd", {})

        # BFD global
        if bfd.get("global_enabled") and (is_ha_keyword or q_lower == "bfd"):
            results.append({
                "type": "ha",
                "title": "BFD global habilitado",
                "device": device_name,
                "score": 0.7 if q_lower == "bfd" else 0.3,
                "snapshot": snapshot.pk,
                "description": "BFD global está habilitado.",
            })

        # BFD sessions
        for s in bfd.get("sessions", []):
            score = 0.0
            if is_ha_keyword:
                score = 0.5
            if q_lower and (q_lower in s.get("name", "").lower() or q_lower in (s.get("peer_ip") or "") or q_lower in s.get("interface", "").lower() or q_lower in (s.get("peer_ipv6") or "")):
                score = 0.9
            if score:
                results.append({
                    "type": "bfd_session",
                    "title": f"BFD {s['name']} -> {s.get('peer_ip') or s.get('peer_ipv6', '?')} via {s.get('interface', '?')}",
                    "device": device_name,
                    "score": score,
                    "snapshot": snapshot.pk,
                    "description": f"Local-disc: {s.get('local_discriminator')}, Remote-disc: {s.get('remote_discriminator')}, Tx: {s.get('min_tx_interval')}, Rx: {s.get('min_rx_interval')}, Mult: {s.get('detect_multiplier')}",
                })

        # BGP peers with BFD/GR
        for bgp in data.get("bgp", []):
            for p in bgp.get("peers", []):
                if not p.get("bfd_enabled") and not p.get("graceful_restart"):
                    continue
                score = 0.5 if is_ha_keyword else 0.0
                peer_ip = p.get("ip", "")
                if q_lower and q_lower in peer_ip:
                    score = 0.9
                if score:
                    results.append({
                        "type": "bgp_bfd" if p.get("bfd_enabled") else "graceful_restart",
                        "title": f"BGP {peer_ip} {'BFD' if p.get('bfd_enabled') else 'GR'}",
                        "device": device_name,
                        "score": score,
                        "snapshot": snapshot.pk,
                    })

        # GR/NSR per protocol
        for proto in ("bgp", "isis", "ospf", "ldp"):
            if ha.get("graceful_restart", {}).get(proto) and (is_ha_keyword or "graceful" in q_lower):
                results.append({
                    "type": "graceful_restart",
                    "title": f"Graceful Restart {proto.upper()}",
                    "device": device_name,
                    "score": 0.8 if "graceful" in q_lower else 0.4,
                    "snapshot": snapshot.pk,
                })
            if ha.get("nsr", {}).get(proto) and (is_ha_keyword or "nsr" in q_lower or "non-stop" in q_lower):
                results.append({
                    "type": "nsr",
                    "title": f"NSR {proto.upper()}",
                    "device": device_name,
                    "score": 0.8 if "nsr" in q_lower else 0.4,
                    "snapshot": snapshot.pk,
                })

        # LDP HA
        ldp_bfd = ha.get("bfd", {}).get("ldp_enabled")
        ldp_gr = ha.get("graceful_restart", {}).get("ldp")
        if (ldp_bfd or ldp_gr) and (is_ha_keyword or "ldp" in q_lower):
            results.append({
                "type": "ldp_ha",
                "title": f"LDP {'BFD' if ldp_bfd else ''} {'GR' if ldp_gr else ''}".strip(),
                "device": device_name,
                "score": 0.6,
                "snapshot": snapshot.pk,
            })

        # BFD per-interface (IGP)
        for iface in data.get("interfaces", []):
            has_bfd_iface = iface.get("isis_bfd_enabled") or iface.get("ospf_bfd_enabled") or iface.get("ospfv3_bfd_enabled") or iface.get("isis_ipv6_bfd_enabled") or iface.get("mpls_ldp_bfd_enabled")
            if not has_bfd_iface:
                continue
            if not is_ha_keyword and q_lower not in iface.get("name", "").lower():
                continue
            results.append({
                "type": "igp_bfd",
                "title": f"Interface {iface['name']} com BFD",
                "device": device_name,
                "score": 0.8 if q_lower in iface.get("name", "").lower() else 0.4,
                "snapshot": snapshot.pk,
            })

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique


def _search_multicast(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search multicast/PIM/IGMP/MLD data."""
    q = classification["query"]
    q_lower = q.lower()
    results: list[dict] = []
    is_mc_keyword = any(k in q_lower for k in ("multicast", "pim", "igmp", "mld", "rp", "bsr", "snooping"))

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        data = parsed.parsed_data
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"
        mc = data.get("multicast", {})

        # Global routing
        for key, label in [("ipv4_routing_enabled", "Multicast IPv4"), ("ipv6_routing_enabled", "Multicast IPv6")]:
            if mc.get(key) and (is_mc_keyword or q_lower in label.lower()):
                results.append({"type": "multicast_global", "title": f"{label} routing habilitado", "device": device_name, "score": 0.7, "snapshot": snapshot.pk})

        # PIM global (static RPs, BSR)
        pim_global = mc.get("pim", {}).get("global", {})
        for rp in pim_global.get("static_rps", []):
            if q_lower and (q_lower in rp["rp_address"] or (is_mc_keyword and "rp" in q_lower)):
                results.append({"type": "multicast_global", "title": f"Static RP {rp['rp_address']}", "device": device_name, "score": 0.9, "snapshot": snapshot.pk, "description": f"ACL: {rp.get('acl', 'N/A')}"})
        for bsr in pim_global.get("bsr_candidates", []):
            if is_mc_keyword or "bsr" in q_lower or q_lower in bsr.lower():
                results.append({"type": "multicast_global", "title": f"BSR candidate {bsr}", "device": device_name, "score": 0.8, "snapshot": snapshot.pk})

        # Interfaces
        for iface in data.get("interfaces", []):
            name = iface.get("name", "")
            if iface.get("pim_enabled") and (is_mc_keyword or q_lower in name.lower() or q_lower in (iface.get("pim_mode") or "")):
                results.append({"type": "pim_interface", "title": f"PIM {iface.get('pim_mode', '?')} em {name}", "device": device_name, "score": 0.8, "snapshot": snapshot.pk})
            if iface.get("igmp_enabled") and (is_mc_keyword or q_lower in name.lower() or "igmp" in q_lower):
                results.append({"type": "igmp_interface", "title": f"IGMP v{iface.get('igmp_version', '?')} em {name}", "device": device_name, "score": 0.8, "snapshot": snapshot.pk})
            for g in iface.get("igmp_static_groups", []) + iface.get("igmp_join_groups", []):
                if q_lower and q_lower in g:
                    results.append({"type": "igmp_interface", "title": f"Grupo IGMP {g} em {name}", "device": device_name, "score": 0.9, "snapshot": snapshot.pk})
            if iface.get("mld_enabled") and (is_mc_keyword or q_lower in name.lower() or "mld" in q_lower):
                results.append({"type": "mld_interface", "title": f"MLD v{iface.get('mld_version', '?')} em {name}", "device": device_name, "score": 0.8, "snapshot": snapshot.pk})
            for g in iface.get("mld_static_groups", []):
                if q_lower and q_lower in g:
                    results.append({"type": "mld_interface", "title": f"Grupo MLD {g} em {name}", "device": device_name, "score": 0.9, "snapshot": snapshot.pk})

        # IGMP snooping
        snoop = mc.get("igmp_snooping", {})
        if snoop.get("global_enabled") and (is_mc_keyword or "snooping" in q_lower):
            results.append({"type": "multicast_global", "title": "IGMP snooping global habilitado", "device": device_name, "score": 0.6, "snapshot": snapshot.pk})
        for v in snoop.get("vlans", []):
            if q_lower and (q_lower in v["vlan_id"] or "snooping" in q_lower):
                desc = f"Versão: {v.get('version', 'N/A')}"
                if v.get("querier_enabled"):
                    desc += " | Querier: Sim"
                results.append({"type": "igmp_snooping_vlan", "title": f"IGMP snooping VLAN {v['vlan_id']}", "device": device_name, "score": 0.7, "snapshot": snapshot.pk, "description": desc})

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique


def _search_ipv6(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search IPv6-related data."""
    q = classification["query"]
    q_lower = q.lower()
    qval = classification.get("value", q)
    results: list[dict] = []

    is_ipv6_keyword = any(k in q_lower for k in ("ipv6", "vpnv6", "ospfv3", "isis ipv6"))

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        data = parsed.parsed_data
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"

        # IPv6 static routes
        for route in data.get("ipv6_static_routes", []):
            score = 0.0
            if is_ipv6_keyword:
                score = 0.5
            elif q_lower and q_lower in route.get("prefix", "").lower():
                score = 0.9
            elif q_lower and q_lower in route.get("destination", "").lower():
                score = 0.9
            elif q_lower and q_lower in route.get("next_hop", "").lower():
                score = 0.8
            elif route.get("vpn_instance") and q_lower in route["vpn_instance"].lower():
                score = 0.8
            if score > 0:
                nh = route.get("next_hop", "?")
                results.append({"type": "ipv6_route", "title": f"Rota IPv6 {route.get('prefix', '?')} via {nh}", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # IPv6 prefix-lists
        for pl in data.get("prefix_lists", []):
            if not pl.get("is_ipv6"):
                continue
            score = 0.0
            if is_ipv6_keyword:
                score = 0.5
            elif q_lower and q_lower == pl["name"].lower():
                score = 1.0
            elif q_lower and q_lower in pl["name"].lower():
                score = 0.8
            if score == 0 and q_lower:
                for rule in pl.get("rules", []):
                    if q_lower in rule.get("prefix", "").lower():
                        score = 0.9
                        break
            if score > 0:
                results.append({"type": "ipv6_prefix_list", "title": f"IPv6 prefix-list {pl['name']} ({len(pl.get('rules', []))} regras)", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # BGP blocks
        for bgp in data.get("bgp", []):
            ipv6 = bgp.get("ipv6_unicast", {})
            # Peers
            for peer in ipv6.get("peers", []):
                score = 0.0
                if is_ipv6_keyword:
                    score = 0.5
                elif q_lower and q_lower in peer.get("peer", ""):
                    score = 0.9
                elif q_lower and peer.get("route_policy_import") and q_lower in peer["route_policy_import"].lower():
                    score = 0.8
                elif q_lower and peer.get("route_policy_export") and q_lower in peer["route_policy_export"].lower():
                    score = 0.8
                if score > 0:
                    enabled = "habilitado" if peer.get("enabled") else "desabilitado"
                    results.append({"type": "bgp_ipv6_peer", "title": f"BGP IPv6 peer {peer['peer']} ({enabled})", "device": device_name, "score": score, "snapshot": snapshot.pk})
            # Networks
            for net in ipv6.get("networks", []):
                score = 0.0
                net_str = net.get("prefix", str(net)) if isinstance(net, dict) else str(net)
                if is_ipv6_keyword:
                    score = 0.5
                elif q_lower and q_lower in net_str.lower():
                    score = 0.9
                if score > 0:
                    results.append({"type": "bgp_ipv6_network", "title": f"BGP IPv6 network {net_str}", "device": device_name, "score": score, "snapshot": snapshot.pk})

            # VPNv6 peers
            for peer in bgp.get("vpnv6", {}).get("peers", []):
                score = 0.0
                if is_ipv6_keyword:
                    score = 0.5
                elif q_lower and q_lower in peer.get("peer", ""):
                    score = 0.9
                if score > 0:
                    enabled = "habilitado" if peer.get("enabled") else "desabilitado"
                    results.append({"type": "vpnv6_peer", "title": f"VPNv6 peer {peer['peer']} ({enabled})", "device": device_name, "score": score, "snapshot": snapshot.pk})

            # IPv6 vpn-instances in BGP
            for vi in bgp.get("vpn_instances_ipv6", []):
                score = 0.0
                if is_ipv6_keyword:
                    score = 0.5
                elif q_lower and vi.get("name") and q_lower in vi["name"].lower():
                    score = 0.9
                if score > 0:
                    results.append({"type": "ipv6_vpn_instance", "title": f"VPN-instance IPv6 {vi.get('name', '?')}", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # OSPFv3
        for ospf in data.get("ospfv3", []):
            score = 0.0
            if is_ipv6_keyword:
                score = 0.5
            elif q_lower and q_lower == ospf.get("process_id", ""):
                score = 0.9
            elif q_lower and ospf.get("router_id") and q_lower in ospf["router_id"]:
                score = 0.8
            if score > 0:
                results.append({"type": "ospfv3", "title": f"OSPFv3 processo {ospf.get('process_id', '?')} (router-id {ospf.get('router_id', '?')})", "device": device_name, "score": score, "snapshot": snapshot.pk})

        # Interfaces with ISIS IPv6
        for iface in data.get("interfaces", []):
            if iface.get("isis_ipv6_enabled"):
                score = 0.0
                if is_ipv6_keyword:
                    score = 0.5
                elif q_lower and q_lower in iface.get("name", "").lower():
                    score = 0.9
                if score > 0:
                    results.append({"type": "isis_ipv6_interface", "title": f"ISIS IPv6 interface {iface['name']}", "device": device_name, "score": score, "snapshot": snapshot.pk})

            # Interface IPv6 addresses (direct match)
            for addr in iface.get("ipv6_addresses", []):
                addr_str = addr.get("address", "")
                if q_lower and q_lower == addr_str:
                    results.append({"type": "ipv6_interface_address", "title": f"Interface {iface['name']}: {addr_str}/{addr.get('prefix_length', '?')}", "device": device_name, "score": 0.95, "snapshot": snapshot.pk})

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique


def _search_nat(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search NAT / PAT / Port Forward data in parsed snapshots."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)
    q_lower = q.lower()
    results: list[dict] = []

    is_nat_keyword = any(q_lower.startswith(k) for k in ("nat", "address-group"))
    is_port_query = q_lower.isdigit() and len(q_lower) <= 5

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (parsed_qs.values("snapshot__device_id").annotate(max_id=Max("pk")).values_list("max_id", flat=True))
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    for parsed in parsed_qs:
        nat = parsed.parsed_data.get("nat", {})
        if not nat and not is_nat_keyword and not is_port_query:
            continue
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"

        for ag in nat.get("address_groups", []):
            score = 0.0
            if is_nat_keyword:
                score = 0.5
            elif q_lower and q_lower == ag["name"].lower():
                score = 1.0
            elif q_lower and q_lower in ag["name"].lower():
                score = 0.8
            elif q_lower in ag.get("start_ip", "") or q_lower in ag.get("end_ip", ""):
                score = 0.7
            if score > 0:
                results.append({"type": "nat_address_group", "title": f"Address-group {ag['name']} ({ag['start_ip']}-{ag['end_ip']})", "device": device_name, "score": score, "snapshot": snapshot.pk, "url": f"/analysis/{parsed.pk}/"})

        for ob in nat.get("outbound_rules", []):
            score = 0.0
            if is_nat_keyword:
                score = 0.5
            elif q_lower and ob.get("acl") and q_lower == ob["acl"].lower():
                score = 0.8
            elif q_lower and ob.get("address_group") and q_lower == ob["address_group"].lower():
                score = 0.8
            if score > 0:
                acl_part = f"ACL {ob['acl']}" if ob.get("acl") else "sem ACL"
                results.append({"type": "nat_outbound", "title": f"NAT outbound {acl_part}", "device": device_name, "score": score, "snapshot": snapshot.pk, "url": f"/analysis/{parsed.pk}/"})

        for sr in nat.get("static_rules", []):
            score = 0.0
            if is_nat_keyword:
                score = 0.5
            elif q_lower and q_lower in sr.get("global_ip", ""):
                score = 0.9
            elif q_lower and q_lower in sr.get("inside_ip", ""):
                score = 0.7
            if score > 0:
                results.append({"type": "nat_static", "title": f"NAT static {sr['global_ip']} -> {sr['inside_ip']}", "device": device_name, "score": score, "snapshot": snapshot.pk, "url": f"/analysis/{parsed.pk}/"})

        for sv in nat.get("server_rules", []):
            score = 0.0
            if is_nat_keyword:
                score = 0.5
            elif q_lower and q_lower in sv.get("global_ip", ""):
                score = 0.9
            elif q_lower and q_lower in sv.get("inside_ip", ""):
                score = 0.7
            elif is_port_query and sv.get("global_port") == q_lower:
                score = 0.8
            if score > 0:
                results.append({"type": "nat_server", "title": f"NAT server {sv.get('global_ip', '?')}:{sv.get('global_port', '?')} -> {sv.get('inside_ip', '?')}:{sv.get('inside_port', '?')}", "device": device_name, "score": score, "snapshot": snapshot.pk, "url": f"/analysis/{parsed.pk}/"})

        for iface in parsed.parsed_data.get("interfaces", []):
            if iface.get("has_nat") and (is_nat_keyword or (q_lower and q_lower in iface["name"].lower())):
                results.append({"type": "nat_interface", "title": f"Interface com NAT: {iface['name']}", "device": device_name, "score": 0.6, "snapshot": snapshot.pk, "url": f"/analysis/{parsed.pk}/"})

    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('title', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique[:20]


# ── VRF / VPN-instance search ─────────────────────────────────────────────


def _search_vrf(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search VRF / VPN-instance / L3VPN data in parsed snapshots.

    Searches: VPN-instance names, RD, RT, interfaces in VRF,
    static routes in VRF, BGP vpn-instance, VPNv4 peers.
    """
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)
    q_lower = q.lower()
    results: list[dict] = []

    is_vrf_query = q_lower in ("vpn-instance", "vrf", "l3vpn", "vpnv4")

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

    for parsed in parsed_qs:
        parsed_data = parsed.parsed_data
        vpn_instances = parsed_data.get("vpn_instances", [])
        bgp_blocks = parsed_data.get("bgp", [])
        snapshot = parsed.snapshot
        device_name = snapshot.device.name if snapshot.device else "?"

        # Get raw config text for evidence
        raw_text = snapshot.raw_config or ""

        # Search VPN-instance names
        for vi in vpn_instances:
            name = vi.get("name", "")
            desc = vi.get("description", "")
            evidence = []
            score = 0.0

            if is_vrf_query:
                score = 0.6
            elif q_lower and q_lower in name.lower():
                score = 1.0 if name.lower() == q_lower else 0.8
            elif desc and q_lower in desc.lower():
                score = 0.7
            elif qtype == "asn" and qval:
                for af in vi.get("address_families", {}).values():
                    rd = af.get("route_distinguisher", "")
                    if qval in rd:
                        score = max(score, 0.9)
                    for vt in af.get("vpn_targets", []):
                        if qval in vt.get("value", ""):
                            score = max(score, 0.8)
            elif qtype == "text":
                for af in vi.get("address_families", {}).values():
                    rd = af.get("route_distinguisher", "")
                    if rd and q_lower in rd.lower():
                        score = max(score, 0.7)
                    for vt in af.get("vpn_targets", []):
                        if q_lower in vt.get("value", "").lower():
                            score = max(score, 0.7)

            if score > 0:
                if raw_text:
                    evidence = _get_evidence_lines(raw_text, name)
                results.append({
                    "type": "vpn_instance",
                    "title": f"VPN-instance {name}",
                    "vpn_instance": name,
                    "description": desc,
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": evidence[:3],
                })

        # Search VPNv4 peers even without vpn_instances
        for bgp in bgp_blocks:
            for vp in bgp.get("vpnv4", {}).get("peers", []):
                peer = vp.get("peer", "")
                vpnv4_score = 0.0
                if is_vrf_query or q_lower in "vpnv4":
                    vpnv4_score = 0.6
                elif q_lower and q_lower in peer.lower():
                    vpnv4_score = 0.8
                if vpnv4_score > 0:
                    results.append({
                        "type": "vpnv4_peer",
                        "title": f"VPNv4 peer {peer}",
                        "vpnv4_peer": peer,
                        "enabled": vp.get("enabled", False),
                        "device": device_name,
                        "snapshot": snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": vpnv4_score,
                        "evidence": [],
                    })

            # Search BGP vpn-instance
            for vi in bgp.get("vpn_instances", []):
                vi_name = vi["name"]
                if q_lower and q_lower in vi_name.lower():
                    results.append({
                        "type": "bgp_vpn_instance",
                        "title": f"BGP vpn-instance {vi_name}",
                        "vpn_instance": vi_name,
                        "import_routes": vi.get("import_routes", []),
                        "device": device_name,
                        "snapshot": snapshot.pk,
                        "parsed_config": parsed.pk,
                        "url": f"/analysis/{parsed.pk}/",
                        "score": 0.7,
                        "evidence": [],
                    })

                for ce_peer in vi.get("peers", []):
                    if q_lower and q_lower == ce_peer.get("ip", "").lower():
                        results.append({
                            "type": "ce_peer",
                            "title": f"CE peer {ce_peer['ip']} in {vi_name}",
                            "vpn_instance": vi_name,
                            "ce_peer": ce_peer["ip"],
                            "remote_as": ce_peer.get("remote_as"),
                            "device": device_name,
                            "snapshot": snapshot.pk,
                            "parsed_config": parsed.pk,
                            "url": f"/analysis/{parsed.pk}/",
                            "score": 1.0,
                            "evidence": [],
                        })

        # Search interfaces in VRF
        for iface in parsed_data.get("interfaces", []):
            vpn_name = iface.get("vpn_instance")
            if not vpn_name:
                continue
            iface_name = iface.get("name", "")
            ip_addr = iface.get("ip_address", "")
            iface_desc = iface.get("description", "")
            score = 0.0

            if q_lower in iface_name.lower():
                score = 0.8
            elif q_lower and vpn_name and q_lower in vpn_name.lower():
                score = 0.6
            elif qtype == "ip" and ip_addr and qval in ip_addr:
                score = 0.7

            if score > 0:
                evidence = []
                if raw_text:
                    evidence = _get_evidence_lines(raw_text, iface_name)
                results.append({
                    "type": "vrf_interface",
                    "title": f"VRF interface {iface_name} ({vpn_name})",
                    "interface": iface_name,
                    "vpn_instance": vpn_name,
                    "ip_address": ip_addr,
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": evidence[:3],
                })

        # Search static routes in VRF
        for route in parsed_data.get("static_routes", []):
            vpn_name = route.get("vpn_instance")
            if not vpn_name:
                continue
            dest = f"{route.get('network', '?')}/{route.get('netmask', '?')}"
            nh = route.get("next_hop", "?")
            score = 0.0

            if q_lower in dest.lower():
                score = 0.8
            elif qtype == "prefix" and qval and qval in dest.replace(" ", "/"):
                score = 0.7
            elif qtype == "ip" and nh and qval == nh:
                score = 0.7
            elif q_lower and vpn_name and q_lower in vpn_name.lower():
                score = 0.5

            if score > 0:
                results.append({
                    "type": "vrf_static_route",
                    "title": f"VRF route {dest} via {nh} ({vpn_name})",
                    "vpn_instance": vpn_name,
                    "destination": dest,
                    "next_hop": nh,
                    "device": device_name,
                    "snapshot": snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": score,
                    "evidence": [],
                })
                for vi in bgp.get("vpn_instances", []):
                    vi_name = vi["name"]
                    if q_lower and q_lower in vi_name.lower():
                        results.append({
                            "type": "bgp_vpn_instance",
                            "vpn_instance": vi_name,
                            "import_routes": vi.get("import_routes", []),
                            "ce_peers": [p["ip"] for p in vi.get("peers", [])],
                            "snapshot_id": snapshot.pk,
                            "device": snapshot.device.name if snapshot.device else "?",
                            "score": 0.7,
                            "evidence": [],
                        })

                    for ce_peer in vi.get("peers", []):
                        if q_lower and q_lower == ce_peer.get("ip", "").lower():
                            results.append({
                                "type": "ce_peer",
                                "vpn_instance": vi_name,
                                "ce_peer": ce_peer["ip"],
                                "remote_as": ce_peer.get("remote_as"),
                                "snapshot_id": snapshot.pk,
                                "device": snapshot.device.name if snapshot.device else "?",
                                "score": 1.0,
                                "evidence": [],
                            })

                vpnv4 = bgp.get("vpnv4", {})
                for vp in vpnv4.get("peers", []):
                    peer = vp.get("peer", "")
                    if (q_lower in peer.lower()
                            or q_lower == "vpnv4"
                            or (qtype == "ip" and qval == peer)):
                        results.append({
                            "type": "vpnv4_peer",
                            "vpnv4_peer": peer,
                            "enabled": vp.get("enabled", False),
                            "snapshot_id": snapshot.pk,
                            "device": snapshot.device.name if snapshot.device else "?",
                            "score": 0.8 if qval == peer else 0.6,
                            "evidence": [],
                        })

    # Deduplicate by key
    seen: set[str] = set()
    unique_results = []
    for r in results:
        key = f"{r.get('type', '')}|{r.get('vpn_instance', '')}|{r.get('vpnv4_peer', '')}|{r.get('ce_peer', '')}|{r.get('interface', '')}"
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    unique_results.sort(key=lambda x: x.get("score", 0), reverse=True)
    return unique_results[:20]


def _search_huawei_advanced(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    query = classification["query"].lower()
    category_labels = {
        "evpn_vxlan": "EVPN / VXLAN",
        "segment_routing": "Segment Routing / SRv6",
        "mpls_te": "MPLS-TE / RSVP-TE",
        "cgnat": "CGNAT Avançado",
        "msdp": "MSDP",
        "telemetry": "Telemetria / Streaming",
        "bgp_advanced": "BGP Avançado",
    }
    aliases = {
        "evpn_vxlan": ("evpn", "vxlan", "vni", "nve", "bridge-domain"),
        "segment_routing": ("segment-routing", "segment routing", "srv6", "locator", "prefix-sid"),
        "mpls_te": ("mpls te", "mpls-te", "rsvp-te", "explicit-path", "tunnel-policy"),
        "cgnat": ("cgnat", "nat instance", "port-block", "session-limit"),
        "msdp": ("msdp",),
        "telemetry": ("telemetry", "grpc", "netstream", "sflow", "sensor-group", "subscription"),
        "bgp_advanced": ("route-reflector", "reflect-client", "confederation", "add-path", "dampening", "route-limit"),
    }
    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
    if only_last_snapshot or (filters and filters.get("last_snapshot_only")):
        from django.db.models import Max
        latest_ids = (
            parsed_qs.values("snapshot__device_id")
            .annotate(max_id=Max("snapshot_id"))
            .values_list("max_id", flat=True)
        )
        parsed_qs = parsed_qs.filter(snapshot_id__in=list(latest_ids))

    results = []
    for parsed in parsed_qs:
        advanced = parsed.parsed_data.get("huawei_advanced", {})
        for category, label in category_labels.items():
            payload = advanced.get(category, {})
            enabled = payload.get("enabled", False) or any(
                value for key, value in payload.items() if key.endswith("_enabled")
            )
            active = enabled or any(
                value
                for key, value in payload.items()
                if key != "enabled" and not key.endswith("_enabled")
            )
            if not active:
                continue
            searchable = f"{label} {category} {payload}".lower()
            alias_match = any(query in alias or alias in query for alias in aliases[category])
            if query not in searchable and not (enabled and alias_match):
                continue
            evidence_query = next((alias for alias in aliases[category] if alias in parsed.snapshot.raw_config.lower()), query)
            results.append({
                "type": category,
                "title": label,
                "description": f"Recursos detectados: {payload}",
                "device": parsed.snapshot.device.name if parsed.snapshot.device else "",
                "device_pk": parsed.snapshot.device_id,
                "snapshot": parsed.snapshot_id,
                "parsed_config": parsed.pk,
                "url": f"/analysis/{parsed.pk}/documentation/",
                "score": 0.9 if query in searchable else 0.7,
                "metadata": payload,
                "evidence": _get_evidence_lines(parsed.snapshot.raw_config, evidence_query)[:3],
            })
    return results[:20]


def _search_zte_olt(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search ZTE OLT entities: PON, ONU serial, VLAN and service-port."""
    q = classification["query"]
    q_lower = q.lower()
    qtype = classification["type"]
    qval = str(classification.get("value", q))

    parsed_qs = ParsedConfig.objects.select_related("snapshot__device").all()
    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(snapshot__device__name__icontains=filters["device"])
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
        olt = parsed.parsed_data.get("zte_olt", {})
        if not olt.get("enabled"):
            continue
        device_name = parsed.snapshot.device.name if parsed.snapshot.device else ""
        for pon in olt.get("pon_ports", []):
            searchable = " ".join([
                pon.get("name", ""),
                pon.get("pon", ""),
                pon.get("description", ""),
            ]).lower()
            if q_lower in searchable:
                results.append({
                    "type": "zte_pon",
                    "title": pon.get("name", pon.get("pon", "")),
                    "description": f"{pon.get('onu_count', 0)} ONU(s)",
                    "device": device_name,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": 0.9,
                    "evidence": [pon.get("raw", "")[:300]],
                })
        for onu in olt.get("onus", []):
            service_vlans = {str(s.get("vlan") or s.get("user_vlan") or "") for s in onu.get("service_ports", [])}
            searchable = " ".join([
                onu.get("interface", ""),
                onu.get("serial", ""),
                onu.get("name", ""),
                onu.get("description", ""),
                onu.get("type", ""),
                onu.get("pon", ""),
                onu.get("onu_id", ""),
                " ".join(service_vlans),
            ]).lower()
            vlan_match = qtype in ("vlan", "asn") and qval in service_vlans
            if q_lower in searchable or vlan_match:
                results.append({
                    "type": "zte_onu",
                    "title": onu.get("interface", ""),
                    "description": f"{onu.get('serial', '-')} — VLAN(s): {', '.join(sorted(v for v in service_vlans if v)) or '-'}",
                    "device": device_name,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": 1.0 if q_lower in onu.get("serial", "").lower() else 0.85,
                    "evidence": [onu.get("raw", "")[:400]],
                })
        for service in olt.get("service_ports", []):
            fields = [
                service.get("id", ""),
                service.get("onu", ""),
                service.get("vlan", ""),
                service.get("user_vlan", ""),
                service.get("gemport", ""),
                service.get("vport", ""),
            ]
            vlan_match = qtype in ("vlan", "asn") and qval in {
                str(service.get("vlan", "")),
                str(service.get("user_vlan", "")),
            }
            if q_lower in " ".join(fields).lower() or vlan_match:
                results.append({
                    "type": "zte_service_port",
                    "title": f"Service-port {service.get('id', '-')}",
                    "description": f"{service.get('onu', '-')} — VLAN {service.get('vlan') or service.get('user_vlan') or '-'}",
                    "device": device_name,
                    "snapshot": parsed.snapshot.pk,
                    "parsed_config": parsed.pk,
                    "url": f"/analysis/{parsed.pk}/",
                    "score": 0.8,
                    "evidence": [service.get("raw", "")],
                })
    results.sort(key=lambda item: item["score"], reverse=True)
    return results[:30]


def _search_vlan_tracking(query: str) -> list[dict]:
    """Search VLAN tracking sessions, VLANs, issues, links, and endpoints."""
    from apps.vlan_tracking.operational import search_vlan_tracking
    return search_vlan_tracking(query)


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
    vrf_results = _search_vrf(
        classification, effective_filters, only_last_snapshot
    )
    qos_results = _search_qos(
        classification, effective_filters, only_last_snapshot
    )
    bng_results = _search_bng(classification, effective_filters, only_last_snapshot)
    ha_results = _search_ha(classification, effective_filters, only_last_snapshot)
    multicasts_results = _search_multicast(classification, effective_filters, only_last_snapshot)
    pppoe_results = _search_pppoe(classification, effective_filters, only_last_snapshot)
    huawei_advanced_results = _search_huawei_advanced(
        classification, effective_filters, only_last_snapshot
    )
    zte_olt_results = _search_zte_olt(
        classification, effective_filters, only_last_snapshot
    )
    ipv6_results = _search_ipv6(classification, effective_filters, only_last_snapshot)
    nat_results = _search_nat(
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
        "vrf": len(vrf_results),
        "qos": len(qos_results),
        "nat": len(nat_results),
        "ipv6": len(ipv6_results),
        "bng": len(bng_results),
        "ha": len(ha_results),
        "multicast": len(multicasts_results),
        "pppoe": len(pppoe_results),
        "huawei_advanced": len(huawei_advanced_results),
        "zte_olt": len(zte_olt_results),
        "raw_matches": len(raw_matches),
    }

    total = sum(summary_counts.values())

    # VLAN Tracking search
    vlan_tracking_results = _search_vlan_tracking(query)

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
        "vrf": vrf_results,
        "qos": qos_results,
        "nat": nat_results,
        "ipv6": ipv6_results,
        "bng": bng_results,
        "ha": ha_results,
        "multicast": multicasts_results,
        "pppoe": pppoe_results,
        "huawei_advanced": huawei_advanced_results,
        "zte_olt": zte_olt_results,
        "vlan_tracking": vlan_tracking_results,
        "raw_matches": raw_matches,
    }
