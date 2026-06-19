"""Detector de circuitos L3 (trânsito IP).

Detecta subinterfaces dot1q com IP /30 e rota estática apontando
para o next-hop dentro da mesma rede /30 — caracterizando um
circuito de trânsito L3.
"""

from __future__ import annotations

import ipaddress
import re

from apps.analysis.models import DetectedCircuit


def detect_l3_transit_circuits(
    snapshot, parsed_data: dict
) -> list[DetectedCircuit]:
    """Detecta circuitos de trânsito L3 a partir dos dados parseados.

    Algoritmo:
        1. Para cada interface com vlan-type dot1q e IP /30:
           a. Calcula a rede de trânsito (transit_network).
           b. Para cada rota estática, verifica se o next-hop
              está dentro da rede /30.
           c. Separa rotas default (0.0.0.0/0) de rotas específicas.
           d. Para cada rota específica, cria um circuito com
              routed_prefix e metadata routed_prefix_is_public.
           e. Se houver rota default, adiciona
              default_route_via_transit na metadata.
           f. Se apenas rotas default baterem, cria único circuito
              com routed_prefix=None.
        2. Cria objetos DetectedCircuit para cada match.

    Args:
        snapshot: Instância de ConfigSnapshot.
        parsed_data: Dicionário retornado pelo parser.

    Returns:
        Lista de objetos DetectedCircuit criados (já salvos).
    """
    circuits: list[DetectedCircuit] = []

    # Collect all /30 subinterfaces with dot1q VLAN
    candidates = _find_transit_candidates(parsed_data)

    static_routes = parsed_data.get("static_routes", [])

    for candidate in candidates:
        transit_network = candidate["transit_network"]
        local_ip = candidate["local_ip"]
        interface_name = candidate["interface_name"]
        vlan_id = candidate["vlan_id"]

        # Separate matching routes into default vs specific
        matching_defaults: list[dict] = []
        matching_specifics: list[dict] = []

        for route in static_routes:
            next_hop = route.get("next_hop")
            if not next_hop:
                continue

            # Skip NULL0 / interface-based routes
            if _is_non_ip_next_hop(next_hop):
                continue

            try:
                nh_ip = ipaddress.ip_address(next_hop)
            except ValueError:
                continue

            if nh_ip not in transit_network:
                continue

            # Classify as default or specific
            if _is_default_route(route):
                matching_defaults.append(route)
            else:
                matching_specifics.append(route)

        remote_ip = None
        if matching_specifics:
            remote_ip = matching_specifics[0].get("next_hop")
        elif matching_defaults:
            remote_ip = matching_defaults[0].get("next_hop")

        if not matching_specifics and not matching_defaults:
            continue

        # Build metadata flags
        has_default_route = bool(matching_defaults)

        if matching_specifics:
            # Create one circuit per specific route
            for route in matching_specifics:
                routed_prefix = _extract_routed_prefix(route, transit_network)
                routed_prefix_is_public = _is_public_prefix(routed_prefix)

                metadata = {
                    "routed_prefix_is_public": routed_prefix_is_public,
                }
                if has_default_route:
                    metadata["default_route_via_transit"] = True

                evidence = {
                    "interface": interface_name,
                    "vlan_id": vlan_id,
                    "transit_network": str(transit_network),
                    "local_ip": local_ip,
                    "remote_ip": route.get("next_hop", ""),
                    "next_hop": route.get("next_hop", ""),
                    "routed_prefix": routed_prefix,
                    "static_route_raw": route.get("raw", ""),
                    "method": "dot1q_subinterface_with_connected_static_route",
                    "metadata": metadata,
                }

                circuit = DetectedCircuit(
                    snapshot=snapshot,
                    circuit_type=DetectedCircuit.CircuitType.L3_TRANSIT,
                    description=route.get("description", ""),
                    details={
                        "interface": interface_name,
                        "vlan_id": vlan_id,
                        "transit_network": str(transit_network),
                        "local_ip": local_ip,
                        "remote_ip": route.get("next_hop", ""),
                        "routed_prefix": routed_prefix,
                        "routed_prefix_is_public": routed_prefix_is_public,
                        "confidence": 0.80,
                        "vendor": "huawei",
                        "evidence": evidence,
                        "metadata": metadata,
                    },
                )
                circuit.save()
                circuits.append(circuit)
        else:
            # Only default routes match — create circuit without routed_prefix
            metadata = {
                "default_route_via_transit": True,
                "routed_prefix_is_public": False,
            }

            evidence = {
                "interface": interface_name,
                "vlan_id": vlan_id,
                "transit_network": str(transit_network),
                "local_ip": local_ip,
                "remote_ip": matching_defaults[0].get("next_hop", ""),
                "next_hop": matching_defaults[0].get("next_hop", ""),
                "routed_prefix": None,
                "static_route_raw": matching_defaults[0].get("raw", ""),
                "method": "dot1q_subinterface_with_connected_static_route_default_only",
                "metadata": metadata,
            }

            circuit = DetectedCircuit(
                snapshot=snapshot,
                circuit_type=DetectedCircuit.CircuitType.L3_TRANSIT,
                description=matching_defaults[0].get("description", ""),
                details={
                    "interface": interface_name,
                    "vlan_id": vlan_id,
                    "transit_network": str(transit_network),
                    "local_ip": local_ip,
                    "remote_ip": matching_defaults[0].get("next_hop", ""),
                    "routed_prefix": None,
                    "routed_prefix_is_public": False,
                    "confidence": 0.60,
                    "vendor": "huawei",
                    "evidence": evidence,
                    "metadata": metadata,
                },
            )
            circuit.save()
            circuits.append(circuit)

    return circuits


def _find_transit_candidates(parsed_data: dict) -> list[dict]:
    """Find subinterfaces with dot1q VLAN and /30 IP address."""
    candidates = []
    interfaces = parsed_data.get("interfaces", [])

    for iface in interfaces:
        # Must be a subinterface with dot1q VLAN
        if iface.get("vlan_type") != "dot1q":
            continue
        vlan_id = iface.get("vlan_id")
        if vlan_id is None:
            continue

        ip_addr_str = iface.get("ip_address")
        if not ip_addr_str:
            continue

        # Parse "ip_address" field: "<ip> <netmask>" or "<ip>/<prefix>"
        network = _ip_str_to_network(ip_addr_str)
        if network is None:
            continue

        # Must be /30
        if network.prefixlen != 30:
            continue

        # Skip if network is 0.0.0.0/30 (unlikely but guard)
        if str(network.network_address) == "0.0.0.0":
            continue

        candidates.append(
            {
                "interface_name": iface["name"],
                "vlan_id": int(vlan_id) if vlan_id else None,
                "local_ip": _extract_ip_only(ip_addr_str),
                "transit_network": network,
                "ip_address_str": ip_addr_str,
            }
        )

    return candidates


def _extract_ip_only(ip_str: str) -> str:
    """Extract just the IP address from 'A.B.C.D M.M.M.M' or 'A.B.C.D/30'."""
    ip_str = ip_str.strip()
    if "/" in ip_str:
        return ip_str.split("/")[0]
    return ip_str.split()[0] if ip_str else ""


def _ip_str_to_network(ip_str: str) -> ipaddress.IPv4Network | None:
    """Convert an ip address string to an IPv4Network.

    Supports formats:
        - "10.0.0.1 255.255.255.252"
        - "10.0.0.1/30"
    """
    ip_str = ip_str.strip()

    if "/" in ip_str:
        try:
            return ipaddress.IPv4Network(ip_str, strict=False)
        except ValueError:
            return None

    # Format: "A.B.C.D M.M.M.M"
    parts = ip_str.split()
    if len(parts) == 2:
        try:
            addr = ipaddress.IPv4Address(parts[0])
            netmask = ipaddress.IPv4Address(parts[1])
            # Convert netmask to prefix length
            prefix = bin(int(netmask)).count("1")
            network = ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
            return network
        except ValueError:
            return None

    return None


def _is_non_ip_next_hop(next_hop: str) -> bool:
    """Check if the next-hop is an interface name or NULL0 (not an IP)."""
    upper = next_hop.upper()
    if upper in ("NULL0", "NULL 0", "NULL"):
        return True
    # Interface names like GigabitEthernet0/0/1, Eth-Trunk1, etc.
    if next_hop.replace("/", "").replace("-", "").isalpha() is False:
        # Has digits and letters — likely an interface
        if any(c.isdigit() for c in next_hop) and any(c.isalpha() for c in next_hop):
            if not next_hop.replace(".", "").replace("/", "").isdigit():
                return True
    return False


def _extract_routed_prefix(route: dict, transit_network) -> str | None:
    """Extract the routed prefix from a static route.

    If the static route destination is the transit network itself
    (e.g. a direct route), return None.
    Otherwise, return the destination as a CIDR string.
    Default routes (0.0.0.0/0) are also returned as None here
    since they are handled separately.
    """
    network = route.get("network")
    netmask = route.get("netmask")

    if not network or not netmask:
        return None

    # Don't return default route as routed_prefix
    if network == "0.0.0.0" and netmask == "0.0.0.0":
        return None

    try:
        dest = _ip_str_to_network(f"{network} {netmask}")
        if dest and dest != transit_network:
            return str(dest)
    except (ValueError, TypeError):
        pass

    return None


def _is_default_route(route: dict) -> bool:
    """Check if a static route is a default route (0.0.0.0/0)."""
    return route.get("network") == "0.0.0.0" and route.get("netmask") == "0.0.0.0"


def _is_public_prefix(prefix: str | None) -> bool:
    """Check if a CIDR prefix is a public (non-private) IP range.

    Private ranges (returns False):
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 100.64.0.0/10 (CGNAT)
        - 127.0.0.0/8 (loopback)
    """
    if not prefix:
        return False

    try:
        network = ipaddress.IPv4Network(prefix, strict=False)
        return not network.is_private
    except (ValueError, TypeError):
        return False


# ── VLAN Transport detector ──────────────────────────────────────────────


def detect_vlan_transport_circuits(
    snapshot, parsed_data: dict
) -> list[DetectedCircuit]:
    """Detecta circuitos de transporte VLAN simples.

    Uma subinterface dot1q sem IP e sem outros marcadores
    (QinQ, L2 binding) é classificada como transporte L2/VLAN.

    Regras:
        - Subinterface com vlan-type dot1q
        - Sem IP configurado
        - Sem QinQ (second_vlan_id, pe_vid, ce_vid)
        - Sem l2 binding vsi
    """
    circuits: list[DetectedCircuit] = []
    interfaces = parsed_data.get("interfaces", [])

    for iface in interfaces:
        if iface.get("vlan_type") not in ("dot1q",):
            continue
        vlan_id = iface.get("vlan_id")
        ip_addr = iface.get("ip_address")
        second_vlan_id = iface.get("second_vlan_id")
        pe_vid = iface.get("pe_vid")
        ce_vid = iface.get("ce_vid")
        vsi_name = iface.get("vsi_name")

        if not vlan_id:
            continue

        # Skip if it has IP (might be L3 or other type)
        if ip_addr:
            continue

        # Skip if it's QinQ
        if second_vlan_id or pe_vid or ce_vid:
            continue

        # Skip if it's L2 binding
        if vsi_name:
            continue

        description = iface.get("description", "")

        # Confidence based on description quality
        has_good_description = bool(description.strip())
        confidence = 0.70 if has_good_description else 0.50

        circuit = DetectedCircuit(
            snapshot=snapshot,
            circuit_type=DetectedCircuit.CircuitType.VLAN_TRANSPORT,
            description=description,
            details={
                "interface": iface["name"],
                "vlan_id": int(vlan_id) if vlan_id else None,
                "parent_interface": iface.get("parent"),
                "description": description,
                "confidence": confidence,
                "vendor": "huawei",
                "evidence": {
                    "interface": iface["name"],
                    "vlan_id": vlan_id,
                    "method": "dot1q_subinterface_without_ip",
                },
            },
        )
        circuit.save()
        circuits.append(circuit)

    return circuits


# ── QinQ Transport detector ────────────────────────────────────────────


def detect_qinq_transport_circuits(
    snapshot, parsed_data: dict
) -> list[DetectedCircuit]:
    """Detecta circuitos QinQ (dupla tag 802.1Q).

    Detecta subinterfaces com:
        - vlan-type dot1q X second-dot1q Y
        - qinq termination pe-vid X ce-vid Y
    """
    circuits: list[DetectedCircuit] = []
    interfaces = parsed_data.get("interfaces", [])

    for iface in interfaces:
        vlan_type = iface.get("vlan_type", "")
        second_vlan_id = iface.get("second_vlan_id")
        pe_vid = iface.get("pe_vid")
        ce_vid = iface.get("ce_vid")

        is_qinq = (
            (vlan_type == "dot1q" and second_vlan_id is not None)
            or (vlan_type == "qinq_termination" and pe_vid is not None)
        )

        if not is_qinq:
            continue

        vlan_id = iface.get("vlan_id")
        ip_addr = iface.get("ip_address")
        description = iface.get("description", "")

        details = {
            "interface": iface["name"],
            "vlan_id": int(vlan_id) if vlan_id else None,
            "second_vlan_id": int(second_vlan_id) if second_vlan_id else None,
            "pe_vid": int(pe_vid) if pe_vid else None,
            "ce_vid": int(ce_vid) if ce_vid else None,
            "ip_address": ip_addr,
            "parent_interface": iface.get("parent"),
            "description": description,
            "confidence": 0.85,
            "vendor": "huawei",
            "evidence": {
                "interface": iface["name"],
                "vlan_type": vlan_type,
                "second_vlan_id": int(second_vlan_id) if second_vlan_id else None,
                "pe_vid": int(pe_vid) if pe_vid else None,
                "ce_vid": int(ce_vid) if ce_vid else None,
                "method": "qinq_subinterface_detected",
            },
        }

        circuit = DetectedCircuit(
            snapshot=snapshot,
            circuit_type=DetectedCircuit.CircuitType.QINQ_TRANSPORT,
            description=description,
            details=details,
        )
        circuit.save()
        circuits.append(circuit)

    return circuits


# ── L2VPN VSI detector ────────────────────────────────────────────────


def detect_l2vpn_vsi_circuits(
    snapshot, parsed_data: dict
) -> list[DetectedCircuit]:
    """Detecta circuitos L2VPN/VSI.

    Detecta subinterfaces com l2 binding vsi <name> e também
    blocos VSI órfãos (sem binding em subinterface).
    """
    circuits: list[DetectedCircuit] = []
    interfaces = parsed_data.get("interfaces", [])
    vsi_blocks = parsed_data.get("vsi", [])

    # Build lookup by VSI name
    vsi_lookup: dict[str, dict] = {}
    for vsi in vsi_blocks:
        vsi_lookup[vsi["name"]] = vsi

    bound_vsi_names: set[str] = set()

    for iface in interfaces:
        vsi_name = iface.get("vsi_name")
        if not vsi_name:
            continue

        bound_vsi_names.add(vsi_name)
        vlan_id = iface.get("vlan_id")
        description = iface.get("description", "")
        vsi_info = vsi_lookup.get(vsi_name, {})

        confidence = 0.90 if vsi_name in vsi_lookup else 0.75

        details = {
            "interface": iface["name"],
            "vlan_id": int(vlan_id) if vlan_id else None,
            "vsi_name": vsi_name,
            "vsi_id": vsi_info.get("vsi_id"),
            "vsi_peers": vsi_info.get("peers", []),
            "peer_count": len(vsi_info.get("peers", [])),
            "parent_interface": iface.get("parent"),
            "description": description,
            "confidence": confidence,
            "vendor": "huawei",
            "evidence": {
                "interface": iface["name"],
                "vsi_name": vsi_name,
                "method": "l2_binding_vsi",
            },
        }

        circuit = DetectedCircuit(
            snapshot=snapshot,
            circuit_type=DetectedCircuit.CircuitType.L2VPN_VSI,
            description=description,
            details=details,
        )
        circuit.save()
        circuits.append(circuit)

    # Create orphan VSI circuits for VSI blocks without binding
    for vsi_name, vsi in vsi_lookup.items():
        if vsi_name in bound_vsi_names:
            continue

        circuit = DetectedCircuit(
            snapshot=snapshot,
            circuit_type=DetectedCircuit.CircuitType.L2VPN_VSI,
            description=f"VSI {vsi_name} (sem binding em subinterface)",
            details={
                "interface": None,
                "vlan_id": None,
                "vsi_name": vsi_name,
                "vsi_id": vsi.get("vsi_id"),
                "vsi_peers": vsi.get("peers", []),
                "peer_count": len(vsi.get("peers", [])),
                "parent_interface": None,
                "description": "",
                "confidence": 0.70,
                "vendor": "huawei",
                "evidence": {
                    "vsi_name": vsi_name,
                    "method": "orphan_vsi_block",
                },
            },
        )
        circuit.save()
        circuits.append(circuit)

    return circuits
