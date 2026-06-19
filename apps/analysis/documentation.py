"""Serviço de documentação automática determinística.

Gera documentação técnica estruturada em português com base nos
dados parseados, circuitos detectados e issues encontradas.
Sem uso de IA — toda a geração é feita por regras Python puras.
"""

from __future__ import annotations

import ipaddress

from apps.analysis.models import AnalysisIssue, DetectedCircuit, ParsedConfig

# ── Keywords de detecção de funções ──────────────────────────────────────
BNG_KEYWORDS = {"bas", "bng", "pppoe", "radius", "aaa"}
L2VPN_KEYWORDS = {"vsi", "vpls", "l2vpn"}


def generate_analysis_documentation(
    parsed_config: ParsedConfig,
) -> dict:
    """Gera documentação técnica completa a partir de um ParsedConfig.

    Args:
        parsed_config: Instância de ParsedConfig com parsed_data,
                       snapshot, circuits e issues relacionados.

    Returns:
        Dicionário estruturado com as seções da documentação.
    """
    parsed_data = parsed_config.parsed_data
    snapshot = parsed_config.snapshot
    device = snapshot.device

    circuits = list(snapshot.detected_circuits.all())
    issues = list(snapshot.analysis_issues.all())
    services = list(snapshot.detected_services.all())

    interfaces = parsed_data.get("interfaces", [])
    static_routes = parsed_data.get("static_routes", [])
    bgp_blocks = parsed_data.get("bgp", [])
    sysname = parsed_data.get("sysname", "")
    all_blocks = parsed_data.get("blocks", [])

    # Build connected networks lookup
    connected_networks = _build_connected_networks(interfaces)

    # ── Summary ─────────────────────────────────────────────────────
    summary = {
        "device_name": device.name if device else "—",
        "vendor": snapshot.vendor or "—",
        "sysname": sysname or "—",
        "analysis_date": parsed_config.created_at.isoformat() if parsed_config.created_at else "—",
        "parsed_id": parsed_config.pk,
        "snapshot_id": snapshot.pk,
        "total_interfaces": len(interfaces),
        "total_eth_trunks": sum(
            1 for i in interfaces if i.get("type") == "eth-trunk"
        ),
        "total_subinterfaces": sum(
            1 for i in interfaces if i.get("vlan_type") == "dot1q"
        ),
        "total_static_routes": len(static_routes),
        "total_circuits": len(circuits),
        "total_issues": len(issues),
        "total_services": len(services),
        "has_bgp": len(bgp_blocks) > 0,
        "has_bng": any(svc.service_type == "bng" for svc in services),
        "has_aaa": any(svc.service_type == "aaa" for svc in services),
        "has_radius": any(svc.service_type == "radius" for svc in services),
        "has_snmp": parsed_data.get("snmp", {}).get("enabled", False),
        "has_ntp": parsed_data.get("ntp", {}).get("enabled", False),
        "has_syslog": parsed_data.get("syslog", {}).get("enabled", False),
        "has_local_users": bool(parsed_data.get("local_users", [])),
        "has_vty": bool(parsed_data.get("vty_lines", [])),
        "has_ssh_stelnet": parsed_data.get("ssh", {}).get("enabled", False),
        "has_isis": bool(parsed_data.get("isis", [])),
        "has_mpls": parsed_data.get("mpls", {}).get("enabled", False),
        "has_mpls_ldp": parsed_data.get("mpls_ldp", {}).get("enabled", False),
    }

    # ── Detected roles ──────────────────────────────────────────────
    detected_roles = _detect_roles(parsed_data, interfaces, bgp_blocks, all_blocks)

    # ── Interfaces ──────────────────────────────────────────────────
    documented_interfaces = [_document_interface(iface) for iface in interfaces]

    # ── Eth-Trunks ──────────────────────────────────────────────────
    eth_trunks = [
        _document_interface(iface)
        for iface in interfaces
        if iface.get("type") == "eth-trunk"
    ]

    # ── Subinterfaces ───────────────────────────────────────────────
    subinterfaces = [
        _document_interface(iface)
        for iface in interfaces
        if iface.get("vlan_type") == "dot1q"
    ]

    # ── Static routes ───────────────────────────────────────────────
    documented_routes = [
        _document_static_route(route, connected_networks)
        for route in static_routes
    ]

    # ── BGP ─────────────────────────────────────────────────────────
    documented_bgp = [_document_bgp_block(bgp) for bgp in bgp_blocks]

    # ── Circuits ────────────────────────────────────────────────────
    documented_circuits = [
        _document_circuit(circuit) for circuit in circuits
    ]

    # ── Services ────────────────────────────────────────────────────
    documented_services = [_document_service(svc) for svc in services]

    # ── Issues ──────────────────────────────────────────────────────
    documented_issues = [
        {
            "severity": issue.severity,
            "severity_display": issue.get_severity_display(),
            "code": issue.code,
            "title": issue.title,
            "description": issue.description,
            "metadata": issue.metadata,
        }
        for issue in issues
    ]

    # ── Logical map ─────────────────────────────────────────────────
    logical_map = _build_logical_map(
        sysname, interfaces, static_routes, bgp_blocks, circuits
    )

    # ── Recommendations ─────────────────────────────────────────────
    recommendations = _generate_recommendations(issues, interfaces, static_routes)

    # ── Management documentation ────────────────────────────────────
    mgmt_snmp = _document_snmp(parsed_data)
    mgmt_ntp = _document_ntp(parsed_data)
    mgmt_syslog = _document_syslog(parsed_data)
    mgmt_access = _document_management_access(parsed_data)
    mgmt_local_users = _document_local_users(parsed_data)

    return {
        "summary": summary,
        "detected_roles": detected_roles,
        "interfaces": documented_interfaces,
        "eth_trunks": eth_trunks,
        "subinterfaces": subinterfaces,
        "static_routes": documented_routes,
        "bgp": documented_bgp,
        "circuits": documented_circuits,
        "services": documented_services,
        "issues": documented_issues,
        "logical_map": logical_map,
        "recommendations": recommendations,
        # Management
        "management": {
            "snmp": mgmt_snmp,
            "ntp": mgmt_ntp,
            "syslog": mgmt_syslog,
            "access": mgmt_access,
            "local_users": mgmt_local_users,
        },
        # Core
        "core": _document_core(parsed_data) or _build_core_documentation(parsed_data),
        # Policies
        "policies": _build_policy_documentation(parsed_data),
    }


# ── Role detection ──────────────────────────────────────────────────────


def _detect_roles(
    parsed_data: dict,
    interfaces: list[dict],
    bgp_blocks: list[dict],
    all_blocks: list[dict],
) -> list[dict]:
    """Detecta funções prováveis do equipamento."""
    roles: list[dict] = []

    vendor = parsed_data.get("vendor", "")

    # BGP
    if bgp_blocks:
        role_name = "Roteador Cisco com BGP" if vendor == "cisco" else "Roteador com BGP"
        roles.append(
            {
                "role": role_name,
                "evidence": f"{len(bgp_blocks)} bloco(s) BGP encontrado(s)",
                "confidence": "alta",
            }
        )

    # Transporte VLAN — muitas subinterfaces dot1q
    dot1q_count = sum(1 for i in interfaces if i.get("vlan_type") == "dot1q")
    if dot1q_count >= 2:
        role_suffix = " 802.1Q" if vendor == "cisco" else ""
        roles.append(
            {
                "role": f"Subinterfaces VLAN{role_suffix}",
                "evidence": f"{dot1q_count} subinterface(s) dot1q encontrada(s)",
                "confidence": "média",
            }
        )
    elif dot1q_count == 1:
        # Single dot1q subinterface — still mention it
        role_suffix = " 802.1Q" if vendor == "cisco" else ""
        roles.append(
            {
                "role": f"Subinterface VLAN{role_suffix}",
                "evidence": f"{dot1q_count} subinterface(s) dot1q encontrada(s)",
                "confidence": "baixa",
            }
        )

    # Prefixo público via trânsito privado
    if _has_public_prefix_via_private_transit(parsed_data, interfaces):
        roles.append(
            {
                "role": "Entrega de prefixos públicos por trânsito privado",
                "evidence": "Rota(s) estática(s) com next-hop privado apontando para prefixo público",
                "confidence": "alta",
            }
        )

    # Eth-Trunk / agregação
    eth_count = sum(1 for i in interfaces if i.get("type") == "eth-trunk")
    if eth_count > 0:
        roles.append(
            {
                "role": "Agregação de links / uplinks",
                "evidence": f"{eth_count} Eth-Trunk(s) configurada(s)",
                "confidence": "alta",
            }
        )

    # BNG/BAS específico (baseado em blocos parseados)
    bas_blocks = parsed_data.get("bas_interfaces", [])
    aaa_blocks = parsed_data.get("aaa", [])
    radius_blocks = parsed_data.get("radius_servers", [])
    pools = parsed_data.get("ip_pools", [])

    if bas_blocks and aaa_blocks and radius_blocks:
        roles.append(
            {
                "role": "BNG/BAS completo com AAA e RADIUS",
                "evidence": f"{len(bas_blocks)} BAS, {len(aaa_blocks)} AAA, "
                           f"{len(radius_blocks)} RADIUS, {len(pools)} pool(s)",
                "confidence": "alta",
            }
        )
    elif bas_blocks and aaa_blocks:
        roles.append(
            {
                "role": "Possível BNG/BAS com AAA",
                "evidence": f"{len(bas_blocks)} BAS, {len(aaa_blocks)} AAA",
                "confidence": "alta",
            }
        )
    elif aaa_blocks and radius_blocks:
        roles.append(
            {
                "role": "Autenticação AAA/RADIUS",
                "evidence": f"{len(aaa_blocks)} AAA, {len(radius_blocks)} RADIUS",
                "confidence": "alta",
            }
        )
    elif pools:
        roles.append(
            {
                "role": "Distribuição de endereços por IP Pool",
                "evidence": f"{len(pools)} pool(s) de IP configurado(s)",
                "confidence": "média",
            }
        )

    # BNG keywords (fallback)
    raw_text = parsed_data.get("raw", "").lower()
    existing_role_names = {r["role"] for r in roles}
    if not any("BNG" in n or "AAA" in n or "RADIUS" in n or "Pool" in n
               for n in existing_role_names):
        if any(kw in raw_text for kw in BNG_KEYWORDS):
            roles.append(
                {
                    "role": "Possível BNG/Autenticação de assinantes",
                    "evidence": "Palavras-chave BNG/BAS/PPPoE/RADIUS/AAA encontradas",
                    "confidence": "média",
                }
            )

    # L2VPN/VPLS
    if any(kw in raw_text for kw in L2VPN_KEYWORDS):
        roles.append(
            {
                "role": "Possível transporte L2VPN/VPLS",
                "evidence": "Palavras-chave VSI/VPLS/L2VPN encontradas",
                "confidence": "média",
            }
        )

    # L2 Switching roles
    l2_port_count = sum(1 for i in interfaces if i.get("is_l2_port"))
    if l2_port_count > 0:
        roles.append({
            "role": "Comutação L2 (Switching)",
            "evidence": f"{l2_port_count} porta(s) configurada(s) com modo L2",
            "confidence": "alta",
        })

    vlans = parsed_data.get("vlans", [])
    if vlans:
        roles.append({
            "role": f"VLANs configuradas ({len(vlans)})",
            "evidence": f"{len(vlans)} VLAN(s) configurada(s)",
            "confidence": "alta",
        })

    stp = parsed_data.get("stp", {})
    if stp.get("enabled"):
        mode = (stp.get("mode") or "desconhecido").upper()
        roles.append({
            "role": f"STP ativo ({mode})",
            "evidence": f"Modo {mode} detectado",
            "confidence": "alta",
        })

    # OSPF role
    ospf_blocks = parsed_data.get("ospf", [])
    if ospf_blocks:
        process_ids = [ob.get("process_id", "?") for ob in ospf_blocks]
        total_areas = set()
        total_networks = 0
        for ob in ospf_blocks:
            for a in ob.get("areas", []):
                total_areas.add(a)
            total_networks += len(ob.get("networks", []))
        roles.append({
            "role": f"Roteamento dinâmico OSPF ({', '.join(process_ids)})",
            "evidence": f"{len(ospf_blocks)} processo(s), "
                       f"{len(total_areas)} área(s), "
                       f"{total_networks} rede(s)",
            "confidence": "alta",
        })

    # Management roles
    snmp_data = parsed_data.get("snmp", {})
    if snmp_data.get("enabled"):
        versions = snmp_data.get("versions", [])
        ver_str = ", ".join(versions) if versions else "v2c/v3"
        roles.append(
            {
                "role": f"Gerência SNMP ({ver_str})",
                "evidence": f"{len(snmp_data.get('communities', []))} community(ies), "
                           f"{len(snmp_data.get('trap_hosts', []))} trap host(s)",
                "confidence": "alta",
            }
        )

    ntp_data = parsed_data.get("ntp", {})
    if ntp_data.get("enabled") and ntp_data.get("servers"):
        roles.append(
            {
                "role": "Sincronização NTP",
                "evidence": f"{len(ntp_data['servers'])} servidor(es) NTP configurado(s)",
                "confidence": "alta",
            }
        )

    syslog_data = parsed_data.get("syslog", {})
    if syslog_data.get("enabled") and syslog_data.get("log_hosts"):
        roles.append(
            {
                "role": "Envio de logs para servidor remoto",
                "evidence": f"{len(syslog_data['log_hosts'])} loghost(s) configurado(s)",
                "confidence": "alta",
            }
        )

    vty_lines = parsed_data.get("vty_lines", [])
    ssh_data = parsed_data.get("ssh", {})
    if vty_lines or ssh_data.get("enabled"):
        roles.append(
            {
                "role": "Acesso administrativo via SSH/VTY",
                "evidence": f"{len(vty_lines)} linha(s) VTY, "
                           f"SSH: {'sim' if ssh_data.get('enabled') else 'não'}",
                "confidence": "alta",
            }
        )

    local_users = parsed_data.get("local_users", [])
    if local_users:
        high_priv = sum(1 for u in local_users if u.get("privilege_level", 0) >= 15)
        roles.append(
            {
                "role": f"Usuários locais ({len(local_users)} usuário(s))",
                "evidence": f"{high_priv} usuário(s) com privilégio máximo",
                "confidence": "alta",
            }
        )

    # Core roles - MPLS/LDP/ISIS
    core_data = _build_core_documentation(parsed_data)

    if core_data["has_mpls"] and core_data["has_mpls_ldp"] and bgp_blocks:
        roles.append({
            "role": "Roteador PE/P de core",
            "evidence": "MPLS + LDP + BGP detectados",
            "confidence": "alta",
        })

    if core_data["has_isis"]:
        roles.append({
            "role": "Roteador de core com ISIS",
            "evidence": f"{len(core_data['isis'])} processo(s) ISIS detectado(s)",
            "confidence": "alta",
        })

    if core_data["has_mpls_ldp"]:
        roles.append({
            "role": "Label distribution via LDP",
            "evidence": f"{len(core_data['mpls_ldp']['remote_peers'])} peer(s) LDP remoto(s)",
            "confidence": "alta",
        })

    return roles


def _has_public_prefix_via_private_transit(
    parsed_data: dict, interfaces: list[dict]
) -> bool:
    """Verifica se há rota estática com next-hop privado e prefixo público."""
    connected = _build_connected_networks(interfaces)

    for route in parsed_data.get("static_routes", []):
        nh = route.get("next_hop", "")
        network = route.get("network", "")
        netmask = route.get("netmask", "")

        if not nh or not network or not netmask:
            continue

        # Check if next-hop is private
        try:
            nh_ip = ipaddress.ip_address(nh)
        except ValueError:
            continue

        if not nh_ip.is_private:
            continue

        # Check if any connected network contains this next-hop
        if not any(nh_ip in net for net in connected):
            continue

        # Check if destination is public — use _ip_str_to_network for correct parsing
        dest_net = _ip_str_to_network(f"{network} {netmask}")
        if dest_net and not dest_net.is_private:
            return True
    return False


# ── Interface documentation ─────────────────────────────────────────────


def _document_interface(iface: dict) -> dict:
    """Gera documentação estruturada para uma interface."""
    iface_type = iface.get("type", "unknown")
    name = iface.get("name", "?")
    desc = iface.get("description", "")
    ip = iface.get("ip_address")
    vlan_type = iface.get("vlan_type")
    vlan_id = iface.get("vlan_id")
    parent = iface.get("parent")
    shutdown = iface.get("shutdown", False)

    explanation = _explain_interface_type(iface_type, name, desc, vlan_id)

    return {
        "name": name,
        "type": iface_type,
        "type_display": _interface_type_display(iface_type),
        "description": desc if desc else None,
        "ip_address": ip,
        "vlan_type": vlan_type,
        "vlan_id": vlan_id,
        "parent": parent,
        "shutdown": shutdown,
        "explanation": explanation,
    }


def _explain_interface_type(iface_type: str, name: str, desc: str, vlan_id) -> str:
    """Gera explicação curta em português para uma interface."""
    if desc and vlan_id:
        return (
            f"Subinterface VLAN com tag {vlan_id} — \"{desc}\". "
            "Usada para transportar tráfego de um cliente ou serviço específico com isolamento 802.1Q."
        )
    if desc:
        return (
            f"Interface \"{desc}\". "
            + {
                "physical": "Interface física do equipamento.",
                "eth-trunk": "Agregação lógica de links físicos.",
                "port_channel": "Agregação lógica de links (EtherChannel).",
                "loopback": "Interface lógica do equipamento.",
                "vlanif": "Interface L3 de VLAN.",
                "subinterface": "Subinterface VLAN.",
                "physical_subinterface": "Subinterface física VLAN.",
                "null": "Interface nula (descartar tráfego).",
                "nve": "Interface NVE (VXLAN).",
            }.get(
                iface_type,
                "Interface do equipamento.",
            )
        )
    return {
        "physical": "Interface física do equipamento. Pode ser usada diretamente ou como membro de Eth-Trunk.",
        "eth-trunk": "Agregação lógica de links físicos, geralmente usada para uplink, transporte ou conexão com outro equipamento.",
        "port_channel": "Agregação lógica de links físicos (EtherChannel), usada para aumentar redundância e banda.",
        "loopback": "Interface lógica geralmente usada para identificação, roteamento, BGP/MPLS ou gerência.",
        "vlanif": "Interface L3 associada a uma VLAN.",
        "subinterface": "Subinterface VLAN usada para separar tráfego por tag 802.1Q.",
        "physical_subinterface": "Subinterface VLAN física usada para separar tráfego por tag 802.1Q.",
        "null": "Interface nula. Tráfego descartado. Usada para rotas de blackhole.",
        "nve": "Interface NVE (Network Virtualization Edge) para túneis VXLAN.",
    }.get(iface_type, "Interface do equipamento.")


def _interface_type_display(iface_type: str) -> str:
    """Retorna nome amigável do tipo de interface."""
    return {
        "physical": "Física",
        "eth-trunk": "Eth-Trunk (Agregação)",
        "port_channel": "Port-Channel (Agregação)",
        "loopback": "Loopback",
        "vlanif": "VLANIF",
        "subinterface": "Subinterface",
        "physical_subinterface": "Subinterface Física",
        "null": "Null",
        "nve": "NVE",
    }.get(iface_type, iface_type)


# ── Static route documentation ─────────────────────────────────────────


def _document_static_route(
    route: dict, connected_networks: list[ipaddress.IPv4Network]
) -> dict:
    """Gera documentação estruturada para uma rota estática."""
    network = route.get("network", "?")
    netmask = route.get("netmask", "?")
    next_hop = route.get("next_hop", "?")
    description = route.get("description", "")
    preference = route.get("preference", "60")
    tag = route.get("tag")

    # Build CIDR notation
    if netmask != "?":
        try:
            cidr = str(ipaddress.IPv4Network(f"{network} {netmask}", strict=False))
        except (ValueError, TypeError):
            cidr = f"{network}/{netmask}"
    else:
        cidr = f"{network}/{netmask}"

    # Check reachability
    next_hop_reachable = False
    try:
        nh_ip = ipaddress.ip_address(next_hop)
        next_hop_reachable = any(nh_ip in net for net in connected_networks)
    except ValueError:
        pass

    # Explanation
    if next_hop.upper() in ("NULL0", "NULL 0", "NULL"):
        explanation = (
            f"Rota de blackhole para {cidr}. "
            "Todo tráfego para este destino é descartado na própria interface NULL0."
        )
    elif next_hop_reachable:
        via_info = f"via {next_hop}"
        if description:
            via_info += f" ({description})"
        explanation = (
            f"Rota estática para {cidr} {via_info}. "
            "O next-hop está em uma rede diretamente conectada."
        )
    else:
        via_info = f"via {next_hop}"
        if description:
            via_info += f" ({description})"
        explanation = (
            f"Rota estática para {cidr} {via_info}. "
            "O next-hop NÃO está em uma rede diretamente conectada — "
            "pode estar inacessível ou depender de roteamento dinâmico."
        )

    result = {
        "destination": cidr,
        "network": network,
        "netmask": netmask,
        "next_hop": next_hop,
        "description": description if description else None,
        "preference": preference,
        "tag": tag,
        "next_hop_reachable": next_hop_reachable,
        "is_default": network == "0.0.0.0" and netmask == "0.0.0.0",
        "is_null0": next_hop.upper() in ("NULL0", "NULL 0", "NULL"),
        "explanation": explanation,
    }
    return result


# ── BGP documentation ──────────────────────────────────────────────────


def _document_bgp_block(bgp: dict) -> dict:
    """Gera documentação estruturada para um bloco BGP."""
    peers = []
    for peer in bgp.get("peers", []):
        peers.append(
            {
                "ip": peer.get("ip", "?"),
                "remote_as": peer.get("remote_as", "?"),
                "description": peer.get("description", "") or None,
            }
        )

    return {
        "as_number": bgp.get("as_number", "?"),
        "peer_count": len(peers),
        "network_count": len(bgp.get("networks", [])),
        "peers": peers,
        "networks": bgp.get("networks", []),
    }


# ── Circuit documentation ──────────────────────────────────────────────


def _document_circuit(circuit: DetectedCircuit) -> dict:
    """Gera documentação estruturada para um circuito detectado."""
    d = circuit.details
    circuit_type = circuit.circuit_type
    circuit_type_display = circuit.get_circuit_type_display()

    if circuit_type == DetectedCircuit.CircuitType.L3_TRANSIT:
        explanation = _explain_l3_transit(circuit)
    elif circuit_type == DetectedCircuit.CircuitType.VLAN_TRANSPORT:
        explanation = _explain_vlan_transport(circuit)
    elif circuit_type == DetectedCircuit.CircuitType.QINQ_TRANSPORT:
        explanation = _explain_qinq_transport(circuit)
    elif circuit_type == DetectedCircuit.CircuitType.L2VPN_VSI:
        explanation = _explain_l2vpn_vsi(circuit)
    else:
        explanation = f"Circuito do tipo {circuit_type_display} detectado."

    routed_prefix = d.get("routed_prefix")
    iface = d.get("interface")
    vlan_id = d.get("vlan_id")
    transit_network = d.get("transit_network")
    local_ip = d.get("local_ip")
    remote_ip = d.get("remote_ip")
    confidence = d.get("confidence", 0)
    rp_public = d.get("routed_prefix_is_public")
    metadata = d.get("metadata", {})

    # New fields for vlan_transport, qinq, l2vpn
    second_vlan_id = d.get("second_vlan_id")
    pe_vid = d.get("pe_vid")
    ce_vid = d.get("ce_vid")
    vsi_name = d.get("vsi_name")
    vsi_id = d.get("vsi_id")
    vsi_peers = d.get("vsi_peers", [])
    peer_count = d.get("peer_count", 0)
    parent_interface = d.get("parent_interface")

    return {
        "type": circuit_type,
        "type_display": circuit_type_display,
        "interface": iface,
        "vlan_id": vlan_id,
        "transit_network": transit_network,
        "local_ip": local_ip,
        "remote_ip": remote_ip,
        "routed_prefix": routed_prefix,
        "routed_prefix_is_public": rp_public,
        "confidence": confidence,
        "default_route_via_transit": metadata.get("default_route_via_transit", False),
        "description": circuit.description or None,
        "explanation": explanation,
        # New fields
        "second_vlan_id": second_vlan_id,
        "pe_vid": pe_vid,
        "ce_vid": ce_vid,
        "vsi_name": vsi_name,
        "vsi_id": vsi_id,
        "vsi_peers": vsi_peers,
        "peer_count": peer_count,
        "parent_interface": parent_interface,
    }


def _explain_l3_transit(circuit: DetectedCircuit) -> str:
    """Gera explicação em português para um circuito de trânsito L3."""
    d = circuit.details
    iface = d.get("interface", "?")
    vlan_id = d.get("vlan_id", "?")
    transit = d.get("transit_network", "?")
    local_ip = d.get("local_ip", "?")
    remote_ip = d.get("remote_ip", "?")
    routed_prefix = d.get("routed_prefix")
    confidence = d.get("confidence", 0)
    metadata = d.get("metadata", {})

    has_default = metadata.get("default_route_via_transit", False)
    is_public = d.get("routed_prefix_is_public")

    parts = [
        f"Este circuito parece ser uma entrega L3 usando uma VLAN de transporte.",
        f"A interface {iface} usa a VLAN {vlan_id} com IP de trânsito {transit}.",
        f"O IP local é {local_ip} e o next-hop remoto é {remote_ip}.",
    ]

    if routed_prefix:
        public_label = "público" if is_public else "privado"
        parts.append(
            f"O prefixo {routed_prefix} ({public_label}) está sendo roteado "
            f"para o equipamento remoto por cima desse trânsito."
        )

    if has_default:
        parts.append(
            "Uma rota default (0.0.0.0/0) também aponta para esta rede de trânsito."
        )

    parts.append(f"Confiança da detecção: {confidence:.0%}.")

    return " ".join(parts)


def _explain_vlan_transport(circuit: DetectedCircuit) -> str:
    """Gera explicação em português para transporte VLAN simples."""
    d = circuit.details
    iface = d.get("interface", "?")
    vlan_id = d.get("vlan_id", "?")
    desc = d.get("description", "")
    confidence = d.get("confidence", 0)

    parts = [
        f"Este circuito parece ser um transporte L2 simples por VLAN.",
        f"A subinterface {iface} usa a VLAN {vlan_id} sem endereço IP, "
        f"indicando que o equipamento provavelmente está apenas "
        f"transportando ou entregando essa VLAN para outro equipamento.",
    ]
    if desc:
        parts.append(f"Descrição: \"{desc}\".")
    parts.append(f"Confiança da detecção: {confidence:.0%}.")

    return " ".join(parts)


def _explain_qinq_transport(circuit: DetectedCircuit) -> str:
    """Gera explicação em português para transporte QinQ."""
    d = circuit.details
    iface = d.get("interface", "?")
    outer_vlan = d.get("vlan_id")
    inner_vlan = d.get("second_vlan_id")
    pe_vid = d.get("pe_vid")
    ce_vid = d.get("ce_vid")
    confidence = d.get("confidence", 0)

    parts = [
        f"Este circuito utiliza QinQ (dupla tag 802.1Q) na interface {iface}."
    ]
    if outer_vlan and inner_vlan:
        parts.append(
            f"VLAN externa (service): {outer_vlan}, "
            f"VLAN interna (customer): {inner_vlan}."
        )
    elif pe_vid and ce_vid:
        parts.append(
            f"PE-VID (externa): {pe_vid}, CE-VID (interna): {ce_vid}."
        )
    parts.append(
        "QinQ permite multiplexar múltiplos clientes sobre uma mesma "
        "interface física, preservando as VLANs do cliente."
    )
    parts.append(f"Confiança da detecção: {confidence:.0%}.")

    return " ".join(parts)


def _explain_l2vpn_vsi(circuit: DetectedCircuit) -> str:
    """Gera explicação em português para L2VPN com VSI."""
    d = circuit.details
    iface = d.get("interface")
    vsi_name = d.get("vsi_name", "?")
    vsi_id = d.get("vsi_id")
    peers = d.get("vsi_peers", [])
    vlan_id = d.get("vlan_id")
    confidence = d.get("confidence", 0)

    parts = [
        f"Este circuito utiliza L2VPN/VSI para transporte de camada 2 "
        f"através da rede MPLS/VPLS."
    ]
    if iface:
        parts.append(f"Interface associada: {iface}.")
    parts.append(f"VSI: {vsi_name}.")
    if vsi_id:
        parts.append(f"VSI-ID: {vsi_id}.")
    if vlan_id:
        parts.append(f"VLAN associada: {vlan_id}.")
    if peers:
        parts.append(f"{len(peers)} peer(s): {', '.join(peers)}.")
    parts.append(f"Confiança da detecção: {confidence:.0%}.")

    return " ".join(parts)


# ── Logical map ────────────────────────────────────────────────────────


def _build_logical_map(
    sysname: str,
    interfaces: list[dict],
    static_routes: list[dict],
    bgp_blocks: list[dict],
    circuits: list[DetectedCircuit],
) -> str:
    """Gera um mapa lógico textual do equipamento."""
    lines: list[str] = []
    name = sysname or "Equipamento"
    lines.append(f"Equipamento: {name}")

    # Group subinterfaces by parent
    parents: dict[str, list[dict]] = {}
    standalone: list[dict] = []

    for iface in interfaces:
        parent = iface.get("parent")
        if parent:
            parents.setdefault(parent, []).append(iface)
        else:
            standalone.append(iface)

    # Build a set of known parents (interfaces that have subinterfaces)
    # Also include Eth-Trunks and physical interfaces that exist in standalone
    parent_set = set(parents.keys())
    standalone_names = {i["name"] for i in standalone}

    # Show root-level interfaces first (Eth-Trunks, physical interfaces)
    for iface in standalone:
        iface_name = iface["name"]
        iface_desc = iface.get("description", "")
        ip = iface.get("ip_address", "")
        iface_type = iface.get("type", "")

        # Skip subinterfaces in standalone list (they should have parent)
        if "." in iface_name and iface_type not in ("eth-trunk",):
            continue

        label = iface_name
        if ip:
            label += f" | {ip}"
        if iface_desc:
            label += f" | {iface_desc}"

        lines.append(f"├── {label}")

        # Show children (subinterfaces)
        children = parents.get(iface_name, [])
        for child in children:
            child_name = child["name"]
            child_desc = child.get("description", "")
            child_ip = child.get("ip_address", "")
            child_vlan = child.get("vlan_id")

            clabel = child_name
            if child_vlan:
                clabel += f" | VLAN {child_vlan}"
            if child_ip:
                clabel += f" | {child_ip}"
            if child_desc:
                clabel += f" | {child_desc}"

            lines.append(f"│   ├── {clabel}")

            # Show routes that belong to this subinterface (from circuits)
            child_routes = _find_routes_for_subinterface(
                child_name, static_routes, circuits
            )
            for r in child_routes:
                lines.append(f"│   │   └── Rota: {r}")

        # Show orphan subinterfaces (subinterfaces whose parent is not in config)
        # Subinterfaces whose parent doesn't exist as a standalone interface
        # e.g., Eth-Trunk100.1234 where Eth-Trunk100 exists

    # Show subinterfaces whose parent is not a known interface
    for parent_name, children in parents.items():
        if parent_name in standalone_names:
            continue
        lines.append(f"├── {parent_name} (interface pai não listada)")
        for child in children:
            child_name = child["name"]
            child_vlan = child.get("vlan_id")
            child_ip = child.get("ip_address", "")
            clabel = f"│   └── {child_name}"
            if child_vlan:
                clabel += f" | VLAN {child_vlan}"
            if child_ip:
                clabel += f" | {child_ip}"
            lines.append(clabel)

            # Show routes that belong to this orphan subinterface
            child_routes = _find_routes_for_subinterface(
                child_name, static_routes, circuits
            )
            for r in child_routes:
                lines.append(f"│       └── Rota: {r}")

    # Show BGP blocks
    for bgp in bgp_blocks:
        as_number = bgp.get("as_number", "?")
        lines.append(f"├── BGP AS {as_number}")
        for peer in bgp.get("peers", []):
            peer_ip = peer.get("ip", "?")
            peer_as = peer.get("remote_as", "?")
            peer_desc = peer.get("description", "")
            plabel = f"│   └── Peer {peer_ip} AS {peer_as}"
            if peer_desc:
                plabel += f" ({peer_desc})"
            lines.append(plabel)

    # Show VSI / L2VPN info from circuits
    vsi_seen: set[str] = set()
    for circuit in circuits:
        d = circuit.details
        if circuit.circuit_type != "l2vpn_vsi":
            continue
        vsi_name = d.get("vsi_name")
        if not vsi_name or vsi_name in vsi_seen:
            continue
        vsi_seen.add(vsi_name)
        vsi_id = d.get("vsi_id")
        peers = d.get("vsi_peers", [])
        label = f"├── VSI {vsi_name}"
        if vsi_id:
            label += f" | ID {vsi_id}"
        lines.append(label)
        for peer in peers:
            lines.append(f"│   └── Peer: {peer}")
        # Show binding interfaces
        binding_ifaces = [
            c2.details.get("interface")
            for c2 in circuits
            if c2.details.get("vsi_name") == vsi_name
            and c2.details.get("interface")
        ]
        for b_iface in binding_ifaces:
            lines.append(f"│   └── Binding: {b_iface}")

    # Add footer
    if lines:
        # Replace last ├── with └── for proper tree ending
        if len(lines) > 1:
            last_line = lines[-1]
            if last_line.startswith("├──"):
                lines[-1] = "└──" + last_line[3:]
            elif last_line.startswith("│"):
                lines[-1] = " " + last_line[1:]
                lines[-1] = "└──" + lines[-1][3:] if lines[-1].startswith("├──") else lines[-1]

    return "\n".join(lines)


def _find_routes_for_subinterface(
    iface_name: str, static_routes: list[dict], circuits: list[DetectedCircuit]
) -> list[str]:
    """Encontra rotas associadas a uma subinterface via circuitos detectados."""
    result: list[str] = []

    for circuit in circuits:
        d = circuit.details
        if d.get("interface") != iface_name:
            continue
        route_prefix = d.get("routed_prefix")
        remote_ip = d.get("remote_ip", "?")
        if route_prefix:
            result.append(f"{route_prefix} via {remote_ip}")
        else:
            # Default route
            result.append(f"0.0.0.0/0 via {remote_ip} (default)")

    return result


# ── Service documentation ─────────────────────────────────────────────


def _document_service(svc) -> dict:
    """Gera documentação estruturada para um serviço detectado."""
    return {
        "service_type": svc.service_type,
        "service_type_display": svc.get_service_type_display(),
        "name": svc.name or "",
        "description": svc.description or "",
        "confidence": svc.confidence,
        "metadata": svc.metadata,
    }


# ── Recommendations ────────────────────────────────────────────────────


def _generate_recommendations(
    issues: list[AnalysisIssue],
    interfaces: list[dict],
    static_routes: list[dict],
) -> list[dict]:
    """Gera recomendações operacionais baseadas em issues e dados detectados."""
    recs: list[dict] = []
    seen_codes: set[str] = set()

    # Recommendations based on existing issues
    issue_codes = {i.code for i in issues}

    if "interface_missing_description" in issue_codes:
        recs.append(
            {
                "recommendation": "Adicionar descrição (description) em interfaces físicas sem identificação.",
                "rationale": "Descriptions facilitam troubleshooting e identificação de circuitos.",
                "severity": "info",
            }
        )

    if "subinterface_missing_description" in issue_codes:
        recs.append(
            {
                "recommendation": "Adicionar descrição em subinterfaces dot1q sem identificação.",
                "rationale": "Subinterfaces sem description dificultam identificar o cliente/circuito associado.",
                "severity": "warning",
            }
        )

    if "static_route_missing_description" in issue_codes:
        recs.append(
            {
                "recommendation": "Adicionar descrição em rotas estáticas de cliente ou transporte.",
                "rationale": "Rotas sem descrição dificultam auditoria e troubleshooting.",
                "severity": "warning",
            }
        )

    if "static_route_unreachable_next_hop" in issue_codes:
        recs.append(
            {
                "recommendation": "Validar reachability dos next-hops apontados em rotas estáticas.",
                "rationale": "Next-hops inalcançáveis indicam rotas mortas que podem causar queda de serviço.",
                "severity": "critical",
            }
        )

    if "bgp_peer_missing_description" in issue_codes:
        recs.append(
            {
                "recommendation": "Adicionar descrição nos peers BGP.",
                "rationale": "Peers BGP sem descrição dificultam identificar o vizinho e o contrato.",
                "severity": "warning",
            }
        )

    # Proactive recommendations (not dependent on issues)
    recs.append(
        {
            "recommendation": "Documentar VLANs e circuitos com padrão de nomenclatura consistente.",
            "rationale": "Padrões de nomenclatura como CLIENTE-TIPO-REDE facilitam a operação diária.",
            "severity": "info",
        }
    )

    recs.append(
        {
            "recommendation": "Criar snapshot antes e depois de alterações de configuração.",
            "rationale": "Snapshots permitem comparar mudanças e agilizar rollback.",
            "severity": "info",
        }
    )

    # Check if there are BGP peers
    has_bgp = any("bgp" in str(i.metadata) or "peer" in str(i.metadata) for i in issues)
    # Alternative: check from the caller context

    return recs


# ── Utilities ──────────────────────────────────────────────────────────


def _build_connected_networks(
    interfaces: list[dict],
) -> list[ipaddress.IPv4Network]:
    """Build a list of all directly connected networks from interfaces."""
    networks: list[ipaddress.IPv4Network] = []
    for iface in interfaces:
        ip_str = iface.get("ip_address")
        if not ip_str:
            continue
        network = _ip_str_to_network(ip_str)
        if network:
            networks.append(network)
    return networks


def _ip_str_to_network(ip_str: str) -> ipaddress.IPv4Network | None:
    """Convert ip address string to IPv4Network."""
    ip_str = ip_str.strip()
    if "/" in ip_str:
        try:
            return ipaddress.IPv4Network(ip_str, strict=False)
        except ValueError:
            return None
    parts = ip_str.split()
    if len(parts) == 2:
        try:
            addr = ipaddress.IPv4Address(parts[0])
            netmask = ipaddress.IPv4Address(parts[1])
            prefix = bin(int(netmask)).count("1")
            return ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
        except ValueError:
            return None
    return None


# ── Policy documentation ────────────────────────────────────────────────


def _build_policy_documentation(parsed_data: dict) -> dict | None:
    """Gera documentacao estruturada para politicas de roteamento e filtros.

    Returns dict with keys: ip_prefixes, route_policies, acls, dependencies, orphans
    or None if no policy data found.
    """
    route_policies = parsed_data.get("route_policies", [])
    prefix_lists = parsed_data.get("prefix_lists", [])
    acls = parsed_data.get("acls", [])

    if not (route_policies or prefix_lists or acls):
        return None

    data: dict = {"summary": "", "sections": []}
    parts = []

    # IP Prefixes
    if prefix_lists:
        ip_entries = []
        for pp in prefix_lists:
            ip_entries.append({
                "name": pp["name"],
                "rules": [
                    {
                        "index": r.get("index"),
                        "action": r.get("action"),
                        "prefix": f"{r.get('prefix', '?')}/{r.get('mask_length', '?')}",
                        "ge": r.get("greater_equal"),
                        "le": r.get("less_equal"),
                        "raw": r.get("raw"),
                    }
                    for r in pp.get("rules", [])
                ],
            })
        data["ip_prefixes"] = ip_entries
        parts.append(f"{len(prefix_lists)} ip-prefix lists")

    # Route Policies
    if route_policies:
        rp_entries = []
        by_name: dict = {}
        for rp in route_policies:
            by_name.setdefault(rp["name"], []).append(rp)
        for name, nodes in by_name.items():
            rp_entries.append({
                "name": name,
                "nodes": [
                    {
                        "node": n.get("node"),
                        "action": n.get("action"),
                        "if_match": n.get("if_match", []),
                        "apply": n.get("apply", []),
                    }
                    for n in sorted(nodes, key=lambda x: x.get("node", 0))
                ],
            })
        data["route_policies"] = rp_entries
        parts.append(f"{len(route_policies)} route-policy nodes")

    # AS-path filters
    as_path_filters = parsed_data.get("as_path_filters", [])
    if as_path_filters:
        data["as_path_filters"] = [
            {
                "name": af["name"],
                "rules": [{"action": r.get("action"), "pattern": r.get("pattern"), "raw": r.get("raw")} for r in af.get("rules", [])],
            }
            for af in as_path_filters
        ]
        parts.append(f"{len(as_path_filters)} as-path filter(s)")

    # Community filters
    community_filters = parsed_data.get("community_filters", [])
    if community_filters:
        data["community_filters"] = [
            {
                "name": cf["name"],
                "type": cf.get("type", "basic"),
                "rules": [{"action": r.get("action"), "value": r.get("value"), "raw": r.get("raw"), "index": r.get("index")} for r in cf.get("rules", [])],
            }
            for cf in community_filters
        ]
        parts.append(f"{len(community_filters)} community filter(s)")

    # ACLs
    if acls:
        acl_entries = []
        for acl in acls:
            acl_entries.append({
                "name": acl.get("name"),
                "type": acl.get("type"),
                "rules": [
                    {
                        "action": r.get("action"),
                        "source": r.get("source"),
                        "destination": r.get("destination"),
                        "protocol": r.get("protocol"),
                        "raw": r.get("raw"),
                    }
                    for r in acl.get("rules", [])
                ],
            })
        data["acls"] = acl_entries
        parts.append(f"{len(acls)} ACL(s)")

    # Dependencies
    from apps.analysis.policy_utils import build_policy_reference_map
    ref_map = build_policy_reference_map(parsed_data)
    if ref_map.get("bgp_peer_policies"):
        deps = []
        for bpp in ref_map["bgp_peer_policies"]:
            deps.append({
                "peer": bpp["peer"],
                "direction": bpp["direction"],
                "route_policy": bpp["route_policy"],
                "found": bpp.get("found", True),
                "dependencies": bpp.get("dependencies", {}),
            })
        data["dependencies"] = deps

    # Orphans
    if ref_map.get("orphan_route_policies") or ref_map.get("orphan_ip_prefixes") or ref_map.get("orphan_as_path_filters") or ref_map.get("orphan_community_filters"):
        data["orphans"] = {
            "route_policies": ref_map.get("orphan_route_policies", []),
            "ip_prefixes": ref_map.get("orphan_ip_prefixes", []),
            "as_path_filters": ref_map.get("orphan_as_path_filters", []),
            "community_filters": ref_map.get("orphan_community_filters", []),
        }

    data["summary"] = ", ".join(parts)
    return data


# ── Management documentation ────────────────────────────────────────────


def _document_snmp(parsed_data: dict) -> dict | None:
    """Gera documentação estruturada para SNMP."""
    snmp = parsed_data.get("snmp", {})
    if not snmp.get("enabled"):
        return None

    versions = snmp.get("versions", [])
    communities = snmp.get("communities", [])
    trap_hosts = snmp.get("trap_hosts", [])
    users = snmp.get("users", [])
    groups = snmp.get("groups", [])
    acl_refs = snmp.get("acl_refs", [])

    parts = ["SNMP foi detectado neste equipamento."]
    if versions:
        parts.append(f"Versões habilitadas: {', '.join(versions)}.")
    read_count = sum(1 for c in communities if c.get("access") == "read")
    write_count = sum(1 for c in communities if c.get("access") == "write")
    if communities:
        parts.append(f"{read_count} comunidade(s) de leitura e {write_count} de escrita configuradas.")
    if trap_hosts:
        ips = [t.get("ip", "?") for t in trap_hosts]
        parts.append(f"{len(trap_hosts)} servidor(es) de trap: {', '.join(ips)}.")
    if users:
        parts.append(f"{len(users)} usuário(s) SNMPv3 configurado(s).")
    if acl_refs:
        parts.append(f"Acesso restrito por ACL(s): {', '.join(acl_refs)}.")
    else:
        parts.append("ATENÇÃO: Nenhuma ACL de restrição detectada.")

    return {
        "enabled": True,
        "versions": versions,
        "community_count": len(communities),
        "read_community_count": read_count,
        "write_community_count": write_count,
        "trap_host_count": len(trap_hosts),
        "trap_hosts": [t.get("ip") for t in trap_hosts],
        "user_count": len(users),
        "group_count": len(groups),
        "has_acl": bool(acl_refs),
        "acl_refs": acl_refs,
        "explanation": " ".join(parts),
    }


def _document_ntp(parsed_data: dict) -> dict | None:
    """Gera documentação estruturada para NTP."""
    ntp = parsed_data.get("ntp", {})
    if not ntp.get("enabled"):
        return None

    servers = ntp.get("servers", [])
    source_iface = ntp.get("source_interface")
    auth_enabled = ntp.get("authentication_enabled", False)

    parts = ["NTP foi detectado neste equipamento."]
    if servers:
        ips = [s.get("ip") for s in servers if s.get("ip")]
        prefer = []
        for s in servers:
            if s.get("preference") and s.get("ip"):
                prefer.append(s["ip"])
        parts.append(f"Servidor(es): {', '.join(ips)}.")
        if prefer:
            parts.append(f"Preferência: {', '.join(prefer)}.")
    else:
        parts.append("NTP habilitado mas sem servidores configurados.")
    if source_iface:
        parts.append(f"Interface de origem: {source_iface}.")
    parts.append("Autenticação: " + ("ativada." if auth_enabled else "não configurada."))

    return {
        "enabled": True,
        "server_count": len(servers),
        "servers": [s.get("ip") for s in servers if s.get("ip")],
        "source_interface": source_iface,
        "authentication_enabled": auth_enabled,
        "explanation": " ".join(parts),
    }


def _document_syslog(parsed_data: dict) -> dict | None:
    """Gera documentação estruturada para Syslog/info-center."""
    syslog = parsed_data.get("syslog", {})
    if not syslog.get("enabled"):
        return None

    log_hosts = syslog.get("log_hosts", [])
    facilities = syslog.get("facilities", [])

    parts = ["Info-center/Syslog foi detectado neste equipamento."]
    if log_hosts:
        ips = [h.get("ip") for h in log_hosts if h.get("ip")]
        parts.append(f"Log host(s): {', '.join(ips)}.")
        if facilities:
            parts.append(f"Facilities: {', '.join(facilities)}.")
    else:
        parts.append("ATENÇÃO: Nenhum loghost remoto configurado.")

    return {
        "enabled": True,
        "log_host_count": len(log_hosts),
        "log_hosts": [h.get("ip") for h in log_hosts if h.get("ip")],
        "facilities": facilities,
        "explanation": " ".join(parts),
    }


def _document_management_access(parsed_data: dict) -> dict | None:
    """Gera documentação estruturada para acesso administrativo."""
    vty_lines = parsed_data.get("vty_lines", [])
    ssh_data = parsed_data.get("ssh", {})
    ma = parsed_data.get("management_access", {})

    if not vty_lines and not ssh_data.get("enabled"):
        return None

    parts = ["Acesso administrativo configurado via VTY."]
    if vty_lines:
        for vty in vty_lines:
            proto = vty.get("protocol_inbound", "não especificado")
            auth = vty.get("authentication_mode", "não especificado")
            acl = vty.get("acl_inbound", "nenhuma")
            timeout = vty.get("idle_timeout", "não configurado")
            parts.append(f"Protocolo: {proto}. Autenticação: {auth}. ACL: {acl}. Timeout: {timeout}.")
    if ssh_data.get("enabled"):
        parts.append("SSH/Stelnet habilitado.")
        if ssh_data.get("users"):
            parts.append(f"{len(ssh_data['users'])} usuário(s) SSH configurado(s).")

    return {
        "enabled": True,
        "vty_count": len(vty_lines),
        "vty_lines": vty_lines,
        "ssh_enabled": ssh_data.get("enabled", False),
        "ssh_user_count": len(ssh_data.get("users", [])),
        "explanation": " ".join(parts),
    }


def _document_local_users(parsed_data: dict) -> list[dict]:
    """Gera documentação estruturada para usuários locais."""
    users = parsed_data.get("local_users", [])
    if not users:
        return []

    doc_users = []
    for user in users:
        doc_users.append({
            "name": user.get("name"),
            "privilege_level": user.get("privilege_level"),
            "has_password": user.get("has_password", False),
            "service_types": user.get("service_types", []),
        })

    return doc_users


# ── Core documentation (ISIS/MPLS/LDP) ─────────────────────────────────


def _build_core_documentation(parsed_data: dict) -> dict:
    isis_blocks = parsed_data.get("isis", [])
    mpls_data = parsed_data.get("mpls", {})
    mpls_ldp_data = parsed_data.get("mpls_ldp", {})
    interfaces = parsed_data.get("interfaces", [])

    isis_docs = []
    for isis in isis_blocks:
        isis_docs.append({
            "process_id": isis.get("process_id"),
            "network_entity": isis.get("network_entity"),
            "is_level": isis.get("is_level"),
            "cost_style": isis.get("cost_style"),
            "import_routes": isis.get("import_routes", []),
            "vpn_instance": isis.get("vpn_instance"),
        })

    isis_interfaces = []
    for iface in interfaces:
        if iface.get("isis_enabled"):
            isis_interfaces.append({
                "name": iface.get("name"),
                "isis_process_id": iface.get("isis_process_id"),
                "isis_circuit_type": iface.get("isis_circuit_type"),
                "isis_cost": iface.get("isis_cost"),
            })

    mpls_interfaces = []
    for iface in interfaces:
        if iface.get("mpls_enabled"):
            mpls_interfaces.append({
                "name": iface.get("name"),
            })

    ldp_interfaces = []
    for iface in interfaces:
        if iface.get("mpls_ldp_enabled"):
            ldp_interfaces.append({
                "name": iface.get("name"),
            })

    return {
        "isis": isis_docs,
        "isis_interfaces": isis_interfaces,
        "mpls": {
            "enabled": mpls_data.get("enabled", False),
            "lsr_id": mpls_data.get("lsr_id"),
            "te_enabled": mpls_data.get("te_enabled", False),
        },
        "mpls_ldp": {
            "enabled": mpls_ldp_data.get("enabled", False),
            "graceful_restart": mpls_ldp_data.get("graceful_restart", False),
            "remote_peers": mpls_ldp_data.get("remote_peers", []),
        },
        "mpls_interfaces": mpls_interfaces,
        "ldp_interfaces": ldp_interfaces,
        "has_isis": len(isis_blocks) > 0,
        "has_mpls": mpls_data.get("enabled", False),
        "has_mpls_ldp": mpls_ldp_data.get("enabled", False),
    }


def _document_core(parsed_data: dict) -> dict | None:
    core = _build_core_documentation(parsed_data)
    if not any([core["has_isis"], core["has_mpls"], core["has_mpls_ldp"]]):
        return None

    parts = []
    if core["has_isis"]:
        proc_ids = [p.get("process_id", "?") for p in core["isis"]]
        parts.append(f"ISIS detectado: {', '.join(str(p) for p in proc_ids)} processo(s).")
    if core["has_mpls"]:
        lsr = core["mpls"].get("lsr_id", "")
        te = "com TE" if core["mpls"].get("te_enabled") else "sem TE"
        parts.append(f"MPLS habilitado (LSR-ID: {lsr or 'N/A'}, {te}).")
    if core["has_mpls_ldp"]:
        peers = core["mpls_ldp"].get("remote_peers", [])
        gr = "com graceful restart" if core["mpls_ldp"].get("graceful_restart") else "sem graceful restart"
        parts.append(f"LDP detectado ({gr}, {len(peers)} peer(s) remoto(s)).")

    return {
        **core,
        "explanation": " ".join(parts),
    }


    parts = ip_str.split()
    if len(parts) == 2:
        try:
            addr = ipaddress.IPv4Address(parts[0])
            netmask = ipaddress.IPv4Address(parts[1])
            prefix = bin(int(netmask)).count("1")
            return ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
        except ValueError:
            return None
    return None
