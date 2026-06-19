"""Detector de problemas/riscos em configurações parseadas.

Cria objetos AnalysisIssue para:
    - Interface sem description
    - Subinterface dot1q sem description
    - Rota estática sem description
    - Peer BGP sem description (se o parser identificar)
    - Rota estática com next-hop inalcançável
"""

from __future__ import annotations

import ipaddress

from apps.analysis.models import AnalysisIssue
from apps.analysis.policy_utils import find_policy_issues
from apps.analysis.policy_utils import find_policy_issues

# Severity mapping: simplify reuse
SEVERITY_LOW = AnalysisIssue.Severity.INFO
SEVERITY_MEDIUM = AnalysisIssue.Severity.WARNING
SEVERITY_HIGH = AnalysisIssue.Severity.CRITICAL


def detect_issues(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Detecta todos os issues conhecidos nos dados parseados.

    Args:
        snapshot: Instância de ConfigSnapshot.
        parsed_data: Dicionário retornado pelo parser.

    Returns:
        Lista de objetos AnalysisIssue criados (já salvos).
    """
    issues: list[AnalysisIssue] = []

    # Collect connected networks for unreachable next-hop detection
    connected_networks = _build_connected_networks(parsed_data)

    issues.extend(_detect_interface_no_description(snapshot, parsed_data))
    issues.extend(_detect_subinterface_no_description(snapshot, parsed_data))
    issues.extend(_detect_static_route_no_description(snapshot, parsed_data))
    issues.extend(_detect_bgp_peer_no_description(snapshot, parsed_data))
    issues.extend(
        _detect_unreachable_next_hop(snapshot, parsed_data, connected_networks)
    )

    # Management security issues
    issues.extend(_detect_snmp_v2c(snapshot, parsed_data))
    issues.extend(_detect_snmp_write_community(snapshot, parsed_data))
    issues.extend(_detect_snmp_without_acl(snapshot, parsed_data))
    issues.extend(_detect_ntp_without_auth(snapshot, parsed_data))
    issues.extend(_detect_syslog_without_loghost(snapshot, parsed_data))
    issues.extend(_detect_telnet_enabled(snapshot, parsed_data))
    issues.extend(_detect_vty_without_acl(snapshot, parsed_data))
    issues.extend(_detect_local_user_high_privilege(snapshot, parsed_data))
    issues.extend(_detect_management_acl_not_found(snapshot, parsed_data))
    # L2 switching issues
    issues.extend(_detect_l2_trunk_allow_all(snapshot, parsed_data))
    issues.extend(_detect_l2_port_missing_desc(snapshot, parsed_data))
    issues.extend(_detect_l2_stp_disabled_trunk(snapshot, parsed_data))
    issues.extend(_detect_l2_edge_port_trunk(snapshot, parsed_data))
    issues.extend(_detect_l2_vlan_used_not_defined(snapshot, parsed_data))
    issues.extend(_detect_l2_vlan_defined_unused(snapshot, parsed_data))

    # Policy/routing filter issues
    issues.extend(_detect_policy_issues(snapshot, parsed_data))

    # OSPF issues
    issues.extend(_detect_ospf_no_router_id(snapshot, parsed_data))
    issues.extend(_detect_ospf_passive_missing(snapshot, parsed_data))
    issues.extend(_detect_ospf_redistribution_without_filter(snapshot, parsed_data))

    return issues


def _detect_policy_issues(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Policy/routing filter issues from find_policy_issues()."""
    issues = []
    raw_issues = find_policy_issues(parsed_data)
    severity_map = {
        "high": AnalysisIssue.Severity.CRITICAL,
        "medium": AnalysisIssue.Severity.WARNING,
        "low": AnalysisIssue.Severity.INFO,
    }
    for ri in raw_issues:
        issues.append(
            _make_issue(
                snapshot,
                severity_map.get(ri.get("severity", "low"), AnalysisIssue.Severity.INFO),
                ri.get("code", "unknown"),
                ri.get("title", ""),
                ri.get("description", ""),
                metadata=ri.get("metadata", {}),
            )
        )
    # Also detect BGP route-policy not found
    from apps.analysis.policy_utils import build_policy_reference_map
    ref_map = build_policy_reference_map(parsed_data)
    for bpp in ref_map.get("bgp_peer_policies", []):
        if not bpp.get("found"):
            issues.append(
                _make_issue(
                    snapshot,
                    AnalysisIssue.Severity.CRITICAL,
                    "bgp_route_policy_not_found",
                    f"Route-policy referencia não encontrada",
                    f"Peer BGP {bpp['peer']} referencia route-policy {bpp['route_policy']} "
                    f"no sentido {bpp['direction']}, mas ela n\u00e3o foi localizada na configura\u00e7\u00e3o.",
                    metadata={
                        "peer_ip": bpp["peer"],
                        "direction": bpp["direction"],
                        "route_policy": bpp["route_policy"],
                    },
                )
            )
    return issues


def _detect_policy_issues(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Policy/routing filter issues from find_policy_issues()."""
    issues = []
    raw_issues = find_policy_issues(parsed_data)
    severity_map = {
        "high": AnalysisIssue.Severity.CRITICAL,
        "medium": AnalysisIssue.Severity.WARNING,
        "low": AnalysisIssue.Severity.INFO,
    }
    for ri in raw_issues:
        issues.append(
            _make_issue(
                snapshot,
                severity_map.get(ri.get("severity", "low"), AnalysisIssue.Severity.INFO),
                ri.get("code", "unknown"),
                ri.get("title", ""),
                ri.get("description", ""),
                metadata=ri.get("metadata", {}),
            )
        )
    # Also detect BGP route-policy not found
    from apps.analysis.policy_utils import build_policy_reference_map
    ref_map = build_policy_reference_map(parsed_data)
    for bpp in ref_map.get("bgp_peer_policies", []):
        if not bpp.get("found"):
            issues.append(
                _make_issue(
                    snapshot,
                    AnalysisIssue.Severity.CRITICAL,
                    "bgp_route_policy_not_found",
                    f"Route-policy referencia não encontrada",
                    f"Peer BGP {bpp['peer']} referencia route-policy {bpp['route_policy']} "
                    f"no sentido {bpp['direction']}, mas ela n\u00e3o foi localizada na configura\u00e7\u00e3o.",
                    metadata={
                        "peer_ip": bpp["peer"],
                        "direction": bpp["direction"],
                        "route_policy": bpp["route_policy"],
                    },
                )
            )
    return issues


def _build_connected_networks(parsed_data: dict) -> list[ipaddress.IPv4Network]:
    """Build a list of all directly connected networks from interfaces."""
    networks = []
    for iface in parsed_data.get("interfaces", []):
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


def _make_issue(
    snapshot,
    severity: str,
    code: str,
    title: str,
    description: str,
    metadata: dict | None = None,
) -> AnalysisIssue:
    """Helper to create and save an AnalysisIssue."""
    issue = AnalysisIssue(
        snapshot=snapshot,
        severity=severity,
        code=code,
        title=title,
        description=description,
        metadata=metadata or {},
    )
    issue.save()
    return issue


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


def _detect_interface_no_description(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Interfaces (físicas e Eth-Trunk) sem description."""
    issues = []
    skipped_types = {"loopback", "null", "nve", "vlanif"}

    for iface in parsed_data.get("interfaces", []):
        iface_type = iface.get("type", "")
        if iface_type in skipped_types:
            continue

        # Skip subinterfaces (handled by _detect_subinterface_no_description)
        if iface.get("subinterface_number") is not None:
            continue

        desc = iface.get("description", "")
        if desc.strip():
            continue

        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_LOW,
                "interface_missing_description",
                f"Interface sem descrição: {iface['name']}",
                f"A interface {iface['name']} não possui descrição configurada. "
                f"Recomenda-se adicionar uma descrição para facilitar o troubleshooting.",
                metadata={
                    "interface": iface["name"],
                    "type": iface_type,
                },
            )
        )

    return issues


def _detect_subinterface_no_description(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Subinterfaces dot1q sem description."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("vlan_type") != "dot1q":
            continue
        desc = iface.get("description", "")
        if desc.strip():
            continue

        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_MEDIUM,
                "subinterface_missing_description",
                f"Subinterface dot1q sem descrição: {iface['name']}",
                f"A subinterface {iface['name']} (VLAN {iface.get('vlan_id', '?')}) "
                f"não possui descrição. Isso dificulta a identificação do circuito associado.",
                metadata={
                    "interface": iface["name"],
                    "vlan_id": iface.get("vlan_id"),
                },
            )
        )

    return issues


def _detect_static_route_no_description(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Rotas estáticas sem description.

    Nota: Cisco IOS não suporta nativamente 'description' em 'ip route'.
    Para evitar falso positivo, este detector é ignorado para vendor cisco.
    """
    vendor = parsed_data.get("vendor", "")
    if vendor == "cisco":
        return []

    issues = []
    for route in parsed_data.get("static_routes", []):
        # Skip default route (0.0.0.0/0) — usually doesn't need description
        if route.get("network") == "0.0.0.0" and route.get("netmask") == "0.0.0.0":
            continue

        desc = route.get("description")
        if desc and desc.strip():
            continue

        dest = f"{route.get('network', '?')}/{route.get('netmask', '?')}"
        nh = route.get("next_hop", "?")
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_MEDIUM,
                "static_route_missing_description",
                f"Rota estática sem descrição: {dest}",
                f"A rota estática {dest} via {nh} não possui descrição. "
                f"Recomenda-se documentar o motivo/contrato da rota.",
                metadata={
                    "destination": dest,
                    "next_hop": nh,
                    "raw": route.get("raw", ""),
                },
            )
        )

    return issues


def _detect_bgp_peer_no_description(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Peers BGP sem description."""
    issues = []
    for bgp_block in parsed_data.get("bgp", []):
        as_number = bgp_block.get("as_number", "?")
        for peer in bgp_block.get("peers", []):
            desc = peer.get("description", "")
            if desc.strip():
                continue
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "bgp_peer_missing_description",
                    f"Peer BGP sem descrição: {peer.get('ip', '?')}",
                    f"O peer BGP {peer.get('ip', '?')} (AS {peer.get('remote_as', '?')}) "
                    f"no AS {as_number} não possui descrição.",
                    metadata={
                        "peer_ip": peer.get("ip"),
                        "remote_as": peer.get("remote_as"),
                        "local_as": as_number,
                    },
                )
            )
    return issues


def _detect_unreachable_next_hop(
    snapshot, parsed_data: dict, connected_networks: list[ipaddress.IPv4Network]
) -> list[AnalysisIssue]:
    """Rotas estáticas com next-hop que não está em nenhuma rede conectada.

    Isso indica que a rota pode estar morta (next-hop inalcançável),
    a menos que haja roteamento dinâmico aprendendo o caminho.
    """
    issues = []

    for route in parsed_data.get("static_routes", []):
        nh = route.get("next_hop")
        if not nh:
            continue

        # Skip NULL0 / interface-based routes
        if nh.upper() in ("NULL0", "NULL 0", "NULL"):
            continue
        # Skip if it looks like an interface name
        if not _looks_like_ip(nh):
            continue

        try:
            nh_ip = ipaddress.ip_address(nh)
        except ValueError:
            continue

        # Check if next-hop falls within any connected network
        reachable = any(nh_ip in net for net in connected_networks)

        if not reachable:
            dest = f"{route.get('network', '?')}/{route.get('netmask', '?')}"
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "static_route_unreachable_next_hop",
                    f"Next-hop inalcançável: {nh}",
                    f"A rota estática {dest} via {nh} tem next-hop que não pertence "
                    f"a nenhuma rede diretamente conectada. Pode indicar rota morta "
                    f"ou necessidade de roteamento dinâmico.",
                    metadata={
                        "destination": dest,
                        "next_hop": nh,
                        "raw": route.get("raw", ""),
                    },
                )
            )

    return issues


# ── Management security issue detectors ───────────────────────────────


def _detect_snmp_v2c(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """SNMP v2c habilitado — risco de segurança."""
    issues = []
    snmp = parsed_data.get("snmp", {})
    versions = snmp.get("versions", [])
    if not any(v.startswith("v2") for v in versions):
        return issues

    issues.append(
        _make_issue(
            snapshot,
            SEVERITY_MEDIUM,
            "snmp_v2c_enabled",
            "SNMP v2c habilitado",
            "SNMP v2c foi detectado. Recomenda-se preferir SNMPv3 "
            "com autenticação e privacidade, e restringir acesso por ACL.",
            metadata={"versions": versions},
        )
    )
    return issues


def _detect_snmp_write_community(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Community SNMP de escrita detectada — risco alto."""
    issues = []
    snmp = parsed_data.get("snmp", {})
    for comm in snmp.get("communities", []):
        if comm.get("access") == "write":
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "snmp_write_community",
                    "Community SNMP de escrita detectada",
                    "Foi detectada community SNMP com permissão de escrita. "
                    "Validar necessidade e restringir acesso por ACL. "
                    "Considere migrar para SNMPv3.",
                    metadata={"access": "write", "acl_ref": comm.get("acl_ref")},
                )
            )
    return issues


def _detect_snmp_without_acl(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """SNMP ativo sem ACL — risco de exposição.

    Só gera issue se NENHUMA referência a ACL foi encontrada no SNMP.
    Se há refs (mesmo sem definição ACL no config), considera que ACL
    existe — a validação se a definição existe é feita por
    management_acl_reference_not_found.
    """
    issues = []
    snmp = parsed_data.get("snmp", {})
    if not snmp.get("enabled"):
        return issues

    # If there are any ACL refs at all, don't flag "without ACL"
    raw_refs = snmp.get("acl_refs", [])
    if raw_refs:
        return issues

    issues.append(
        _make_issue(
            snapshot,
            SEVERITY_HIGH,
            "snmp_without_acl",
            "SNMP sem ACL detectado",
            "SNMP foi detectado sem referência clara a ACL de restrição de "
            "origem. Recomenda-se restringir os gerentes SNMP por ACL.",
            metadata={"versions": snmp.get("versions", [])},
        )
    )
    return issues


def _detect_ntp_without_auth(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NTP sem autenticação."""
    issues = []
    ntp = parsed_data.get("ntp", {})
    if not ntp.get("enabled"):
        return issues
    if ntp.get("authentication_enabled"):
        return issues
    if not ntp.get("servers"):
        return issues

    issues.append(
        _make_issue(
            snapshot,
            SEVERITY_LOW,
            "ntp_without_authentication",
            "NTP sem autenticação",
            "NTP foi detectado sem autenticação configurada. "
            "Validar política de segurança da rede — NTP sem autenticação "
            "pode ser vulnerável a ataques de desvio de horário.",
            metadata={
                "server_count": len(ntp.get("servers", [])),
            },
        )
    )
    return issues


def _detect_syslog_without_loghost(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Syslog ativo mas sem servidor remoto."""
    issues = []
    syslog = parsed_data.get("syslog", {})
    if not syslog.get("enabled"):
        return issues
    if syslog.get("log_hosts"):
        return issues

    issues.append(
        _make_issue(
            snapshot,
            SEVERITY_MEDIUM,
            "syslog_without_loghost",
            "Syslog sem servidor remoto",
            "Info-center/syslog foi detectado mas nenhum loghost remoto "
            "está configurado. Recomenda-se configurar envio de logs "
            "para servidor central de monitoramento.",
            metadata={},
        )
    )
    return issues


def _detect_telnet_enabled(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Telnet habilitado — risco alto."""
    issues = []
    ma = parsed_data.get("management_access", {})
    if not ma.get("has_telnet"):
        return issues

    issues.append(
        _make_issue(
            snapshot,
            SEVERITY_HIGH,
            "telnet_enabled",
            "Telnet habilitado",
            "Acesso Telnet foi detectado. Telnet não é seguro — "
            "recomenda-se usar SSH/Stelnet para acesso administrativo "
            "e restringir por ACL.",
            metadata={},
        )
    )
    return issues


def _detect_vty_without_acl(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Linhas VTY sem ACL de entrada."""
    issues = []
    ma = parsed_data.get("management_access", {})
    if not ma.get("has_vty"):
        return issues

    # Check enriched VTY ACL refs (with existence info)
    vty_lines = parsed_data.get("vty_lines", [])
    has_valid_acl = False
    for vty in vty_lines:
        ref = vty.get("acl_inbound")
        if ref:
            defined = vty.get("acl_inbound_defined", False)
            if defined:
                has_valid_acl = True
                break
            # If ref exists but not defined, still treat as "has ACL" for this check
            has_valid_acl = True
            break

    if has_valid_acl or ma.get("has_acl_on_vty"):
        return issues

    issues.append(
        _make_issue(
            snapshot,
            SEVERITY_MEDIUM,
            "vty_without_acl",
            "VTY sem ACL",
            "Linhas VTY sem ACL de entrada detectadas. "
            "Recomenda-se restringir acesso administrativo por ACL "
            "para prevenir acessos não autorizados.",
            metadata={},
        )
    )
    return issues


def _detect_local_user_high_privilege(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Usuário local com privilégio alto (15)."""
    issues = []
    users = parsed_data.get("local_users", [])

    for user in users:
        priv = user.get("privilege_level")
        if priv is not None and priv >= 15:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "local_user_high_privilege",
                    f"Usuário local com privilégio elevado: {user['name']}",
                    f"Usuário local '{user['name']}' com privilégio nível "
                    f"{priv} detectado. Validar necessidade, políticas de "
                    f"senha forte e controle de acesso.",
                    metadata={
                        "username": user["name"],
                        "privilege_level": priv,
                        "service_types": user.get("service_types", []),
                    },
                )
            )

    return issues


# ── ACL reference not found detector ────────────────────────────────


def _detect_management_acl_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Detecta ACLs de gerência referenciadas mas não definidas.

    Verifica SNMP e VTY ACL refs contra as definições de ACL parseadas.
    Se uma ACL é referenciada mas não foi encontrada na configuração,
    cria um issue informativo.
    """
    issues = []
    acls = parsed_data.get("acls", [])
    defined_numbers = {a["number"] for a in acls if a["number"]}
    defined_names = {a["name"] for a in acls if a["name"]}

    # Check SNMP ACL refs
    snmp = parsed_data.get("snmp", {})
    for ref_entry in snmp.get("acl_refs_enriched", []):
        ref = ref_entry.get("ref", "")
        if ref and not ref_entry.get("exists") and ref not in defined_numbers:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "management_acl_reference_not_found",
                    f"ACL de gerência referenciada não encontrada: {ref}",
                    f"Foi encontrada referência à ACL {ref} em configuração SNMP, "
                    f"mas a definição da ACL não foi localizada na configuração "
                    f"analisada. Validar se a configuração completa foi coletada.",
                    metadata={"acl_ref": ref, "context": "snmp"},
                )
            )

    # Check VTY ACL refs
    for vty in parsed_data.get("vty_lines", []):
        for direction in ("acl_inbound", "acl_outbound"):
            ref = vty.get(direction)
            if ref:
                defined = vty.get(f"{direction}_defined", False)
                if not defined and ref not in defined_numbers:
                    issues.append(
                        _make_issue(
                            snapshot,
                            SEVERITY_MEDIUM,
                            "management_acl_reference_not_found",
                            f"ACL de gerência referenciada não encontrada: {ref}",
                            f"Foi encontrada referência à ACL {ref} em linha VTY, "
                            f"mas a definição da ACL não foi localizada na configuração "
                            f"analisada. Validar se a configuração completa foi coletada.",
                            metadata={"acl_ref": ref, "context": "vty"},
                        )
                    )

    return issues


# ── L2 switching issue detectors ───────────────────────────────────────


def _detect_l2_trunk_allow_all(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Trunk permitindo todas as VLANs (allow-pass vlan all)."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        allowed = iface.get("trunk_allowed_vlans", "")
        if allowed and allowed.strip().lower() == "all":
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "l2_trunk_allow_all_vlans",
                    f"Trunk permitindo todas as VLANs: {iface['name']}",
                    f"A porta trunk {iface['name']} está configurada com "
                    f"allow-pass vlan all. Recomenda-se restringir às VLANs "
                    f"necessárias para segurança L2.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_l2_port_missing_desc(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Portas access/trunk/hybrid sem description."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        mode = iface.get("port_mode")
        if mode not in ("access", "trunk", "hybrid"):
            continue
        desc = iface.get("description", "").strip()
        if desc:
            continue
        code = f"l2_{mode}_port_missing_description"
        title_map = {
            "access": "Porta access sem descrição",
            "trunk": "Porta trunk sem descrição",
            "hybrid": "Porta hybrid sem descrição",
        }
        sev = SEVERITY_LOW if mode == "access" else SEVERITY_MEDIUM
        issues.append(
            _make_issue(
                snapshot,
                sev,
                code,
                f"{title_map.get(mode, 'Porta L2')}: {iface['name']}",
                f"A porta {iface['name']} (modo {mode}) não possui descrição. "
                f"Recomenda-se identificar o equipamento ou cliente conectado.",
                metadata={"interface": iface["name"], "port_mode": mode},
            )
        )
    return issues


def _detect_l2_stp_disabled_trunk(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """STP desabilitado em porta trunk."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("port_mode") != "trunk":
            continue
        if iface.get("stp_disabled"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "l2_stp_disabled_on_trunk",
                    f"STP desabilitado em trunk: {iface['name']}",
                    f"STP está desabilitado na porta trunk {iface['name']}. "
                    f"Isso pode aumentar o risco de loop L2. Validar necessidade.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_l2_edge_port_trunk(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Edge-port configurado em trunk."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("port_mode") != "trunk":
            continue
        if iface.get("stp_edge_port"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "l2_edge_port_on_trunk",
                    f"Edge-port configurado em trunk: {iface['name']}",
                    f"stp edged-port está habilitado na trunk {iface['name']}. "
                    f"Isso pode ser incorreto se conectado a outro switch.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_l2_vlan_used_not_defined(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VLAN usada em porta/subinterface mas n\u00e3o definida em vlan/vlan batch.
    S\u00f3 gera issue quando h\u00e1 contexto de switching local."""
    issues = []
    defined_vlans = {v["vlan_id"] for v in parsed_data.get("vlans", [])}
    has_local_switching = bool(defined_vlans) or any(
        i.get("is_l2_port") for i in parsed_data.get("interfaces", [])
    )
    if not has_local_switching:
        return issues
    usage = _collect_vlan_usage(parsed_data)
    used_vlans = set(usage.keys())
    for vid in sorted(used_vlans):
        if vid not in defined_vlans and vid != 1:
            sources = usage.get(vid, [])
            issues.append(
                _make_issue(
                    snapshot, SEVERITY_MEDIUM, "l2_vlan_used_not_defined",
                    f"VLAN {vid} usada mas n\u00e3o definida",
                    f"A VLAN {vid} \u00e9 usada mas n\u00e3o foi encontrada "
                    f"em vlan batch ou bloco vlan.",
                    metadata={"vlan_id": vid, "sources": sources, "suggested_action": "Adicionar vlan batch se for local."},
                )
            )
    return issues


def _detect_l2_vlan_defined_unused(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VLAN definida mas sem uso detectado."""
    issues = []
    defined_vlans = {v["vlan_id"] for v in parsed_data.get("vlans", [])}
    usage = _collect_vlan_usage(parsed_data)
    used_vlans = set(usage.keys())
    for vlan in parsed_data.get("vlans", []):
        vid = vlan["vlan_id"]
        if vid not in used_vlans:
            desc = vlan.get("description") or vlan.get("name") or ""
            issues.append(
                _make_issue(
                    snapshot, SEVERITY_LOW, "l2_vlan_defined_unused",
                    f"VLAN {vid} definida sem uso detectado",
                    f"A VLAN {vid} está definida{(' (' + desc + ')') if desc else ''} "
                    f"mas não foi encontrada em portas, subinterfaces, "
                    f"QinQ, L2VPN, circuitos ou STP.",
                    metadata={"vlan_id": vid, "definition_source": vlan.get("source", ""),
                              "description": desc,
                              "suggested_action": "Remover se não for mais necessária."},
                )
            )
    return issues


def _collect_vlan_usage(parsed_data: dict) -> dict[int, list[dict]]:
    """Coleta uso de VLANs em toda a config."""
    usage: dict[int, list[dict]] = {}
    def _add(vid, src, iface, reason):
        usage.setdefault(vid, []).append({"source": src, "interface": iface, "reason": reason})
    for iface in parsed_data.get("interfaces", []):
        name = iface.get("name", "?")
        for key in ("access_vlan", "trunk_pvid", "hybrid_pvid"):
            val = iface.get(key)
            if val is not None:
                try: _add(int(val), "interface", name, key)
                except: pass
        for hkey in ("trunk_allowed_vlans", "hybrid_tagged_vlans", "hybrid_untagged_vlans"):
            hval = iface.get(hkey, "")
            if hval and hval.strip().lower() != "all":
                for t in hval.split():
                    if t.isdigit(): _add(int(t), "interface", name, hkey)
        vid = iface.get("vlan_id")
        if vid is not None and iface.get("vlan_type") == "dot1q":
            try: _add(int(vid), "subinterface", name, "dot1q")
            except: pass
        for qk in ("pe_vid", "ce_vid", "second_vlan_id"):
            qv = iface.get(qk)
            if qv is not None:
                try: _add(int(qv), "qinq", name, qk)
                except: pass
        vsi = iface.get("vsi_name")
        if vsi and vid is not None:
            try: _add(int(vid), "l2vpn", name, f"vsi:{vsi}")
            except: pass
    for cr in parsed_data.get("circuits", []):
        d = cr if isinstance(cr, dict) else {}
        cv = d.get("vlan_id")
        if cv is not None:
            try: _add(int(cv), "circuit", d.get("interface", "?"), d.get("circuit_type", "unknown"))
            except: pass
    for inst in parsed_data.get("stp", {}).get("instances", []):
        for v in inst.get("vlans", []):
            _add(v, "stp", f"instance_{inst['instance_id']}", "stp_instance")
    return usage


# ── OSPF issue detectors ──────────────────────────────────────────────


def _detect_ospf_no_router_id(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """OSPF sem router-id configurado explicitamente."""
    issues = []
    for ospf in parsed_data.get("ospf", []):
        if not ospf.get("router_id"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "ospf_no_router_id",
                    f"OSPF processo {ospf.get('process_id', '?')} sem router-id",
                    f"O processo OSPF {ospf.get('process_id', '?')} não possui "
                    f"router-id configurado explicitamente. O router-id pode "
                    f"ser selecionado automaticamente, o que pode causar "
                    f"instabilidade se o endereço mudar.",
                    metadata={
                        "process_id": ospf.get("process_id"),
                    },
                )
            )
    return issues


def _detect_ospf_passive_missing(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """OSPF com interfaces de rede sem passive-interface onde esperado.

    Detecta interfaces OSPF que não são loopback e não são passive-interface,
    indicando possível falta de otimização. Gera issue apenas quando há
    redes OSPF configuradas e nenhuma passive-interface foi definida.
    """
    issues = []
    for ospf in parsed_data.get("ospf", []):
        networks = ospf.get("networks", [])
        passive_ifaces = ospf.get("passive_interfaces", [])
        if not networks:
            continue
        # Filter out loopback-like networks (127.x, 0.0.0.0)
        non_loopback = [
            n for n in networks
            if not n.get("network", "").startswith("127.")
        ]
        if not non_loopback:
            continue
        # If there are interface networks but no passive-interface defined
        if not passive_ifaces:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "ospf_passive_missing",
                    f"OSPF processo {ospf.get('process_id', '?')} sem passive-interface",
                    f"O processo OSPF {ospf.get('process_id', '?')} possui "
                    f"{len(non_loopback)} rede(s) configurada(s) mas nenhuma "
                    f"passive-interface definida. Considere configurar "
                    f"passive-interface em redes LAN para evitar envio "
                    f"desnecessário de hellos OSPF.",
                    metadata={
                        "process_id": ospf.get("process_id"),
                        "network_count": len(non_loopback),
                    },
                )
            )
    return issues


def _detect_ospf_redistribution_without_filter(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """OSPF com redistribuição de rotas sem filtro.

    Detecta import-route sem route-policy associado, o que pode
    causar vazamento de rotas indesejadas para a rede OSPF.
    """
    issues = []
    for ospf in parsed_data.get("ospf", []):
        for redist in ospf.get("redistribute", []):
            details = redist.get("details", "")
            # Check if there's a route-policy (directive) in the details
            has_filter = "route-policy" in details.lower() if details else False
            # Also check raw text for route-policy reference
            raw = ospf.get("raw", "")
            if not has_filter:
                # Check if import-route line includes route-policy
                for line in raw.splitlines():
                    if "import-route" in line.lower() and "route-policy" in line.lower():
                        has_filter = True
                        break
            if not has_filter:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_MEDIUM,
                        "ospf_redistribution_without_filter",
                        f"OSPF processo {ospf.get('process_id', '?')} com "
                        f"redistribuição sem filtro: {redist.get('protocol', '?')}",
                        f"O processo OSPF {ospf.get('process_id', '?')} "
                        f"redistribui rotas {redist.get('protocol', '?')} "
                        f"sem route-policy associado. Isso pode causar "
                        f"vazamento de rotas indesejadas.",
                        metadata={
                            "process_id": ospf.get("process_id"),
                            "protocol": redist.get("protocol"),
                        },
                    )
                )
    return issues


def _looks_like_ip(value: str) -> bool:
    """Rough check if a string looks like an IP address."""
    return value.replace(".", "").isdigit() and value.count(".") == 3
