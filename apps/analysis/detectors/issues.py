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

    # Core/ISIS/MPLS/LDP issues
    issues.extend(_detect_isis_without_network_entity(snapshot, parsed_data))
    issues.extend(_detect_isis_interface_unknown_process(snapshot, parsed_data))
    issues.extend(_detect_isis_plain_authentication(snapshot, parsed_data))
    issues.extend(_detect_mpls_without_lsr_id(snapshot, parsed_data))
    issues.extend(_detect_ldp_without_mpls(snapshot, parsed_data))
    issues.extend(_detect_interface_ldp_without_mpls(snapshot, parsed_data))
    issues.extend(_detect_mpls_interface_without_ldp(snapshot, parsed_data))
    issues.extend(_detect_ldp_remote_peer_without_ip(snapshot, parsed_data))

    # VRF / L3VPN issues
    issues.extend(_detect_vpn_instance_without_rd(snapshot, parsed_data))
    issues.extend(_detect_vpn_instance_without_rt(snapshot, parsed_data))
    issues.extend(_detect_interface_vpn_instance_not_found(snapshot, parsed_data))
    issues.extend(_detect_static_route_vpn_instance_not_found(snapshot, parsed_data))
    issues.extend(_detect_bgp_vpn_instance_not_found(snapshot, parsed_data))
    issues.extend(_detect_vpn_instance_without_interface(snapshot, parsed_data))
    issues.extend(_detect_vpn_instance_without_routes(snapshot, parsed_data))
    issues.extend(_detect_vpnv4_peer_not_enabled(snapshot, parsed_data))
    issues.extend(_detect_duplicate_route_distinguisher(snapshot, parsed_data))

    # QoS / Traffic Policy issues
    issues.extend(_detect_traffic_policy_not_found(snapshot, parsed_data))
    issues.extend(_detect_traffic_classifier_not_found(snapshot, parsed_data))
    issues.extend(_detect_traffic_behavior_not_found(snapshot, parsed_data))
    issues.extend(_detect_qos_classifier_acl_not_found(snapshot, parsed_data))
    issues.extend(_detect_traffic_policy_orphan(snapshot, parsed_data))
    issues.extend(_detect_traffic_classifier_orphan(snapshot, parsed_data))
    issues.extend(_detect_traffic_behavior_orphan(snapshot, parsed_data))
    issues.extend(_detect_qos_profile_not_found(snapshot, parsed_data))
    issues.extend(_detect_qos_profile_orphan(snapshot, parsed_data))
    issues.extend(_detect_qos_car_without_red_discard(snapshot, parsed_data))
    issues.extend(_detect_customer_interface_without_qos(snapshot, parsed_data))

    # NAT issues
    issues.extend(_detect_nat_acl_not_found(snapshot, parsed_data))
    issues.extend(_detect_nat_address_group_not_found(snapshot, parsed_data))
    issues.extend(_detect_nat_address_group_orphan(snapshot, parsed_data))
    issues.extend(_detect_nat_outbound_without_address_group(snapshot, parsed_data))
    issues.extend(_detect_nat_static_private_global_ip(snapshot, parsed_data))
    issues.extend(_detect_nat_server_sensitive_port(snapshot, parsed_data))
    issues.extend(_detect_nat_server_without_protocol(snapshot, parsed_data))
    issues.extend(_detect_nat_interface_missing_description(snapshot, parsed_data))
    issues.extend(_detect_nat_vpn_instance_not_found(snapshot, parsed_data))
    issues.extend(_detect_nat_alg_sip_enabled(snapshot, parsed_data))

    # ── BNG/AAA/RADIUS/IP pool issues ─────────────────────────────────
    bng_issues = _detect_bng_issues(parsed_data)
    for iss in bng_issues:
        iss.snapshot = snapshot
        iss.save()
        issues.append(iss)

    # ── PPPoE / Virtual-Template issues ──────────────────────────────
    pppoe_issues = _detect_pppoe_issues(parsed_data)
    for iss in pppoe_issues:
        iss.snapshot = snapshot
        iss.save()
        issues.append(iss)

    # ── HA / BFD / GR / NSR issues ──────────────────────────────────
    ha_issues = _detect_ha_issues(parsed_data)
    for iss in ha_issues:
        iss.snapshot = snapshot
        iss.save()
        issues.append(iss)

    # ── Multicast / PIM / IGMP / MLD issues ─────────────────────────
    mcast_issues = _detect_multicast_issues(parsed_data)
    for iss in mcast_issues:
        iss.snapshot = snapshot
        iss.save()
        issues.append(iss)

    # Huawei advanced feature families
    for iss in _detect_huawei_advanced_issues(parsed_data):
        iss.snapshot = snapshot
        iss.save()
        issues.append(iss)

    for iss in _detect_zte_olt_issues(parsed_data):
        iss.snapshot = snapshot
        iss.save()
        issues.append(iss)

    return issues


def _detect_huawei_advanced_issues(parsed_data: dict) -> list[AnalysisIssue]:
    advanced = parsed_data.get("huawei_advanced", {})
    issues: list[AnalysisIssue] = []
    evpn = advanced.get("evpn_vxlan", {})
    if evpn.get("evpn_enabled") and not evpn.get("vxlan_enabled"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_MEDIUM,
            category="evpn_vxlan",
            code="evpn_without_vxlan",
            title="EVPN habilitado sem VXLAN/VNI detectado",
            description="A configuração possui EVPN, mas nenhum VXLAN/VNI associado foi identificado.",
        ))
    if evpn.get("vxlan_enabled") and not evpn.get("nve_interfaces"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_MEDIUM,
            category="evpn_vxlan",
            code="vxlan_without_nve_interface",
            title="VXLAN sem interface NVE detectada",
            description="Revise a origem e os peers do overlay VXLAN.",
        ))

    sr = advanced.get("segment_routing", {})
    if sr.get("srv6_enabled") and not sr.get("locators"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_HIGH,
            category="segment_routing",
            code="srv6_without_locator",
            title="SRv6 habilitado sem locator",
            description="SRv6 requer ao menos um locator para alocação de SIDs.",
        ))

    te = advanced.get("mpls_te", {})
    if te.get("enabled") and not parsed_data.get("mpls", {}).get("enabled"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_HIGH,
            category="mpls_te",
            code="mpls_te_without_mpls",
            title="MPLS-TE habilitado sem MPLS global",
        ))

    cgnat = advanced.get("cgnat", {})
    if cgnat.get("enabled") and not cgnat.get("logging_enabled"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_MEDIUM,
            category="cgnat",
            code="cgnat_without_logging",
            title="CGNAT sem logging detectado",
            description="CGNAT deve manter registros de tradução conforme requisitos operacionais e legais.",
        ))

    msdp = advanced.get("msdp", {})
    if msdp.get("enabled") and not parsed_data.get("multicast", {}).get("ipv4_routing_enabled"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_HIGH,
            category="msdp",
            code="msdp_without_multicast_routing",
            title="MSDP sem multicast routing-enable",
        ))
    if msdp.get("enabled") and not msdp.get("peers"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_MEDIUM,
            category="msdp",
            code="msdp_without_peer",
            title="MSDP habilitado sem peer",
        ))

    telemetry = advanced.get("telemetry", {})
    if telemetry.get("enabled") and not telemetry.get("destination_groups"):
        issues.append(AnalysisIssue(
            severity=SEVERITY_MEDIUM,
            category="telemetry",
            code="telemetry_without_destination",
            title="Telemetria sem destination-group",
        ))
    return issues


def _detect_zte_olt_issues(parsed_data: dict) -> list[AnalysisIssue]:
    """Detect ZTE OLT inventory and provisioning risks."""
    if parsed_data.get("vendor") != "zte":
        return []
    olt = parsed_data.get("zte_olt", {})
    if not olt.get("enabled"):
        return []

    issues: list[AnalysisIssue] = []
    for pon in olt.get("pon_ports", []):
        if not pon.get("onu_count"):
            issues.append(AnalysisIssue(
                severity=SEVERITY_LOW,
                category="zte_olt",
                code="zte_pon_without_onu",
                title=f"PON sem ONU provisionada: {pon.get('name', '?')}",
                description="A porta PON foi encontrada sem ONUs provisionadas.",
                metadata={"pon": pon.get("pon"), "raw": pon.get("raw", "")},
            ))

    for onu in olt.get("onus", []):
        identifier = onu.get("interface") or f"{onu.get('pon')}:{onu.get('onu_id')}"
        if not onu.get("serial"):
            issues.append(AnalysisIssue(
                severity=SEVERITY_MEDIUM,
                category="zte_olt",
                code="zte_onu_without_serial",
                title=f"ONU sem serial: {identifier}",
                description="A ONU não possui serial detectado no provisionamento.",
                metadata={"onu": identifier, "raw": onu.get("raw", "")},
            ))
        if not (onu.get("description") or onu.get("name")):
            issues.append(AnalysisIssue(
                severity=SEVERITY_MEDIUM,
                category="zte_olt",
                code="zte_onu_without_description",
                title=f"ONU sem identificação: {identifier}",
                description="A ONU não possui name/description. Recomenda-se identificar cliente, circuito ou endereço.",
                metadata={"onu": identifier, "serial": onu.get("serial", "")},
            ))
        if not onu.get("service_ports"):
            issues.append(AnalysisIssue(
                severity=SEVERITY_HIGH,
                category="zte_olt",
                code="zte_onu_without_service_port",
                title=f"ONU sem service-port: {identifier}",
                description="A ONU está provisionada, mas não foi encontrada associação de serviço/VLAN.",
                metadata={"onu": identifier, "serial": onu.get("serial", "")},
            ))

    for service in olt.get("service_ports", []):
        if not service.get("vlan") and not service.get("user_vlan"):
            issues.append(AnalysisIssue(
                severity=SEVERITY_HIGH,
                category="zte_olt",
                code="zte_service_port_without_vlan",
                title=f"Service-port sem VLAN: {service.get('id', '?')}",
                description="Service-port ZTE sem VLAN detectável. Validar provisionamento do cliente.",
                metadata={"service": service},
            ))
    return issues


# ── Multicast issue codes ──────────────────────────────────────────────

ISSUE_PIM_WITHOUT_MULTICAST_ROUTING = "pim_without_multicast_routing"
ISSUE_IGMP_WITHOUT_MULTICAST_ROUTING = "igmp_without_multicast_routing"
ISSUE_MLD_WITHOUT_IPV6_MULTICAST_ROUTING = "mld_without_ipv6_multicast_routing"
ISSUE_PIM_WITHOUT_RP_OR_BSR = "pim_without_rp_or_bsr"
ISSUE_IGMP_SNOOPING_WITHOUT_QUERIER = "igmp_snooping_without_querier"
ISSUE_IGMP_VERSION_1 = "igmp_version_1"
ISSUE_PIM_INTERFACE_MISSING_DESCRIPTION = "pim_interface_missing_description"
ISSUE_MULTICAST_VPN_INSTANCE_NOT_FOUND = "multicast_vpn_instance_not_found"
ISSUE_IGMP_INVALID_GROUP_ADDRESS = "igmp_invalid_group_address"
ISSUE_MLD_INVALID_GROUP_ADDRESS = "mld_invalid_group_address"
ISSUE_PIM_STATIC_RP_NOT_LOCAL = "pim_static_rp_not_local"


def _detect_multicast_issues(parsed_data):
    """Detect multicast / PIM / IGMP / MLD issues."""
    issues = []
    mc = parsed_data.get("multicast", {})
    interfaces = parsed_data.get("interfaces", [])
    vpn_instance_names = {v["name"] for v in parsed_data.get("vpn_instances", [])}

    ipv4_routing = mc.get("ipv4_routing_enabled", False)
    ipv6_routing = mc.get("ipv6_routing_enabled", False)
    pim_global = mc.get("pim", {}).get("global", {})
    pim_vpn_list = mc.get("pim", {}).get("vpn_instances", [])
    igmp_snoop = mc.get("igmp_snooping", {})

    has_rp_or_bsr = bool(pim_global.get("static_rps") or pim_global.get("bsr_candidates") or pim_global.get("rp_candidates"))

    def _is_multicast_ipv4(ip: str) -> bool:
        try:
            import ipaddress
            return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network("224.0.0.0/4")
        except Exception:
            return False

    def _is_multicast_ipv6(ip: str) -> bool:
        return ip.lower().startswith("ff")

    for iface in interfaces:
        name = iface.get("name", "")

        # A) PIM without multicast routing-enable
        if iface.get("pim_enabled") and not ipv4_routing:
            issues.append(AnalysisIssue(
                code=ISSUE_PIM_WITHOUT_MULTICAST_ROUTING,
                severity="high",
                title=f"PIM na interface {name} sem multicast routing-enable",
                description=f"A interface {name} tem PIM habilitado mas o multicast routing global (multicast routing-enable) não está configurado.",
            ))

        # B) IGMP without multicast routing-enable
        if iface.get("igmp_enabled") and not ipv4_routing:
            issues.append(AnalysisIssue(
                code=ISSUE_IGMP_WITHOUT_MULTICAST_ROUTING,
                severity="medium",
                title=f"IGMP na interface {name} sem multicast routing-enable",
                description=f"A interface {name} tem IGMP habilitado mas o multicast routing global não está configurado.",
            ))

        # C) MLD without IPv6 multicast routing-enable
        if iface.get("mld_enabled") and not ipv6_routing:
            issues.append(AnalysisIssue(
                code=ISSUE_MLD_WITHOUT_IPV6_MULTICAST_ROUTING,
                severity="medium",
                title=f"MLD na interface {name} sem IPv6 multicast routing-enable",
                description=f"A interface {name} tem MLD habilitado mas o IPv6 multicast routing global não está configurado.",
            ))

        # G) IGMP version 1
        if iface.get("igmp_version") == 1:
            issues.append(AnalysisIssue(
                code=ISSUE_IGMP_VERSION_1,
                severity="low",
                title=f"IGMP version 1 na interface {name}",
                description=f"A interface {name} usa IGMP version 1. Recomendado version 2 ou 3.",
            ))

        # H) PIM interface missing description
        if iface.get("pim_enabled") and not iface.get("description"):
            issues.append(AnalysisIssue(
                code=ISSUE_PIM_INTERFACE_MISSING_DESCRIPTION,
                severity="low",
                title=f"Interface PIM {name} sem descrição",
                description=f"A interface {name} tem PIM habilitado mas não possui descrição.",
            ))

        # J) IGMP invalid group
        for g in iface.get("igmp_static_groups", []) + iface.get("igmp_join_groups", []):
            if not _is_multicast_ipv4(g):
                issues.append(AnalysisIssue(
                    code=ISSUE_IGMP_INVALID_GROUP_ADDRESS,
                    severity="medium",
                    title=f"IGMP grupo inválido na interface {name}: {g}",
                    description=f"O endereço {g} não é um grupo multicast IPv4 válido (224.0.0.0/4).",
                ))

        # K) MLD invalid group
        for g in iface.get("mld_static_groups", []):
            if not _is_multicast_ipv6(g):
                issues.append(AnalysisIssue(
                    code=ISSUE_MLD_INVALID_GROUP_ADDRESS,
                    severity="medium",
                    title=f"MLD grupo inválido na interface {name}: {g}",
                    description=f"O endereço {g} não é um grupo multicast IPv6 válido (deve começar com ff).",
                ))

    # D) PIM without RP/BSR — only if sparse-mode (or unknown mode) is active
    def _pim_needs_rp_or_bsr() -> bool:
        """Check if any PIM sparse-mode is active (needs RP/BSR)."""
        global_mode = pim_global.get("mode")
        if global_mode == "sm":
            return True
        if global_mode in ("dm", "ssm"):
            return False
        # Check per-interface — bare "pim" defaults to sm on Huawei
        for iface in interfaces:
            if iface.get("pim_enabled"):
                mode = iface.get("pim_mode")
                if mode in (None, "sm"):
                    return True
        return False

    has_pim = bool(pim_global.get("static_rps") or any(i.get("pim_enabled") for i in interfaces))
    if has_pim and not has_rp_or_bsr and _pim_needs_rp_or_bsr():
        issues.append(AnalysisIssue(
            code=ISSUE_PIM_WITHOUT_RP_OR_BSR,
            severity="medium",
            title="PIM habilitado sem RP/BSR",
            description="PIM sparse-mode está habilitado mas nenhum RP ou BSR foi configurado.",
        ))

    # E) PIM static RP not local (low severity - RP may be remote)
    local_ips = set()
    for i in interfaces:
        ip = i.get("ip_address", "")
        if ip:
            try:
                import ipaddress
                ipaddress.IPv4Address(ip)
                local_ips.add(ip.split("/")[0] if "/" in ip else ip)
            except Exception:
                pass
    for rp in pim_global.get("static_rps", []):
        rp_addr = rp.get("rp_address", "")
        if rp_addr and rp_addr not in local_ips and "." in rp_addr:
            issues.append(AnalysisIssue(
                code=ISSUE_PIM_STATIC_RP_NOT_LOCAL,
                severity="low",
                title=f"Static RP {rp_addr} nao e endereco local",
                description=f"O static RP {rp_addr} nao corresponde a nenhum IP de interface local. Pode ser remoto ou haver erro de digitacao.",
            ))

    # F) IGMP snooping without querier
    for vlan_entry in igmp_snoop.get("vlans", []):
        if vlan_entry.get("enabled") and not vlan_entry.get("querier_enabled"):
            issues.append(AnalysisIssue(
                code=ISSUE_IGMP_SNOOPING_WITHOUT_QUERIER,
                severity="low",
                title=f"IGMP snooping VLAN {vlan_entry['vlan_id']} sem querier",
                description=f"IGMP snooping está habilitado na VLAN {vlan_entry['vlan_id']} mas querier não está configurado.",
            ))

    # I) Multicast VPN-instance not found
    for v in mc.get("vpn_instances", []):
        if v["name"] and v["name"] not in vpn_instance_names:
            issues.append(AnalysisIssue(
                code=ISSUE_MULTICAST_VPN_INSTANCE_NOT_FOUND,
                severity="high",
                title=f"Multicast VPN-instance inexistente: {v['name']}",
                description=f"Multicast está configurado com VPN-instance {v['name']} que não está definida no equipamento.",
            ))
    for v in pim_vpn_list:
        if v["name"] and v["name"] not in vpn_instance_names:
            issues.append(AnalysisIssue(
                code=ISSUE_MULTICAST_VPN_INSTANCE_NOT_FOUND,
                severity="high",
                title=f"PIM VPN-instance inexistente: {v['name']}",
                description=f"PIM está configurado com VPN-instance {v['name']} que não está definida no equipamento.",
            ))

    return issues


# ── HA / BFD / Graceful Restart / NSR issue codes ─────────────────────────

ISSUE_BFD_SESSION_WITHOUT_COMMIT = "bfd_session_without_commit"
ISSUE_BFD_SESSION_WITHOUT_DISCRIMINATOR = "bfd_session_without_discriminator"
ISSUE_BFD_SESSION_INTERFACE_NOT_FOUND = "bfd_session_interface_not_found"
ISSUE_BFD_ENABLED_WITHOUT_GLOBAL = "bfd_enabled_without_global"
ISSUE_BGP_CORE_PEER_WITHOUT_BFD = "bgp_core_peer_without_bfd"
ISSUE_BFD_TIMERS_TOO_AGGRESSIVE = "bfd_timers_too_aggressive"
ISSUE_GRACEFUL_RESTART_WITHOUT_NSR = "graceful_restart_without_nsr"
ISSUE_LDP_WITHOUT_GRACEFUL_RESTART = "ldp_without_graceful_restart"
ISSUE_IGP_CORE_INTERFACE_WITHOUT_BFD = "igp_core_interface_without_bfd"


def _detect_ha_issues(parsed_data):
    """Detect HA / BFD / GR / NSR issues."""
    issues = []
    ha = parsed_data.get("ha", {})
    bfd = ha.get("bfd", {})
    interfaces = parsed_data.get("interfaces", [])
    iface_names = {i["name"] for i in interfaces}
    gr = ha.get("graceful_restart", {})
    nsr = ha.get("nsr", {})

    # Collect BGP data
    bgp_local_as = None
    bgp_peers = []
    for bgp in parsed_data.get("bgp", []):
        bgp_local_as = bgp.get("local_as")
        bgp_peers.extend(bgp.get("peers", []))

    # A) BFD session without commit
    for s in bfd.get("sessions", []):
        if not s.get("committed"):
            issues.append(AnalysisIssue(
                code=ISSUE_BFD_SESSION_WITHOUT_COMMIT,
                severity="high",
                title=f"Sessão BFD {s.get('name', '?')} sem commit",
                description=f"A sessão BFD {s.get('name', '?')} não possui commit. A sessão pode não estar ativa.",
            ))

        # B) BFD session without discriminator
        if not s.get("local_discriminator") and not s.get("remote_discriminator"):
            issues.append(AnalysisIssue(
                code=ISSUE_BFD_SESSION_WITHOUT_DISCRIMINATOR,
                severity="medium",
                title=f"Sessão BFD {s.get('name', '?')} sem discriminator",
                description=f"A sessão BFD {s.get('name', '?')} não possui local/remote discriminator.",
            ))

        # C) BFD session references non-existent interface
        iface_ref = s.get("interface", "")
        if iface_ref and iface_ref not in iface_names:
            issues.append(AnalysisIssue(
                code=ISSUE_BFD_SESSION_INTERFACE_NOT_FOUND,
                severity="high",
                title=f"Sessão BFD {s.get('name', '?')} referencia interface inexistente: {iface_ref}",
                description=f"A interface {iface_ref} referenciada pela sessão BFD {s.get('name', '?')} não está definida na configuração.",
            ))

        # F) BFD timers too aggressive
        tx = s.get("min_tx_interval")
        rx = s.get("min_rx_interval")
        mult = s.get("detect_multiplier")
        if (tx is not None and tx < 50) or (rx is not None and rx < 50) or (mult is not None and mult < 3):
            issues.append(AnalysisIssue(
                code=ISSUE_BFD_TIMERS_TOO_AGGRESSIVE,
                severity="low",
                title=f"Sessão BFD {s.get('name', '?')} com timers agressivos (tx={tx}ms rx={rx}ms mult={mult})",
                description=f"Timers BFD muito agressivos podem causar flapping. Mínimo recomendado: 50ms/3x.",
            ))

    # D) BFD enabled in protocol/peer without BFD global
    bfd_global = bfd.get("global_enabled", False)
    has_bfd_in_protocol = False
    for iface in interfaces:
        if iface.get("isis_bfd_enabled") or iface.get("ospf_bfd_enabled") or iface.get("isis_ipv6_bfd_enabled") or iface.get("mpls_ldp_bfd_enabled"):
            has_bfd_in_protocol = True
            break
    for p in bgp_peers:
        if p.get("bfd_enabled"):
            has_bfd_in_protocol = True
            break
    if has_bfd_in_protocol and not bfd_global:
        issues.append(AnalysisIssue(
            code=ISSUE_BFD_ENABLED_WITHOUT_GLOBAL,
            severity="medium",
            title="BFD habilitado em protocolo/peer sem BFD global ativo",
            description="Há peers ou interfaces com BFD habilitado, mas o BFD global não está configurado (comando 'bfd').",
        ))

    # E) BGP core peer without BFD
    for p in bgp_peers:
        is_core = False
        ci = p.get("connect_interface", "")
        if ci and "loopback" in ci.lower():
            is_core = True
        if bgp_local_as and p.get("remote_as") == bgp_local_as:
            is_core = True
        if is_core and not p.get("bfd_enabled"):
            issues.append(AnalysisIssue(
                code=ISSUE_BGP_CORE_PEER_WITHOUT_BFD,
                severity="medium",
                title=f"BGP core peer {p.get('ip', '?')} sem BFD",
                description=f"O BGP peer {p.get('ip', '?')} é core (iBGP/LoopBack) mas não tem BFD habilitado. Falhas podem demorar mais para convergir.",
            ))

    # G) GR without NSR in core
    for isis in parsed_data.get("isis", []):
        if isis.get("graceful_restart") and not isis.get("nsr_enabled"):
            issues.append(AnalysisIssue(
                code=ISSUE_GRACEFUL_RESTART_WITHOUT_NSR,
                severity="low",
                title=f"ISIS processo {isis.get('process_id', '?')} com GR sem NSR",
                description=f"Graceful Restart habilitado em ISIS {isis.get('process_id', '?')} mas NSR não está ativo. NSR garante reconvergência sem depender de vizinhos.",
            ))
            break
    for ospf in parsed_data.get("ospf", []):
        if ospf.get("graceful_restart") and not ospf.get("nsr_enabled"):
            issues.append(AnalysisIssue(
                code=ISSUE_GRACEFUL_RESTART_WITHOUT_NSR,
                severity="low",
                title=f"OSPF processo {ospf.get('process_id', '?')} com GR sem NSR",
                description=f"Graceful Restart habilitado em OSPF {ospf.get('process_id', '?')} mas NSR não está ativo.",
            ))
            break

    # H) LDP without graceful-restart in core MPLS
    if ha.get("graceful_restart", {}).get("ldp") is False and parsed_data.get("mpls_ldp", {}).get("enabled"):
        issues.append(AnalysisIssue(
            code=ISSUE_LDP_WITHOUT_GRACEFUL_RESTART,
            severity="low",
            title="LDP sem graceful-restart em core MPLS",
            description="O MPLS LDP está habilitado sem graceful-restart. Falhas em link MPLS podem causar flapping de LSP.",
        ))

    # I) IGP core interface without BFD
    for iface in interfaces:
        name = iface.get("name", "")
        part_of_igp = iface.get("isis_enabled") or iface.get("ospfv3_enabled")
        if not part_of_igp:
            continue
        is_core_interface = bool(
            (iface.get("isis_enabled") or iface.get("ospfv3_enabled"))
            and not iface.get("bas")
            and not iface.get("pppoe_server", {}).get("enabled")
        )
        if not is_core_interface:
            continue
        has_bfd_on_iface = bool(
            iface.get("isis_bfd_enabled")
            or iface.get("ospf_bfd_enabled")
            or iface.get("ospfv3_bfd_enabled")
            or iface.get("isis_ipv6_bfd_enabled")
        )
        has_bfd_all_interfaces = False
        for isis in parsed_data.get("isis", []):
            if isis.get("bfd_all_interfaces"):
                has_bfd_all_interfaces = True
        if not has_bfd_on_iface and not has_bfd_all_interfaces:
            issues.append(AnalysisIssue(
                code=ISSUE_IGP_CORE_INTERFACE_WITHOUT_BFD,
                severity="low",
                title=f"Interface core {name} sem BFD",
                description=f"A interface {name} participa de IGP core mas não tem BFD habilitado. Convergência pode ser mais lenta.",
            ))

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


# ── NAT issue detectors ──────────────────────────────────────────────


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is RFC1918 private."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except (ValueError, ImportError):
        return False


def _get_nat_address_group_names(parsed_data: dict) -> set[str]:
    return {ag["name"] for ag in parsed_data.get("nat", {}).get("address_groups", [])}


def _get_acl_names(parsed_data: dict) -> set[str]:
    acl_names: set[str] = set()
    for a in parsed_data.get("acls", []):
        if a.get("number"):
            acl_names.add(a["number"])
        if a.get("name"):
            acl_names.add(a["name"])
    return acl_names


SENSITIVE_PORTS = {"22", "23", "3389", "445", "139", "5900"}


def _detect_nat_acl_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT outbound references a non-existent ACL."""
    issues = []
    acl_names = _get_acl_names(parsed_data)
    for ob in parsed_data.get("nat", {}).get("outbound_rules", []):
        acl = ob.get("acl")
        if acl and acl not in acl_names:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "nat_acl_not_found",
                    f"NAT outbound referencia ACL inexistente: {acl}",
                    f"A regra NAT outbound usa ACL {acl}, mas ela nao foi encontrada.",
                    metadata={"acl": acl, "raw": ob.get("raw", "")},
                )
            )
    return issues


def _detect_nat_address_group_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT outbound references a non-existent address-group."""
    issues = []
    group_names = _get_nat_address_group_names(parsed_data)
    for ob in parsed_data.get("nat", {}).get("outbound_rules", []):
        ag = ob.get("address_group")
        if ag and ag not in group_names:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "nat_address_group_not_found",
                    f"NAT outbound referencia address-group inexistente: {ag}",
                    f"A regra NAT outbound usa address-group {ag}, mas ele nao foi encontrado.",
                    metadata={"address_group": ag, "raw": ob.get("raw", "")},
                )
            )
    return issues


def _detect_nat_address_group_orphan(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Address-group defined but not referenced by any NAT rule."""
    issues = []
    group_names = _get_nat_address_group_names(parsed_data)
    referenced = set()
    for ob in parsed_data.get("nat", {}).get("outbound_rules", []):
        if ob.get("address_group"):
            referenced.add(ob["address_group"])
    for name in sorted(group_names - referenced):
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_LOW,
                "nat_address_group_orphan",
                f"NAT address-group orfao: {name}",
                f"O address-group {name} esta definido mas nao referenciado "
                f"por nenhuma regra NAT outbound.",
                metadata={"address_group": name},
            )
        )
    return issues


def _detect_nat_outbound_without_address_group(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT outbound without an address-group (uses interface IP)."""
    issues = []
    for ob in parsed_data.get("nat", {}).get("outbound_rules", []):
        if not ob.get("address_group"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "nat_outbound_without_address_group",
                    f"NAT outbound sem address-group: ACL {ob.get('acl', '?')}",
                    f"Regra NAT outbound sem address-group explicito. "
                    f"Usara o IP da interface de saida como origem.",
                    metadata={"acl": ob.get("acl"), "raw": ob.get("raw", "")},
                )
            )
    return issues


def _detect_nat_static_private_global_ip(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT static with a private (RFC1918) global IP."""
    issues = []
    for sr in parsed_data.get("nat", {}).get("static_rules", []):
        global_ip = sr.get("global_ip", "")
        if _is_private_ip(global_ip):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "nat_static_private_global_ip",
                    f"NAT static com global IP privado: {global_ip}",
                    f"O IP global {global_ip} em NAT static e um endereco privado "
                    f"(RFC1918). Validar se o IP publico correto foi configurado.",
                    metadata={"global_ip": global_ip, "inside_ip": sr.get("inside_ip")},
                )
            )
    return issues


def _detect_nat_server_sensitive_port(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT server exposes a sensitive port (SSH, Telnet, RDP)."""
    issues = []
    for sv in parsed_data.get("nat", {}).get("server_rules", []):
        port = sv.get("global_port", "")
        if port in SENSITIVE_PORTS:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "nat_server_sensitive_port",
                    f"NAT server expoe porta sensivel: {port}",
                    f"O NAT server para {sv.get('global_ip', '?')} expoe "
                    f"a porta {port} (porta sensivel). Validar necessidade "
                    f"e restricao de origem por ACL.",
                    metadata={
                        "port": port,
                        "global_ip": sv.get("global_ip"),
                        "protocol": sv.get("protocol"),
                        "inside_ip": sv.get("inside_ip"),
                    },
                )
            )
    return issues


def _detect_nat_server_without_protocol(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT server without explicit protocol."""
    issues = []
    for sv in parsed_data.get("nat", {}).get("server_rules", []):
        if not sv.get("protocol"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "nat_server_without_protocol",
                    f"NAT server sem protocolo explicito: {sv.get('global_ip', '?')}",
                    f"O NAT server para {sv.get('global_ip', '?')} nao possui "
                    f"protocolo explicito (tcp/udp). Padrao e tcp.",
                    metadata={
                        "global_ip": sv.get("global_ip"),
                        "global_port": sv.get("global_port"),
                    },
                )
            )
    return issues


def _detect_nat_interface_missing_description(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Interface with NAT but no description."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("has_nat") and not iface.get("description", "").strip():
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "nat_interface_missing_description",
                    f"Interface com NAT sem descricao: {iface['name']}",
                    f"A interface {iface['name']} possui configuracao NAT "
                    f"mas nao tem descricao. Recomenda-se identificar "
                    f"o link/conexao.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_nat_vpn_instance_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT references a VPN-instance that doesn't exist."""
    issues = []
    vpn_names = {v["name"] for v in parsed_data.get("vpn_instances", [])}
    # Check address-groups with vpn-instance
    for ag in parsed_data.get("nat", {}).get("address_groups", []):
        vpn = ag.get("vpn_instance")
        if vpn and vpn not in vpn_names:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "nat_vpn_instance_not_found",
                    f"NAT address-group referencia VPN inexistente: {vpn}",
                    f"O address-group {ag['name']} referencia VPN-instance "
                    f"{vpn}, mas ela nao foi encontrada.",
                    metadata={"address_group": ag["name"], "vpn_instance": vpn},
                )
            )
    # Check NAT outbound with vpn-instance
    for ob in parsed_data.get("nat", {}).get("outbound_rules", []):
        vpn = ob.get("vpn_instance")
        if vpn and vpn not in vpn_names:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "nat_vpn_instance_not_found",
                    f"NAT outbound referencia VPN inexistente: {vpn}",
                    f"A regra NAT outbound referncia VPN-instance {vpn}.",
                    metadata={"vpn_instance": vpn, "acl": ob.get("acl")},
                )
            )
    return issues


def _detect_nat_alg_sip_enabled(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """NAT ALG SIP is enabled."""
    issues = []
    for alg in parsed_data.get("nat", {}).get("alg", []):
        if alg.get("protocol") == "sip" and alg.get("enabled"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "nat_alg_sip_enabled",
                    "NAT ALG SIP habilitado",
                    "ALG SIP esta habilitado. Pode causar comportamento "
                    "inesperado em VoIP. Validar necessidade.",
                    metadata={"protocol": "sip", "enabled": True},
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


# ── Core / ISIS / MPLS / LDP issue detectors ──────────────────────────


def _detect_isis_without_network_entity(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """ISIS process without network entity."""
    issues = []
    for isis in parsed_data.get("isis", []):
        if not isis.get("network_entity"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "isis_without_network_entity",
                    f"ISIS processo {isis['process_id']} sem network-entity",
                    f"Processo ISIS {isis['process_id']} detectado sem "
                    f"network-entity. O protocolo pode não formar "
                    f"adjacência corretamente.",
                    metadata={"process_id": isis["process_id"]},
                )
            )
    return issues


def _detect_isis_interface_unknown_process(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """ISIS interface references a process that doesn't exist."""
    issues = []
    isis_process_ids = {p["process_id"] for p in parsed_data.get("isis", [])}
    for iface in parsed_data.get("interfaces", []):
        proc_id = iface.get("isis_process_id")
        if proc_id and proc_id not in isis_process_ids:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "isis_interface_unknown_process",
                    f"Interface {iface['name']} referencia processo ISIS "
                    f"{proc_id} inexistente",
                    f"Interface {iface['name']} possui isis enable {proc_id}, "
                    f"mas o processo ISIS correspondente não foi encontrado.",
                    metadata={
                        "interface": iface["name"],
                        "isis_process_id": proc_id,
                    },
                )
            )
    return issues


def _detect_isis_plain_authentication(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """ISIS simple/plain authentication detected."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        auth = iface.get("isis_authentication", {})
        if auth.get("enabled") and auth.get("secret_type") == "simple":
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "isis_plain_authentication",
                    f"ISIS com autenticação simples em {iface['name']}",
                    f"Autenticação ISIS simples/plain foi detectada na "
                    f"interface {iface['name']}. Validar uso de cipher/MD5 "
                    f"conforme política de segurança.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_mpls_without_lsr_id(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """MPLS enabled without LSR ID."""
    issues = []
    mpls = parsed_data.get("mpls", {})
    if mpls.get("enabled") and not mpls.get("lsr_id"):
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_HIGH,
                "mpls_without_lsr_id",
                "MPLS sem LSR ID",
                "MPLS habilitado sem lsr-id detectado. "
                "Validar configuração de loopback/LSR ID.",
                metadata={},
            )
        )
    return issues


def _detect_ldp_without_mpls(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """LDP enabled without MPLS global."""
    issues = []
    ldp = parsed_data.get("mpls_ldp", {})
    mpls = parsed_data.get("mpls", {})
    if ldp.get("enabled") and not mpls.get("enabled"):
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_HIGH,
                "ldp_without_mpls",
                "LDP habilitado sem MPLS global",
                "LDP foi detectado, mas MPLS global não parece habilitado. "
                "LDP depende de MPLS para funcionar.",
                metadata={},
            )
        )
    return issues


def _detect_interface_ldp_without_mpls(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Interface with LDP but without MPLS on the same interface."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("mpls_ldp_enabled") and not iface.get("mpls_enabled"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "interface_ldp_without_mpls",
                    f"Interface {iface['name']} com LDP sem MPLS",
                    f"Interface {iface['name']} possui mpls ldp, "
                    f"mas não possui comando mpls na própria interface.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_mpls_interface_without_ldp(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """MPLS interface without LDP — low severity, may be intentional."""
    issues = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("mpls_enabled") and not iface.get("mpls_ldp_enabled"):
            # Skip loopback — LDP on loopback is not required
            if iface.get("type") == "loopback":
                continue
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "mpls_interface_without_ldp",
                    f"Interface MPLS {iface['name']} sem LDP",
                    f"Interface {iface['name']} possui MPLS habilitado mas "
                    f"sem LDP. Pode ser intencional (ex: transporte LSP estático "
                    f"ou TE tunnel), mas validar se deveria formar "
                    f"label distribution.",
                    metadata={"interface": iface["name"]},
                )
            )
    return issues


def _detect_ldp_remote_peer_without_ip(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """LDP remote-peer without remote-ip."""
    issues = []
    ldp = parsed_data.get("mpls_ldp", {})
    for peer in ldp.get("remote_peers", []):
        if not peer.get("remote_ip"):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "ldp_remote_peer_without_ip",
                    f"LDP remote-peer {peer['name']} sem remote-ip",
                    f"Remote-peer LDP {peer['name']} sem remote-ip detectado.",
                    metadata={"peer_name": peer["name"]},
                )
            )
    return issues


# ── VRF / L3VPN issue detectors ──────────────────────────────────────


def _get_vpn_instance_names(parsed_data: dict) -> set[str]:
    """Get all defined VPN-instance names."""
    return {v["name"] for v in parsed_data.get("vpn_instances", [])}


def _detect_vpn_instance_without_rd(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VPN-instance without Route Distinguisher."""
    issues = []
    for vi in parsed_data.get("vpn_instances", []):
        af_data = vi.get("address_families", {})
        has_rd = any(
            af.get("route_distinguisher") for af in af_data.values()
        )
        if not has_rd:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "vpn_instance_without_rd",
                    f"VPN-instance sem Route Distinguisher: {vi['name']}",
                    f"A VPN-instance {vi['name']} não possui "
                    f"route-distinguisher configurado. "
                    f"L3VPN pode não funcionar corretamente.",
                    metadata={"vpn_instance": vi["name"]},
                )
            )
    return issues


def _detect_vpn_instance_without_rt(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VPN-instance without VPN target (import/export)."""
    issues = []
    for vi in parsed_data.get("vpn_instances", []):
        af_data = vi.get("address_families", {})
        has_rt = any(
            af.get("vpn_targets") for af in af_data.values()
        )
        if not has_rt:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "vpn_instance_without_rt",
                    f"VPN-instance sem VPN target: {vi['name']}",
                    f"A VPN-instance {vi['name']} não possui "
                    f"vpn-target import/export configurado.",
                    metadata={"vpn_instance": vi["name"]},
                )
            )
    return issues


def _detect_interface_vpn_instance_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Interface references a VPN-instance that doesn't exist."""
    issues = []
    vpn_names = _get_vpn_instance_names(parsed_data)
    for iface in parsed_data.get("interfaces", []):
        vpn = iface.get("vpn_instance")
        if vpn and vpn not in vpn_names:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "interface_vpn_instance_not_found",
                    f"Interface referencia VPN-instance inexistente: "
                    f"{iface['name']} -> {vpn}",
                    f"A interface {iface['name']} está configurada com "
                    f"ip binding vpn-instance {vpn}, mas esta "
                    f"VPN-instance não foi encontrada na configuração.",
                    metadata={
                        "interface": iface["name"],
                        "vpn_instance": vpn,
                    },
                )
            )
    return issues


def _detect_static_route_vpn_instance_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Static route references a VPN-instance that doesn't exist."""
    issues = []
    vpn_names = _get_vpn_instance_names(parsed_data)
    for route in parsed_data.get("static_routes", []):
        vpn = route.get("vpn_instance")
        if vpn and vpn not in vpn_names:
            dest = f"{route.get('network', '?')}/{route.get('netmask', '?')}"
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "static_route_vpn_instance_not_found",
                    f"Rota estática referencia VPN-instance inexistente: "
                    f"{dest} -> {vpn}",
                    f"A rota estática {dest} via {route.get('next_hop', '?')} "
                    f"referencia a VPN-instance {vpn}, que não foi "
                    f"encontrada na configuração.",
                    metadata={
                        "destination": dest,
                        "next_hop": route.get("next_hop"),
                        "vpn_instance": vpn,
                    },
                )
            )
    return issues


def _detect_bgp_vpn_instance_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """BGP ipv4-family vpn-instance references a VPN-instance that doesn't exist."""
    issues = []
    vpn_names = _get_vpn_instance_names(parsed_data)
    for bgp in parsed_data.get("bgp", []):
        for vi in bgp.get("vpn_instances", []):
            if vi["name"] not in vpn_names:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_HIGH,
                        "bgp_vpn_instance_not_found",
                        f"BGP ipv4-family referencia VPN-instance inexistente: "
                        f"{vi['name']}",
                        f"O BGP possui ipv4-family vpn-instance {vi['name']}, "
                        f"mas esta VPN-instance não foi encontrada na configuração.",
                        metadata={"vpn_instance": vi["name"]},
                    )
                )
    return issues


def _detect_vpn_instance_without_interface(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VPN-instance without any interface bound."""
    issues = []
    vpn_ifaces: dict[str, list[str]] = {}
    for iface in parsed_data.get("interfaces", []):
        vpn = iface.get("vpn_instance")
        if vpn:
            vpn_ifaces.setdefault(vpn, []).append(iface["name"])

    for vi in parsed_data.get("vpn_instances", []):
        if vi["name"] not in vpn_ifaces:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "vpn_instance_without_interface",
                    f"VPN-instance sem interface vinculada: {vi['name']}",
                    f"A VPN-instance {vi['name']} não possui nenhuma "
                    f"interface com ip binding vpn-instance. "
                    f"Pode estar incompleta ou não aplicada.",
                    metadata={"vpn_instance": vi["name"]},
                )
            )
    return issues


def _detect_vpn_instance_without_routes(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VPN-instance without any routes (no BGP, no import-route, no static routes)."""
    issues = []
    vrf_static: dict[str, list] = {}
    for route in parsed_data.get("static_routes", []):
        vpn = route.get("vpn_instance")
        if vpn:
            vrf_static.setdefault(vpn, []).append(route)

    vrf_bgp: set[str] = set()
    for bgp in parsed_data.get("bgp", []):
        for vi in bgp.get("vpn_instances", []):
            if vi.get("peers") or vi.get("networks") or vi.get("import_routes"):
                vrf_bgp.add(vi["name"])

    for vi in parsed_data.get("vpn_instances", []):
        name = vi["name"]
        has_static = name in vrf_static
        has_bgp = name in vrf_bgp
        if not has_static and not has_bgp:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_MEDIUM,
                    "vpn_instance_without_routes",
                    f"VPN-instance sem rotas configuradas: {name}",
                    f"A VPN-instance {name} não possui rotas estáticas, "
                    f"BGP ipv4-family vpn-instance com peers, "
                    f"networks ou import-route.",
                    metadata={"vpn_instance": name},
                )
            )
    return issues


def _detect_vpnv4_peer_not_enabled(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """VPNv4 peer detected but not enabled."""
    issues = []
    for bgp in parsed_data.get("bgp", []):
        for vp in bgp.get("vpnv4", {}).get("peers", []):
            if not vp.get("enabled") and vp.get("peer"):
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_MEDIUM,
                        "vpnv4_peer_not_enabled",
                        f"VPNv4 peer não habilitado: {vp['peer']}",
                        f"O peer VPNv4 {vp['peer']} foi referenciado "
                        f"mas não possui 'peer {vp['peer']} enable' "
                        f"dentro de ipv4-family vpnv4.",
                        metadata={"peer": vp["peer"]},
                    )
                )
    return issues


def _detect_duplicate_route_distinguisher(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Duplicate RD detected across different VPN-instances."""
    issues = []
    rd_map: dict[str, list[str]] = {}
    for vi in parsed_data.get("vpn_instances", []):
        for af in vi.get("address_families", {}).values():
            rd = af.get("route_distinguisher")
            if rd:
                rd_map.setdefault(rd, []).append(vi["name"])

    for rd, names in rd_map.items():
        if len(names) > 1:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_HIGH,
                    "duplicate_route_distinguisher",
                    f"Route Distinguisher duplicado: {rd}",
                    f"O RD {rd} está sendo usado por múltiplas "
                    f"VPN-instances: {', '.join(names)}. "
                    f"RDs duplicados podem causar conflitos "
                    f"de roteamento VPNv4.",
                    metadata={
                        "route_distinguisher": rd,
                        "vpn_instances": names,
                    },
                )
            )
    return issues


# ── QoS / Traffic Policy issue detectors ──────────────────────────────


def _get_qos_names(parsed_data: dict) -> dict:
    """Get sets of defined QoS component names."""
    qos = parsed_data.get("qos", {})
    return {
        "classifiers": {c["name"] for c in qos.get("traffic_classifiers", [])},
        "behaviors": {b["name"] for b in qos.get("traffic_behaviors", [])},
        "policies": {p["name"] for p in qos.get("traffic_policies", [])},
        "profiles": {p["name"] for p in qos.get("qos_profiles", [])},
    }


def _detect_traffic_policy_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Traffic-policy applied on interface but not defined."""
    issues = []
    names = _get_qos_names(parsed_data)
    defined = names["policies"]

    for iface in parsed_data.get("interfaces", []):
        for tp in iface.get("traffic_policies_applied", []):
            if tp["name"] not in defined:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_HIGH,
                        "traffic_policy_not_found",
                        f"Traffic-policy aplicada nao encontrada: {tp['name']}",
                        f"A interface {iface['name']} aplica traffic-policy "
                        f"{tp['name']} sentido {tp['direction']}, mas a politica "
                        f"nao foi encontrada na configuracao.",
                        metadata={
                            "interface": iface["name"],
                            "policy": tp["name"],
                            "direction": tp["direction"],
                        },
                    )
                )
    return issues


def _detect_traffic_classifier_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Traffic policy references a classifier that doesn't exist."""
    issues = []
    names = _get_qos_names(parsed_data)
    defined = names["classifiers"]

    for policy in parsed_data.get("qos", {}).get("traffic_policies", []):
        for ce in policy.get("classifiers", []):
            if ce["classifier"] not in defined:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_HIGH,
                        "traffic_classifier_not_found",
                        f"Traffic-policy referencia classifier inexistente: "
                        f"{ce['classifier']}",
                        f"A policy {policy['name']} referencia o classifier "
                        f"{ce['classifier']} que nao foi encontrado.",
                        metadata={
                            "policy": policy["name"],
                            "classifier": ce["classifier"],
                        },
                    )
                )
    return issues


def _detect_traffic_behavior_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Traffic policy references a behavior that doesn't exist."""
    issues = []
    names = _get_qos_names(parsed_data)
    defined = names["behaviors"]

    for policy in parsed_data.get("qos", {}).get("traffic_policies", []):
        for ce in policy.get("classifiers", []):
            if ce["behavior"] not in defined:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_HIGH,
                        "traffic_behavior_not_found",
                        f"Traffic-policy referencia behavior inexistente: "
                        f"{ce['behavior']}",
                        f"A policy {policy['name']} referencia o behavior "
                        f"{ce['behavior']} que nao foi encontrado.",
                        metadata={
                            "policy": policy["name"],
                            "behavior": ce["behavior"],
                        },
                    )
                )
    return issues


def _detect_qos_classifier_acl_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Classifier references an ACL that doesn't exist."""
    issues = []
    acls = parsed_data.get("acls", [])
    acl_numbers = {a["number"] for a in acls if a["number"]}
    acl_names = {a["name"] for a in acls if a["name"]}
    all_acls = acl_numbers | acl_names

    for cl in parsed_data.get("qos", {}).get("traffic_classifiers", []):
        for im in cl.get("if_match", []):
            if im["type"] == "acl" and im["value"] not in all_acls:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_MEDIUM,
                        "qos_classifier_acl_not_found",
                        f"Classifier referencia ACL inexistente: {im['value']}",
                        f"O classifier {cl['name']} faz if-match acl "
                        f"{im['value']}, mas esta ACL nao foi encontrada.",
                        metadata={
                            "classifier": cl["name"],
                            "acl": im["value"],
                        },
                    )
                )
    return issues


def _detect_traffic_policy_orphan(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Traffic policy defined but not applied to any interface."""
    issues = []
    qos = parsed_data.get("qos", {})
    policies = qos.get("traffic_policies", [])
    applied = set()
    for iface in parsed_data.get("interfaces", []):
        for tp in iface.get("traffic_policies_applied", []):
            applied.add(tp["name"])

    for p in policies:
        if p["name"] not in applied:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "traffic_policy_orphan",
                    f"Traffic-policy definida mas nao aplicada: {p['name']}",
                    f"A traffic-policy {p['name']} esta definida mas nao "
                    f"esta aplicada a nenhuma interface.",
                    metadata={"policy": p["name"]},
                )
            )
    return issues


def _detect_traffic_classifier_orphan(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Traffic classifier not referenced by any policy."""
    issues = []
    qos = parsed_data.get("qos", {})
    classifiers = {c["name"] for c in qos.get("traffic_classifiers", [])}
    referenced = set()
    for p in qos.get("traffic_policies", []):
        for ce in p.get("classifiers", []):
            referenced.add(ce["classifier"])

    for cname in sorted(classifiers - referenced):
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_LOW,
                "traffic_classifier_orphan",
                f"Traffic classifier orfao: {cname}",
                f"O classifier {cname} esta definido mas nao e referenciado "
                f"por nenhuma traffic-policy.",
                metadata={"classifier": cname},
            )
        )
    return issues


def _detect_traffic_behavior_orphan(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Traffic behavior not referenced by any policy."""
    issues = []
    qos = parsed_data.get("qos", {})
    behaviors = {b["name"] for b in qos.get("traffic_behaviors", [])}
    referenced = set()
    for p in qos.get("traffic_policies", []):
        for ce in p.get("classifiers", []):
            referenced.add(ce["behavior"])

    for bname in sorted(behaviors - referenced):
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_LOW,
                "traffic_behavior_orphan",
                f"Traffic behavior orfao: {bname}",
                f"O behavior {bname} esta definido mas nao e referenciado "
                f"por nenhuma traffic-policy.",
                metadata={"behavior": bname},
            )
        )
    return issues


def _detect_qos_profile_not_found(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """QoS profile applied on interface but not defined."""
    issues = []
    names = _get_qos_names(parsed_data)
    defined = names["profiles"]

    for iface in parsed_data.get("interfaces", []):
        for qp in iface.get("qos_profiles_applied", []):
            if qp["name"] not in defined:
                issues.append(
                    _make_issue(
                        snapshot,
                        SEVERITY_MEDIUM,
                        "qos_profile_not_found",
                        f"QoS-profile aplicado nao encontrado: {qp['name']}",
                        f"A interface {iface['name']} aplica qos-profile "
                        f"{qp['name']} sentido {qp['direction']}, mas o "
                        f"perfil nao foi encontrado.",
                        metadata={
                            "interface": iface["name"],
                            "profile": qp["name"],
                            "direction": qp["direction"],
                        },
                    )
                )
    return issues


def _detect_qos_profile_orphan(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """QoS profile defined but not applied to any interface."""
    issues = []
    qos = parsed_data.get("qos", {})
    profiles = {p["name"] for p in qos.get("qos_profiles", [])}
    applied = set()
    for iface in parsed_data.get("interfaces", []):
        for qp in iface.get("qos_profiles_applied", []):
            applied.add(qp["name"])

    for pname in sorted(profiles - applied):
        issues.append(
            _make_issue(
                snapshot,
                SEVERITY_LOW,
                "qos_profile_orphan",
                f"QoS-profile orfao: {pname}",
                f"O qos-profile {pname} esta definido mas nao aplicado "
                f"a nenhuma interface.",
                metadata={"profile": pname},
            )
        )
    return issues


def _detect_qos_car_without_red_discard(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """CAR without explicit red discard action."""
    issues = []
    for bh in parsed_data.get("qos", {}).get("traffic_behaviors", []):
        car = bh.get("car")
        if car and car.get("red_action") not in ("discard", None):
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "qos_car_without_red_discard",
                    f"CAR sem descarte explicito para red: {bh['name']}",
                    f"O behavior {bh['name']} possui CAR com acao red="
                    f"{car.get('red_action', 'ausente')}. "
                    f"Pode ser intencional, mas validar politica de banda.",
                    metadata={
                        "behavior": bh["name"],
                        "red_action": car.get("red_action"),
                    },
                )
            )
    return issues


def _detect_customer_interface_without_qos(snapshot, parsed_data: dict) -> list[AnalysisIssue]:
    """Interface with clear customer indication but no QoS."""
    issues = []
    qos_interfaces = set()
    for iface in parsed_data.get("interfaces", []):
        if iface.get("traffic_policies_applied") or iface.get("qos_profiles_applied") or iface.get("qos_car"):
            qos_interfaces.add(iface["name"])

    for iface in parsed_data.get("interfaces", []):
        if iface["name"] in qos_interfaces:
            continue
        desc = iface.get("description", "").lower()
        vpn = iface.get("vpn_instance")
        has_customer_indication = (
            "cliente" in desc or "customer" in desc
            or bool(vpn)
            or iface.get("is_vrf_interface")
        )
        if has_customer_indication:
            issues.append(
                _make_issue(
                    snapshot,
                    SEVERITY_LOW,
                    "customer_interface_without_qos",
                    f"Interface de cliente sem QoS: {iface['name']}",
                    f"A interface {iface['name']} possui indicio de "
                    f"cliente (VPN: {vpn or 'N/A'}), "
                    f"mas nao possui traffic-policy, qos-profile ou "
                    f"qos car configurado.",
                    metadata={
                        "interface": iface["name"],
                        "vpn_instance": vpn,
                        "description": iface.get("description", ""),
                    },
                )
            )
    return issues


# ── IPv6 issues ──────────────────────────────────────────────────────

ISSUE_IPV6_ADDRESS_WITHOUT_ENABLE = "ipv6_address_without_enable"
ISSUE_BGP_IPV6_PEER_NOT_ENABLED = "bgp_ipv6_peer_not_enabled"
ISSUE_IPV6_STATIC_ROUTE_NEXTHOP_UNREACHABLE = "ipv6_static_route_nexthop_unreachable"
ISSUE_IPV6_DEFAULT_ROUTE_DETECTED = "ipv6_default_route_detected"
ISSUE_IPV6_PREFIX_PERMIT_ANY = "ipv6_prefix_permit_any"
ISSUE_OSPFV3_INTERFACE_UNKNOWN_PROCESS = "ospfv3_interface_unknown_process"
ISSUE_ISIS_IPV6_INTERFACE_UNKNOWN_PROCESS = "isis_ipv6_interface_unknown_process"
ISSUE_VPNV6_PEER_NOT_ENABLED = "vpnv6_peer_not_enabled"
ISSUE_BGP_IPV6_VPN_INSTANCE_NOT_FOUND = "bgp_ipv6_vpn_instance_not_found"

# Reference RFC1918 equivalent for IPv6: all private IPv6 unicast addresses
# But for simplicity, check for link-local/ULA

# Collect all IPv6 addresses from interfaces
def _get_all_ipv6_addresses(parsed_data):
    addrs = set()
    for iface in parsed_data.get("interfaces", []):
        for addr in iface.get("ipv6_addresses", []):
            addrs.add(addr.get("address", ""))
    return addrs


def _detect_ipv6_issues(parsed_data):
    """Detect IPv6-related issues across all parsed data."""
    issues = []

    # A) Interface with IPv6 address without ipv6 enable
    for iface in parsed_data.get("interfaces", []):
        if iface.get("ipv6_addresses") and not iface.get("ipv6_enabled"):
            issues.append(AnalysisIssue(
                code=ISSUE_IPV6_ADDRESS_WITHOUT_ENABLE,
                severity="medium",
                title=f"Interface {iface['name']} possui IPv6 address sem ipv6 enable",
                description=(
                    f"A interface {iface['name']} tem endereco IPv6 configurado "
                    f"mas o comando 'ipv6 enable' nao foi encontrado."
                ),
            ))

    # B) BGP IPv6 peer without enable
    for bgp in parsed_data.get("bgp", []):
        for peer in bgp.get("ipv6_unicast", {}).get("peers", []):
            if not peer.get("enabled"):
                issues.append(AnalysisIssue(
                    code=ISSUE_BGP_IPV6_PEER_NOT_ENABLED,
                    severity="medium",
                    title=f"BGP IPv6 peer {peer['peer']} sem enable em ipv6-family",
                    description=(
                        f"O peer BGP IPv6 {peer['peer']} foi definido mas "
                        f"nao possui 'enable' em ipv6-family unicast."
                    ),
                ))

    # C) IPv6 static route next-hop unreachable
    iface_addrs = _get_all_ipv6_addresses(parsed_data)
    for route in parsed_data.get("ipv6_static_routes", []):
        nh = route.get("next_hop")
        dest = route.get("destination", "")
        if nh and nh not in iface_addrs and nh not in ("::",) and not nh.startswith("fe80:"):
            issues.append(AnalysisIssue(
                code=ISSUE_IPV6_STATIC_ROUTE_NEXTHOP_UNREACHABLE,
                severity="high",
                title=f"IPv6 route next-hop {nh} inalcancavel",
                description=(
                    f"A rota IPv6 para {dest} usa next-hop {nh}, "
                    f"mas {nh} nao foi encontrado em nenhuma interface IPv6 do equipamento."
                ),
            ))

    # D) IPv6 default route
    for route in parsed_data.get("ipv6_static_routes", []):
        if route.get("destination") == "::" or route.get("prefix") == "::/0":
            issues.append(AnalysisIssue(
                code=ISSUE_IPV6_DEFAULT_ROUTE_DETECTED,
                severity="info",
                title="Rota default IPv6 detectada",
                description=(
                    f"Rota default IPv6 (::/0) via {route.get('next_hop', 'N/A')} encontrada."
                ),
            ))

    # E) IPv6 prefix-list permit any
    for pl in parsed_data.get("prefix_lists", []):
        if not pl.get("is_ipv6"):
            continue
        for rule in pl.get("rules", []):
            prefix = rule.get("prefix", "")
            mask_len = rule.get("mask_length")
            le = rule.get("less_equal")
            ge = rule.get("greater_equal")
            if prefix == "::" and mask_len == 0 and rule.get("action") == "permit":
                if (le and le >= 128) or (not le and not ge):
                    issues.append(AnalysisIssue(
                        code=ISSUE_IPV6_PREFIX_PERMIT_ANY,
                        severity="high",
                        title=f"IPv6 prefix-list {pl['name']} permite ::/0",
                        description=(
                            f"O prefix-list IPv6 {pl['name']} possui regra "
                            f"permitindo ::/0, que permite todo o trafego IPv6."
                        ),
                    ))

    # F) OSPFv3 interface references unknown process
    known_ospfv3_processes = {o.get("process_id") for o in parsed_data.get("ospfv3", [])}
    for iface in parsed_data.get("interfaces", []):
        pid = iface.get("ospfv3_process_id")
        if pid and pid not in known_ospfv3_processes:
            issues.append(AnalysisIssue(
                code=ISSUE_OSPFV3_INTERFACE_UNKNOWN_PROCESS,
                severity="medium",
                title=f"Interface {iface['name']} referencia processo OSPFv3 {pid} inexistente",
                description=(
                    f"A interface {iface['name']} tem ospfv3 {pid} area configurado, "
                    f"mas o processo OSPFv3 {pid} nao existe na configuracao."
                ),
            ))

    # G) ISIS IPv6 interface references unknown process
    known_isis_processes = {p.get("process_id") for p in parsed_data.get("isis", [])}
    for iface in parsed_data.get("interfaces", []):
        pid = iface.get("isis_ipv6_process_id")
        if pid and pid not in known_isis_processes:
            issues.append(AnalysisIssue(
                code=ISSUE_ISIS_IPV6_INTERFACE_UNKNOWN_PROCESS,
                severity="medium",
                title=f"Interface {iface['name']} referencia processo ISIS {pid} inexistente para IPv6",
                description=(
                    f"A interface {iface['name']} tem isis ipv6 enable {pid}, "
                    f"mas o processo ISIS {pid} nao existe na configuracao."
                ),
            ))

    # H) VPNv6 peer without enable
    for bgp in parsed_data.get("bgp", []):
        for peer in bgp.get("vpnv6", {}).get("peers", []):
            if not peer.get("enabled"):
                issues.append(AnalysisIssue(
                    code=ISSUE_VPNV6_PEER_NOT_ENABLED,
                    severity="medium",
                    title=f"VPNv6 peer {peer['peer']} sem enable",
                    description=(
                        f"O peer VPNv6 {peer['peer']} foi configurado mas "
                        f"nao possui 'enable' em ipv6-family vpnv6."
                    ),
                ))

    # I) BGP ipv6-family vpn-instance references nonexistent VPN-instance
    existing_vpn_instances = {v.get("name") for v in parsed_data.get("vpn_instances", [])}
    for bgp in parsed_data.get("bgp", []):
        for vi in bgp.get("vpn_instances_ipv6", []):
            vpn_name = vi.get("name", "")
            if vpn_name and vpn_name not in existing_vpn_instances:
                issues.append(AnalysisIssue(
                    code=ISSUE_BGP_IPV6_VPN_INSTANCE_NOT_FOUND,
                    severity="high",
                    title=f"BGP ipv6-family vpn-instance referencia VPN-instance inexistente: {vpn_name}",
                    description=(
                        f"O BGP possui ipv6-family vpn-instance {vpn_name}, "
                        f"mas a VPN-instance {vpn_name} nao foi definida."
                    ),
                ))

    return issues


# ── BNG/AAA/RADIUS/IP pool issues ─────────────────────────────────────

# Issue codes
ISSUE_BAS_DOMAIN_NOT_FOUND = "bas_domain_not_found"
ISSUE_DOMAIN_AUTH_SCHEME_NOT_FOUND = "domain_authentication_scheme_not_found"
ISSUE_DOMAIN_ACCT_SCHEME_NOT_FOUND = "domain_accounting_scheme_not_found"
ISSUE_DOMAIN_AUTHZ_SCHEME_NOT_FOUND = "domain_authorization_scheme_not_found"
ISSUE_DOMAIN_RADIUS_GROUP_NOT_FOUND = "domain_radius_group_not_found"
ISSUE_DOMAIN_IP_POOL_NOT_FOUND = "domain_ip_pool_not_found"
ISSUE_RADIUS_GROUP_WITHOUT_AUTH = "radius_group_without_authentication_server"
ISSUE_RADIUS_GROUP_WITHOUT_ACCT = "radius_group_without_accounting_server"
ISSUE_RADIUS_SHARED_KEY_PLAIN = "radius_shared_key_plain"
ISSUE_IP_POOL_WITHOUT_GATEWAY = "ip_pool_without_gateway"
ISSUE_IP_POOL_WITHOUT_SECTION = "ip_pool_without_section"
ISSUE_BAS_WITHOUT_USER_VLAN = "bas_interface_without_user_vlan"
ISSUE_BAS_WITHOUT_AUTH_METHOD = "bas_interface_without_authentication_method"
ISSUE_DOMAIN_WITHOUT_ACCT = "domain_without_accounting"
ISSUE_BAS_MISSING_DESCRIPTION = "bas_interface_missing_description"

# ── PPPoE / Virtual-Template issue codes ────────────────────────────────
ISSUE_PPPOE_VT_NOT_FOUND = "pppoe_virtual_template_not_found"
ISSUE_VIRTUAL_TEMPLATE_ORPHAN = "virtual_template_orphan"
ISSUE_PPPOE_WITHOUT_BAS = "pppoe_interface_without_bas"
ISSUE_PPPOE_WITHOUT_DOMAIN = "pppoe_interface_without_domain"
ISSUE_PPPOE_WITHOUT_USER_VLAN = "pppoe_interface_without_user_vlan"
ISSUE_VT_WITHOUT_PPP_AUTH = "virtual_template_without_ppp_authentication"
ISSUE_PPP_AUTH_PAP_ENABLED = "ppp_authentication_pap_enabled"
ISSUE_PPPOE_WITHOUT_MAX_SESSIONS = "pppoe_without_max_sessions"
ISSUE_VT_POOL_NOT_FOUND = "virtual_template_pool_not_found"
ISSUE_VT_MTU_NOT_1492 = "virtual_template_mtu_not_1492"


def _detect_pppoe_issues(parsed_data):
    """Detect PPPoE / Virtual-Template issues."""
    issues = []
    interfaces = parsed_data.get("interfaces", [])
    pools = {p.get("name") for p in parsed_data.get("ip_pools", [])}

    # Collect Virtual-Template names and data
    vt_names = set()
    vt_data = {}
    for iface in interfaces:
        name = iface.get("name", "")
        if name.lower().startswith("virtual-template"):
            vt_names.add(name)
            vt_data[name] = iface

    # Track which VTs are used
    used_vts = set()

    # Check each interface with PPPoE server bind
    for iface in interfaces:
        pppoe = iface.get("pppoe_server")
        if not pppoe or not pppoe.get("enabled"):
            continue
        iface_name = iface.get("name", "")
        vt_ref = pppoe.get("virtual_template", "")
        if vt_ref:
            used_vts.add(vt_ref)

        # A) Virtual-Template not found
        if vt_ref and vt_ref not in vt_names:
            issues.append(AnalysisIssue(
                code=ISSUE_PPPOE_VT_NOT_FOUND,
                severity="high",
                title=f"PPPoE interface {iface_name} referencia Virtual-Template inexistente: {vt_ref}",
                description=f"A interface {iface_name} faz bind para {vt_ref}, mas ela não está definida na configuração.",
            ))

        # C) PPPoE interface without BAS
        bas = iface.get("bas")
        if not bas or not bas.get("enabled"):
            issues.append(AnalysisIssue(
                code=ISSUE_PPPOE_WITHOUT_BAS,
                severity="high",
                title=f"Interface PPPoE {iface_name} sem BAS configurado",
                description=f"A interface {iface_name} tem pppoe-server bind mas não possui bloco BAS. Assinantes PPPoE não serão autenticados.",
            ))

        # D) PPPoE without default-domain
        if bas and bas.get("enabled") and not bas.get("default_domain"):
            issues.append(AnalysisIssue(
                code=ISSUE_PPPOE_WITHOUT_DOMAIN,
                severity="high",
                title=f"Interface PPPoE {iface_name} sem default-domain no BAS",
                description=f"A interface {iface_name} tem BAS mas nenhum default-domain definido.",
            ))

        # E) PPPoE without user-vlan
        if not iface.get("user_vlan"):
            issues.append(AnalysisIssue(
                code=ISSUE_PPPOE_WITHOUT_USER_VLAN,
                severity="medium",
                title=f"Interface PPPoE {iface_name} sem user-vlan",
                description=f"A interface {iface_name} tem PPPoE server mas não tem user-vlan definida.",
            ))

        # H) PPPoE without max-sessions
        if not pppoe.get("max_sessions"):
            issues.append(AnalysisIssue(
                code=ISSUE_PPPOE_WITHOUT_MAX_SESSIONS,
                severity="info" if False else "low",
                title=f"Interface PPPoE {iface_name} sem max-sessions",
                description=f"A interface {iface_name} tem PPPoE server mas não define max-sessions.",
            ))

    # Check each Virtual-Template
    for name, vt in vt_data.items():
        # F) VT without PPP authentication-mode
        if not vt.get("ppp_authentication_modes"):
            issues.append(AnalysisIssue(
                code=ISSUE_VT_WITHOUT_PPP_AUTH,
                severity="high",
                title=f"Virtual-Template {name} sem ppp authentication-mode",
                description=f"A Virtual-Template {name} não possui ppp authentication-mode configurado.",
            ))

        # G) PAP enabled
        modes = vt.get("ppp_authentication_modes", [])
        if any(m.lower() == "pap" for m in modes):
            issues.append(AnalysisIssue(
                code=ISSUE_PPP_AUTH_PAP_ENABLED,
                severity="medium",
                title=f"Virtual-Template {name} com ppp authentication-mode pap",
                description=f"PAP pode ser aceito por compatibilidade, mas validar segurança. Preferir CHAP.",
            ))

        # I) Remote address pool not found
        pool = vt.get("remote_address_pool")
        if pool and pool not in pools:
            issues.append(AnalysisIssue(
                code=ISSUE_VT_POOL_NOT_FOUND,
                severity="high",
                title=f"Virtual-Template {name} referencia IP pool inexistente: {pool}",
                description=f"A Virtual-Template {name} usa remote address pool {pool}, mas ele não está definido.",
            ))

        # J) MTU not 1492 when used for PPPoE
        if name in used_vts:
            vt_mtu = vt.get("mtu")
            if vt_mtu is not None and vt_mtu != 1492:
                issues.append(AnalysisIssue(
                    code=ISSUE_VT_MTU_NOT_1492,
                    severity="info",
                    title=f"Virtual-Template {name} com MTU {vt_mtu} (esperado 1492 para PPPoE)",
                    description=f"A MTU recomendada para PPPoE é 1492. MTU {vt_mtu} pode causar fragmentação.",
                ))

    # B) Orphan Virtual-Templates
    for name in vt_names:
        if name not in used_vts:
            issues.append(AnalysisIssue(
                code=ISSUE_VIRTUAL_TEMPLATE_ORPHAN,
                severity="low",
                title=f"Virtual-Template {name} órfã",
                description=f"A Virtual-Template {name} está definida mas nenhuma interface PPPoE a referencia.",
            ))

    return issues


def _detect_bng_issues(parsed_data):
    """Detect BNG/AAA/RADIUS/IP pool issues."""
    issues = []

    # Collect all valid references
    aaa_blocks = parsed_data.get("aaa", [])
    all_domains = set()
    all_auth_schemes = set()
    all_acct_schemes = set()
    all_authz_schemes = set()
    for ab in aaa_blocks:
        for d in ab.get("domains", []):
            all_domains.add(d["name"])
        for s in ab.get("authentication_schemes", []):
            all_auth_schemes.add(s["name"])
        for s in ab.get("accounting_schemes", []):
            all_acct_schemes.add(s["name"])
        for s in ab.get("authorization_schemes", []):
            all_authz_schemes.add(s["name"])
    for d in parsed_data.get("aaa_domains", []):
        all_domains.add(d["name"])

    all_radius_groups = {r["name"] for r in parsed_data.get("radius_servers", [])}
    all_ip_pools = {p["name"] for p in parsed_data.get("ip_pools", [])}

    # A) BAS interface references domain inexistente
    for iface in parsed_data.get("interfaces", []):
        bas = iface.get("bas")
        if not bas or not bas.get("enabled"):
            continue
        dom = bas.get("default_domain")
        if dom and dom not in all_domains:
            issues.append(AnalysisIssue(
                code=ISSUE_BAS_DOMAIN_NOT_FOUND,
                severity="high",
                title=f"BAS interface {iface['name']} referencia domínio inexistente: {dom}",
                description=f"A interface BAS {iface['name']} usa domínio {dom}, mas ele não foi definido.",
            ))
        # M) BAS sem authentication-method
        if not bas.get("authentication_method"):
            issues.append(AnalysisIssue(
                code=ISSUE_BAS_WITHOUT_AUTH_METHOD,
                severity="medium",
                title=f"BAS interface {iface['name']} sem authentication-method",
                description=f"A interface BAS {iface['name']} não possui authentication-method configurado.",
            ))
        # L) BAS sem user-vlan
        if not iface.get("user_vlan"):
            issues.append(AnalysisIssue(
                code=ISSUE_BAS_WITHOUT_USER_VLAN,
                severity="medium",
                title=f"BAS interface {iface['name']} sem user-vlan",
                description=f"A interface BAS {iface['name']} não possui user-vlan configurada.",
            ))
        # O) BAS sem description
        if not iface.get("description"):
            issues.append(AnalysisIssue(
                code=ISSUE_BAS_MISSING_DESCRIPTION,
                severity="medium",
                title=f"BAS interface {iface['name']} sem descrição",
                description=f"A interface BAS {iface['name']} não possui descrição configurada.",
            ))

    # Collect all domains (from AAA blocks + standalone)
    all_domain_entries = []
    for ab in aaa_blocks:
        all_domain_entries.extend(ab.get("domains", []))
    all_domain_entries.extend(parsed_data.get("aaa_domains", []))

    for d in all_domain_entries:
        name = d["name"]

        # B) Domain references auth-scheme inexistente
        as_scheme = d.get("authentication_scheme")
        if as_scheme and as_scheme not in all_auth_schemes:
            issues.append(AnalysisIssue(
                code=ISSUE_DOMAIN_AUTH_SCHEME_NOT_FOUND,
                severity="high",
                title=f"Domain {name} referencia authentication-scheme inexistente: {as_scheme}",
                description=f"O domínio {name} usa authentication-scheme {as_scheme}, mas ele não foi definido em AAA.",
            ))

        # C) Domain references acct-scheme inexistente
        ac_scheme = d.get("accounting_scheme")
        if ac_scheme and ac_scheme not in all_acct_schemes:
            issues.append(AnalysisIssue(
                code=ISSUE_DOMAIN_ACCT_SCHEME_NOT_FOUND,
                severity="high",
                title=f"Domain {name} referencia accounting-scheme inexistente: {ac_scheme}",
                description=f"O domínio {name} usa accounting-scheme {ac_scheme}, mas ele não foi definido em AAA.",
            ))

        # D) Domain references authz-scheme inexistente
        az_scheme = d.get("authorization_scheme")
        if az_scheme and az_scheme not in all_authz_schemes:
            issues.append(AnalysisIssue(
                code=ISSUE_DOMAIN_AUTHZ_SCHEME_NOT_FOUND,
                severity="medium",
                title=f"Domain {name} referencia authorization-scheme inexistente: {az_scheme}",
            ))

        # E) Domain references radius group inexistente
        rg = d.get("radius_server_group")
        if rg and rg not in all_radius_groups:
            issues.append(AnalysisIssue(
                code=ISSUE_DOMAIN_RADIUS_GROUP_NOT_FOUND,
                severity="high",
                title=f"Domain {name} referencia radius-server group inexistente: {rg}",
                description=f"O domínio {name} usa grupo RADIUS {rg}, mas ele não foi definido.",
            ))

        # F) Domain references ip-pool inexistente
        ip = d.get("ip_pool")
        if ip and ip not in all_ip_pools:
            issues.append(AnalysisIssue(
                code=ISSUE_DOMAIN_IP_POOL_NOT_FOUND,
                severity="high",
                title=f"Domain {name} referencia ip-pool inexistente: {ip}",
                description=f"O domínio {name} usa IP pool {ip}, mas ele não foi definido.",
            ))

        # N) Domain sem accounting-scheme
        if not d.get("accounting_scheme"):
            issues.append(AnalysisIssue(
                code=ISSUE_DOMAIN_WITHOUT_ACCT,
                severity="medium",
                title=f"Domain {name} sem accounting-scheme",
                description=f"O domínio {name} não possui accounting-scheme configurado.",
            ))

    # G) RADIUS group without authentication server
    for rg in parsed_data.get("radius_servers", []):
        if not rg.get("authentication_servers"):
            issues.append(AnalysisIssue(
                code=ISSUE_RADIUS_GROUP_WITHOUT_AUTH,
                severity="high",
                title=f"RADIUS group {rg['name']} sem servidor de autenticação",
                description=f"O grupo RADIUS {rg['name']} não possui nenhum servidor de autenticação configurado.",
            ))

        # H) RADIUS group without accounting server
        if not rg.get("accounting_servers"):
            issues.append(AnalysisIssue(
                code=ISSUE_RADIUS_GROUP_WITHOUT_ACCT,
                severity="medium",
                title=f"RADIUS group {rg['name']} sem servidor de contabilidade",
                description=f"O grupo RADIUS {rg['name']} não possui nenhum servidor de contabilidade configurado.",
            ))

        # I) RADIUS shared-key simple
        if rg.get("shared_key_type") == "simple":
            issues.append(AnalysisIssue(
                code=ISSUE_RADIUS_SHARED_KEY_PLAIN,
                severity="high",
                title=f"RADIUS group {rg['name']} com shared-key simple (texto plano)",
                description=f"O grupo RADIUS {rg['name']} usa shared-key simple, que não é criptografada. Recomenda-se usar cipher.",
            ))

    # J) IP pool without gateway
    for pool in parsed_data.get("ip_pools", []):
        if not pool.get("gateway"):
            issues.append(AnalysisIssue(
                code=ISSUE_IP_POOL_WITHOUT_GATEWAY,
                severity="high",
                title=f"IP pool {pool['name']} sem gateway",
                description=f"O IP pool {pool['name']} não possui gateway configurado.",
            ))

        # K) IP pool local without section
        if pool.get("mode") != "remote" and not pool.get("sections"):
            issues.append(AnalysisIssue(
                code=ISSUE_IP_POOL_WITHOUT_SECTION,
                severity="medium",
                title=f"IP pool local {pool['name']} sem section/range",
                description=f"O IP pool local {pool['name']} não possui seção/range de endereços configurada.",
            ))

    return issues
