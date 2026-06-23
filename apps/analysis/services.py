"""Análise de configurações de rede.

Funções de alto nível para analisar snapshots de configuração.
"""

from __future__ import annotations

from django.db import transaction

from apps.analysis.models import DetectedService, ParsedConfig
from apps.parsers.registry import get_parser_for_vendor, list_supported_vendors


@transaction.atomic
def analyze_config_snapshot(snapshot) -> ParsedConfig:
    """Executa análise completa de um snapshot de configuração.

    Args:
        snapshot: Instância de ConfigSnapshot.

    Returns:
        Instância de ParsedConfig com dados analisados.

    Raises:
        ValueError: Se a configuração estiver vazia ou vendor inválido.
        KeyError: Se o vendor não for suportado.
    """
    if not snapshot.raw_config or not snapshot.raw_config.strip():
        raise ValueError("Configuração vazia ou inválida.")

    # Check if already analyzed (idempotent)
    existing = ParsedConfig.objects.filter(snapshot=snapshot).first()
    if existing and existing.parsed_data:
        existing.delete()
        # Delete associated objects for clean re-analysis
        from apps.analysis.models import AnalysisIssue, DetectedCircuit, DetectedService
        AnalysisIssue.objects.filter(snapshot=snapshot).delete()
        DetectedCircuit.objects.filter(snapshot=snapshot).delete()
        DetectedService.objects.filter(snapshot=snapshot).delete()

    # Parse
    try:
        vendor_name, parser_cls = get_parser_for_vendor(snapshot.vendor)
    except KeyError:
        supported = list_supported_vendors()
        raise ValueError(
            f"Vendor '{snapshot.vendor}' não suportado. "
            f"Vendores suportados: {', '.join(sorted(supported))}"
        )
    parser = parser_cls(snapshot.raw_config)
    parsed_data = parser.parse()

    # Create ParsedConfig
    parsed = ParsedConfig.objects.create(
        snapshot=snapshot,
        parsed_data=parsed_data,
    )

    # Detect services
    detect_services(parsed.snapshot, parsed_data)

    # Detect issues
    from apps.analysis.detectors.issues import detect_issues
    detect_issues(parsed.snapshot, parsed_data)

    # Detect circuits
    from apps.analysis.detectors.circuits import (
        detect_l3_transit_circuits,
        detect_vlan_transport_circuits,
        detect_qinq_transport_circuits,
        detect_l2vpn_vsi_circuits,
    )
    detect_l3_transit_circuits(parsed.snapshot, parsed_data)
    detect_vlan_transport_circuits(parsed.snapshot, parsed_data)
    detect_qinq_transport_circuits(parsed.snapshot, parsed_data)
    detect_l2vpn_vsi_circuits(parsed.snapshot, parsed_data)
    from apps.analysis.detectors.circuits import detect_olt_circuits
    detect_olt_circuits(parsed.snapshot, parsed_data)

    return parsed


def detect_services(snapshot, parsed_data: dict) -> list[DetectedService]:
    """Detecta serviços de rede a partir dos dados parseados.

    Cria objetos DetectedService para:
        - BNG/BAS
        - AAA (autenticação)
        - RADIUS (servidores)
        - IP Pool
        - Acesso de assinante (subscriber access)

    Args:
        snapshot: Instância de ConfigSnapshot.
        parsed_data: Dicionário retornado pelo parser.

    Returns:
        Lista de objetos DetectedService criados (já salvos).
    """
    services: list[DetectedService] = []

    # ── BNG/BAS ─────────────────────────────────────────────────────
    bng_svc = _detect_bng(parsed_data)
    if bng_svc:
        bng_svc.snapshot = snapshot
        bng_svc.save()
        services.append(bng_svc)

    # ── AAA ─────────────────────────────────────────────────────────
    aaa_svc = _detect_aaa(parsed_data)
    if aaa_svc:
        aaa_svc.snapshot = snapshot
        aaa_svc.save()
        services.append(aaa_svc)

    # ── RADIUS servers ──────────────────────────────────────────────
    radius_services = _detect_radius_servers(parsed_data)
    for svc in radius_services:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    # ── IP Pools ────────────────────────────────────────────────────
    pool_services = _detect_ip_pools(parsed_data)
    for svc in pool_services:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    # ── Subscriber Access ───────────────────────────────────────────
    sub_svc = _detect_subscriber_access(parsed_data)
    if sub_svc:
        sub_svc.snapshot = snapshot
        sub_svc.save()
        services.append(sub_svc)

    # ── SNMP ────────────────────────────────────────────────────────
    snmp_svc = _detect_snmp(parsed_data)
    if snmp_svc:
        snmp_svc.snapshot = snapshot
        snmp_svc.save()
        services.append(snmp_svc)

    # ── NTP ─────────────────────────────────────────────────────────
    ntp_svc = _detect_ntp(parsed_data)
    if ntp_svc:
        ntp_svc.snapshot = snapshot
        ntp_svc.save()
        services.append(ntp_svc)

    # ── Syslog ──────────────────────────────────────────────────────
    syslog_svc = _detect_syslog(parsed_data)
    if syslog_svc:
        syslog_svc.snapshot = snapshot
        syslog_svc.save()
        services.append(syslog_svc)

    # ── Management Access ───────────────────────────────────────────
    mgmt_svc = _detect_management_access(parsed_data)
    if mgmt_svc:
        mgmt_svc.snapshot = snapshot
        mgmt_svc.save()
        services.append(mgmt_svc)

    # ── Local Users ────────────────────────────────────────────────
    user_services = _detect_local_users(parsed_data)
    for svc in user_services:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    # ── L2 Switching ───────────────────────────────────────────────
    l2_svc = _detect_l2_switching(parsed_data)
    if l2_svc:
        l2_svc.snapshot = snapshot
        l2_svc.save()
        services.append(l2_svc)

    # ── VLAN Service ──────────────────────────────────────────────
    vlan_svc = _detect_vlan_service(parsed_data)
    if vlan_svc:
        vlan_svc.snapshot = snapshot
        vlan_svc.save()
        services.append(vlan_svc)

    # ── STP ────────────────────────────────────────────────────────
    stp_svc = _detect_stp_service(parsed_data)
    if stp_svc:
        stp_svc.snapshot = snapshot
        stp_svc.save()
        services.append(stp_svc)

    # ── Policy services ──────────────────────────────────────────
    from apps.analysis.policy_utils import build_policy_reference_map, get_policy_service_info
    policy_info = get_policy_service_info(parsed_data)
    if policy_info:
        for pi in policy_info:
            svc = DetectedService(
                snapshot=snapshot,
                service_type=pi["service_type"],
                name=pi["name"],
                confidence=0.85,
                metadata=pi.get("metadata", {}),
            )
            svc.save()
            services.append(svc)

    # ── OSPF ─────────────────────────────────────────────────────
    from apps.analysis.detectors.services import _detect_ospf
    ospf_svc = _detect_ospf(parsed_data)
    if ospf_svc:
        ospf_svc.snapshot = snapshot
        ospf_svc.save()
        services.append(ospf_svc)

    # ── ISIS ─────────────────────────────────────────────────────
    isis_svc = _detect_isis(parsed_data)
    if isis_svc:
        isis_svc.snapshot = snapshot
        isis_svc.save()
        services.append(isis_svc)

    # ── MPLS ─────────────────────────────────────────────────────
    mpls_svc = _detect_mpls(parsed_data)
    if mpls_svc:
        mpls_svc.snapshot = snapshot
        mpls_svc.save()
        services.append(mpls_svc)

    # ── MPLS LDP ─────────────────────────────────────────────────
    ldp_svc = _detect_mpls_ldp(parsed_data)
    if ldp_svc:
        ldp_svc.snapshot = snapshot
        ldp_svc.save()
        services.append(ldp_svc)

    # ── VRF / VPN-instance ────────────────────────────────────────
    vrf_svc = _detect_vrf(parsed_data)
    if vrf_svc:
        vrf_svc.snapshot = snapshot
        vrf_svc.save()
        services.append(vrf_svc)

    # ── L3VPN ─────────────────────────────────────────────────────
    l3vpn_svc = _detect_l3vpn(parsed_data)
    if l3vpn_svc:
        l3vpn_svc.snapshot = snapshot
        l3vpn_svc.save()
        services.append(l3vpn_svc)

    # ── BGP VPNv4 ─────────────────────────────────────────────────
    vpnv4_svc = _detect_vpnv4(parsed_data)
    if vpnv4_svc:
        vpnv4_svc.snapshot = snapshot
        vpnv4_svc.save()
        services.append(vpnv4_svc)

    # ── QoS ───────────────────────────────────────────────────────
    qos_svc = _detect_qos(parsed_data)
    if qos_svc:
        qos_svc.snapshot = snapshot
        qos_svc.save()
        services.append(qos_svc)

    # ── Traffic Policy ────────────────────────────────────────────
    tp_svc = _detect_traffic_policy(parsed_data)
    if tp_svc:
        tp_svc.snapshot = snapshot
        tp_svc.save()
        services.append(tp_svc)

    # ── CAR / Controle de Banda ───────────────────────────────────
    car_svc = _detect_qos_car(parsed_data)
    if car_svc:
        car_svc.snapshot = snapshot
        car_svc.save()
        services.append(car_svc)

    # ── NAT ───────────────────────────────────────────────────────
    nat_svc = _detect_nat(parsed_data)
    if nat_svc:
        nat_svc.snapshot = snapshot
        nat_svc.save()
        services.append(nat_svc)

    nat_ob_svc = _detect_nat_outbound(parsed_data)
    if nat_ob_svc:
        nat_ob_svc.snapshot = snapshot
        nat_ob_svc.save()
        services.append(nat_ob_svc)

    nat_st_svc = _detect_nat_static(parsed_data)
    if nat_st_svc:
        nat_st_svc.snapshot = snapshot
        nat_st_svc.save()
        services.append(nat_st_svc)

    nat_sv_svc = _detect_nat_server(parsed_data)
    if nat_sv_svc:
        nat_sv_svc.snapshot = snapshot
        nat_sv_svc.save()
        services.append(nat_sv_svc)

    # ── IPv4 services ───────────────────────────────────────────────
    from apps.analysis.detectors.services import _detect_ipv6
    ipv6_svc = _detect_ipv6(parsed_data)
    if ipv6_svc:
        ipv6_svc.snapshot = snapshot
        ipv6_svc.save()
        services.append(ipv6_svc)

    from apps.analysis.detectors.services import _detect_bgp_ipv6
    bgp_ipv6_svc = _detect_bgp_ipv6(parsed_data)
    if bgp_ipv6_svc:
        bgp_ipv6_svc.snapshot = snapshot
        bgp_ipv6_svc.save()
        services.append(bgp_ipv6_svc)

    from apps.analysis.detectors.services import _detect_vpnv6
    vpnv6_svc = _detect_vpnv6(parsed_data)
    if vpnv6_svc:
        vpnv6_svc.snapshot = snapshot
        vpnv6_svc.save()
        services.append(vpnv6_svc)

    from apps.analysis.detectors.services import _detect_ospfv3
    ospfv3_svc = _detect_ospfv3(parsed_data)
    if ospfv3_svc:
        ospfv3_svc.snapshot = snapshot
        ospfv3_svc.save()
        services.append(ospfv3_svc)

    from apps.analysis.detectors.services import _detect_isis_ipv6
    isis_ipv6_svc = _detect_isis_ipv6(parsed_data)
    if isis_ipv6_svc:
        isis_ipv6_svc.snapshot = snapshot
        isis_ipv6_svc.save()
        services.append(isis_ipv6_svc)

    # ── BNG Advanced ───────────────────────────────────────────────
    from apps.analysis.detectors.services import _detect_bng_advanced, _detect_bas_interfaces, _detect_subscriber_domains, _detect_aaa_scheme, _detect_radius_groups

    bng_adv_svc = _detect_bng_advanced(parsed_data)
    if bng_adv_svc:
        bng_adv_svc.snapshot = snapshot
        bng_adv_svc.save()
        services.append(bng_adv_svc)

    bas_iface_svcs = _detect_bas_interfaces(parsed_data)
    for svc in bas_iface_svcs:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    domain_svcs = _detect_subscriber_domains(parsed_data)
    for svc in domain_svcs:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    aaa_scheme_svc = _detect_aaa_scheme(parsed_data)
    if aaa_scheme_svc:
        aaa_scheme_svc.snapshot = snapshot
        aaa_scheme_svc.save()
        services.append(aaa_scheme_svc)

    radius_group_svcs = _detect_radius_groups(parsed_data)
    for svc in radius_group_svcs:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    # ── HA / BFD / GR / NSR ─────────────────────────────────────────
    from apps.analysis.detectors.services import _detect_bfd, _detect_graceful_restart, _detect_nsr

    bfd_svc = _detect_bfd(parsed_data)
    if bfd_svc:
        bfd_svc.snapshot = snapshot
        bfd_svc.save()
        services.append(bfd_svc)

    gr_svc = _detect_graceful_restart(parsed_data)
    if gr_svc:
        gr_svc.snapshot = snapshot
        gr_svc.save()
        services.append(gr_svc)

    nsr_svc = _detect_nsr(parsed_data)
    if nsr_svc:
        nsr_svc.snapshot = snapshot
        nsr_svc.save()
        services.append(nsr_svc)

    # ── Multicast / PIM / IGMP / MLD ────────────────────────────────
    from apps.analysis.detectors.services import _detect_multicast, _detect_pim, _detect_igmp, _detect_igmp_snooping, _detect_mld

    mcast_svc = _detect_multicast(parsed_data)
    if mcast_svc:
        mcast_svc.snapshot = snapshot
        mcast_svc.save()
        services.append(mcast_svc)

    pim_svc = _detect_pim(parsed_data)
    if pim_svc:
        pim_svc.snapshot = snapshot
        pim_svc.save()
        services.append(pim_svc)

    igmp_svc = _detect_igmp(parsed_data)
    if igmp_svc:
        igmp_svc.snapshot = snapshot
        igmp_svc.save()
        services.append(igmp_svc)

    igmp_snoop_svc = _detect_igmp_snooping(parsed_data)
    if igmp_snoop_svc:
        igmp_snoop_svc.snapshot = snapshot
        igmp_snoop_svc.save()
        services.append(igmp_snoop_svc)

    mld_svc = _detect_mld(parsed_data)
    if mld_svc:
        mld_svc.snapshot = snapshot
        mld_svc.save()
        services.append(mld_svc)

    # ── PPPoE / Virtual-Template / PPP Access ──────────────────────
    from apps.analysis.detectors.services import _detect_pppoe_server, _detect_virtual_templates, _detect_ppp_access

    pppoe_svc = _detect_pppoe_server(parsed_data)
    if pppoe_svc:
        pppoe_svc.snapshot = snapshot
        pppoe_svc.save()
        services.append(pppoe_svc)

    vt_svcs = _detect_virtual_templates(parsed_data)
    for svc in vt_svcs:
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    ppp_access_svc = _detect_ppp_access(parsed_data)
    if ppp_access_svc:
        ppp_access_svc.snapshot = snapshot
        ppp_access_svc.save()
        services.append(ppp_access_svc)

    # ── Huawei advanced feature families ───────────────────────────
    from apps.analysis.detectors.services import _detect_huawei_advanced_services

    for svc in _detect_huawei_advanced_services(parsed_data):
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    from apps.analysis.detectors.services import _detect_zte_olt_services

    for svc in _detect_zte_olt_services(parsed_data):
        svc.snapshot = snapshot
        svc.save()
        services.append(svc)

    return services


def _detect_isis(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço ISIS."""
    isis_processes = parsed_data.get("isis", [])
    interfaces = parsed_data.get("interfaces", [])

    if not isis_processes:
        return None

    isis_ifaces = [i for i in interfaces if i.get("isis_enabled")]
    processes_info = []
    for p in isis_processes:
        info = f"processo {p['process_id']}"
        if p.get("network_entity"):
            info += f", NET: {p['network_entity']}"
        if p.get("is_level"):
            info += f", {p['is_level']}"
        processes_info.append(info)

    return DetectedService(
        service_type=DetectedService.ServiceType.ISIS,
        name=f"ISIS ({len(isis_processes)} processo(s))",
        description=(
            f"ISIS configurado: {'; '.join(processes_info)}. "
            f"{len(isis_ifaces)} interface(s) com ISIS habilitado."
        ),
        confidence=0.90,
        metadata={
            "process_count": len(isis_processes),
            "interface_count": len(isis_ifaces),
            "processes": [
                {
                    "process_id": p["process_id"],
                    "network_entity": p.get("network_entity"),
                    "is_level": p.get("is_level"),
                }
                for p in isis_processes
            ],
            "interfaces": [i["name"] for i in isis_ifaces],
        },
    )


def _detect_mpls(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço MPLS global."""
    mpls = parsed_data.get("mpls", {})
    if not mpls.get("enabled"):
        return None

    interfaces = parsed_data.get("interfaces", [])
    mpls_ifaces = [i for i in interfaces if i.get("mpls_enabled")]

    parts = ["MPLS detectado no equipamento."]
    if mpls.get("lsr_id"):
        parts.append(f"LSR ID: {mpls['lsr_id']}.")
    if mpls.get("te_enabled"):
        parts.append("MPLS TE habilitado.")
    if mpls_ifaces:
        parts.append(f"{len(mpls_ifaces)} interface(s) com MPLS.")

    return DetectedService(
        service_type=DetectedService.ServiceType.MPLS,
        name=f"MPLS ({mpls.get('lsr_id', 'sem LSR ID')})",
        description=" ".join(parts),
        confidence=0.90,
        metadata={
            "lsr_id": mpls.get("lsr_id"),
            "te_enabled": mpls.get("te_enabled", False),
            "interface_count": len(mpls_ifaces),
            "interfaces": [i["name"] for i in mpls_ifaces],
        },
    )


def _detect_mpls_ldp(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço MPLS LDP."""
    ldp = parsed_data.get("mpls_ldp", {})
    if not ldp.get("enabled"):
        return None

    interfaces = parsed_data.get("interfaces", [])
    ldp_ifaces = [i for i in interfaces if i.get("mpls_ldp_enabled")]
    remote_peers = ldp.get("remote_peers", [])

    parts = ["LDP detectado no equipamento."]
    if ldp.get("graceful_restart"):
        parts.append("Graceful-restart habilitado.")
    if ldp_ifaces:
        parts.append(f"{len(ldp_ifaces)} interface(s) com LDP.")
    if remote_peers:
        peer_names = [p["name"] for p in remote_peers]
        parts.append(f"Remote-peer(s): {', '.join(peer_names)}.")

    return DetectedService(
        service_type=DetectedService.ServiceType.MPLS_LDP,
        name=f"LDP ({len(remote_peers)} remote-peer(s))",
        description=" ".join(parts),
        confidence=0.90,
        metadata={
            "graceful_restart": ldp.get("graceful_restart", False),
            "interface_count": len(ldp_ifaces),
            "interfaces": [i["name"] for i in ldp_ifaces],
            "remote_peer_count": len(remote_peers),
            "remote_peers": [
                {
                    "name": p["name"],
                    "remote_ip": p.get("remote_ip"),
                }
                for p in remote_peers
            ],
        },
    )


def _detect_bng(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço principal de BNG/BAS."""
    indicators = parsed_data.get("bng_indicators", [])
    keywords_found = {i["keyword"] for i in indicators}
    aaa_blocks = parsed_data.get("aaa", [])
    radius_blocks = parsed_data.get("radius_servers", [])
    bas_blocks = parsed_data.get("bas_interfaces", [])
    domains = parsed_data.get("aaa_domains", [])
    pools = parsed_data.get("ip_pools", [])

    has_bas = bool(bas_blocks) or "bas_block" in keywords_found
    has_aaa = bool(aaa_blocks)
    has_radius = bool(radius_blocks)
    has_domains = bool(domains)
    has_pools = bool(pools)
    has_subscriber = (
        "access-type layer2-subscriber" in keywords_found
        or "access-type layer3-subscriber" in keywords_found
    )

    if has_bas and has_aaa and has_radius:
        confidence = 0.90
        desc = (
            "Equipamento com função de BNG/BAS completa. "
            "Possui blocos BAS, AAA e servidores RADIUS configurados, "
            "indicando autenticação e controle de sessões de assinantes."
        )
    elif has_bas and has_aaa:
        confidence = 0.80
        desc = (
            "Equipamento com função de BNG/BAS. "
            "Possui BAS e AAA, mas sem RADIUS explícito."
        )
    elif has_bas or (has_aaa and has_radius and has_domains):
        confidence = 0.70
        desc = (
            "Equipamento com possíveis funções de BNG. "
            "Foram encontrados indicadores de autenticação e acesso de assinantes."
        )
    elif len(keywords_found) >= 4:
        confidence = 0.50
        desc = (
            "Equipamento com alguns indicadores de BNG. "
            "Pode haver funções de autenticação ou acesso de assinantes."
        )
    else:
        return None

    return DetectedService(
        service_type=DetectedService.ServiceType.BNG,
        name="BNG/BAS",
        description=desc,
        confidence=confidence,
        metadata={
            "indicators": list(keywords_found),
            "has_bas": has_bas,
            "has_aaa": has_aaa,
            "has_radius": has_radius,
            "has_domains": has_domains,
            "has_pools": has_pools,
            "has_subscriber": has_subscriber,
        },
    )


def _detect_aaa(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço AAA (autenticação, autorização, contabilização)."""
    aaa_blocks = parsed_data.get("aaa", [])
    domains = parsed_data.get("aaa_domains", [])
    auth_schemes = parsed_data.get("auth_schemes", [])
    acct_schemes = parsed_data.get("acct_schemes", [])

    if not aaa_blocks and not domains:
        return None

    confidence = 0.0
    if aaa_blocks and domains and (auth_schemes or acct_schemes):
        confidence = 0.85
    elif aaa_blocks and domains:
        confidence = 0.75
    elif aaa_blocks:
        confidence = 0.60
    elif domains:
        confidence = 0.50

    desc = (
        f"Bloco AAA encontrado com {len(domains)} domínio(s), "
        f"{len(auth_schemes)} esquema(s) de autenticação e "
        f"{len(acct_schemes)} esquema(s) de contabilização."
    )

    return DetectedService(
        service_type=DetectedService.ServiceType.AAA,
        name="AAA",
        description=desc,
        confidence=confidence,
        metadata={
            "domain_count": len(domains),
            "auth_scheme_count": len(auth_schemes),
            "acct_scheme_count": len(acct_schemes),
        },
    )


def _detect_radius_servers(parsed_data: dict) -> list[DetectedService]:
    """Detecta servidores RADIUS configurados."""
    services: list[DetectedService] = []
    radius_blocks = parsed_data.get("radius_servers", [])

    for rb in radius_blocks:
        name = rb.get("name", rb.get("template", "radius-server"))
        metadata = {
            "template": rb.get("template", ""),
            "has_authentication": rb.get("has_authentication", False),
            "has_accounting": rb.get("has_accounting", False),
        }

        services.append(
            DetectedService(
                service_type=DetectedService.ServiceType.RADIUS,
                name=name,
                description=(
                    f"Servidor RADIUS '{name}' configurado. "
                    "Usado para autenticação, autorização e "
                    "contabilização de assinantes."
                ),
                confidence=0.85,
                metadata=metadata,
            )
        )

    return services


# ── L2 Switching ────────────────────────────────────────────────────


def _detect_l2_switching(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço de comutação L2 (switching)."""
    interfaces = parsed_data.get("interfaces", [])
    l2_ports = [i for i in interfaces if i.get("is_l2_port")]
    if not l2_ports:
        return None

    access_count = sum(1 for i in l2_ports if i.get("port_mode") == "access")
    trunk_count = sum(1 for i in l2_ports if i.get("port_mode") == "trunk")
    hybrid_count = sum(1 for i in l2_ports if i.get("port_mode") == "hybrid")

    parts = [f"Comutação L2 detectada com {len(l2_ports)} porta(s) L2."]
    if access_count:
        parts.append(f"{access_count} access.")
    if trunk_count:
        parts.append(f"{trunk_count} trunk.")
    if hybrid_count:
        parts.append(f"{hybrid_count} hybrid.")

    return DetectedService(
        service_type=DetectedService.ServiceType.L2_SWITCHING,
        name="Comutação L2",
        description=" ".join(parts),
        confidence=0.85,
        metadata={
            "l2_port_count": len(l2_ports),
            "access_count": access_count,
            "trunk_count": trunk_count,
            "hybrid_count": hybrid_count,
        },
    )


# ── VLAN Service ────────────────────────────────────────────────────


def _detect_vlan_service(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço de VLANs configuradas."""
    vlans = parsed_data.get("vlans", [])
    if not vlans:
        return None

    defined = [v for v in vlans if v.get("description")]
    named = [v for v in vlans if v.get("name")]

    return DetectedService(
        service_type=DetectedService.ServiceType.VLAN_SERVICE,
        name=f"VLANs ({len(vlans)})",
        description=f"{len(vlans)} VLAN(s) configurada(s). "
                    f"{len(defined)} com descrição.",
        confidence=0.85 if defined else 0.70,
        metadata={
            "vlan_count": len(vlans),
            "defined_count": len(defined),
            "named_count": len(named),
        },
    )


# ── STP Service ─────────────────────────────────────────────────────


def _detect_stp_service(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço STP/RSTP/MSTP."""
    stp = parsed_data.get("stp", {})
    if not stp.get("enabled"):
        return None

    mode = stp.get("mode", "desconhecido")
    instances = stp.get("instances", [])
    regions = stp.get("regions", [])

    parts = [f"STP detectado (modo: {mode})."]
    if regions:
        parts.append(f"{len(regions)} região(ões) MSTP.")
    if instances:
        parts.append(f"{len(instances)} instância(s).")

    return DetectedService(
        service_type=DetectedService.ServiceType.STP,
        name=f"STP ({mode})",
        description=" ".join(parts),
        confidence=0.85 if instances else 0.80,
        metadata={
            "mode": mode,
            "instance_count": len(instances),
            "region_count": len(regions),
        },
    )


def _detect_ip_pools(parsed_data: dict) -> list[DetectedService]:
    """Detecta pools de endereços IP."""
    services: list[DetectedService] = []
    pools = parsed_data.get("ip_pools", [])

    for pool in pools:
        name = pool.get("name", "ip-pool")
        gateway = pool.get("gateway")
        dns_servers = pool.get("dns_servers", [])

        desc = f"Pool de endereços IP '{name}'."
        if gateway:
            desc += f" Gateway: {gateway}."
        if dns_servers:
            desc += f" DNS: {', '.join(dns_servers)}."

        services.append(
            DetectedService(
                service_type=DetectedService.ServiceType.IP_POOL,
                name=name,
                description=desc,
                confidence=0.85,
                metadata={
                    "gateway": gateway,
                    "dns_servers": dns_servers,
                },
            )
        )

    return services


def _detect_subscriber_access(parsed_data: dict) -> DetectedService | None:
    """Detecta interfaces com acesso de assinantes (BAS/subscriber)."""
    interfaces = parsed_data.get("interfaces", [])
    bas_blocks = parsed_data.get("bas_interfaces", [])

    # Check for BAS blocks
    if bas_blocks:
        return DetectedService(
            service_type=DetectedService.ServiceType.SUBSCRIBER_ACCESS,
            name="Acesso de Assinantes (BAS)",
            description=(
                f"{len(bas_blocks)} bloco(s) BAS encontrado(s) com "
                f"configuração de acesso de assinantes."
            ),
            confidence=0.85,
            metadata={"bas_block_count": len(bas_blocks)},
        )

    # Check interfaces for subscriber keywords
    subscriber_ifaces = []
    for iface in interfaces:
        raw = iface.get("raw", "").lower()
        if "subscriber" in raw or "bas" in raw:
            subscriber_ifaces.append(iface["name"])

    if subscriber_ifaces:
        return DetectedService(
            service_type=DetectedService.ServiceType.SUBSCRIBER_ACCESS,
            name="Acesso de Assinantes",
            description=(
                f"{len(subscriber_ifaces)} interface(s) com "
                f"indícios de acesso de assinantes."
            ),
            confidence=0.60,
            metadata={"interfaces": subscriber_ifaces},
        )

    return None


# ── SNMP ─────────────────────────────────────────────────────────────


def _detect_snmp(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço SNMP."""
    snmp = parsed_data.get("snmp", {})
    if not snmp.get("enabled"):
        return None

    versions = snmp.get("versions", [])
    communities = snmp.get("communities", [])
    trap_hosts = snmp.get("trap_hosts", [])
    users = snmp.get("users", [])
    groups = snmp.get("groups", [])
    acl_refs = snmp.get("acl_refs", [])

    has_v3 = "v3" in versions
    has_v2 = any(v.startswith("v2") for v in versions)
    has_acl = bool(acl_refs)

    # Higher confidence with v3 + ACL
    confidence = 0.85 if (has_v3 and has_acl) else 0.80

    parts = ["SNMP detectado no equipamento."]
    if versions:
        parts.append(f"Versões: {', '.join(versions)}.")
    if communities:
        read_count = sum(1 for c in communities if c.get("access") == "read")
        write_count = sum(1 for c in communities if c.get("access") == "write")
        parts.append(f"{read_count} community leitura, {write_count} community escrita (mascaradas).")
    if trap_hosts:
        parts.append(f"{len(trap_hosts)} trap host(s) configurado(s).")
    if users:
        parts.append(f"{len(users)} usuário(s) SNMPv3.")
    if has_acl:
        parts.append(f"ACL(s) associada(s): {', '.join(acl_refs)}.")

    return DetectedService(
        service_type=DetectedService.ServiceType.SNMP,
        name=f"SNMP ({', '.join(versions) if versions else 'v2c/v3'})",
        description=" ".join(parts),
        confidence=confidence,
        metadata={
            "versions": versions,
            "community_count": len(communities),
            "trap_host_count": len(trap_hosts),
            "user_count": len(users),
            "group_count": len(groups),
            "has_acl": has_acl,
            "acl_refs": acl_refs,
        },
    )


# ── NTP ──────────────────────────────────────────────────────────────


def _detect_ntp(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço NTP."""
    ntp = parsed_data.get("ntp", {})
    if not ntp.get("enabled"):
        return None

    servers = ntp.get("servers", [])
    source_iface = ntp.get("source_interface")
    auth_enabled = ntp.get("authentication_enabled", False)

    parts = ["NTP detectado no equipamento."]
    if servers:
        ips = [s["ip"] for s in servers if s.get("ip")]
        parts.append(f"Servidor(es): {', '.join(ips)}.")
    if source_iface:
        parts.append(f"Interface de origem: {source_iface}.")
    parts.append("Autenticação: " + ("ativada." if auth_enabled else "não configurada."))

    confidence = 0.85 if servers else 0.60

    return DetectedService(
        service_type=DetectedService.ServiceType.NTP,
        name=f"NTP ({len(servers)} servidor(es))",
        description=" ".join(parts),
        confidence=confidence,
        metadata={
            "server_count": len(servers),
            "servers": [s.get("ip") for s in servers if s.get("ip")],
            "source_interface": source_iface,
            "authentication_enabled": auth_enabled,
        },
    )


# ── Syslog ───────────────────────────────────────────────────────────


def _detect_syslog(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço Syslog/info-center."""
    syslog = parsed_data.get("syslog", {})
    if not syslog.get("enabled"):
        return None

    log_hosts = syslog.get("log_hosts", [])
    facilities = syslog.get("facilities", [])

    parts = ["Syslog (info-center) detectado no equipamento."]
    if log_hosts:
        ips = [h["ip"] for h in log_hosts if h.get("ip")]
        parts.append(f"Log host(s): {', '.join(ips)}.")
    else:
        parts.append("Nenhum loghost remoto configurado.")
    if facilities:
        parts.append(f"Facilities: {', '.join(facilities)}.")

    confidence = 0.85 if log_hosts else 0.50

    return DetectedService(
        service_type=DetectedService.ServiceType.SYSLOG,
        name=f"Info-center ({len(log_hosts)} loghost(s))",
        description=" ".join(parts),
        confidence=confidence,
        metadata={
            "log_host_count": len(log_hosts),
            "log_hosts": [h.get("ip") for h in log_hosts if h.get("ip")],
            "facilities": facilities,
        },
    )


# ── Management Access ────────────────────────────────────────────────


def _detect_management_access(parsed_data: dict) -> DetectedService | None:
    """Detecta configuração de acesso administrativo."""
    ma = parsed_data.get("management_access", {})
    vty_lines = parsed_data.get("vty_lines", [])
    ssh_data = parsed_data.get("ssh", {})

    has_vty = ma.get("has_vty", False) or bool(vty_lines)
    has_ssh = ma.get("has_ssh", False) or ssh_data.get("enabled", False)
    has_telnet = ma.get("has_telnet", False)
    has_acl = ma.get("has_acl_on_vty", False)

    if not has_vty:
        return None

    parts = ["Acesso administrativo configurado."]
    if has_ssh:
        parts.append("SSH/Stelnet habilitado.")
    if has_telnet:
        parts.append("ATENÇÃO: Telnet detectado.")
    if has_acl:
        parts.append("ACL de entrada nas linhas VTY.")

    auth_modes = set()
    for vty in vty_lines:
        if vty.get("authentication_mode"):
            auth_modes.add(vty["authentication_mode"])

    confidence = 0.90 if (has_ssh and has_acl) else 0.85

    return DetectedService(
        service_type=DetectedService.ServiceType.MANAGEMENT_ACCESS,
        name="Acesso Administrativo",
        description=" ".join(parts),
        confidence=confidence,
        metadata={
            "vty_line_count": len(vty_lines),
            "has_ssh": has_ssh,
            "has_telnet": has_telnet,
            "has_acl_on_vty": has_acl,
            "authentication_modes": list(auth_modes),
        },
    )


# ── Local Users ──────────────────────────────────────────────────────


def _detect_local_users(parsed_data: dict) -> list[DetectedService]:
    """Detecta usuários locais configurados."""
    services: list[DetectedService] = []
    users = parsed_data.get("local_users", [])

    for user in users:
        name = user.get("name", "unknown")
        privilege = user.get("privilege_level")
        has_pw = user.get("has_password", False)
        pw_type = user.get("password_type", "unknown")
        service_types = user.get("service_types", [])

        desc = f"Usuário local '{name}'."
        if privilege is not None:
            desc += f" Privilégio nível {privilege}."
        if service_types:
            desc += f" Acesso: {', '.join(service_types)}."
        if has_pw:
            desc += " Senha configurada (tipo não revelado)."
        else:
            desc += " ATENÇÃO: sem senha configurada."

        metadata = {
            "privilege_level": privilege,
            "has_password": has_pw,
            "password_type": pw_type,
            "service_types": service_types,
        }

        services.append(
            DetectedService(
                service_type=DetectedService.ServiceType.LOCAL_USER,
                name=name,
                description=desc,
                confidence=0.90 if has_pw else 0.70,
                metadata=metadata,
            )
        )

    return services


# ── VRF / VPN-instance ────────────────────────────────────────────────


def _detect_vrf(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço VRF/VPN-instance."""
    vpn_instances = parsed_data.get("vpn_instances", [])
    if not vpn_instances:
        return None

    interface_count = sum(
        1 for iface in parsed_data.get("interfaces", [])
        if iface.get("is_vrf_interface")
    )
    total_routes = sum(
        1 for r in parsed_data.get("static_routes", [])
        if r.get("vpn_instance")
    )

    names = [v["name"] for v in vpn_instances]
    rds = []
    for v in vpn_instances:
        for af in v.get("address_families", {}).values():
            if af.get("route_distinguisher"):
                rds.append(af["route_distinguisher"])

    desc = (
        f"{len(vpn_instances)} VPN-instance(s) detectada(s): "
        f"{', '.join(names)}. "
        f"{interface_count} interface(s) em VRF, "
        f"{total_routes} rota(s) estatica(s) VRF."
    )

    return DetectedService(
        service_type=DetectedService.ServiceType.VRF,
        name=f"VRF ({len(vpn_instances)})",
        description=desc,
        confidence=0.90 if rds else 0.70,
        metadata={
            "vrf_count": len(vpn_instances),
            "vrf_names": names,
            "route_distinguishers": rds,
            "interface_count": interface_count,
            "static_route_count": total_routes,
        },
    )


# ── L3VPN ─────────────────────────────────────────────────────────────


def _detect_l3vpn(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço L3VPN MPLS."""
    vpn_instances = parsed_data.get("vpn_instances", [])
    bgp_blocks = parsed_data.get("bgp", [])

    if not vpn_instances:
        return None

    has_vpnv4 = any(
        bool(bgp.get("vpnv4", {}).get("peers"))
        for bgp in bgp_blocks
    )
    has_bgp_vpn = any(
        bool(bgp.get("vpn_instances"))
        for bgp in bgp_blocks
    )
    complete = has_bgp_vpn and has_vpnv4

    complete_vrfs = 0
    vrf_names_with_bgp = set()
    for bgp in bgp_blocks:
        for vi in bgp.get("vpn_instances", []):
            vrf_names_with_bgp.add(vi["name"])
            if vi.get("peers") or vi.get("networks") or vi.get("import_routes"):
                complete_vrfs += 1

    has_rd = any(
        vi.get("address_families", {}).get("ipv4", {}).get("route_distinguisher")
        for vi in vpn_instances
    )

    total_rt = sum(
        len(af.get("vpn_targets", []))
        for vi in vpn_instances
        for af in vi.get("address_families", {}).values()
    )

    names = [v["name"] for v in vpn_instances]

    if complete:
        confidence = 0.90
        desc = (
            "L3VPN MPLS completo detectado: "
            f"{len(vpn_instances)} VPN-instance(s), "
            "BGP VPNv4 ativo, BGP ipv4-family vpn-instance configurado."
        )
    elif has_rd:
        confidence = 0.80
        desc = (
            "L3VPN MPLS parcial: "
            f"{len(vpn_instances)} VPN-instance(s) com RD, "
            "mas sem BGP vpn-instance ou VPNv4 completo."
        )
    else:
        confidence = 0.60
        desc = "VRF/VPN-instance(s) detectada(s) sem configuracao L3VPN MPLS completa."

    return DetectedService(
        service_type=DetectedService.ServiceType.L3VPN,
        name=f"L3VPN ({len(vpn_instances)})",
        description=desc,
        confidence=confidence,
        metadata={
            "vrf_count": len(vpn_instances),
            "vrf_names": names,
            "has_rd": has_rd,
            "total_route_targets": total_rt,
            "has_vpnv4": has_vpnv4,
            "has_bgp_vpn_instance": has_bgp_vpn,
            "complete_vrfs": complete_vrfs,
            "vrf_names_with_bgp": list(vrf_names_with_bgp),
        },
    )


# ── BGP VPNv4 ─────────────────────────────────────────────────────────


def _detect_vpnv4(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço BGP VPNv4."""
    bgp_blocks = parsed_data.get("bgp", [])
    all_vpnv4_peers = []
    for bgp in bgp_blocks:
        vpnv4 = bgp.get("vpnv4", {})
        all_vpnv4_peers.extend(vpnv4.get("peers", []))

    if not all_vpnv4_peers:
        return None

    enabled_count = sum(1 for p in all_vpnv4_peers if p.get("enabled"))
    peer_ips = [p["peer"] for p in all_vpnv4_peers if p.get("peer")]

    desc = (
        f"BGP VPNv4 detectado com {len(all_vpnv4_peers)} peer(s) "
        f"({enabled_count} habilitado(s)). "
        f"Peers: {', '.join(peer_ips)}."
    )

    return DetectedService(
        service_type=DetectedService.ServiceType.VPNV4,
        name=f"BGP VPNv4 ({len(all_vpnv4_peers)})",
        description=desc,
        confidence=0.85 if enabled_count else 0.50,
        metadata={
            "total_peers": len(all_vpnv4_peers),
            "enabled_peers": enabled_count,
            "peer_ips": peer_ips,
        },
    )


# ── QoS / Traffic Policy ──────────────────────────────────────────────


def _detect_qos(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço QoS geral."""
    qos = parsed_data.get("qos", {})
    classifiers = qos.get("traffic_classifiers", [])
    behaviors = qos.get("traffic_behaviors", [])
    policies = qos.get("traffic_policies", [])

    if not any([classifiers, behaviors, policies]):
        return None

    ifaces_with_qos = [
        i["name"] for i in parsed_data.get("interfaces", [])
        if i.get("traffic_policies_applied") or i.get("qos_profiles_applied") or i.get("qos_car")
    ]

    desc = (
        f"QoS detectado: {len(classifiers)} classifier(es), "
        f"{len(behaviors)} behavior(s), {len(policies)} policy(ies)."
    )
    if ifaces_with_qos:
        desc += f" Aplicado em {len(ifaces_with_qos)} interface(s)."

    return DetectedService(
        service_type=DetectedService.ServiceType.QOS,
        name=f"QoS ({len(policies)} politica(s))",
        description=desc,
        confidence=0.85 if policies else 0.70,
        metadata={
            "classifier_count": len(classifiers),
            "behavior_count": len(behaviors),
            "policy_count": len(policies),
            "interfaces_with_qos": ifaces_with_qos,
        },
    )


def _detect_traffic_policy(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço Traffic Policy."""
    policies = parsed_data.get("qos", {}).get("traffic_policies", [])
    if not policies:
        return None

    applied = sum(
        1 for i in parsed_data.get("interfaces", [])
        if i.get("traffic_policies_applied")
    )

    desc = (
        f"{len(policies)} traffic-policy(ies) configurada(s), "
        f"{applied} aplicada(s) em interface."
    )

    return DetectedService(
        service_type=DetectedService.ServiceType.TRAFFIC_POLICY,
        name=f"Traffic Policy ({len(policies)})",
        description=desc,
        confidence=0.85 if applied else 0.70,
        metadata={
            "policy_count": len(policies),
            "applied_count": applied,
            "policy_names": [p["name"] for p in policies],
        },
    )


def _detect_qos_car(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço CAR / Controle de Banda."""
    behaviors = parsed_data.get("qos", {}).get("traffic_behaviors", [])
    iface_cars = [
        i for i in parsed_data.get("interfaces", [])
        if i.get("qos_car")
    ]

    car_behaviors = [b for b in behaviors if b.get("car")]
    if not car_behaviors and not iface_cars:
        return None

    total_car = len(car_behaviors) + len(iface_cars)
    cirs = []
    for b in car_behaviors:
        if b["car"] and b["car"].get("cir"):
            cirs.append(b["car"]["cir"])
    for i in iface_cars:
        for c in i.get("qos_car", []):
            if c.get("cir"):
                cirs.append(c["cir"])

    desc = (
        f"CAR / Controle de Banda detectado: {total_car} regra(s). "
        f"{len(car_behaviors)} em traffic-behavior, "
        f"{len(iface_cars)} interface(s) com qos car."
    )

    return DetectedService(
        service_type=DetectedService.ServiceType.QOS_CAR,
        name=f"CAR ({total_car})",
        description=desc,
        confidence=0.85,
        metadata={
            "total_car_rules": total_car,
            "behavior_car_count": len(car_behaviors),
            "interface_car_count": len(iface_cars),
            "cir_rates": cirs,
        },
    )


# ── NAT / PAT ──────────────────────────────────────────────────────────


def _detect_nat(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço NAT geral."""
    nat = parsed_data.get("nat", {})
    if not any([nat.get("address_groups"), nat.get("outbound_rules"),
                nat.get("static_rules"), nat.get("server_rules")]):
        return None

    ifaces_with_nat = [
        i["name"] for i in parsed_data.get("interfaces", []) if i.get("has_nat")
    ]

    ob_count = len(nat.get("outbound_rules", []))
    st_count = len(nat.get("static_rules", []))
    sv_count = len(nat.get("server_rules", []))
    total = ob_count + st_count + sv_count

    desc = (
        f"NAT detectado: {total} regra(s) "
        f"({ob_count} outbound, {st_count} static, {sv_count} server)."
    )
    if ifaces_with_nat:
        desc += f" Aplicado em {len(ifaces_with_nat)} interface(s)."

    return DetectedService(
        service_type=DetectedService.ServiceType.NAT,
        name=f"NAT ({total})",
        description=desc,
        confidence=0.90 if total > 0 else 0.70,
        metadata={
            "outbound_count": ob_count,
            "static_count": st_count,
            "server_count": sv_count,
            "address_group_count": len(nat.get("address_groups", [])),
            "interfaces_with_nat": ifaces_with_nat,
        },
    )


def _detect_nat_outbound(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço NAT Outbound (PAT)."""
    rules = parsed_data.get("nat", {}).get("outbound_rules", [])
    if not rules:
        return None
    return DetectedService(
        service_type=DetectedService.ServiceType.NAT_OUTBOUND,
        name=f"NAT Outbound ({len(rules)})",
        description=f"{len(rules)} regra(s) de NAT outbound configurada(s).",
        confidence=0.85,
        metadata={"rule_count": len(rules), "rules": rules},
    )


def _detect_nat_static(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço NAT Estático."""
    rules = parsed_data.get("nat", {}).get("static_rules", [])
    if not rules:
        return None
    return DetectedService(
        service_type=DetectedService.ServiceType.NAT_STATIC,
        name=f"NAT Estático ({len(rules)})",
        description=f"{len(rules)} regra(s) de NAT static configurada(s).",
        confidence=0.85,
        metadata={"rule_count": len(rules), "rules": rules},
    )


def _detect_nat_server(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço NAT Server (Port Forward)."""
    rules = parsed_data.get("nat", {}).get("server_rules", [])
    if not rules:
        return None
    return DetectedService(
        service_type=DetectedService.ServiceType.NAT_SERVER,
        name=f"NAT Server ({len(rules)})",
        description=f"{len(rules)} regra(s) de NAT server configurada(s).",
        confidence=0.85,
        metadata={"rule_count": len(rules), "rules": rules},
    )
