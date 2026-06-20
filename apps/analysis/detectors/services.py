"""Detector de serviços/funções de rede.

Detecta serviços como BNG/BAS, AAA, RADIUS, IP Pools
e acesso de assinantes com base nos dados parseados.
"""

from __future__ import annotations

from apps.analysis.models import DetectedService, ParsedConfig


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

    # ── BNG Advanced services ───────────────────────────────────────
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

    # ── OSPF ───────────────────────────────────────────────────────
    ospf_svc = _detect_ospf(parsed_data)
    if ospf_svc:
        ospf_svc.snapshot = snapshot
        ospf_svc.save()
        services.append(ospf_svc)

    # ── IPv6 ───────────────────────────────────────────────────────
    ipv6_svc = _detect_ipv6(parsed_data)
    if ipv6_svc:
        ipv6_svc.snapshot = snapshot
        ipv6_svc.save()
        services.append(ipv6_svc)

    # ── BGP IPv6 ───────────────────────────────────────────────────
    bgp_ipv6_svc = _detect_bgp_ipv6(parsed_data)
    if bgp_ipv6_svc:
        bgp_ipv6_svc.snapshot = snapshot
        bgp_ipv6_svc.save()
        services.append(bgp_ipv6_svc)

    # ── VPNv6 ──────────────────────────────────────────────────────
    vpnv6_svc = _detect_vpnv6(parsed_data)
    if vpnv6_svc:
        vpnv6_svc.snapshot = snapshot
        vpnv6_svc.save()
        services.append(vpnv6_svc)

    # ── OSPFv3 ─────────────────────────────────────────────────────
    ospfv3_svc = _detect_ospfv3(parsed_data)
    if ospfv3_svc:
        ospfv3_svc.snapshot = snapshot
        ospfv3_svc.save()
        services.append(ospfv3_svc)

    # ── ISIS IPv6 ──────────────────────────────────────────────────
    isis_ipv6_svc = _detect_isis_ipv6(parsed_data)
    if isis_ipv6_svc:
        isis_ipv6_svc.snapshot = snapshot
        isis_ipv6_svc.save()
        services.append(isis_ipv6_svc)

    return services


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
        f"{total_routes} rota(s) estática(s) VRF."
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
        desc = "VRF/VPN-instance(s) detectada(s) sem configuração L3VPN MPLS completa."

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


# ── OSPF ──────────────────────────────────────────────────────────────


def _detect_ospf(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço OSPF."""
    ospf_blocks = parsed_data.get("ospf", [])
    if not ospf_blocks:
        return None

    total_areas = set()
    total_networks = 0
    for ob in ospf_blocks:
        for a in ob.get("areas", []):
            if isinstance(a, dict):
                total_areas.add(a.get("id", str(a)))
            else:
                total_areas.add(a)
        total_networks += len(ob.get("networks", []))

    process_ids = [ob.get("process_id", "?") for ob in ospf_blocks]

    parts = [f"OSPF detectado com {len(ospf_blocks)} processo(s)."]
    parts.append(f"Processo(s): {', '.join(process_ids)}.")
    if total_areas:
        parts.append(f"{len(total_areas)} área(s).")
    if total_networks:
        parts.append(f"{total_networks} rede(s) anunciada(s).")

    has_router_id = any(ob.get("router_id") for ob in ospf_blocks)

    return DetectedService(
        service_type=DetectedService.ServiceType.OSPF,
        name=f"OSPF ({', '.join(process_ids)})",
        description=" ".join(parts),
        confidence=0.85 if has_router_id else 0.75,
        metadata={
            "process_count": len(ospf_blocks),
            "process_ids": process_ids,
            "area_count": len(total_areas),
            "network_count": total_networks,
            "has_router_id": has_router_id,
        },
    )


# ── IPv6 ──────────────────────────────────────────────────────────────


def _detect_ipv6(parsed_data: dict) -> DetectedService | None:
    """Detecta configuração IPv6 geral."""
    interfaces = parsed_data.get("interfaces", [])
    ipv6_ifaces = [i for i in interfaces if i.get("ipv6_enabled")]
    routes = parsed_data.get("ipv6_static_routes", [])
    bgp_blocks = parsed_data.get("bgp", [])

    has_bgp = any(
        bool(bgp.get("ipv6_unicast", {}).get("peers") or bgp.get("ipv6_unicast", {}).get("networks"))
        for bgp in bgp_blocks
    )

    if not ipv6_ifaces and not routes:
        return None

    parts = [f"IPv6 habilitado em {len(ipv6_ifaces)} interface(s)."]
    if routes:
        parts.append(f"{len(routes)} rota(s) estática(s) IPv6.")
    if has_bgp:
        parts.append("BGP IPv6 configurado.")

    iface_names = [i["name"] for i in ipv6_ifaces]
    ipv6_prefix_lists = [pl["name"] for pl in parsed_data.get("prefix_lists", []) if pl.get("is_ipv6")]

    return DetectedService(
        service_type=DetectedService.ServiceType.IPV6,
        name=f"IPv6 ({len(ipv6_ifaces)} interfaces)",
        description=" ".join(parts),
        confidence=0.90 if (ipv6_ifaces and (routes or has_bgp)) else 0.75,
        metadata={
            "interface_count": len(ipv6_ifaces),
            "interfaces": iface_names,
            "route_count": len(routes),
            "has_bgp_ipv6": has_bgp,
            "ipv6_prefix_lists": ipv6_prefix_lists,
        },
    )


def _detect_bgp_ipv6(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço BGP IPv6 unicast."""
    bgp_blocks = parsed_data.get("bgp", [])
    all_ipv6_peers = []
    all_ipv6_networks = []
    for bgp in bgp_blocks:
        ipv6 = bgp.get("ipv6_unicast", {})
        all_ipv6_peers.extend(ipv6.get("peers", []))
        all_ipv6_networks.extend(ipv6.get("networks", []))

    if not all_ipv6_peers and not all_ipv6_networks:
        return None

    enabled_count = sum(1 for p in all_ipv6_peers if p.get("enabled"))
    peer_ips = [p["peer"] for p in all_ipv6_peers if p.get("peer")]

    desc = f"BGP IPv6 com {len(all_ipv6_peers)} peer(s) ({enabled_count} habilitado(s)) e {len(all_ipv6_networks)} rede(s)."

    return DetectedService(
        service_type=DetectedService.ServiceType.BGP_IPV6,
        name=f"BGP IPv6 ({len(all_ipv6_peers)})",
        description=desc,
        confidence=0.85 if enabled_count else 0.60,
        metadata={
            "total_peers": len(all_ipv6_peers),
            "enabled_peers": enabled_count,
            "peer_ips": peer_ips,
            "network_count": len(all_ipv6_networks),
            "networks": all_ipv6_networks,
        },
    )


def _detect_vpnv6(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço BGP VPNv6."""
    bgp_blocks = parsed_data.get("bgp", [])
    all_vpnv6_peers = []
    all_ipv6_vpn_instances = []
    for bgp in bgp_blocks:
        all_vpnv6_peers.extend(bgp.get("vpnv6", {}).get("peers", []))
        for vi in bgp.get("vpn_instances_ipv6", []):
            all_ipv6_vpn_instances.append(vi.get("name", ""))

    if not all_vpnv6_peers and not all_ipv6_vpn_instances:
        return None

    enabled_count = sum(1 for p in all_vpnv6_peers if p.get("enabled"))
    desc = f"VPNv6 com {len(all_vpnv6_peers)} peer(s) ({enabled_count} habilitado(s))."
    if all_ipv6_vpn_instances:
        desc += f" VPN-instance IPv6: {', '.join(all_ipv6_vpn_instances)}."

    return DetectedService(
        service_type=DetectedService.ServiceType.VPNV6,
        name=f"VPNv6 ({len(all_vpnv6_peers)})",
        description=desc,
        confidence=0.85 if enabled_count else 0.60,
        metadata={
            "total_peers": len(all_vpnv6_peers),
            "enabled_peers": enabled_count,
            "ipv6_vpn_instances": all_ipv6_vpn_instances,
        },
    )


def _detect_ospfv3(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço OSPFv3."""
    ospfv3_blocks = parsed_data.get("ospfv3", [])
    interfaces = parsed_data.get("interfaces", [])
    ospfv3_ifaces = [i for i in interfaces if i.get("ospfv3_enabled")]

    if not ospfv3_blocks and not ospfv3_ifaces:
        return None

    process_ids = [o.get("process_id", "?") for o in ospfv3_blocks]
    desc = f"OSPFv3 com {len(ospfv3_blocks)} processo(s) ({', '.join(process_ids)}), {len(ospfv3_ifaces)} interface(s)."

    has_router_id = any(o.get("router_id") for o in ospfv3_blocks)

    return DetectedService(
        service_type=DetectedService.ServiceType.OSPFV3,
        name=f"OSPFv3 ({', '.join(process_ids)})",
        description=desc,
        confidence=0.85 if has_router_id else 0.75,
        metadata={
            "process_count": len(ospfv3_blocks),
            "process_ids": process_ids,
            "interface_count": len(ospfv3_ifaces),
            "has_router_id": has_router_id,
        },
    )


def _detect_isis_ipv6(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço ISIS IPv6."""
    interfaces = parsed_data.get("interfaces", [])
    isis_ipv6_ifaces = [i for i in interfaces if i.get("isis_ipv6_enabled")]

    if not isis_ipv6_ifaces:
        return None

    iface_names = [i["name"] for i in isis_ipv6_ifaces]
    desc = f"ISIS IPv6 habilitado em {len(isis_ipv6_ifaces)} interface(s): {', '.join(iface_names)}."

    return DetectedService(
        service_type=DetectedService.ServiceType.ISIS_IPV6,
        name=f"ISIS IPv6 ({len(isis_ipv6_ifaces)})",
        description=desc,
        confidence=0.85,
        metadata={
            "interface_count": len(isis_ipv6_ifaces),
            "interfaces": iface_names,
        },
    )


# ── BNG Advanced ──────────────────────────────────────────────────


def _detect_bng_advanced(parsed_data: dict) -> DetectedService | None:
    """Detecta serviço BNG Avançado com AAA schemes, RADIUS, IP pools."""
    aaa_blocks = parsed_data.get("aaa", [])
    domains = parsed_data.get("aaa_domains", [])
    radius_blocks = parsed_data.get("radius_servers", [])
    pools = parsed_data.get("ip_pools", [])

    # Check for domains inside AAA blocks too
    has_aaa = bool(aaa_blocks)
    has_standalone_domains = bool(domains)
    has_domains_in_aaa = any(bool(ab.get("domains")) for ab in aaa_blocks)
    has_domains = has_standalone_domains or has_domains_in_aaa
    has_complex_radius = any(r.get("authentication_servers") or r.get("accounting_servers") for r in radius_blocks)
    has_structured_pools = any(p.get("sections") or p.get("type") for p in pools)

    if not (has_aaa and has_domains):
        return None

    # Count schemes
    total_auth = sum(len(ab.get("authentication_schemes", [])) for ab in aaa_blocks)
    total_acct = sum(len(ab.get("accounting_schemes", [])) for ab in aaa_blocks)
    total_authz = sum(len(ab.get("authorization_schemes", [])) for ab in aaa_blocks)

    domain_names = list({d["name"] for d in domains})
    for ab in aaa_blocks:
        for d in ab.get("domains", []):
            if d["name"] not in domain_names:
                domain_names.append(d["name"])

    confidence = 0.90 if (total_auth and total_acct and has_complex_radius) else 0.80

    return DetectedService(
        service_type=DetectedService.ServiceType.BNG_ADVANCED,
        name=f"BNG Avançado ({len(domain_names)} domínios)",
        description=f"BNG Avançado com {total_auth} auth-scheme(s), {total_acct} acct-scheme(s), {total_authz} authz-scheme(s), {len(radius_blocks)} grupo(s) RADIUS, {len(pools)} pool(s).",
        confidence=confidence,
        metadata={
            "domain_count": len(domain_names),
            "domains": domain_names,
            "auth_scheme_count": total_auth,
            "acct_scheme_count": total_acct,
            "authz_scheme_count": total_authz,
            "radius_group_count": len(radius_blocks),
            "ip_pool_count": len(pools),
        },
    )


def _detect_bas_interfaces(parsed_data: dict) -> list[DetectedService]:
    """Detecta interfaces BAS configuradas."""
    services: list[DetectedService] = []
    for iface in parsed_data.get("interfaces", []):
        bas = iface.get("bas")
        if not bas or not bas.get("enabled"):
            continue
        services.append(DetectedService(
            service_type=DetectedService.ServiceType.BAS_INTERFACE,
            name=f"BAS {iface['name']}",
            description=f"BAS interface {iface['name']} com domínio {bas.get('default_domain', 'N/A')}, método {bas.get('authentication_method', 'N/A')}.",
            confidence=0.90,
            metadata={
                "interface": iface["name"],
                "default_domain": bas.get("default_domain"),
                "authentication_method": bas.get("authentication_method"),
                "user_vlan": iface.get("user_vlan"),
            },
        ))
    return services


def _detect_subscriber_domains(parsed_data: dict) -> list[DetectedService]:
    """Detecta domínios de assinante."""
    services: list[DetectedService] = []
    domains_seen: set = set()
    for d in parsed_data.get("aaa_domains", []):
        if d["name"] in domains_seen:
            continue
        domains_seen.add(d["name"])
        services.append(DetectedService(
            service_type=DetectedService.ServiceType.SUBSCRIBER_DOMAIN,
            name=d["name"],
            description=f"Domínio {d['name']} com auth-scheme {d.get('authentication_scheme', 'N/A')}, acct-scheme {d.get('accounting_scheme', 'N/A')}.",
            confidence=0.85,
            metadata={
                "name": d["name"],
                "authentication_scheme": d.get("authentication_scheme"),
                "accounting_scheme": d.get("accounting_scheme"),
                "radius_server_group": d.get("radius_server_group"),
                "ip_pool": d.get("ip_pool"),
            },
        ))
    # Also detect domains inside AAA blocks
    for ab in parsed_data.get("aaa", []):
        for d in ab.get("domains", []):
            if d["name"] in domains_seen:
                continue
            domains_seen.add(d["name"])
            services.append(DetectedService(
                service_type=DetectedService.ServiceType.SUBSCRIBER_DOMAIN,
                name=d["name"],
                description=f"Domínio {d['name']} dentro de AAA com auth-scheme {d.get('authentication_scheme', 'N/A')}.",
                confidence=0.85,
                metadata=d,
            ))
    return services


def _detect_aaa_scheme(parsed_data: dict) -> DetectedService | None:
    """Detecta configuração de AAA schemes."""
    total = 0
    details = []
    for ab in parsed_data.get("aaa", []):
        for s in ab.get("authentication_schemes", []):
            total += 1
            details.append(f"auth {s['name']}({','.join(s.get('authentication_mode', []))})")
        for s in ab.get("accounting_schemes", []):
            total += 1
            details.append(f"acct {s['name']}({','.join(s.get('accounting_mode', []))})")
        for s in ab.get("authorization_schemes", []):
            total += 1
            details.append(f"authz {s['name']}({','.join(s.get('authorization_mode', []))})")
    if not total:
        return None
    return DetectedService(
        service_type=DetectedService.ServiceType.AAA_SCHEME,
        name=f"AAA Scheme ({total})",
        description=f"{total} esquema(s) AAA: {', '.join(details)}.",
        confidence=0.85,
        metadata={"scheme_count": total, "details": details},
    )


def _detect_radius_groups(parsed_data: dict) -> list[DetectedService]:
    """Detecta grupos RADIUS configurados."""
    services: list[DetectedService] = []
    for rg in parsed_data.get("radius_servers", []):
        auth_count = len(rg.get("authentication_servers", []))
        acct_count = len(rg.get("accounting_servers", []))
        services.append(DetectedService(
            service_type=DetectedService.ServiceType.RADIUS_GROUP,
            name=rg["name"],
            description=f"Grupo RADIUS {rg['name']} com {auth_count} servidor(es) auth, {acct_count} servidor(es) acct.",
            confidence=0.90 if auth_count else 0.70,
            metadata={
                "name": rg["name"],
                "authentication_server_count": auth_count,
                "accounting_server_count": acct_count,
                "has_shared_key": rg.get("has_shared_key"),
                "retransmit": rg.get("retransmit"),
                "timeout": rg.get("timeout"),
            },
        ))
    return services
