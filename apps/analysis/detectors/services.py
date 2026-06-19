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
