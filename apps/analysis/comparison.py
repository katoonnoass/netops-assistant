"""Serviço de comparação de configurações.

Compara dois snapshots (base e target) e gera um dicionário
estruturado com diferenças, impactos e recomendações.
Suporta interfaces, rotas estáticas, BGP, ISIS, MPLS, LDP,
VLANs, STP, switching, circuitos, serviços e políticas.
Totalmente determinístico, sem IA.
"""

from __future__ import annotations

import difflib
import hashlib

from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot


def compare_config_snapshots(
    base_snapshot: ConfigSnapshot,
    target_snapshot: ConfigSnapshot,
    title: str = "",
) -> ConfigComparison:
    """Compara dois snapshots e cria um registro ConfigComparison.

    Args:
        base_snapshot: Snapshot base (antes).
        target_snapshot: Snapshot alvo (depois).
        title: Título opcional para a comparação.

    Returns:
        ConfigComparison salvo no banco.
    """
    # Ensure both snapshots are analyzed
    base_parsed = _ensure_analyzed(base_snapshot)
    target_parsed = _ensure_analyzed(target_snapshot)

    base_data = base_parsed.parsed_data
    target_data = target_parsed.parsed_data

    base_circuits = list(DetectedCircuit.objects.filter(snapshot=base_snapshot))
    target_circuits = list(DetectedCircuit.objects.filter(snapshot=target_snapshot))
    base_services = list(DetectedService.objects.filter(snapshot=base_snapshot))
    target_services = list(DetectedService.objects.filter(snapshot=target_snapshot))
    base_issues = list(AnalysisIssue.objects.filter(snapshot=base_snapshot))
    target_issues = list(AnalysisIssue.objects.filter(snapshot=target_snapshot))

    # Raw text diff
    raw_diff = _generate_raw_diff(base_snapshot.raw_config, target_snapshot.raw_config)

    # Structured comparisons
    interfaces = _compare_interfaces(base_data, target_data)
    static_routes = _compare_static_routes(base_data, target_data)
    bgp = _compare_bgp(base_data, target_data)
    vlans = _compare_vlans(base_data, target_data)
    stp_comp = _compare_stp(base_data, target_data)
    circuits = _compare_circuits(base_circuits, target_circuits)
    services = _compare_services(base_services, target_services)
    issues = _compare_issues(base_issues, target_issues)
    isis = _compare_isis(base_data, target_data)
    mpls = _compare_mpls(base_data, target_data)
    mpls_ldp = _compare_mpls_ldp(base_data, target_data)

    # QoS comparison
    qos = _compare_qos(base_data, target_data)

    # Build switching section
    switching = _build_switching_section(interfaces, base_data, target_data)

    # Service-specific impacts
    service_impacts = _build_service_impacts(services)

    # Policy impacts
    policy_impacts = _build_policy_impacts(base_data, target_data)
    switching_impacts = _build_switching_impacts(vlans, stp_comp, switching)
    isis_mpls_impacts = _build_isis_mpls_impacts(isis, mpls, mpls_ldp)
    vpn_instances = _compare_vpn_instances(base_data, target_data)
    vrf_impacts = _build_vrf_impacts(vpn_instances)
    qos_impacts = _build_qos_impacts(qos)
    ipv6_data = _compare_ipv6(base_data, target_data)
    nat = _compare_nat(base_data, target_data)
    ipv6_impacts = _build_ipv6_impacts(ipv6_data)
    nat_impacts = _build_nat_impacts(nat)

    # ── BNG comparison ─────────────────────────────────────────────
    bng_data = _compare_bng(base_data, target_data)
    bng_impacts = _build_bng_impacts(bng_data)

    # ── Multicast comparison ───────────────────────────────────────
    multicast_data = _compare_multicast(base_data, target_data)
    multicast_impacts = _build_multicast_impacts(multicast_data)

    # Validation and rollback plans
    validation_plan = _build_validation_plan(interfaces, static_routes, bgp, services, issues)
    rollback_plan = _build_rollback_plan(interfaces, static_routes, bgp, services)

    # ✦ Add switching validation commands
    if vlans.get("added") or vlans.get("removed") or vlans.get("changed"):
        validation_plan.append({
            "category": "vlan",
            "title": "Validar VLANs alteradas",
            "commands": ["display vlan"],
            "reason": "VLANs foram adicionadas/removidas/alteradas.",
            "severity": "info",
        })
    if stp_comp.get("mode_changed") or stp_comp.get("instances_changed") or stp_comp.get("enabled_changed"):
        validation_plan.append({
            "category": "stp",
            "title": "Validar configura\u00e7\u00e3o STP/MSTP",
            "commands": ["display stp brief", "display stp region-configuration"],
            "reason": "STP foi alterado. Validar risco de loop L2.",
            "severity": "warning",
        })
    if switching.get("eth_trunk_members_changed"):
        for item in switching["eth_trunk_members_changed"]:
            eth_name = item["eth_trunk"]
            eth_id = eth_name.replace("Eth-Trunk", "").replace("Eth-Trunk", "")
            validation_plan.append({
                "category": "eth_trunk",
                "title": f"Validar {eth_name} (membros alterados)",
                "commands": [f"display eth-trunk {eth_id}", f"display interface {eth_name}"],
                "reason": "Membros do Eth-Trunk foram alterados. Validar LACP.",
                "severity": "warning",
            })

        # ✦ Add policy validation commands
    if _has_policy_changes(base_data, target_data):
        validation_plan.append({
            "category": "policy",
            "title": "Validar pol\u00edticas de roteamento alteradas",
            "commands": [
                "display current-configuration | include ip ip-prefix",
                "display current-configuration | include route-policy",
                "display current-configuration | include acl",
                "display current-configuration | include as-path-filter",
                "display current-configuration | include community-filter",
                "display ip ip-prefix",
                "display route-policy",
                "display acl",
            ],
            "commands": [
                "display current-configuration | include ip ip-prefix",
                "display current-configuration | include route-policy",
                "display current-configuration | include acl",
                "display ip ip-prefix",
                "display route-policy",
                "display acl",
            ],
            "reason": "IP-prefixes, route-policies ou ACLs foram alterados.",
            "severity": "warning",
        })
        # Per-BGP peer validation
        from apps.analysis.policy_utils import build_policy_reference_map
        for bgp_block in target_data.get("bgp", []):
            for peer in bgp_block.get("peers", []):
                for d in ("import", "export"):
                    rp_name = peer.get(f"route_policy_{d}")
                    if rp_name:
                        validation_plan.append({
                            "category": "bgp_policy",
                            "title": f"Validar policy {rp_name} (peer {peer.get('ip', '?')}, {d})",
                            "commands": [
                                f"display route-policy {rp_name}",
                                f"display bgp peer {peer.get('ip', '?')}",
                                f"display bgp routing-table peer {peer.get('ip', '?')} advertised-routes",
                                f"display bgp routing-table peer {peer.get('ip', '?')} received-routes",
                            ],
                            "reason": f"Route-policy {rp_name} aplicada no peer BGP {peer.get('ip', '?')} sentido {d}.",
                            "severity": "info",
                        })

    # ✦ Add ISIS validation commands
    if isis.get("added") or isis.get("removed") or isis.get("changed"):
        validation_plan.append({
            "category": "isis",
            "title": "Validar ISIS",
            "commands": [
                "display isis peer",
                "display isis interface",
                "display isis route",
            ],
            "reason": "ISIS foi alterado. Validar adjac\u00eancias e reachability IGP.",
            "severity": "warning",
        })

    # ✦ Add MPLS validation commands
    if mpls.get("enabled_changed") or mpls.get("lsr_id_changed") or mpls.get("te_changed"):
        validation_plan.append({
            "category": "mpls",
            "title": "Validar MPLS",
            "commands": [
                "display mpls lsp",
            ],
            "reason": "MPLS foi alterado. Validar LSP e labels.",
            "severity": "warning",
        })

    # ✦ Add MPLS LDP validation commands
    if mpls_ldp.get("enabled_changed") or mpls_ldp.get("interfaces_changed") or mpls_ldp.get("remote_peers_changed"):
        validation_plan.append({
            "category": "mpls_ldp",
            "title": "Validar MPLS LDP",
            "commands": [
                "display mpls ldp session",
                "display mpls ldp interface",
            ],
            "reason": "LDP foi alterado. Validar sess\u00f5es e troca de labels.",
            "severity": "warning",
        })

    # ✦ Add switching rollback suggestions
    for v in vlans.get("added", []):
        rollback_plan.append({
            "change_type": "vlan_added",
            "object": f"VLAN {v['vlan_id']}",
            "suggestion": "Validar remo\u00e7\u00e3o ap\u00f3s confirmar que n\u00e3o h\u00e1 portas/subinterfaces/QinQ/L2VPN/STP usando-a.",
            "risk_level": "medium",
            "verification_commands": ["display vlan"],
        })
    for v in vlans.get("removed", []):
        rollback_plan.append({
            "change_type": "vlan_removed",
            "object": f"VLAN {v['vlan_id']}",
            "suggestion": "Recriar a VLAN com descri\u00e7\u00e3o/nome anterior.",
            "risk_level": "medium",
            "verification_commands": ["display vlan"],
        })
    for item in switching.get("allowed_vlans_changed", []):
        rollback_plan.append({
            "change_type": "allowed_vlans_changed",
            "object": item["interface"],
            "suggestion": "Restaurar lista anterior de VLANs permitidas no trunk.",
            "risk_level": "medium",
            "verification_commands": [f"display current-configuration interface {item['interface']}"],
        })
    for item in switching.get("access_vlan_changed", []):
        rollback_plan.append({
            "change_type": "access_vlan_changed",
            "object": item["interface"],
            "suggestion": f"Restaurar VLAN de acesso anterior ({item.get('before', '?')}).",
            "risk_level": "medium",
            "verification_commands": [f"display current-configuration interface {item['interface']}"],
        })
    for item in switching.get("pvid_changed", []):
        rollback_plan.append({
            "change_type": "pvid_changed",
            "object": item["interface"],
            "suggestion": f"Restaurar PVID anterior ({item.get('before', '?')}).",
            "risk_level": "medium",
            "verification_commands": [f"display current-configuration interface {item['interface']}"],
        })
    if stp_comp.get("mode_changed") or stp_comp.get("instances_changed"):
        rollback_plan.append({
            "change_type": "stp_changed",
            "object": "STP/MSTP",
            "suggestion": "Rollback de STP deve ser feito com cautela em janela de manuten\u00e7\u00e3o, validando risco de loop L2.",
            "risk_level": "high",
            "verification_commands": ["display stp brief", "display stp region-configuration"],
        })
    # ✦ Add policy rollback suggestions
    from apps.analysis.policy_utils import build_policy_reference_map
    if _has_policy_changes(base_data, target_data):
        rollback_plan.append({
            "change_type": "policy_changed",
            "object": "IP-prefix / Route-Policy / ACL / Filters",
            "suggestion": "Restaurar ip-prefix, route-policy, ACL, as-path-filter ou community-filter anteriores. Validar BGP antes/depois.",
            "risk_level": "high",
            "verification_commands": ["display ip ip-prefix", "display route-policy", "display acl", "display bgp routing-table"],
        })
        # Individual filter rollback suggestions
        all_aspath = [a["name"] for a in base_data.get("as_path_filters", [])]
        all_aspath += [a["name"] for a in target_data.get("as_path_filters", [])]
        for fname in sorted(set(all_aspath)):
            rollback_plan.append({
                "change_type": "as_path_filter_changed",
                "object": f"AS-path filter {fname}",
                "suggestion": "Restaurar regra anterior do as-path-filter.",
                "risk_level": "medium",
                "verification_commands": [f"display current-configuration | include as-path-filter {fname}"],
            })
        all_comm = [c["name"] for c in base_data.get("community_filters", [])]
        all_comm += [c["name"] for c in target_data.get("community_filters", [])]
        for fname in sorted(set(all_comm)):
            rollback_plan.append({
                "change_type": "community_filter_changed",
                "object": f"Community-filter {fname}",
                "suggestion": "Restaurar regra anterior do community-filter.",
                "risk_level": "medium",
                "verification_commands": [f"display current-configuration | include community-filter {fname}"],
            })

    # ✦ Add ISIS rollback suggestions
    if isis.get("added") or isis.get("removed") or isis.get("changed"):
        rollback_plan.append({
            "change_type": "isis_changed",
            "object": "ISIS",
            "suggestion": "Restaurar configura\u00e7\u00e3o ISIS anterior. Revalidar adjac\u00eancias IGP e reachability de loopbacks.",
            "risk_level": "high",
            "verification_commands": ["display isis peer", "display isis route"],
        })
    if isis.get("network_entity_changed"):
        rollback_plan.append({
            "change_type": "isis_network_entity_changed",
            "object": "Network-entity ISIS",
            "suggestion": "Restaurar network-entity anterior. Isso pode derrubar adjac\u00eancias temporariamente.",
            "risk_level": "critical",
            "verification_commands": ["display isis peer", "display current-configuration | include isis"],
        })

    # ✦ Add MPLS rollback suggestions
    if mpls.get("lsr_id_changed"):
        rollback_plan.append({
            "change_type": "mpls_lsr_id_changed",
            "object": "MPLS LSR ID",
            "suggestion": "Restaurar LSR ID anterior. Pode interromper labels e sess\u00f5es LDP.",
            "risk_level": "high",
            "verification_commands": ["display mpls lsp", "display mpls ldp session"],
        })

    # ✦ Add MPLS LDP rollback suggestions
    if mpls_ldp.get("interfaces_changed"):
        rollback_plan.append({
            "change_type": "mpls_ldp_interface_changed",
            "object": "Interface LDP",
            "suggestion": "Restaurar interfaces LDP anteriores. Pode impactar transporte MPLS.",
            "risk_level": "high",
            "verification_commands": ["display mpls ldp interface", "display mpls lsp"],
        })
    if mpls_ldp.get("remote_peers_changed"):
        rollback_plan.append({
            "change_type": "mpls_ldp_remote_peer_changed",
            "object": "Remote-peer LDP",
            "suggestion": "Restaurar remote-peers LDP anteriores e validar sess\u00e3o remota.",
            "risk_level": "high",
            "verification_commands": ["display mpls ldp session"],
        })

    for item in switching.get("eth_trunk_members_changed", []):
        rollback_plan.append({
            "change_type": "eth_trunk_members_changed",
            "object": item["eth_trunk"],
            "suggestion": "Restaurar membros f\u00edsicos anteriores e validar LACP/redund\u00e2ncia.",
            "risk_level": "high",
            "verification_commands": [f"display eth-trunk {item['eth_trunk'].replace('Eth-Trunk', '')}", f"display interface {item['eth_trunk']}"],
        })

    # Impacts and recommendations
    multicast_data = _compare_multicast(base_data, target_data)
    multicast_impacts = _build_multicast_impacts(multicast_data)
    impacts = _build_impacts(interfaces, static_routes, bgp, circuits, issues)
    impacts.extend(service_impacts)
    impacts.extend(switching_impacts)
    impacts.extend(policy_impacts)
    impacts.extend(isis_mpls_impacts)
    impacts.extend(vrf_impacts)
    impacts.extend(qos_impacts)
    impacts.extend(nat_impacts)
    impacts.extend(ipv6_impacts)

    impacts.extend(multicast_impacts)

    impacts.extend(bng_impacts)

    # ✦ Add BNG validation/rollback (only if real BNG changes exist)
    def _has_bng_changes(d):
        for section in d.values():
            if isinstance(section, dict):
                if section.get("added") or section.get("removed") or section.get("changed"):
                    return True
        return False
    if _has_bng_changes(bng_data):
        validation_plan.append({
            "category": "bng",
            "title": "Validar configuração BNG/AAA alterada",
            "commands": [
                "display access-user domain ",
                "display access-user interface ",
                "display aaa configuration",
                "display domain",
                "display radius-server configuration group ",
                "display ip pool name ",
                "display ip pool usage",
            ],
            "reason": "BNG/AAA/RADIUS/IP pool alterado. Validar autenticação, accounting e pools de assinantes.",
            "severity": "warning",
        })
        rollback_plan.append({
            "change_type": "bng",
            "object": "domain/scheme/radius/pool/bas",
            "suggestion": "Restaurar domínio, AAA schemes, RADIUS group, IP pool e BAS interface anteriores. Validar usuários online e accounting.",
            "risk_level": "warning",
            "verification_commands": [
                "display access-user domain ",
                "display aaa configuration",
                "display domain",
                "display radius-server configuration group ",
                "display ip pool name ",
            ],
        })

    # ✦ Add PPPoE validation/rollback (only if real PPPoE changes exist)
    def _has_pppoe_changes(d):
        for section in [d.get("pppoe_interfaces", {}), d.get("virtual_templates", {})]:
            if section.get("added") or section.get("removed") or section.get("changed"):
                return True
        return False
    # ✦ Add HA validation/rollback (only if real HA changes exist)
    def _has_ha_changes(d):
        for section in [d.get("bfd", {}), d.get("bgp_ha", {}), d.get("isis_ha", {}), d.get("nsr", {}), d.get("ldp_ha", {})]:
            if section.get("added") or section.get("removed") or section.get("changed"):
                return True
        return False
    if _has_ha_changes(bng_data):
        validation_plan.append({
            "category": "ha",
            "title": "Validar configuracao HA/BFD/GR alterada",
            "commands": [
                "display bfd session all",
                "display bfd session all verbose",
                "display bgp peer",
                "display isis peer",
                "display isis interface",
                "display ospf peer",
                "display ospf interface",
                "display ospfv3 peer",
                "display mpls ldp session",
                "display current-configuration | include bfd",
                "display current-configuration | include graceful-restart",
                "display current-configuration | include nsr",
                "display current-configuration | include non-stop-routing",
            ],
            "reason": "HA/BFD/GR/NSR alterado. Validar convergencia e alta disponibilidade.",
            "severity": "warning",
        })
        rollback_plan.append({
            "change_type": "ha",
            "object": "bfd/gr/nsr/ldp",
            "suggestion": "Restaurar sessoes BFD, timers, GR, NSR e LDP GR anteriores. Validar peers e sessoes apos rollback.",
            "risk_level": "warning",
            "verification_commands": [
                "display bfd session all",
                "display bgp peer",
                "display isis peer",
                "display current-configuration | include bfd",
                "display current-configuration | include graceful-restart",
            ],
        })

    # ✦ Add multicast validation/rollback (only if real multicast changes exist)
    def _has_multicast_changes(d):
        for section in ["global", "pim", "igmp", "igmp_snooping", "mld", "vpn_instances"]:
            s = d.get(section, {})
            if s.get("added") or s.get("removed") or s.get("changed"):
                return True
        return False

    multicast_data = _compare_multicast(base_data, target_data)
    if _has_multicast_changes(multicast_data):
        validation_plan.append({
            "category": "multicast",
            "title": "Validar configuracao multicast/PIM/IGMP/MLD alterada",
            "commands": [
                "display multicast routing-table",
                "display pim routing-table",
                "display pim neighbor",
                "display pim interface",
                "display igmp group",
                "display igmp interface",
                "display igmp-snooping vlan",
                "display mld group",
                "display mld interface",
                "display current-configuration | include multicast",
                "display current-configuration | include pim",
                "display current-configuration | include igmp",
                "display current-configuration | include mld",
            ],
            "reason": "Multicast/PIM/IGMP/MLD alterado. Validar tabelas e vizinhanca.",
            "severity": "warning",
        })
        rollback_plan.append({
            "change_type": "multicast",
            "object": "multicast/pim/igmp/mld",
            "suggestion": "Restaurar configuracao multicast/PIM/IGMP/MLD anterior. Validar grupos e vizinhanca apos rollback.",
            "risk_level": "warning",
            "verification_commands": [
                "display multicast routing-table",
                "display pim routing-table",
                "display pim neighbor",
                "display igmp group",
                "display igmp-snooping vlan",
                "display current-configuration | include multicast",
            ],
        })

    if _has_pppoe_changes(bng_data):
        validation_plan.append({
            "category": "pppoe",
            "title": "Validar configuracao PPPoE alterada",
            "commands": [
                "display pppoe-server session summary",
                "display access-user interface ",
                "display access-user domain ",
                "display current-configuration interface ",
                "display current-configuration interface Virtual-Template",
                "display aaa configuration",
                "display radius-server configuration",
                "display ip pool name ",
            ],
            "reason": "PPPoE/Virtual-Template alterado. Validar sessoes e autenticacao PPPoE.",
            "severity": "warning",
        })
        rollback_plan.append({
            "change_type": "pppoe",
            "object": "pppoe/virtual-template/bas",
            "suggestion": "Restaurar bind PPPoE, Virtual-Template, authentication-mode, max-sessions e BAS/domain anteriores. Validar sessoes PPPoE e access-user.",
            "risk_level": "warning",
            "verification_commands": [
                "display pppoe-server session summary",
                "display access-user interface ",
                "display current-configuration interface ",
                "display aaa configuration",
            ],
        })

    # ✦ Add IPv6 validation commands (only if real IPv6 changes exist)
    def _has_ipv6_changes(d):
        """Check if any section of an IPv6 diff dict has actual changes."""
        for section in d.values():
            if isinstance(section, dict):
                if section.get("added") or section.get("removed") or section.get("changed"):
                    return True
        return False
    if _has_ipv6_changes(ipv6_data):
        validation_plan.append({
            "category": "ipv6",
            "title": "Validar configuração IPv6 alterada",
            "commands": ["display ipv6 interface brief", "display ipv6 routing-table",
                         "display bgp ipv6 peer", "display bgp ipv6 routing-table",
                         "display bgp vpnv6 all peer", "display ospfv3 peer",
                         "display ospfv3 interface", "display isis peer", "display isis interface",
                         "display current-configuration | include ipv6"],
            "reason": "IPv6 foi alterado. Validar interfaces, rotas, peers e tabelas.",
            "severity": "warning",
        })
        rollback_plan.append({
            "change_type": "ipv6",
            "object": "interface/rota/peer",
            "suggestion": "Restaurar IPv6 address anterior. Verificar rota IPv6. Restaurar peer BGP IPv6. Restaurar VPNv6. Validar tabela IPv6 antes/depois.",
            "risk_level": "warning",
            "verification_commands": [
                "display ipv6 routing-table",
                "display bgp ipv6 peer",
            ],
        })

    recommendations = _build_recommendations(interfaces, static_routes, bgp, circuits, issues)

    # Build summary
    huawei_advanced = _compare_huawei_advanced(base_data, target_data)
    if any(huawei_advanced.values()):
        changed_categories = [
            item["category"]
            for key in ("added", "removed", "changed")
            for item in huawei_advanced[key]
        ]
        impacts.append({
            "severity": "warning",
            "category": "huawei_advanced",
            "description": "Recursos Huawei avançados alterados: " + ", ".join(changed_categories),
        })
        validation_plan.append({
            "severity": "warning",
            "title": "Validar recursos Huawei avançados",
            "reason": "EVPN/VXLAN, SR, MPLS-TE, CGNAT, MSDP, telemetria ou BGP avançado foram alterados.",
            "commands": [
                "display evpn vpn-instance",
                "display vxlan vni",
                "display segment-routing prefix mpls forwarding",
                "display mpls te tunnel",
                "display nat session table",
                "display msdp peer",
                "display telemetry subscription",
                "display bgp peer",
            ],
        })
        rollback_plan.append({
            "change_type": "huawei_advanced",
            "object": ", ".join(changed_categories),
            "suggestion": "Restaurar os blocos avançados anteriores e validar control-plane e forwarding.",
            "risk_level": "warning",
            "verification_commands": [
                "display current-configuration | include evpn|vxlan|segment-routing|mpls te|nat instance|msdp|telemetry",
            ],
        })
    zte_olt = _compare_zte_olt(base_data, target_data)
    if any(section["added"] or section["removed"] or section["changed"] for section in zte_olt.values()):
        changed_sections = [
            section
            for section, changes in zte_olt.items()
            if changes.get("added") or changes.get("removed") or changes.get("changed")
        ]
        impacts.append({
            "severity": "warning",
            "category": "zte_olt",
            "description": "Estrutura ZTE OLT alterada: " + ", ".join(changed_sections),
        })
        validation_plan.append({
            "severity": "warning",
            "title": "Validar inventário ZTE OLT alterado",
            "reason": "Portas PON, ONUs, VLANs ou service-ports foram alterados.",
            "commands": [
                "show running-config | include gpon-olt|gpon-onu|service-port|tcont|gemport|vlan",
                "show gpon onu state",
                "show gpon onu by serial-number",
            ],
        })
        rollback_plan.append({
            "change_type": "zte_olt",
            "object": ", ".join(changed_sections),
            "suggestion": "Restaurar os blocos ZTE OLT anteriores e validar PON/ONU/service-port antes de reabrir clientes.",
            "risk_level": "warning",
            "verification_commands": [
                "show running-config | include gpon-olt|gpon-onu|service-port",
                "show gpon onu state",
            ],
        })
    summary_parts = [
        f"Comparação: {title}" if title else f"Comparação de snapshots.",
        f"Interfaces: {_fmt_summary(interfaces)}.",
        f"Rotas estáticas: {_fmt_summary(static_routes)}.",
        f"BGP: {_fmt_bgp_summary(bgp)}.",
        f"VPN-instances: {_fmt_summary(vpn_instances)}.",
        f"ISIS: {_fmt_summary(isis)}.",
        f"MPLS: {_fmt_mpls_summary(mpls)}.",
        f"MPLS LDP: {_fmt_mpls_ldp_summary(mpls_ldp)}.",
        f"Circuitos: {_fmt_summary(circuits)}.",
        f"Serviços: {_fmt_summary(services)}.",
        f"Multicast: {_fmt_multicast_summary(multicast_data)}.",
        f"Huawei avançado: {len(huawei_advanced.get('changed', []))} seção(ões) alterada(s).",
        f"ZTE OLT: {sum(len(zte_olt[key]) for key in zte_olt)} alteração(ões).",
        f"Issues: {issues.get('new_count', 0)} nova(s), "
        f"{issues.get('resolved_count', 0)} resolvida(s).",
    ]

    diff_data = {
        "raw_diff": raw_diff,
        "interfaces": interfaces,
        "static_routes": static_routes,
        "bgp": bgp,
        "isis": isis,
        "vpn_instances": vpn_instances,
        "qos": qos,
        "mpls": mpls,
        "mpls_ldp": mpls_ldp,
        "vlans": vlans,
        "stp": stp_comp,
        "switching": switching,
        "ip_prefixes": _compare_ip_prefixes(base_data, target_data),
        "route_policies": _compare_route_policies(base_data, target_data),
        "acls": _compare_acls(base_data, target_data),
        "as_path_filters": _compare_as_path_filters(base_data, target_data),
        "community_filters": _compare_community_filters(base_data, target_data),
        "policy_dependencies": _compare_policy_deps(base_data, target_data),
        "circuits": circuits,
        "services": services,
        "issues": issues,
        "ipv6": ipv6_data,
        "bng": _compare_bng(base_data, target_data),
        "multicast": multicast_data,
        "huawei_advanced": huawei_advanced,
        "zte_olt": zte_olt,
        "impacts": impacts,
        "recommendations": recommendations,
        "validation_plan": validation_plan,
        "rollback_plan": rollback_plan,
    }

    comparison = ConfigComparison.objects.create(
        base_snapshot=base_snapshot,
        target_snapshot=target_snapshot,
        title=title,
        summary=" ".join(summary_parts),
        diff_data=diff_data,
    )
    return comparison


def _compare_huawei_advanced(base_data: dict, target_data: dict) -> dict:
    base = base_data.get("huawei_advanced", {})
    target = target_data.get("huawei_advanced", {})
    result = {"added": [], "removed": [], "changed": []}
    for category in sorted(set(base) | set(target)):
        before = base.get(category, {})
        after = target.get(category, {})
        before_enabled = bool(before.get("enabled")) or any(
            value for key, value in before.items() if key.endswith("_enabled")
        )
        after_enabled = bool(after.get("enabled")) or any(
            value for key, value in after.items() if key.endswith("_enabled")
        )
        if not before_enabled and after_enabled:
            result["added"].append({"category": category, "after": after})
        elif before_enabled and not after_enabled:
            result["removed"].append({"category": category, "before": before})
        elif before != after:
            result["changed"].append({"category": category, "before": before, "after": after})
    return result


def _compare_zte_olt(base_data: dict, target_data: dict) -> dict:
    """Compare ZTE OLT GPON inventory between two snapshots."""
    base = base_data.get("zte_olt", {})
    target = target_data.get("zte_olt", {})
    result = {
        "pon_ports": {"added": [], "removed": [], "changed": []},
        "onus": {"added": [], "removed": [], "changed": []},
        "service_ports": {"added": [], "removed": [], "changed": []},
        "vlans": {"added": [], "removed": [], "changed": []},
    }

    def compare_list(section: str, base_items: list[dict], target_items: list[dict], key_fn):
        base_map = {key_fn(item): item for item in base_items}
        target_map = {key_fn(item): item for item in target_items}
        for key in sorted(set(base_map) | set(target_map)):
            before = base_map.get(key)
            after = target_map.get(key)
            if before is None:
                result[section]["added"].append(after)
            elif after is None:
                result[section]["removed"].append(before)
            elif before != after:
                result[section]["changed"].append({"key": key, "before": before, "after": after})

    compare_list("pon_ports", base.get("pon_ports", []), target.get("pon_ports", []), lambda item: item.get("name", item.get("pon", "")))
    compare_list("onus", base.get("onus", []), target.get("onus", []), lambda item: f"{item.get('pon', '')}:{item.get('onu_id', '')}")
    compare_list("service_ports", base.get("service_ports", []), target.get("service_ports", []), lambda item: str(item.get("id", "")))
    compare_list("vlans", base.get("vlans", []), target.get("vlans", []), lambda item: str(item.get("vlan_id", "")))
    return result


def _ensure_analyzed(snapshot: ConfigSnapshot) -> ParsedConfig:
    """Garante que o snapshot tenha ParsedConfig, analisando se necessário."""
    parsed = ParsedConfig.objects.filter(snapshot=snapshot).first()
    if parsed is None:
        parsed = analyze_config_snapshot(snapshot)
    return parsed


def _fmt_summary(d: dict) -> str:
    added = len(d.get("added", []))
    removed = len(d.get("removed", []))
    changed = len(d.get("changed", []))
    parts = []
    if added:
        parts.append(f"{added} adicionada(s)")
    if removed:
        parts.append(f"{removed} removida(s)")
    if changed:
        parts.append(f"{changed} alterada(s)")
    if not parts:
        return "sem mudanças"
    return ", ".join(parts)


# ── NAT comparison ─────────────────────────────────────────────────────


def _fmt_multicast_summary(d: dict) -> str:
    parts = []
    for section, label in [("pim_global", "PIM global"), ("pim_interfaces", "PIM interfaces"), ("igmp_interfaces", "IGMP"), ("mld_interfaces", "MLD"), ("igmp_snooping", "IGMP snooping")]:
        s = d.get(section, {})
        if isinstance(s, dict):
            a = len(s.get("added", [])); r = len(s.get("removed", [])); c = len(s.get("changed", []))
            if a or r or c:
                parts.append(f"{label}: {a}+ {r}- {c}~")
    if not parts:
        return "sem mudanças"
    return "; ".join(parts)


def _ag_key(ag: dict) -> str:
    return ag.get("name", "")


# ── BNG comparison ─────────────────────────────────────────────────────


def _collect_bng_domains(parsed_data: dict) -> list[dict]:
    """Collect all domains from AAA blocks and standalone domains."""
    domains = []
    seen = set()
    for ab in parsed_data.get("aaa", []):
        for d in ab.get("domains", []):
            dn = d.get("name", "")
            if dn and dn not in seen:
                seen.add(dn)
                domains.append(d)
    for d in parsed_data.get("aaa_domains", []):
        dn = d.get("name", "")
        if dn and dn not in seen:
            seen.add(dn)
            domains.append(d)
    return domains


def _collect_bng_auth_schemes(parsed_data: dict) -> list[dict]:
    """Collect all AAA schemes from AAA blocks."""
    schemes = []
    for ab in parsed_data.get("aaa", []):
        for s in ab.get("authentication_schemes", []):
            schemes.append(s)
        for s in ab.get("authorization_schemes", []):
            schemes.append(s)
        for s in ab.get("accounting_schemes", []):
            schemes.append(s)
    return schemes


def _compare_bng_domains(base_domains: list, target_domains: list) -> dict:
    """Compare subscriber domains."""
    base_map = {d.get("name", ""): d for d in base_domains}
    target_map = {d.get("name", ""): d for d in target_domains}
    base_names = set(base_map.keys())
    target_names = set(target_map.keys())

    added = sorted(target_names - base_names)
    removed = sorted(base_names - target_names)
    common = sorted(base_names & target_names)

    changed = []
    for name in common:
        b = base_map[name]
        t = target_map[name]
        changes = {}
        mappings = [
            ("authentication_scheme", "authentication-scheme"),
            ("accounting_scheme", "accounting-scheme"),
            ("authorization_scheme", "authorization-scheme"),
            ("radius_server_group", "radius-server group"),
            ("ip_pool", "ip-pool"),
            ("dns_primary", "DNS primary"),
            ("dns_secondary", "DNS secondary"),
        ]
        for key, label in mappings:
            if b.get(key) != t.get(key):
                changes[key] = {"before": b.get(key), "after": t.get(key), "label": label}
        if changes:
            changed.append({"name": name, "changes": changes})
    return {"added": added, "removed": removed, "changed": changed}


def _compare_bng_radius_groups(base_radius: list, target_radius: list) -> dict:
    """Compare RADIUS server groups."""
    base_map = {r.get("name", ""): r for r in base_radius}
    target_map = {r.get("name", ""): r for r in target_radius}
    base_names = set(base_map.keys())
    target_names = set(target_map.keys())

    added = sorted(target_names - base_names)
    removed = sorted(base_names - target_names)
    common = sorted(base_names & target_names)

    changed = []
    for name in common:
        b = base_map[name]
        t = target_map[name]
        changes = {}

        # Compare auth servers
        b_auth = b.get("authentication_servers", [])
        t_auth = t.get("authentication_servers", [])
        if _server_lists_differ(b_auth, t_auth):
            changes["authentication_servers"] = {
                "before": _summarize_servers(b_auth),
                "after": _summarize_servers(t_auth),
                "label": "servidores de autenticação",
            }

        # Compare acct servers
        b_acct = b.get("accounting_servers", [])
        t_acct = t.get("accounting_servers", [])
        if _server_lists_differ(b_acct, t_acct):
            changes["accounting_servers"] = {
                "before": _summarize_servers(b_acct),
                "after": _summarize_servers(t_acct),
                "label": "servidores de accounting",
            }

        # Compare retransmit/timeout
        for key, label in [("retransmit", "retransmit"), ("timeout", "timeout")]:
            if b.get(key) != t.get(key):
                changes[key] = {"before": b.get(key), "after": t.get(key), "label": label}

        # Compare shared-key type (never show the actual key)
        if b.get("shared_key_type") != t.get("shared_key_type"):
            changes["shared_key_type"] = {
                "before": b.get("shared_key_type", "unknown"),
                "after": t.get("shared_key_type", "unknown"),
                "label": "tipo de shared-key",
            }

        if changes:
            changed.append({"name": name, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed}


def _server_lists_differ(a: list, b: list) -> bool:
    """Check if two server lists differ (IP/port/weight)."""
    if len(a) != len(b):
        return True
    key = lambda s: (s.get("ip", ""), s.get("port"), s.get("weight"))
    return sorted(key(s) for s in a) != sorted(key(s) for s in b)


def _summarize_servers(servers: list) -> list:
    """Summarize servers for display (no secrets)."""
    return [{"ip": s.get("ip"), "port": s.get("port"), "weight": s.get("weight")} for s in servers]


def _compare_bng_ip_pools(base_pools: list, target_pools: list) -> dict:
    """Compare IP pools."""
    base_map = {p.get("name", ""): p for p in base_pools}
    target_map = {p.get("name", ""): p for p in target_pools}
    base_names = set(base_map.keys())
    target_names = set(target_map.keys())

    added = sorted(target_names - base_names)
    removed = sorted(base_names - target_names)
    common = sorted(base_names & target_names)

    changed = []
    for name in common:
        b = base_map[name]
        t = target_map[name]
        changes = {}

        for key, label in [
            ("gateway", "gateway"), ("mask", "máscara"),
            ("lease", "lease"), ("radius_server_group", "RADIUS group"),
            ("mode", "modo"), ("type", "tipo"),
        ]:
            if b.get(key) != t.get(key):
                changes[key] = {"before": b.get(key), "after": t.get(key), "label": label}

        # Compare DNS servers
        b_dns = sorted(b.get("dns_servers", []))
        t_dns = sorted(t.get("dns_servers", []))
        if b_dns != t_dns:
            changes["dns_servers"] = {"before": b_dns, "after": t_dns, "label": "DNS servers"}

        # Compare sections
        b_sections = sorted(s.get("start_ip", "") for s in b.get("sections", []))
        t_sections = sorted(s.get("start_ip", "") for s in t.get("sections", []))
        if b_sections != t_sections:
            changes["sections"] = {"before": b.get("sections", []), "after": t.get("sections", []), "label": "seções/ranges"}

        if changes:
            changed.append({"name": name, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed}


def _compare_bng_bas_interfaces(base_interfaces: list, target_interfaces: list) -> dict:
    """Compare BAS interfaces."""
    base_map = {i.get("name", ""): i for i in base_interfaces if i.get("bas", {}).get("enabled")}
    target_map = {i.get("name", ""): i for i in target_interfaces if i.get("bas", {}).get("enabled")}
    base_names = set(base_map.keys())
    target_names = set(target_map.keys())

    added = sorted(target_names - base_names)
    removed = sorted(base_names - target_names)
    common = sorted(base_names & target_names)

    changed = []
    for name in common:
        b = base_map[name]
        t = target_map[name]
        changes = {}

        # Description
        if b.get("description") != t.get("description"):
            changes["description"] = {"before": b.get("description"), "after": t.get("description"), "label": "descrição"}

        # User VLAN / QinQ
        if b.get("user_vlan") != t.get("user_vlan"):
            changes["user_vlan"] = {"before": b.get("user_vlan"), "after": t.get("user_vlan"), "label": "user-vlan"}
        if b.get("qinq_vlan") != t.get("qinq_vlan"):
            changes["qinq_vlan"] = {"before": b.get("qinq_vlan"), "after": t.get("qinq_vlan"), "label": "qinq-vlan"}

        # BAS attributes
        b_bas = b.get("bas", {})
        t_bas = t.get("bas", {})
        for key, label in [
            ("default_domain", "default-domain"),
            ("pre_authentication_domain", "pre-auth domain"),
            ("authentication_method", "authentication-method"),
            ("access_type", "access-type"),
            ("accounting_copy_radius_group", "accounting-copy RADIUS group"),
        ]:
            if b_bas.get(key) != t_bas.get(key):
                changes[key] = {"before": b_bas.get(key), "after": t_bas.get(key), "label": label}

        # Triggers
        for key, label in [("ip_trigger", "ip-trigger"), ("arp_trigger", "arp-trigger"), ("ipv6_trigger", "ipv6-trigger")]:
            if b_bas.get(key) != t_bas.get(key):
                changes[key] = {"before": b_bas.get(key), "after": t_bas.get(key), "label": label}

        if changes:
            changed.append({"name": name, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed}


def _compare_pppoe_virtual_templates(base_vts: list, target_vts: list) -> dict:
    """Compare Virtual-Templates."""
    base_map = {vt.get("name", ""): vt for vt in base_vts}
    target_map = {vt.get("name", ""): vt for vt in target_vts}
    base_names = set(base_map.keys())
    target_names = set(target_map.keys())

    added = sorted(target_names - base_names)
    removed = sorted(base_names - target_names)
    common = sorted(base_names & target_names)

    changed = []
    for name in common:
        b = base_map[name]
        t = target_map[name]
        changes = {}
        for key, label in [
            ("description", "descrição"),
            ("mtu", "MTU"),
            ("ip_unnumbered_interface", "ip unnumbered"),
            ("remote_address_pool", "remote address pool"),
            ("ppp_keepalive", "PPP keepalive"),
            ("ppp_mru", "PPP MRU"),
            ("ipv6_enabled", "IPv6"),
        ]:
            if b.get(key) != t.get(key):
                changes[key] = {"before": b.get(key), "after": t.get(key), "label": label}
        # Compare auth modes as sorted list
        b_modes = sorted(b.get("ppp_authentication_modes", []))
        t_modes = sorted(t.get("ppp_authentication_modes", []))
        if b_modes != t_modes:
            changes["ppp_authentication_modes"] = {
                "before": b_modes, "after": t_modes,
                "label": "PPP authentication-mode",
            }
        if changes:
            changed.append({"name": name, "changes": changes})
    return {"added": added, "removed": removed, "changed": changed}


def _compare_pppoe_interfaces(base_interfaces: list, target_interfaces: list) -> dict:
    """Compare PPPoE server bind on interfaces."""
    base_map = {}
    for i in base_interfaces:
        p = i.get("pppoe_server")
        if p and p.get("enabled"):
            base_map[i["name"]] = (i, p)
    target_map = {}
    for i in target_interfaces:
        p = i.get("pppoe_server")
        if p and p.get("enabled"):
            target_map[i["name"]] = (i, p)

    base_names = set(base_map.keys())
    target_names = set(target_map.keys())
    added = sorted(target_names - base_names)
    removed = sorted(base_names - target_names)
    common = sorted(base_names & target_names)

    changed = []
    for name in common:
        b_iface, b_pppoe = base_map[name]
        t_iface, t_pppoe = target_map[name]
        changes = {}

        # PPPoE attributes
        for key, label in [
            ("virtual_template", "Virtual-Template"),
            ("max_sessions", "max-sessions"),
        ]:
            if b_pppoe.get(key) != t_pppoe.get(key):
                changes[key] = {"before": b_pppoe.get(key), "after": t_pppoe.get(key), "label": label}

        # Interface attributes
        for key, label in [
            ("user_vlan", "user-vlan"),
            ("qinq_vlan", "qinq-vlan"),
            ("description", "descrição"),
        ]:
            if b_iface.get(key) != t_iface.get(key):
                changes[key] = {"before": b_iface.get(key), "after": t_iface.get(key), "label": label}

        # BAS attributes
        b_bas = b_iface.get("bas", {})
        t_bas = t_iface.get("bas", {})
        if b_bas.get("default_domain") != t_bas.get("default_domain"):
            changes["default_domain"] = {"before": b_bas.get("default_domain"), "after": t_bas.get("default_domain"), "label": "default-domain"}

        if changes:
            changed.append({"name": name, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed}


def _compare_ha(base, target):
    """Compare HA/BFD/GR/NSR configuration."""
    result = {
        "bfd": {"added": [], "removed": [], "changed": []},
        "bgp_ha": {"added": [], "removed": [], "changed": []},
        "ospf_ha": {"changed": []},
        "isis_ha": {"changed": []},
        "ldp_ha": {"changed": []},
        "nsr": {"changed": []},
    }

    # BFD sessions (compare all keys including discriminators)
    BFD_COMPARE_KEYS = [
        "peer_ip", "peer_ipv6", "interface",
        "local_discriminator", "remote_discriminator",
        "min_tx_interval", "min_rx_interval", "detect_multiplier", "committed",
    ]
    b_base = {s.get("name", ""): s for s in base.get("ha", {}).get("bfd", {}).get("sessions", [])}
    b_target = {s.get("name", ""): s for s in target.get("ha", {}).get("bfd", {}).get("sessions", [])}
    for name, s in b_target.items():
        if name not in b_base:
            result["bfd"]["added"].append(name)
        elif any(s.get(k) != b_base[name].get(k) for k in BFD_COMPARE_KEYS):
            result["bfd"]["changed"].append({"name": name, "changes": {k: {"before": b_base[name].get(k), "after": s.get(k)} for k in BFD_COMPARE_KEYS if s.get(k) != b_base[name].get(k)}})
    for name in b_base:
        if name not in b_target:
            result["bfd"]["removed"].append(name)

    # BGP HA (BFD/GR per peer)
    base_peers = {}
    target_peers = {}
    for bgp in base.get("bgp", []):
        for p in bgp.get("peers", []):
            base_peers[p["ip"]] = p
    for bgp in target.get("bgp", []):
        for p in bgp.get("peers", []):
            target_peers[p["ip"]] = p
    for ip, p in target_peers.items():
        if ip not in base_peers:
            continue
        bp = base_peers[ip]
        changes = {}
        if bp.get("bfd_enabled") != p.get("bfd_enabled"):
            changes["bfd_enabled"] = {"before": bp.get("bfd_enabled"), "after": p.get("bfd_enabled")}
        if bp.get("graceful_restart") != p.get("graceful_restart"):
            changes["graceful_restart"] = {"before": bp.get("graceful_restart"), "after": p.get("graceful_restart")}
        if changes:
            result["bgp_ha"]["changed"].append({"peer": ip, "changes": changes})

    # GR/NSR
    for k in ("bgp", "isis", "ospf", "ldp"):
        b_gr = base.get("ha", {}).get("graceful_restart", {}).get(k)
        t_gr = target.get("ha", {}).get("graceful_restart", {}).get(k)
        if b_gr != t_gr:
            result["isis_ha"]["changed"].append({"protocol": k, "key": "graceful_restart", "before": b_gr, "after": t_gr})
        b_nsr = base.get("ha", {}).get("nsr", {}).get(k)
        t_nsr = target.get("ha", {}).get("nsr", {}).get(k)
        if b_nsr != t_nsr:
            result["nsr"]["changed"].append({"protocol": k, "before": b_nsr, "after": t_nsr})

    return result


def _compare_bng(base, target):
    """Compare BNG/AAA/RADIUS/IP pool config between two parsed configs."""
    # Collect data from parsed_data
    base_domains = _collect_bng_domains(base)
    target_domains = _collect_bng_domains(target)
    base_radius = base.get("radius_servers", [])
    target_radius = target.get("radius_servers", [])
    base_pools = base.get("ip_pools", [])
    target_pools = target.get("ip_pools", [])
    base_interfaces = base.get("interfaces", [])
    target_interfaces = target.get("interfaces", [])

    # PPPoE / Virtual-Template
    base_vts = [i for i in base_interfaces if i.get("name", "").lower().startswith("virtual-template")]
    target_vts = [i for i in target_interfaces if i.get("name", "").lower().startswith("virtual-template")]

    # HA comparison
    ha_data = _compare_ha(base, target)

    return {
        "subscriber_domains": _compare_bng_domains(base_domains, target_domains),
        "radius_groups": _compare_bng_radius_groups(base_radius, target_radius),
        "ip_pools": _compare_bng_ip_pools(base_pools, target_pools),
        "bas_interfaces": _compare_bng_bas_interfaces(base_interfaces, target_interfaces),
        "pppoe_interfaces": _compare_pppoe_interfaces(base_interfaces, target_interfaces),
        "virtual_templates": _compare_pppoe_virtual_templates(base_vts, target_vts),
    } | ha_data

def _compare_ipv6(base, target):
    """Compare IPv6 configuration between two parsed configs."""
    result = {
        "interfaces": {"added": [], "removed": [], "changed": []},
        "routes": {"added": [], "removed": [], "changed": []},
        "bgp_peers": {"added": [], "removed": [], "changed": []},
        "bgp_networks": {"added": [], "removed": [], "changed": []},
        "prefix_lists": {"added": [], "removed": [], "changed": []},
        "vpnv6_peers": {"added": [], "removed": [], "changed": []},
        "ospfv3": {"added": [], "removed": [], "changed": []},
        "isis_ipv6": {"added": [], "removed": [], "changed": []},
    }

    # Helper
    def ipv6_key(iface):
        key_data = {"name": iface["name"], "addrs": []}
        for a in iface.get("ipv6_addresses", []):
            key_data["addrs"].append(f"{a['address']}/{a['prefix_length']}")
        return key_data

    # Interfaces
    base_ifaces = {i["name"]: i for i in base.get("interfaces", []) if i.get("ipv6_addresses")}
    target_ifaces = {i["name"]: i for i in target.get("interfaces", []) if i.get("ipv6_addresses")}
    for name, i in target_ifaces.items():
        if name not in base_ifaces:
            result["interfaces"]["added"].append(ipv6_key(i))
        elif ipv6_key(i) != ipv6_key(base_ifaces[name]):
            result["interfaces"]["changed"].append({"name": name, "old": ipv6_key(base_ifaces[name]), "new": ipv6_key(i)})
    for name, i in base_ifaces.items():
        if name not in target_ifaces:
            result["interfaces"]["removed"].append(ipv6_key(i))

    # Routes
    base_routes = {r.get("prefix", ""): r for r in base.get("ipv6_static_routes", [])}
    target_routes = {r.get("prefix", ""): r for r in target.get("ipv6_static_routes", [])}
    for prefix, r in target_routes.items():
        if prefix not in base_routes:
            result["routes"]["added"].append(r)
        elif r.get("next_hop") != base_routes[prefix].get("next_hop"):
            result["routes"]["changed"].append({"prefix": prefix, "old": base_routes[prefix], "new": r})
    for prefix, r in base_routes.items():
        if prefix not in target_routes:
            result["routes"]["removed"].append(r)

    # BGP IPv6
    def bgp_ipv6_key(bgp):
        peers = []
        for p in bgp.get("ipv6_unicast", {}).get("peers", []):
            peers.append({"peer": p.get("peer"), "enabled": p.get("enabled"), "rpi": p.get("route_policy_import"), "rpe": p.get("route_policy_export")})
        nets = bgp.get("ipv6_unicast", {}).get("networks", [])
        return {"peers": peers, "networks": nets}

    base_bgp = base.get("bgp", [])
    target_bgp = target.get("bgp", [])
    base_key = bgp_ipv6_key({"ipv6_unicast": base_bgp[0].get("ipv6_unicast", {})}) if base_bgp else {"peers": [], "networks": []}
    target_key = bgp_ipv6_key({"ipv6_unicast": target_bgp[0].get("ipv6_unicast", {})}) if target_bgp else {"peers": [], "networks": []}

    # Peers
    base_peers = {p["peer"]: p for p in base_key["peers"]}
    target_peers = {p["peer"]: p for p in target_key["peers"]}
    for peer, p in target_peers.items():
        if peer not in base_peers:
            result["bgp_peers"]["added"].append(p)
        elif p != base_peers[peer]:
            result["bgp_peers"]["changed"].append({"peer": peer, "old": base_peers[peer], "new": p})
    for peer, p in base_peers.items():
        if peer not in target_peers:
            result["bgp_peers"]["removed"].append(p)

    # Networks (supports both string and dict formats)
    def _net_key(n):
        if isinstance(n, dict):
            return n.get("prefix", n.get("network", str(n)))
        return str(n)
    base_net_keys = set(_net_key(n) for bgp in base_bgp for n in bgp.get("ipv6_unicast", {}).get("networks", []))
    target_net_keys = set(_net_key(n) for bgp in target_bgp for n in bgp.get("ipv6_unicast", {}).get("networks", []))
    result["bgp_networks"]["added"] = list(target_net_keys - base_net_keys)
    result["bgp_networks"]["removed"] = list(base_net_keys - target_net_keys)

    # Prefix-lists
    base_pl = {pl["name"]: pl for pl in base.get("prefix_lists", []) if pl.get("is_ipv6")}
    target_pl = {pl["name"]: pl for pl in target.get("prefix_lists", []) if pl.get("is_ipv6")}
    for name, pl in target_pl.items():
        if name not in base_pl:
            result["prefix_lists"]["added"].append(pl)
        elif pl != base_pl[name]:
            result["prefix_lists"]["changed"].append({"name": name, "old": base_pl[name], "new": pl})
    for name, pl in base_pl.items():
        if name not in target_pl:
            result["prefix_lists"]["removed"].append(pl)

    # VPNv6
    base_vpnv6 = {p["peer"]: p for bgp in base_bgp for p in bgp.get("vpnv6", {}).get("peers", [])}
    target_vpnv6 = {p["peer"]: p for bgp in target_bgp for p in bgp.get("vpnv6", {}).get("peers", [])}
    for peer, p in target_vpnv6.items():
        if peer not in base_vpnv6:
            result["vpnv6_peers"]["added"].append(p)
        elif p != base_vpnv6[peer]:
            result["vpnv6_peers"]["changed"].append({"peer": peer, "old": base_vpnv6[peer], "new": p})
    for peer, p in base_vpnv6.items():
        if peer not in target_vpnv6:
            result["vpnv6_peers"]["removed"].append(p)

    # OSPFv3
    base_ospfv3 = {o["process_id"]: o for o in base.get("ospfv3", [])}
    target_ospfv3 = {o["process_id"]: o for o in target.get("ospfv3", [])}
    for pid, o in target_ospfv3.items():
        if pid not in base_ospfv3:
            result["ospfv3"]["added"].append(o)
        elif o != base_ospfv3[pid]:
            result["ospfv3"]["changed"].append({"process_id": pid, "old": base_ospfv3[pid], "new": o})
    for pid, o in base_ospfv3.items():
        if pid not in target_ospfv3:
            result["ospfv3"]["removed"].append(o)

    # ISIS IPv6
    def isis_ipv6_key(iface):
        return {"name": iface["name"], "pid": iface.get("isis_ipv6_process_id"), "cost": iface.get("isis_ipv6_cost")}
    base_isis = {i["name"]: isis_ipv6_key(i) for i in base.get("interfaces", []) if i.get("isis_ipv6_enabled")}
    target_isis = {i["name"]: isis_ipv6_key(i) for i in target.get("interfaces", []) if i.get("isis_ipv6_enabled")}
    for name, i in target_isis.items():
        if name not in base_isis:
            result["isis_ipv6"]["added"].append(i)
        elif i != base_isis[name]:
            result["isis_ipv6"]["changed"].append({"name": name, "old": base_isis[name], "new": i})
    for name, i in base_isis.items():
        if name not in target_isis:
            result["isis_ipv6"]["removed"].append(i)

    return result

def _compare_nat(base_data: dict, target_data: dict) -> dict:
    base_nat = base_data.get("nat", {})
    target_nat = target_data.get("nat", {})
    base_ag = {_ag_key(a): a for a in base_nat.get("address_groups", [])}
    target_ag = {_ag_key(a): a for a in target_nat.get("address_groups", [])}
    ag_changed = []
    for n in sorted(set(base_ag) & set(target_ag)):
        if base_ag[n] != target_ag[n]:
            ag_changed.append({"name": n})
    ob_added = [o for o in target_nat.get("outbound_rules", []) if o not in base_nat.get("outbound_rules", [])]
    ob_removed = [o for o in base_nat.get("outbound_rules", []) if o not in target_nat.get("outbound_rules", [])]
    st_added = [s for s in target_nat.get("static_rules", []) if s not in base_nat.get("static_rules", [])]
    st_removed = [s for s in base_nat.get("static_rules", []) if s not in target_nat.get("static_rules", [])]
    sv_added = [s for s in target_nat.get("server_rules", []) if s not in base_nat.get("server_rules", [])]
    sv_removed = [s for s in base_nat.get("server_rules", []) if s not in target_nat.get("server_rules", [])]
    alg_changed = base_nat.get("alg", []) != target_nat.get("alg", [])
    return {
        "address_groups": {"changed": ag_changed,
            "added": [target_ag[n] for n in sorted(set(target_ag) - set(base_ag))],
            "removed": [base_ag[n] for n in sorted(set(base_ag) - set(target_ag))]},
        "outbound_rules": {"added": ob_added, "removed": ob_removed},
        "static_rules": {"added": st_added, "removed": st_removed},
        "server_rules": {"added": sv_added, "removed": sv_removed},
        "alg_changed": alg_changed,
    }


def _build_ipv6_impacts(ipv6_data):
    """Build impact descriptions for IPv6 changes."""
    impacts = []
    if not isinstance(ipv6_data, dict) or not ipv6_data:
        return impacts
    ifaces = ipv6_data.get("interfaces", {})
    routes = ipv6_data.get("routes", {})
    peers = ipv6_data.get("bgp_peers", {})
    vpnv6 = ipv6_data.get("vpnv6_peers", {})
    ospf = ipv6_data.get("ospfv3", {})
    isis = ipv6_data.get("isis_ipv6", {})
    if ifaces.get("added") or ifaces.get("removed") or ifaces.get("changed"):
        impacts.append({
            "impact": "Endereco IPv6 alterado em interface.",
            "detail": "Pode impactar conectividade IPv6.",
            "severity": "warning",
        })
    if routes.get("added") or routes.get("removed") or routes.get("changed"):
        impacts.append({
            "impact": "Rota IPv6 alterada.",
            "detail": "Pode impactar encaminhamento IPv6.",
            "severity": "warning",
        })
    if peers.get("added") or peers.get("removed") or peers.get("changed"):
        impacts.append({
            "impact": "BGP IPv6 peer alterado.",
            "detail": "Pode impactar rotas BGP IPv6.",
            "severity": "warning",
        })
    if vpnv6.get("added") or vpnv6.get("removed") or vpnv6.get("changed"):
        impacts.append({
            "impact": "VPNv6 alterado.",
            "detail": "Pode impactar L3VPN IPv6.",
            "severity": "warning",
        })
    if ospf.get("added") or ospf.get("removed") or ospf.get("changed"):
        impacts.append({
            "impact": "OSPFv3 alterado.",
            "detail": "Pode impactar roteamento IPv6 interno.",
            "severity": "warning",
        })
    if isis.get("added") or isis.get("removed") or isis.get("changed"):
        impacts.append({
            "impact": "ISIS IPv6 alterado.",
            "detail": "Pode impactar roteamento IPv6 interno.",
            "severity": "warning",
        })
    return impacts

def _build_nat_impacts(nat: dict) -> list[dict]:
    impacts = []
    if nat.get("address_groups", {}).get("changed"):
        impacts.append({"impact": "Address-group NAT alterado.", "detail": "Pode mudar pool publico usado por clientes.", "severity": "warning"})
    if nat.get("outbound_rules", {}).get("added") or nat.get("outbound_rules", {}).get("removed"):
        impacts.append({"impact": "NAT outbound alterado.", "detail": "Pode impactar saida de clientes para Internet.", "severity": "warning"})
    if nat.get("static_rules", {}).get("added") or nat.get("static_rules", {}).get("removed"):
        impacts.append({"impact": "NAT static alterado.", "detail": "Pode impactar publicacao de servicos.", "severity": "warning"})
    if nat.get("server_rules", {}).get("added") or nat.get("server_rules", {}).get("removed"):
        impacts.append({"impact": "NAT server alterado.", "detail": "Validar portas publicadas.", "severity": "warning"})
    if nat.get("alg_changed"):
        impacts.append({"impact": "ALG alterado.", "detail": "Validar aplicacoes afetadas.", "severity": "info"})
    return impacts


def _fmt_nat_summary(nat: dict) -> str:
    parts = []
    for k, label in [("outbound_rules", "outbound"), ("static_rules", "static"), ("server_rules", "server")]:
        v = nat.get(k, {})
        a = len(v.get("added", []))
        r = len(v.get("removed", []))
        if a:
            parts.append(f"{a} {label} adicionado(s)")
        if r:
            parts.append(f"{r} {label} removido(s)")
    ag = nat.get("address_groups", {})
    if ag.get("changed"):
        parts.append(f"{len(ag['changed'])} address-group(s) alterado(s)")
    if not parts:
        return "sem mudancas"
    return ", ".join(parts)


# ── BNG impacts ────────────────────────────────────────────────────────


def _build_bng_impacts(bng: dict) -> list[dict]:
    """Generate impact statements for BNG changes."""
    impacts = []
    bas = bng.get("bas_interfaces", {})
    domains = bng.get("subscriber_domains", {})
    radius = bng.get("radius_groups", {})
    pools = bng.get("ip_pools", {})

    if bas.get("added") or bas.get("removed"):
        impacts.append({"impact": "BAS interface adicionada ou removida.", "detail": "Pode impactar autenticacao de assinantes.", "severity": "warning"})
    for c in bas.get("changed", []):
        ch = c.get("changes", {})
        if "default_domain" in ch:
            impacts.append({"impact": f"Default-domain alterado na BAS {c['name']}: {ch['default_domain']['before']} -> {ch['default_domain']['after']}.", "detail": "Pode impactar autenticacao e perfil dos assinantes.", "severity": "warning"})
        if "authentication_method" in ch:
            impacts.append({"impact": f"Authentication-method alterado na BAS {c['name']}: {ch['authentication_method']['before']} -> {ch['authentication_method']['after']}.", "detail": "Pode impactar metodo de login dos assinantes.", "severity": "warning"})
        if "user_vlan" in ch:
            impacts.append({"impact": f"User-VLAN alterada na BAS {c['name']}: {ch['user_vlan']['before']} -> {ch['user_vlan']['after']}.", "detail": "Pode impactar assinantes dessa VLAN.", "severity": "warning"})
    if domains.get("changed"):
        impacts.append({"impact": "Domain de assinante alterado.", "detail": "Pode impactar autenticacao, accounting ou pool de IPs.", "severity": "warning"})
    if radius.get("changed"):
        has_auth = any("authentication_servers" in c.get("changes", {}) for c in radius.get("changed", []))
        has_acct = any("accounting_servers" in c.get("changes", {}) for c in radius.get("changed", []))
        if has_auth:
            impacts.append({"impact": "Servidor RADIUS de autenticacao alterado.", "detail": "Pode impactar login dos assinantes.", "severity": "high"})
        if has_acct:
            impacts.append({"impact": "Servidor RADIUS de accounting alterado.", "detail": "Pode impactar bilhetagem/controle.", "severity": "high"})
    if pools.get("changed"):
        impacts.append({"impact": "IP pool alterado.", "detail": "Pode impactar entrega de IP aos assinantes.", "severity": "warning"})

    # PPPoE impacts
    vt = bng.get("virtual_templates", {})
    pppoe_if = bng.get("pppoe_interfaces", {})
    if vt.get("changed") or vt.get("added") or vt.get("removed"):
        impacts.append({"impact": "Virtual-Template alterada.", "detail": "Pode impactar sessoes PPPoE.", "severity": "warning"})
    for c in vt.get("changed", []):
        ch = c.get("changes", {})
        if "ppp_authentication_modes" in ch:
            impacts.append({"impact": f"PPP authentication-mode alterado na Virtual-Template {c['name']}.", "detail": "Pode impactar login dos assinantes.", "severity": "high"})
    if pppoe_if.get("changed") or pppoe_if.get("added") or pppoe_if.get("removed"):
        impacts.append({"impact": "PPPoE server bind alterado.", "detail": "Pode impactar autenticacao de assinantes.", "severity": "warning"})
    for c in pppoe_if.get("changed", []):
        ch = c.get("changes", {})
        if "max_sessions" in ch:
            impacts.append({"impact": f"Max-sessions alterado na PPPoE {c['name']}: {ch['max_sessions']['before']} -> {ch['max_sessions']['after']}.", "detail": "Pode impactar capacidade de acesso.", "severity": "warning"})
        if "user_vlan" in ch:
            impacts.append({"impact": f"User-VLAN alterada na PPPoE {c['name']}: {ch['user_vlan']['before']} -> {ch['user_vlan']['after']}.", "detail": "Pode impactar assinantes dessa VLAN.", "severity": "warning"})

    # HA impacts
    bfd = bng.get("bfd", {})
    bgp_ha = bng.get("bgp_ha", {})
    isis_ha = bng.get("isis_ha", {})
    nsr = bng.get("nsr", {})
    ldp_ha = bng.get("ldp_ha", {})
    if bfd.get("changed") or bfd.get("added") or bfd.get("removed"):
        impacts.append({"impact": "BFD alterado. Pode impactar tempo de convergencia.", "detail": "Sessoes BFD foram adicionadas, removidas ou alteradas.", "severity": "warning"})
    for c in bgp_ha.get("changed", []):
        if c.get("changes", {}).get("bfd_enabled", {}).get("after") is False:
            impacts.append({"impact": f"BFD removido de peer BGP {c['peer']}. Falhas podem demorar mais para convergir.", "detail": "", "severity": "warning"})
    if any(c.get("changes", {}).get("graceful_restart") for c in bgp_ha.get("changed", [])):
        impacts.append({"impact": "Graceful Restart alterado. Pode impactar reconvergencia sem flap.", "detail": "", "severity": "warning"})
    if nsr.get("changed"):
        impacts.append({"impact": "NSR alterado. Pode impactar alta disponibilidade.", "detail": "", "severity": "warning"})
    if any(c.get("key") == "graceful_restart" for c in isis_ha.get("changed", []) if c.get("protocol") == "ldp"):
        impacts.append({"impact": "LDP GR alterado. Pode impactar estabilidade MPLS apos falha.", "detail": "", "severity": "warning"})
    return impacts


# ── NAT comparison ─────────────────────────────────────────────────────


def _ag_key(ag: dict) -> str:
    return ag.get("name", "")


def _compare_nat(base_data: dict, target_data: dict) -> dict:
    """Compare NAT configuration."""
    base_nat = base_data.get("nat", {})
    target_nat = target_data.get("nat", {})
    base_ag = {_ag_key(a): a for a in base_nat.get("address_groups", [])}
    target_ag = {_ag_key(a): a for a in target_nat.get("address_groups", [])}
    ag_changed = []
    for n in sorted(set(base_ag) & set(target_ag)):
        if base_ag[n] != target_ag[n]:
            ag_changed.append({"name": n})
    ob_added = [o for o in target_nat.get("outbound_rules", []) if o not in base_nat.get("outbound_rules", [])]
    ob_removed = [o for o in base_nat.get("outbound_rules", []) if o not in target_nat.get("outbound_rules", [])]
    st_added = [s for s in target_nat.get("static_rules", []) if s not in base_nat.get("static_rules", [])]
    st_removed = [s for s in base_nat.get("static_rules", []) if s not in target_nat.get("static_rules", [])]
    sv_added = [s for s in target_nat.get("server_rules", []) if s not in base_nat.get("server_rules", [])]
    sv_removed = [s for s in base_nat.get("server_rules", []) if s not in target_nat.get("server_rules", [])]
    alg_changed = base_nat.get("alg", []) != target_nat.get("alg", [])
    return {
        "address_groups": {"changed": ag_changed,
            "added": [target_ag[n] for n in sorted(set(target_ag) - set(base_ag))],
            "removed": [base_ag[n] for n in sorted(set(base_ag) - set(target_ag))]},
        "outbound_rules": {"added": ob_added, "removed": ob_removed},
        "static_rules": {"added": st_added, "removed": st_removed},
        "server_rules": {"added": sv_added, "removed": sv_removed},
        "alg_changed": alg_changed,
    }


def _build_nat_impacts(nat: dict) -> list[dict]:
    impacts = []
    if nat.get("address_groups", {}).get("changed"):
        impacts.append({"impact": "Address-group NAT alterado.", "detail": "Pode mudar pool publico usado por clientes.", "severity": "warning"})
    if nat.get("outbound_rules", {}).get("added") or nat.get("outbound_rules", {}).get("removed"):
        impacts.append({"impact": "NAT outbound alterado.", "detail": "Pode impactar saida de clientes para Internet.", "severity": "warning"})
    if nat.get("static_rules", {}).get("added") or nat.get("static_rules", {}).get("removed"):
        impacts.append({"impact": "NAT static alterado.", "detail": "Pode impactar publicacao de servicos.", "severity": "warning"})
    if nat.get("server_rules", {}).get("added") or nat.get("server_rules", {}).get("removed"):
        impacts.append({"impact": "NAT server alterado.", "detail": "Validar portas publicadas.", "severity": "warning"})
    if nat.get("alg_changed"):
        impacts.append({"impact": "ALG alterado.", "detail": "Validar aplicacoes afetadas.", "severity": "info"})
    return impacts


def _fmt_nat_summary(nat: dict) -> str:
    parts = []
    for k, label in [("outbound_rules", "outbound"), ("static_rules", "static"), ("server_rules", "server")]:
        v = nat.get(k, {})
        a = len(v.get("added", []))
        r = len(v.get("removed", []))
        if a:
            parts.append(f"{a} {label} adicionado(s)")
        if r:
            parts.append(f"{r} {label} removido(s)")
    ag = nat.get("address_groups", {})
    if ag.get("changed"):
        parts.append(f"{len(ag['changed'])} address-group(s) alterado(s)")
    if not parts:
        return "sem mudancas"
    return ", ".join(parts)


def _fmt_bgp_summary(bgp: dict) -> str:
    parts = []
    peers_added = len(bgp.get("peers_added", []))
    peers_removed = len(bgp.get("peers_removed", []))
    nets_added = len(bgp.get("networks_added", []))
    nets_removed = len(bgp.get("networks_removed", []))
    if peers_added:
        parts.append(f"{peers_added} peer(s) adicionado(s)")
    if peers_removed:
        parts.append(f"{peers_removed} peer(s) removido(s)")
    if nets_added:
        parts.append(f"{nets_added} rede(s) adicionada(s)")
    if nets_removed:
        parts.append(f"{nets_removed} rede(s) removida(s)")
    if bgp.get("local_as_changed"):
        parts.append("AS local alterado")
    if not parts:
        return "sem mudanças"
    return ", ".join(parts)


# ── Raw diff ───────────────────────────────────────────────────────────


def _generate_raw_diff(base_text: str, target_text: str) -> dict:
    base_lines = base_text.splitlines(keepends=True)
    target_lines = target_text.splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(
            base_lines,
            target_lines,
            fromfile="base",
            tofile="target",
            n=3,
        )
    )
    # Limit to 2000 lines
    truncated = len(diff_lines) > 2000
    if truncated:
        diff_lines = diff_lines[:2000]

    added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))

    return {
        "lines": "".join(diff_lines),
        "added_count": added,
        "removed_count": removed,
        "truncated": truncated,
    }


# ── Interface comparison ───────────────────────────────────────────────


def _interface_key(iface: dict) -> str:
    return iface.get("name", "")


def _compare_interfaces(base_data: dict, target_data: dict) -> dict:
    base_ifaces = {_interface_key(i): i for i in base_data.get("interfaces", [])}
    target_ifaces = {_interface_key(i): i for i in target_data.get("interfaces", [])}

    base_names = set(base_ifaces.keys())
    target_names = set(target_ifaces.keys())

    added_names = target_names - base_names
    removed_names = base_names - target_names
    common_names = base_names & target_names

    added = [_make_iface_summary(target_ifaces[n]) for n in sorted(added_names)]
    removed = [_make_iface_summary(base_ifaces[n]) for n in sorted(removed_names)]

    changed = []
    for name in sorted(common_names):
        changes = _detect_iface_changes(base_ifaces[name], target_ifaces[name])
        if changes:
            changed.append({"name": name, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed}


def _make_iface_summary(iface: dict) -> dict:
    return {
        "name": iface.get("name"),
        "type": iface.get("type"),
        "description": iface.get("description"),
        "ip_address": iface.get("ip_address"),
        "vlan_id": iface.get("vlan_id"),
        "vsi_name": iface.get("vsi_name"),
    }


def _detect_iface_changes(base: dict, target: dict) -> list[dict]:
    changes = []
    fields = ["description", "ip_address", "vlan_id", "second_vlan_id", "vsi_name", "shutdown",
              "port_mode", "access_vlan", "trunk_allowed_vlans", "trunk_pvid",
              "stp_enabled", "stp_disabled", "stp_edge_port"]
    for field in fields:
        bv = base.get(field)
        tv = target.get(field)
        if bv != tv:
            changes.append({
                "field": field,
                "from": bv,
                "to": tv,
            })
    return changes


# ── Static route comparison ────────────────────────────────────────────


def _route_key(route: dict) -> str:
    vpn = route.get("vpn_instance") or ""
    return f"{vpn}|{route.get('network', '')}/{route.get('netmask', '')} via {route.get('next_hop', '')}"


def _compare_static_routes(base_data: dict, target_data: dict) -> dict:
    base_routes = {_route_key(r): r for r in base_data.get("static_routes", [])}
    target_routes = {_route_key(r): r for r in target_data.get("static_routes", [])}

    base_keys = set(base_routes.keys())
    target_keys = set(target_routes.keys())

    added_keys = target_keys - base_keys
    removed_keys = base_keys - target_keys
    common_keys = base_keys & target_keys

    added = [_make_route_summary(target_routes[k]) for k in sorted(added_keys)]
    removed = [_make_route_summary(base_routes[k]) for k in sorted(removed_keys)]

    changed = []
    for key in sorted(common_keys):
        changes = _detect_route_changes(base_routes[key], target_routes[key])
        if changes:
            changed.append({"key": key, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed}


def _make_route_summary(route: dict) -> dict:
    vpn = route.get("vpn_instance")
    dest = f"{route.get('network', '?')}/{route.get('netmask', '?')}"
    if vpn:
        dest = f"[{vpn}] {dest}"
    return {
        "destination": dest,
        "network": route.get("network"),
        "netmask": route.get("netmask"),
        "next_hop": route.get("next_hop"),
        "description": route.get("description"),
        "preference": route.get("preference", "60"),
        "vpn_instance": vpn,
    }


def _detect_route_changes(base: dict, target: dict) -> list[dict]:
    changes = []
    fields = ["next_hop", "description", "preference", "tag", "vpn_instance"]
    for field in fields:
        bv = base.get(field)
        tv = target.get(field)
        if bv != tv:
            changes.append({"field": field, "from": bv, "to": tv})
    return changes


# ── BGP comparison ─────────────────────────────────────────────────────


def _compare_bgp(base_data: dict, target_data: dict) -> dict:
    base_bgps = base_data.get("bgp", [])
    target_bgps = target_data.get("bgp", [])

    base_as = base_bgps[0].get("as_number") if base_bgps else None
    target_as = target_bgps[0].get("as_number") if target_bgps else None
    local_as_changed = (base_as != target_as) and base_as is not None and target_as is not None

    # Compare peers
    base_peers = {}
    for bgp in base_bgps:
        for p in bgp.get("peers", []):
            base_peers[p["ip"]] = p
    target_peers = {}
    for bgp in target_bgps:
        for p in bgp.get("peers", []):
            target_peers[p["ip"]] = p

    base_peer_ips = set(base_peers.keys())
    target_peer_ips = set(target_peers.keys())

    peers_added = [target_peers[ip] for ip in sorted(target_peer_ips - base_peer_ips)]
    peers_removed = [base_peers[ip] for ip in sorted(base_peer_ips - target_peer_ips)]

    peers_changed = []
    for ip in sorted(base_peer_ips & target_peer_ips):
        bp = base_peers[ip]
        tp = target_peers[ip]
        pchanges = []
        bgp_fields = [
            "remote_as", "description", "route_policy_import",
            "route_policy_export", "connect_interface",
            "has_password", "enabled",
        ]
        for field in bgp_fields:
            bv = bp.get(field)
            tv = tp.get(field)
            if bv != tv:
                pchanges.append({"field": field, "from": bv, "to": tv})
        if pchanges:
            peers_changed.append({"ip": ip, "changes": pchanges})

    # Compare networks
    base_nets = set()
    for bgp in base_bgps:
        for n in bgp.get("networks", []):
            base_nets.add(n)
    target_nets = set()
    for bgp in target_bgps:
        for n in bgp.get("networks", []):
            target_nets.add(n)

    networks_added = sorted(target_nets - base_nets)
    networks_removed = sorted(base_nets - target_nets)

    return {
        "base_as": base_as,
        "target_as": target_as,
        "local_as_changed": local_as_changed,
        "peers_added": peers_added,
        "peers_removed": peers_removed,
        "peers_changed": peers_changed,
        "networks_added": networks_added,
        "networks_removed": networks_removed,
    }


# ── Circuit comparison ─────────────────────────────────────────────────


def _circuit_key(circuit: DetectedCircuit) -> str:
    d = circuit.details
    parts = [circuit.circuit_type, str(d.get("interface", "")), str(d.get("vlan_id", ""))]
    rp = d.get("routed_prefix") or d.get("vsi_name") or str(d.get("second_vlan_id", ""))
    parts.append(str(rp))
    return "|".join(parts)


def _compare_circuits(base_list: list, target_list: list) -> dict:
    base = {_circuit_key(c): c for c in base_list}
    target = {_circuit_key(c): c for c in target_list}
    base_keys = set(base.keys())
    target_keys = set(target.keys())
    return {
        "added": [_circuit_summary(target[k]) for k in sorted(target_keys - base_keys)],
        "removed": [_circuit_summary(base[k]) for k in sorted(base_keys - target_keys)],
        "changed": [],
    }


def _circuit_summary(c: DetectedCircuit) -> dict:
    d = c.details
    return {
        "type": c.circuit_type,
        "type_display": c.get_circuit_type_display(),
        "interface": d.get("interface"),
        "vlan_id": d.get("vlan_id"),
        "routed_prefix": d.get("routed_prefix"),
        "vsi_name": d.get("vsi_name"),
        "description": c.description,
    }


# ── Service comparison ─────────────────────────────────────────────────


def _service_key(svc: DetectedService) -> str:
    return f"{svc.service_type}|{svc.name}"


def _compare_services(base_list: list, target_list: list) -> dict:
    base = {_service_key(s): s for s in base_list}
    target = {_service_key(s): s for s in target_list}
    base_keys = set(base.keys())
    target_keys = set(target.keys())
    return {
        "added": [_service_summary(target[k]) for k in sorted(target_keys - base_keys)],
        "removed": [_service_summary(base[k]) for k in sorted(base_keys - target_keys)],
        "changed": [],
    }


def _service_summary(s: DetectedService) -> dict:
    return {
        "service_type": s.service_type,
        "type_display": s.get_service_type_display(),
        "name": s.name,
        "confidence": s.confidence,
    }


# ── Issue comparison ───────────────────────────────────────────────────


def _issue_key(issue: AnalysisIssue) -> str:
    meta = issue.metadata or {}
    return f"{issue.code}|{meta.get('interface', '')}|{meta.get('next_hop', '')}|{meta.get('peer_ip', '')}"


def _compare_issues(base_list: list, target_list: list) -> dict:
    base = {_issue_key(i): i for i in base_list}
    target = {_issue_key(i): i for i in target_list}
    base_keys = set(base.keys())
    target_keys = set(target.keys())

    new_keys = target_keys - base_keys
    resolved_keys = base_keys - target_keys
    unchanged_keys = base_keys & target_keys

    return {
        "new": [_issue_summary(target[k]) for k in sorted(new_keys)],
        "resolved": [_issue_summary(base[k]) for k in sorted(resolved_keys)],
        "unchanged": [_issue_summary(target[k]) for k in sorted(unchanged_keys)],
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "unchanged_count": len(unchanged_keys),
    }


def _issue_summary(issue: AnalysisIssue) -> dict:
    return {
        "code": issue.code,
        "severity": issue.severity,
        "severity_display": issue.get_severity_display(),
        "title": issue.title,
        "description": issue.description,
    }



# ── VLAN comparison ──────────────────────────────────────────────────


def _vlan_key(vlan: dict) -> int:
    return vlan.get("vlan_id", 0)



# ── Policy comparison helpers ─────────────────────────────────────────


def _has_policy_changes(base_data: dict, target_data: dict) -> bool:
    """Check if any policy data changed between base and target."""
    for key in ("prefix_lists", "route_policies", "acls"):
        b = base_data.get(key, [])
        t = target_data.get(key, [])
        if str(b) != str(t):
            return True
    return False


def _compare_as_path_filters(base_data: dict, target_data: dict) -> dict:
    """Compare AS-path filters between base and target."""
    base = {af.get("name"): af for af in base_data.get("as_path_filters", [])}
    target = {af.get("name"): af for af in target_data.get("as_path_filters", [])}
    result: dict = {"added": [], "removed": [], "changed": []}
    added = set(target) - set(base)
    removed = set(base) - set(target)
    for name in sorted(added):
        result["added"].append({"name": name, "rules": target[name].get("rules", [])})
    for name in sorted(removed):
        result["removed"].append({"name": name, "rules": base[name].get("rules", [])})
    for name in sorted(set(base) & set(target)):
        if base[name] != target[name]:
            result["changed"].append({"name": name, "before": base[name].get("rules"), "after": target[name].get("rules")})
    return result


def _compare_community_filters(base_data: dict, target_data: dict) -> dict:
    """Compare community filters between base and target."""
    base = {cf.get("name"): cf for cf in base_data.get("community_filters", [])}
    target = {cf.get("name"): cf for cf in target_data.get("community_filters", [])}
    result: dict = {"added": [], "removed": [], "changed": []}
    added = set(target) - set(base)
    removed = set(base) - set(target)
    for name in sorted(added):
        result["added"].append({"name": name, "type": target[name].get("type"), "rules": target[name].get("rules", [])})
    for name in sorted(removed):
        result["removed"].append({"name": name, "type": base[name].get("type"), "rules": base[name].get("rules", [])})
    for name in sorted(set(base) & set(target)):
        if base[name] != target[name]:
            result["changed"].append({"name": name, "type": base[name].get("type"), "before": base[name].get("rules"), "after": target[name].get("rules")})
    return result


def _compare_ip_prefixes(base_data: dict, target_data: dict) -> dict:
    """Compare IP prefix-lists between base and target."""
    base = {p["name"]: p for p in base_data.get("prefix_lists", [])}
    target = {p["name"]: p for p in target_data.get("prefix_lists", [])}
    result: dict = {"added": [], "removed": [], "changed": []}
    added = set(target) - set(base)
    removed = set(base) - set(target)
    for name in sorted(added):
        result["added"].append({"name": name, "rule_count": len(target[name].get("rules", []))})
    for name in sorted(removed):
        result["removed"].append({"name": name, "rule_count": len(base[name].get("rules", []))})
    for name in sorted(set(base) & set(target)):
        if base[name] != target[name]:
            result["changed"].append({"name": name, "rules_before": base[name].get("rules", []), "rules_after": target[name].get("rules", [])})
    return result


def _compare_route_policies(base_data: dict, target_data: dict) -> dict:
    """Compare route-policies between base and target."""
    base = {_rp_key(p): p for p in base_data.get("route_policies", [])}
    target = {_rp_key(p): p for p in target_data.get("route_policies", [])}
    result: dict = {"added": [], "removed": [], "changed": []}
    added = set(target) - set(base)
    removed = set(base) - set(target)
    for key in sorted(added):
        result["added"].append({"name": target[key]["name"], "node": target[key].get("node"), "action": target[key].get("action")})
    for key in sorted(removed):
        result["removed"].append({"name": base[key]["name"], "node": base[key].get("node"), "action": base[key].get("action")})
    for key in sorted(set(base) & set(target)):
        if base[key] != target[key]:
            result["changed"].append({"name": target[key]["name"], "node": target[key].get("node"), "before": base[key], "after": target[key]})
    return result


def _rp_key(rp: dict) -> str:
    return f"{rp.get('name', '?')}:{rp.get('node', 0)}"


def _compare_acls(base_data: dict, target_data: dict) -> dict:
    """Compare ACLs between base and target."""
    base = {a.get("name", ""): a for a in base_data.get("acls", [])}
    target = {a.get("name", ""): a for a in target_data.get("acls", [])}
    result: dict = {"added": [], "removed": [], "changed": []}
    added = set(target) - set(base)
    removed = set(base) - set(target)
    for name in sorted(added):
        result["added"].append({"name": name, "type": target[name].get("type"), "rule_count": len(target[name].get("rules", []))})
    for name in sorted(removed):
        result["removed"].append({"name": name, "type": base[name].get("type"), "rule_count": len(base[name].get("rules", []))})
    for name in sorted(set(base) & set(target)):
        if base[name] != target[name]:
            result["changed"].append({"name": name, "type": target[name].get("type")})
    return result


def _compare_policy_deps(base_data: dict, target_data: dict) -> dict:
    """Compare policy dependency maps."""
    from apps.analysis.policy_utils import build_policy_reference_map
    base_ref = build_policy_reference_map(base_data)
    target_ref = build_policy_reference_map(target_data)
    result: dict = {}
    b_orphans = set(base_ref.get("orphan_route_policies", []))
    t_orphans = set(target_ref.get("orphan_route_policies", []))
    if b_orphans != t_orphans:
        result["orphan_route_policies"] = {
            "resolved": sorted(b_orphans - t_orphans),
            "new": sorted(t_orphans - b_orphans),
        }
    return result


def _build_policy_impacts(base_data: dict, target_data: dict) -> list[dict]:
    """Generate impact statements for policy changes."""
    impacts = []
    base_rp = {_rp_key(p): p for p in base_data.get("route_policies", [])}
    target_rp = {_rp_key(p): p for p in target_data.get("route_policies", [])}
    added = set(target_rp) - set(base_rp)
    removed = set(base_rp) - set(target_rp)
    changed = {k for k in set(base_rp) & set(target_rp) if base_rp[k] != target_rp[k]}
    if added:
        for k in sorted(added):
            impacts.append({
                "impact": f"Route-policy {target_rp[k]['name']} (node {target_rp[k].get('node')}) adicionada.",
                "detail": "Validar impacto nos peers BGP que a referenciam.",
                "severity": "warning",
            })
    if removed:
        for k in sorted(removed):
            impacts.append({
                "impact": f"Route-policy {base_rp[k]['name']} (node {base_rp[k].get('node')}) removida.",
                "detail": "Pode impactar an\u00fancios BGP recebidos/enviados. Validar peers referenciados.",
                "severity": "high",
            })
    if changed:
        impacts.append({
            "impact": f"Route-policy alterada ({len(changed)} node(s)).",
            "detail": "Pode alterar filtros de roteamento. Validar an\u00fancios BGP antes/depois.",
            "severity": "high",
        })
    # Check IP prefix changes
    base_pp = set(p["name"] for p in base_data.get("prefix_lists", []))
    target_pp = set(p["name"] for p in target_data.get("prefix_lists", []))
    if base_pp != target_pp:
        impacts.append({
            "impact": "IP prefix-list adicionada/removida.",
            "detail": "Pode mudar quais prefixos s\u00e3o permitidos/negados por route-policies.",
            "severity": "warning",
        })
    # Check AS-path / community filter changes
    base_af_names = set(a.get("name", "") for a in base_data.get("as_path_filters", []))
    target_af_names = set(a.get("name", "") for a in target_data.get("as_path_filters", []))
    if base_af_names != target_af_names or str(base_data.get("as_path_filters", [])) != str(target_data.get("as_path_filters", [])):
        impacts.append({
            "impact": "AS-path filter alterado.",
            "detail": "Pode impactar seleção/filtragem de rotas por origem AS.",
            "severity": "warning",
        })
    base_cf_names = set(c.get("name", "") for c in base_data.get("community_filters", []))
    target_cf_names = set(c.get("name", "") for c in target_data.get("community_filters", []))
    if base_cf_names != target_cf_names or str(base_data.get("community_filters", [])) != str(target_data.get("community_filters", [])):
        impacts.append({
            "impact": "Community-filter alterado.",
            "detail": "Pode impactar políticas baseadas em communities BGP.",
            "severity": "warning",
        })
    # Check BGP peer policy changes
    for bgp in target_data.get("bgp", []):
        for peer in bgp.get("peers", []):
            for d in ("import", "export"):
                rp_name = peer.get(f"route_policy_{d}")
                new_name = f"{peer.get('ip', '?')}_{d}"
                for bgp_b in base_data.get("bgp", []):
                    for peer_b in bgp_b.get("peers", []):
                        if peer_b.get("ip") == peer.get("ip"):
                            old_rp = peer_b.get(f"route_policy_{d}")
                            if old_rp and old_rp != rp_name:
                                impacts.append({
                                    "impact": f"Route-policy {d} do peer {peer.get('ip', '?')} alterada: {old_rp} \u2192 {rp_name}.",
                                    "detail": "Pode impactar an\u00fancios BGP recebidos/enviados.",
                                    "severity": "high",
                                })
    return impacts

def _compare_vlans(base_data: dict, target_data: dict) -> dict:
    """Compara VLANs entre base e target."""
    base = {_vlan_key(v): v for v in base_data.get("vlans", [])}
    target = {_vlan_key(v): v for v in target_data.get("vlans", [])}
    base_ids = set(base.keys())
    target_ids = set(target.keys())
    added_ids = target_ids - base_ids
    removed_ids = base_ids - target_ids
    common_ids = base_ids & target_ids
    added = [{"vlan_id": vid, "description": target[vid].get("description", ""), "source": target[vid].get("source", "")} for vid in sorted(added_ids)]
    removed = [{"vlan_id": vid, "description": base[vid].get("description", ""), "source": base[vid].get("source", "")} for vid in sorted(removed_ids)]
    changed = []
    for vid in sorted(common_ids):
        bv, tv = base[vid], target[vid]
        ch = {}
        for field in ("description", "name"):
            if bv.get(field) != tv.get(field):
                ch[field] = {"before": bv.get(field, ""), "after": tv.get(field, "")}
        if ch:
            changed.append({"vlan_id": vid, "changes": ch})
    return {"added": added, "removed": removed, "changed": changed}


# ── STP comparison ───────────────────────────────────────────────────


def _compare_stp(base_data: dict, target_data: dict) -> dict:
    """Compara STP/MSTP entre base e target."""
    base_stp = base_data.get("stp", {})
    target_stp = target_data.get("stp", {})
    result: dict = {}
    if base_stp.get("enabled") != target_stp.get("enabled"):
        result["enabled_changed"] = {"before": base_stp.get("enabled"), "after": target_stp.get("enabled")}
    if base_stp.get("mode") != target_stp.get("mode"):
        result["mode_changed"] = {"before": base_stp.get("mode"), "after": target_stp.get("mode")}
    # Compare regions
    base_regions = {r.get("name", ""): r for r in base_stp.get("regions", [])}
    target_regions = {r.get("name", ""): r for r in target_stp.get("regions", [])}
    if base_regions != target_regions:
        result["region_changed"] = True
    # Compare instances by instance_id
    base_insts = {i["instance_id"]: i for i in base_stp.get("instances", [])}
    target_insts = {i["instance_id"]: i for i in target_stp.get("instances", [])}
    added_insts = [target_insts[iid] for iid in sorted(set(target_insts) - set(base_insts))]
    removed_insts = [base_insts[iid] for iid in sorted(set(base_insts) - set(target_insts))]
    changed_insts = []
    for iid in sorted(set(base_insts) & set(target_insts)):
        if base_insts[iid].get("vlans") != target_insts[iid].get("vlans"):
            changed_insts.append({"instance_id": iid, "vlans_before": base_insts[iid].get("vlans"), "vlans_after": target_insts[iid].get("vlans")})
    if added_insts:
        result["instances_added"] = added_insts
    if removed_insts:
        result["instances_removed"] = removed_insts
    if changed_insts:
        result["instances_changed"] = changed_insts
    return result


# ── Switching section builder ────────────────────────────────────────


def _build_switching_section(interfaces: dict, base_data: dict, target_data: dict) -> dict:
    """Constrói seção switching operacional."""
    section: dict = {}
    eth_trunk_changes = []
    allowed_vlan_changes = []
    access_vlan_changes = []
    pvid_changes = []
    mode_changes = []
    for iface in interfaces.get("changed", []):
        name = iface.get("name", "")
        for ch in iface.get("changes", []):
            field = ch.get("field", "")
            if field == "trunk_allowed_vlans":
                allowed_vlan_changes.append({"interface": name, "before": ch.get("from"), "after": ch.get("to")})
            elif field == "access_vlan":
                access_vlan_changes.append({"interface": name, "before": ch.get("from"), "after": ch.get("to")})
            elif field == "trunk_pvid":
                pvid_changes.append({"interface": name, "before": ch.get("from"), "after": ch.get("to")})
            elif field == "port_mode":
                mode_changes.append({"interface": name, "before": ch.get("from"), "after": ch.get("to")})
    # Eth-Trunk members
    base_ifaces = {i["name"]: i for i in base_data.get("interfaces", [])}
    target_ifaces = {i["name"]: i for i in target_data.get("interfaces", [])}
    for name in set(list(base_ifaces.keys()) + list(target_ifaces.keys())):
        bi = base_ifaces.get(name, {})
        ti = target_ifaces.get(name, {})
        if bi.get("type") not in ("eth-trunk",) and ti.get("type") not in ("eth-trunk",):
            continue
        bm = set(bi.get("members", []) or [])
        tm = set(ti.get("members", []) or [])
        added = tm - bm
        removed = bm - tm
        if added or removed:
            eth_trunk_changes.append({"eth_trunk": name, "members_added": sorted(added), "members_removed": sorted(removed)})
    if eth_trunk_changes:
        section["eth_trunk_members_changed"] = eth_trunk_changes
    if allowed_vlan_changes:
        section["allowed_vlans_changed"] = allowed_vlan_changes
    if access_vlan_changes:
        section["access_vlan_changed"] = access_vlan_changes
    if pvid_changes:
        section["pvid_changed"] = pvid_changes
    if mode_changes:
        section["port_mode_changed"] = mode_changes
    return section


# ── Switching impacts ────────────────────────────────────────────────


def _build_switching_impacts(vlans: dict, stp_comp: dict, switching: dict) -> list[dict]:
    """Impactos de VLAN, STP e switching."""
    impacts = []
    for v in vlans.get("added", []):
        impacts.append({"impact": f"Nova VLAN {v.get('vlan_id', '?')} adicionada.", "detail": "Validar se há portas/circuitos associados.", "severity": "info"})
    for v in vlans.get("removed", []):
        impacts.append({"impact": f"VLAN {v.get('vlan_id', '?')} removida.", "detail": "Validar se nenhum cliente/trunk/QinQ/L2VPN dependia dela.", "severity": "warning"})
    for v in vlans.get("changed", []):
        impacts.append({"impact": f"Descrição/nome da VLAN {v.get('vlan_id', '?')} alterado.", "detail": "Validar documentação e finalidade.", "severity": "info"})
    for item in switching.get("allowed_vlans_changed", []):
        impacts.append({"impact": f"Lista de VLANs permitidas alterada em {item['interface']}.", "detail": "Pode impactar transporte L2.", "severity": "warning"})
    for item in switching.get("access_vlan_changed", []):
        impacts.append({"impact": f"VLAN de acesso alterada em {item['interface']}.", "detail": "Pode mover cliente/equipamento para outro domínio L2.", "severity": "warning"})
    for item in switching.get("pvid_changed", []):
        impacts.append({"impact": f"PVID/native VLAN alterada em {item['interface']}.", "detail": "Pode afetar tráfego sem tag.", "severity": "warning"})
    for item in switching.get("eth_trunk_members_changed", []):
        impacts.append({"impact": f"Membros físicos de {item['eth_trunk']} alterados.", "detail": "Validar LACP/redundância/balanceamento.", "severity": "warning"})
    if stp_comp.get("mode_changed") or stp_comp.get("instances_changed"):
        impacts.append({"impact": "STP/MSTP alterado.", "detail": "Validar risco de loop L2 e convergência.", "severity": "high"})
    elif stp_comp.get("enabled_changed"):
        impacts.append({"impact": "STP foi habilitado/desabilitado.", "detail": "Validar risco de loop L2.", "severity": "high"})
    return impacts


# ── Impacts ────────────────────────────────────────────────────────────


def _build_impacts(
    interfaces: dict,
    static_routes: dict,
    bgp: dict,
    circuits: dict,
    issues: dict,
) -> list[dict]:
    impacts = []

    for iface in interfaces.get("added", []):
        impacts.append({
            "impact": f"Nova interface adicionada: {iface['name']}.",
            "detail": "Pode indicar novo circuito, novo cliente ou novo serviço.",
            "severity": "info",
        })
    for iface in interfaces.get("removed", []):
        impacts.append({
            "impact": f"Interface removida: {iface['name']}.",
            "detail": "Pode indicar desativação de circuito ou serviço.",
            "severity": "warning",
        })
    for iface in interfaces.get("changed", []):
        for ch in iface.get("changes", []):
            impacts.append({
                "impact": f"Interface {iface['name']}: {ch['field']} alterado.",
                "detail": f"De '{ch.get('from', 'vazio')}' para '{ch.get('to', 'vazio')}'.",
                "severity": "info",
            })

    for route in static_routes.get("added", []):
        impacts.append({
            "impact": f"Nova rota estática: {route.get('destination', '?')} via {route.get('next_hop', '?')}.",
            "detail": "Pode indicar novo circuito, novo cliente ou novo caminho de transporte.",
            "severity": "info",
        })
    for route in static_routes.get("removed", []):
        impacts.append({
            "impact": f"Rota estática removida: {route.get('destination', '?')}.",
            "detail": "Validar se o destino não depende mais deste equipamento.",
            "severity": "warning",
        })

    for peer in bgp.get("peers_added", []):
        impacts.append({
            "impact": f"Novo peer BGP: {peer.get('ip', '?')} (AS {peer.get('remote_as', '?')}).",
            "detail": "Pode indicar novo cliente, novo upstream ou nova sessão de peering.",
            "severity": "info",
        })
    for peer in bgp.get("peers_removed", []):
        impacts.append({
            "impact": f"Peer BGP removido: {peer.get('ip', '?')}.",
            "detail": "Pode impactar troca de rotas com cliente/upstream/IX.",
            "severity": "warning",
        })
    if bgp.get("local_as_changed"):
        impacts.append({
            "impact": "AS local do BGP alterado.",
            "detail": "Impacto crítico em toda a rede BGP. Verificar peers e políticas.",
            "severity": "critical",
        })

    for c in circuits.get("added", []):
        impacts.append({
            "impact": f"Novo circuito detectado: {c.get('type_display', '?')}.",
            "detail": f"Interface {c.get('interface', '?')}. Pode indicar nova entrega de circuito.",
            "severity": "info",
        })
    for c in circuits.get("removed", []):
        impacts.append({
            "impact": f"Circuito removido: {c.get('type_display', '?')}.",
            "detail": f"Interface {c.get('interface', '?')}. Validar desativação.",
            "severity": "warning",
        })

    if issues.get("new_count", 0) > 0:
        impacts.append({
            "impact": f"{issues['new_count']} nova(s) issue(s) detectada(s).",
            "detail": "Verificar se representam riscos operacionais.",
            "severity": "warning",
        })

    return impacts


# ── Recommendations ────────────────────────────────────────────────────


def _build_recommendations(
    interfaces: dict,
    static_routes: dict,
    bgp: dict,
    circuits: dict,
    issues: dict,
) -> list[dict]:
    recs = []

    if static_routes.get("added"):
        recs.append({
            "recommendation": "Validar reachability de novos next-hops em rotas estáticas.",
            "rationale": "Next-hops inalcançáveis podem causar queda de serviço.",
            "severity": "warning",
        })

    if static_routes.get("changed"):
        recs.append({
            "recommendation": "Conferir se alterações em rotas estáticas não impactam clientes ativos.",
            "rationale": "Rotas alteradas podem redirecionar tráfego indevidamente.",
            "severity": "warning",
        })

    if bgp.get("peers_added") or bgp.get("peers_removed"):
        recs.append({
            "recommendation": "Executar comandos de validação após alterações em BGP.",
            "rationale": "Mudanças em peers BGP podem impactar a tabela de rotas global.",
            "severity": "warning",
        })

    if interfaces.get("added") or interfaces.get("removed"):
        recs.append({
            "recommendation": "Registrar motivo da mudança de interface no snapshot.",
            "rationale": "Snapshots sem documentação dificultam auditoria futura.",
            "severity": "info",
        })

    if circuits.get("added") or circuits.get("removed"):
        recs.append({
            "recommendation": "Comparar documentação antes/depois para verificar circuitos alterados.",
            "rationale": "Documentação desatualizada gera retrabalho em troubleshooting.",
            "severity": "info",
        })

    if issues.get("new_count", 0) > 0:
        recs.append({
            "recommendation": "Revisar novas issues e mitigar riscos antes de concluir a mudança.",
            "rationale": "Issues novas podem indicar configuração incompleta ou errada.",
            "severity": "warning",
        })

    recs.append({
        "recommendation": "Criar rollback se mudanças envolverem BGP, rotas ou interfaces críticas.",
        "rationale": "Ter um plano de rollback reduz o tempo de indisponibilidade em caso de erro.",
        "severity": "info",
    })

    return recs


# ── Service-specific impacts ──────────────────────────────────────────


def _build_service_impacts(services: dict) -> list[dict]:
    """Generate deterministic impacts for service changes."""
    impacts = []

    for svc in services.get("removed", []):
        st = svc.get("service_type", "")
        name = svc.get("name", "")
        if st == "radius":
            impacts.append({
                "impact": f"Servidor RADIUS removido: {name}.",
                "detail": "Pode impactar autenticação, autorização ou contabilização de assinantes.",
                "severity": "critical",
            })
        elif st == "aaa":
            impacts.append({
                "impact": "Configuração AAA removida.",
                "detail": "Pode impactar login administrativo ou autenticação de assinantes.",
                "severity": "critical",
            })
        elif st == "bng":
            impacts.append({
                "impact": "Função BNG/BAS deixou de ser detectada.",
                "detail": "Validar se não houve remoção acidental de autenticação de assinantes.",
                "severity": "critical",
            })
        elif st == "ip_pool":
            impacts.append({
                "impact": f"Pool de endereços removido: {name}.",
                "detail": "Pode impedir atribuição de IP para assinantes.",
                "severity": "critical",
            })
        elif st == "subscriber_access":
            impacts.append({
                "impact": "Acesso de assinantes removido.",
                "detail": "Pode derrubar autenticação ou sessões de clientes.",
                "severity": "critical",
            })
        elif st == "snmp":
            impacts.append({
                "impact": f"SNMP removido/alterado: {name}.",
                "detail": "Validar monitoramento e gerência do equipamento.",
                "severity": "warning",
            })
        elif st == "ntp":
            impacts.append({
                "impact": "Servidor NTP removido.",
                "detail": "Validar sincronização de horário do equipamento.",
                "severity": "warning",
            })
        elif st == "syslog":
            impacts.append({
                "impact": "Loghost syslog removido.",
                "detail": "Validar recebimento de logs no servidor central.",
                "severity": "info",
            })
        elif st == "management_access":
            impacts.append({
                "impact": "Acesso administrativo removido ou alterado.",
                "detail": "Validar métodos de acesso remoto ao equipamento.",
                "severity": "warning",
            })
        elif st == "local_user":
            impacts.append({
                "impact": f"Usuário local removido: {name}.",
                "detail": "Validar controle de acesso administrativo.",
                "severity": "info",
            })

    for svc in services.get("added", []):
        st = svc.get("service_type", "")
        name = svc.get("name", "")
        if st == "radius":
            impacts.append({
                "impact": f"Novo servidor RADIUS adicionado: {name}.",
                "detail": "Validar conectividade, chave compartilhada e políticas AAA.",
                "severity": "warning",
            })
        elif st == "ip_pool":
            impacts.append({
                "impact": f"Novo pool de endereços detectado: {name}.",
                "detail": "Validar faixa, gateway, DNS e domínio associado.",
                "severity": "warning",
            })
        elif st == "aaa":
            impacts.append({
                "impact": "Nova configuração AAA detectada.",
                "detail": "Pode indicar novo domínio de autenticação ou esquema de contabilização.",
                "severity": "warning",
            })
        elif st == "subscriber_access":
            impacts.append({
                "impact": "Novo acesso de assinantes detectado.",
                "detail": "Validar interface, VLAN e tipo de autenticação (PPPoE/IPoE).",
                "severity": "warning",
            })
        elif st == "snmp":
            impacts.append({
                "impact": f"SNMP alterado: {name}.",
                "detail": "Validar monitoramento e restrições de ACL.",
                "severity": "warning",
            })
        elif st == "ntp":
            impacts.append({
                "impact": "Novo servidor NTP detectado.",
                "detail": "Validar sincronização de horário.",
                "severity": "info",
            })
        elif st == "syslog":
            impacts.append({
                "impact": "Novo loghost syslog detectado.",
                "detail": "Validar recebimento de logs no servidor.",
                "severity": "info",
            })
        elif st == "management_access":
            impacts.append({
                "impact": "Configuração de acesso administrativo alterada.",
                "detail": "Validar protocolo, autenticação e ACLs nas linhas VTY.",
                "severity": "warning",
            })
        elif st == "local_user":
            impacts.append({
                "impact": f"Usuário local adicionado: {name}.",
                "detail": "Validar necessidade e políticas de senha forte.",
                "severity": "info",
            })

    return impacts


# ── Validation Plan ────────────────────────────────────────────────────


def _build_validation_plan(
    interfaces: dict,
    static_routes: dict,
    bgp: dict,
    services: dict,
    issues: dict,
) -> list[dict]:
    """Generate a deterministic post-change validation plan."""
    plan: list[dict] = []

    # Interface changes
    for iface in interfaces.get("added", []):
        name = iface.get("name", "?")
        plan.append({
            "category": "interface",
            "title": f"Validar interface adicionada: {name}",
            "commands": [
                f"display interface {name}",
                f"display current-configuration interface {name}",
            ],
            "reason": "Conferir se a interface subiu corretamente e está configurada como esperado.",
            "severity": "warning",
        })

    for iface in interfaces.get("changed", []):
        name = iface.get("name", "?")
        plan.append({
            "category": "interface",
            "title": f"Validar interface alterada: {name}",
            "commands": [
                f"display interface {name}",
                f"display current-configuration interface {name}",
            ],
            "reason": "Confirmar que as alterações na interface estão aplicadas.",
            "severity": "warning",
        })

    # Subinterface VLAN changes
    for iface in interfaces.get("added", []):
        name = iface.get("name", "?")
        vlan_id = iface.get("vlan_id")
        if vlan_id:
            plan.append({
                "category": "vlan",
                "title": f"Validar subinterface VLAN: {name}",
                "commands": [
                    f"display interface {name}",
                    f"display arp interface {name}",
                    f"display current-configuration interface {name}",
                ],
                "reason": "Verificar se a VLAN está ativa e passando tráfego.",
                "severity": "warning",
            })

    # Static route changes
    for route in static_routes.get("added", []):
        dest = route.get("destination", "?")
        nh = route.get("next_hop", "?")
        plan.append({
            "category": "routing",
            "title": f"Validar nova rota estática: {dest}",
            "commands": [
                f"display ip routing-table {dest.split()[0] if ' ' in dest else dest}",
                f"ping -a {nh} {nh}",
            ],
            "reason": "Confirmar que a rota está instalada e o next-hop é alcançável.",
            "severity": "warning",
        })

    for route in static_routes.get("changed", []):
        key = route.get("key", "?")
        plan.append({
            "category": "routing",
            "title": f"Validar rota estática alterada: {key}",
            "commands": [
                f"display ip routing-table {key.split()[0] if ' ' in key else key}",
            ],
            "reason": "Confirmar que a alteração na rota está correta.",
            "severity": "warning",
        })

    # BGP changes
    if bgp.get("peers_added") or bgp.get("peers_removed") or bgp.get("peers_changed"):
        for peer in bgp.get("peers_added", []):
            ip = peer.get("ip", "?")
            plan.append({
                "category": "bgp",
                "title": f"Validar novo peer BGP: {ip}",
                "commands": [
                    f"display bgp peer {ip}",
                    f"display bgp routing-table peer {ip} advertised-routes",
                    f"display bgp routing-table peer {ip} received-routes",
                    f"display current-configuration configuration bgp",
                ],
                "reason": "Verificar se o peer BGP estabeleceu e está trocando rotas.",
                "severity": "warning",
            })
        for peer in bgp.get("peers_changed", []):
            ip = peer.get("ip", "?")
            plan.append({
                "category": "bgp",
                "title": f"Validar peer BGP alterado: {ip}",
                "commands": [
                    f"display bgp peer {ip}",
                    f"display current-configuration configuration bgp",
                ],
                "reason": "Confirmar que as alterações no peer BGP foram aplicadas.",
                "severity": "warning",
            })

    # Service-related validation
    svc_removed = services.get("removed", [])
    svc_added = services.get("added", [])
    if any(s.get("service_type") in ("radius", "aaa", "bng") for s in svc_removed + svc_added):
        plan.append({
            "category": "aaa",
            "title": "Validar configuração AAA/RADIUS",
            "commands": [
                "display current-configuration configuration aaa",
                "display current-configuration | include radius",
                "display aaa online-fail-record",
                "display radius-server configuration",
            ],
            "reason": "AAA/RADIUS impacta autenticação de assinantes e acesso administrativo.",
            "severity": "critical",
        })

    if any(s.get("service_type") == "ip_pool" for s in svc_removed + svc_added):
        plan.append({
            "category": "ip_pool",
            "title": "Validar pools de endereços IP",
            "commands": [
                "display ip pool",
                "display access-user domain",
            ],
            "reason": "Pool de IP alterado pode impedir novos assinantes de obterem endereço.",
            "severity": "critical",
        })

    if bgp.get("networks_added") or bgp.get("networks_removed"):
        plan.append({
            "category": "bgp",
            "title": "Validar redes BGP anunciadas",
            "commands": [
                "display bgp routing-table",
                "display current-configuration configuration bgp",
            ],
            "reason": "Redes anunciadas incorretamente podem causar blackhole ou rotação indevida.",
            "severity": "warning",
        })

    if issues.get("new_count", 0) > 0:
        plan.append({
            "category": "issues",
            "title": "Revisar novas issues detectadas",
            "commands": [],
            "reason": "Issues novas podem indicar configuração incompleta ou errada.",
            "severity": "warning",
        })

    # Management service changes
    svc_added = services.get("added", [])
    svc_removed = services.get("removed", [])

    if any(s.get("service_type") == "snmp" for s in svc_added + svc_removed):
        plan.append({
            "category": "management",
            "title": "Validar configuração SNMP",
            "commands": [
                "display current-configuration | include snmp-agent",
                "display snmp-agent sys-info version",
                "display snmp-agent community",
                "display snmp-agent target-host",
            ],
            "reason": "SNMP alterado. Validar versões, comunidades e servidores de trap.",
            "severity": "warning",
        })

    if any(s.get("service_type") == "ntp" for s in svc_added + svc_removed):
        plan.append({
            "category": "management",
            "title": "Validar configuração NTP",
            "commands": [
                "display current-configuration | include ntp-service",
                "display ntp-service status",
                "display ntp-service sessions",
            ],
            "reason": "NTP alterado. Validar sincronização de horário.",
            "severity": "info",
        })

    if any(s.get("service_type") == "syslog" for s in svc_added + svc_removed):
        plan.append({
            "category": "management",
            "title": "Validar configuração de syslog",
            "commands": [
                "display current-configuration | include info-center",
                "display logbuffer",
            ],
            "reason": "Syslog alterado. Validar recebimento de logs no servidor.",
            "severity": "info",
        })

    if any(s.get("service_type") == "management_access" for s in svc_added + svc_removed):
        plan.append({
            "category": "management",
            "title": "Validar acesso administrativo",
            "commands": [
                "display current-configuration configuration user-interface",
                "display ssh server status",
                "display users",
            ],
            "reason": "Acesso administrativo alterado. Validar protocolo, ACLs e autenticação.",
            "severity": "warning",
        })

    if any(s.get("service_type") == "local_user" for s in svc_added + svc_removed):
        plan.append({
            "category": "management",
            "title": "Validar usuários locais",
            "commands": [
                "display current-configuration | include local-user",
                "display local-user",
            ],
            "reason": "Usuários locais alterados. Validar contas e privilégios.",
            "severity": "info",
        })

    return plan


# ── Rollback Plan ──────────────────────────────────────────────────────


def _build_rollback_plan(
    interfaces: dict,
    static_routes: dict,
    bgp: dict,
    services: dict,
) -> list[dict]:
    """Generate a suggested rollback plan (safe, no automatic config push)."""
    plan: list[dict] = []

    plan.append({
        "change_type": "general",
        "object": "processo",
        "suggestion": "Antes de aplicar rollback, confirmar janela de manutenção e impacto.",
        "risk_level": "info",
        "verification_commands": [],
    })
    plan.append({
        "change_type": "general",
        "object": "snapshot",
        "suggestion": "Salvar snapshot atual antes do rollback.",
        "risk_level": "info",
        "verification_commands": [],
    })

    for iface in interfaces.get("added", []):
        name = iface.get("name", "?")
        plan.append({
            "change_type": "interface_added",
            "object": name,
            "suggestion": f"Remover a interface {name} com 'undo interface {name}' se não estiver mais em uso.",
            "risk_level": "medium",
            "verification_commands": [
                f"display interface {name}",
                f"display current-configuration interface {name}",
            ],
        })

    for route in static_routes.get("added", []):
        dest = route.get("destination", "?").split()[0] if route.get("destination") else "?"
        mask = route.get("netmask", "?")
        nh = route.get("next_hop", "?")
        vpn = route.get("vpn_instance")
        vpn_part = f"vpn-instance {vpn} " if vpn else ""
        plan.append({
            "change_type": "static_route_added",
            "object": f"{route.get('destination', '?')} via {nh}",
            "suggestion": f"Remover a rota com 'undo ip route-static {vpn_part}{dest} {mask} {nh}' após validar que não está mais em uso.",
            "risk_level": "medium",
            "verification_commands": [
                f"display ip routing-table {dest}",
            ],
        })

    for peer in bgp.get("peers_added", []):
        ip = peer.get("ip", "?")
        plan.append({
            "change_type": "bgp_peer_added",
            "object": ip,
            "suggestion": f"Remover ou desabilitar o peer BGP {ip} com 'undo peer {ip}' ou 'peer {ip} disable'.",
            "risk_level": "high",
            "verification_commands": [
                f"display bgp peer {ip}",
            ],
        })

    if bgp.get("peers_changed"):
        for pc in bgp["peers_changed"]:
            ip = pc.get("ip", "?")
            plan.append({
                "change_type": "bgp_peer_changed",
                "object": ip,
                "suggestion": f"Reverter alterações no peer {ip} conforme configuração original salva.",
                "risk_level": "high",
                "verification_commands": [
                    f"display bgp peer {ip}",
                    f"display current-configuration configuration bgp",
                ],
            })

    svc_removed = services.get("removed", [])
    svc_added = services.get("added", [])

    if any(s.get("service_type") in ("radius", "aaa", "bng") for s in svc_removed + svc_added):
        plan.append({
            "change_type": "aaa_radius_changed",
            "object": "AAA/RADIUS",
            "suggestion": "Rollback de AAA/RADIUS deve ser feito com extremo cuidado. Restaurar configuração AAA original e validar autenticação de assinantes e acesso administrativo.",
            "risk_level": "critical",
            "verification_commands": [
                "display current-configuration configuration aaa",
                "display aaa online-fail-record",
            ],
        })

    if any(s.get("service_type") == "ip_pool" for s in svc_removed + svc_added):
        plan.append({
            "change_type": "ip_pool_changed",
            "object": "IP Pool",
            "suggestion": "Restaurar pool de IP original. Validar gateway, DNS e faixa de endereços.",
            "risk_level": "high",
            "verification_commands": [
                "display ip pool",
            ],
        })

    if bgp.get("networks_added") or bgp.get("networks_removed"):
        plan.append({
            "change_type": "bgp_network_changed",
            "object": "redes BGP",
            "suggestion": "Reverter redes BGP adicionadas/removidas. Verificar an\u00fancios com 'display bgp routing-table'.",
            "risk_level": "high",
            "verification_commands": [
                "display bgp routing-table",
            ],
        })

    return plan


# ── ISIS comparison ─────────────────────────────────────────────────────


def _compare_isis(base_data: dict, target_data: dict) -> dict:
    """Compare ISIS configuration between two snapshots."""
    base_isis = base_data.get("isis", [])
    target_isis = target_data.get("isis", [])

    base = {p.get("process_id", "1"): p for p in base_isis}
    target = {p.get("process_id", "1"): p for p in target_isis}

    base_ids = set(base.keys())
    target_ids = set(target.keys())

    added = [target[pid] for pid in sorted(target_ids - base_ids)]
    removed = [base[pid] for pid in sorted(base_ids - target_ids)]

    changed = []
    network_entity_changed = False
    for pid in sorted(base_ids & target_ids):
        bp = base[pid]
        tp = target[pid]
        changes = []
        for field in ("network_entity", "is_level", "cost_style"):
            bv = bp.get(field)
            tv = tp.get(field)
            if bv != tv:
                changes.append({"field": field, "from": bv, "to": tv})
                if field == "network_entity":
                    network_entity_changed = True

        b_import = set(bp.get("import_routes", []))
        t_import = set(tp.get("import_routes", []))
        if b_import != t_import:
            changes.append({
                "field": "import_routes",
                "from": sorted(b_import),
                "to": sorted(t_import),
            })

        if changes:
            changed.append({"process_id": pid, "changes": changes})

        # Compare ISIS on interfaces for this process
        base_ifaces_map = {i["name"]: i for i in base_data.get("interfaces", [])}
        target_ifaces_map = {i["name"]: i for i in target_data.get("interfaces", [])}
        base_isis_ifaces = {n for n, i in base_ifaces_map.items() if i.get("isis_process_id") == pid}
        target_isis_ifaces = {n for n, i in target_ifaces_map.items() if i.get("isis_process_id") == pid}
        ifaces_added = sorted(target_isis_ifaces - base_isis_ifaces)
        ifaces_removed = sorted(base_isis_ifaces - target_isis_ifaces)
        ifaces_changed = []
        for name in sorted(base_isis_ifaces & target_isis_ifaces):
            bi = base_ifaces_map[name]
            ti = target_ifaces_map[name]
            i_changes = []
            for f, key in [("isis_cost", "cost"), ("isis_circuit_type", "circuit_type")]:
                bv = bi.get(f)
                tv = ti.get(f)
                if bv != tv:
                    i_changes.append({"field": key, "from": bv, "to": tv})
            if i_changes:
                ifaces_changed.append({"name": name, "changes": i_changes})

        if ifaces_added or ifaces_removed or ifaces_changed:
            changes.append({
                "field": "interfaces",
                "interfaces_added": ifaces_added,
                "interfaces_removed": ifaces_removed,
                "interfaces_changed": ifaces_changed,
            })

        if changes:
            changed.append({"process_id": pid, "changes": changes})

    result = {"added": added, "removed": removed, "changed": changed}
    if network_entity_changed:
        result["network_entity_changed"] = True
    return result


# ── MPLS comparison ─────────────────────────────────────────────────────


def _compare_mpls(base_data: dict, target_data: dict) -> dict:
    """Compare MPLS global configuration."""
    base_mpls = base_data.get("mpls", {})
    target_mpls = target_data.get("mpls", {})

    result = {}
    if base_mpls.get("enabled") != target_mpls.get("enabled"):
        result["enabled_changed"] = {"before": base_mpls.get("enabled"), "after": target_mpls.get("enabled")}
    if base_mpls.get("lsr_id") != target_mpls.get("lsr_id"):
        result["lsr_id_changed"] = {"before": base_mpls.get("lsr_id"), "after": target_mpls.get("lsr_id")}
    if base_mpls.get("te_enabled") != target_mpls.get("te_enabled"):
        result["te_changed"] = {"before": base_mpls.get("te_enabled"), "after": target_mpls.get("te_enabled")}
    # Compare MPLS interfaces
    base_mpls_ifaces = {i["name"] for i in base_data.get("interfaces", []) if i.get("mpls_enabled")}
    target_mpls_ifaces = {i["name"] for i in target_data.get("interfaces", []) if i.get("mpls_enabled")}
    ifaces_added = sorted(target_mpls_ifaces - base_mpls_ifaces)
    ifaces_removed = sorted(base_mpls_ifaces - target_mpls_ifaces)
    if ifaces_added or ifaces_removed:
        result["interfaces_changed"] = {"added": ifaces_added, "removed": ifaces_removed}
    return result


# ── MPLS LDP comparison ─────────────────────────────────────────────────


def _compare_mpls_ldp(base_data: dict, target_data: dict) -> dict:
    """Compare MPLS LDP configuration."""
    base_ldp = base_data.get("mpls_ldp", {})
    target_ldp = target_data.get("mpls_ldp", {})

    result = {}
    if base_ldp.get("enabled") != target_ldp.get("enabled"):
        result["enabled_changed"] = {"before": base_ldp.get("enabled"), "after": target_ldp.get("enabled")}
    if base_ldp.get("graceful_restart") != target_ldp.get("graceful_restart"):
        result["graceful_restart_changed"] = {"before": base_ldp.get("graceful_restart"), "after": target_ldp.get("graceful_restart")}

    base_rp = {p.get("name", ""): p for p in base_ldp.get("remote_peers", [])}
    target_rp = {p.get("name", ""): p for p in target_ldp.get("remote_peers", [])}
    rp_added = [target_rp[name] for name in sorted(set(target_rp) - set(base_rp))]
    rp_removed = [base_rp[name] for name in sorted(set(base_rp) - set(target_rp))]
    rp_changed = []
    for name in sorted(set(base_rp) & set(target_rp)):
        if base_rp[name].get("remote_ip") != target_rp[name].get("remote_ip"):
            rp_changed.append({"name": name, "from": base_rp[name].get("remote_ip"), "to": target_rp[name].get("remote_ip")})
    if rp_added or rp_removed or rp_changed:
        result["remote_peers_changed"] = {
            "added": rp_added,
            "removed": rp_removed,
            "changed": rp_changed,
        }

    # Compare LDP interfaces (stored on individual interface dicts)
    base_ldp_ifaces = {i["name"] for i in base_data.get("interfaces", []) if i.get("mpls_ldp_enabled")}
    target_ldp_ifaces = {i["name"] for i in target_data.get("interfaces", []) if i.get("mpls_ldp_enabled")}
    ifaces_added = sorted(target_ldp_ifaces - base_ldp_ifaces)
    ifaces_removed = sorted(base_ldp_ifaces - target_ldp_ifaces)
    if ifaces_added or ifaces_removed:
        result["interfaces_changed"] = {
            "added": ifaces_added,
            "removed": ifaces_removed,
        }

    return result


# ── ISIS/MPLS impact builder ────────────────────────────────────────────


def _build_isis_mpls_impacts(isis: dict, mpls: dict, mpls_ldp: dict) -> list[dict]:
    """Generate impact statements for ISIS/MPLS/LDP changes."""
    impacts = []

    if isis.get("added") or isis.get("removed") or isis.get("changed"):
        impacts.append({
            "impact": "ISIS alterado.",
            "detail": "Pode impactar adjac\u00eancias IGP e reachability de loopbacks.",
            "severity": "warning",
        })
    if isis.get("network_entity_changed"):
        impacts.append({
            "impact": "Network-entity ISIS alterada.",
            "detail": "Pode derrubar adjac\u00eancias.",
            "severity": "high",
        })
    if mpls.get("lsr_id_changed"):
        impacts.append({
            "impact": "MPLS LSR ID alterado.",
            "detail": "Pode impactar labels e sess\u00f5es LDP.",
            "severity": "high",
        })
    if mpls_ldp.get("interfaces_changed"):
        impacts.append({
            "impact": "Interface LDP alterada.",
            "detail": "Pode impactar transporte MPLS.",
            "severity": "warning",
        })
    if mpls_ldp.get("remote_peers_changed"):
        impacts.append({
            "impact": "Remote-peer LDP alterado.",
            "detail": "Validar sess\u00e3o remota.",
            "severity": "warning",
        })

    return impacts


# ── Formatters for ISIS/MPLS/LDP summaries ──────────────────────────────


def _fmt_mpls_summary(mpls: dict) -> str:
    parts = []
    if mpls.get("enabled_changed"):
        parts.append("enabled alterado")
    if mpls.get("lsr_id_changed"):
        parts.append("LSR ID alterado")
    if mpls.get("te_changed"):
        parts.append("TE alterado")
    if not parts:
        return "sem mudan\u00e7as"
    return ", ".join(parts)


def _fmt_mpls_ldp_summary(ldp: dict) -> str:
    parts = []
    if ldp.get("enabled_changed"):
        parts.append("enabled alterado")
    if ldp.get("graceful_restart_changed"):
        parts.append("graceful-restart alterado")
    if ldp.get("interfaces_changed"):
        parts.append("interfaces alteradas")
    if ldp.get("remote_peers_changed"):
        parts.append("remote-peers alterados")
    if not parts:
        return "sem mudan\u00e7as"
    return ", ".join(parts)


# ── VPN-instance / VRF comparison ──────────────────────────────────────


def _vpn_instance_key(vi: dict) -> str:
    return vi.get("name", "")


def _compare_vpn_instances(base_data: dict, target_data: dict) -> dict:
    """Compare VPN-instance / VRF configuration."""
    base = {_vpn_instance_key(v): v for v in base_data.get("vpn_instances", [])}
    target = {_vpn_instance_key(v): v for v in target_data.get("vpn_instances", [])}

    base_names = set(base.keys())
    target_names = set(target.keys())
    added = [_make_vpn_instance_summary(target[n]) for n in sorted(target_names - base_names)]
    removed = [_make_vpn_instance_summary(base[n]) for n in sorted(base_names - target_names)]
    changed = []
    for name in sorted(base_names & target_names):
        bv, tv = base[name], target[name]
        changes = []
        if bv.get("description") != tv.get("description"):
            changes.append({"field": "description", "from": bv.get("description"), "to": tv.get("description")})
        if str(bv.get("address_families")) != str(tv.get("address_families")):
            changes.append({"field": "rd_rt", "from": bv.get("address_families"), "to": tv.get("address_families")})
        if changes:
            changed.append({"name": name, "changes": changes})

    return {"added": added, "removed": removed, "changed": changed,
            "rd_added": [], "rd_removed": [], "rd_changed": [],
            "rt_added": [], "rt_removed": [], "rt_changed": [],
            "interfaces_changed": [], "bgp_vpn_instance_changed": [],
            "vpnv4_added": [], "vpnv4_removed": [], "vpnv4_changed": []}


def _make_vpn_instance_summary(vi: dict) -> dict:
    rd = None
    for af in vi.get("address_families", {}).values():
        if af.get("route_distinguisher"):
            rd = af["route_distinguisher"]
    return {"name": vi.get("name", ""), "description": vi.get("description"), "route_distinguisher": rd}


def _build_vrf_impacts(vpn_instances: dict) -> list[dict]:
    impacts = []
    for vi in vpn_instances.get("added", []):
        impacts.append({"impact": f"Nova VPN-instance adicionada: {vi.get('name', '?')}.", "detail": "Pode indicar novo cliente L3VPN.", "severity": "info"})
    for vi in vpn_instances.get("removed", []):
        impacts.append({"impact": f"VPN-instance removida: {vi.get('name', '?')}.", "detail": "Validar se circuitos e rotas foram desativados.", "severity": "warning"})
    return impacts


# ── QoS comparison ─────────────────────────────────────────────────────


def _qos_policy_key(p: dict) -> str:
    return p.get("name", "")


def _qos_beh_key(b: dict) -> str:
    return b.get("name", "")


def _qos_cl_key(c: dict) -> str:
    return c.get("name", "")


def _compare_qos(base_data: dict, target_data: dict) -> dict:
    """Compare QoS / Traffic Policy configuration."""
    base_qos = base_data.get("qos", {})
    target_qos = target_data.get("qos", {})

    base_p = {_qos_policy_key(p): p for p in base_qos.get("traffic_policies", [])}
    target_p = {_qos_policy_key(p): p for p in target_qos.get("traffic_policies", [])}
    policies_changed = []
    for name in sorted(set(base_p) & set(target_p)):
        if base_p[name] != target_p[name]:
            policies_changed.append({"name": name})

    base_c = {_qos_cl_key(c): c for c in base_qos.get("traffic_classifiers", [])}
    target_c = {_qos_cl_key(c): c for c in target_qos.get("traffic_classifiers", [])}
    classifiers_changed = []
    for name in sorted(set(base_c) & set(target_c)):
        if base_c[name] != target_c[name]:
            classifiers_changed.append({"name": name})

    base_b = {_qos_beh_key(b): b for b in base_qos.get("traffic_behaviors", [])}
    target_b = {_qos_beh_key(b): b for b in target_qos.get("traffic_behaviors", [])}
    behaviors_changed = []
    car_changed = []
    for name in sorted(set(base_b) & set(target_b)):
        if base_b[name] != target_b[name]:
            behaviors_changed.append({"name": name})
        bc = base_b[name].get("car")
        tc = target_b[name].get("car")
        if bc != tc:
            car_changed.append({"behavior": name, "from": bc or {}, "to": tc or {}})

    def _get_bindings(data):
        b = {}
        for iface in data.get("interfaces", []):
            for tp in iface.get("traffic_policies_applied", []):
                k = f"{iface['name']}|{tp['name']}|{tp['direction']}"
                b[k] = {"interface": iface["name"], "policy": tp["name"], "direction": tp["direction"]}
        return b

    base_bind = _get_bindings(base_data)
    target_bind = _get_bindings(target_data)
    interface_bindings_changed = base_bind != target_bind

    return {
        "policies_changed": policies_changed,
        "classifiers_changed": classifiers_changed,
        "behaviors_changed": behaviors_changed,
        "car_changed": car_changed,
        "interface_bindings_changed": interface_bindings_changed,
    }


def _build_qos_impacts(qos: dict) -> list[dict]:
    """Generate impact statements for QoS changes."""
    impacts = []
    for p in qos.get("policies_changed", []):
        impacts.append({"impact": f"Traffic-policy alterada: {p.get('name', '?')}.", "detail": "Pode impactar controle de banda do cliente.", "severity": "warning"})
    for c in qos.get("classifiers_changed", []):
        impacts.append({"impact": f"Traffic classifier alterado: {c.get('name', '?')}.", "detail": "Pode mudar o trafego afetado pela politica.", "severity": "warning"})
    for c in qos.get("car_changed", []):
        impacts.append({"impact": f"CAR alterado para {c.get('behavior', '?')}: {c.get('from', {}).get('cir', '?')} -> {c.get('to', {}).get('cir', '?')} kbps.", "detail": "Pode alterar velocidade contratada/limitada do cliente.", "severity": "high"})
    for b in qos.get("behaviors_changed", []):
        impacts.append({"impact": f"Traffic behavior alterado: {b.get('name', '?')}.", "detail": "Pode impactar acoes de QoS como remark e queue.", "severity": "warning"})
    if qos.get("interface_bindings_changed"):
        impacts.append({"impact": "Aplicacao de traffic-policy em interfaces alterada.", "detail": "Interface pode ficar sem controle de banda ou ganhar nova politica.", "severity": "warning"})
    return impacts


def _fmt_qos_summary(qos: dict) -> str:
    parts = []
    if qos.get("policies_changed"):
        parts.append(f"{len(qos['policies_changed'])} policy(ies) alterada(s)")
    if qos.get("classifiers_changed"):
        parts.append(f"{len(qos['classifiers_changed'])} classifier(es) alterado(s)")
    if qos.get("behaviors_changed"):
        parts.append(f"{len(qos['behaviors_changed'])} behavior(s) alterado(s)")
    if qos.get("car_changed"):
        parts.append(f"{len(qos['car_changed'])} CAR alterado(s)")
    if not parts:
        return "sem mudancas"
    return ", ".join(parts)


# ── Multicast comparison ──────────────────────────────────────────────


def _compare_multicast(base: dict, target: dict) -> dict:
    """Compare multicast/PIM/IGMP/MLD configuration between two snapshots."""
    result: dict = {
        "global": {"added": [], "removed": [], "changed": []},
        "pim": {"added": [], "removed": [], "changed": []},
        "igmp": {"added": [], "removed": [], "changed": []},
        "igmp_snooping": {"added": [], "removed": [], "changed": []},
        "mld": {"added": [], "removed": [], "changed": []},
        "vpn_instances": {"added": [], "removed": [], "changed": []},
    }

    b_mc = base.get("multicast", {})
    t_mc = target.get("multicast", {})
    b_ifaces = base.get("interfaces", [])
    t_ifaces = target.get("interfaces", [])

    # ── Global routing ────────────────────────────────────────────────
    for key, label in [
        ("ipv4_routing_enabled", "multicast routing IPv4"),
        ("ipv6_routing_enabled", "multicast routing IPv6"),
    ]:
        bv = b_mc.get(key, False)
        tv = t_mc.get(key, False)
        if bv != tv:
            result["global"]["changed"].append({"key": key, "label": label, "before": bv, "after": tv})

    # ── PIM: global (static-RP, BSR, RP-candidate) ────────────────────
    def _build_pim_key(pim_global: dict) -> dict:
        return {
            "static_rps": sorted(pim_global.get("static_rps", []), key=lambda x: x.get("rp_address", "") if isinstance(x, dict) else str(x)),
            "bsr_candidates": sorted(pim_global.get("bsr_candidates", []), key=str),
            "rp_candidates": sorted(pim_global.get("rp_candidates", []), key=lambda x: x.get("group", "") if isinstance(x, dict) else str(x)),
            "mode": pim_global.get("mode", "sm"),
        }

    b_pim_key = _build_pim_key(b_mc.get("pim", {}).get("global", {}))
    t_pim_key = _build_pim_key(t_mc.get("pim", {}).get("global", {}))
    if b_pim_key != t_pim_key:
        result["pim"]["changed"].append({"section": "global", "before": b_pim_key, "after": t_pim_key})

    # PIM: interfaces
    def _pim_key(iface: dict) -> str:
        return iface.get("name", "")

    b_pim_ifaces = {i["name"]: i for i in b_ifaces if i.get("pim_enabled")}
    t_pim_ifaces = {i["name"]: i for i in t_ifaces if i.get("pim_enabled")}
    b_pim_names = set(b_pim_ifaces)
    t_pim_names = set(t_pim_ifaces)
    for name in sorted(t_pim_names - b_pim_names):
        result["pim"]["added"].append({"name": name, "mode": t_pim_ifaces[name].get("pim_mode")})
    for name in sorted(b_pim_names - t_pim_names):
        result["pim"]["removed"].append({"name": name, "mode": b_pim_ifaces[name].get("pim_mode")})
    for name in sorted(b_pim_names & t_pim_names):
        bi, ti = b_pim_ifaces[name], t_pim_ifaces[name]
        changes = {}
        for field in ["pim_mode", "pim_hello_holdtime"]:
            if bi.get(field) != ti.get(field):
                changes[field] = {"before": bi.get(field), "after": ti.get(field)}
        if changes:
            result["pim"]["changed"].append({"name": name, "changes": changes})

    # ── IGMP: interfaces ──────────────────────────────────────────────
    b_igmp = {i["name"]: i for i in b_ifaces if i.get("igmp_enabled")}
    t_igmp = {i["name"]: i for i in t_ifaces if i.get("igmp_enabled")}
    b_igmp_names = set(b_igmp)
    t_igmp_names = set(t_igmp)
    for name in sorted(t_igmp_names - b_igmp_names):
        result["igmp"]["added"].append({"name": name, "version": t_igmp[name].get("igmp_version")})
    for name in sorted(b_igmp_names - t_igmp_names):
        result["igmp"]["removed"].append({"name": name, "version": b_igmp[name].get("igmp_version")})
    for name in sorted(b_igmp_names & t_igmp_names):
        bi, ti = b_igmp[name], t_igmp[name]
        changes = {}
        for field in ["igmp_version", "igmp_limit"]:
            if bi.get(field) != ti.get(field):
                changes[field] = {"before": bi.get(field), "after": ti.get(field)}
        for g_field in ["igmp_static_groups", "igmp_join_groups"]:
            bg = sorted(bi.get(g_field, []))
            tg = sorted(ti.get(g_field, []))
            if bg != tg:
                changes[g_field] = {"before": bg, "after": tg}
        if changes:
            result["igmp"]["changed"].append({"name": name, "changes": changes})

    # ── MLD: interfaces ──────────────────────────────────────────────
    b_mld = {i["name"]: i for i in b_ifaces if i.get("mld_enabled")}
    t_mld = {i["name"]: i for i in t_ifaces if i.get("mld_enabled")}
    b_mld_names = set(b_mld)
    t_mld_names = set(t_mld)
    for name in sorted(t_mld_names - b_mld_names):
        result["mld"]["added"].append({"name": name, "version": t_mld[name].get("mld_version")})
    for name in sorted(b_mld_names - t_mld_names):
        result["mld"]["removed"].append({"name": name, "version": b_mld[name].get("mld_version")})
    for name in sorted(b_mld_names & t_mld_names):
        bi, ti = b_mld[name], t_mld[name]
        changes = {}
        if bi.get("mld_version") != ti.get("mld_version"):
            changes["mld_version"] = {"before": bi.get("mld_version"), "after": ti.get("mld_version")}
        bg = sorted(bi.get("mld_static_groups", []))
        tg = sorted(ti.get("mld_static_groups", []))
        if bg != tg:
            changes["mld_static_groups"] = {"before": bg, "after": tg}
        if changes:
            result["mld"]["changed"].append({"name": name, "changes": changes})

    # ── IGMP snooping: global + VLANs ─────────────────────────────────
    b_snoop_global = b_mc.get("igmp_snooping", {}).get("global_enabled", False)
    t_snoop_global = t_mc.get("igmp_snooping", {}).get("global_enabled", False)
    if b_snoop_global != t_snoop_global:
        result["igmp_snooping"]["changed"].append({
            "section": "global",
            "field": "enabled",
            "before": b_snoop_global,
            "after": t_snoop_global,
        })

    b_snoop_vlans = {v["vlan_id"]: v for v in b_mc.get("igmp_snooping", {}).get("vlans", [])}
    t_snoop_vlans = {v["vlan_id"]: v for v in t_mc.get("igmp_snooping", {}).get("vlans", [])}
    b_vids = set(b_snoop_vlans)
    t_vids = set(t_snoop_vlans)
    for vid in sorted(t_vids - b_vids):
        result["igmp_snooping"]["added"].append(t_snoop_vlans[vid])
    for vid in sorted(b_vids - t_vids):
        result["igmp_snooping"]["removed"].append(b_snoop_vlans[vid])
    for vid in sorted(b_vids & t_vids):
        bv, tv = b_snoop_vlans[vid], t_snoop_vlans[vid]
        vchanges = {}
        for field in ["enabled", "version", "querier_enabled"]:
            if bv.get(field) != tv.get(field):
                vchanges[field] = {"before": bv.get(field), "after": tv.get(field)}
        if vchanges:
            result["igmp_snooping"]["changed"].append({"vlan_id": vid, "changes": vchanges})

    # ── VPN-instance multicast ────────────────────────────────────────
    def _vpn_key(v: dict) -> tuple:
        return (v.get("name", ""),)

    b_vpns = {_vpn_key(v): v for v in b_mc.get("pim", {}).get("vpn_instances", [])}
    t_vpns = {_vpn_key(v): v for v in t_mc.get("pim", {}).get("vpn_instances", [])}
    for k in sorted(set(t_vpns) - set(b_vpns)):
        result["vpn_instances"]["added"].append(t_vpns[k])
    for k in sorted(set(b_vpns) - set(t_vpns)):
        result["vpn_instances"]["removed"].append(b_vpns[k])
    for k in sorted(set(b_vpns) & set(t_vpns)):
        if b_vpns[k] != t_vpns[k]:
            result["vpn_instances"]["changed"].append({"name": dict(k) if isinstance(k, tuple) and len(k) == 1 else k, "before": b_vpns[k], "after": t_vpns[k]})

    return result


def _build_multicast_impacts(multicast: dict) -> list[dict]:
    """Build impact descriptions for multicast changes."""
    impacts = []

    for c in multicast.get("global", {}).get("changed", []):
        impacts.append({"impact": f"Multicast {c['label']}: {c['before']} -> {c['after']}.", "detail": "Ativa/desativa roteamento multicast global.", "severity": "warning"})

    for c in multicast.get("pim", {}).get("changed", []):
        if c.get("section") == "global":
            impacts.append({"impact": f"PIM global alterado.", "detail": "Parametros PIM (static-RP, BSR, RP-candidate) foram alterados.", "severity": "warning"})

    for iface in multicast.get("pim", {}).get("added", []):
        impacts.append({"impact": f"PIM adicionado na interface {iface.get('name')}.", "detail": "Nova interface PIM altera vizinhanca multicast.", "severity": "info"})
    for iface in multicast.get("pim", {}).get("removed", []):
        impacts.append({"impact": f"PIM removido da interface {iface.get('name')}.", "detail": "Interface sem PIM pode isolar vizinhanca multicast.", "severity": "warning"})
    for iface in multicast.get("pim", {}).get("changed", []):
        impacts.append({"impact": f"PIM alterado na interface {iface.get('name', '?')}.", "detail": "Modo/hello-holdtime PIM alterado.", "severity": "info"})

    for iface in multicast.get("igmp", {}).get("added", []):
        impacts.append({"impact": f"IGMP adicionado na interface {iface.get('name')}.", "detail": "Novos grupos multicast podem ser recebidos.", "severity": "info"})
    for iface in multicast.get("igmp", {}).get("removed", []):
        impacts.append({"impact": f"IGMP removido da interface {iface.get('name')}.", "detail": "Interface perde grupos multicast.", "severity": "warning"})
    for iface in multicast.get("igmp", {}).get("changed", []):
        impacts.append({"impact": f"IGMP alterado na interface {iface.get('name', '?')}.", "detail": "Versao ou grupos IGMP alterados.", "severity": "info"})

    for vlan in multicast.get("igmp_snooping", {}).get("added", []):
        impacts.append({"impact": f"IGMP snooping adicionado VLAN {vlan.get('vlan_id', '?')}.", "detail": "Nova VLAN com snooping.", "severity": "info"})
    for vlan in multicast.get("igmp_snooping", {}).get("removed", []):
        impacts.append({"impact": f"IGMP snooping removido VLAN {vlan.get('vlan_id', '?')}.", "detail": "VLAN pode inundar trafego multicast.", "severity": "warning"})
    for vlan in multicast.get("igmp_snooping", {}).get("changed", []):
        impacts.append({"impact": f"IGMP snooping alterado VLAN {vlan.get('vlan_id', '?')}.", "detail": "Parametros IGMP snooping alterados.", "severity": "info"})

    for iface in multicast.get("mld", {}).get("added", []):
        impacts.append({"impact": f"MLD adicionado interface {iface.get('name')}.", "detail": "Novos grupos IPv6 multicast.", "severity": "info"})
    for iface in multicast.get("mld", {}).get("removed", []):
        impacts.append({"impact": f"MLD removido interface {iface.get('name')}.", "detail": "Interface perde grupos IPv6 multicast.", "severity": "warning"})

    for v in multicast.get("vpn_instances", {}).get("added", []):
        impacts.append({"impact": f"VPN-instance multicast adicionado: {v.get('name', '?')}.", "detail": "Nova VPN com multicast.", "severity": "info"})
    for v in multicast.get("vpn_instances", {}).get("removed", []):
        impacts.append({"impact": f"VPN-instance multicast removido: {v.get('name', '?')}.", "detail": "VPN perdeu multicast.", "severity": "warning"})

    return impacts
