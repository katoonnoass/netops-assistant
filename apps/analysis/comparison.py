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

    # Build switching section
    switching = _build_switching_section(interfaces, base_data, target_data)

    # Service-specific impacts
    service_impacts = _build_service_impacts(services)

    # Policy impacts
    policy_impacts = _build_policy_impacts(base_data, target_data)
    switching_impacts = _build_switching_impacts(vlans, stp_comp, switching)
    isis_mpls_impacts = _build_isis_mpls_impacts(isis, mpls, mpls_ldp)

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
    impacts = _build_impacts(interfaces, static_routes, bgp, circuits, issues)
    impacts.extend(service_impacts)
    impacts.extend(switching_impacts)
    impacts.extend(policy_impacts)
    impacts.extend(isis_mpls_impacts)
    recommendations = _build_recommendations(interfaces, static_routes, bgp, circuits, issues)

    # Build summary
    summary_parts = [
        f"Comparação: {title}" if title else f"Comparação de snapshots.",
        f"Interfaces: {_fmt_summary(interfaces)}.",
        f"Rotas estáticas: {_fmt_summary(static_routes)}.",
        f"BGP: {_fmt_bgp_summary(bgp)}.",
        f"ISIS: {_fmt_summary(isis)}.",
        f"MPLS: {_fmt_mpls_summary(mpls)}.",
        f"MPLS LDP: {_fmt_mpls_ldp_summary(mpls_ldp)}.",
        f"Circuitos: {_fmt_summary(circuits)}.",
        f"Serviços: {_fmt_summary(services)}.",
        f"Issues: {issues.get('new_count', 0)} nova(s), "
        f"{issues.get('resolved_count', 0)} resolvida(s).",
    ]

    diff_data = {
        "raw_diff": raw_diff,
        "interfaces": interfaces,
        "static_routes": static_routes,
        "bgp": bgp,
        "isis": isis,
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
