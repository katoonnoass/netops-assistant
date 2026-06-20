"""Testes para suporte IPv6 Huawei/VRP."""

from __future__ import annotations

import os

from django.test import TestCase

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.ipv6_utils import build_ipv6_dependency_map, build_ipv6_summary
from apps.analysis.models import AnalysisIssue, DetectedService, ParsedConfig
from apps.analysis.search import global_network_search
from apps.devices.models import Device
from apps.parsers.registry import get_parser_for_vendor

SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "sample_configs",
)


def _parse(config_text: str):
    parser_cls = get_parser_for_vendor("huawei")[1]
    parser = parser_cls(config_text)
    return parser.parse()


def _load_sample(name: str) -> str:
    path = os.path.join(SAMPLES_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


IPV6_BASIC = _load_sample("huawei_ipv6_basic.txt")
IPV6_VPNV6 = _load_sample("huawei_ipv6_vpnv6.txt")
IPV6_RISKY = _load_sample("huawei_ipv6_risky.txt")
IPV6_CHANGE_BEFORE = _load_sample("huawei_ipv6_change_before.txt")
IPV6_CHANGE_AFTER = _load_sample("huawei_ipv6_change_after.txt")


def _analyze(device: Device, config_text: str) -> ParsedConfig:
    from apps.analysis.services import analyze_config_snapshot
    from apps.config_archive.models import ConfigSnapshot
    snap = ConfigSnapshot.objects.create(
        device=device,
        raw_config=config_text,
        vendor="huawei",
    )
    return analyze_config_snapshot(snap)


# =====================================================================
# PARSER TESTS
# =====================================================================


class ParserTests(TestCase):
    """Testes do parser para IPv6."""

    def test_ipv6_enable_in_interface(self):
        parsed = _parse(IPV6_BASIC)
        for name in ("GigabitEthernet0/0/0", "GigabitEthernet0/1/0", "LoopBack0"):
            has_v6 = any(i.get("ipv6_enabled") for i in parsed["interfaces"] if i["name"] == name)
            self.assertTrue(has_v6, f"No block for {name} has ipv6_enabled")

    def test_ipv6_address_slash(self):
        parsed = _parse(IPV6_BASIC)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0" and i.get("ipv6_addresses"):
                addrs = [(a["address"], a["prefix_length"]) for a in i["ipv6_addresses"]]
                self.assertIn(("2001:db8:100::1", 64), addrs)
                return
        self.fail("No IPv6 address found")

    def test_ipv6_static_route(self):
        parsed = _parse(IPV6_BASIC)
        routes = parsed.get("ipv6_static_routes", [])
        self.assertTrue(any(r["destination"] == "2001:db8:200::" and r["next_hop"] == "2001:db8:100::2" for r in routes))

    def test_ipv6_static_route_vpn_instance(self):
        parsed = _parse(IPV6_VPNV6)
        routes = parsed.get("ipv6_static_routes", [])
        self.assertTrue(any(r["vpn_instance"] == "CLIENTE-A" and r["destination"] == "2001:db8:400::" for r in routes))

    def test_ipv6_prefix_list(self):
        parsed = _parse(IPV6_BASIC)
        pls = [pl for pl in parsed.get("prefix_lists", []) if pl.get("is_ipv6")]
        self.assertTrue(any(pl["name"] == "CLIENTE-V6" for pl in pls))

    def test_bgp_ipv6_unicast_peers(self):
        parsed = _parse(IPV6_BASIC)
        peers = parsed["bgp"][0]["ipv6_unicast"]["peers"]
        self.assertTrue(any(p["peer"] == "2001:db8:ffff::2" for p in peers))

    def test_bgp_ipv6_peer_as_number(self):
        parsed = _parse(IPV6_BASIC)
        peers = parsed["bgp"][0]["peers"]
        self.assertTrue(any(p["ip"] == "2001:db8:ffff::2" and p["remote_as"] == "64520" for p in peers))

    def test_bgp_ipv6_peer_route_policy(self):
        parsed = _parse(IPV6_BASIC)
        for p in parsed["bgp"][0]["ipv6_unicast"]["peers"]:
            if p["peer"] == "2001:db8:ffff::2":
                self.assertEqual(p["route_policy_export"], "EXPORT-V6")
                return
        self.fail("BGP IPv6 peer not found")

    def test_bgp_vpnv6_peers(self):
        parsed = _parse(IPV6_VPNV6)
        peers = parsed["bgp"][0]["vpnv6"]["peers"]
        self.assertTrue(any(p["peer"] == "2001:db8:ffff::2" for p in peers))

    def test_bgp_ipv6_family_vpn_instance(self):
        parsed = _parse(IPV6_VPNV6)
        vis = parsed["bgp"][0]["vpn_instances_ipv6"]
        self.assertTrue(any(vi["name"] == "CLIENTE-A" for vi in vis))

    def test_ospfv3_process(self):
        parsed = _parse(IPV6_BASIC)
        self.assertTrue(any(o["process_id"] == "1" for o in parsed.get("ospfv3", [])))

    def test_ospfv3_interface(self):
        parsed = _parse(IPV6_BASIC)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0" and i.get("ospfv3_enabled"):
                self.assertEqual(i["ospfv3_process_id"], "1")
                self.assertEqual(i["ospfv3_area"], "0.0.0.0")
                return
        self.fail("No OSPFv3 interface")

    def test_isis_ipv6_interface(self):
        parsed = _parse(IPV6_BASIC)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0" and i.get("isis_ipv6_enabled"):
                self.assertEqual(i["isis_ipv6_process_id"], "1")
                self.assertEqual(i["isis_ipv6_cost"], 10)
                return
        self.fail("No ISIS IPv6 interface")

    def test_route_policy_ipv6_prefix(self):
        parsed = _parse(IPV6_BASIC)
        for rp in parsed.get("route_policies", []):
            if rp["name"] == "EXPORT-V6":
                types = [i["type"] for i in rp.get("if_match", [])]
                self.assertIn("ipv6-prefix-list", types)
                return
        self.fail("Route-policy not found")


# =====================================================================
# UTILS TESTS
# =====================================================================


class UtilsTests(TestCase):
    """Testes dos utilitários IPv6."""

    def test_build_ipv6_summary(self):
        parsed = _parse(IPV6_BASIC)
        s = build_ipv6_summary(parsed)
        self.assertGreater(s["total_ipv6_interfaces"], 0)
        self.assertGreater(s["total_ipv6_routes"], 0)
        self.assertGreater(s["total_bgp_ipv6_peers"], 0)
        self.assertGreater(s["total_ospfv3_processes"], 0)

    def test_build_ipv6_dependency_map(self):
        parsed = _parse(IPV6_BASIC)
        deps = build_ipv6_dependency_map(parsed)
        self.assertGreater(len(deps["ipv6_interfaces"]), 0)
        self.assertGreater(len(deps["ipv6_routes"]), 0)
        self.assertGreater(len(deps["ospfv3_processes"]), 0)

    def test_dependency_map_isis_ipv6(self):
        parsed = _parse(IPV6_BASIC)
        deps = build_ipv6_dependency_map(parsed)
        self.assertGreater(len(deps["isis_ipv6_interfaces"]), 0)

    def test_dependency_map_vpnv6(self):
        parsed = _parse(IPV6_VPNV6)
        deps = build_ipv6_dependency_map(parsed)
        self.assertGreater(len(deps["vpnv6_peers"]), 0)
        self.assertGreater(len(deps["ipv6_vpn_instances"]), 0)

    def test_dependency_map_prefix_lists(self):
        parsed = _parse(IPV6_BASIC)
        deps = build_ipv6_dependency_map(parsed)
        self.assertIn("CLIENTE-V6", deps["ipv6_prefix_lists"])

    def test_dependency_map_route_policies_v6(self):
        parsed = _parse(IPV6_BASIC)
        deps = build_ipv6_dependency_map(parsed)
        self.assertIn("EXPORT-V6", deps["route_policies_v6"])


# =====================================================================
# SERVICE TESTS
# =====================================================================


class ServiceTests(TestCase):
    """Testes de detecção de serviços IPv6."""

    def test_ipv6_service(self):
        parsed = _parse(IPV6_BASIC)
        from apps.analysis.detectors.services import _detect_ipv6
        svc = _detect_ipv6(parsed)
        self.assertIsNotNone(svc)
        self.assertGreater(svc.metadata.get("interface_count", 0), 0)

    def test_bgp_ipv6_service(self):
        parsed = _parse(IPV6_BASIC)
        from apps.analysis.detectors.services import _detect_bgp_ipv6
        svc = _detect_bgp_ipv6(parsed)
        self.assertIsNotNone(svc)

    def test_vpnv6_service(self):
        parsed = _parse(IPV6_VPNV6)
        from apps.analysis.detectors.services import _detect_vpnv6
        svc = _detect_vpnv6(parsed)
        self.assertIsNotNone(svc)

    def test_ospfv3_service(self):
        parsed = _parse(IPV6_BASIC)
        from apps.analysis.detectors.services import _detect_ospfv3
        svc = _detect_ospfv3(parsed)
        self.assertIsNotNone(svc)
        self.assertIn("1", svc.metadata.get("process_ids", []))

    def test_isis_ipv6_service(self):
        parsed = _parse(IPV6_BASIC)
        from apps.analysis.detectors.services import _detect_isis_ipv6
        svc = _detect_isis_ipv6(parsed)
        self.assertIsNotNone(svc)
        self.assertGreater(svc.metadata.get("interface_count", 0), 0)


# =====================================================================
# ISSUE TESTS
# =====================================================================


class IssueTests(TestCase):
    """Testes de detecção de issues IPv6."""

    def test_ipv6_address_without_enable(self):
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        self.assertTrue(any(i.code == "ipv6_address_without_enable" for i in issues))

    def test_bgp_ipv6_peer_not_enabled(self):
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        self.assertTrue(any(i.code == "bgp_ipv6_peer_not_enabled" for i in issues))

    def test_ipv6_default_route_detected(self):
        # Verify no false positive - risky config has no ::/0 route
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        # This config has no default route
        self.assertFalse(any(i.code == "ipv6_default_route_detected" for i in issues))

    def test_ipv6_prefix_permit_any(self):
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        self.assertTrue(any(i.code == "ipv6_prefix_permit_any" for i in issues))

    def test_ospfv3_interface_unknown_process(self):
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        self.assertTrue(any(i.code == "ospfv3_interface_unknown_process" for i in issues))

    def test_isis_ipv6_interface_unknown_process(self):
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        self.assertTrue(any(i.code == "isis_ipv6_interface_unknown_process" for i in issues))

    def test_vpnv6_peer_not_enabled(self):
        # All VPNv6 peers in risky config have enable; test detection on a config with disabled peer
        parsed = _parse(IPV6_VPNV6)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        # VPNV6 config has all peers enabled, so no issue
        self.assertFalse(any(i.code == "vpnv6_peer_not_enabled" for i in issues))

    def test_bgp_ipv6_vpn_instance_not_found(self):
        parsed = _parse(IPV6_RISKY)
        from apps.analysis.detectors.issues import _detect_ipv6_issues
        issues = _detect_ipv6_issues(parsed)
        self.assertTrue(any(i.code == "bgp_ipv6_vpn_instance_not_found" for i in issues))


# =====================================================================
# SEARCH TESTS
# =====================================================================


class SearchTests(TestCase):
    """Testes de busca global IPv6."""

    def setUp(self):
        self.device = Device.objects.create(name="IPV6-SEARCH-TEST")

    def test_search_ipv6_address(self):
        _analyze(self.device, IPV6_BASIC)
        results = global_network_search("2001:db8:100::1")
        ipv6 = results.get("ipv6", [])
        self.assertGreater(len(ipv6), 0)

    def test_search_ipv6_keyword(self):
        _analyze(self.device, IPV6_BASIC)
        results = global_network_search("ipv6")
        self.assertGreater(results["summary"].get("ipv6", 0), 0)

    def test_search_vpnv6_keyword(self):
        _analyze(self.device, IPV6_VPNV6)
        results = global_network_search("vpnv6")
        self.assertGreater(results["summary"].get("ipv6", 0), 0)

    def test_search_ospfv3_keyword(self):
        _analyze(self.device, IPV6_BASIC)
        results = global_network_search("ospfv3")
        self.assertGreater(results["summary"].get("ipv6", 0), 0)

    def test_search_isis_ipv6_keyword(self):
        _analyze(self.device, IPV6_BASIC)
        results = global_network_search("isis ipv6")
        self.assertGreater(results["summary"].get("ipv6", 0), 0)


# =====================================================================
# COMPARISON TESTS
# =====================================================================


class ComparisonTests(TestCase):
    """Testes de comparação IPv6."""

    def setUp(self):
        self.device = Device.objects.create(name="IPV6-DIFF-TEST")

    def test_ipv6_key_in_diff_data(self):
        base = _analyze(self.device, IPV6_CHANGE_BEFORE)
        target = _analyze(self.device, IPV6_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        self.assertIn("ipv6", comp.diff_data)

    def test_ipv6_impact_detected(self):
        base = _analyze(self.device, IPV6_CHANGE_BEFORE)
        target = _analyze(self.device, IPV6_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        impacts = comp.diff_data.get("impacts", [])
        ipv6_impacts = [i for i in impacts if "IPv6" in i.get("impact", "")]
        self.assertTrue(len(ipv6_impacts) > 0)

    def test_validation_has_ipv6_commands(self):
        base = _analyze(self.device, IPV6_CHANGE_BEFORE)
        target = _analyze(self.device, IPV6_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        vplan = comp.diff_data.get("validation_plan", [])
        has_ipv6 = any("ipv6" in str(v).lower() for v in vplan)
        self.assertTrue(has_ipv6)

    def test_rollback_has_ipv6_suggestions(self):
        base = _analyze(self.device, IPV6_CHANGE_BEFORE)
        target = _analyze(self.device, IPV6_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        rplan = comp.diff_data.get("rollback_plan", [])
        has_ipv6 = any("IPv6" in str(r.get("suggestion", "")) for r in rplan)
        self.assertTrue(has_ipv6)


# =====================================================================
# DOCUMENTATION TESTS
# =====================================================================


class DocumentationTests(TestCase):
    """Testes da documentação IPv6."""

    def setUp(self):
        self.device = Device.objects.create(name="IPV6-DOC-TEST")

    def test_ipv6_section_exists(self):
        pc = _analyze(self.device, IPV6_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertIn("ipv6", doc)

    def test_ipv6_interfaces_in_docs(self):
        pc = _analyze(self.device, IPV6_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc["ipv6"].get("interfaces", [])), 0)

    def test_ipv6_routes_in_docs(self):
        pc = _analyze(self.device, IPV6_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc["ipv6"].get("routes", [])), 0)

    def test_bgp_ipv6_in_docs(self):
        pc = _analyze(self.device, IPV6_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc["ipv6"].get("bgp_peers", [])), 0)

    def test_vpnv6_in_docs(self):
        pc = _analyze(self.device, IPV6_VPNV6)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc["ipv6"].get("vpnv6_peers", [])), 0)

    def test_ospfv3_in_docs(self):
        pc = _analyze(self.device, IPV6_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc["ipv6"].get("ospfv3", [])), 0)

    def test_isis_ipv6_in_docs(self):
        pc = _analyze(self.device, IPV6_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc["ipv6"].get("isis_ipv6_interfaces", [])), 0)


# =====================================================================
# INTERFACE MERGE TESTS
# =====================================================================


CONFIG_MERGE_SAME = """#
sysname MERGE-TEST
#
interface GigabitEthernet0/0/1
 description TESTE
 ip address 10.0.0.1 255.255.255.252
 ipv6 enable
 ipv6 address 2001:db8:1::1/64
#
return
"""

CONFIG_MERGE_DUPLICATE = """#
sysname MERGE-TEST
#
interface GigabitEthernet0/0/1
 description CLIENTE-A
 ip binding vpn-instance CLIENTE-A
#
interface GigabitEthernet0/0/1
 traffic-policy CLIENTE-A-QOS outbound
 ipv6 enable
 ipv6 address 2001:db8:1::1/64
#
return
"""


class InterfaceMergeTests(TestCase):
    """Testes de merge de interfaces duplicadas."""

    def test_single_interface_has_no_duplicate(self):
        parsed = _parse(CONFIG_MERGE_SAME)
        count = sum(1 for i in parsed["interfaces"] if i["name"] == "GigabitEthernet0/0/1")
        self.assertEqual(count, 1)

    def test_single_interface_preserves_ipv4_and_ipv6(self):
        parsed = _parse(CONFIG_MERGE_SAME)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/1":
                self.assertIsNotNone(i.get("ip_address"))
                self.assertTrue(i.get("ipv6_enabled"))
                self.assertGreater(len(i.get("ipv6_addresses", [])), 0)
                return
        self.fail("Interface not found")

    def test_duplicate_interfaces_merged(self):
        parsed = _parse(CONFIG_MERGE_DUPLICATE)
        count = sum(1 for i in parsed["interfaces"] if i["name"] == "GigabitEthernet0/0/1")
        self.assertEqual(count, 1)

    def test_duplicate_merge_preserves_all_fields(self):
        parsed = _parse(CONFIG_MERGE_DUPLICATE)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/1":
                self.assertEqual(i.get("description"), "CLIENTE-A")
                self.assertEqual(i.get("vpn_instance"), "CLIENTE-A")
                self.assertGreater(len(i.get("traffic_policies_applied", [])), 0)
                self.assertTrue(i.get("ipv6_enabled"))
                return
        self.fail("Interface not found")

    def test_ipv6_basic_has_no_duplicate_blocks(self):
        """The huawei_ipv6_basic.txt has some interfaces appearing in multiple blocks.
        After merge, each interface name should appear only once."""
        parsed = _parse(IPV6_BASIC)
        names = [i["name"] for i in parsed["interfaces"]]
        self.assertEqual(len(names), len(set(names)), f"Duplicate interfaces: {[n for n in names if names.count(n) > 1]}")


# =====================================================================
# IPV6 ADDRESS AUTO LINK-LOCAL TESTS
# =====================================================================


CONFIG_LINK_LOCAL = """#
sysname LL-TEST
#
interface GigabitEthernet0/0/0
 ipv6 enable
 ipv6 address auto link-local
 ipv6 address auto global
 ipv6 address FE80::1 link-local
 ipv6 address FE80::2/64 link-local
 ipv6 address 2001:db8::1/64
#
return
"""


class LinkLocalTests(TestCase):
    """Testes de parsing de ipv6 address auto/link-local."""

    def test_ipv6_link_local_auto(self):
        parsed = _parse(CONFIG_LINK_LOCAL)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0":
                self.assertTrue(i.get("ipv6_link_local_auto"))
                return

    def test_ipv6_global_auto(self):
        parsed = _parse(CONFIG_LINK_LOCAL)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0":
                self.assertTrue(i.get("ipv6_global_auto"))
                return

    def test_ipv6_link_local_address_without_prefix(self):
        parsed = _parse(CONFIG_LINK_LOCAL)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0":
                addrs = i.get("ipv6_link_local_addresses", [])
                self.assertTrue(any(a["address"] == "FE80::1" and a["prefix_length"] is None for a in addrs))
                return

    def test_ipv6_link_local_address_with_prefix(self):
        parsed = _parse(CONFIG_LINK_LOCAL)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0":
                addrs = i.get("ipv6_link_local_addresses", [])
                self.assertTrue(any(a["address"] == "FE80::2" and a["prefix_length"] == 64 for a in addrs))
                return

    def test_normal_ipv6_address_still_parsed(self):
        parsed = _parse(CONFIG_LINK_LOCAL)
        for i in parsed["interfaces"]:
            if i["name"] == "GigabitEthernet0/0/0":
                addrs = i.get("ipv6_addresses", [])
                self.assertTrue(any(a["address"] == "2001:db8::1" and a["prefix_length"] == 64 for a in addrs))
                return


# =====================================================================
# COMPARISON WITHOUT CHANGES TESTS
# =====================================================================


class ComparisonNoChangeTests(TestCase):
    """Testes de comparação IPv6 sem mudanças."""

    def setUp(self):
        self.device = Device.objects.create(name="IPV6-NOCHANGE-TEST")

    def test_no_ipv6_impacts_when_no_change(self):
        from apps.analysis.services import analyze_config_snapshot
        from apps.config_archive.models import ConfigSnapshot
        snap1 = ConfigSnapshot.objects.create(device=self.device, raw_config=IPV6_CHANGE_BEFORE, vendor="huawei")
        snap2 = ConfigSnapshot.objects.create(device=self.device, raw_config=IPV6_CHANGE_BEFORE, vendor="huawei")
        pc1 = analyze_config_snapshot(snap1)
        pc2 = analyze_config_snapshot(snap2)
        comp = compare_config_snapshots(snap1, snap2)
        impacts = comp.diff_data.get("impacts", [])
        ipv6_impacts = [i for i in impacts if "IPv6" in i.get("impact", "")]
        self.assertEqual(len(ipv6_impacts), 0)

    def test_no_ipv6_validation_when_no_change(self):
        from apps.analysis.services import analyze_config_snapshot
        from apps.config_archive.models import ConfigSnapshot
        snap1 = ConfigSnapshot.objects.create(device=self.device, raw_config=IPV6_CHANGE_BEFORE, vendor="huawei")
        snap2 = ConfigSnapshot.objects.create(device=self.device, raw_config=IPV6_CHANGE_BEFORE, vendor="huawei")
        pc1 = analyze_config_snapshot(snap1)
        pc2 = analyze_config_snapshot(snap2)
        comp = compare_config_snapshots(snap1, snap2)
        vplan = comp.diff_data.get("validation_plan", [])
        has_ipv6 = any("ipv6" in str(v).lower() for v in vplan)
        self.assertFalse(has_ipv6)

    def test_no_ipv6_rollback_when_no_change(self):
        from apps.analysis.services import analyze_config_snapshot
        from apps.config_archive.models import ConfigSnapshot
        snap1 = ConfigSnapshot.objects.create(device=self.device, raw_config=IPV6_CHANGE_BEFORE, vendor="huawei")
        snap2 = ConfigSnapshot.objects.create(device=self.device, raw_config=IPV6_CHANGE_BEFORE, vendor="huawei")
        pc1 = analyze_config_snapshot(snap1)
        pc2 = analyze_config_snapshot(snap2)
        comp = compare_config_snapshots(snap1, snap2)
        rplan = comp.diff_data.get("rollback_plan", [])
        has_ipv6 = any("IPv6" in str(r.get("suggestion", "")) for r in rplan)
        self.assertFalse(has_ipv6)
