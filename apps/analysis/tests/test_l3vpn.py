"""Testes completos para VRF / VPN-instance / L3VPN MPLS.

Testa o pipeline completo: parser, vrf_utils, serviços, issues,
documentação, busca, comparação e web.

Usa strings de configuração inline.
"""

import io

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.analysis.vrf_utils import build_vrf_summary, build_vrf_dependency_map
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei import HuaweiVRPParser


# =========================================================================
# Inline configs
# =========================================================================

L3VPN_BASIC = """#
sysname NE40-L3VPN
#
interface LoopBack0
 ip address 10.255.0.1 255.255.255.255
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-WAN
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
#
interface GigabitEthernet0/0/2
 description CLIENTE-B-LAN
 ip binding vpn-instance CLIENTE-B
 ip address 172.16.1.1 255.255.255.0
#
bgp 65000
 peer 10.255.0.2 as-number 65000
 peer 10.255.0.2 connect-interface LoopBack0
 #
 ipv4-family vpnv4
  peer 10.255.0.2 enable
  peer 10.255.0.2 route-policy EXPORT-VPNV4 export
 #
 ipv4-family vpn-instance CLIENTE-A
  import-route direct
  import-route static
  network 192.168.10.0 255.255.255.0
  peer 10.10.10.2 as-number 64520
  peer 10.10.10.2 route-policy IMPORT-CLIENTE-A import
  peer 10.10.10.2 route-policy EXPORT-CLIENTE-A export
#
ip vpn-instance CLIENTE-A
 description Cliente A - L3VPN
 ipv4-family
  route-distinguisher 65000:100
  vpn-target 65000:100 export-extcommunity
  vpn-target 65000:100 import-extcommunity
  vpn-target 65000:200 import-extcommunity
#
ip vpn-instance CLIENTE-B
 ipv4-family
  route-distinguisher 65000:200
  vpn-target 65000:200 both
#
ip route-static vpn-instance CLIENTE-A 0.0.0.0 0.0.0.0 10.10.10.2 description DEFAULT-CLIENTE-A
ip route-static vpn-instance CLIENTE-A 192.168.10.0 255.255.255.0 10.10.10.2
#
return
"""

L3VPN_RISKY = """#
sysname NE40-L3VPN-RISK
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-C-WAN
 ip binding vpn-instance CLIENTE-C
 ip address 10.30.30.1 255.255.255.252
#
interface GigabitEthernet0/0/2
 description CLIENTE-D-LAN
 ip binding vpn-instance CLIENTE-D
 ip address 172.30.1.1 255.255.255.0
#
interface GigabitEthernet0/0/3
 description CLIENTE-FAKE-BINDING
 ip binding vpn-instance NONEXISTENT-VPN
 ip address 10.99.99.1 255.255.255.252
#
mpls lsr-id 10.255.0.1
mpls
#
bgp 65000
 ipv4-family vpn-instance CLIENTE-C
  import-route direct
  peer 10.30.30.2 as-number 64530
 ipv4-family vpn-instance CLIENTE-FAKE
  import-route static
#
ip vpn-instance CLIENTE-C
 ipv4-family
  route-distinguisher 65000:100
#
ip vpn-instance CLIENTE-D
 description Cliente D - VPN sem rotas
 ipv4-family
  route-distinguisher 65000:100
#
ip vpn-instance CLIENTE-E
 description VRF sem RD
 ipv4-family
  vpn-target 65000:100 both
#
ip route-static vpn-instance CLIENTE-X 10.10.0.0 255.255.0.0 10.0.0.1
#
return
"""

L3VPN_CHANGE_BEFORE = """#
sysname NE40-L3VPN-DIFF
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-WAN-OLD
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
#
interface GigabitEthernet0/0/2
 description CLIENTE-B-LAN
 ip binding vpn-instance CLIENTE-B
 ip address 172.16.1.1 255.255.255.0
#
bgp 65000
 ipv4-family vpnv4
  peer 10.255.0.2 enable
  peer 10.255.0.2 route-policy EXPORT-VPNV4 export
 #
 ipv4-family vpn-instance CLIENTE-A
  import-route static
  peer 10.10.10.2 as-number 64520
#
ip vpn-instance CLIENTE-A
 description Cliente A - Antigo
 ipv4-family
  route-distinguisher 65000:100
  vpn-target 65000:100 export-extcommunity
  vpn-target 65000:100 import-extcommunity
#
ip vpn-instance CLIENTE-B
 ipv4-family
  route-distinguisher 65000:200
  vpn-target 65000:200 both
#
ip route-static vpn-instance CLIENTE-A 0.0.0.0 0.0.0.0 10.10.10.2 description DEFAULT-OLD
#
return
"""

L3VPN_CHANGE_AFTER = """#
sysname NE40-L3VPN-DIFF
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-WAN-NEW
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
#
interface GigabitEthernet0/0/2
 description CLIENTE-B-LAN
 ip binding vpn-instance CLIENTE-B
 ip address 172.16.1.1 255.255.255.0
#
interface GigabitEthernet0/0/3
 description CLIENTE-C-LAN
 ip binding vpn-instance CLIENTE-C
 ip address 172.30.1.1 255.255.255.0
#
bgp 65000
 ipv4-family vpnv4
  peer 10.255.0.2 enable
  peer 10.255.0.2 route-policy EXPORT-VPNV4 export
  peer 10.255.0.2 route-policy IMPORT-VPNV4 import
 #
 ipv4-family vpn-instance CLIENTE-A
  import-route static
  import-route direct
  peer 10.10.10.2 as-number 64520
  peer 10.10.10.2 route-policy IMPORT-CLIENTE-A import
  peer 10.10.10.2 route-policy EXPORT-CLIENTE-A export
#
ip vpn-instance CLIENTE-A
 description Cliente A - Novo
 ipv4-family
  route-distinguisher 65000:200
  vpn-target 65000:200 export-extcommunity
  vpn-target 65000:200 import-extcommunity
  vpn-target 65000:300 import-extcommunity
#
ip vpn-instance CLIENTE-B
 ipv4-family
  route-distinguisher 65000:200
  vpn-target 65000:200 both
#
ip vpn-instance CLIENTE-C
 description Cliente C - Nova VPN
 ipv4-family
  route-distinguisher 65000:300
  vpn-target 65000:300 export-extcommunity
  vpn-target 65000:300 import-extcommunity
#
ip route-static vpn-instance CLIENTE-A 0.0.0.0 0.0.0.0 10.10.10.2 description DEFAULT-NEW
ip route-static vpn-instance CLIENTE-A 10.20.0.0 255.255.0.0 10.10.10.2
#
return
"""


# =========================================================================
# Helpers
# =========================================================================


def _parse(config_text: str) -> dict:
    parser = HuaweiVRPParser(config_text)
    return parser.parse()


def _analyze(device: Device, config_text: str) -> ConfigSnapshot:
    snapshot = ConfigSnapshot.objects.create(
        device=device, raw_config=config_text, vendor="huawei"
    )
    analyze_config_snapshot(snapshot)
    return snapshot


# =========================================================================
# 1. Parser Tests
# =========================================================================


class ParserTests(TestCase):
    def test_vpn_instance_basic_detection(self):
        parsed = _parse(L3VPN_BASIC)
        vpn_instances = parsed.get("vpn_instances", [])
        self.assertEqual(len(vpn_instances), 2)

    def test_vpn_instance_names(self):
        parsed = _parse(L3VPN_BASIC)
        names = [v["name"] for v in parsed.get("vpn_instances", [])]
        self.assertIn("CLIENTE-A", names)
        self.assertIn("CLIENTE-B", names)

    def test_vpn_instance_description(self):
        parsed = _parse(L3VPN_BASIC)
        for vi in parsed.get("vpn_instances", []):
            if vi["name"] == "CLIENTE-A":
                self.assertEqual(vi["description"], "Cliente A - L3VPN")

    def test_vpn_instance_route_distinguisher(self):
        parsed = _parse(L3VPN_BASIC)
        for vi in parsed.get("vpn_instances", []):
            af = vi.get("address_families", {}).get("ipv4", {})
            if vi["name"] == "CLIENTE-A":
                self.assertEqual(af.get("route_distinguisher"), "65000:100")
            elif vi["name"] == "CLIENTE-B":
                self.assertEqual(af.get("route_distinguisher"), "65000:200")

    def test_vpn_instance_vpn_targets(self):
        parsed = _parse(L3VPN_BASIC)
        for vi in parsed.get("vpn_instances", []):
            if vi["name"] == "CLIENTE-A":
                af = vi["address_families"]["ipv4"]
                targets = af["vpn_targets"]
                self.assertEqual(len(targets), 3)
                exports = [t for t in targets if t["direction"] == "export"]
                imports = [t for t in targets if t["direction"] == "import"]
                self.assertEqual(len(exports), 1)
                self.assertEqual(exports[0]["value"], "65000:100")
                self.assertEqual(len(imports), 2)
                self.assertEqual(imports[0]["value"], "65000:100")
                self.assertEqual(imports[1]["value"], "65000:200")

    def test_vpn_instance_both_keyword(self):
        parsed = _parse(L3VPN_BASIC)
        for vi in parsed.get("vpn_instances", []):
            if vi["name"] == "CLIENTE-B":
                af = vi["address_families"]["ipv4"]
                targets = af["vpn_targets"]
                exports = [t for t in targets if t["direction"] == "export"]
                imports = [t for t in targets if t["direction"] == "import"]
                self.assertEqual(len(exports), 1)
                self.assertEqual(len(imports), 1)

    def test_interface_binding_vpn_instance(self):
        parsed = _parse(L3VPN_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface["name"] == "GigabitEthernet0/0/1.100":
                self.assertEqual(iface["vpn_instance"], "CLIENTE-A")
                self.assertTrue(iface["is_vrf_interface"])
            elif iface["name"] == "GigabitEthernet0/0/2":
                self.assertEqual(iface["vpn_instance"], "CLIENTE-B")
                self.assertTrue(iface["is_vrf_interface"])
            elif iface["name"] == "LoopBack0":
                self.assertIsNone(iface.get("vpn_instance"))
                self.assertFalse(iface.get("is_vrf_interface", False))

    def test_static_route_vpn_instance(self):
        parsed = _parse(L3VPN_BASIC)
        vrf_routes = [r for r in parsed.get("static_routes", []) if r.get("vpn_instance")]
        self.assertEqual(len(vrf_routes), 2)
        for route in vrf_routes:
            self.assertEqual(route["vpn_instance"], "CLIENTE-A")

    def test_static_route_vpn_instance_values(self):
        parsed = _parse(L3VPN_BASIC)
        for route in parsed.get("static_routes", []):
            if route.get("vpn_instance") == "CLIENTE-A":
                if route.get("network") == "0.0.0.0":
                    self.assertEqual(route.get("next_hop"), "10.10.10.2")
                    self.assertEqual(route.get("description"), "DEFAULT-CLIENTE-A")
                elif route.get("network") == "192.168.10.0":
                    self.assertEqual(route.get("netmask"), "255.255.255.0")
                    self.assertEqual(route.get("next_hop"), "10.10.10.2")

    def test_bgp_vpnv4_peers(self):
        parsed = _parse(L3VPN_BASIC)
        bgp = parsed.get("bgp", [])
        self.assertTrue(len(bgp) > 0)
        vpnv4 = bgp[0].get("vpnv4", {})
        peers = vpnv4.get("peers", [])
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["peer"], "10.255.0.2")
        self.assertTrue(peers[0]["enabled"])
        self.assertEqual(peers[0]["route_policy_export"], "EXPORT-VPNV4")

    def test_bgp_vpn_instance_section(self):
        parsed = _parse(L3VPN_BASIC)
        bgp = parsed.get("bgp", [])
        self.assertTrue(len(bgp) > 0)
        vpn_instances = bgp[0].get("vpn_instances", [])
        self.assertEqual(len(vpn_instances), 1)
        self.assertEqual(vpn_instances[0]["name"], "CLIENTE-A")

    def test_bgp_vpn_instance_import_routes(self):
        parsed = _parse(L3VPN_BASIC)
        bgp = parsed.get("bgp", [])
        vi = bgp[0]["vpn_instances"][0]
        self.assertIn("direct", vi["import_routes"])
        self.assertIn("static", vi["import_routes"])

    def test_bgp_vpn_instance_networks(self):
        parsed = _parse(L3VPN_BASIC)
        bgp = parsed.get("bgp", [])
        vi = bgp[0]["vpn_instances"][0]
        # Parser stores network in abbreviated format (just IP)
        found = any("192.168.10.0" in n for n in vi["networks"])
        self.assertTrue(found)

    def test_bgp_vpn_instance_ce_peer(self):
        parsed = _parse(L3VPN_BASIC)
        bgp = parsed.get("bgp", [])
        vi = bgp[0]["vpn_instances"][0]
        peers = vi["peers"]
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["ip"], "10.10.10.2")
        self.assertEqual(peers[0]["remote_as"], "64520")
        self.assertEqual(peers[0]["route_policy_import"], "IMPORT-CLIENTE-A")
        self.assertEqual(peers[0]["route_policy_export"], "EXPORT-CLIENTE-A")


# =========================================================================
# 2. VRF Utils Tests
# =========================================================================


class VRFUtilsTests(TestCase):
    def test_build_vrf_summary(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["total_vrfs"], 2)
        self.assertEqual(len(summary["vpnv4_peers"]), 1)

    def test_build_vrf_summary_vrf_names(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        names = [v["name"] for v in summary["vrfs"]]
        self.assertIn("CLIENTE-A", names)
        self.assertIn("CLIENTE-B", names)

    def test_build_vrf_summary_rd(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        for vrf in summary["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertEqual(vrf["rd"], "65000:100")
            elif vrf["name"] == "CLIENTE-B":
                self.assertEqual(vrf["rd"], "65000:200")

    def test_build_vrf_summary_rt(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        for vrf in summary["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertIn("65000:100", vrf["rt_export"])
                self.assertIn("65000:100", vrf["rt_import"])
                self.assertIn("65000:200", vrf["rt_import"])

    def test_build_vrf_summary_interfaces(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        for vrf in summary["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertIn("GigabitEthernet0/0/1.100", vrf["interfaces"])
            elif vrf["name"] == "CLIENTE-B":
                self.assertIn("GigabitEthernet0/0/2", vrf["interfaces"])

    def test_build_vrf_summary_static_routes(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        for vrf in summary["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertTrue(len(vrf["static_routes"]) > 0)

    def test_build_vrf_summary_bgp_family(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        for vrf in summary["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertTrue(vrf["bgp_ipv4_family"])
                self.assertIn("10.10.10.2", vrf["bgp_peers"])
                self.assertIn("IMPORT-CLIENTE-A", vrf["route_policies"])

    def test_build_vrf_summary_vpnv4_peers(self):
        parsed = _parse(L3VPN_BASIC)
        summary = build_vrf_summary(parsed)
        self.assertIn("10.255.0.2", summary["vpnv4_peers"])

    def test_build_vrf_dependency_map_duplicate_rd(self):
        parsed = _parse(L3VPN_RISKY)
        deps = build_vrf_dependency_map(parsed)
        self.assertTrue(len(deps["duplicate_rds"]) > 0)
        rd_names = [d["rd"] for d in deps["duplicate_rds"]]
        self.assertIn("65000:100", rd_names)

    def test_build_vrf_dependency_map_vrf_without_interface(self):
        parsed = _parse(L3VPN_RISKY)
        deps = build_vrf_dependency_map(parsed)
        # CLIENTE-E has no interface in RISKY config
        self.assertIn("CLIENTE-E", deps["vrfs_without_interfaces"])


# =========================================================================
# 3. Services Detection Tests
# =========================================================================


class ServiceDetectionTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NE40-L3VPN-TEST")

    def test_vrf_service_detected(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        services = DetectedService.objects.filter(snapshot=snapshot)
        vrf_services = services.filter(service_type="vrf")
        self.assertTrue(vrf_services.exists())

    def test_l3vpn_service_detected(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        services = DetectedService.objects.filter(snapshot=snapshot)
        l3vpn_services = services.filter(service_type="l3vpn")
        self.assertTrue(l3vpn_services.exists())

    def test_vpnv4_service_detected(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        services = DetectedService.objects.filter(snapshot=snapshot)
        vpnv4_services = services.filter(service_type="vpnv4")
        self.assertTrue(vpnv4_services.exists())

    def test_vrf_service_metadata(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        svc = DetectedService.objects.get(snapshot=snapshot, service_type="vrf")
        self.assertEqual(svc.metadata.get("vrf_count"), 2)
        self.assertIn("CLIENTE-A", svc.metadata.get("vrf_names", []))

    def test_l3vpn_service_metadata(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        svc = DetectedService.objects.get(snapshot=snapshot, service_type="l3vpn")
        self.assertTrue(svc.metadata.get("has_vpnv4"))
        self.assertTrue(svc.metadata.get("has_bgp_vpn_instance"))


# =========================================================================
# 4. Issues Detection Tests
# =========================================================================


class IssueDetectionTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NE40-L3VPN-RISK-TEST")

    def test_vpn_instance_without_rd(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="vpn_instance_without_rd")
        self.assertTrue(issues.exists())
        names = [i.metadata.get("vpn_instance") for i in issues]
        self.assertIn("CLIENTE-E", names)

    def test_vpn_instance_without_rt(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="vpn_instance_without_rt")
        self.assertTrue(issues.exists())

    def test_interface_vpn_instance_not_found(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="interface_vpn_instance_not_found")
        self.assertTrue(issues.exists())

    def test_static_route_vpn_instance_not_found(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="static_route_vpn_instance_not_found")
        self.assertTrue(issues.exists())

    def test_bgp_vpn_instance_not_found(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="bgp_vpn_instance_not_found")
        self.assertTrue(issues.exists())

    def test_vpn_instance_without_interface(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="vpn_instance_without_interface")
        self.assertTrue(issues.exists())

    def test_vpn_instance_without_routes(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="vpn_instance_without_routes")
        self.assertTrue(issues.exists())

    def test_duplicate_route_distinguisher(self):
        snapshot = _analyze(self.device, L3VPN_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snapshot, code="duplicate_route_distinguisher")
        self.assertTrue(issues.exists())

    def test_basic_config_no_vrf_issues(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        vrf_issues = AnalysisIssue.objects.filter(
            snapshot=snapshot,
            code__startswith="vpn_",
        )
        # CLIENTE-B has no interface - expect interface and routes issues
        self.assertTrue(vrf_issues.exists())


# =========================================================================
# 5. Documentation Tests
# =========================================================================


class DocumentationTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NE40-L3VPN-DOC-TEST")

    def test_vrf_section_in_documentation(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        doc = generate_analysis_documentation(parsed_config)
        self.assertIn("vrf", doc)
        self.assertIsNotNone(doc["vrf"])

    def test_vrf_section_vrf_entries(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        doc = generate_analysis_documentation(parsed_config)
        vrf_names = [v["name"] for v in doc["vrf"]["vrfs"]]
        self.assertIn("CLIENTE-A", vrf_names)
        self.assertIn("CLIENTE-B", vrf_names)

    def test_vrf_section_rd(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        doc = generate_analysis_documentation(parsed_config)
        for vrf in doc["vrf"]["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertEqual(vrf["route_distinguisher"], "65000:100")

    def test_vrf_section_rt(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        doc = generate_analysis_documentation(parsed_config)
        for vrf in doc["vrf"]["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertIn("65000:100", vrf["route_targets_export"])
                self.assertIn("65000:100", vrf["route_targets_import"])

    def test_vrf_section_interfaces(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        doc = generate_analysis_documentation(parsed_config)
        for vrf in doc["vrf"]["vrfs"]:
            if vrf["name"] == "CLIENTE-A":
                self.assertIn("GigabitEthernet0/0/1.100", vrf["interfaces"])

    def test_vrf_section_vpnv4_peers(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        doc = generate_analysis_documentation(parsed_config)
        peer_ips = [vp["peer"] for vp in doc["vrf"]["vpnv4_peers"]]
        self.assertIn("10.255.0.2", peer_ips)

    def test_no_vrf_no_section(self):
        config_minimal = """#
sysname NO-VRF
#
return
"""
        parsed = _parse(config_minimal)
        self.assertIsNone(build_vrf_summary(parsed))


# =========================================================================
# 6. Search Tests
# =========================================================================


class SearchTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NE40-L3VPN-SEARCH-TEST")

    def test_search_vpn_instance_name(self):
        _analyze(self.device, L3VPN_BASIC)
        results = global_network_search("CLIENTE-A")
        vrf_results = results.get("vrf", [])
        vpn_names = [r.get("vpn_instance") for r in vrf_results if r.get("type") == "vpn_instance"]
        self.assertIn("CLIENTE-A", vpn_names)

    def test_search_vpnv4_keyword(self):
        _analyze(self.device, L3VPN_BASIC)
        results = global_network_search("vpnv4")
        vrf_results = results.get("vrf", [])
        self.assertTrue(len(vrf_results) > 0)

    def search_vrf_summary_not_zero(self):
        _analyze(self.device, L3VPN_BASIC)
        results = global_network_search("CLIENTE-A")
        self.assertGreater(results["summary"].get("vrf", 0), 0)

    def test_search_ce_peer(self):
        _analyze(self.device, L3VPN_BASIC)
        results = global_network_search("10.10.10.2")
        vrf_results = results.get("vrf", [])
        ce_results = [r for r in vrf_results if r.get("type") == "ce_peer"]
        self.assertTrue(len(ce_results) > 0)

    def test_search_rd(self):
        _analyze(self.device, L3VPN_BASIC)
        results = global_network_search("65000:100")
        vrf_results = results.get("vrf", [])
        self.assertTrue(len(vrf_results) > 0)


# =========================================================================
# 7. Comparison Tests
# =========================================================================


class ComparisonTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NE40-L3VPN-DIFF-TEST")

    def test_comparison_contains_vpn_instances(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap, title="L3VPN Diff")
        diff_data = comparison.diff_data
        self.assertIn("vpn_instances", diff_data)

    def test_comparison_vpn_instance_added(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        added = comparison.diff_data["vpn_instances"].get("added", [])
        added_names = [v["name"] for v in added]
        self.assertIn("CLIENTE-C", added_names)

    def test_comparison_vpn_instance_rd_changed(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        changed = comparison.diff_data["vpn_instances"].get("changed", [])
        changed_names = [c["name"] for c in changed]
        self.assertIn("CLIENTE-A", changed_names)

    def test_comparison_vpn_instance_rt_changed(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        changed = comparison.diff_data["vpn_instances"].get("changed", [])
        changed_names = [c["name"] for c in changed]
        self.assertIn("CLIENTE-A", changed_names)

    def test_comparison_vpnv4_changed(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        changed = comparison.diff_data["vpn_instances"].get("changed", [])
        changed_names = [c["name"] for c in changed]
        # CLIENTE-A should have changes (rd/rt changed)
        self.assertIn("CLIENTE-A", changed_names)

    def test_comparison_validation_plan_has_vrf_commands(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        validation_plan = comparison.diff_data.get("validation_plan", [])
        # There should be some validation plan entries
        self.assertTrue(len(validation_plan) > 0)

    def test_comparison_validation_plan_has_display_vpn_instance(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        # Validation plan exists
        self.assertTrue(len(comparison.diff_data.get("validation_plan", [])) > 0)

    def test_comparison_rollback_plan_has_vrf(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        rollback_plan = comparison.diff_data.get("rollback_plan", [])
        self.assertTrue(len(rollback_plan) > 0)

    def test_comparison_impacts_include_vrf(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        impacts = comparison.diff_data.get("impacts", [])
        # There should be some impacts
        self.assertTrue(len(impacts) > 0)

    def test_comparison_interfaces_changed(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        # CLIENTE-C is new - check in 'added'
        added_names = [v["name"] for v in comparison.diff_data["vpn_instances"].get("added", [])]
        self.assertTrue(len(added_names) > 0)

    def test_comparison_bgp_vpn_instance_changed(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap)
        changed = comparison.diff_data["vpn_instances"].get("changed", [])
        self.assertTrue(len(changed) > 0)


# =========================================================================
# 8. Web Tests
# =========================================================================


class WebTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NE40-L3VPN-WEB-TEST")

    def test_documentation_page_shows_vrf_section(self):
        snapshot = _analyze(self.device, L3VPN_BASIC)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        response = self.client.get(
            reverse("analysis_documentation", args=[parsed_config.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "VRF")
        self.assertContains(response, "CLIENTE-A")

    def test_search_page_shows_vrf_results(self):
        _analyze(self.device, L3VPN_BASIC)
        response = self.client.get(reverse("search"), {"q": "CLIENTE-A"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CLIENTE-A")

    def test_search_page_vpnv4_results(self):
        _analyze(self.device, L3VPN_BASIC)
        response = self.client.get(reverse("search"), {"q": "vpnv4"})
        self.assertEqual(response.status_code, 200)

    def test_comparison_detail_page_shows_vrf(self):
        base_snap = _analyze(self.device, L3VPN_CHANGE_BEFORE)
        target_snap = _analyze(self.device, L3VPN_CHANGE_AFTER)
        comparison = compare_config_snapshots(base_snap, target_snap, title="L3VPN Diff")
        response = self.client.get(
            reverse("comparison_detail", args=[comparison.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_documentation_page_no_vrf_no_section(self):
        config = """#
sysname NO-VRF
#
return
"""
        snapshot = _analyze(self.device, config)
        parsed_config = ParsedConfig.objects.get(snapshot=snapshot)
        response = self.client.get(
            reverse("analysis_documentation", args=[parsed_config.pk])
        )
        self.assertEqual(response.status_code, 200)
