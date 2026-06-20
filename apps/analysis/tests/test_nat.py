"""Testes completos para NAT / PAT / Port Forward.

Testa o pipeline completo: parser, utils, serviços, issues,
documentação, busca, comparação e web.
"""

from django.test import TestCase
from django.urls import reverse

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import AnalysisIssue, DetectedService, ParsedConfig
from apps.analysis.nat_utils import build_nat_summary, build_nat_dependency_map
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei import HuaweiVRPParser

NAT_BASIC = """#
sysname NE40-NAT
#
interface GigabitEthernet0/0/0
 description WAN-UPLINK
 ip address 200.200.200.1 255.255.255.252
 nat outbound 3001 address-group 1
 nat server protocol tcp global 200.200.200.200 www inside 10.0.0.200 80
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-L3VPN
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
 nat outbound 3002 address-group 10
#
nat address-group 1 200.200.200.10 200.200.200.20
nat address-group 10 203.0.113.1 203.0.113.10 vpn-instance CLIENTE-A
#
ip vpn-instance CLIENTE-A
 ipv4-family
  route-distinguisher 65000:100
  vpn-target 65000:100 both
#
acl number 3001
 rule 5 permit ip source 10.0.0.0 0.255.255.255
#
acl number 3002
 rule 5 permit ip source 192.168.0.0 0.0.255.255
#
nat static global 200.200.200.100 inside 10.0.0.100
#
return
"""

NAT_RISKY = """#
sysname NE40-NAT-RISK
#
interface GigabitEthernet0/0/0
 nat outbound 9999 address-group 99
 nat server protocol tcp global 200.200.200.100 22 inside 10.0.0.100 22
 nat server protocol tcp global 200.200.200.101 3389 inside 10.0.0.101 3389
 nat server global 200.200.200.200 inside 10.0.0.200
#
nat address-group 1 200.200.200.10 200.200.200.20
#
nat static global 10.0.0.1 inside 192.168.0.1
#
return
"""

NAT_CHANGE_BEFORE = """#
sysname NE40-NAT-DIFF
#
nat address-group 1 200.200.200.10 200.200.200.20
nat outbound 3001 address-group 1
nat static global 200.200.200.100 inside 10.0.0.100
#
return
"""

NAT_CHANGE_AFTER = """#
sysname NE40-NAT-DIFF
#
nat address-group 1 200.200.200.50 200.200.200.60
nat address-group 2 200.200.200.70 200.200.200.80
nat outbound 3001 address-group 2
nat outbound 3002 address-group 1
nat static global 200.200.200.200 inside 10.0.0.200
#
return
"""


def _parse(text):
    return HuaweiVRPParser(text).parse()


def _analyze(device, text):
    snap = ConfigSnapshot.objects.create(device=device, raw_config=text, vendor="huawei")
    analyze_config_snapshot(snap)
    return snap


class ParserTests(TestCase):
    def test_address_group_basic(self):
        parsed = _parse(NAT_BASIC)
        ags = parsed["nat"]["address_groups"]
        self.assertEqual(len(ags), 2)

    def test_address_group_values(self):
        parsed = _parse(NAT_BASIC)
        for ag in parsed["nat"]["address_groups"]:
            if ag["name"] == "1":
                self.assertEqual(ag["start_ip"], "200.200.200.10")
                self.assertEqual(ag["end_ip"], "200.200.200.20")

    def test_address_group_vpn_instance(self):
        parsed = _parse(NAT_BASIC)
        for ag in parsed["nat"]["address_groups"]:
            if ag["name"] == "10":
                self.assertEqual(ag["vpn_instance"], "CLIENTE-A")

    def test_nat_outbound_standalone(self):
        # Test standalone nat outbound (not inside interface)
        parsed = _parse("#\nsysname T\n#\nnat outbound 1001 address-group 5\n#\nreturn\n")
        obs = parsed["nat"]["outbound_rules"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["acl"], "1001")

    def test_nat_outbound_in_interface(self):
        parsed = _parse(NAT_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "GigabitEthernet0/0/0":
                self.assertEqual(len(iface.get("nat_outbound", [])), 1)

    def test_nat_outbound_no_pat(self):
        parsed = _parse("#\nsysname T\n#\nnat outbound 1001 address-group 5 no-pat\n#\nreturn\n")
        for ob in parsed["nat"]["outbound_rules"]:
            self.assertTrue(ob.get("no_pat"))

    def test_nat_static_basic(self):
        parsed = _parse(NAT_BASIC)
        sts = parsed["nat"]["static_rules"]
        self.assertEqual(len(sts), 1)
        self.assertEqual(sts[0]["global_ip"], "200.200.200.100")
        self.assertEqual(sts[0]["inside_ip"], "10.0.0.100")

    def test_nat_in_interface(self):
        parsed = _parse(NAT_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "GigabitEthernet0/0/0":
                self.assertTrue(iface.get("has_nat"))
                self.assertEqual(len(iface.get("nat_outbound", [])), 1)
                self.assertEqual(len(iface.get("nat_server", [])), 1)

    def test_nat_interface_vrf(self):
        parsed = _parse(NAT_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "GigabitEthernet0/0/1.100":
                self.assertTrue(iface.get("has_nat"))
                self.assertEqual(iface.get("vpn_instance"), "CLIENTE-A")


class UtilsTests(TestCase):
    def test_build_nat_summary(self):
        parsed = _parse(NAT_BASIC)
        s = build_nat_summary(parsed)
        self.assertIsNotNone(s)
        self.assertEqual(s["total_address_groups"], 2)
        self.assertEqual(s["total_outbound_rules"], 2)
        self.assertEqual(s["total_static_rules"], 1)

    def test_build_nat_dependency_map(self):
        parsed = _parse(NAT_BASIC)
        deps = build_nat_dependency_map(parsed)
        self.assertEqual(len(deps["outbound"]), 2)

    def test_nat_dependency_acl_found(self):
        parsed = _parse(NAT_BASIC)
        deps = build_nat_dependency_map(parsed)
        for ob in deps["outbound"]:
            if ob["acl"] == "3001":
                self.assertTrue(ob["acl_found"])

    def test_nat_dependency_vpn_instance(self):
        parsed = _parse(NAT_BASIC)
        deps = build_nat_dependency_map(parsed)
        # Check that at least one has a vpn_instance
        has_vpn = any(d.get("vpn_instance") for d in deps["outbound"])
        self.assertTrue(has_vpn)


class ServiceTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NAT-TEST")

    def test_nat_service(self):
        snap = _analyze(self.device, NAT_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="nat").exists())

    def test_nat_outbound_service(self):
        snap = _analyze(self.device, NAT_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="nat_outbound").exists())

    def test_nat_static_service(self):
        snap = _analyze(self.device, NAT_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="nat_static").exists())

    def test_nat_server_service(self):
        snap = _analyze(self.device, NAT_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="nat_server").exists())


class IssueTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NAT-RISK-TEST")

    def test_nat_acl_not_found(self):
        snap = _analyze(self.device, NAT_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="nat_acl_not_found").exists())

    def test_nat_address_group_not_found(self):
        snap = _analyze(self.device, NAT_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="nat_address_group_not_found").exists())

    def test_nat_static_private_global_ip(self):
        snap = _analyze(self.device, NAT_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="nat_static_private_global_ip").exists())

    def test_nat_server_sensitive_ports(self):
        snap = _analyze(self.device, NAT_RISKY)
        issues = AnalysisIssue.objects.filter(snapshot=snap, code="nat_server_sensitive_port")
        self.assertTrue(issues.exists())

    def test_nat_server_without_protocol(self):
        snap = _analyze(self.device, NAT_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="nat_server_without_protocol").exists())

    def test_nat_interface_missing_description(self):
        snap = _analyze(self.device, NAT_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="nat_interface_missing_description").exists())


class DocumentationTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NAT-DOC-TEST")

    def test_nat_section_in_documentation(self):
        snap = _analyze(self.device, NAT_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertIn("nat", doc)
        self.assertIsNotNone(doc["nat"])

    def test_nat_section_address_groups(self):
        snap = _analyze(self.device, NAT_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertEqual(len(doc["nat"]["address_groups"]), 2)

    def test_nat_section_outbound(self):
        snap = _analyze(self.device, NAT_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertEqual(len(doc["nat"]["outbound_rules"]), 2)

    def test_nat_section_static(self):
        snap = _analyze(self.device, NAT_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertEqual(len(doc["nat"]["static_rules"]), 1)


class SearchTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NAT-SEARCH-TEST")

    def test_search_nat_keyword(self):
        _analyze(self.device, NAT_BASIC)
        results = global_network_search("nat")
        self.assertGreater(results["summary"].get("nat", 0), 0)

    def test_search_address_group(self):
        _analyze(self.device, NAT_BASIC)
        results = global_network_search("address-group 1")
        self.assertGreater(results["summary"].get("nat", 0), 0)

    def test_search_global_ip(self):
        _analyze(self.device, NAT_BASIC)
        results = global_network_search("200.200.200.100")
        self.assertGreater(results["summary"].get("nat", 0), 0)

    def test_search_inside_ip(self):
        _analyze(self.device, NAT_BASIC)
        results = global_network_search("10.0.0.100")
        self.assertGreater(results["summary"].get("nat", 0), 0)


class ComparisonTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NAT-DIFF-TEST")

    def test_comparison_contains_nat_impacts(self):
        base = _analyze(self.device, NAT_CHANGE_BEFORE)
        target = _analyze(self.device, NAT_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        impacts = comp.diff_data.get("impacts", [])
        has_nat = any("NAT" in i.get("impact", "") for i in impacts)
        self.assertTrue(has_nat)

    def test_comparison_address_group_changed(self):
        base = _analyze(self.device, NAT_CHANGE_BEFORE)
        target = _analyze(self.device, NAT_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        impacts = comp.diff_data.get("impacts", [])
        has_ag = any("Address-group" in i.get("impact", "") for i in impacts)
        self.assertTrue(has_ag)

    def test_comparison_outbound_added(self):
        base = _analyze(self.device, NAT_CHANGE_BEFORE)
        target = _analyze(self.device, NAT_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        impacts = comp.diff_data.get("impacts", [])
        has_ob = any("NAT outbound" in i.get("impact", "") for i in impacts)
        self.assertTrue(has_ob)

    def test_comparison_static_changed(self):
        base = _analyze(self.device, NAT_CHANGE_BEFORE)
        target = _analyze(self.device, NAT_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        impacts = comp.diff_data.get("impacts", [])
        has_st = any("NAT static" in i.get("impact", "") for i in impacts)
        self.assertTrue(has_st)


class WebTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="NAT-WEB-TEST")

    def test_documentation_page_shows_nat(self):
        snap = _analyze(self.device, NAT_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        r = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "NAT")
        self.assertContains(r, "address-group")

    def test_search_page_shows_nat(self):
        _analyze(self.device, NAT_BASIC)
        r = self.client.get(reverse("search"), {"q": "nat"})
        self.assertEqual(r.status_code, 200)
