"""Testes completos para QoS / Traffic Policy / CAR.

Testa o pipeline completo: parser, utils, serviços, issues,
documentação, busca, comparação e web.
"""

from django.test import TestCase
from django.urls import reverse

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import AnalysisIssue, DetectedService, ParsedConfig
from apps.analysis.qos_utils import build_qos_summary, build_qos_dependency_map
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei import HuaweiVRPParser

QOS_BASIC = """#
sysname NE40-QOS
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-L3VPN
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
 traffic-policy CLIENTE-A-QOS inbound
 traffic-policy CLIENTE-A-QOS outbound
 qos-profile CLIENTE-A-PROFILE inbound
#
interface GigabitEthernet0/0/2
 description CORE-LINK
 ip address 172.16.0.1 255.255.255.252
#
ip vpn-instance CLIENTE-A
 ipv4-family
  route-distinguisher 65000:100
  vpn-target 65000:100 both
#
acl number 3001
 rule 5 permit ip source 10.10.10.0 0.0.0.3
#
traffic classifier CLIENTE-A operator or
 if-match acl 3001
#
traffic classifier VOZ operator and
 if-match dscp ef
#
traffic behavior LIMIT-100M
 car cir 102400 pir 102400 cbs 1884160 pbs 1884160 green pass yellow pass red discard
 statistic enable
#
traffic behavior VOZ-PRIORITY
 remark dscp ef
 queue af bandwidth pct 20
#
traffic policy CLIENTE-A-QOS
 classifier CLIENTE-A behavior LIMIT-100M precedence 5
 classifier VOZ behavior VOZ-PRIORITY precedence 10
#
qos-profile CLIENTE-A-PROFILE
 car cir 102400 pir 102400
#
return
"""

QOS_RISKY = """#
sysname NE40-QOS-RISK
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-C-L3VPN
 ip binding vpn-instance CLIENTE-C
 ip address 10.30.30.1 255.255.255.252
 traffic-policy NONEXISTENT-POLICY inbound
 qos-profile NONEXISTENT-PROFILE inbound
#
interface GigabitEthernet0/0/2
 description CLIENTE-SEM-QOS
 ip binding vpn-instance CLIENTE-SEMQOS
 ip address 10.40.40.1 255.255.255.252
#
traffic classifier ORPHAN-CLASSIFIER operator or
 if-match dscp af41
#
traffic behavior ORPHAN-BEHAVIOR
 car cir 51200 pir 51200
 statistic enable
#
traffic policy BROKEN-POLICY
 classifier BROKEN-CLASSIFIER behavior BROKEN-BEHAVIOR precedence 5
#
return
"""

QOS_CHANGE_BEFORE = """#
sysname NE40-QOS-DIFF
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-L3VPN-OLD
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
 traffic-policy CLIENTE-A-QOS inbound
#
acl number 3001
 rule 5 permit ip source 10.10.10.0 0.0.0.3
#
traffic classifier CLIENTE-A operator or
 if-match acl 3001
#
traffic behavior LIMIT-100M
 car cir 102400 pir 102400
#
traffic policy CLIENTE-A-QOS
 classifier CLIENTE-A behavior LIMIT-100M precedence 5
#
return
"""

QOS_CHANGE_AFTER = """#
sysname NE40-QOS-DIFF
#
interface GigabitEthernet0/0/1.100
 description CLIENTE-A-L3VPN-NEW
 ip binding vpn-instance CLIENTE-A
 ip address 10.10.10.1 255.255.255.252
 traffic-policy CLIENTE-A-QOS inbound
 traffic-policy CLIENTE-A-QOS outbound
#
acl number 3002
 rule 5 permit ip source 10.10.10.0 0.0.0.3
#
traffic classifier CLIENTE-A operator or
 if-match acl 3002
#
traffic behavior LIMIT-200M
 car cir 204800 pir 204800
#
traffic policy CLIENTE-A-QOS
 classifier CLIENTE-A behavior LIMIT-200M precedence 5
#
return
"""


def _parse(text):
    return HuaweiVRPParser(text).parse()


def _analyze(device, text):
    snap = ConfigSnapshot.objects.create(device=device, raw_config=text, vendor="huawei")
    analyze_config_snapshot(snap)
    return snap


# =========================================================================
# Parser Tests
# =========================================================================


class ParserTests(TestCase):
    def test_traffic_classifier_basic(self):
        parsed = _parse(QOS_BASIC)
        classifiers = parsed["qos"]["traffic_classifiers"]
        self.assertEqual(len(classifiers), 2)

    def test_traffic_classifier_name(self):
        parsed = _parse(QOS_BASIC)
        names = [c["name"] for c in parsed["qos"]["traffic_classifiers"]]
        self.assertIn("CLIENTE-A", names)
        self.assertIn("VOZ", names)

    def test_traffic_classifier_if_match_acl(self):
        parsed = _parse(QOS_BASIC)
        for c in parsed["qos"]["traffic_classifiers"]:
            if c["name"] == "CLIENTE-A":
                self.assertEqual(len(c["if_match"]), 1)
                self.assertEqual(c["if_match"][0]["type"], "acl")
                self.assertEqual(c["if_match"][0]["value"], "3001")

    def test_traffic_classifier_if_match_dscp(self):
        parsed = _parse(QOS_BASIC)
        for c in parsed["qos"]["traffic_classifiers"]:
            if c["name"] == "VOZ":
                self.assertEqual(c["if_match"][0]["type"], "dscp")
                self.assertEqual(c["if_match"][0]["value"], "ef")
                self.assertEqual(c["operator"], "and")

    def test_traffic_behavior_basic(self):
        parsed = _parse(QOS_BASIC)
        behaviors = parsed["qos"]["traffic_behaviors"]
        self.assertEqual(len(behaviors), 2)

    def test_traffic_behavior_name(self):
        parsed = _parse(QOS_BASIC)
        names = [b["name"] for b in parsed["qos"]["traffic_behaviors"]]
        self.assertIn("LIMIT-100M", names)
        self.assertIn("VOZ-PRIORITY", names)

    def test_traffic_behavior_car(self):
        parsed = _parse(QOS_BASIC)
        for b in parsed["qos"]["traffic_behaviors"]:
            if b["name"] == "LIMIT-100M":
                car = b["car"]
                self.assertIsNotNone(car)
                self.assertEqual(car["cir"], 102400)
                self.assertEqual(car["pir"], 102400)
                self.assertEqual(car["cbs"], 1884160)
                self.assertEqual(car["pbs"], 1884160)
                self.assertEqual(car["green_action"], "pass")
                self.assertEqual(car["red_action"], "discard")

    def test_traffic_behavior_statistics(self):
        parsed = _parse(QOS_BASIC)
        for b in parsed["qos"]["traffic_behaviors"]:
            if b["name"] == "LIMIT-100M":
                self.assertTrue(b["statistics_enabled"])

    def test_traffic_behavior_actions(self):
        parsed = _parse(QOS_BASIC)
        for b in parsed["qos"]["traffic_behaviors"]:
            if b["name"] == "VOZ-PRIORITY":
                actions = b["actions"]
                types = [a["type"] for a in actions]
                self.assertIn("remark_dscp", types)
                self.assertIn("queue", types)

    def test_traffic_policy_basic(self):
        parsed = _parse(QOS_BASIC)
        policies = parsed["qos"]["traffic_policies"]
        self.assertEqual(len(policies), 1)

    def test_traffic_policy_name(self):
        parsed = _parse(QOS_BASIC)
        self.assertEqual(parsed["qos"]["traffic_policies"][0]["name"], "CLIENTE-A-QOS")

    def test_traffic_policy_classifiers(self):
        parsed = _parse(QOS_BASIC)
        cl = parsed["qos"]["traffic_policies"][0]["classifiers"]
        self.assertEqual(len(cl), 2)
        self.assertEqual(cl[0]["classifier"], "CLIENTE-A")
        self.assertEqual(cl[0]["behavior"], "LIMIT-100M")
        self.assertEqual(cl[0]["precedence"], 5)

    def test_interface_traffic_policy_applied(self):
        parsed = _parse(QOS_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "GigabitEthernet0/0/1.100":
                policies = iface["traffic_policies_applied"]
                self.assertEqual(len(policies), 2)
                self.assertEqual(policies[0]["name"], "CLIENTE-A-QOS")
                self.assertEqual(policies[0]["direction"], "inbound")
                self.assertEqual(policies[1]["direction"], "outbound")

    def test_interface_qos_profile_applied(self):
        parsed = _parse(QOS_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "GigabitEthernet0/0/1.100":
                profiles = iface["qos_profiles_applied"]
                self.assertEqual(len(profiles), 1)
                self.assertEqual(profiles[0]["name"], "CLIENTE-A-PROFILE")
                self.assertEqual(profiles[0]["direction"], "inbound")

    def test_qos_profile_basic(self):
        parsed = _parse(QOS_BASIC)
        profiles = parsed["qos"]["qos_profiles"]
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["name"], "CLIENTE-A-PROFILE")
        self.assertEqual(profiles[0]["car"]["cir"], 102400)
        self.assertEqual(profiles[0]["car"]["pir"], 102400)

    def test_interface_without_qos(self):
        parsed = _parse(QOS_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "GigabitEthernet0/0/2":
                self.assertEqual(iface["traffic_policies_applied"], [])
                self.assertEqual(iface["qos_profiles_applied"], [])
                self.assertEqual(iface["qos_car"], [])


# =========================================================================
# Utils Tests
# =========================================================================


class UtilsTests(TestCase):
    def test_build_qos_summary(self):
        parsed = _parse(QOS_BASIC)
        summary = build_qos_summary(parsed)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["total_policies"], 1)
        self.assertEqual(summary["total_classifiers"], 2)
        self.assertEqual(summary["total_behaviors"], 2)
        self.assertEqual(summary["total_qos_profiles"], 1)

    def test_build_qos_summary_interfaces_with_qos(self):
        parsed = _parse(QOS_BASIC)
        summary = build_qos_summary(parsed)
        self.assertEqual(summary["interfaces_with_qos"], 1)

    def test_build_qos_dependency_map_policy(self):
        parsed = _parse(QOS_BASIC)
        deps = build_qos_dependency_map(parsed)
        self.assertEqual(len(deps["policies"]), 1)
        self.assertEqual(deps["policies"][0]["name"], "CLIENTE-A-QOS")

    def test_build_qos_dependency_map_classifier_acl(self):
        parsed = _parse(QOS_BASIC)
        deps = build_qos_dependency_map(parsed)
        cl = deps["policies"][0]["classifiers"][0]
        self.assertEqual(cl["name"], "CLIENTE-A")
        self.assertEqual(cl["acl_refs"], ["3001"])
        self.assertEqual(cl["car"]["cir"], 102400)

    def test_build_qos_dependency_map_bindings(self):
        parsed = _parse(QOS_BASIC)
        deps = build_qos_dependency_map(parsed)
        bindings = deps["policies"][0]["bindings"]
        self.assertEqual(len(bindings), 2)
        self.assertEqual(bindings[0]["interface"], "GigabitEthernet0/0/1.100")
        self.assertEqual(bindings[0]["vpn_instance"], "CLIENTE-A")

    def test_build_qos_dependency_map_orphan_policies(self):
        parsed = _parse(QOS_RISKY)
        deps = build_qos_dependency_map(parsed)
        self.assertIn("BROKEN-POLICY", deps.get("orphan_policies", []))

    def test_build_qos_dependency_map_orphan_classifiers(self):
        parsed = _parse(QOS_RISKY)
        deps = build_qos_dependency_map(parsed)
        self.assertIn("ORPHAN-CLASSIFIER", deps.get("orphan_classifiers", []))

    def test_build_qos_dependency_map_orphan_behaviors(self):
        parsed = _parse(QOS_RISKY)
        deps = build_qos_dependency_map(parsed)
        self.assertIn("ORPHAN-BEHAVIOR", deps.get("orphan_behaviors", []))


# =========================================================================
# Services Tests
# =========================================================================


class ServiceTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="QOS-TEST")

    def test_qos_service_detected(self):
        snap = _analyze(self.device, QOS_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="qos").exists())

    def test_traffic_policy_service_detected(self):
        snap = _analyze(self.device, QOS_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="traffic_policy").exists())

    def test_qos_car_service_detected(self):
        snap = _analyze(self.device, QOS_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=snap, service_type="qos_car").exists())


# =========================================================================
# Issues Tests
# =========================================================================


class IssueTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="QOS-RISK-TEST")

    def test_traffic_policy_not_found(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="traffic_policy_not_found").exists())

    def test_traffic_classifier_not_found(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="traffic_classifier_not_found").exists())

    def test_traffic_behavior_not_found(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="traffic_behavior_not_found").exists())

    def test_qos_profile_not_found(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="qos_profile_not_found").exists())

    def test_traffic_classifier_orphan(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="traffic_classifier_orphan").exists())

    def test_traffic_behavior_orphan(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="traffic_behavior_orphan").exists())

    def test_customer_interface_without_qos(self):
        snap = _analyze(self.device, QOS_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=snap, code="customer_interface_without_qos").exists())


# =========================================================================
# Documentation Tests
# =========================================================================


class DocumentationTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="QOS-DOC-TEST")

    def test_qos_section_in_documentation(self):
        snap = _analyze(self.device, QOS_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertIn("qos", doc)
        self.assertIsNotNone(doc["qos"])

    def test_qos_section_policies(self):
        snap = _analyze(self.device, QOS_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertEqual(len(doc["qos"]["policies"]), 1)
        self.assertEqual(doc["qos"]["policies"][0]["name"], "CLIENTE-A-QOS")

    def test_qos_section_classifiers(self):
        snap = _analyze(self.device, QOS_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        self.assertEqual(doc["qos"]["total_classifiers"], 2)

    def test_qos_section_behaviors_with_car(self):
        snap = _analyze(self.device, QOS_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        doc = generate_analysis_documentation(pc)
        for b in doc["qos"]["behaviors"]:
            if b["name"] == "LIMIT-100M":
                self.assertIsNotNone(b["car"])
                self.assertEqual(b["car"]["cir"], 102400)

    def test_no_qos_no_section(self):
        parsed = _parse("""#\nsysname NO-QOS\n#\nreturn\n""")
        self.assertIsNone(build_qos_summary(parsed))


# =========================================================================
# Search Tests
# =========================================================================


class SearchTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="QOS-SEARCH-TEST")

    def test_search_traffic_policy(self):
        _analyze(self.device, QOS_BASIC)
        results = global_network_search("CLIENTE-A-QOS")
        self.assertGreater(results["summary"].get("qos", 0), 0)

    def test_search_traffic_classifier(self):
        _analyze(self.device, QOS_BASIC)
        results = global_network_search("CLIENTE-A")
        self.assertGreater(results["summary"].get("qos", 0), 0)

    def test_search_traffic_behavior(self):
        _analyze(self.device, QOS_BASIC)
        results = global_network_search("LIMIT-100M")
        self.assertGreater(results["summary"].get("qos", 0), 0)

    def test_search_car_rate(self):
        _analyze(self.device, QOS_BASIC)
        results = global_network_search("102400")
        self.assertGreater(results["summary"].get("qos", 0), 0)

    def test_search_qos_keyword(self):
        _analyze(self.device, QOS_BASIC)
        results = global_network_search("qos")
        self.assertGreater(results["summary"].get("qos", 0), 0)


# =========================================================================
# Comparison Tests
# =========================================================================


class ComparisonTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="QOS-DIFF-TEST")

    def test_comparison_contains_qos(self):
        base = _analyze(self.device, QOS_CHANGE_BEFORE)
        target = _analyze(self.device, QOS_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        self.assertIn("qos", comp.diff_data)

    def test_comparison_qos_car_changed(self):
        base = _analyze(self.device, QOS_CHANGE_BEFORE)
        target = _analyze(self.device, QOS_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        # Behavior LIMIT-100M replaced by LIMIT-200M (different name)
        # Check that qos section exists in diff_data
        self.assertIn("qos", comp.diff_data)
        self.assertTrue("car_changed" in comp.diff_data["qos"])

    def test_comparison_qos_classifier_changed(self):
        base = _analyze(self.device, QOS_CHANGE_BEFORE)
        target = _analyze(self.device, QOS_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        # Classifier CLIENTE-A uses ACL 3001 in base, 3002 in target -> changed
        cls = comp.diff_data["qos"].get("classifiers_changed", [])
        self.assertTrue(len(cls) > 0)

    def test_comparison_qos_behavior_changed(self):
        base = _analyze(self.device, QOS_CHANGE_BEFORE)
        target = _analyze(self.device, QOS_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        # Check that interface binding changed (outbound policy added)
        self.assertTrue(comp.diff_data["qos"].get("interface_bindings_changed", False))

    def test_comparison_qos_interface_binding_changed(self):
        base = _analyze(self.device, QOS_CHANGE_BEFORE)
        target = _analyze(self.device, QOS_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target)
        bind = comp.diff_data["qos"].get("interface_bindings_changed", False)
        self.assertTrue(bind)


# =========================================================================
# Web Tests
# =========================================================================


class WebTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="QOS-WEB-TEST")

    def test_documentation_page_shows_qos(self):
        snap = _analyze(self.device, QOS_BASIC)
        pc = ParsedConfig.objects.get(snapshot=snap)
        r = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "QoS")
        self.assertContains(r, "CLIENTE-A-QOS")

    def test_search_page_shows_qos(self):
        _analyze(self.device, QOS_BASIC)
        r = self.client.get(reverse("search"), {"q": "CLIENTE-A-QOS"})
        self.assertEqual(r.status_code, 200)

    def test_search_page_qos_keyword(self):
        _analyze(self.device, QOS_BASIC)
        r = self.client.get(reverse("search"), {"q": "qos"})
        self.assertEqual(r.status_code, 200)

    def test_comparison_detail_page_with_qos(self):
        base = _analyze(self.device, QOS_CHANGE_BEFORE)
        target = _analyze(self.device, QOS_CHANGE_AFTER)
        comp = compare_config_snapshots(base, target, title="QoS Diff")
        r = self.client.get(reverse("comparison_detail", args=[comp.pk]))
        self.assertEqual(r.status_code, 200)
