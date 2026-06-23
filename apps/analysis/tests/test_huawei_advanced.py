from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import AnalysisIssue, DetectedService
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei.parser import HuaweiVRPParser


SAMPLES = Path(settings.BASE_DIR) / "sample_configs"


def load_sample(name):
    return (SAMPLES / name).read_text(encoding="utf-8")


class HuaweiAdvancedParserTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.parsed = HuaweiVRPParser(load_sample("huawei_advanced_basic.txt")).parse()
        cls.advanced = cls.parsed["huawei_advanced"]

    def test_evpn_vxlan(self):
        data = self.advanced["evpn_vxlan"]
        self.assertTrue(data["enabled"])
        self.assertIn(50100, data["vnis"])
        self.assertIn("Nve1", data["nve_interfaces"])

    def test_segment_routing_and_srv6(self):
        data = self.advanced["segment_routing"]
        self.assertTrue(data["enabled"])
        self.assertTrue(data["srv6_enabled"])
        self.assertEqual(data["locators"][0]["name"], "LOC-CORE")

    def test_mpls_te_and_rsvp(self):
        data = self.advanced["mpls_te"]
        self.assertTrue(data["enabled"])
        self.assertTrue(data["rsvp_te_enabled"])
        self.assertIn("Tunnel0/0/1", data["tunnel_interfaces"])

    def test_cgnat_msdp_and_telemetry(self):
        self.assertIn("CGN-CLIENTES", self.advanced["cgnat"]["instances"])
        self.assertTrue(self.advanced["cgnat"]["logging_enabled"])
        self.assertIn("10.0.0.2", self.advanced["msdp"]["peers"])
        self.assertIn("COLLECTORS", self.advanced["telemetry"]["destination_groups"])

    def test_bgp_advanced(self):
        data = self.advanced["bgp_advanced"]
        self.assertIn("192.0.2.2", data["route_reflector_clients"])
        self.assertTrue(data["add_path_enabled"])
        self.assertTrue(data["dampening_enabled"])


class HuaweiAdvancedIntegrationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = Device.objects.create(name="NE40-ADV", vendor="huawei")
        cls.snapshot = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=load_sample("huawei_advanced_basic.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_services_created(self):
        service_types = set(DetectedService.objects.filter(snapshot=self.snapshot).values_list("service_type", flat=True))
        self.assertTrue({"evpn_vxlan", "segment_routing", "mpls_te", "cgnat", "msdp", "telemetry"}.issubset(service_types))

    def test_search_finds_advanced_features(self):
        for query in ("evpn", "srv6", "rsvp-te", "cgnat", "msdp", "telemetry", "add-path"):
            with self.subTest(query=query):
                results = global_network_search(query)
                self.assertGreater(len(results["huawei_advanced"]), 0)

    def test_search_ignores_inactive_advanced_defaults(self):
        plain_snapshot = ConfigSnapshot.objects.create(
            device=Device.objects.create(name="NE40-PLAIN", vendor="huawei"),
            raw_config="#\nsysname NE40-PLAIN\n#\n",
            vendor="huawei",
        )
        analyze_config_snapshot(plain_snapshot)
        results = global_network_search("evpn", filters={"device": "NE40-PLAIN"})
        self.assertEqual(results["huawei_advanced"], [])

    def test_documentation_contains_advanced_section(self):
        documentation = generate_analysis_documentation(self.parsed)
        self.assertTrue(documentation["summary"]["has_huawei_advanced"])
        self.assertTrue(documentation["huawei_advanced"]["evpn_vxlan"]["enabled"])

    def test_documentation_web_renders(self):
        user = User.objects.create_user(username="advanced-viewer", password="pass123")
        self.client.force_login(user)
        response = self.client.get(reverse("analysis_documentation", args=[self.parsed.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Huawei VRP Avançado")


class HuaweiAdvancedRiskTests(TestCase):
    def test_risky_config_generates_expected_issues(self):
        snapshot = ConfigSnapshot.objects.create(
            raw_config=load_sample("huawei_advanced_risky.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(snapshot)
        codes = set(AnalysisIssue.objects.filter(snapshot=snapshot).values_list("code", flat=True))
        expected = {
            "vxlan_without_nve_interface",
            "srv6_without_locator",
            "mpls_te_without_mpls",
            "cgnat_without_logging",
            "msdp_without_multicast_routing",
            "msdp_without_peer",
            "telemetry_without_destination",
        }
        self.assertTrue(expected.issubset(codes))


class HuaweiAdvancedComparisonTests(TestCase):
    def test_comparison_detects_advanced_changes(self):
        device = Device.objects.create(name="NE40-ADV-DIFF", vendor="huawei")
        before = ConfigSnapshot.objects.create(device=device, raw_config=load_sample("huawei_advanced_change_before.txt"), vendor="huawei")
        after = ConfigSnapshot.objects.create(device=device, raw_config=load_sample("huawei_advanced_change_after.txt"), vendor="huawei")
        analyze_config_snapshot(before)
        analyze_config_snapshot(after)
        comparison = compare_config_snapshots(before, after)
        advanced_diff = comparison.diff_data["huawei_advanced"]
        categories = {item["category"] for item in advanced_diff["added"] + advanced_diff["changed"]}
        self.assertIn("evpn_vxlan", categories)
        self.assertIn("segment_routing", categories)
        self.assertIn("telemetry", categories)
        self.assertTrue(any(item.get("category") == "huawei_advanced" for item in comparison.diff_data["impacts"]))
        self.assertTrue(any(item.get("title") == "Validar recursos Huawei avançados" for item in comparison.diff_data["validation_plan"]))
        self.assertTrue(any(item.get("change_type") == "huawei_advanced" for item in comparison.diff_data["rollback_plan"]))
