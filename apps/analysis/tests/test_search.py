"""Testes da busca técnica global (search service + views + CLI)."""

import io
import os

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from apps.analysis.models import (
    AnalysisIssue,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.search import (
    classify_search_query,
    global_network_search,
)
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "tests", "fixtures"
)
SAMPLE_DIR = os.path.join(settings.BASE_DIR, "sample_configs")


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _load_sample(name: str) -> str:
    path = os.path.join(SAMPLE_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── Classification tests ─────────────────────────────────────────────────┼


class ClassifySearchQueryTests(TestCase):
    def test_classify_ip(self):
        result = classify_search_query("10.255.123.2")
        self.assertEqual(result["type"], "ip")
        self.assertEqual(result["value"], "10.255.123.2")

    def test_classify_prefix(self):
        result = classify_search_query("200.200.200.0/30")
        self.assertEqual(result["type"], "prefix")
        self.assertEqual(result["value"], "200.200.200.0/30")

    def test_classify_vlan_numeric(self):
        result = classify_search_query("1234")
        self.assertEqual(result["type"], "vlan")
        self.assertEqual(result["value"], "1234")

    def test_classify_vlan_explicit(self):
        result = classify_search_query("vlan 1234")
        self.assertEqual(result["type"], "vlan")
        self.assertEqual(result["value"], "1234")

    def test_classify_interface(self):
        result = classify_search_query("Eth-Trunk100.1234")
        self.assertEqual(result["type"], "interface")
        self.assertEqual(result["value"], "Eth-Trunk100.1234")

    def test_classify_asn_numeric(self):
        result = classify_search_query("64520")
        self.assertEqual(result["type"], "asn")
        self.assertEqual(result["value"], "64520")

    def test_classify_asn_with_prefix(self):
        result = classify_search_query("AS64520")
        self.assertEqual(result["type"], "asn")
        self.assertEqual(result["value"], "64520")

    def test_classify_text(self):
        result = classify_search_query("RADIUS-ISP")
        self.assertEqual(result["type"], "text")
        self.assertEqual(result["value"], "RADIUS-ISP")

    def test_classify_low_vlan_is_vlan_not_asn(self):
        """Numbers 1-4094 are VLAN, not ASN."""
        result = classify_search_query("100")
        self.assertEqual(result["type"], "vlan")

    def test_classify_text_vsi(self):
        result = classify_search_query("VSI-CLIENTE-Z")
        self.assertEqual(result["type"], "text")

    def test_classify_loopback_interface(self):
        result = classify_search_query("LoopBack0")
        self.assertEqual(result["type"], "interface")


# ── Search service tests ─────────────────────────────────────────────────


class SearchServiceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = Device.objects.create(
            name="SEARCH-DEVICE", vendor="huawei"
        )
        cls.snap = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=_load_sample("huawei_search_demo.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snap)

    def test_search_by_vlan_1234(self):
        result = global_network_search("1234")
        self.assertGreater(result["summary"]["interfaces"], 0)
        self.assertGreater(result["summary"]["circuits"], 0)

    def test_search_by_interface(self):
        result = global_network_search("Eth-Trunk100.1234")
        self.assertGreater(result["summary"]["interfaces"], 0)
        # Should find interface and circuit
        titles = [i["title"] for i in result["interfaces"]]
        self.assertTrue(
            any("Eth-Trunk100.1234" in t for t in titles),
            f"Eth-Trunk100.1234 not found in {titles}",
        )

    def test_search_by_ip_route(self):
        result = global_network_search("10.255.123.2")
        # Should find at least static route (next-hop)
        self.assertGreater(result["summary"]["static_routes"], 0)

    def test_search_by_prefix(self):
        result = global_network_search("200.200.200.0/30")
        self.assertGreater(result["summary"]["static_routes"], 0)

    def test_search_by_prefix_bgp_network(self):
        result = global_network_search("200.200.200.0/30")
        self.assertGreater(result["summary"]["bgp_peers"], 0)

    def test_search_by_asn(self):
        result = global_network_search("64520")
        self.assertGreater(result["summary"]["bgp_peers"], 0)

    def test_search_by_radius(self):
        result = global_network_search("RADIUS-ISP")
        self.assertGreater(result["summary"]["services"], 0)

    def test_search_by_vsi(self):
        result = global_network_search("VSI-CLIENTE-Z")
        self.assertGreater(result["summary"]["circuits"], 0)

    def test_search_nonexistent_returns_zero(self):
        result = global_network_search("ZZNONEXISTENT999")
        self.assertEqual(result["summary"]["total"], 0)

    def test_search_raw_matches_limited(self):
        result = global_network_search("Eth-Trunk")
        # Should find evidence snippets, not full config
        for rm in result.get("raw_matches", []):
            for ev in rm.get("evidence", []):
                self.assertLess(len(ev), 500)  # Not the full config

    def test_search_devices(self):
        result = global_network_search("SEARCH-DEVICE")
        self.assertGreater(result["summary"]["devices"], 0)

    def test_search_filter_vendor(self):
        result = global_network_search("Eth-Trunk100", filters={"vendor": "huawei"})
        self.assertGreater(result["summary"]["interfaces"], 0)

    def test_search_filter_device(self):
        result = global_network_search(
            "Eth-Trunk100", filters={"device": "SEARCH-DEVICE"}
        )
        self.assertGreater(result["summary"]["interfaces"], 0)

    def test_search_filter_last_snapshot_only(self):
        result = global_network_search(
            "Eth-Trunk100", filters={"last_snapshot_only": True}
        )
        self.assertGreater(result["summary"]["interfaces"], 0)

    def test_search_classification_in_result(self):
        result = global_network_search("Eth-Trunk100.1234")
        self.assertEqual(result["classification"]["type"], "interface")

    def test_search_services_find_radius(self):
        result = global_network_search("RADIUS-ISP")
        svc_types = {s["metadata"].get("service_type", "") for s in result["services"]}
        self.assertIn("radius", svc_types)

    def test_search_issues(self):
        # Create an issue for testing
        AnalysisIssue.objects.create(
            snapshot=self.snap,
            severity="warning",
            code="test_search_code",
            title="Test issue for search",
        )
        result = global_network_search("test_search_code")
        self.assertGreater(result["summary"]["issues"], 0)


# ── Web search tests ─────────────────────────────────────────────────────


class SearchWebTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = Device.objects.create(
            name="WEB-SEARCH-DEVICE", vendor="huawei"
        )
        snap = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=_load_sample("huawei_search_demo.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(snap)

    def test_search_page_200(self):
        r = self.client.get(reverse("search"))
        self.assertEqual(r.status_code, 200)

    def test_search_with_query_200(self):
        r = self.client.get(reverse("search"), {"q": "Eth-Trunk100.1234"})
        self.assertEqual(r.status_code, 200)

    def test_search_with_results_shows_count(self):
        r = self.client.get(reverse("search"), {"q": "Eth-Trunk100.1234"})
        self.assertContains(r, "interfaces")

    def test_search_filter_vendor(self):
        r = self.client.get(
            reverse("search"),
            {"q": "Eth-Trunk100", "vendor": "huawei"},
        )
        self.assertEqual(r.status_code, 200)

    def test_search_filter_device(self):
        r = self.client.get(
            reverse("search"),
            {"q": "Eth-Trunk100", "device": "WEB-SEARCH-DEVICE"},
        )
        self.assertEqual(r.status_code, 200)

    def test_search_empty_no_results(self):
        r = self.client.get(reverse("search"), {"q": "ZZZ-NONEXISTENT"})
        self.assertContains(r, "Nenhum resultado")

    def test_search_no_query_shows_empty_state(self):
        r = self.client.get(reverse("search"))
        self.assertContains(r, "Digite um termo")


# ── CLI search tests ─────────────────────────────────────────────────────


class SearchCLITests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = Device.objects.create(
            name="CLI-SEARCH-DEVICE", vendor="huawei"
        )
        snap = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=_load_sample("huawei_search_demo.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(snap)

    def test_cli_search_interface(self):
        out = io.StringIO()
        call_command("network_search", "Eth-Trunk100.1234", stdout=out)
        output = out.getvalue()
        self.assertIn("BUSCA TÉCNICA GLOBAL", output)
        self.assertIn("interfaces", output)

    def test_cli_search_shows_section_counts(self):
        out = io.StringIO()
        call_command("network_search", "1234", stdout=out)
        output = out.getvalue()
        self.assertIn("interfaces", output)
        # Section title is capitalized: "Circuitos" in CLI output
        self.assertIn("circuit", output.lower())

    def test_cli_search_empty(self):
        out = io.StringIO()
        call_command("network_search", "ZZZ-NONEXISTENT-999", stdout=out)
        output = out.getvalue()
        self.assertIn("Total:", output)
        self.assertIn("0", output)

    def test_cli_search_prefix(self):
        out = io.StringIO()
        call_command("network_search", "200.200.200.0/30", stdout=out)
        output = out.getvalue()
        self.assertIn("rotas estáticas", output.lower())
