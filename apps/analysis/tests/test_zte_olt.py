from pathlib import Path

from django.test import TestCase

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import AnalysisIssue, DetectedCircuit, DetectedService, ParsedConfig
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.registry import get_parser_for_vendor, list_supported_vendors
from apps.parsers.zte import ZTEOLTParser


def load_sample() -> str:
    path = Path("apps/parsers/zte/tests/fixtures/zte_olt_basic.txt")
    return path.read_text(encoding="utf-8")


class ZTERegistryTests(TestCase):
    def test_registry_supports_zte_aliases(self):
        canonical, parser_cls = get_parser_for_vendor("zte_olt")
        self.assertEqual(canonical, "zte")
        self.assertIs(parser_cls, ZTEOLTParser)

    def test_supported_vendors_include_zte(self):
        self.assertIn("zte", list_supported_vendors())


class ZTEAnalysisTests(TestCase):
    def test_analyze_zte_olt_snapshot(self):
        device = Device.objects.create(name="ZTE-OLT-C320-01", vendor="zte")
        snapshot = ConfigSnapshot.objects.create(
            device=device,
            vendor="zte",
            raw_config=load_sample(),
        )

        parsed = analyze_config_snapshot(snapshot)
        self.assertIsInstance(parsed, ParsedConfig)
        self.assertEqual(parsed.parsed_data["vendor"], "zte")
        self.assertTrue(parsed.parsed_data["zte_olt"]["enabled"])
        self.assertTrue(
            DetectedService.objects.filter(
                snapshot=snapshot,
                service_type=DetectedService.ServiceType.GPON_OLT,
            ).exists()
        )
        self.assertTrue(
            AnalysisIssue.objects.filter(
                snapshot=snapshot,
                code="zte_onu_without_service_port",
            ).exists()
        )
        self.assertTrue(
            DetectedCircuit.objects.filter(
                snapshot=snapshot,
                circuit_type=DetectedCircuit.CircuitType.OLT,
            ).exists()
        )

    def test_search_zte_onu_by_serial_and_vlan(self):
        device = Device.objects.create(name="ZTE-OLT-C320-01", vendor="zte")
        snapshot = ConfigSnapshot.objects.create(device=device, vendor="zte", raw_config=load_sample())
        analyze_config_snapshot(snapshot)

        by_serial = global_network_search("ZTEG12345678", filters={"vendor": "zte"})
        self.assertGreaterEqual(by_serial["summary"]["zte_olt"], 1)
        self.assertEqual(by_serial["zte_olt"][0]["type"], "zte_onu")

        by_vlan = global_network_search("100", filters={"vendor": "zte"})
        self.assertGreaterEqual(by_vlan["summary"]["zte_olt"], 1)

    def test_documentation_and_comparison_include_zte_olt(self):
        device = Device.objects.create(name="ZTE-OLT-C320-01", vendor="zte")
        base_snapshot = ConfigSnapshot.objects.create(device=device, vendor="zte", raw_config=load_sample())
        target_snapshot = ConfigSnapshot.objects.create(
            device=device,
            vendor="zte",
            raw_config=load_sample().replace("service-port 1 vport 1 user-vlan 100 vlan 100", "service-port 2 vport 1 user-vlan 200 vlan 200"),
        )
        base_parsed = analyze_config_snapshot(base_snapshot)
        target_parsed = analyze_config_snapshot(target_snapshot)

        documentation = generate_analysis_documentation(base_parsed)
        self.assertTrue(documentation["summary"]["has_zte_olt"])
        self.assertTrue(documentation["zte_olt"]["enabled"])

        comparison = compare_config_snapshots(base_snapshot, target_snapshot)
        self.assertIn("zte_olt", comparison.diff_data)
        self.assertTrue(
            comparison.diff_data["zte_olt"]["service_ports"]["changed"]
            or comparison.diff_data["zte_olt"]["onus"]["changed"]
            or comparison.diff_data["zte_olt"]["pon_ports"]["changed"]
        )
