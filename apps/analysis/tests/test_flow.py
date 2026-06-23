"""Testes de fluxo completo de análise.

Testa:
    - Registry de parsers
    - analyze_config_snapshot
    - Detecção de circuito L3 (/30 + rota estática)
    - Issues de interface sem descrição
    - Issues de rota estática sem descrição
    - Issues de next-hop inalcançável
    - Idempotência: rodar análise duas vezes não duplica registros
"""

import os

from django.test import TestCase

from apps.analysis.detectors.circuits import detect_l3_transit_circuits
from apps.analysis.detectors.issues import detect_issues
from apps.analysis.models import AnalysisIssue, DetectedCircuit, ParsedConfig
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei import HuaweiVRPParser
from apps.parsers.registry import get_parser_for_vendor, list_supported_vendors
from apps.parsers.zte import ZTEOLTParser

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

class RegistryTests(TestCase):
    def test_get_parser_huawei(self):
        canonical, parser_cls = get_parser_for_vendor("huawei")
        self.assertEqual(canonical, "huawei")
        self.assertIs(parser_cls, HuaweiVRPParser)

    def test_get_parser_huawei_vrp(self):
        canonical, parser_cls = get_parser_for_vendor("huawei_vrp")
        self.assertEqual(canonical, "huawei")
        self.assertIs(parser_cls, HuaweiVRPParser)

    def test_get_parser_vrp(self):
        canonical, parser_cls = get_parser_for_vendor("vrp")
        self.assertEqual(canonical, "huawei")
        self.assertIs(parser_cls, HuaweiVRPParser)

    def test_get_parser_case_insensitive(self):
        canonical, parser_cls = get_parser_for_vendor("HUAWEI")
        self.assertEqual(canonical, "huawei")

    def test_get_parser_zte(self):
        canonical, parser_cls = get_parser_for_vendor("zte")
        self.assertEqual(canonical, "zte")
        self.assertIs(parser_cls, ZTEOLTParser)

    def test_get_parser_unsupported_vendor(self):
        with self.assertRaises(KeyError):
            get_parser_for_vendor("invalid_vendor_name")

    def test_list_supported_vendors(self):
        vendors = list_supported_vendors()
        self.assertIn("huawei", vendors)
        self.assertIn("cisco", vendors)
        self.assertIn("zte", vendors)

    def test_get_parser_unsupported_message(self):
        try:
            get_parser_for_vendor("invalid")
        except KeyError as exc:
            msg = str(exc)
            self.assertIn("invalid", msg)
            self.assertIn("huawei", msg)
            self.assertIn("cisco", msg)
            self.assertIn("zte", msg)


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------

class AnalyzeConfigSnapshotTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
        )

    def test_analyze_creates_parsed_config(self):
        parsed = analyze_config_snapshot(self.snapshot)
        self.assertIsInstance(parsed, ParsedConfig)
        self.assertEqual(parsed.snapshot, self.snapshot)

    def test_analyze_parses_interfaces(self):
        parsed = analyze_config_snapshot(self.snapshot)
        interfaces = parsed.parsed_data.get("interfaces", [])
        self.assertGreater(len(interfaces), 0)

    def test_analyze_parses_static_routes(self):
        parsed = analyze_config_snapshot(self.snapshot)
        routes = parsed.parsed_data.get("static_routes", [])
        self.assertGreater(len(routes), 0)

    def test_analyze_detects_circuits(self):
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        self.assertGreater(len(circuits), 0)

    def test_analyze_detects_issues(self):
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(snapshot=self.snapshot)
        self.assertGreater(len(issues), 0)

    def test_analyze_twice_does_not_duplicate(self):
        """Idempotência: rodar duas vezes não duplica circuitos nem issues."""
        analyze_config_snapshot(self.snapshot)
        c1 = DetectedCircuit.objects.filter(snapshot=self.snapshot).count()
        i1 = AnalysisIssue.objects.filter(snapshot=self.snapshot).count()

        analyze_config_snapshot(self.snapshot)
        c2 = DetectedCircuit.objects.filter(snapshot=self.snapshot).count()
        i2 = AnalysisIssue.objects.filter(snapshot=self.snapshot).count()

        self.assertEqual(c1, c2)
        self.assertEqual(i1, i2)

    def test_analyze_without_vendor_raises(self):
        snap = ConfigSnapshot.objects.create(
            raw_config="#\ninterface LoopBack0\n ip address 1.1.1.1 255.255.255.255\n#\n",
        )
        with self.assertRaises(ValueError):
            analyze_config_snapshot(snap)

    def test_analyze_empty_config_raises(self):
        snap = ConfigSnapshot.objects.create(
            raw_config="",
            vendor="huawei",
        )
        with self.assertRaises(ValueError):
            analyze_config_snapshot(snap)


# ---------------------------------------------------------------------------
# L3 Circuit detection tests
# ---------------------------------------------------------------------------

class L3CircuitDetectionTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)

    def test_l3_transit_circuit_detected(self):
        """Deve detectar Eth-Trunk100.1234 como circuito L3 transit."""
        circuits = self.circuits.filter(circuit_type="l3_transit")
        self.assertGreaterEqual(len(circuits), 1)

        # Find the specific circuit
        circuit = circuits.filter(
            details__interface="Eth-Trunk100.1234"
        ).first()
        self.assertIsNotNone(circuit, "Eth-Trunk100.1234 deve ser detectado")

    def test_circuit_has_correct_fields(self):
        circuit = self.circuits.filter(
            details__interface="Eth-Trunk100.1234"
        ).first()
        self.assertIsNotNone(circuit)
        details = circuit.details

        self.assertEqual(details.get("interface"), "Eth-Trunk100.1234")
        self.assertEqual(details.get("vlan_id"), 1234)
        self.assertEqual(details.get("transit_network"), "10.255.123.0/30")
        self.assertEqual(details.get("local_ip"), "10.255.123.1")
        self.assertEqual(details.get("remote_ip"), "10.255.123.2")
        self.assertEqual(details.get("routed_prefix"), "200.200.200.0/30")
        self.assertAlmostEqual(details.get("confidence", 0), 0.80, places=2)

    def test_circuit_has_l3_transit_type(self):
        circuit = self.circuits.filter(
            details__interface="Eth-Trunk100.1234"
        ).first()
        self.assertEqual(circuit.circuit_type, "l3_transit")

    def test_eth_trunk1_200_not_detected(self):
        """Eth-Trunk1.200 tem /30 mas não tem rota apontando — não deve detectar."""
        circuit = self.circuits.filter(
            details__interface="Eth-Trunk1.200"
        ).first()
        self.assertIsNone(
            circuit,
            "Eth-Trunk1.200 não deve ser detectado (sem rota correspondente)",
        )


# ---------------------------------------------------------------------------
# Issue detection tests
# ---------------------------------------------------------------------------

class IssueDetectionTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("missing_descriptions.txt"),
            vendor="huawei",
        )

    def test_interface_missing_description(self):
        """GigabitEthernet0/0/1 não tem description."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="interface_missing_description",
        )
        self.assertGreaterEqual(len(issues), 1)
        titles = [i.title for i in issues]
        self.assertTrue(
            any("GigabitEthernet0/0/1" in t for t in titles),
            f"Esperava GigabitEthernet0/0/1 nos issues: {titles}",
        )

    def test_interface_with_description_ignored(self):
        """GigabitEthernet0/0/2 tem description — não deve gerar issue."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="interface_missing_description",
        )
        titles = [i.title for i in issues]
        self.assertFalse(
            any("GigabitEthernet0/0/2" in t for t in titles),
            f"Interface com descrição não deve gerar issue: {titles}",
        )

    def test_subinterface_missing_description(self):
        """Eth-Trunk1.100 não tem description."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="subinterface_missing_description",
        )
        self.assertGreaterEqual(len(issues), 1)
        titles = [i.title for i in issues]
        self.assertTrue(
            any("Eth-Trunk1.100" in t for t in titles),
            f"Esperava Eth-Trunk1.100: {titles}",
        )

    def test_subinterface_with_description_ignored(self):
        """Eth-Trunk1.200 tem description — não deve gerar issue."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="subinterface_missing_description",
        )
        titles = [i.title for i in issues]
        self.assertFalse(
            any("Eth-Trunk1.200" in t for t in titles),
        )

    def test_static_route_missing_description(self):
        """Rota 10.200.0.0/24 não tem description."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="static_route_missing_description",
        )
        self.assertGreaterEqual(len(issues), 1)
        descs = [i.description for i in issues]
        self.assertTrue(
            any("10.200.0.0" in d for d in descs),
        )

    def test_static_route_with_description_ignored(self):
        """Rota 10.201.0.0/24 tem description — não deve gerar issue."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="static_route_missing_description",
        )
        descs = [i.description for i in issues]
        self.assertFalse(
            any("10.201.0.0" in d for d in descs),
        )


class UnreachableNextHopTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("unreachable_next_hop.txt"),
            vendor="huawei",
        )

    def test_unreachable_next_hop_detected(self):
        """172.16.0.0/12 via 198.51.100.1 — IP não conectado."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="static_route_unreachable_next_hop",
        )
        self.assertGreaterEqual(len(issues), 1)
        descs = [i.description for i in issues]
        self.assertTrue(
            any("198.51.100.1" in d for d in descs),
        )

    def test_reachable_next_hop_ignored(self):
        """200.200.200.0/30 via 10.0.0.2 — IP conectado, não deve gerar issue."""
        analyze_config_snapshot(self.snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=self.snapshot,
            code="static_route_unreachable_next_hop",
        )
        descs = [i.description for i in issues]
        self.assertFalse(
            any("10.0.0.2" in d for d in descs),
        )

    def test_idempotent_reanalysis(self):
        """Rodar análise duas vezes com unreachable next-hop."""
        analyze_config_snapshot(self.snapshot)
        c1 = AnalysisIssue.objects.filter(snapshot=self.snapshot).count()

        analyze_config_snapshot(self.snapshot)
        c2 = AnalysisIssue.objects.filter(snapshot=self.snapshot).count()

        self.assertEqual(c1, c2)


# ---------------------------------------------------------------------------
# Detector unit tests (without database)
# ---------------------------------------------------------------------------

class DetectorUnitTests(TestCase):
    """Testa detectores diretamente sem passar pelo service."""

    def setUp(self):
        parser = HuaweiVRPParser(_load_fixture("circuit_l3.txt"))
        self.parsed_data = parser.parse()
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
        )

    def test_detect_l3_transit_directly(self):
        circuits = detect_l3_transit_circuits(self.snapshot, self.parsed_data)
        self.assertGreater(len(circuits), 0)

        # Find the circuit for Eth-Trunk100.1234
        circuit = next(
            (c for c in circuits if c.details.get("interface") == "Eth-Trunk100.1234"),
            None,
        )
        self.assertIsNotNone(circuit, "Eth-Trunk100.1234 deve ser detectado")
        details = circuit.details
        self.assertEqual(details.get("transit_network"), "10.255.123.0/30")
        self.assertEqual(details.get("routed_prefix"), "200.200.200.0/30")

    def test_issues_detect_missing_descriptions(self):
        parser = HuaweiVRPParser(_load_fixture("missing_descriptions.txt"))
        parsed = parser.parse()

        issues = detect_issues(self.snapshot, parsed)
        codes = {i.code for i in issues}

        self.assertIn("interface_missing_description", codes)
        self.assertIn("subinterface_missing_description", codes)
        self.assertIn("static_route_missing_description", codes)

    def test_issues_detect_unreachable(self):
        parser = HuaweiVRPParser(_load_fixture("unreachable_next_hop.txt"))
        parsed = parser.parse()

        issues = detect_issues(self.snapshot, parsed)
        codes = {i.code for i in issues}

        self.assertIn("static_route_unreachable_next_hop", codes)


# ---------------------------------------------------------------------------
# Detector improvements: default route + public/private
# ---------------------------------------------------------------------------

class DetectorDefaultRouteTests(TestCase):
    """Testa que rota default 0.0.0.0/0 não vira routed_prefix principal."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("unreachable_next_hop.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(self.snapshot)

    def test_default_route_does_not_become_routed_prefix(self):
        """Default route (0.0.0.0/0) não deve aparecer como routed_prefix."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        for c in circuits:
            routed = c.details.get("routed_prefix")
            self.assertIsNotNone(routed)
            self.assertNotEqual(routed, "0.0.0.0/0")

    def test_default_route_tracked_in_metadata(self):
        """Default route deve aparecer como default_route_via_transit na metadata."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        has_default_flag = any(
            c.details.get("metadata", {}).get("default_route_via_transit")
            for c in circuits
        )
        self.assertTrue(has_default_flag)


class DefaultRouteOnlyCircuitTests(TestCase):
    """Testa circuito onde apenas rota default aponta para o /30."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("default_route_only.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(self.snapshot)

    def test_circuit_still_created_with_default_only(self):
        """Circuito deve ser criado mesmo com apenas rota default."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        self.assertGreaterEqual(len(circuits), 1)

    def test_circuit_has_no_routed_prefix(self):
        """Circuito com apenas rota default deve ter routed_prefix=None."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        for c in circuits:
            self.assertIsNone(c.details.get("routed_prefix"))

    def test_circuit_has_default_route_flag(self):
        """Circuito com apenas rota default deve ter default_route_via_transit."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        has_flag = any(
            c.details.get("metadata", {}).get("default_route_via_transit")
            for c in circuits
        )
        self.assertTrue(has_flag)

    def test_confidence_lower_for_default_only(self):
        """Confiança deve ser 0.60 para circuito apenas com rota default."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        for c in circuits:
            self.assertEqual(c.details.get("confidence"), 0.60)


class PublicPrivatePrefixTests(TestCase):
    """Testa detecção de routed_prefix público vs privado."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(self.snapshot)

    def test_public_prefix_marked_as_public(self):
        """200.200.200.0/30 é público — deve marcar routed_prefix_is_public=true."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        circuit = circuits.filter(
            details__interface="Eth-Trunk100.1234"
        ).first()
        self.assertIsNotNone(circuit)
        self.assertTrue(
            circuit.details.get("routed_prefix_is_public", False)
        )

    def test_metadata_has_routed_prefix_is_public(self):
        """Metadados devem conter routed_prefix_is_public."""
        circuits = DetectedCircuit.objects.filter(snapshot=self.snapshot)
        for c in circuits:
            metadata = c.details.get("metadata", {})
            self.assertIn("routed_prefix_is_public", metadata)
