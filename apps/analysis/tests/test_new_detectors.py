"""Testes dos novos detectores: VLAN transport, QinQ, L2VPN VSI.

Testa:
    - Detector cria vlan_transport
    - Detector cria qinq_transport
    - Detector cria l2vpn_vsi
    - Arquivo misto detecta 4 tipos de circuito
    - Não cria duplicidade indevida
    - Documentação explica os novos tipos
    - Mapa lógico contém VLAN, QinQ e VSI
"""

import os

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from apps.analysis.detectors.circuits import (
    detect_l2vpn_vsi_circuits,
    detect_qinq_transport_circuits,
    detect_vlan_transport_circuits,
)
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import DetectedCircuit
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.parsers.huawei import HuaweiVRPParser

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "tests", "fixtures"
)
SAMPLE_DIR = str(settings.BASE_DIR / "sample_configs")


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _load_sample(name: str) -> str:
    path = os.path.join(SAMPLE_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── Parser tests ────────────────────────────────────────────────


class NewParserFieldsTests(TestCase):
    """Testa que o parser extrai os novos campos corretamente."""

    def test_parser_extracts_second_vlan_id(self):
        config = _load_sample("huawei_qinq_transport.txt")
        parser = HuaweiVRPParser(config)
        parsed = parser.parse()
        ifaces = parsed["interfaces"]
        # Find Eth-Trunk100.3000 with second-dot1q
        iface = next(
            (i for i in ifaces if i.get("second_vlan_id")), None
        )
        self.assertIsNotNone(iface, "Deveria encontrar interface com second_vlan_id")
        self.assertEqual(iface["second_vlan_id"], "100")

    def test_parser_extracts_pe_vid_ce_vid(self):
        config = _load_sample("huawei_qinq_transport.txt")
        parser = HuaweiVRPParser(config)
        parsed = parser.parse()
        ifaces = parsed["interfaces"]
        iface = next(
            (i for i in ifaces if i.get("pe_vid")), None
        )
        self.assertIsNotNone(iface)
        self.assertEqual(iface["pe_vid"], "3002")
        self.assertEqual(iface["ce_vid"], "300")

    def test_parser_extracts_vsi_name(self):
        config = _load_sample("huawei_l2vpn_vsi.txt")
        parser = HuaweiVRPParser(config)
        parsed = parser.parse()
        ifaces = parsed["interfaces"]
        iface = next(
            (i for i in ifaces if i.get("vsi_name")), None
        )
        self.assertIsNotNone(iface)
        self.assertEqual(iface["vsi_name"], "VSI-CLIENTE-X")

    def test_parser_extracts_vsi_blocks(self):
        config = _load_sample("huawei_l2vpn_vsi.txt")
        parser = HuaweiVRPParser(config)
        parsed = parser.parse()
        vsi_blocks = parsed.get("vsi", [])
        self.assertEqual(len(vsi_blocks), 2)

        vsi_x = next(v for v in vsi_blocks if v["name"] == "VSI-CLIENTE-X")
        self.assertEqual(vsi_x["vsi_id"], "5000")
        self.assertEqual(vsi_x["peers"], ["10.10.10.10"])

        vsi_y = next(v for v in vsi_blocks if v["name"] == "VSI-CLIENTE-Y")
        self.assertEqual(vsi_y["vsi_id"], "5001")
        self.assertEqual(len(vsi_y["peers"]), 2)

    def test_vlan_transport_iface_fields(self):
        """Subinterface sem IP deve ter os campos esperados."""
        config = _load_sample("huawei_vlan_transport.txt")
        parser = HuaweiVRPParser(config)
        parsed = parser.parse()
        ifaces = parsed["interfaces"]
        # Eth-Trunk100.2000 should have vlan_type dot1q but no IP
        iface = next(i for i in ifaces if i["name"] == "Eth-Trunk100.2000")
        self.assertEqual(iface["vlan_type"], "dot1q")
        self.assertEqual(iface["vlan_id"], "2000")
        self.assertIsNone(iface["ip_address"])
        self.assertEqual(iface["description"], "TRANSPORTE-OLT-POP02")


# ── Detector tests ─────────────────────────────────────────────────


class VlanTransportDetectorTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_vlan_transport.txt"),
            vendor="huawei",
        )

    def test_detects_vlan_transport(self):
        """Deve detectar subinterfaces dot1q sem IP como vlan_transport."""
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="vlan_transport",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_detects_three_transport_circuits(self):
        """3 subinterfaces sem IP no fixture -> 3 vlan_transport."""
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="vlan_transport",
        )
        self.assertEqual(len(circuits), 3)

    def test_confidence_with_description(self):
        """Interface com description deve ter confidence 0.70."""
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.2000",
        )
        self.assertEqual(circuit.details["confidence"], 0.70)

    def test_confidence_without_description(self):
        """Interface sem description deve ter confidence 0.50."""
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.2002",
        )
        self.assertEqual(circuit.details["confidence"], 0.50)


class QinQDetectorTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_qinq_transport.txt"),
            vendor="huawei",
        )

    def test_detects_qinq(self):
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="qinq_transport",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_detects_three_qinq_circuits(self):
        """3 interfaces QinQ no fixture."""
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="qinq_transport",
        )
        self.assertEqual(len(circuits), 3)

    def test_second_dot1q_has_second_vlan_id(self):
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.3000",
        )
        self.assertEqual(circuit.details["second_vlan_id"], 100)
        self.assertEqual(circuit.details["vlan_id"], 3000)

    def test_qinq_termination_has_pe_ce_vid(self):
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.3002",
        )
        self.assertEqual(circuit.details["pe_vid"], 3002)
        self.assertEqual(circuit.details["ce_vid"], 300)

    def test_confidence_is_85(self):
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.3000",
        )
        self.assertEqual(circuit.details["confidence"], 0.85)


class L2VpnVsiDetectorTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_l2vpn_vsi.txt"),
            vendor="huawei",
        )

    def test_detects_l2vpn_vsi(self):
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="l2vpn_vsi",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_detects_binding_circuits(self):
        """2 subinterfaces com binding + 0 orphan = 2 circuitos."""
        analyze_config_snapshot(self.snapshot)
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="l2vpn_vsi",
        )
        # 2 with binding interfaces, no orphans
        self.assertEqual(len(circuits), 2)

    def test_binding_has_vsi_name(self):
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.4000",
        )
        self.assertEqual(circuit.details["vsi_name"], "VSI-CLIENTE-X")
        self.assertEqual(circuit.details["vsi_id"], "5000")

    def test_binding_confidence_90(self):
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.4000",
        )
        self.assertEqual(circuit.details["confidence"], 0.90)

    def test_binding_has_vsi_peers(self):
        analyze_config_snapshot(self.snapshot)
        circuit = DetectedCircuit.objects.get(
            snapshot=self.snapshot,
            details__interface="Eth-Trunk100.4001",
        )
        self.assertEqual(len(circuit.details.get("vsi_peers", [])), 2)


# ── Mixed config tests ────────────────────────────────────────────


class MixedConfigTests(TestCase):
    """Testa o arquivo misto com 4 tipos de circuito."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_mixed_isp_services.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(self.snapshot)

    def test_detects_l3_transit(self):
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="l3_transit",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_detects_vlan_transport(self):
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="vlan_transport",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_detects_qinq_transport(self):
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="qinq_transport",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_detects_l2vpn_vsi(self):
        circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="l2vpn_vsi",
        )
        self.assertGreaterEqual(len(circuits), 1)

    def test_all_four_types_detected(self):
        """Os 4 tipos devem ser detectados no arquivo misto."""
        types = set(
            DetectedCircuit.objects.filter(
                snapshot=self.snapshot
            ).values_list("circuit_type", flat=True)
        )
        expected = {"l3_transit", "vlan_transport", "qinq_transport", "l2vpn_vsi"}
        for t in expected:
            self.assertIn(t, types, f"Tipo {t} não encontrado em {types}")

    def test_no_duplicate_vlan_transport_for_qinq(self):
        """Subinterface QinQ não deve ter vlan_transport."""
        qinq_circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="qinq_transport",
        )
        qinq_ifaces = {c.details.get("interface") for c in qinq_circuits}
        vlan_circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="vlan_transport",
        )
        vlan_ifaces = {c.details.get("interface") for c in vlan_circuits}
        overlap = qinq_ifaces & vlan_ifaces
        self.assertEqual(
            len(overlap), 0,
            f"QinQ e VLAN transport compartilham interfaces: {overlap}",
        )

    def test_no_duplicate_vlan_transport_for_l2vpn(self):
        """Subinterface L2VPN não deve ter vlan_transport."""
        l2vpn_circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="l2vpn_vsi",
        )
        l2vpn_ifaces = {c.details.get("interface") for c in l2vpn_circuits}
        vlan_circuits = DetectedCircuit.objects.filter(
            snapshot=self.snapshot,
            circuit_type="vlan_transport",
        )
        vlan_ifaces = {c.details.get("interface") for c in vlan_circuits}
        overlap = l2vpn_ifaces & vlan_ifaces
        self.assertEqual(
            len(overlap), 0,
            f"L2VPN e VLAN transport compartilham interfaces: {overlap}",
        )


# ── Documentation tests ───────────────────────────────────────────


class NewCircuitDocumentationTests(TestCase):
    """Testa que a documentação explica os novos tipos de circuito."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_mixed_isp_services.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.doc = generate_analysis_documentation(self.parsed)

    def test_doc_explains_vlan_transport(self):
        texts = [c["explanation"] for c in self.doc["circuits"]]
        has_vlan_transport = any(
            "transporte L2" in t and "VLAN" in t for t in texts
        )
        self.assertTrue(has_vlan_transport, "Deveria explicar VLAN transport")

    def test_doc_explains_qinq(self):
        texts = [c["explanation"] for c in self.doc["circuits"]]
        has_qinq = any("QinQ" in t or "dupla tag" in t for t in texts)
        self.assertTrue(has_qinq, "Deveria explicar QinQ")

    def test_doc_explains_l2vpn(self):
        texts = [c["explanation"] for c in self.doc["circuits"]]
        has_l2vpn = any("L2VPN" in t or "VSI" in t for t in texts)
        self.assertTrue(has_l2vpn, "Deveria explicar L2VPN/VSI")

    def test_logical_map_contains_vlan(self):
        self.assertIn("VLAN 2000", self.doc["logical_map"])

    def test_logical_map_contains_qinq(self):
        self.assertIn("VLAN 3000", self.doc["logical_map"])

    def test_logical_map_contains_vsi(self):
        self.assertIn("VSI-CLIENTE-Z", self.doc["logical_map"])

    def test_logical_map_contains_vsi_id(self):
        self.assertIn("9000", self.doc["logical_map"])


class NewCircuitWebTests(TestCase):
    """Testa que as páginas web funcionam com os novos detectores."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_mixed_isp_services.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)

    def test_detail_page_returns_200(self):
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_doc_page_returns_200(self):
        url = reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_doc_page_shows_circuit_types(self):
        url = reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Trânsito L3")
        self.assertContains(response, "Transporte QinQ")
        self.assertContains(response, "L2VPN com VSI")


# ── Unit-level detector tests (without service) ────────────────────────


class DetectorUnitTests(TestCase):
    """Testa detectores diretamente sem analyze_config_snapshot."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_mixed_isp_services.txt"),
            vendor="huawei",
        )
        parser = HuaweiVRPParser(_load_sample("huawei_mixed_isp_services.txt"))
        self.parsed_data = parser.parse()

    def test_detect_vlan_transport_directly(self):
        circuits = detect_vlan_transport_circuits(self.snapshot, self.parsed_data)
        self.assertGreater(len(circuits), 0)
        types = {c.circuit_type for c in circuits}
        self.assertIn("vlan_transport", types)

    def test_detect_qinq_directly(self):
        circuits = detect_qinq_transport_circuits(self.snapshot, self.parsed_data)
        self.assertGreater(len(circuits), 0)
        types = {c.circuit_type for c in circuits}
        self.assertIn("qinq_transport", types)

    def test_detect_l2vpn_directly(self):
        circuits = detect_l2vpn_vsi_circuits(self.snapshot, self.parsed_data)
        self.assertGreater(len(circuits), 0)
        types = {c.circuit_type for c in circuits}
        self.assertIn("l2vpn_vsi", types)
