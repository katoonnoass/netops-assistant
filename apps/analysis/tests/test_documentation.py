"""Testes do serviço de documentação automática.

Testa:
    - generate_analysis_documentation() com fixture L3
    - Detecção de funções (BGP, agregação, trânsito público)
    - Mapa lógico textual
    - Página web /analysis/<id>/documentation/
    - Recomendações quando existem issues
"""

import os

from django.test import TestCase
from django.urls import reverse

from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import DetectedCircuit, ParsedConfig
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class DocumentationServiceL3Tests(TestCase):
    """Testa generate_analysis_documentation com circuito L3."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.doc = generate_analysis_documentation(self.parsed)

    def test_summary_has_basic_fields(self):
        self.assertEqual(self.doc["summary"]["total_interfaces"], 8)
        self.assertEqual(self.doc["summary"]["total_static_routes"], 4)
        self.assertGreaterEqual(self.doc["summary"]["total_circuits"], 1)

    def test_detected_role_roteador_bgp(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        self.assertIn("Roteador com BGP", roles)

    def test_detected_role_agregacao(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        self.assertIn("Agregação de links / uplinks", roles)

    def test_detected_role_public_prefix_transit(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        self.assertIn(
            "Entrega de prefixos públicos por trânsito privado",
            roles,
        )

    def test_logical_map_contains_eth_trunk(self):
        self.assertIn("Eth-Trunk100", self.doc["logical_map"])

    def test_logical_map_contains_subinterface(self):
        self.assertIn("Eth-Trunk100.1234", self.doc["logical_map"])

    def test_logical_map_contains_vlan(self):
        self.assertIn("VLAN 1234", self.doc["logical_map"])

    def test_logical_map_contains_routed_prefix(self):
        self.assertIn("200.200.200.0/30", self.doc["logical_map"])

    def test_logical_map_contains_remote_ip(self):
        self.assertIn("10.255.123.2", self.doc["logical_map"])

    def test_circuits_list_not_empty(self):
        self.assertGreater(len(self.doc["circuits"]), 0)

    def test_circuit_explanation_in_portuguese(self):
        """Explicação do circuito deve estar em português."""
        for c in self.doc["circuits"]:
            self.assertIn("transporte", c["explanation"].lower())
            self.assertIn("vlan", c["explanation"].lower())

    def test_interfaces_documented(self):
        self.assertGreater(len(self.doc["interfaces"]), 0)
        # Check that each interface has an explanation
        for iface in self.doc["interfaces"]:
            self.assertIn("explanation", iface)
            self.assertTrue(len(iface["explanation"]) > 0)

    def test_static_routes_documented(self):
        self.assertGreater(len(self.doc["static_routes"]), 0)
        for route in self.doc["static_routes"]:
            self.assertIn("explanation", route)
            self.assertIn("next_hop_reachable", route)

    def test_recommendations_generated(self):
        self.assertGreater(len(self.doc["recommendations"]), 0)

    def test_bgp_documented(self):
        self.assertGreater(len(self.doc["bgp"]), 0)
        bgp = self.doc["bgp"][0]
        self.assertEqual(bgp["as_number"], "65000")

    def test_issues_not_empty(self):
        """circuit_l3.txt tem interfaces/rotas sem description — lista com issues."""
        self.assertGreater(len(self.doc["issues"]), 0)


class DocumentationServiceWithIssuesTests(TestCase):
    """Testa documentação com issues presentes."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("missing_descriptions.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.doc = generate_analysis_documentation(self.parsed)

    def test_issues_populated(self):
        """missing_descriptions.txt tem issues — lista não deve estar vazia."""
        self.assertGreater(len(self.doc["issues"]), 0)

    def test_recommendations_include_descriptions(self):
        """Deve recomendar adicionar descrições quando há issues de description."""
        texts = [r["recommendation"] for r in self.doc["recommendations"]]
        has_desc_rec = any(
            "descrição" in r.lower() or "description" in r.lower()
            for r in texts
        )
        self.assertTrue(
            has_desc_rec,
            f"Esperava recomendação sobre descrições: {texts}",
        )

    def test_logical_map_contains_sysname(self):
        self.assertIn("SW-MISSING-DESCS", self.doc["logical_map"])


class DocumentationWebTests(TestCase):
    """Testa a página web de documentação."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)

    def test_documentation_page_returns_200(self):
        url = reverse(
            "analysis_documentation", kwargs={"pk": self.parsed.pk}
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_documentation_uses_correct_template(self):
        url = reverse(
            "analysis_documentation", kwargs={"pk": self.parsed.pk}
        )
        response = self.client.get(url)
        self.assertTemplateUsed(response, "analysis/documentation.html")

    def test_documentation_shows_circuit_explanation(self):
        """Página deve exibir explicação do circuito L3."""
        url = reverse(
            "analysis_documentation", kwargs={"pk": self.parsed.pk}
        )
        response = self.client.get(url)
        self.assertContains(response, "entrega L3")
        self.assertContains(response, "Eth-Trunk100.1234")
        self.assertContains(response, "200.200.200.0/30")

    def test_documentation_shows_logical_map(self):
        url = reverse(
            "analysis_documentation", kwargs={"pk": self.parsed.pk}
        )
        response = self.client.get(url)
        self.assertContains(response, "Eth-Trunk100")
        self.assertContains(response, "VLAN 1234")

    def test_documentation_shows_roles(self):
        url = reverse(
            "analysis_documentation", kwargs={"pk": self.parsed.pk}
        )
        response = self.client.get(url)
        self.assertContains(response, "Roteador com BGP")

    def test_documentation_link_on_detail_page(self):
        """Página de detalhe deve ter link para documentação."""
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Ver documentação automática")


class DocumentationUnreachableTests(TestCase):
    """Testa documentação com unreachable next-hop."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("unreachable_next_hop.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.doc = generate_analysis_documentation(self.parsed)

    def test_recommendations_include_unreachable(self):
        """Deve recomendar validar reachability quando há unreachable."""
        texts = [r["recommendation"] for r in self.doc["recommendations"]]
        has_unreachable_rec = any(
            "reachability" in r.lower() or "inalcançável" in r.lower()
            for r in texts
        )
        self.assertTrue(
            has_unreachable_rec,
            f"Esperava recomendação sobre reachability: {texts}",
        )


class DocumentationEdgeCasesTests(TestCase):
    """Testa documentação com configuração mínima."""

    def test_empty_config_returns_basic_doc(self):
        """Configuração vazia não deve quebrar a documentação."""
        snapshot = ConfigSnapshot.objects.create(
            raw_config="#\nsysname TESTE-EMPTY\n#\nreturn\n",
            vendor="huawei",
        )
        parsed = analyze_config_snapshot(snapshot)
        doc = generate_analysis_documentation(parsed)

        self.assertEqual(doc["summary"]["total_interfaces"], 0)
        self.assertEqual(doc["summary"]["total_circuits"], 0)
        self.assertFalse(doc["detected_roles"])  # no roles detected
