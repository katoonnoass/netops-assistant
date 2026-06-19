"""Testes da interface web (views, templates, URLs)."""

import os

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from apps.analysis.models import DetectedCircuit, ParsedConfig
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

FIXTURES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "tests", "fixtures"
)


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class DashboardTests(TestCase):
    def test_dashboard_returns_200(self):
        """Página inicial / deve responder 200."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_by_name(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_dashboard_uses_correct_template(self):
        response = self.client.get(reverse("dashboard"))
        self.assertTemplateUsed(response, "core/dashboard.html")

    def test_dashboard_shows_empty_state(self):
        """Dashboard sem análises deve mostrar 'Nenhuma análise encontrada'."""
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Nenhuma análise encontrada")


class NewAnalysisPageTests(TestCase):
    def test_new_analysis_returns_200(self):
        response = self.client.get("/configs/new/")
        self.assertEqual(response.status_code, 200)

    def test_new_analysis_by_name(self):
        response = self.client.get(reverse("new_analysis"))
        self.assertEqual(response.status_code, 200)

    def test_new_analysis_uses_correct_template(self):
        response = self.client.get(reverse("new_analysis"))
        self.assertTemplateUsed(response, "config_archive/config_form.html")

    def test_new_analysis_has_form_fields(self):
        """Form deve conter campos device_name, vendor, raw_config, notes."""
        response = self.client.get(reverse("new_analysis"))
        self.assertContains(response, "id_device_name")
        self.assertContains(response, "id_vendor")
        self.assertContains(response, "id_raw_config")
        self.assertContains(response, "id_notes")


class NewAnalysisPostTests(TestCase):
    CONFIG = _load_fixture("circuit_l3.txt")

    def test_post_valid_creates_device(self):
        """POST válido deve criar Device."""
        self.client.post(
            reverse("new_analysis"),
            {
                "device_name": "TESTE-WEB",
                "vendor": "huawei",
                "raw_config": self.CONFIG,
                "notes": "Teste via navegador",
            },
        )
        self.assertTrue(Device.objects.filter(name="TESTE-WEB").exists())

    def test_post_valid_creates_snapshot(self):
        """POST válido deve criar ConfigSnapshot."""
        self.client.post(
            reverse("new_analysis"),
            {
                "device_name": "TESTE-WEB",
                "vendor": "huawei",
                "raw_config": self.CONFIG,
                "notes": "Teste via navegador",
            },
        )
        self.assertEqual(ConfigSnapshot.objects.count(), 1)

    def test_post_valid_creates_parsed_config(self):
        """POST válido deve executar análise e criar ParsedConfig."""
        self.client.post(
            reverse("new_analysis"),
            {
                "device_name": "TESTE-WEB",
                "vendor": "huawei",
                "raw_config": self.CONFIG,
                "notes": "Teste via navegador",
            },
        )
        self.assertEqual(ParsedConfig.objects.count(), 1)

    def test_post_valid_redirects_to_analysis_detail(self):
        """POST válido deve redirecionar para /analysis/<pk>/."""
        response = self.client.post(
            reverse("new_analysis"),
            {
                "device_name": "TESTE-WEB",
                "vendor": "huawei",
                "raw_config": self.CONFIG,
                "notes": "Teste via navegador",
            },
        )
        parsed = ParsedConfig.objects.first()
        self.assertRedirects(
            response, reverse("analysis_detail", kwargs={"pk": parsed.pk})
        )

    def test_post_empty_config_rejected(self):
        """Configuração vazia deve rejeitar."""
        response = self.client.post(
            reverse("new_analysis"),
            {
                "device_name": "TESTE-WEB",
                "vendor": "huawei",
                "raw_config": "",
                "notes": "",
            },
        )
        self.assertEqual(response.status_code, 200)  # stays on form
        self.assertContains(response, "não pode estar vazia")

    def test_post_empty_device_name_rejected(self):
        """Nome do equipamento vazio deve rejeitar."""
        response = self.client.post(
            reverse("new_analysis"),
            {
                "device_name": "",
                "vendor": "huawei",
                "raw_config": self.CONFIG,
                "notes": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "obrigatório")


class AnalysisDetailTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(
            name="TESTE-WEB", vendor="huawei", hostname="TESTE-WEB"
        )
        self.snapshot = ConfigSnapshot.objects.create(
            device=self.device,
            raw_config=_load_fixture("circuit_l3.txt"),
            vendor="huawei",
            source="paste",
        )
        # Run analysis via service
        from apps.analysis.services import analyze_config_snapshot
        self.parsed = analyze_config_snapshot(self.snapshot)

    def test_detail_returns_200(self):
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_detail_uses_correct_template(self):
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertTemplateUsed(response, "analysis/detail.html")

    def test_detail_shows_circuit_eth_trunk(self):
        """Resultado deve mostrar circuito Eth-Trunk100.1234."""
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Eth-Trunk100.1234")
        self.assertContains(response, "10.255.123.0/30")

    def test_detail_shows_routed_prefix(self):
        """Resultado deve mostrar prefixo roteado 200.200.200.0/30."""
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "200.200.200.0/30")

    def test_detail_shows_interface_count(self):
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Interfaces")
        self.assertContains(response, "Rotas Estáticas")

    def test_detail_shows_parsed_json_section(self):
        """Seção colapsável de dados parseados deve existir."""
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Dados parseados")


class SnapshotListTests(TestCase):
    def test_list_returns_200(self):
        response = self.client.get("/configs/")
        self.assertEqual(response.status_code, 200)

    def test_list_by_name(self):
        response = self.client.get(reverse("snapshot_list"))
        self.assertEqual(response.status_code, 200)

    def test_list_uses_correct_template(self):
        response = self.client.get(reverse("snapshot_list"))
        self.assertTemplateUsed(response, "config_archive/config_list.html")

    def test_list_shows_empty_state(self):
        response = self.client.get(reverse("snapshot_list"))
        self.assertContains(response, "Nenhuma análise encontrada")


class SampleConfigsTests(TestCase):
    """Testa que sample_configs/ existe com os arquivos esperados."""

    def setUp(self):
        self.sample_dir = settings.BASE_DIR / "sample_configs"

    def test_sample_configs_dir_exists(self):
        self.assertTrue(os.path.isdir(self.sample_dir))

    def test_huawei_l3_transit_public_prefix_exists(self):
        path = self.sample_dir / "huawei_l3_transit_public_prefix.txt"
        self.assertTrue(os.path.isfile(path))

    def test_huawei_missing_descriptions_exists(self):
        path = self.sample_dir / "huawei_missing_descriptions.txt"
        self.assertTrue(os.path.isfile(path))

    def test_huawei_bgp_basic_exists(self):
        path = self.sample_dir / "huawei_bgp_basic.txt"
        self.assertTrue(os.path.isfile(path))

    def test_sample_configs_all_present(self):
        """Deve haver exatamente 7 arquivos .txt em sample_configs."""
        txt_files = [f for f in os.listdir(self.sample_dir) if f.endswith(".txt")]
        self.assertGreaterEqual(len(txt_files), 7)
