"""Testes de detecção de BNG/AAA/RADIUS/IP Pool.

Testa:
    - Parser detecta blocos AAA, domain, radius-server, ip pool, bas
    - Parser extrai bng_indicators
    - Detector cria serviços BNG, AAA, RADIUS, IP Pool, Subscriber
    - Idempotência: reanálise não duplica serviços
    - Documentação inclui funções BNG/AAA
    - Páginas web continuam funcionando
"""

import os

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import DetectedService
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot

SAMPLE_DIR = str(settings.BASE_DIR / "sample_configs")


def _load_sample(name: str) -> str:
    path = os.path.join(SAMPLE_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── Parser tests ────────────────────────────────────────────────


class ParserBngTests(TestCase):
    """Testa que o parser detecta blocos BNG/AAA corretamente."""

    def setUp(self):
        from apps.parsers.huawei import HuaweiVRPParser
        config = _load_sample("huawei_bng_radius_aaa.txt")
        self.parsed = HuaweiVRPParser(config).parse()

    def test_detects_aaa_block(self):
        self.assertGreater(len(self.parsed.get("aaa", [])), 0)

    def test_detects_radius_servers(self):
        self.assertGreater(len(self.parsed.get("radius_servers", [])), 0)

    def test_detects_aaa_domains(self):
        self.assertGreater(len(self.parsed.get("aaa_domains", [])), 0)

    def test_detects_ip_pools(self):
        self.assertGreater(len(self.parsed.get("ip_pools", [])), 0)

    def test_detects_bas_interfaces(self):
        self.assertGreater(len(self.parsed.get("bas_interfaces", [])), 0)

    def test_detects_auth_schemes(self):
        self.assertGreater(len(self.parsed.get("auth_schemes", [])), 0)

    def test_detects_bng_indicators(self):
        indicators = self.parsed.get("bng_indicators", [])
        self.assertGreater(len(indicators), 0)
        keywords = {i["keyword"] for i in indicators}
        self.assertIn("aaa_block", keywords)
        self.assertIn("radius_server_block", keywords)

    def test_parser_basic_has_aaa(self):
        from apps.parsers.huawei import HuaweiVRPParser
        config = _load_sample("huawei_bng_basic.txt")
        parsed = HuaweiVRPParser(config).parse()
        self.assertGreater(len(parsed.get("aaa", [])), 0)
        self.assertGreater(len(parsed.get("aaa_domains", [])), 0)


# ── Service detector tests ──────────────────────────────────────


class BngServiceDetectionTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_bng_radius_aaa.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(self.snapshot)

    def test_detects_bng_service(self):
        services = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="bng"
        )
        self.assertGreaterEqual(len(services), 1)

    def test_bng_confidence_high(self):
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="bng"
        )
        self.assertGreaterEqual(svc.confidence, 0.80)

    def test_detects_aaa_service(self):
        services = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="aaa"
        )
        self.assertGreaterEqual(len(services), 1)

    def test_detects_radius_services(self):
        services = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="radius"
        )
        self.assertGreaterEqual(len(services), 1)

    def test_detects_ip_pool_services(self):
        services = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="ip_pool"
        )
        self.assertGreaterEqual(len(services), 1)

    def test_detects_subscriber_access(self):
        services = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="subscriber_access"
        )
        self.assertGreaterEqual(len(services), 1)

    def test_idempotent_reanalysis(self):
        """Reanalisar não deve duplicar serviços."""
        c1 = DetectedService.objects.filter(snapshot=self.snapshot).count()
        analyze_config_snapshot(self.snapshot)
        c2 = DetectedService.objects.filter(snapshot=self.snapshot).count()
        self.assertEqual(c1, c2)


class BngBasicServiceTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_bng_basic.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(self.snapshot)

    def test_detects_bng_basic(self):
        services = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="bng"
        )
        self.assertGreaterEqual(len(services), 1)

    def test_bng_basic_confidence(self):
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="bng"
        )
        # Has BAS + AAA + domains but no explicit RADIUS block
        self.assertGreaterEqual(svc.confidence, 0.70)


# ── Documentation tests ─────────────────────────────────────────


class BngDocumentationTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_bng_radius_aaa.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.doc = generate_analysis_documentation(self.parsed)

    def test_doc_has_services(self):
        self.assertGreater(len(self.doc["services"]), 0)

    def test_doc_has_bng_role(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        has_bng = any("BNG" in r or "AAA" in r or "RADIUS" in r for r in roles)
        self.assertTrue(has_bng, f"Esperava função BNG/AAA/RADIUS: {roles}")

    def test_doc_summary_has_service_count(self):
        self.assertGreater(self.doc["summary"]["total_services"], 0)

    def test_doc_bng_service_has_description(self):
        bng_services = [
            s for s in self.doc["services"] if s["service_type"] == "bng"
        ]
        self.assertGreater(len(bng_services), 0)
        self.assertTrue(len(bng_services[0]["description"]) > 0)


# ── Web tests ───────────────────────────────────────────────────


class BngWebTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_bng_radius_aaa.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)

    def test_detail_page_200(self):
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_detail_shows_services(self):
        url = reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Serviços Detectados")

    def test_doc_page_200(self):
        url = reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_doc_shows_services(self):
        url = reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        response = self.client.get(url)
        self.assertContains(response, "Serviços Detectados")
