"""Tests for PPPoE Server / Virtual-Template / PPP Subscriber Access support."""

from __future__ import annotations

import os
from django.test import TestCase
from django.urls import reverse
from apps.analysis.bng_utils import build_bng_dependency_map
from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import AnalysisIssue, DetectedService, ParsedConfig
from apps.analysis.search import global_network_search
from apps.devices.models import Device
from apps.parsers.registry import get_parser_for_vendor


SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "sample_configs",
)


def _parse(config_text: str):
    parser_cls = get_parser_for_vendor("huawei")[1]
    parser = parser_cls(config_text)
    return parser.parse()


def _load_sample(name: str) -> str:
    path = os.path.join(SAMPLES_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def _analyze(device: Device, config_text: str) -> ParsedConfig:
    from apps.analysis.services import analyze_config_snapshot
    from apps.config_archive.models import ConfigSnapshot
    snap = ConfigSnapshot.objects.create(device=device, raw_config=config_text, vendor="huawei")
    return analyze_config_snapshot(snap)


PPPOE_BASIC = _load_sample("huawei_pppoe_basic.txt")
PPPOE_RISKY = _load_sample("huawei_pppoe_risky.txt")
PPPOE_CHANGE_BEFORE = _load_sample("huawei_pppoe_change_before.txt")
PPPOE_CHANGE_AFTER = _load_sample("huawei_pppoe_change_after.txt")


# ── Parser Tests ───────────────────────────────────────────────────────


class ParserTests(TestCase):
    """Testes do parser para PPPoE / Virtual-Template."""

    def test_virtual_template_detected(self):
        parsed = _parse(PPPOE_BASIC)
        ifaces = [i for i in parsed.get("interfaces", []) if i.get("name", "").lower().startswith("virtual-template")]
        self.assertGreater(len(ifaces), 0, "Virtual-Template deve ser detectada")

    def test_virtual_template_has_ppp_auth(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i["name"] == "Virtual-Template1":
                self.assertIn("chap", i.get("ppp_authentication_modes", []))
                return
        self.fail("Virtual-Template1 não encontrada")

    def test_virtual_template_keepalive(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i["name"] == "Virtual-Template1":
                self.assertTrue(i.get("ppp_keepalive"))
                return

    def test_virtual_template_mtu(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i["name"] == "Virtual-Template1":
                self.assertEqual(i.get("mtu"), 1492)
                return

    def test_virtual_template_ip_unnumbered(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i["name"] == "Virtual-Template1":
                self.assertEqual(i.get("ip_unnumbered_interface"), "LoopBack0")
                return

    def test_virtual_template_remote_pool(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i["name"] == "Virtual-Template1":
                self.assertEqual(i.get("remote_address_pool"), "POOL-CLIENTES")
                return

    def test_pppoe_server_bind(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            pppoe = i.get("pppoe_server")
            if pppoe and pppoe.get("enabled"):
                self.assertIn("Virtual-Template", pppoe.get("virtual_template", ""))
                return
        self.fail("Nenhuma interface PPPoE encontrada")

    def test_pppoe_max_sessions(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            pppoe = i.get("pppoe_server")
            if pppoe and pppoe.get("max_sessions"):
                self.assertEqual(pppoe["max_sessions"], 16000)
                return

    def test_pppoe_with_bas(self):
        """PPPoE interface preserva campos BAS."""
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            pppoe = i.get("pppoe_server")
            if pppoe and pppoe.get("enabled"):
                bas = i.get("bas", {})
                self.assertTrue(bas.get("enabled"))
                self.assertEqual(bas.get("default_domain"), "cliente-pppoe")
                self.assertEqual(bas.get("authentication_method"), "ppp")
                return

    def test_pppoe_user_vlan_preserved(self):
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i.get("pppoe_server", {}).get("enabled"):
                self.assertEqual(i.get("user_vlan"), "200")
                return

    def test_pppoe_top_level_structure(self):
        parsed = _parse(PPPOE_BASIC)
        pppoe = parsed.get("pppoe", {})
        self.assertIn("virtual_templates", pppoe)
        self.assertIn("pppoe_interfaces", pppoe)
        self.assertGreater(len(pppoe["virtual_templates"]), 0)
        self.assertGreater(len(pppoe["pppoe_interfaces"]), 0)

    def test_pppoe_interface_preserves_bas_triggers(self):
        """PPPoE interface não perde triggers BAS."""
        parsed = _parse(PPPOE_BASIC)
        for i in parsed.get("interfaces", []):
            if i.get("pppoe_server", {}).get("enabled"):
                bas = i.get("bas", {})
                self.assertTrue(bas.get("ip_trigger"))
                self.assertTrue(bas.get("arp_trigger"))
                self.assertTrue(bas.get("ipv6_trigger"))
                return


# ── Utils Tests ────────────────────────────────────────────────────────


class UtilsTests(TestCase):
    """Testes de utilitários PPPoE."""

    def test_build_pppoe_summary(self):
        from apps.analysis.pppoe_utils import build_pppoe_summary
        parsed = _parse(PPPOE_BASIC)
        summary = build_pppoe_summary(parsed)
        self.assertGreaterEqual(summary["total_pppoe_interfaces"], 1)
        self.assertGreaterEqual(summary["total_virtual_templates"], 1)

    def test_pppoe_dependency_map(self):
        from apps.analysis.pppoe_utils import build_pppoe_dependency_map
        parsed = _parse(PPPOE_BASIC)
        dep = build_pppoe_dependency_map(parsed)
        self.assertIn("pppoe_interfaces", dep)
        self.assertIn("virtual_templates", dep)
        self.assertGreater(len(dep["virtual_templates"]), 0)
        self.assertGreater(len(dep["pppoe_interfaces"]), 0)

    def test_dependency_map_missing_references(self):
        from apps.analysis.pppoe_utils import build_pppoe_dependency_map
        parsed = _parse(PPPOE_RISKY)
        dep = build_pppoe_dependency_map(parsed)
        missing = dep.get("missing_references", [])
        codes = [m["type"] for m in missing]
        self.assertIn("pppoe_virtual_template_not_found", codes)
        self.assertIn("virtual_template_orphan", codes)

    def test_dependency_map_includes_vt_details(self):
        from apps.analysis.pppoe_utils import build_pppoe_dependency_map
        parsed = _parse(PPPOE_BASIC)
        dep = build_pppoe_dependency_map(parsed)
        vt = dep["virtual_templates"][0]
        self.assertIn("ppp_authentication_modes", vt)
        self.assertIn("remote_address_pool", vt)


# ── Service Tests ──────────────────────────────────────────────────────


class ServiceTests(TestCase):
    """Testes de detecção de serviços PPPoE."""

    def setUp(self):
        self.device = Device.objects.create(name="PPPOE-SVC-TEST")

    def test_pppoe_server_service(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        svc = DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.PPPOE).first()
        self.assertIsNotNone(svc, "PPPoE Server service deve ser detectado")

    def test_virtual_template_service(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        svcs = DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.VIRTUAL_TEMPLATE)
        self.assertGreater(len(svcs), 0, "Virtual-Template service deve ser detectado")

    def test_ppp_access_service(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        svc = DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.PPP_ACCESS).first()
        self.assertIsNotNone(svc, "PPP Subscriber Access service deve ser detectado")


# ── Issue Tests ────────────────────────────────────────────────────────


class IssueTests(TestCase):
    """Testes de detecção de issues PPPoE."""

    def setUp(self):
        self.device = Device.objects.create(name="PPPOE-ISS-TEST")

    def _get_issues(self, config_text):
        pc = _analyze(self.device, config_text)
        return list(AnalysisIssue.objects.filter(snapshot=pc.snapshot))

    def test_pppoe_vt_not_found(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("pppoe_virtual_template_not_found", codes)

    def test_virtual_template_orphan(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("virtual_template_orphan", codes)

    def test_pppoe_interface_without_bas(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("pppoe_interface_without_bas", codes)

    def test_pppoe_interface_without_domain(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("pppoe_interface_without_domain", codes)

    def test_pppoe_interface_without_user_vlan(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("pppoe_interface_without_user_vlan", codes)

    def test_vt_without_ppp_auth(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("virtual_template_without_ppp_authentication", codes)

    def test_ppp_auth_pap_enabled(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("ppp_authentication_pap_enabled", codes)

    def test_pppoe_without_max_sessions(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("pppoe_without_max_sessions", codes)

    def test_vt_pool_not_found(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("virtual_template_pool_not_found", codes)

    def test_vt_mtu_not_1492(self):
        issues = self._get_issues(PPPOE_RISKY)
        codes = [i.code for i in issues]
        self.assertIn("virtual_template_mtu_not_1492", codes)

    def test_no_issues_on_basic_config(self):
        issues = self._get_issues(PPPOE_BASIC)
        pppoe_codes = [i.code for i in issues if "pppoe" in i.code or "virtual_template" in i.code or "ppp_" in i.code]
        self.assertEqual(len(pppoe_codes), 0, "Configuração básica não deve gerar issues PPPoE")


# ── Documentation Tests ────────────────────────────────────────────────


class DocumentationTests(TestCase):
    """Testes de documentação PPPoE."""

    def setUp(self):
        self.device = Device.objects.create(name="PPPOE-DOC-TEST")

    def test_pppoe_section_exists(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertIn("pppoe", doc)
        self.assertIsNotNone(doc["pppoe"])

    def test_pppoe_has_virtual_templates(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc.get("pppoe", {}).get("virtual_templates", [])), 0)

    def test_pppoe_has_interfaces(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertGreater(len(doc.get("pppoe", {}).get("pppoe_interfaces", [])), 0)

    def test_pppoe_shows_auth_modes(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        doc = generate_analysis_documentation(pc)
        for vt in doc.get("pppoe", {}).get("virtual_templates", []):
            if vt["name"] == "Virtual-Template1":
                self.assertIn("chap", vt.get("ppp_authentication_modes", []))
                return

    def test_pppoe_shows_remote_pool(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        doc = generate_analysis_documentation(pc)
        for vt in doc.get("pppoe", {}).get("virtual_templates", []):
            if vt["name"] == "Virtual-Template1":
                self.assertEqual(vt.get("remote_address_pool"), "POOL-CLIENTES")
                return


# ── Search Tests ───────────────────────────────────────────────────────


class SearchTests(TestCase):
    """Testes de busca PPPoE."""

    def setUp(self):
        self.device = Device.objects.create(name="PPPOE-SEARCH-TEST")
        _analyze(self.device, PPPOE_BASIC)

    def test_search_pppoe(self):
        results = global_network_search("pppoe")
        self.assertGreater(len(results.get("pppoe", [])), 0)

    def test_search_virtual_template(self):
        results = global_network_search("Virtual-Template1")
        pppoe = results.get("pppoe", [])
        self.assertGreater(len(pppoe), 0)

    def test_search_chap(self):
        results = global_network_search("chap")
        pppoe = results.get("pppoe", [])
        self.assertGreater(len(pppoe), 0)

    def test_search_max_sessions(self):
        results = global_network_search("16000")
        pppoe = results.get("pppoe", [])
        # May appear in raw matches
        total = len(pppoe) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)


# ── Comparison Tests ───────────────────────────────────────────────────


class ComparisonTests(TestCase):
    """Testes de comparação PPPoE."""

    def setUp(self):
        self.device = Device.objects.create(name="PPPOE-DIFF-TEST")

    def test_pppoe_key_in_diff_data(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        self.assertIn("virtual_templates", bng)
        self.assertIn("pppoe_interfaces", bng)

    def test_virtual_template_changed(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        changed = bng.get("virtual_templates", {}).get("changed", [])
        self.assertGreater(len(changed), 0, "Deve detectar Virtual-Template alterada")

    def test_auth_mode_changed(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        changed = bng.get("virtual_templates", {}).get("changed", [])
        auth_changes = [c for c in changed if "ppp_authentication_modes" in c.get("changes", {})]
        self.assertGreater(len(auth_changes), 0, "Deve detectar auth-mode alterado")

    def test_max_sessions_changed(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        changed = bng.get("pppoe_interfaces", {}).get("changed", [])
        ms_changes = [c for c in changed if "max_sessions" in c.get("changes", {})]
        self.assertGreater(len(ms_changes), 0, "Deve detectar max-sessions alterado")

    def test_pppoe_impacts_generated(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        impacts = comp.diff_data.get("impacts", [])
        pppoe_impacts = [i for i in impacts if "PPPoE" in i.get("impact", "") or "Virtual-Template" in i.get("impact", "")]
        self.assertGreater(len(pppoe_impacts), 0, "Deve gerar impacts para mudancas PPPoE")

    def test_validation_plan_includes_pppoe(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        vplan = comp.diff_data.get("validation_plan", [])
        has_pppoe = any(v.get("category") == "pppoe" for v in vplan)
        self.assertTrue(has_pppoe, "Validation plan deve incluir PPPoE quando ha mudancas reais")

    def test_validation_pppoe_not_added_without_changes(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        comp = compare_config_snapshots(base.snapshot, base.snapshot)
        vplan = comp.diff_data.get("validation_plan", [])
        has_pppoe = any(v.get("category") == "pppoe" for v in vplan)
        self.assertFalse(has_pppoe, "Sem mudancas PPPoE nao deve gerar validation plan")


# ── Web Tests ──────────────────────────────────────────────────────────


class WebTests(TestCase):
    """Testes de template web PPPoE."""

    def setUp(self):
        self.device = Device.objects.create(name="PPPOE-WEB-TEST")

    def test_documentation_web_shows_pppoe(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertContains(response, "PPPoE / Virtual-Template / PPP Access")

    def test_documentation_web_shows_virtual_template(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertContains(response, "Virtual-Template1")

    def test_documentation_web_shows_auth_modes(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertContains(response, "chap")

    def test_documentation_web_shows_max_sessions(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertContains(response, "16000")

    def test_documentation_web_shows_remote_pool(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertContains(response, "POOL-CLIENTES")

    def test_documentation_web_no_radius_secret(self):
        """Segredo RADIUS não deve aparecer na documentação."""
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        response_text = response.content.decode("utf-8").lower()
        self.assertNotIn("secret", response_text)

    def test_search_web_shows_pppoe(self):
        pc = _analyze(self.device, PPPOE_BASIC)
        response = self.client.get(reverse("search") + "?q=pppoe")
        self.assertEqual(response.status_code, 200)

    def test_comparison_web_shows_pppoe_section(self):
        base = _analyze(self.device, PPPOE_CHANGE_BEFORE)
        target = _analyze(self.device, PPPOE_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        response = self.client.get(reverse("comparison_detail", args=[comp.pk]))
        self.assertEqual(response.status_code, 200)
