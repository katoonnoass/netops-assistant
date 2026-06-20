"""Testes completos para BNG Avançado / AAA / RADIUS / IP pool."""

from __future__ import annotations

import os

from django.test import TestCase

from apps.analysis.bng_utils import build_bng_dependency_map, build_bng_summary
from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.ipv6_utils import build_ipv6_dependency_map, build_ipv6_summary
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


BNG_BASIC = _load_sample("huawei_bng_advanced_basic.txt")
BNG_RISKY = _load_sample("huawei_bng_advanced_risky.txt")
BNG_CHANGE_BEFORE = _load_sample("huawei_bng_advanced_change_before.txt")
BNG_CHANGE_AFTER = _load_sample("huawei_bng_advanced_change_after.txt")


class ParserTests(TestCase):
    """Testes do parser para BNG Avançado."""

    def test_aaa_block_detected(self):
        parsed = _parse(BNG_BASIC)
        self.assertGreater(len(parsed.get("aaa", [])), 0)

    def test_auth_scheme_name(self):
        parsed = _parse(BNG_BASIC)
        schemes = parsed["aaa"][0].get("authentication_schemes", [])
        self.assertTrue(any(s["name"] == "AUTH-PPPOE" for s in schemes))

    def test_auth_scheme_mode(self):
        parsed = _parse(BNG_BASIC)
        for s in parsed["aaa"][0].get("authentication_schemes", []):
            if s["name"] == "AUTH-PPPOE":
                self.assertIn("radius", s.get("authentication_mode", []))
                self.assertIn("local", s.get("authentication_mode", []))
                return

    def test_acct_scheme_realtime(self):
        parsed = _parse(BNG_BASIC)
        for s in parsed["aaa"][0].get("accounting_schemes", []):
            if s["name"] == "ACC-PPPOE":
                self.assertEqual(s.get("accounting_realtime"), 15)
                return

    def test_authz_scheme_mode(self):
        parsed = _parse(BNG_BASIC)
        for s in parsed["aaa"][0].get("authorization_schemes", []):
            if s["name"] == "AUTHZ-PPPOE":
                self.assertIn("radius", s.get("authorization_mode", []))
                return

    def test_domain_in_aaa(self):
        parsed = _parse(BNG_BASIC)
        for d in parsed["aaa"][0].get("domains", []):
            if d["name"] == "cliente-pppoe":
                self.assertEqual(d.get("authentication_scheme"), "AUTH-PPPOE")
                self.assertEqual(d.get("accounting_scheme"), "ACC-PPPOE")
                self.assertEqual(d.get("radius_server_group"), "RAD-CLIENTES")
                self.assertEqual(d.get("ip_pool"), "POOL-CLIENTES")
                return
        self.fail("Domain not found in AAA")

    def test_domain_dns(self):
        parsed = _parse(BNG_BASIC)
        for d in parsed["aaa"][0].get("domains", []):
            if d["name"] == "cliente-pppoe":
                self.assertEqual(d.get("dns_primary"), "8.8.8.8")
                self.assertEqual(d.get("dns_secondary"), "1.1.1.1")
                return

    def test_radius_group_servers(self):
        parsed = _parse(BNG_BASIC)
        for rg in parsed.get("radius_servers", []):
            if rg["name"] == "RAD-CLIENTES":
                self.assertEqual(len(rg.get("authentication_servers", [])), 2)
                self.assertEqual(len(rg.get("accounting_servers", [])), 2)
                self.assertEqual(rg.get("authentication_servers", [])[0]["ip"], "10.10.10.10")
                self.assertEqual(rg.get("retransmit"), 3)
                self.assertEqual(rg.get("timeout"), 5)
                return
        self.fail("RADIUS group not found")

    def test_radius_shared_key_not_saved(self):
        parsed = _parse(BNG_BASIC)
        for rg in parsed.get("radius_servers", []):
            if rg["name"] == "RAD-CLIENTES":
                self.assertTrue(rg.get("has_shared_key"))
                self.assertTrue(rg.get("shared_key_encrypted"))
                # Ensure no plaintext secret stored in parsed_data
                self.assertFalse(any("plain" in str(v).lower() for v in ((rg.get("shared_key_type") or ""),)))
                self.assertEqual(rg.get("shared_key_type"), "cipher")
                return

    def test_ip_pool_local(self):
        parsed = _parse(BNG_BASIC)
        for p in parsed.get("ip_pools", []):
            if p["name"] == "POOL-CLIENTES":
                self.assertEqual(p.get("type"), "bas")
                self.assertEqual(p.get("mode"), "local")
                self.assertEqual(p.get("gateway"), "100.64.0.1")
                self.assertEqual(p.get("mask"), "255.255.255.0")
                self.assertEqual(len(p.get("sections", [])), 1)
                self.assertEqual(p.get("lease"), "1 0 0")
                self.assertIn("8.8.8.8", p.get("dns_servers", []))
                return

    def test_ip_pool_remote(self):
        parsed = _parse(BNG_BASIC)
        for p in parsed.get("ip_pools", []):
            if p["name"] == "POOL-REMOTO":
                self.assertEqual(p.get("type"), "bas")
                self.assertEqual(p.get("mode"), "remote")
                self.assertEqual(p.get("radius_server_group"), "RAD-CLIENTES")
                return

    def test_bas_interface_in_interface(self):
        parsed = _parse(BNG_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "Eth-Trunk100.200":
                bas = iface.get("bas")
                self.assertIsNotNone(bas)
                self.assertTrue(bas.get("enabled"))
                self.assertEqual(bas.get("access_type"), "layer2-subscriber")
                self.assertEqual(bas.get("default_domain"), "cliente-pppoe")
                self.assertEqual(bas.get("authentication_method"), "pppoe")
                self.assertEqual(bas.get("accounting_copy_radius_group"), "RAD-CLIENTES")
                self.assertTrue(bas.get("ip_trigger"))
                self.assertTrue(bas.get("arp_trigger"))
                self.assertTrue(bas.get("ipv6_trigger"))
                self.assertEqual(iface.get("user_vlan"), "200")
                return

    def test_bas_interface_qinq(self):
        parsed = _parse(BNG_BASIC)
        for iface in parsed["interfaces"]:
            if iface["name"] == "Eth-Trunk100.300":
                self.assertEqual(iface.get("user_vlan"), "300")
                self.assertEqual(iface.get("qinq_vlan"), "400")
                bas = iface.get("bas")
                self.assertEqual(bas.get("authentication_method"), "bind")
                return


class UtilsTests(TestCase):
    """Testes dos utilitários BNG."""

    def test_build_bng_summary(self):
        parsed = _parse(BNG_BASIC)
        s = build_bng_summary(parsed)
        self.assertGreater(s["total_bas_interfaces"], 0)
        self.assertGreater(s["total_domains"], 0)
        self.assertGreater(s["total_radius_groups"], 0)
        self.assertGreater(s["total_ip_pools"], 0)

    def test_build_bng_dependency_map(self):
        parsed = _parse(BNG_BASIC)
        deps = build_bng_dependency_map(parsed)
        self.assertGreater(len(deps["bas_interfaces"]), 0)
        self.assertEqual(len(deps["missing_references"]), 0)

    def test_dependency_map_missing_references(self):
        parsed = _parse(BNG_RISKY)
        deps = build_bng_dependency_map(parsed)
        self.assertGreater(len(deps["missing_references"]), 0)


class ServiceTests(TestCase):
    """Testes de detecção de serviços BNG Avançado."""

    def setUp(self):
        self.device = Device.objects.create(name="BNG-SVC-TEST")

    def test_bng_advanced_service(self):
        _analyze(self.device, BNG_BASIC)
        svc = DetectedService.objects.filter(service_type="bng_advanced").first()
        self.assertIsNotNone(svc)
        self.assertGreater(svc.metadata.get("domain_count", 0), 0)

    def test_bas_interface_service(self):
        _analyze(self.device, BNG_BASIC)
        svcs = DetectedService.objects.filter(service_type="bas_interface")
        self.assertGreater(len(svcs), 0)

    def test_subscriber_domain_service(self):
        _analyze(self.device, BNG_BASIC)
        svcs = DetectedService.objects.filter(service_type="subscriber_domain")
        self.assertGreater(len(svcs), 0)

    def test_radius_group_service(self):
        _analyze(self.device, BNG_BASIC)
        svcs = DetectedService.objects.filter(service_type="radius_group")
        self.assertGreater(len(svcs), 0)


class IssueTests(TestCase):
    """Testes de detecção de issues BNG."""

    def setUp(self):
        self.device = Device.objects.create(name="BNG-ISSUE-TEST")

    def test_bas_domain_not_found(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="bas_domain_not_found").exists())

    def test_domain_auth_scheme_not_found(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="domain_authentication_scheme_not_found").exists())

    def test_domain_radius_group_not_found(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="domain_radius_group_not_found").exists())

    def test_domain_ip_pool_not_found(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="domain_ip_pool_not_found").exists())

    def test_radius_group_without_auth(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="radius_group_without_authentication_server").exists())

    def test_radius_shared_key_plain(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="radius_shared_key_plain").exists())

    def test_ip_pool_without_gateway(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="ip_pool_without_gateway").exists())

    def test_ip_pool_without_section(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="ip_pool_without_section").exists())

    def test_bas_without_user_vlan(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="bas_interface_without_user_vlan").exists())

    def test_bas_without_auth_method(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="bas_interface_without_authentication_method").exists())

    def test_bas_without_description(self):
        _analyze(self.device, BNG_RISKY)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot__device=self.device, code="bas_interface_missing_description").exists())


class SearchTests(TestCase):
    """Testes de busca global BNG."""

    def setUp(self):
        self.device = Device.objects.create(name="BNG-SEARCH-TEST")

    def test_search_domain(self):
        _analyze(self.device, BNG_BASIC)
        results = global_network_search("cliente-pppoe")
        self.assertGreater(results["summary"].get("bng", 0), 0)

    def test_search_radius_group(self):
        _analyze(self.device, BNG_BASIC)
        results = global_network_search("RAD-CLIENTES")
        self.assertGreater(results["summary"].get("bng", 0), 0)

    def test_search_ip_pool(self):
        _analyze(self.device, BNG_BASIC)
        results = global_network_search("POOL-CLIENTES")
        self.assertGreater(results["summary"].get("bng", 0), 0)


class DocumentationTests(TestCase):
    """Testes da documentação BNG."""

    def setUp(self):
        self.device = Device.objects.create(name="BNG-DOC-TEST")

    def test_bng_section_exists(self):
        pc = _analyze(self.device, BNG_BASIC)
        doc = generate_analysis_documentation(pc)
        self.assertIn("bng", doc)

    def test_bng_has_bas_interfaces(self):
        pc = _analyze(self.device, BNG_BASIC)
        doc = generate_analysis_documentation(pc)
        bng = doc.get("bng", {}) or {}
        self.assertGreater(len(bng.get("bas_interfaces", [])), 0)

    def test_bng_has_domains(self):
        pc = _analyze(self.device, BNG_BASIC)
        doc = generate_analysis_documentation(pc)
        bng = doc.get("bng", {}) or {}
        self.assertGreater(len(bng.get("domains", [])), 0)

    def test_bng_has_radius_groups(self):
        pc = _analyze(self.device, BNG_BASIC)
        doc = generate_analysis_documentation(pc)
        bng = doc.get("bng", {}) or {}
        self.assertGreater(len(bng.get("radius_groups", [])), 0)


class ComparisonTests(TestCase):
    """Testes de comparação BNG."""

    def setUp(self):
        self.device = Device.objects.create(name="BNG-DIFF-TEST")

    def test_bng_key_in_diff_data(self):
        base = _analyze(self.device, BNG_CHANGE_BEFORE)
        target = _analyze(self.device, BNG_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        self.assertIn("bng", comp.diff_data)

    def test_bng_has_bas_interfaces_key(self):
        base = _analyze(self.device, BNG_CHANGE_BEFORE)
        target = _analyze(self.device, BNG_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        self.assertIn("bas_interfaces", bng)
