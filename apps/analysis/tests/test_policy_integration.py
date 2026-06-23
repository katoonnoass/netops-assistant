"""
Testes de integração completos para Políticas de Roteamento e Filtros.

Testa o pipeline completo:
    parse → analyze → documentation → search → comparison → templates web

Usa o sample huawei_policy_full_visual.txt que contém BGP, route-policy,
ip-prefix, ACL, as-path-filter e community-filter.
"""

import os

from django.test import TestCase
from django.urls import reverse

from apps.core.tests import *

from apps.analysis.models import (
    ConfigComparison,
    DetectedService,
    ParsedConfig,
    AnalysisIssue,
    DetectedCircuit,
)
from apps.analysis.services import analyze_config_snapshot
from apps.analysis.policy_utils import build_policy_reference_map
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

SAMPLE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "sample_configs"
)


def _load(name: str) -> str:
    with open(os.path.join(SAMPLE_DIR, name), encoding="utf-8") as f:
        return f.read()


# =========================================================================
# Full pipeline integration
# =========================================================================


class PolicyFullPipelineTests(TestCase):
    """Testa o pipeline completo: parse → analyze → docs → search → compare."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.device = Device.objects.create(
            name="NE40-POLICY-FULL", vendor="huawei", hostname="NE40-POLICY-FULL"
        )
        cls.snapshot = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=_load("huawei_policy_full_visual.txt"),
            vendor="huawei",
            source="upload",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)
        cls.pd = cls.parsed.parsed_data

    # ── Analysis completeness ────────────────────────────────────────

    def test_parsed_config_created(self):
        """ParsedConfig foi criado."""
        self.assertIsInstance(self.parsed, ParsedConfig)

    def test_bgp_detected(self):
        """BGP foi detectado."""
        self.assertGreater(len(self.pd.get("bgp", [])), 0)

    def test_route_policies_detected(self):
        """Route-policies foram detectadas."""
        self.assertGreater(len(self.pd.get("route_policies", [])), 0)

    def test_ip_prefixes_detected(self):
        """IP prefix-lists foram detectadas."""
        self.assertGreater(len(self.pd.get("prefix_lists", [])), 0)

    def test_acls_detected(self):
        """ACLs foram detectadas."""
        self.assertGreater(len(self.pd.get("acls", [])), 0)

    def test_as_path_filters_detected(self):
        """AS-path filters foram detectados."""
        self.assertGreater(len(self.pd.get("as_path_filters", [])), 0)

    def test_community_filters_detected(self):
        """Community filters foram detectados."""
        self.assertGreater(len(self.pd.get("community_filters", [])), 0)

    def test_policy_services_detected(self):
        """Serviço de route_policy foi detectado."""
        self.assertTrue(
            DetectedService.objects.filter(
                snapshot=self.snapshot, service_type="route_policy"
            ).exists()
        )

    def test_bgp_peers_have_route_policy(self):
        """Peers BGP possuem route-policy import/export."""
        for bgp in self.pd.get("bgp", []):
            for peer in bgp.get("peers", []):
                if peer.get("route_policy_import") or peer.get("route_policy_export"):
                    return  # Found at least one
        self.fail("Nenhum peer BGP com route-policy encontrado")

    # ── Dependency map ───────────────────────────────────────────────

    def test_dependency_map_has_bgp_peer_policies(self):
        """Dependency map contém BGP peer policies."""
        ref = build_policy_reference_map(self.pd)
        self.assertGreater(len(ref.get("bgp_peer_policies", [])), 0)

    def test_dependency_map_policy_found(self):
        """Route-policy referenciada foi encontrada."""
        ref = build_policy_reference_map(self.pd)
        for bpp in ref.get("bgp_peer_policies", []):
            if bpp.get("direction") == "export":
                self.assertTrue(bpp.get("found"))

    def test_dependency_map_has_ip_prefix_dep(self):
        """Dependência BGP → route-policy → ip-prefix existe."""
        ref = build_policy_reference_map(self.pd)
        for bpp in ref.get("bgp_peer_policies", []):
            deps = bpp.get("dependencies", {})
            if deps.get("ip_prefixes"):
                self.assertGreater(len(deps["ip_prefixes"]), 0)
                return
        self.fail("Nenhuma dependência ip-prefix encontrada")

    def test_dependency_map_has_as_path_dep(self):
        """Dependência BGP → route-policy → as-path-filter existe."""
        ref = build_policy_reference_map(self.pd)
        for bpp in ref.get("bgp_peer_policies", []):
            deps = bpp.get("dependencies", {})
            if deps.get("as_path_filters"):
                self.assertGreater(len(deps["as_path_filters"]), 0)
                return
        self.fail("Nenhuma dependência as-path encontrada")

    def test_dependency_map_has_community_dep(self):
        """Dependência BGP → route-policy → community-filter existe."""
        ref = build_policy_reference_map(self.pd)
        for bpp in ref.get("bgp_peer_policies", []):
            deps = bpp.get("dependencies", {})
            if deps.get("community_filters"):
                self.assertGreater(len(deps["community_filters"]), 0)
                return
        self.fail("Nenhuma dependência community encontrada")

    # ── Documentation web ────────────────────────────────────────────

    def test_documentation_200(self):
        """Página de documentação responde 200."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertEqual(response.status_code, 200)

    def test_documentation_has_policies_section(self):
        """Documentação contém seção policies."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "Políticas de Roteamento e Filtros")

    def test_documentation_has_ip_prefix_text(self):
        """Documentação contém texto 'IP Prefix'."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "IP Prefix")

    def test_documentation_has_route_policy_text(self):
        """Documentação contém 'Route-Policy'."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "Route-Policy")

    def test_documentation_has_acl_text(self):
        """Documentação contém 'ACL'."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "ACL")

    def test_documentation_has_as_path_text(self):
        """Documentação contém 'AS-Path'."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "AS-Path")

    def test_documentation_has_community_text(self):
        """Documentação contém 'Community'."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "Community")

    def test_documentation_has_export_cliente(self):
        """Documentação contém EXPORT-CLIENTE."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "EXPORT-CLIENTE")

    def test_documentation_has_import_cliente(self):
        """Documentação contém IMPORT-CLIENTE."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "IMPORT-CLIENTE")

    def test_documentation_has_cliente_x(self):
        """Documentação contém CLIENTE-X."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "CLIENTE-X")

    def test_documentation_has_community_value(self):
        """Documentação contém 65000:100."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "65000:100")

    def test_documentation_has_bgp_peer(self):
        """Documentação contém peer BGP."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "10.255.0.2")

    def test_documentation_has_acl_rule(self):
        """Documentação mostra regra ACL (source 10.0.0.0)."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(response, "10.0.0.0")


# =========================================================================
# Search web tests
# =========================================================================


class PolicySearchIntegrationTests(TestCase):
    """Testes de busca web para policies."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_full_visual.txt"), vendor="huawei"
        )
        analyze_config_snapshot(cls.snapshot)

    def test_search_export_cliente_shows_policies_section(self):
        """Busca EXPORT-CLIENTE mostra se\u00e7\u00e3o Pol\u00edticas/Filtros."""
        r = self.client.get("/search/?q=EXPORT-CLIENTE")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")

    def test_search_export_cliente_finds_route_policy(self):
        """Busca EXPORT-CLIENTE encontra route-policy no HTML."""
        r = self.client.get("/search/?q=EXPORT-CLIENTE")
        self.assertContains(r, "EXPORT-CLIENTE")
        self.assertContains(r, "route_policy")

    def test_search_export_cliente_finds_bgp_dependency(self):
        """Busca EXPORT-CLIENTE encontra depend\u00eancia BGP no HTML."""
        r = self.client.get("/search/?q=EXPORT-CLIENTE")
        self.assertContains(r, "bgp_policy_dependency")
        self.assertContains(r, "Route-policy")

    def test_search_community_value_shows_policies_section(self):
        """Busca 65000:100 mostra se\u00e7\u00e3o Pol\u00edticas/Filtros."""
        r = self.client.get("/search/?q=65000:100")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")
        self.assertContains(r, "Community")

    def test_search_as_path_shows_policies_section(self):
        """Busca as-path-filter mostra se\u00e7\u00e3o Pol\u00edticas/Filtros."""
        r = self.client.get("/search/?q=as-path-filter")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")
        self.assertContains(r, "as_path_filter")

    def test_search_cliente_x_finds_ip_prefix(self):
        """Busca CLIENTE-X encontra ip-prefix no HTML."""
        r = self.client.get("/search/?q=CLIENTE-X")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")
        self.assertContains(r, "ip_prefix")

    def test_search_community_value_finds_filter(self):
        """Busca 65000:100 encontra community-filter no HTML."""
        r = self.client.get("/search/?q=65000:100")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "community_filter")

    def test_search_as_path_finds_filter(self):
        """Busca as-path-filter encontra AS-path filter no HTML."""
        r = self.client.get("/search/?q=as-path-filter")
        self.assertEqual(r.status_code, 200)

    def test_search_acl_number_finds_acl(self):
        """Busca 3001 encontra ACL no HTML."""
        r = self.client.get("/search/?q=3001")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "ACL")

    def test_search_acl_3001_quoted_finds_acl(self):
        """Busca 'acl 3001' encontra ACL."""
        r = self.client.get("/search/?q=acl+3001")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")
        self.assertContains(r, "acl")

    def test_search_as_path_filter_10_finds_filter(self):
        """Busca 'as-path-filter 10' encontra AS-path filter."""
        r = self.client.get("/search/?q=as-path-filter+10")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")
        self.assertContains(r, "AS-path")

    def test_search_community_filter_20_finds_filter(self):
        """Busca 'community-filter 20' encontra community filter."""
        r = self.client.get("/search/?q=community-filter+20")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")
        self.assertContains(r, "Community")

    def test_search_200_prefix_finds_ip_prefix(self):
        """Busca '200.200.200.0/30' encontra ip-prefix rule."""
        r = self.client.get("/search/?q=200.200.200.0/30")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Pol\u00edticas / Filtros")


# =========================================================================
# Comparison web tests
# =========================================================================


class PolicyComparisonIntegrationTests(TestCase):
    """Testes de comparação web para policies."""

    def _compare_and_get(self):
        """Cria comparação via serviço e retorna response da página."""
        base = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_change_before.txt"), vendor="huawei"
        )
        target = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_change_after.txt"), vendor="huawei"
        )
        analyze_config_snapshot(base)
        analyze_config_snapshot(target)

        from apps.analysis.comparison import compare_config_snapshots
        comp = compare_config_snapshots(base, target)
        return self.client.get(
            reverse("comparison_detail", kwargs={"pk": comp.pk})
        )

    def test_comparison_200(self):
        """Página de comparação responde 200."""
        r = self._compare_and_get()
        self.assertEqual(r.status_code, 200)

    def test_comparison_has_ip_prefix(self):
        """Comparação contém seção IP Prefix."""
        r = self._compare_and_get()
        self.assertContains(r, "IP Prefix")

    def test_comparison_has_route_policies(self):
        """Comparação contém seção Route-Policies."""
        r = self._compare_and_get()
        self.assertContains(r, "Route-Policies")

    def test_comparison_has_acls(self):
        """Comparação contém seção ACLs."""
        r = self._compare_and_get()
        self.assertContains(r, "ACLs")

    def test_comparison_has_as_path_filters(self):
        """Comparação contém seção AS-Path Filters."""
        r = self._compare_and_get()
        self.assertContains(r, "AS-Path Filters")

    def test_comparison_has_community_filters(self):
        """Comparação contém seção Community Filters."""
        r = self._compare_and_get()
        self.assertContains(r, "Community Filters")

    def test_comparison_has_validation_plan(self):
        """Comparação contém Plano de Validação."""
        r = self._compare_and_get()
        self.assertContains(r, "Plano de Valida\u00e7\u00e3o")

    def test_comparison_validation_has_policy_commands(self):
        """Validation plan contém comando de route-policy."""
        r = self._compare_and_get()
        self.assertContains(r, "route-policy")

    def test_comparison_validation_has_as_path_cmd(self):
        """Validation plan contém comando as-path-filter."""
        r = self._compare_and_get()
        self.assertContains(r, "as-path-filter")

    def test_comparison_has_rollback_plan(self):
        """Comparação contém Plano de Rollback."""
        r = self._compare_and_get()
        self.assertContains(r, "Plano de Rollback")

    def test_comparison_rollback_has_policy_suggestion(self):
        """Rollback plan contém sugestão de policy."""
        r = self._compare_and_get()
        content = r.content.decode("utf-8")
        self.assertTrue(
            "Restaurar" in content or "Rollback" in content or "policy" in content.lower()
        )


# =========================================================================
# CLI-compatible diff_data test
# =========================================================================


class PolicyComparisonDiffTests(TestCase):
    """Testa diff_data gerado pela comparação de policies."""

    def test_diff_data_has_all_policy_keys(self):
        """diff_data contém ip_prefixes, route_policies, acls, as_path_filters, community_filters."""
        base = ConfigSnapshot(
            raw_config=_load("huawei_policy_change_before.txt"), vendor="huawei"
        )
        base.save()
        target = ConfigSnapshot(
            raw_config=_load("huawei_policy_change_after.txt"), vendor="huawei"
        )
        target.save()
        analyze_config_snapshot(base)
        analyze_config_snapshot(target)

        from apps.analysis.comparison import compare_config_snapshots
        comp = compare_config_snapshots(base, target)
        dd = comp.diff_data

        self.assertIn("ip_prefixes", dd)
        self.assertIn("route_policies", dd)
        self.assertIn("acls", dd)
        self.assertIn("as_path_filters", dd)
        self.assertIn("community_filters", dd)
        self.assertIn("validation_plan", dd)
        self.assertIn("rollback_plan", dd)


# =========================================================================
# Unit tests for global_network_search returning policies
# =========================================================================


class PolicyGlobalSearchTests(TestCase):
    """Testa global_network_search retornar se\u00e7\u00e3o policies."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_full_visual.txt"), vendor="huawei"
        )
        analyze_config_snapshot(cls.snapshot)

    def test_search_returns_policies_key(self):
        """global_network_search retorna chave policies."""
        from apps.analysis.search import global_network_search
        results = global_network_search("EXPORT-CLIENTE")
        self.assertIn("policies", results)

    def test_search_policies_not_empty(self):
        """global_network_search('EXPORT-CLIENTE') retorna policies n\u00e3o vazias."""
        from apps.analysis.search import global_network_search
        results = global_network_search("EXPORT-CLIENTE")
        self.assertGreater(len(results.get("policies", [])), 0)

    def test_search_policies_has_route_policy(self):
        """results['policies'] cont\u00e9m route_policy."""
        from apps.analysis.search import global_network_search
        results = global_network_search("EXPORT-CLIENTE")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("route_policy", types)

    def test_search_policies_has_bgp_dependency(self):
        """results['policies'] cont\u00e9m bgp_policy_dependency."""
        from apps.analysis.search import global_network_search
        results = global_network_search("EXPORT-CLIENTE")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("bgp_policy_dependency", types)

    def test_search_ip_prefix(self):
        """Busca CLIENTE-X retorna ip_prefix."""
        from apps.analysis.search import global_network_search
        results = global_network_search("CLIENTE-X")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("ip_prefix", types)

    def test_search_as_path_filter(self):
        """Busca as-path-filter retorna as_path_filter."""
        from apps.analysis.search import global_network_search
        results = global_network_search("as-path-filter")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("as_path_filter", types)

    def test_search_community_filter(self):
        """Busca community-filter retorna community_filter."""
        from apps.analysis.search import global_network_search
        results = global_network_search("community-filter")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("community_filter", types)

    def test_search_acl(self):
        """Busca 3001 retorna ACL."""
        from apps.analysis.search import global_network_search
        results = global_network_search("3001")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("acl", types)

    def test_search_community_value(self):
        """Busca 65000:100 retorna community_filter."""
        from apps.analysis.search import global_network_search
        results = global_network_search("65000:100")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("community_filter", types)

    def test_search_acl_3001_returns_acl(self):
        """Busca 'acl 3001' retorna ACL."""
        from apps.analysis.search import global_network_search
        results = global_network_search("acl 3001")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("acl", types)

    def test_search_as_path_filter_10_returns_filter(self):
        """Busca 'as-path-filter 10' retorna as_path_filter."""
        from apps.analysis.search import global_network_search
        results = global_network_search("as-path-filter 10")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("as_path_filter", types)

    def test_search_community_filter_20_returns_filter(self):
        """Busca 'community-filter 20' retorna community_filter."""
        from apps.analysis.search import global_network_search
        results = global_network_search("community-filter 20")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("community_filter", types)

    def test_search_prefix_200_returns_ip_prefix(self):
        """Busca '200.200.200.0/30' retorna ip_prefix rule."""
        from apps.analysis.search import global_network_search
        results = global_network_search("200.200.200.0/30")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("ip_prefix", types)

    def test_search_policies_has_evidence(self):
        """Resultados de policies incluem evidence."""
        from apps.analysis.search import global_network_search
        results = global_network_search("EXPORT-CLIENTE")
        for pol in results.get("policies", []):
            if pol["type"] == "route_policy":
                self.assertGreater(len(pol.get("evidence", [])), 0)
                return
        self.fail("Nenhum route_policy com evidence encontrado")

    def test_search_community_index_in_description(self):
        """Community rule description cont\u00e9m index."""
        from apps.analysis.search import global_network_search
        results = global_network_search("65000:200")
        for pol in results.get("policies", []):
            if pol["type"] == "community_filter":
                self.assertIn("Index", pol.get("description", ""))
                self.assertIn("10", pol.get("description", ""))
                return
        self.fail("Nenhum community_filter com index 10 encontrado")

    def test_search_route_policy_generic(self):
        """Busca 'route-policy' retorna route_policy generico."""
        from apps.analysis.search import global_network_search
        results = global_network_search("route-policy")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("route_policy", types)
        self.assertGreater(len(results.get("policies", [])), 0)

    def test_search_ip_prefix_generic(self):
        """Busca 'ip-prefix' retorna ip_prefix generico."""
        from apps.analysis.search import global_network_search
        results = global_network_search("ip-prefix")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("ip_prefix", types)
        self.assertGreater(len(results.get("policies", [])), 0)

    def test_search_acls_generic(self):
        """Busca 'acl' retorna ACL generico."""
        from apps.analysis.search import global_network_search
        results = global_network_search("acl")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("acl", types)

    def test_search_as_path_generic(self):
        """Busca 'as-path-filter' retorna as_path_filter generico."""
        from apps.analysis.search import global_network_search
        results = global_network_search("as-path-filter")
        types = [r["type"] for r in results.get("policies", [])]
        self.assertIn("as_path_filter", types)
# Community-filter with index
# =========================================================================


class PolicyCommunityIndexTests(TestCase):
    """Community-filter com index opcional."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        cls.parsed = HuaweiVRPParser(_load("huawei_policy_full_visual.txt")).parse()

    def test_community_filter_has_index(self):
        """Community-filter 20 cont\u00e9m regra com index 10."""
        for cf in self.parsed.get("community_filters", []):
            if cf.get("name") == "20":
                for rule in cf.get("rules", []):
                    if rule.get("index") == 10:
                        return
        self.fail("Regra com index 10 n\u00e3o encontrada em community-filter 20")

    def test_community_filter_basic_has_index(self):
        """Community-filter CLIENTE-COMM cont\u00e9m regra com index 10."""
        for cf in self.parsed.get("community_filters", []):
            if cf.get("name") == "CLIENTE-COMM":
                for rule in cf.get("rules", []):
                    if rule.get("index") == 10:
                        return
        self.fail("Regra com index 10 n\u00e3o encontrada em CLIENTE-COMM")

    def test_community_index_in_documentation(self):
        """Documentacao contem index em community-filter."""
        from apps.analysis.services import analyze_config_snapshot
        snap = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_full_visual.txt"), vendor="huawei"
        )
        parsed = analyze_config_snapshot(snap)
        from apps.analysis.documentation import generate_analysis_documentation
        doc = generate_analysis_documentation(parsed)
        pol = doc.get("policies", {})
        cfs = pol.get("community_filters", [])
        found = False
        for cf in cfs:
            for rule in cf.get("rules", []):
                if rule.get("index") is not None:
                    found = True
                    break
        self.assertTrue(found, "Nenhum community-filter com index na documentacao")


# =========================================================================
# OSPF Detection Integration Tests
# =========================================================================


class TestOspfDetection(TestCase):
    """Testa parser, serviço, issues e documentação para OSPF."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.device = Device.objects.create(
            name="ROTEADOR-OSPF", vendor="huawei", hostname="ROTEADOR-OSPF"
        )
        cls.snapshot = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=_load("huawei_ospf_basic.txt"),
            vendor="huawei",
            source="upload",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)
        cls.pd = cls.parsed.parsed_data

    # ── Parser ────────────────────────────────────────────────────────

    def test_ospf_parsed(self):
        """OSPF foi detectado no parsed_data."""
        self.assertIn("ospf", self.pd)
        self.assertGreater(len(self.pd["ospf"]), 0)

    def test_ospf_two_processes(self):
        """Dois processos OSPF detectados."""
        self.assertEqual(len(self.pd["ospf"]), 2)

    def test_ospf_process_ids(self):
        """Process IDs corretos (1 e 2)."""
        ids = [o["process_id"] for o in self.pd["ospf"]]
        self.assertIn("1", ids)
        self.assertIn("2", ids)

    def test_ospf_router_id(self):
        """Router-id extraído no processo 1."""
        ospf1 = [o for o in self.pd["ospf"] if o["process_id"] == "1"][0]
        self.assertEqual(ospf1.get("router_id"), "10.0.0.1")

    def test_ospf_no_router_id_on_process2(self):
        """Processo 2 não possui router-id."""
        ospf2 = [o for o in self.pd["ospf"] if o["process_id"] == "2"][0]
        self.assertIsNone(ospf2.get("router_id"))

    def test_ospf_areas(self):
        """Áreas OSPF detectadas."""
        ospf1 = [o for o in self.pd["ospf"] if o["process_id"] == "1"][0]
        self.assertIn("0.0.0.0", ospf1["areas"])
        ospf2 = [o for o in self.pd["ospf"] if o["process_id"] == "2"][0]
        self.assertIn("0.0.0.1", ospf2["areas"])

    def test_ospf_networks(self):
        """Redes OSPF detectadas."""
        ospf1 = [o for o in self.pd["ospf"] if o["process_id"] == "1"][0]
        self.assertGreater(len(ospf1["networks"]), 0)

    def test_ospf_redistribution(self):
        """Redistribuição detectada no processo 2."""
        ospf2 = [o for o in self.pd["ospf"] if o["process_id"] == "2"][0]
        self.assertGreater(len(ospf2["redistribute"]), 0)
        self.assertEqual(ospf2["redistribute"][0]["protocol"], "static")

    def test_ospf_default_route(self):
        """Default-route-advertise detectado no processo 2."""
        ospf2 = [o for o in self.pd["ospf"] if o["process_id"] == "2"][0]
        self.assertTrue(ospf2["default_route_advertise"])

    # ── Service ───────────────────────────────────────────────────────

    def test_ospf_service_detected(self):
        """Serviço OSPF foi detectado."""
        services = self.snapshot.detected_services.filter(service_type="ospf")
        self.assertEqual(services.count(), 1)
        svc = services.first()
        self.assertIn("OSPF", svc.name)

    def test_ospf_service_high_confidence(self):
        """Confiança do serviço OSPF é alta (>= 0.75)."""
        svc = self.snapshot.detected_services.get(service_type="ospf")
        self.assertGreaterEqual(svc.confidence, 0.75)

    # ── Issues ────────────────────────────────────────────────────────

    def test_ospf_no_router_id_issue(self):
        """Issue ospf_no_router_id gerado para processo sem router-id."""
        issues = self.snapshot.analysis_issues.filter(code="ospf_no_router_id")
        self.assertGreaterEqual(issues.count(), 1)

    def test_ospf_passive_missing_issue(self):
        """Issue ospf_passive_missing gerado."""
        issues = self.snapshot.analysis_issues.filter(code="ospf_passive_missing")
        self.assertGreaterEqual(issues.count(), 1)

    def test_ospf_redistribution_without_filter_issue(self):
        """Issue ospf_redistribution_without_filter gerado."""
        issues = self.snapshot.analysis_issues.filter(
            code="ospf_redistribution_without_filter"
        )
        self.assertGreaterEqual(issues.count(), 1)

    # ── Documentation ─────────────────────────────────────────────────

    def test_documentation_has_ospf_role(self):
        """Documentação contém role OSPF."""
        from apps.analysis.documentation import generate_analysis_documentation
        doc = generate_analysis_documentation(self.parsed)
        roles = doc.get("detected_roles", [])
        ospf_roles = [r for r in roles if "OSPF" in r["role"]]
        self.assertGreater(len(ospf_roles), 0)

    def test_documentation_web_200(self):
        """Página de documentação responde 200."""
        r = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertEqual(r.status_code, 200)
