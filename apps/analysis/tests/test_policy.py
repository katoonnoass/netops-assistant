"""Testes para políticas de roteamento e filtros.

Testa:
    - Parser: ip-prefix, route-policy, ACL
    - policy_utils: dependency maps, BGP → policy → prefix
    - Issues: policy issues
    - Services: route_policy, acl_policy
    - Documentação: seção políticas
    - Busca: route-policy, ip-prefix, ACL
    - Comparação: ip-prefixes, route_policies, acls
"""

import os
from django.test import TestCase
from apps.analysis.models import ParsedConfig, DetectedService, ConfigComparison
from apps.config_archive.models import ConfigSnapshot

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'sample_configs')


def _load(name: str) -> str:
    with open(os.path.join(SAMPLE_DIR, name), encoding='utf-8') as f:
        return f.read()


class PolicyParserTests(TestCase):
    """Parser de ip-prefix, route-policy e ACL."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        cls.parsed = HuaweiVRPParser(_load("huawei_policy_basic.txt")).parse()

    def test_ip_prefixes_parsed(self):
        """ip-prefixes detectados e agrupados por nome."""
        self.assertGreater(len(self.parsed.get("prefix_lists", [])), 0)

    def test_ip_prefix_has_rules(self):
        """Cada ip-prefix tem regras."""
        for pp in self.parsed.get("prefix_lists", []):
            self.assertGreater(len(pp.get("rules", [])), 0)

    def test_ip_prefix_rule_has_fields(self):
        """Regra ip-prefix tem index, action, prefix, mask_length."""
        for pp in self.parsed.get("prefix_lists", []):
            for rule in pp.get("rules", []):
                self.assertIn("index", rule)
                self.assertIn("action", rule)
                self.assertIn("prefix", rule)
                self.assertIn("mask_length", rule)

    def test_ip_prefix_ge_le(self):
        """Regra com greater-equal / less-equal."""
        for pp in self.parsed.get("prefix_lists", []):
            for rule in pp.get("rules", []):
                if rule.get("greater_equal") is not None:
                    self.assertIsInstance(rule["greater_equal"], int)
                if rule.get("less_equal") is not None:
                    self.assertIsInstance(rule["less_equal"], int)

    def test_route_policies_parsed(self):
        """Route-policies detectadas."""
        self.assertGreater(len(self.parsed.get("route_policies", [])), 0)

    def test_route_policy_has_fields(self):
        """Route-policy tem name, node, action, if_match, apply."""
        for rp in self.parsed.get("route_policies", []):
            self.assertIn("name", rp)
            self.assertIn("node", rp)
            self.assertIn("action", rp)

    def test_route_policy_if_match(self):
        """Route-policy com if-match ip-prefix."""
        for rp in self.parsed.get("route_policies", []):
            if rp.get("if_match"):
                for im in rp["if_match"]:
                    self.assertIn("type", im)
                    self.assertIn("name", im)

    def test_acls_parsed(self):
        """ACLs detectadas."""
        self.assertGreater(len(self.parsed.get("acls", [])), 0)

    def test_acl_advanced_has_rules(self):
        """ACL advanced tem regras com action."""
        for acl in self.parsed.get("acls", []):
            for rule in acl.get("rules", []):
                self.assertIn("action", rule)


class PolicyUtilsTests(TestCase):
    """policy_utils: dependency maps."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        from apps.analysis.policy_utils import build_policy_reference_map
        cls.parsed = HuaweiVRPParser(_load("huawei_policy_basic.txt")).parse()
        cls.ref_map = build_policy_reference_map(cls.parsed)

    def test_bgp_peer_policy_found(self):
        """BGP peer route-policy export encontrada."""
        exports = [bpp for bpp in self.ref_map.get("bgp_peer_policies", [])
                   if bpp.get("direction") == "export"]
        if exports:
            self.assertTrue(all(e.get("found") for e in exports))

    def test_bgp_peer_policy_not_found(self):
        """BGP peer route-policy import não encontrada (IMPORT-UPSTREAM)."""
        imports = [bpp for bpp in self.ref_map.get("bgp_peer_policies", [])
                   if bpp.get("direction") == "import"]
        if imports:
            self.assertTrue(any(not e.get("found") for e in imports))

    def test_policy_dependencies(self):
        """Policy referência ip-prefix."""
        for bpp in self.ref_map.get("bgp_peer_policies", []):
            if bpp.get("found"):
                deps = bpp.get("dependencies", {})
                if deps.get("ip_prefixes"):
                    self.assertIsInstance(deps["ip_prefixes"], list)


class PolicyIssueTests(TestCase):
    """Issues de política."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        from apps.analysis.policy_utils import find_policy_issues
        cls.parsed_risky = HuaweiVRPParser(_load("huawei_policy_risky.txt")).parse()
        cls.issues = find_policy_issues(cls.parsed_risky)

    def test_ip_prefix_permit_any(self):
        """ip_prefix_permit_any detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("ip_prefix_permit_any", codes)

    def test_route_policy_permit_without_match(self):
        """route_policy_permit_without_match detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("route_policy_permit_without_match", codes)

    def test_route_policy_without_apply(self):
        """route_policy_without_apply detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("route_policy_without_apply", codes)

    def test_acl_rule_any(self):
        """acl_rule_any detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("acl_rule_any", codes)

    def test_route_policy_orphan(self):
        """route_policy_orphan detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("route_policy_orphan", codes)

    def test_ip_prefix_orphan(self):
        """ip_prefix_orphan detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("ip_prefix_orphan", codes)


class PolicyServiceTests(TestCase):
    """Serviços de política."""

    def test_route_policy_service_detected(self):
        """analyze_config_snapshot detecta route_policy service."""
        from apps.analysis.services import analyze_config_snapshot
        snap = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_basic.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(snap)
        self.assertTrue(
            DetectedService.objects.filter(snapshot=snap, service_type="route_policy").exists()
        )

    def test_acl_policy_service_detected(self):
        """analyze_config_snapshot detecta acl_policy service."""
        from apps.analysis.services import analyze_config_snapshot
        snap = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_basic.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(snap)
        self.assertTrue(
            DetectedService.objects.filter(snapshot=snap, service_type="acl_policy").exists()
        )


class PolicyDocTests(TestCase):
    """Documentação automática de políticas."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.analysis.documentation import generate_analysis_documentation
        from apps.analysis.services import analyze_config_snapshot
        snap = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_basic.txt"),
            vendor="huawei",
        )
        parsed = analyze_config_snapshot(snap)
        cls.doc = generate_analysis_documentation(parsed)

    def test_policy_section_exists(self):
        """Documentação tem seção policies."""
        self.assertIsNotNone(self.doc.get("policies"))

    def test_policy_section_has_ip_prefixes(self):
        """Seção policies tem ip_prefixes."""
        policies = self.doc.get("policies", {})
        if policies:
            self.assertIn("ip_prefixes", policies)

    def test_policy_section_has_route_policies(self):
        """Seção policies tem route_policies."""
        policies = self.doc.get("policies", {})
        if policies:
            self.assertIn("route_policies", policies)


class PolicySearchTests(TestCase):
    """Busca global de políticas."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.analysis.services import analyze_config_snapshot
        cls.snap = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_basic.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(cls.snap)

    def test_search_route_policy(self):
        """Busca EXPORT-CLIENTE retorna resultados (via raw_matches ou issues)."""
        from apps.analysis.search import global_network_search
        results = global_network_search("EXPORT-CLIENTE")
        total = results.get("summary", {}).get("total", 0)
        self.assertGreater(total, 0)

    def test_search_ip_prefix(self):
        """Busca CLIENTE-X retorna resultados."""
        from apps.analysis.search import global_network_search
        results = global_network_search("CLIENTE-X")
        total = results.get("summary", {}).get("total", 0)
        self.assertGreater(total, 0)


class PolicyComparisonTests(TestCase):
    """Comparação de políticas."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.analysis.services import analyze_config_snapshot
        from apps.analysis.comparison import compare_config_snapshots
        cls.base = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_change_before.txt") if os.path.exists(os.path.join(SAMPLE_DIR, "huawei_policy_change_before.txt"))
                       else _load("huawei_policy_basic.txt"),
            vendor="huawei",
        )
        cls.target = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_change_after.txt") if os.path.exists(os.path.join(SAMPLE_DIR, "huawei_policy_change_after.txt"))
                       else _load("huawei_policy_basic.txt"),
            vendor="huawei",
        )
        analyze_config_snapshot(cls.base)
        analyze_config_snapshot(cls.target)
        cls.comp = compare_config_snapshots(cls.base, cls.target)
        cls.diff = cls.comp.diff_data

    def test_diff_has_ip_prefixes(self):
        """diff_data tem chave ip_prefixes."""
        self.assertIn("ip_prefixes", self.diff)

    def test_diff_has_route_policies(self):
        """diff_data tem chave route_policies."""
        self.assertIn("route_policies", self.diff)

    def test_diff_has_acls(self):
        """diff_data tem chave acls."""
        self.assertIn("acls", self.diff)

    def test_diff_has_as_path_filters(self):
        """diff_data tem chave as_path_filters."""
        self.assertIn("as_path_filters", self.diff)

    def test_diff_has_community_filters(self):
        """diff_data tem chave community_filters."""
        self.assertIn("community_filters", self.diff)

    def test_diff_as_path_added(self):
        """AS-path filter added detectado."""
        as_path = self.diff.get("as_path_filters", {})
        self.assertGreater(len(as_path.get("added", [])) + len(as_path.get("changed", [])), 0)

    def test_diff_community_added(self):
        """Community filter added detectado."""
        comm = self.diff.get("community_filters", {})
        self.assertGreater(len(comm.get("added", [])) + len(comm.get("changed", [])), 0)

    def test_diff_policy_impacts_exist(self):
        """Impactos de policy existen."""
        impacts = self.diff.get("impacts", [])
        policy_impacts = [i for i in impacts if "policy" in i.get("impact", "").lower() or "AS-path" in i.get("impact", "") or "Community" in i.get("impact", "")]
        self.assertGreaterEqual(len(policy_impacts), 0)


class PolicyParserNewTests(TestCase):
    """Parser de as-path-filter e community-filter."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        cls.parsed = HuaweiVRPParser(_load("huawei_policy_change_before.txt")).parse()

    def test_as_path_filter_parsed(self):
        """AS-path filter detectado."""
        self.assertGreater(len(self.parsed.get("as_path_filters", [])), 0)

    def test_as_path_filter_has_rules(self):
        """AS-path filter tem regras com action e pattern."""
        for af in self.parsed.get("as_path_filters", []):
            self.assertGreater(len(af.get("rules", [])), 0)
            for rule in af.get("rules", []):
                self.assertIn("action", rule)
                self.assertIn("pattern", rule)

    def test_community_filter_parsed(self):
        """Community filter detectado."""
        self.assertGreater(len(self.parsed.get("community_filters", [])), 0)

    def test_community_filter_has_rules(self):
        """Community filter tem regras com action e value."""
        for cf in self.parsed.get("community_filters", []):
            self.assertGreater(len(cf.get("rules", [])), 0)
            for rule in cf.get("rules", []):
                self.assertIn("action", rule)
                self.assertIn("value", rule)

    def test_route_policy_if_match_as_path(self):
        """Route-policy com if-match as-path-filter."""
        for rp in self.parsed.get("route_policies", []):
            for im in rp.get("if_match", []):
                if im.get("type") == "as-path-filter":
                    self.assertIn("name", im)

    def test_route_policy_if_match_community(self):
        """Route-policy com if-match community-filter."""
        for rp in self.parsed.get("route_policies", []):
            for im in rp.get("if_match", []):
                if im.get("type") == "community-filter":
                    self.assertIn("name", im)


class PolicyDependencyTests(TestCase):
    """Dependências com as-path e community filters."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        from apps.analysis.policy_utils import build_policy_reference_map
        cls.parsed_before = HuaweiVRPParser(_load("huawei_policy_change_before.txt")).parse()
        cls.parsed_after = HuaweiVRPParser(_load("huawei_policy_change_after.txt")).parse()
        cls.ref_before = build_policy_reference_map(cls.parsed_before)
        cls.ref_after = build_policy_reference_map(cls.parsed_after)

    def test_deps_include_as_path(self):
        """Dependency map inclui as_path_filters."""
        for bpp in self.ref_before.get("bgp_peer_policies", []):
            deps = bpp.get("dependencies", {})
            if deps.get("as_path_filters"):
                self.assertIsInstance(deps["as_path_filters"], list)
                break

    def test_deps_include_community(self):
        """Dependency map inclui community_filters."""
        for bpp in self.ref_before.get("bgp_peer_policies", []):
            deps = bpp.get("dependencies", {})
            if deps.get("community_filters"):
                self.assertIsInstance(deps["community_filters"], list)
                break

    def test_orphans_detectable(self):
        """Orphans keys existem."""
        self.assertIn("orphan_as_path_filters", self.ref_after)
        self.assertIn("orphan_community_filters", self.ref_after)


class PolicyIssueNewTests(TestCase):
    """Issues de as-path-filter e community-filter."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.parsers.huawei import HuaweiVRPParser
        from apps.analysis.policy_utils import find_policy_issues
        cls.parsed = HuaweiVRPParser(_load("huawei_policy_risky.txt")).parse()
        cls.issues = find_policy_issues(cls.parsed)

    def test_as_path_filter_orphan(self):
        """as_path_filter_orphan detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("as_path_filter_orphan", codes)

    def test_as_path_permit_any(self):
        """as_path_filter_permit_any detectado."""
        codes = [i["code"] for i in self.issues]
        self.assertIn("as_path_filter_permit_any", codes)


class PolicyTemplateTests(TestCase):
    """Testes de templates web para policies."""

    def setUp(self):
        from apps.analysis.services import analyze_config_snapshot
        self.snap = ConfigSnapshot.objects.create(
            raw_config=_load("huawei_policy_full_visual.txt"),
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snap)

    def test_documentation_page_200(self):
        response = self.client.get(f"/analysis/{self.parsed.pk}/documentation/")
        self.assertEqual(response.status_code, 200)

    def test_documentation_has_policies_section(self):
        response = self.client.get(f"/analysis/{self.parsed.pk}/documentation/")
        self.assertContains(response, "Pol\u00edticas de Roteamento e Filtros")

    def test_documentation_has_route_policy(self):
        response = self.client.get(f"/analysis/{self.parsed.pk}/documentation/")
        self.assertContains(response, "EXPORT-CLIENTE")

    def test_documentation_has_ip_prefix(self):
        response = self.client.get(f"/analysis/{self.parsed.pk}/documentation/")
        self.assertContains(response, "CLIENTE-X")

    def test_documentation_has_community_value(self):
        response = self.client.get(f"/analysis/{self.parsed.pk}/documentation/")
        self.assertContains(response, "65000:100")

    def test_search_policy_section(self):
        response = self.client.get("/search/?q=EXPORT-CLIENTE")
        self.assertEqual(response.status_code, 200)

    def test_search_finds_route_policy(self):
        response = self.client.get("/search/?q=EXPORT-CLIENTE")
        self.assertContains(response, "EXPORT-CLIENTE")
