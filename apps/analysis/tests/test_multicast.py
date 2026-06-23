"""Tests for Multicast / PIM / IGMP / MLD support."""

from __future__ import annotations

import os
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse
from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.models import DetectedService, ParsedConfig, AnalysisIssue
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


MCAST_BASIC = _load_sample("huawei_multicast_basic.txt")


class ParserTests(TestCase):
    def test_multicast_ipv4_routing(self):
        parsed = _parse(MCAST_BASIC)
        self.assertTrue(parsed.get("multicast", {}).get("ipv4_routing_enabled"))

    def test_multicast_ipv6_routing(self):
        parsed = _parse(MCAST_BASIC)
        self.assertTrue(parsed.get("multicast", {}).get("ipv6_routing_enabled"))

    def test_pim_static_rp(self):
        parsed = _parse(MCAST_BASIC)
        rps = parsed.get("multicast", {}).get("pim", {}).get("global", {}).get("static_rps", [])
        self.assertGreater(len(rps), 0)
        self.assertEqual(rps[0]["rp_address"], "10.255.0.1")

    def test_pim_bsr_candidate(self):
        parsed = _parse(MCAST_BASIC)
        bsr = parsed.get("multicast", {}).get("pim", {}).get("global", {}).get("bsr_candidates", [])
        self.assertIn("LoopBack0", bsr)

    def test_pim_interface(self):
        parsed = _parse(MCAST_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "GigabitEthernet0/0/0":
                self.assertTrue(iface.get("pim_enabled"))
                self.assertEqual(iface.get("pim_mode"), "sm")
                self.assertEqual(iface.get("pim_hello_holdtime"), 105)
                return

    def test_igmp_interface(self):
        parsed = _parse(MCAST_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "Vlanif100":
                self.assertTrue(iface.get("igmp_enabled"))
                self.assertEqual(iface.get("igmp_version"), 2)
                self.assertIn("239.1.1.1", iface.get("igmp_static_groups", []))
                self.assertIn("239.1.1.2", iface.get("igmp_join_groups", []))
                self.assertEqual(iface.get("igmp_limit"), 100)
                return

    def test_igmp_snooping_global(self):
        parsed = _parse(MCAST_BASIC)
        self.assertTrue(parsed.get("multicast", {}).get("igmp_snooping", {}).get("global_enabled"))

    def test_igmp_snooping_vlan(self):
        parsed = _parse(MCAST_BASIC)
        vlans = parsed.get("multicast", {}).get("igmp_snooping", {}).get("vlans", [])
        self.assertGreater(len(vlans), 0)
        v = vlans[0]
        self.assertEqual(v["vlan_id"], "100")
        self.assertTrue(v["enabled"])
        self.assertEqual(v["version"], 2)

    def test_mld_interface(self):
        parsed = _parse(MCAST_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "Vlanif200":
                self.assertTrue(iface.get("mld_enabled"))
                self.assertEqual(iface.get("mld_version"), 2)
                self.assertIn("ff3e::1", iface.get("mld_static_groups", []))
                return

    def test_pim_mode_sm(self):
        parsed = _parse("""
interface GigabitEthernet0/0/0
 pim sm
#
""")
        for iface in parsed.get("interfaces", []):
            if iface.get("pim_enabled"):
                self.assertEqual(iface.get("pim_mode"), "sm")
                return
        self.fail("Nenhuma interface com pim_enabled encontrada")

    def test_pim_mode_dm(self):
        parsed = _parse("""
interface GigabitEthernet0/0/1
 pim dm
#
""")
        for iface in parsed.get("interfaces", []):
            if iface.get("pim_enabled"):
                self.assertEqual(iface.get("pim_mode"), "dm")
                return
        self.fail("Nenhuma interface com pim_enabled encontrada")

    def test_pim_mode_ssm(self):
        parsed = _parse("""
interface GigabitEthernet0/0/2
 pim ssm
#
""")
        for iface in parsed.get("interfaces", []):
            if iface.get("pim_enabled"):
                self.assertEqual(iface.get("pim_mode"), "ssm")
                return
        self.fail("Nenhuma interface com pim_enabled encontrada")


class ServiceTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="MC-SVC-TEST")

    def test_multicast_service(self):
        pc = _analyze(self.device, MCAST_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.MULTICAST).exists())

    def test_pim_service(self):
        pc = _analyze(self.device, MCAST_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.PIM).exists())

    def test_igmp_service(self):
        pc = _analyze(self.device, MCAST_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.IGMP).exists())

    def test_igmp_snooping_service(self):
        pc = _analyze(self.device, MCAST_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.IGMP_SNOOPING).exists())

    def test_mld_service(self):
        pc = _analyze(self.device, MCAST_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.MLD).exists())


class SearchTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="MC-SEARCH-TEST")
        _analyze(self.device, MCAST_BASIC)

    def test_search_multicast(self):
        results = global_network_search("multicast")
        total = len(results.get("multicast", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)

    def test_search_pim(self):
        results = global_network_search("pim")
        total = len(results.get("multicast", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)

    def test_search_igmp(self):
        results = global_network_search("igmp")
        total = len(results.get("multicast", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)

    def test_search_mld(self):
        results = global_network_search("mld")
        total = len(results.get("multicast", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)

    def test_search_group_ip(self):
        results = global_network_search("239.1.1.1")
        total = len(results.get("multicast", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)


class WebTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="MC-WEB-TEST")
        self.user = User.objects.create_user(username="webviewer", password="view123")
        self.client.login(username="webviewer", password="view123")

    def test_search_web_shows_multicast(self):
        pc = _analyze(self.device, MCAST_BASIC)
        response = self.client.get(reverse("search") + "?q=multicast")
        self.assertEqual(response.status_code, 200)

    def test_documentation_web_shows_multicast(self):
        pc = _analyze(self.device, MCAST_BASIC)
        response = self.client.get(reverse("analysis_documentation", args=[pc.pk]))
        self.assertEqual(response.status_code, 200)

    def test_multicast_detail_web_accessible(self):
        pc = _analyze(self.device, MCAST_BASIC)
        response = self.client.get(reverse("analysis_detail", args=[pc.pk]))
        self.assertEqual(response.status_code, 200)

    def test_multicast_comparison_web(self):
        dev = self.device
        before = _load_sample("huawei_multicast_change_before.txt")
        after = _load_sample("huawei_multicast_change_after.txt")
        from apps.config_archive.models import ConfigSnapshot
        b_snap = ConfigSnapshot.objects.create(device=dev, raw_config=before, vendor="huawei")
        t_snap = ConfigSnapshot.objects.create(device=dev, raw_config=after, vendor="huawei")
        compare_config_snapshots(b_snap, t_snap, title="MCAST TEST")
        from apps.analysis.models import ConfigComparison
        comp = ConfigComparison.objects.first()
        self.assertIsNotNone(comp)
        dd = comp.diff_data
        self.assertIn("multicast", dd)


class ComparisonTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="MC-COMP-TEST")
        self.before = _analyze(self.device, _load_sample("huawei_multicast_change_before.txt"))
        self.after = _analyze(self.device, _load_sample("huawei_multicast_change_after.txt"))

    def test_multicast_diff_data_key(self):
        from apps.config_archive.models import ConfigSnapshot
        b_snap = self.before.snapshot
        t_snap = self.after.snapshot
        comp = compare_config_snapshots(b_snap, t_snap, title="MCAST")
        self.assertIn("multicast", comp.diff_data)

    def test_multicast_diff_contains_pim_changes(self):
        from apps.config_archive.models import ConfigSnapshot
        comp = compare_config_snapshots(self.before.snapshot, self.after.snapshot, title="MCAST")
        mc = comp.diff_data.get("multicast", {})
        self.assertTrue(mc.get("pim", {}).get("changed") or mc.get("pim", {}).get("added") or mc.get("igmp", {}).get("changed") or mc.get("igmp_snooping", {}).get("added") or mc.get("igmp_snooping", {}).get("changed"))

    def test_multicast_impacts_generated(self):
        from apps.config_archive.models import ConfigSnapshot
        comp = compare_config_snapshots(self.before.snapshot, self.after.snapshot, title="MCAST")
        mcast_impacts = [i for i in comp.diff_data.get("impacts", []) if "Multicast" in i.get("impact", "") or "PIM" in i.get("impact", "") or "IGMP" in i.get("impact", "") or "MLD" in i.get("impact", "")]
        self.assertGreater(len(mcast_impacts), 0, "Deve gerar impacts para mudancas multicast")

    def test_validation_plan_includes_multicast(self):
        from apps.config_archive.models import ConfigSnapshot
        comp = compare_config_snapshots(self.before.snapshot, self.after.snapshot, title="MCAST")
        has_mcast = any(v.get("category") == "multicast" for v in comp.diff_data.get("validation_plan", []))
        self.assertTrue(has_mcast, "Validation plan deve incluir multicast quando ha mudancas reais")

    def test_rollback_plan_includes_multicast(self):
        from apps.config_archive.models import ConfigSnapshot
        comp = compare_config_snapshots(self.before.snapshot, self.after.snapshot, title="MCAST")
        has_mcast = any(r.get("change_type") == "multicast" for r in comp.diff_data.get("rollback_plan", []))
        self.assertTrue(has_mcast, "Rollback plan deve incluir multicast quando ha mudancas reais")


class IssueTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="MC-ISSUE-TEST")
        self.user = User.objects.create_user(username="issueviewer", password="view123")
        self.client.login(username="issueviewer", password="view123")

    def test_issues_detected_in_risky_config(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        issues = AnalysisIssue.objects.filter(snapshot=pc.snapshot)
        issue_codes = set(i.code for i in issues)
        self.assertIn("pim_without_multicast_routing", issue_codes)
        self.assertIn("igmp_version_1", issue_codes)

    def test_pim_without_multicast_routing_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="pim_without_multicast_routing").exists())

    def test_igmp_invalid_group_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="igmp_invalid_group_address").exists())

    def test_mld_invalid_group_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="mld_invalid_group_address").exists())

    def test_no_multicast_issues_in_basic_config(self):
        pc = _analyze(self.device, MCAST_BASIC)
        mc_codes = [i.code for i in AnalysisIssue.objects.filter(snapshot=pc.snapshot) if i.code.startswith("pim_") or i.code.startswith("igmp_") or i.code.startswith("mld_") or i.code.startswith("multicast_")]
        # Basic config has igmp-snooping vlan 100 without querier, that's intentional
        allowed_issues = {"igmp_snooping_without_querier", "pim_static_rp_not_local"}
        unexpected = [c for c in mc_codes if c not in allowed_issues]
        self.assertEqual(len(unexpected), 0, f"Issues inesperadas: {unexpected}")

    def test_igmp_without_multicast_routing_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="igmp_without_multicast_routing").exists())

    def test_mld_without_ipv6_multicast_routing_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="mld_without_ipv6_multicast_routing").exists())

    def test_pim_without_rp_or_bsr_issue(self):
        config = """
multicast routing-enable
interface GigabitEthernet0/0/0
 pim sm
"""
        pc = _analyze(self.device, config)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="pim_without_rp_or_bsr").exists())

    def test_sparse_only_fires_without_rp_bsr(self):
        config = """
multicast routing-enable
interface GigabitEthernet0/0/0
 pim dm
"""
        pc = _analyze(self.device, config)
        # dense-mode PIM does NOT need RP/BSR
        self.assertFalse(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="pim_without_rp_or_bsr").exists())

    def test_ssm_without_rp_no_issue(self):
        config = """
multicast routing-enable
interface GigabitEthernet0/0/0
 pim ssm
#
"""
        pc = _analyze(self.device, config)
        self.assertFalse(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="pim_without_rp_or_bsr").exists())

    def test_igmp_snooping_querier_positive(self):
        """IGMP snooping com querier NÃO deve gerar igmp_snooping_without_querier."""
        config = """
igmp-snooping enable
igmp-snooping vlan 100 enable
igmp-snooping vlan 100 querier enable
#
"""
        pc = _analyze(self.device, config)
        # Verificar que querier_enabled=True
        mc = pc.parsed_data.get("multicast", {})
        vlans = mc.get("igmp_snooping", {}).get("vlans", [])
        v100 = [v for v in vlans if v["vlan_id"] == "100"]
        self.assertGreater(len(v100), 0)
        self.assertTrue(v100[0].get("querier_enabled"))
        # Nao deve gerar issue de falta de querier
        self.assertFalse(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="igmp_snooping_without_querier").exists())

    def test_igmp_snooping_without_querier_negative(self):
        """IGMP snooping sem querier DEVE gerar igmp_snooping_without_querier."""
        config = """
igmp-snooping enable
igmp-snooping vlan 200 enable
#
"""
        pc = _analyze(self.device, config)
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="igmp_snooping_without_querier").exists())

    def test_pim_static_rp_not_local_low_severity(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        issues = AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="pim_static_rp_not_local")
        self.assertTrue(issues.exists())
        self.assertEqual(issues.first().severity, "low")

    def test_igmp_snooping_without_querier_low_severity(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        issues = AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="igmp_snooping_without_querier")
        self.assertTrue(issues.exists())
        self.assertEqual(issues.first().severity, "low")

    def test_igmp_version_1_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="igmp_version_1").exists())

    def test_pim_interface_missing_description_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="pim_interface_missing_description").exists())

    def test_multicast_vpn_instance_not_found_issue(self):
        pc = _analyze(self.device, _load_sample("huawei_multicast_risky.txt"))
        self.assertTrue(AnalysisIssue.objects.filter(snapshot=pc.snapshot, code="multicast_vpn_instance_not_found").exists())

    def test_before_after_identical_no_validation_rollback(self):
        before = _analyze(self.device, MCAST_BASIC)
        after = _analyze(self.device, MCAST_BASIC)
        comp = compare_config_snapshots(before.snapshot, after.snapshot, title="MCAST SAME")
        has_vp = any(v.get("category") == "multicast" for v in comp.diff_data.get("validation_plan", []))
        has_rp = any(r.get("change_type") == "multicast" for r in comp.diff_data.get("rollback_plan", []))
        self.assertFalse(has_vp, "Sem mudancas multicast nao deve gerar validation plan")
        self.assertFalse(has_rp, "Sem mudancas multicast nao deve gerar rollback plan")

    def test_web_comparison_shows_multicast(self):
        before = _analyze(self.device, _load_sample("huawei_multicast_change_before.txt"))
        after = _analyze(self.device, _load_sample("huawei_multicast_change_after.txt"))
        comp = compare_config_snapshots(before.snapshot, after.snapshot, title="MCAST WEB")
        response = self.client.get(reverse("comparison_detail", args=[comp.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Multicast / PIM / IGMP / MLD")

    def test_multicast_service_metadata(self):
        pc = _analyze(self.device, MCAST_BASIC)
        svc = DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.MULTICAST).first()
        self.assertIsNotNone(svc)
        meta = svc.metadata
        self.assertIsNotNone(meta)
        self.assertTrue(meta.get("ipv4_routing"))
        self.assertTrue(meta.get("ipv6_routing"))
        self.assertGreater(len(meta.get("static_rps", [])), 0)

    def test_pim_service_metadata_has_rp(self):
        pc = _analyze(self.device, MCAST_BASIC)
        svc = DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.PIM).first()
        self.assertIsNotNone(svc)
        meta = svc.metadata
        rp_addrs = meta.get("static_rps", [])
        self.assertIn("10.255.0.1", rp_addrs)

    def test_igmp_snooping_service_metadata(self):
        pc = _analyze(self.device, MCAST_BASIC)
        svc = DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.IGMP_SNOOPING).first()
        self.assertIsNotNone(svc)
        meta = svc.metadata
        self.assertGreater(len(meta.get("vlans", [])), 0)
