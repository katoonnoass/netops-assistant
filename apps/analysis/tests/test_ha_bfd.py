"""Tests for HA / BFD / Graceful Restart / NSR support."""

from __future__ import annotations

import os
from django.test import TestCase
from django.urls import reverse
from apps.analysis.comparison import compare_config_snapshots
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


HA_BASIC = _load_sample("huawei_ha_bfd_basic.txt")
HA_RISKY = _load_sample("huawei_ha_bfd_risky.txt")
HA_CHANGE_BEFORE = _load_sample("huawei_ha_bfd_change_before.txt")
HA_CHANGE_AFTER = _load_sample("huawei_ha_bfd_change_after.txt")

# ── Parser Tests ───────────────────────────────────────────────────────


class ParserTests(TestCase):
    def test_bfd_global_enabled(self):
        parsed = _parse(HA_BASIC)
        self.assertTrue(parsed.get("ha", {}).get("bfd", {}).get("global_enabled"))

    def test_bfd_session(self):
        parsed = _parse(HA_BASIC)
        sessions = parsed.get("ha", {}).get("bfd", {}).get("sessions", [])
        self.assertGreater(len(sessions), 0)
        s = sessions[0]
        self.assertEqual(s["name"], "TO-PEER-1")

    def test_bfd_session_committed(self):
        parsed = _parse(HA_BASIC)
        for s in parsed.get("ha", {}).get("bfd", {}).get("sessions", []):
            if s["name"] == "TO-PEER-1":
                self.assertTrue(s["committed"])
                self.assertEqual(s["local_discriminator"], "100")
                self.assertEqual(s["min_tx_interval"], 300)
                return

    def test_bgp_peer_bfd(self):
        parsed = _parse(HA_BASIC)
        for bgp in parsed.get("bgp", []):
            for p in bgp.get("peers", []):
                if p.get("ip") == "10.255.0.2":
                    self.assertTrue(p.get("bfd_enabled"))
                    return

    def test_bgp_peer_graceful_restart(self):
        parsed = _parse(HA_BASIC)
        for bgp in parsed.get("bgp", []):
            for p in bgp.get("peers", []):
                if p.get("ip") == "10.255.0.2":
                    self.assertTrue(p.get("graceful_restart"))
                    return

    def test_bgp_global_graceful_restart(self):
        parsed = _parse(HA_BASIC)
        self.assertTrue(parsed.get("ha", {}).get("graceful_restart", {}).get("bgp"))

    def test_isis_bfd_gr_nsr(self):
        parsed = _parse(HA_BASIC)
        for isis in parsed.get("isis", []):
            self.assertTrue(isis.get("bfd_all_interfaces"))
            self.assertTrue(isis.get("graceful_restart"))
            self.assertTrue(isis.get("nsr_enabled"))

    def test_interface_isis_bfd(self):
        parsed = _parse(HA_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "GigabitEthernet0/0/0":
                self.assertTrue(iface.get("isis_bfd_enabled"))
                return

    def test_ldp_graceful_restart(self):
        parsed = _parse(HA_BASIC)
        self.assertTrue(parsed.get("ha", {}).get("graceful_restart", {}).get("ldp"))

    def test_ospfv3_bfd_all_interfaces(self):
        parsed = _parse(HA_BASIC)
        for ospfv3 in parsed.get("ospfv3", []):
            self.assertTrue(ospfv3.get("bfd_all_interfaces"))
            return True

    def test_interface_ospfv3_bfd(self):
        parsed = _parse(HA_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "Eth-Trunk100":
                self.assertTrue(iface.get("ospfv3_bfd_enabled"))
                return

    def test_interface_mpls_ldp_bfd(self):
        parsed = _parse(HA_BASIC)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "Eth-Trunk100":
                self.assertTrue(iface.get("mpls_ldp_bfd_enabled"))
                return

    def test_ldp_bfd_enabled(self):
        parsed = _parse(HA_BASIC)
        self.assertTrue(parsed.get("ha", {}).get("bfd", {}).get("ldp_enabled", True))

    def test_non_stop_routing_isis(self):
        """non-stop-routing deve ser detectado (after config usa non-stop-routing em vez de nsr)."""
        parsed = _parse(HA_CHANGE_AFTER)
        for isis in parsed.get("isis", []):
            self.assertTrue(isis.get("nsr_enabled") or isis.get("non_stop_routing"))
            return

    def test_bgp_bfd_timers(self):
        parsed = _parse(HA_BASIC)
        for bgp in parsed.get("bgp", []):
            for p in bgp.get("peers", []):
                if p.get("ip") == "10.255.0.2":
                    timers = p.get("bfd_timers")
                    self.assertIsNotNone(timers)
                    self.assertEqual(timers["min_tx_interval"], 300)
                    return


class UtilsTests(TestCase):
    def test_build_ha_summary(self):
        from apps.analysis.ha_utils import build_ha_summary
        parsed = _parse(HA_BASIC)
        summary = build_ha_summary(parsed)
        self.assertTrue(summary["bfd_global"])
        self.assertGreaterEqual(summary["bfd_sessions"], 1)
        self.assertGreaterEqual(summary["bgp_peers_with_bfd"], 1)

    def test_build_ha_dependency_map(self):
        from apps.analysis.ha_utils import build_ha_dependency_map
        parsed = _parse(HA_BASIC)
        dep = build_ha_dependency_map(parsed)
        self.assertIn("bfd_sessions", dep)
        self.assertIn("protocol_bindings", dep)
        self.assertGreater(len(dep["protocol_bindings"]), 0)


# ── Service Tests ──────────────────────────────────────────────────────


class ServiceTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="HA-SVC-TEST")

    def test_bfd_service(self):
        pc = _analyze(self.device, HA_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.BFD).exists())

    def test_graceful_restart_service(self):
        pc = _analyze(self.device, HA_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.GRACEFUL_RESTART).exists())

    def test_nsr_service(self):
        pc = _analyze(self.device, HA_BASIC)
        self.assertTrue(DetectedService.objects.filter(snapshot=pc.snapshot, service_type=DetectedService.ServiceType.NSR).exists())


# ── Issue Tests ────────────────────────────────────────────────────────


class IssueTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="HA-ISS-TEST")

    def _get_issues(self, config_text):
        pc = _analyze(self.device, config_text)
        return list(AnalysisIssue.objects.filter(snapshot=pc.snapshot))

    def test_bfd_session_without_commit(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "bfd_session_without_commit" for i in issues))

    def test_bfd_session_without_discriminator(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "bfd_session_without_discriminator" for i in issues))

    def test_bfd_session_interface_not_found(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "bfd_session_interface_not_found" for i in issues))

    def test_bfd_timers_too_aggressive(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "bfd_timers_too_aggressive" for i in issues))

    def test_bgp_core_peer_without_bfd(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "bgp_core_peer_without_bfd" for i in issues))

    def test_igp_core_interface_without_bfd(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "igp_core_interface_without_bfd" for i in issues))

    def test_ldp_without_graceful_restart(self):
        issues = self._get_issues(HA_RISKY)
        self.assertTrue(any(i.code == "ldp_without_graceful_restart" for i in issues))

    def test_no_issues_on_basic_config(self):
        issues = self._get_issues(HA_BASIC)
        ha_codes = [i.code for i in issues if i.code.startswith("bfd_session") or i.code.startswith("bfd_enabled") or i.code.startswith("bfd_timers") or i.code.startswith("bgp_core") or i.code.startswith("ldp_without") or i.code.startswith("graceful_restart") or i.code.startswith("igp_core")]
        self.assertEqual(len(ha_codes), 0, "Configuracao basica nao deve gerar issues HA")


# ── Search Tests ───────────────────────────────────────────────────────


class SearchTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="HA-SEARCH-TEST")
        _analyze(self.device, HA_BASIC)

    def test_search_bfd(self):
        results = global_network_search("bfd")
        self.assertGreater(len(results.get("ha", [])), 0)

    def test_search_graceful_restart(self):
        results = global_network_search("graceful-restart")
        total = len(results.get("ha", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)

    def test_search_nsr(self):
        results = global_network_search("nsr")
        total = len(results.get("ha", [])) + len(results.get("raw_matches", []))
        self.assertGreater(total, 0)

    def test_search_peer_ip(self):
        results = global_network_search("10.255.0.2")
        total = len(results.get("ha", []))
        self.assertGreater(total, 0)


# ── Comparison Tests ───────────────────────────────────────────────────


class ComparisonTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="HA-DIFF-TEST")

    def test_ha_key_in_bng(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        self.assertIn("bfd", bng)

    def test_bfd_global_or_session_changed(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        bfd = bng.get("bfd", {})
        has_change = bool(bfd.get("changed")) or bool(bfd.get("added"))
        has_bgp = bool(bng.get("bgp_ha", {}).get("changed"))
        has_nsr = bool(bng.get("nsr", {}).get("changed"))
        self.assertTrue(has_change or has_bgp or has_nsr)

    def test_validation_plan_includes_ha(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        vplan = comp.diff_data.get("validation_plan", [])
        self.assertTrue(any(v.get("category") == "ha" for v in vplan))

    def test_rollback_plan_includes_ha(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        rplan = comp.diff_data.get("rollback_plan", [])
        self.assertTrue(any(r.get("change_type") == "ha" for r in rplan))

    def test_no_ha_validation_without_changes(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        comp = compare_config_snapshots(base.snapshot, base.snapshot)
        vplan = comp.diff_data.get("validation_plan", [])
        self.assertFalse(any(v.get("category") == "ha" for v in vplan))

    def test_ha_impacts_generated(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        impacts = comp.diff_data.get("impacts", [])
        ha_impacts = [i for i in impacts if "BFD" in i.get("impact", "") or "NSR" in i.get("impact", "") or "Graceful" in i.get("impact", "")]
        self.assertGreater(len(ha_impacts), 0)


# ── Web Tests ──────────────────────────────────────────────────────────


class WebTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="HA-WEB-TEST")

    def test_search_web_shows_bfd(self):
        pc = _analyze(self.device, HA_BASIC)
        response = self.client.get(reverse("search") + "?q=bfd")
        self.assertEqual(response.status_code, 200)

    def test_comparison_web_shows_ha_section(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        response = self.client.get(reverse("comparison_detail", args=[comp.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alta Disponibilidade / BFD / GR / NSR")

    def test_comparison_web_shows_bfd_discriminator_diff(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        response = self.client.get(reverse("comparison_detail", args=[comp.pk]))
        self.assertContains(response, "local_discriminator")


class OspfBfdTests(TestCase):
    """Testes específicos para OSPF BFD per-interface."""

    def test_ospf_bfd_enabled_in_after_config(self):
        """Config 'after' deve ter ospf bfd enable na interface."""
        parsed = _parse(HA_CHANGE_AFTER)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "GigabitEthernet0/0/0":
                self.assertTrue(iface.get("ospf_bfd_enabled"),
                                "ospf_bfd_enabled deve ser True na interface com 'ospf bfd enable'")
                return
        self.fail("Interface GigabitEthernet0/0/0 não encontrada")

    def test_ospf_enable_detected(self):
        """OSPF enable N area X deve ser detectado na interface."""
        parsed = _parse(HA_CHANGE_AFTER)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "GigabitEthernet0/0/0":
                self.assertTrue(iface.get("ospf_enabled"))
                self.assertEqual(iface.get("ospf_process_id"), "1")
                self.assertEqual(iface.get("ospf_area"), "0.0.0.0")
                return
        self.fail("Interface GigabitEthernet0/0/0 não encontrada")


class MplsLdpBfdTests(TestCase):
    """Testes específicos para MPLS LDP BFD em interface."""

    def test_mpls_ldp_bfd_detected(self):
        parsed = _parse(HA_CHANGE_AFTER)
        for iface in parsed.get("interfaces", []):
            if iface.get("name") == "Eth-Trunk100":
                self.assertTrue(iface.get("mpls_ldp_bfd_enabled"),
                                "mpls_ldp_bfd_enabled deve ser True na interface com 'mpls ldp bfd enable'")
                return
        self.fail("Interface Eth-Trunk100 não encontrada")

    def test_ldp_bfd_global(self):
        parsed = _parse(HA_CHANGE_AFTER)
        ldp_bfd = parsed.get("ha", {}).get("bfd", {}).get("ldp_enabled")
        self.assertTrue(ldp_bfd, "ldp_enabled deve ser True quando LDP BFD está configurado")


class BfdComparisonDetailTests(TestCase):
    """Testes de comparação BFD com discriminators."""

    def setUp(self):
        self.device = Device.objects.create(name="HA-BFD-DIFF-DETAIL")

    def test_bfd_discriminator_in_diff(self):
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        target = _analyze(self.device, HA_CHANGE_AFTER)
        comp = compare_config_snapshots(base.snapshot, target.snapshot)
        bng = comp.diff_data.get("bng", {})
        bfd = bng.get("bfd", {})
        changed = bfd.get("changed", [])
        self.assertGreater(len(changed), 0, "Deve haver sessões BFD alteradas")
        has_disc = any("local_discriminator" in c.get("changes", {}) for c in changed)
        self.assertTrue(has_disc, "Diff deve incluir local_discriminator alterado")
        has_timers = any("min_tx_interval" in c.get("changes", {}) for c in changed)
        self.assertTrue(has_timers, "Diff deve incluir min_tx_interval alterado")

    def test_no_ha_plan_without_changes(self):
        """Before == after não deve gerar validation/rollback HA."""
        base = _analyze(self.device, HA_CHANGE_BEFORE)
        comp = compare_config_snapshots(base.snapshot, base.snapshot)
        vplan = comp.diff_data.get("validation_plan", [])
        ha_commands = [v for v in vplan if v.get("category") == "ha"]
        self.assertEqual(len(ha_commands), 0, "Sem mudanças HA não deve gerar validation plan")
        rplan = comp.diff_data.get("rollback_plan", [])
        ha_rollback = [r for r in rplan if r.get("change_type") == "ha"]
        self.assertEqual(len(ha_rollback), 0, "Sem mudanças HA não deve gerar rollback plan")
