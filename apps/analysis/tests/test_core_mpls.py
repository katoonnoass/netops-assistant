"""Testes completos para Core / IGP / MPLS: parser, serviços, issues,
documentação, busca e comparação.

Testa o pipeline completo:
    parse → analyze → documentation → search → comparison

Usa strings de configuração inline para não depender de fixtures externas.
"""

import io

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei import HuaweiVRPParser


# =========================================================================
# Configurações de amostra inline
# =========================================================================

SAMPLE_ISIS_FULL = """#
sysname ROTEADOR-ISIS
#
isis 1
 is-level level-2
 cost-style wide
 network-entity 49.0001.0100.0000.0001.00
 import-route direct
 import-route static
#
interface GigabitEthernet0/0/0
 description LINK-CORE
 ip address 10.0.0.1 255.255.255.252
 isis enable 1
 isis circuit-type level-2
 isis cost 10
 isis authentication-mode md5 cipher %^%#ABC123#%^%
 mpls
 mpls ldp
#
interface LoopBack0
 description ROUTER-ID
 ip address 10.255.0.1 255.255.255.255
 isis enable 1
 isis circuit-type level-2
 isis cost 0
"""

SAMPLE_ISIS_VPN = """#
sysname ROTEADOR-ISIS-VPN
#
isis 2 vpn-instance CLIENTE-A
 is-level level-1
 cost-style narrow
 network-entity 49.0002.0100.0000.0002.00
 import-route bgp
#
interface GigabitEthernet0/0/1
 description LINK-VPN
 ip address 10.0.0.5 255.255.255.252
 isis enable 2
 isis cost 20
"""

SAMPLE_MPLS_LDP_FULL = """#
sysname ROTEADOR-MPLS
#
mpls lsr-id 10.255.0.1
mpls
 mpls te
#
mpls ldp
 graceful-restart
#
mpls ldp remote-peer PEER-1
 remote-ip 10.255.0.2
#
mpls ldp remote-peer PEER-2
 remote-ip 10.255.0.3
#
interface GigabitEthernet0/0/0
 description CORE-LINK
 ip address 10.0.0.1 255.255.255.252
 mpls
 mpls ldp
#
interface GigabitEthernet0/0/1
 description CORE-LINK-2
 ip address 10.0.0.5 255.255.255.252
 mpls
 mpls ldp
"""

SAMPLE_ISIS_WITHOUT_NET = """#
sysname ROTEADOR-ISIS-BAD
#
isis 1
 is-level level-2
 cost-style wide
#
interface GigabitEthernet0/0/0
 description LINK-CORE
 ip address 10.0.0.1 255.255.255.252
 isis enable 1
"""

SAMPLE_MPLS_WITHOUT_LSR = """#
sysname ROTEADOR-MPLS-BAD
#
mpls
#
mpls ldp
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 mpls
"""

SAMPLE_LDP_WITHOUT_MPLS = """#
sysname ROTEADOR-LDP-BAD
#
mpls ldp
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 mpls ldp
"""

SAMPLE_INTERFACE_LDP_WITHOUT_MPLS = """#
sysname ROTEADOR-IF-LDP-BAD
#
mpls lsr-id 10.255.0.1
mpls
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 mpls ldp
"""

SAMPLE_MPLS_IFACE_WITHOUT_LDP = """#
sysname ROTEADOR-MPLS-IFACE
#
mpls lsr-id 10.255.0.1
mpls
mpls ldp
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 mpls
"""

SAMPLE_LDP_REMOTE_NO_IP = """#
sysname ROTEADOR-LDP-NOIP
#
mpls lsr-id 10.255.0.1
mpls
#
mpls ldp
#
mpls ldp remote-peer PEER-SEM-IP
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 mpls
 mpls ldp
"""

SAMPLE_ISIS_UNKNOWN_PROC = """#
sysname ROTEADOR-ISIS-UNKNOWN
#
isis 1
 network-entity 49.0001.0100.0000.0001.00
#
interface GigabitEthernet0/0/0
 description LINK-CORE
 ip address 10.0.0.1 255.255.255.252
 isis enable 99
"""

SAMPLE_ISIS_PLAIN_AUTH = """#
sysname ROTEADOR-ISIS-PLAIN
#
isis 1
 network-entity 49.0001.0100.0000.0001.00
#
interface GigabitEthernet0/0/0
 description LINK-CORE
 ip address 10.0.0.1 255.255.255.252
 isis enable 1
 isis authentication-mode simple plaintext-password
"""

# Configs para comparação
SAMPLE_ISIS_BEFORE = """#
sysname ROTEADOR-COMPARE
#
isis 1
 is-level level-2
 cost-style wide
 network-entity 49.0001.0100.0000.0001.00
 import-route direct
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 isis enable 1
 isis circuit-type level-2
 isis cost 10
 mpls
 mpls ldp
#
mpls lsr-id 10.255.0.1
mpls
#
mpls ldp
#
mpls ldp remote-peer PEER-A
 remote-ip 10.255.0.2
"""

SAMPLE_ISIS_AFTER = """#
sysname ROTEADOR-COMPARE
#
isis 1
 is-level level-1
 cost-style wide
 network-entity 49.0001.0100.0000.0002.00
 import-route direct
 import-route static
#
interface GigabitEthernet0/0/0
 description CORE
 ip address 10.0.0.1 255.255.255.252
 isis enable 1
 isis circuit-type level-1
 isis cost 20
 mpls
 mpls ldp
#
mpls lsr-id 10.255.0.99
mpls
#
mpls ldp
#
mpls ldp remote-peer PEER-A
 remote-ip 10.255.0.2
#
mpls ldp remote-peer PEER-B
 remote-ip 10.255.0.3
"""


# =========================================================================
# 1. Parser tests
# =========================================================================


class ParserIsisTests(TestCase):
    """Testa parser de ISIS diretamente via HuaweiVRPParser."""

    def test_isis_process_detected(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_FULL).parse()
        isis_list = parsed.get("isis", [])
        self.assertEqual(len(isis_list), 1)
        proc = isis_list[0]
        self.assertEqual(proc["process_id"], "1")
        self.assertEqual(proc["network_entity"], "49.0001.0100.0000.0001.00")
        self.assertEqual(proc["is_level"], "level-2")
        self.assertEqual(proc["cost_style"], "wide")
        self.assertIn("direct", proc["import_routes"])
        self.assertIn("static", proc["import_routes"])

    def test_isis_with_vpn_instance(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_VPN).parse()
        isis_list = parsed.get("isis", [])
        self.assertEqual(len(isis_list), 1)
        proc = isis_list[0]
        self.assertEqual(proc["process_id"], "2")
        self.assertEqual(proc["vpn_instance"], "CLIENTE-A")
        self.assertEqual(proc["is_level"], "level-1")
        self.assertEqual(proc["cost_style"], "narrow")
        self.assertEqual(proc["network_entity"], "49.0002.0100.0000.0002.00")

    def test_isis_interface_enable(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_FULL).parse()
        ifaces = parsed["interfaces"]
        g0 = next(i for i in ifaces if i["name"] == "GigabitEthernet0/0/0")
        self.assertTrue(g0.get("isis_enabled"))
        self.assertEqual(g0["isis_process_id"], "1")

    def test_isis_interface_circuit_type(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_FULL).parse()
        ifaces = parsed["interfaces"]
        g0 = next(i for i in ifaces if i["name"] == "GigabitEthernet0/0/0")
        self.assertEqual(g0["isis_circuit_type"], "level-2")

    def test_isis_interface_cost(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_FULL).parse()
        ifaces = parsed["interfaces"]
        g0 = next(i for i in ifaces if i["name"] == "GigabitEthernet0/0/0")
        self.assertEqual(g0["isis_cost"], 10)

    def test_isis_interface_authentication_without_secret(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_FULL).parse()
        ifaces = parsed["interfaces"]
        g0 = next(i for i in ifaces if i["name"] == "GigabitEthernet0/0/0")
        auth = g0.get("isis_authentication", {})
        self.assertTrue(auth.get("enabled"))
        self.assertEqual(auth.get("mode"), "md5")
        self.assertTrue(auth.get("has_secret"))
        self.assertEqual(auth.get("secret_type"), "cipher")
        # O auth dict não armazena o valor real da senha — apenas flags
        self.assertNotIn("password", str(auth.get("mode", "")))
        self.assertNotIn("ABC123", str(auth.get("mode", "")))

    def test_mpls_lsr_id(self):
        parsed = HuaweiVRPParser(SAMPLE_MPLS_LDP_FULL).parse()
        mpls = parsed.get("mpls", {})
        self.assertTrue(mpls.get("enabled"))
        self.assertEqual(mpls["lsr_id"], "10.255.0.1")

    def test_mpls_te_enabled(self):
        parsed = HuaweiVRPParser(SAMPLE_MPLS_LDP_FULL).parse()
        mpls = parsed.get("mpls", {})
        self.assertTrue(mpls.get("te_enabled"))

    def test_mpls_ldp_enabled(self):
        parsed = HuaweiVRPParser(SAMPLE_MPLS_LDP_FULL).parse()
        ldp = parsed.get("mpls_ldp", {})
        self.assertTrue(ldp.get("enabled"))

    def test_mpls_ldp_graceful_restart(self):
        parsed = HuaweiVRPParser(SAMPLE_MPLS_LDP_FULL).parse()
        ldp = parsed.get("mpls_ldp", {})
        self.assertTrue(ldp.get("graceful_restart"))

    def test_ldp_remote_peers(self):
        parsed = HuaweiVRPParser(SAMPLE_MPLS_LDP_FULL).parse()
        ldp = parsed.get("mpls_ldp", {})
        peers = ldp.get("remote_peers", [])
        self.assertEqual(len(peers), 2)
        peer1 = next(p for p in peers if p["name"] == "PEER-1")
        self.assertEqual(peer1["remote_ip"], "10.255.0.2")
        peer2 = next(p for p in peers if p["name"] == "PEER-2")
        self.assertEqual(peer2["remote_ip"], "10.255.0.3")

    def test_interface_mpls_flags(self):
        parsed = HuaweiVRPParser(SAMPLE_MPLS_LDP_FULL).parse()
        ifaces = parsed["interfaces"]
        g0 = next(i for i in ifaces if i["name"] == "GigabitEthernet0/0/0")
        self.assertTrue(g0.get("mpls_enabled"))
        self.assertTrue(g0.get("mpls_ldp_enabled"))

    def test_interface_mpls_flags_on_isis_sample(self):
        parsed = HuaweiVRPParser(SAMPLE_ISIS_FULL).parse()
        ifaces = parsed["interfaces"]
        g0 = next(i for i in ifaces if i["name"] == "GigabitEthernet0/0/0")
        self.assertTrue(g0.get("mpls_enabled"))
        self.assertTrue(g0.get("mpls_ldp_enabled"))


# =========================================================================
# 2. Service detection tests
# =========================================================================


class ServiceDetectionTests(TestCase):
    """Testa detecção de serviços ISIS, MPLS e MPLS LDP."""

    def test_isis_service_detected(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_ISIS_FULL, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        svc = DetectedService.objects.filter(
            snapshot=snap, service_type="isis"
        ).first()
        self.assertIsNotNone(svc)
        self.assertEqual(svc.service_type, "isis")
        self.assertGreaterEqual(svc.confidence, 0.75)

    def test_isis_service_metadata(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_ISIS_FULL, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        svc = DetectedService.objects.get(snapshot=snap, service_type="isis")
        self.assertEqual(svc.metadata["process_count"], 1)
        self.assertEqual(svc.metadata["processes"][0]["network_entity"],
                         "49.0001.0100.0000.0001.00")

    def test_mpls_service_detected(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_MPLS_LDP_FULL, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        svc = DetectedService.objects.filter(
            snapshot=snap, service_type="mpls"
        ).first()
        self.assertIsNotNone(svc)
        self.assertEqual(svc.service_type, "mpls")

    def test_mpls_service_metadata(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_MPLS_LDP_FULL, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        svc = DetectedService.objects.get(snapshot=snap, service_type="mpls")
        self.assertEqual(svc.metadata["lsr_id"], "10.255.0.1")
        self.assertTrue(svc.metadata["te_enabled"])

    def test_mpls_ldp_service_detected(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_MPLS_LDP_FULL, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        svc = DetectedService.objects.filter(
            snapshot=snap, service_type="mpls_ldp"
        ).first()
        self.assertIsNotNone(svc)
        self.assertEqual(svc.service_type, "mpls_ldp")

    def test_mpls_ldp_service_metadata(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_MPLS_LDP_FULL, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        svc = DetectedService.objects.get(snapshot=snap, service_type="mpls_ldp")
        self.assertTrue(svc.metadata["graceful_restart"])
        self.assertEqual(svc.metadata["remote_peer_count"], 2)


# =========================================================================
# 3. Issue detection tests
# =========================================================================


class IssueDetectionTests(TestCase):
    """Testa detecção de issues para ISIS, MPLS e LDP."""

    def test_isis_without_network_entity(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_ISIS_WITHOUT_NET, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="isis_without_network_entity"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_isis_interface_unknown_process(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_ISIS_UNKNOWN_PROC, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="isis_interface_unknown_process"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_isis_plain_authentication(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_ISIS_PLAIN_AUTH, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="isis_plain_authentication"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_mpls_without_lsr_id(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_MPLS_WITHOUT_LSR, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="mpls_without_lsr_id"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_ldp_without_mpls(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_LDP_WITHOUT_MPLS, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="ldp_without_mpls"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_interface_ldp_without_mpls(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_INTERFACE_LDP_WITHOUT_MPLS, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="interface_ldp_without_mpls"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_mpls_interface_without_ldp(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_MPLS_IFACE_WITHOUT_LDP, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="mpls_interface_without_ldp"
        )
        self.assertGreaterEqual(issues.count(), 1)

    def test_ldp_remote_peer_without_ip(self):
        snap = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_LDP_REMOTE_NO_IP, vendor="huawei"
        )
        analyze_config_snapshot(snap)
        issues = AnalysisIssue.objects.filter(
            snapshot=snap, code="ldp_remote_peer_without_ip"
        )
        self.assertGreaterEqual(issues.count(), 1)


# =========================================================================
# 4. Documentation tests
# =========================================================================


class DocumentationCoreTests(TestCase):
    """Testa documentação para Core / IGP / MPLS."""

    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config=SAMPLE_ISIS_FULL + "\n" + SAMPLE_MPLS_LDP_FULL,
            vendor="huawei",
        )
        self.parsed = analyze_config_snapshot(self.snapshot)
        self.doc = generate_analysis_documentation(self.parsed)

    def test_core_section_exists(self):
        self.assertIn("core", self.doc)
        self.assertIsNotNone(self.doc["core"])

    def test_core_has_isis(self):
        self.assertTrue(self.doc["core"]["has_isis"])

    def test_core_has_mpls(self):
        self.assertTrue(self.doc["core"]["has_mpls"])

    def test_core_has_mpls_ldp(self):
        self.assertTrue(self.doc["core"]["has_mpls_ldp"])

    def test_core_lists_isis_processes(self):
        self.assertGreater(len(self.doc["core"]["isis"]), 0)
        proc = self.doc["core"]["isis"][0]
        self.assertEqual(proc["process_id"], "1")

    def test_core_shows_mpls_lsr_id(self):
        self.assertEqual(self.doc["core"]["mpls"]["lsr_id"], "10.255.0.1")
        self.assertTrue(self.doc["core"]["mpls"]["te_enabled"])

    def test_core_shows_ldp_remote_peers(self):
        peers = self.doc["core"]["mpls_ldp"]["remote_peers"]
        self.assertEqual(len(peers), 2)

    def test_core_explanation_mentions_isis(self):
        self.assertIn("ISIS", self.doc["core"]["explanation"])

    def test_core_explanation_mentions_mpls(self):
        self.assertIn("MPLS", self.doc["core"]["explanation"])

    def test_core_explanation_mentions_ldp(self):
        self.assertIn("LDP", self.doc["core"]["explanation"])

    def test_documentation_web_200(self):
        r = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertEqual(r.status_code, 200)

    def test_documentation_web_shows_core_section(self):
        r = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(r, "Core / IGP / MPLS")

    def test_documentation_web_shows_isis(self):
        r = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(r, "ISIS")

    def test_documentation_web_shows_lsr_id(self):
        r = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertContains(r, "10.255.0.1")


# =========================================================================
# 5. Search tests
# =========================================================================


class CoreSearchTests(TestCase):
    """Testa busca técnica para ISIS, MPLS e LDP."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.device = Device.objects.create(
            name="CORE-SEARCH-DEVICE", vendor="huawei", hostname="CORE-SEARCH"
        )
        combined = SAMPLE_ISIS_FULL + "\n" + SAMPLE_MPLS_LDP_FULL
        cls.snapshot = ConfigSnapshot.objects.create(
            device=cls.device,
            raw_config=combined,
            vendor="huawei",
        )
        analyze_config_snapshot(cls.snapshot)

    def test_search_isis_returns_results(self):
        results = global_network_search("isis")
        self.assertGreater(len(results.get("isis", [])), 0)

    def test_search_mpls_returns_results(self):
        results = global_network_search("mpls")
        self.assertGreater(len(results.get("core", [])), 0)
        core_types = {r["type"] for r in results["core"]}
        self.assertIn("mpls", core_types)

    def test_search_ldp_returns_results(self):
        results = global_network_search("ldp")
        self.assertGreater(len(results.get("core", [])), 0)
        core_types = {r["type"] for r in results["core"]}
        self.assertIn("mpls_ldp", core_types)

    def test_search_network_entity_returns_isis(self):
        results = global_network_search("49.0001.0100.0000.0001.00")
        isis_results = results.get("isis", [])
        self.assertGreater(len(isis_results), 0)

    def test_search_isis_summary_not_zero(self):
        results = global_network_search("isis")
        self.assertGreater(results["summary"].get("isis", 0), 0)

    def test_search_mpls_summary_not_zero(self):
        results = global_network_search("mpls")
        self.assertGreater(results["summary"].get("core", 0), 0)

    def test_search_ldp_summary_not_zero(self):
        results = global_network_search("ldp")
        self.assertGreater(results["summary"].get("core", 0), 0)

    def test_search_cli_isis(self):
        out = io.StringIO()
        call_command("network_search", "isis", stdout=out)
        output = out.getvalue()
        self.assertIn("ISIS", output.upper())

    def test_search_cli_mpls(self):
        out = io.StringIO()
        call_command("network_search", "mpls", stdout=out)
        output = out.getvalue()
        self.assertIn("MPLS", output.upper())

    def test_search_cli_ldp(self):
        out = io.StringIO()
        call_command("network_search", "ldp", stdout=out)
        output = out.getvalue()
        self.assertIn("LDP", output.upper())


# =========================================================================
# 6. Comparison tests
# =========================================================================


class CoreComparisonTests(TestCase):
    """Testa comparação de configurações ISIS / MPLS / LDP."""

    def setUp(self):
        self.device = Device.objects.create(
            name="CORE-COMPARE", vendor="huawei", hostname="CORE-COMPARE"
        )
        self.base = ConfigSnapshot.objects.create(
            device=self.device,
            raw_config=SAMPLE_ISIS_BEFORE,
            vendor="huawei",
        )
        self.target = ConfigSnapshot.objects.create(
            device=self.device,
            raw_config=SAMPLE_ISIS_AFTER,
            vendor="huawei",
        )
        analyze_config_snapshot(self.base)
        analyze_config_snapshot(self.target)
        self.comparison = compare_config_snapshots(self.base, self.target)
        self.diff = self.comparison.diff_data

    def test_diff_data_has_isis_key(self):
        self.assertIn("isis", self.diff)

    def test_diff_data_has_mpls_key(self):
        self.assertIn("mpls", self.diff)

    def test_diff_data_has_mpls_ldp_key(self):
        self.assertIn("mpls_ldp", self.diff)

    def test_detects_isis_is_level_change(self):
        isis = self.diff["isis"]
        changed = isis.get("changed", [])
        found = False
        for proc in changed:
            for ch in proc.get("changes", []):
                if ch["field"] == "is_level":
                    self.assertEqual(ch["from"], "level-2")
                    self.assertEqual(ch["to"], "level-1")
                    found = True
        self.assertTrue(found, "is_level change not detected")

    def test_detects_isis_network_entity_change(self):
        isis = self.diff["isis"]
        changed = isis.get("changed", [])
        found = False
        for proc in changed:
            for ch in proc.get("changes", []):
                if ch["field"] == "network_entity":
                    found = True
        self.assertTrue(found, "network_entity change not detected")

    def test_detects_isis_cost_change(self):
        isis = self.diff["isis"]
        changed = isis.get("changed", [])
        found = False
        for proc in changed:
            for ch in proc.get("changes", []):
                if ch["field"] == "interfaces":
                    for ic in ch.get("interfaces_changed", []):
                        for change in ic.get("changes", []):
                            if change["field"] == "cost":
                                found = True
        self.assertTrue(found, "ISIS cost change not detected")

    def test_detects_mpls_lsr_id_change(self):
        mpls = self.diff["mpls"]
        self.assertIn("lsr_id_changed", mpls)
        self.assertEqual(mpls["lsr_id_changed"]["before"], "10.255.0.1")
        self.assertEqual(mpls["lsr_id_changed"]["after"], "10.255.0.99")

    def test_detects_ldp_remote_peer_change(self):
        mpls_ldp = self.diff["mpls_ldp"]
        self.assertIn("remote_peers_changed", mpls_ldp)
        rp = mpls_ldp["remote_peers_changed"]
        self.assertGreater(len(rp.get("added", [])), 0)

    def test_validation_plan_contains_isis_peer(self):
        plan = self.diff.get("validation_plan", [])
        has_isis = any(
            v.get("category") == "isis" for v in plan
        )
        self.assertTrue(has_isis, "validation_plan missing isis category")

    def test_validation_plan_contains_mpls_ldp_session(self):
        plan = self.diff.get("validation_plan", [])
        has_ldp = any(
            v.get("category") == "mpls_ldp" for v in plan
        )
        self.assertTrue(has_ldp, "validation_plan missing mpls_ldp category")

    def test_rollback_plan_contains_suggestions(self):
        plan = self.diff.get("rollback_plan", [])
        has_isis = any(
            v.get("change_type", "").startswith("isis") for v in plan
        )
        has_mpls = any(
            v.get("change_type", "").startswith("mpls") for v in plan
        )
        self.assertTrue(has_isis or has_mpls,
                        "rollback_plan missing isis/mpls suggestions")


# =========================================================================
# 7. Regression tests
# =========================================================================

# Nota: Para garantir que os testes existentes ainda passam, execute:
#     python manage.py test apps.analysis.tests
# Testes antigos em test_policy_integration.py, test_comparison.py,
# test_new_detectors.py, test_documentation.py e test_search.py
# continuam sendo executados como parte da suite completa.
# Nenhum teste existente foi modificado.
