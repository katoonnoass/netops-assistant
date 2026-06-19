"""Testes de integração para Gerência e Observabilidade (Huawei).

Cobre o fluxo completo:
    parser → analyze_config_snapshot → DetectedService → AnalysisIssue
    → documentação → busca → comparação → web

Usa sample_configs/huawei_management_*.txt.
"""

import json
import os

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import (
    AnalysisIssue,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.search import global_network_search
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.parsers.huawei import HuaweiVRPParser

SAMPLE_DIR = str(settings.BASE_DIR / "sample_configs")


def _load_sample(name: str) -> str:
    path = os.path.join(SAMPLE_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


# =========================================================================
# Parser Tests — SNMP, NTP, Syslog, VTY, SSH, local-user, ACL
# =========================================================================


class ManagementParserSnmpTests(TestCase):
    """Parser Huawei: SNMP."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.parser = HuaweiVRPParser(
            _load_sample("huawei_management_snmp_ntp_syslog.txt")
        )
        cls.result = cls.parser.parse()

    def test_snmp_enabled(self):
        self.assertTrue(self.result["snmp"]["enabled"])

    def test_snmp_versions(self):
        versions = self.result["snmp"]["versions"]
        self.assertIn("v2c", versions)
        self.assertIn("v3", versions)

    def test_snmp_community_read_masked(self):
        """Community read é detectada sem salvar o valor real em campo estruturado."""
        comms = self.result["snmp"]["communities"]
        read_comms = [c for c in comms if c.get("access") == "read"]
        self.assertEqual(len(read_comms), 1)
        for c in read_comms:
            self.assertTrue(c.get("community_masked"))
            self.assertTrue(c.get("has_secret"))
            # O valor real NÃO está em campos estruturados
            self.assertNotIn("KEXAMPLE1", str(c))
            self.assertNotIn("KEXAMPLE2", str(c))

    def test_snmp_community_write_masked(self):
        """Community write é detectada sem salvar o valor real."""
        comms = self.result["snmp"]["communities"]
        write_comms = [c for c in comms if c.get("access") == "write"]
        self.assertEqual(len(write_comms), 1)
        for c in write_comms:
            self.assertTrue(c.get("community_masked"))
            self.assertTrue(c.get("has_secret"))

    def test_snmp_secret_type_detected(self):
        """Secret type é detectado como cipher."""
        for comm in self.result["snmp"]["communities"]:
            self.assertEqual(comm.get("secret_type"), "cipher")

    def test_snmp_trap_host(self):
        """Trap host IP é extraído."""
        traps = self.result["snmp"]["trap_hosts"]
        self.assertGreaterEqual(len(traps), 1)
        self.assertEqual(traps[0]["ip"], "10.0.0.10")

    def test_snmp_users(self):
        """Usuários SNMPv3 detectados."""
        self.assertGreaterEqual(len(self.result["snmp"]["users"]), 1)

    def test_snmp_groups(self):
        """Grupos SNMPv3 detectados."""
        self.assertGreaterEqual(len(self.result["snmp"]["groups"]), 1)

    def test_snmp_acl_refs(self):
        """ACL refs SNMP detectadas."""
        self.assertIn("2001", self.result["snmp"]["acl_refs"])

    def test_snmp_no_real_secret_in_parsed_data(self):
        """Campos estruturados do parsed_data não contêm secrets reais.

        Nota: raw_lines e blocks preservam o texto bruto original para
        evidência — as verificações abaixo focam nos campos estruturados.
        """
        # Communities estruturadas não têm valor real
        for comm in self.result["snmp"]["communities"]:
            self.assertNotIn("KEXAMPLE1", str(comm))
            self.assertNotIn("KEXAMPLE2", str(comm))
        # Local users estruturados não têm senha real
        for user in self.result["local_users"]:
            self.assertNotIn("KEXAMPLE", str(user))
            # Apenas flags
            self.assertIn("has_password", str(user))
            self.assertIn("password_type", str(user))

    def test_snmp_raw_lines(self):
        """Raw lines preservadas."""
        self.assertGreater(len(self.result["snmp"]["raw_lines"]), 0)


class ManagementParserNtpTests(TestCase):
    """Parser Huawei: NTP."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.parser = HuaweiVRPParser(
            _load_sample("huawei_management_snmp_ntp_syslog.txt")
        )
        cls.result = cls.parser.parse()

    def test_ntp_enabled(self):
        self.assertTrue(self.result["ntp"]["enabled"])

    def test_ntp_servers(self):
        servers = self.result["ntp"]["servers"]
        self.assertGreaterEqual(len(servers), 2)
        ips = [s["ip"] for s in servers if s.get("ip")]
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)

    def test_ntp_preference_detected(self):
        """Preference flag é detectada."""
        servers = self.result["ntp"]["servers"]
        pref = [s for s in servers if s.get("preference")]
        self.assertGreaterEqual(len(pref), 1)

    def test_ntp_source_interface(self):
        self.assertEqual(self.result["ntp"]["source_interface"], "LoopBack0")

    def test_ntp_raw_lines(self):
        self.assertGreater(len(self.result["ntp"]["raw_lines"]), 0)


class ManagementParserSyslogTests(TestCase):
    """Parser Huawei: Syslog/info-center."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.parser = HuaweiVRPParser(
            _load_sample("huawei_management_snmp_ntp_syslog.txt")
        )
        cls.result = cls.parser.parse()

    def test_syslog_enabled(self):
        self.assertTrue(self.result["syslog"]["enabled"])

    def test_syslog_log_hosts(self):
        hosts = self.result["syslog"]["log_hosts"]
        self.assertGreaterEqual(len(hosts), 2)
        ips = [h["ip"] for h in hosts if h.get("ip")]
        self.assertIn("10.0.0.20", ips)
        self.assertIn("10.0.0.21", ips)

    def test_syslog_facility(self):
        self.assertIn("local7", self.result["syslog"]["facilities"])

    def test_syslog_raw_lines(self):
        self.assertGreater(len(self.result["syslog"]["raw_lines"]), 0)

    def test_syslog_risky_no_loghost(self):
        """Config de risco: syslog habilitado mas sem loghost."""
        parser = HuaweiVRPParser(
            _load_sample("huawei_management_risky.txt")
        )
        result = parser.parse()
        self.assertTrue(result["syslog"]["enabled"])
        self.assertEqual(len(result["syslog"]["log_hosts"]), 0)


class ManagementParserVtyTests(TestCase):
    """Parser Huawei: VTY, SSH, local-user."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.parser = HuaweiVRPParser(
            _load_sample("huawei_management_snmp_ntp_syslog.txt")
        )
        cls.result = cls.parser.parse()

    def test_vty_detected(self):
        self.assertGreater(len(self.result["vty_lines"]), 0)

    def test_vty_authentication_mode(self):
        vty = self.result["vty_lines"][0]
        self.assertEqual(vty["authentication_mode"], "aaa")

    def test_vty_protocol_inbound(self):
        vty = self.result["vty_lines"][0]
        self.assertEqual(vty["protocol_inbound"], "ssh")

    def test_vty_acl_inbound(self):
        vty = self.result["vty_lines"][0]
        self.assertEqual(vty["acl_inbound"], "2001")

    def test_vty_idle_timeout(self):
        vty = self.result["vty_lines"][0]
        self.assertEqual(vty["idle_timeout"], "10 0")

    def test_ssh_enabled(self):
        self.assertTrue(self.result["ssh"]["enabled"])

    def test_ssh_user_detected(self):
        users = self.result["ssh"]["users"]
        self.assertGreaterEqual(len(users), 1)
        usernames = [u["name"] for u in users]
        self.assertIn("admin", usernames)

    def test_local_user_detected(self):
        users = self.result["local_users"]
        self.assertGreaterEqual(len(users), 2)
        usernames = [u["name"] for u in users]
        self.assertIn("admin", usernames)
        self.assertIn("operador", usernames)

    def test_local_user_privilege_level(self):
        users = self.result["local_users"]
        admin = next(u for u in users if u["name"] == "admin")
        self.assertEqual(admin["privilege_level"], 15)

    def test_local_user_password_flag_only(self):
        """Senha local-user nunca armazenada em campo estruturado — apenas flags.

        Nota: raw text original é preservado nos blocks para evidência.
        """
        for user in self.result["local_users"]:
            self.assertTrue(user.get("has_password"))
            self.assertIsNotNone(user.get("password_type"))
            # Verificar que o valor real não está em campos estruturados
            user_str = str(user)
            self.assertIn("has_password", user_str)
            self.assertNotIn("KEXAMPLE", user_str)

    def test_local_user_service_types(self):
        users = self.result["local_users"]
        admin = next(u for u in users if u["name"] == "admin")
        self.assertIn("ssh", admin["service_types"])
        self.assertIn("terminal", admin["service_types"])

    def test_telnet_in_risky_config(self):
        """Config de risco: Telnet detectado."""
        parser = HuaweiVRPParser(
            _load_sample("huawei_management_risky.txt")
        )
        result = parser.parse()
        vty = result["vty_lines"][0]
        self.assertEqual(vty["protocol_inbound"], "telnet")
        self.assertIsNone(vty["acl_inbound"])


class ManagementParserAclTests(TestCase):
    """Parser Huawei: ACL definitions."""

    def test_acl_parsed_when_present(self):
        """Sample com acl number deve ser parseado."""
        # Criamos um texto com ACL definition
        config = """#
sysname TESTE-ACL
#
acl number 2001
 rule 5 permit source 10.0.0.0 0.0.0.255
 rule 10 deny
#
return
"""
        parser = HuaweiVRPParser(config)
        result = parser.parse()
        self.assertGreaterEqual(len(result["acls"]), 1)
        acl = result["acls"][0]
        self.assertEqual(acl["number"], "2001")
        self.assertGreaterEqual(len(acl["rules"]), 2)
        self.assertEqual(acl["rules"][0]["action"], "permit")

    def test_acl_name_parsed(self):
        """ACL named parsed."""
        config = """#
acl name NOC-MGMT basic
 rule 5 permit source 10.10.10.0 0.0.0.255
#
return
"""
        parser = HuaweiVRPParser(config)
        result = parser.parse()
        acl = result["acls"][0]
        self.assertEqual(acl["name"], "NOC-MGMT")
        self.assertEqual(acl["type"], "basic")

    def test_acl_enrich_snmp_valid(self):
        """ACL ref no SNMP com definição existente → enriched exists=true."""
        config = """#
acl number 2001
 rule 5 permit
#
snmp-agent
snmp-agent acl 2001
#
return
"""
        parser = HuaweiVRPParser(config)
        result = parser.parse()
        enriched = result["snmp"].get("acl_refs_enriched", [])
        self.assertGreater(len(enriched), 0)
        self.assertTrue(enriched[0]["exists"])

    def test_acl_enrich_snmp_missing(self):
        """ACL ref no SNMP sem definição → enriched exists=false."""
        config = """#
snmp-agent
snmp-agent acl 2999
#
return
"""
        parser = HuaweiVRPParser(config)
        result = parser.parse()
        enriched = result["snmp"].get("acl_refs_enriched", [])
        self.assertGreater(len(enriched), 0)
        self.assertFalse(enriched[0]["exists"])

    def test_acl_enrich_vty_valid(self):
        """ACL ref na VTY com definição → acl_inbound_defined=True."""
        config = """#
acl number 2001
 rule 5 permit
#
user-interface vty 0 4
 acl 2001 inbound
#
return
"""
        parser = HuaweiVRPParser(config)
        result = parser.parse()
        vty = result["vty_lines"][0]
        self.assertTrue(vty.get("acl_inbound_defined"))


# =========================================================================
# Service Detection Tests
# =========================================================================


class ManagementServiceDetectionTests(TestCase):
    """DetectedService para serviços de gerência."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_snmp_ntp_syslog.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_service_snmp_exists(self):
        self.assertTrue(
            DetectedService.objects.filter(
                snapshot=self.snapshot, service_type="snmp"
            ).exists()
        )

    def test_service_snmp_confidence(self):
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="snmp"
        )
        self.assertGreaterEqual(svc.confidence, 0.80)
        self.assertIn("SNMP", svc.name)

    def test_service_ntp_exists(self):
        self.assertTrue(
            DetectedService.objects.filter(
                snapshot=self.snapshot, service_type="ntp"
            ).exists()
        )

    def test_service_ntp_confidence(self):
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="ntp"
        )
        self.assertGreaterEqual(svc.confidence, 0.80)
        self.assertIn("NTP", svc.name)

    def test_service_syslog_exists(self):
        self.assertTrue(
            DetectedService.objects.filter(
                snapshot=self.snapshot, service_type="syslog"
            ).exists()
        )

    def test_service_syslog_confidence(self):
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="syslog"
        )
        self.assertGreaterEqual(svc.confidence, 0.80)

    def test_service_management_access_exists(self):
        self.assertTrue(
            DetectedService.objects.filter(
                snapshot=self.snapshot, service_type="management_access"
            ).exists()
        )

    def test_service_local_user_exists(self):
        count = DetectedService.objects.filter(
            snapshot=self.snapshot, service_type="local_user"
        ).count()
        self.assertGreaterEqual(count, 2)

    def test_service_metadata_no_secrets(self):
        """Metadata dos serviços não contém secrets."""
        for svc in DetectedService.objects.filter(snapshot=self.snapshot):
            meta_str = json.dumps(svc.metadata)
            self.assertNotIn("KEXAMPLE", meta_str)
            self.assertNotIn("cipher ", meta_str)


class ManagementServiceRiskyTests(TestCase):
    """Serviços detectados em config de risco."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_risky.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_snmp_service_lower_confidence(self):
        """SNMP sem v3 tem confidence 0.80."""
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="snmp"
        )
        self.assertEqual(svc.confidence, 0.80)

    def test_syslog_low_confidence_no_loghost(self):
        """Syslog sem loghost tem confidence 0.50."""
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="syslog"
        )
        self.assertEqual(svc.confidence, 0.50)

    def test_management_access_no_acl(self):
        """Acesso adm sem ACL tem confidence 0.85 (não 0.90)."""
        svc = DetectedService.objects.get(
            snapshot=self.snapshot, service_type="management_access"
        )
        self.assertEqual(svc.confidence, 0.85)


# =========================================================================
# Issue Detection Tests
# =========================================================================


class ManagementIssueTests(TestCase):
    """Issues de gerência — config de risco deve gerar todas."""

    ISSUE_CODES = [
        "snmp_v2c_enabled",
        "snmp_write_community",
        "snmp_without_acl",
        "ntp_without_authentication",
        "syslog_without_loghost",
        "telnet_enabled",
        "vty_without_acl",
        "local_user_high_privilege",
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_risky.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_all_management_issues_present(self):
        """Todas as 8 issues de gerência aparecem na config de risco."""
        for code in self.ISSUE_CODES:
            with self.subTest(code=code):
                self.assertTrue(
                    AnalysisIssue.objects.filter(
                        snapshot=self.snapshot, code=code
                    ).exists(),
                    f"Issue {code} não encontrada",
                )


class ManagementIssueGerenciadaTests(TestCase):
    """Issues — config gerenciada tem issues específicas."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_snmp_ntp_syslog.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_write_community_issue_appears(self):
        """Write community aparece mesmo em config gerenciada."""
        self.assertTrue(
            AnalysisIssue.objects.filter(
                snapshot=self.snapshot, code="snmp_write_community"
            ).exists()
        )

    def test_vty_without_acl_not_present(self):
        """VTY com ACL → não gera vty_without_acl."""
        self.assertFalse(
            AnalysisIssue.objects.filter(
                snapshot=self.snapshot, code="vty_without_acl"
            ).exists()
        )

    def test_snmp_without_acl_not_present(self):
        """SNMP com ACL → não gera snmp_without_acl."""
        self.assertFalse(
            AnalysisIssue.objects.filter(
                snapshot=self.snapshot, code="snmp_without_acl"
            ).exists()
        )

    def test_telnet_not_present(self):
        """SSH ativo, Telnet não → não gera telnet_enabled."""
        self.assertFalse(
            AnalysisIssue.objects.filter(
                snapshot=self.snapshot, code="telnet_enabled"
            ).exists()
        )


class ManagementIssueAclRefTests(TestCase):
    """Issue management_acl_reference_not_found."""

    def test_acl_ref_missing_creates_issue(self):
        """ACL referenciada mas não definida gera issue."""
        config = """#
snmp-agent
snmp-agent acl 2999
#
user-interface vty 0 4
 acl 2999 inbound
#
return
"""
        snapshot = ConfigSnapshot.objects.create(
            raw_config=config, vendor="huawei"
        )
        analyze_config_snapshot(snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=snapshot, code="management_acl_reference_not_found"
        )
        self.assertGreaterEqual(len(issues), 1)

    def test_acl_ref_exists_no_issue(self):
        """ACL referenciada e definida → não gera issue."""
        config = """#
acl number 2001
 rule 5 permit
#
snmp-agent
snmp-agent acl 2001
#
return
"""
        snapshot = ConfigSnapshot.objects.create(
            raw_config=config, vendor="huawei"
        )
        analyze_config_snapshot(snapshot)
        issues = AnalysisIssue.objects.filter(
            snapshot=snapshot, code="management_acl_reference_not_found"
        )
        self.assertEqual(len(issues), 0)


# =========================================================================
# Documentation Tests
# =========================================================================


class ManagementDocumentationTests(TestCase):
    """Documentação automática inclui seção de gerência."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_snmp_ntp_syslog.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)
        cls.doc = generate_analysis_documentation(cls.parsed)

    def test_doc_has_management_section(self):
        self.assertIn("management", self.doc)

    def test_doc_management_has_snmp(self):
        mgmt = self.doc["management"]
        self.assertIsNotNone(mgmt["snmp"])
        self.assertTrue(mgmt["snmp"]["enabled"])

    def test_doc_management_has_ntp(self):
        mgmt = self.doc["management"]
        self.assertIsNotNone(mgmt["ntp"])
        self.assertTrue(mgmt["ntp"]["enabled"])

    def test_doc_management_has_syslog(self):
        mgmt = self.doc["management"]
        self.assertIsNotNone(mgmt["syslog"])
        self.assertTrue(mgmt["syslog"]["enabled"])

    def test_doc_management_has_access(self):
        mgmt = self.doc["management"]
        self.assertIsNotNone(mgmt["access"])
        self.assertTrue(mgmt["access"]["enabled"])

    def test_doc_management_has_local_users(self):
        mgmt = self.doc["management"]
        self.assertGreater(len(mgmt["local_users"]), 0)

    def test_doc_mentions_snmp_role(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        snmp_roles = [r for r in roles if "SNMP" in r]
        self.assertGreater(len(snmp_roles), 0)

    def test_doc_mentions_ntp_role(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        ntp_roles = [r for r in roles if "NTP" in r]
        self.assertGreater(len(ntp_roles), 0)

    def test_doc_mentions_syslog_role(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        syslog_roles = [r for r in roles if "logs" in r.lower()]
        self.assertGreater(len(syslog_roles), 0)

    def test_doc_mentions_admin_access_role(self):
        roles = [r["role"] for r in self.doc["detected_roles"]]
        access_roles = [r for r in roles if "acesso" in r.lower()]
        self.assertGreater(len(access_roles), 0)

    def test_doc_explanation_no_real_secret(self):
        """Explicações não contêm secrets reais."""
        raw = json.dumps(self.doc)
        self.assertNotIn("KEXAMPLE", raw)


# =========================================================================
# Search Tests
# =========================================================================


class ManagementSearchTests(TestCase):
    """Busca técnica global encontra serviços de gerência."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_snmp_ntp_syslog.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_search_snmp_finds_service(self):
        results = global_network_search("snmp")
        self.assertGreater(len(results["services"]), 0)
        titles = [r["title"] for r in results["services"]]
        self.assertTrue(any("SNMP" in t for t in titles))

    def test_search_trap_host_finds_snmp(self):
        """Trap host IP aparece em resultados de busca."""
        results = global_network_search("10.0.0.10")
        self.assertGreater(len(results["raw_matches"]), 0)

    def test_search_ntp_server_finds_service(self):
        results = global_network_search("10.0.0.1")
        self.assertGreater(len(results["services"]), 0)
        self.assertGreater(len(results["raw_matches"]), 0)

    def test_search_loghost_finds_syslog(self):
        results = global_network_search("10.0.0.20")
        self.assertGreater(len(results["raw_matches"]), 0)

    def test_search_local_user_finds_management(self):
        results = global_network_search("local-user admin")
        self.assertGreater(len(results["raw_matches"]), 0)

    def test_search_vty_finds_matches(self):
        results = global_network_search("vty")
        self.assertGreater(len(results["raw_matches"]), 0)

    def test_search_stelnet_finds_ssh(self):
        results = global_network_search("stelnet")
        self.assertGreater(len(results["raw_matches"]), 0)

    def test_search_issue_code(self):
        results = global_network_search("snmp_write_community")
        self.assertGreater(len(results["issues"]), 0)

    def test_search_no_real_secret_exposed(self):
        """Busca não expõe secrets reais em títulos/descrições de resultados."""
        results = global_network_search("KEXAMPLE1")
        # Pode aparecer em raw_matches (texto bruto preservado) mas não em metadados estruturados
        for section_key in ("services", "issues", "bgp_peers", "interfaces", "circuits"):
            for item in results.get(section_key, []):
                title = item.get("title", "")
                desc = item.get("description", "")
                evidence = " ".join(item.get("evidence", []))
                meta_str = str(item.get("metadata", {}))
                combined = title + desc + meta_str
                self.assertNotIn("KEXAMPLE1", combined,
                                 f"Secret found in {section_key}: {item}")


# =========================================================================
# Comparison Tests
# =========================================================================


class ManagementComparisonTests(TestCase):
    """Comparação before/after de gerência."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.analysis.comparison import compare_config_snapshots

        cls.base_snap = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_change_before.txt"),
            vendor="huawei",
        )
        cls.target_snap = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_change_after.txt"),
            vendor="huawei",
        )
        cls.comparison = compare_config_snapshots(
            cls.base_snap, cls.target_snap
        )
        cls.diff = cls.comparison.diff_data

    def test_services_added(self):
        """Serviços de gerência adicionados."""
        added_types = {s["service_type"] for s in self.diff["services"]["added"]}
        self.assertIn("local_user", added_types)

    def test_services_removed(self):
        """Serviços de gerência removidos/alterados."""
        removed_types = {
            s["service_type"] for s in self.diff["services"]["removed"]
        }

    def test_impact_snmp(self):
        """Impacto SNMP gerado."""
        impact_texts = [i["impact"] for i in self.diff["impacts"]]
        snmp_impacts = [t for t in impact_texts if "SNMP" in t]
        self.assertGreater(len(snmp_impacts), 0)

    def test_impact_ntp(self):
        """Impacto NTP gerado."""
        impact_texts = [i["impact"] for i in self.diff["impacts"]]
        ntp_impacts = [t for t in impact_texts if "NTP" in t]
        self.assertGreater(len(ntp_impacts), 0)

    def test_impact_user(self):
        """Impacto usuário gerado."""
        impact_texts = [i["impact"] for i in self.diff["impacts"]]
        user_impacts = [t for t in impact_texts if "usuário" in t.lower()]
        self.assertGreater(len(user_impacts), 0)

    def test_validation_plan_has_snmp_commands(self):
        """Plano de validação contém comando SNMP."""
        plan_commands = []
        for item in self.diff.get("validation_plan", []):
            plan_commands.extend(item.get("commands", []))
        all_text = " ".join(plan_commands)
        self.assertIn("snmp-agent", all_text)

    def test_validation_plan_has_ntp_commands(self):
        """Plano de validação contém comando NTP."""
        plan_commands = []
        for item in self.diff.get("validation_plan", []):
            plan_commands.extend(item.get("commands", []))
        all_text = " ".join(plan_commands)
        self.assertIn("ntp-service", all_text)

    def test_validation_plan_has_syslog_commands(self):
        """Plano de validação contém comando syslog."""
        plan_commands = []
        for item in self.diff.get("validation_plan", []):
            plan_commands.extend(item.get("commands", []))
        all_text = " ".join(plan_commands)
        self.assertIn("info-center", all_text)

    def test_validation_plan_has_local_user_commands(self):
        """Plano de validação contém comando local-user (novo usuário)."""
        plan_commands = []
        for item in self.diff.get("validation_plan", []):
            plan_commands.extend(item.get("commands", []))
        all_text = " ".join(plan_commands)
        self.assertIn("local-user", all_text)

    def test_issues_resolved_or_new(self):
        """Issues foram resolvidas ou novas apareceram."""
        self.assertGreater(
            self.diff["issues"]["resolved_count"]
            + self.diff["issues"]["new_count"],
            0,
        )


# =========================================================================
# Web Tests
# =========================================================================


class ManagementWebTests(TestCase):
    """Páginas web relacionadas à gerência."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.snapshot = ConfigSnapshot.objects.create(
            raw_config=_load_sample("huawei_management_snmp_ntp_syslog.txt"),
            vendor="huawei",
        )
        cls.parsed = analyze_config_snapshot(cls.snapshot)

    def test_detail_page_shows_services(self):
        """Página de análise mostra serviços de gerência."""
        response = self.client.get(
            reverse("analysis_detail", kwargs={"pk": self.parsed.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Serviços")
        self.assertContains(response, "SNMP")
        self.assertContains(response, "NTP")

    def test_documentation_page_shows_management(self):
        """Página de documentação mostra gerência."""
        response = self.client.get(
            reverse("analysis_documentation", kwargs={"pk": self.parsed.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SNMP")
        self.assertContains(response, "NTP")
        self.assertContains(response, "Syslog")

    def test_service_list_filters_by_snmp(self):
        "/services/?type=snmp filtra SNMP."
        response = self.client.get(
            reverse("service_list"), {"type": "snmp"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SNMP")

    def test_service_list_filters_by_ntp(self):
        "/services/?type=ntp filtra NTP."
        response = self.client.get(
            reverse("service_list"), {"type": "ntp"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "NTP")

    def test_issue_list_filters_by_code(self):
        "/issues/?code=snmp_write_community filtra issue."
        code = "snmp_write_community"
        response = self.client.get(
            reverse("issue_list"), {"code": code}
        )
        self.assertEqual(response.status_code, 200)

    def test_search_page_finds_snmp(self):
        "/search/?q=snmp responde 200 e mostra resultados."
        response = self.client.get(
            reverse("search"), {"q": "snmp"}
        )
        self.assertEqual(response.status_code, 200)
