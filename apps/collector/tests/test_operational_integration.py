"""Testes de integração operacional do Collector.

Cobre: dashboard principal, busca global, network_search CLI,
detalhe de dispositivo, README, docs e segurança.
"""

from pathlib import Path

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.collector.models import CollectorRun, CollectorTask, DiscoveryProfile
from apps.devices.models import Device

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent


class MainDashboardIntegrationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_dashboard_shows_collector_section(self):
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Coleta automática")
        self.assertContains(response, "COLETOR")

    def test_dashboard_shows_link_to_collector(self):
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, reverse("collector:dashboard"))

    def test_dashboard_shows_empty_state_when_no_runs(self):
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Nenhuma execução")

    def test_dashboard_shows_run_data_when_exists(self):
        profile = DiscoveryProfile.objects.create(name="Dashboard Test", is_active=True)
        CollectorRun.objects.create(
            profile=profile,
            status=CollectorRun.Status.SUCCESS,
            collected_count=5,
            failed_count=1,
        )
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "5")
        self.assertContains(response, "1")


class SearchIntegrationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")
        # Create data so search finds results
        self.profile = DiscoveryProfile.objects.create(name="Rede Matriz", is_active=True)
        self.run = CollectorRun.objects.create(
            profile=self.profile,
            status=CollectorRun.Status.SUCCESS,
            collected_count=5,
        )
        self.device = Device.objects.create(name="PE-SEARCH", ip_address="10.0.0.1")
        CollectorTask.objects.create(
            run=self.run,
            device=self.device,
            ip_address="10.0.0.1",
            action=CollectorTask.Action.SNMP_DISCOVERY,
            status=CollectorTask.Status.SUCCESS,
        )

    def test_search_finds_profile_by_name(self):
        response = self.client.get(reverse("search") + "?q=Rede%20Matriz")
        self.assertContains(response, "Rede Matriz")

    def test_search_shows_collector_section(self):
        response = self.client.get(reverse("search") + "?q=collector")
        self.assertContains(response, "Collector / Coleta Automática")

    def test_search_finds_run_by_status(self):
        profile = DiscoveryProfile.objects.create(name="Test Profile", is_active=True)
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.FAILED)
        response = self.client.get(reverse("search") + "?q=failed")
        self.assertContains(response, "Falha")

    def test_search_finds_task_by_ip(self):
        profile = DiscoveryProfile.objects.create(name="T", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        device = Device.objects.create(name="PE-01", ip_address="10.0.0.1")
        CollectorTask.objects.create(
            run=run,
            device=device,
            ip_address="10.0.0.1",
            action=CollectorTask.Action.SNMP_DISCOVERY,
            status=CollectorTask.Status.SUCCESS,
        )
        response = self.client.get(reverse("search") + "?q=10.0.0.1")
        self.assertContains(response, "PE-01")

    def test_search_finds_task_by_error(self):
        profile = DiscoveryProfile.objects.create(name="T", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        device = Device.objects.create(name="PE-02", ip_address="10.0.0.2")
        CollectorTask.objects.create(
            run=run,
            device=device,
            ip_address="10.0.0.2",
            action=CollectorTask.Action.SSH_COLLECT,
            status=CollectorTask.Status.FAILED,
            error="Connection refused",
        )
        response = self.client.get(reverse("search") + "?q=Connection%20refused")
        self.assertContains(response, "Connection refused")

    def test_search_finds_collected_device(self):
        device = Device.objects.create(name="COLECTOR-DEVICE", ip_address="10.0.0.3", vendor="huawei")
        profile = DiscoveryProfile.objects.create(name="P", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        CollectorTask.objects.create(
            run=run,
            device=device,
            ip_address="10.0.0.3",
            action=CollectorTask.Action.SNMP_DISCOVERY,
            status=CollectorTask.Status.SUCCESS,
        )
        response = self.client.get(reverse("search") + "?q=COLECTOR-DEVICE")
        self.assertContains(response, "COLECTOR-DEVICE")


class NetworkSearchCLIIntegrationTests(TestCase):
    def setUp(self):
        from io import StringIO
        from django.core.management import call_command
        self.call_command = call_command
        self.StringIO = StringIO
        # Create data so searches find results
        self.profile = DiscoveryProfile.objects.create(
            name="Rede Matriz",
            subnets=["10.0.0.0/24"],
            is_active=True,
        )
        self.run = CollectorRun.objects.create(
            profile=self.profile,
            status=CollectorRun.Status.SUCCESS,
            collected_count=5,
            failed_count=0,
        )
        self.device = Device.objects.create(name="PE-CLI", ip_address="10.0.0.1")
        CollectorTask.objects.create(
            run=self.run,
            device=self.device,
            ip_address="10.0.0.1",
            action=CollectorTask.Action.SNMP_DISCOVERY,
            status=CollectorTask.Status.SUCCESS,
        )
        CollectorTask.objects.create(
            run=self.run,
            device=self.device,
            ip_address="10.0.0.1",
            action=CollectorTask.Action.SSH_COLLECT,
            status=CollectorTask.Status.SUCCESS,
        )

    def test_cli_shows_collector_section(self):
        out = self.StringIO()
        self.call_command("network_search", "collector", stdout=out)
        output = out.getvalue()
        self.assertIn("--- Collector", output)
        self.assertIn("Profile: Rede Matriz", output)

    def test_cli_finds_snmp_tasks(self):
        out = self.StringIO()
        self.call_command("network_search", "snmp", stdout=out)
        output = out.getvalue()
        self.assertIn("--- Collector", output)
        self.assertIn("Descoberta SNMP", output)

    def test_cli_finds_ssh_tasks(self):
        out = self.StringIO()
        self.call_command("network_search", "ssh", stdout=out)
        output = out.getvalue()
        self.assertIn("--- Collector", output)
        self.assertIn("Coleta SSH", output)


class DeviceDetailIntegrationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")
        self.device = Device.objects.create(
            name="PE-INTEGRATION",
            vendor="huawei",
            ip_address="10.0.0.10",
            collector_enabled=True,
            ssh_port=2222,
            snmp_port=1161,
        )

    def test_device_detail_shows_collector_section(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "Collector / Coleta Automática")

    def test_device_detail_shows_collector_enabled(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "Ativado")

    def test_device_detail_shows_ssh_port(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "2222")

    def test_device_detail_shows_snmp_port(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "1161")

    def test_device_detail_shows_last_discovered_at(self):
        from django.utils import timezone
        self.device.last_discovered_at = timezone.now()
        self.device.save(update_fields=["last_discovered_at"])
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "Última descoberta")

    def test_device_detail_shows_last_collected_at(self):
        from django.utils import timezone
        self.device.last_collected_at = timezone.now()
        self.device.save(update_fields=["last_collected_at"])
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "Última coleta")

    def test_device_detail_shows_recent_tasks(self):
        profile = DiscoveryProfile.objects.create(name="P", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        CollectorTask.objects.create(
            run=run,
            device=self.device,
            action=CollectorTask.Action.SNMP_DISCOVERY,
            status=CollectorTask.Status.SUCCESS,
        )
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "Descoberta SNMP")

    def test_device_detail_shows_last_error(self):
        profile = DiscoveryProfile.objects.create(name="P", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        CollectorTask.objects.create(
            run=run,
            device=self.device,
            action=CollectorTask.Action.SSH_COLLECT,
            status=CollectorTask.Status.FAILED,
            error="SSH connection timeout",
        )
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "SSH connection timeout")

    def test_device_detail_link_to_device_status(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, reverse("collector:device_status"))

    def test_device_detail_link_to_last_run(self):
        profile = DiscoveryProfile.objects.create(name="P", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        CollectorTask.objects.create(
            run=run,
            device=self.device,
            action=CollectorTask.Action.SNMP_DISCOVERY,
            status=CollectorTask.Status.SUCCESS,
        )
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, reverse("collector:run_detail", args=[run.pk]))


class SecurityIntegrationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_search_does_not_expose_password(self):
        profile = DiscoveryProfile.objects.create(
            name="SecProfile",
            snmp_community="secret_community",
            is_active=True,
        )
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.SUCCESS)
        response = self.client.get(reverse("search") + "?q=SecProfile")
        self.assertContains(response, "SecProfile")
        self.assertNotContains(response, "secret_community")

    def test_dashboard_does_not_expose_snmp_community(self):
        DiscoveryProfile.objects.create(
            name="SecTest", snmp_community="secret_community", is_active=True,
        )
        CollectorRun.objects.create(
            profile=DiscoveryProfile.objects.first(), status=CollectorRun.Status.SUCCESS,
        )
        response = self.client.get(reverse("dashboard"))
        self.assertNotContains(response, "secret_community")

    def test_device_detail_does_not_expose_encrypted_password(self):
        from apps.collector.models import NetworkCredential
        NetworkCredential.objects.create(
            name="HiddenCred", encrypted_password="should_not_appear",
        )
        device = Device.objects.create(name="SecDevice", vendor="huawei")
        response = self.client.get(reverse("device_detail", args=[device.pk]))
        self.assertNotContains(response, "should_not_appear")


class ReadmeAndDocsIntegrationTests(TestCase):
    def test_readme_contains_collector_section(self):
        readme = BASE_DIR / "README.md"
        self.assertTrue(readme.exists())
        content = readme.read_text(encoding="utf-8")
        self.assertIn("Collector / Coleta Automática", content)

    def test_readme_contains_run_collector_command(self):
        content = (BASE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("run_collector", content)

    def test_readme_contains_dry_run(self):
        content = (BASE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("--dry-run", content)

    def test_readme_contains_lab_validation_link(self):
        content = (BASE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("lab_validation.md", content)

    def test_lab_validation_guide_exists(self):
        guide = BASE_DIR / "docs" / "collector" / "lab_validation.md"
        self.assertTrue(guide.exists())

    def test_lab_validation_contains_dry_run(self):
        content = (BASE_DIR / "docs" / "collector" / "lab_validation.md").read_text(encoding="utf-8")
        self.assertIn("--dry-run", content)

    def test_lab_validation_contains_security_warning(self):
        content = (BASE_DIR / "docs" / "collector" / "lab_validation.md").read_text(encoding="utf-8")
        self.assertIn("senhas", content.lower()) or self.assertIn("secrets", content.lower())


class RegressionIntegrationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_collector_dashboard_still_works(self):
        response = self.client.get(reverse("collector:dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_collector_run_list_still_works(self):
        response = self.client.get(reverse("collector:run_list"))
        self.assertEqual(response.status_code, 200)

    def test_collector_task_list_still_works(self):
        response = self.client.get(reverse("collector:task_list"))
        self.assertEqual(response.status_code, 200)

    def test_collector_profile_list_still_works(self):
        response = self.client.get(reverse("collector:profile_list"))
        self.assertEqual(response.status_code, 200)

    def test_collector_device_status_still_works(self):
        response = self.client.get(reverse("collector:device_status"))
        self.assertEqual(response.status_code, 200)

    def test_device_detail_returns_200(self):
        device = Device.objects.create(name="Regression-Device", vendor="huawei")
        response = self.client.get(reverse("device_detail", args=[device.pk]))
        self.assertEqual(response.status_code, 200)
