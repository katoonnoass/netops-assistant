from io import StringIO
from unittest.mock import patch

from django.core.management import call_command, CommandError
from django.test import TestCase

from apps.collector.models import CollectorRun, DiscoveryProfile
from apps.devices.models import Device


class DiscoverNetworkCommandTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="CLI Test Profile",
            subnets=["10.0.0.0/24"],
            snmp_community="public",
            is_active=True,
        )

    def test_dry_run_executes_without_error(self):
        out = StringIO()
        call_command("discover_network", profile="CLI Test Profile", dry_run=True, stdout=out)
        output = out.getvalue()
        self.assertIn("DRY-RUN", output)

    def test_missing_profile_shows_error(self):
        out = StringIO()
        with self.assertRaises(CommandError):
            call_command("discover_network", profile="NaoExiste", dry_run=True, stdout=out)

    def test_output_does_not_contain_secrets(self):
        out = StringIO()
        call_command("discover_network", profile="CLI Test Profile", dry_run=True, stdout=out)
        output = out.getvalue()
        self.assertNotIn("public", output)


class CollectDeviceConfigsCommandTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(
            name="PE-01", vendor="huawei", ip_address="10.0.0.1", collector_enabled=True,
        )
        self.profile = DiscoveryProfile.objects.create(
            name="CLI Collect Profile",
            snmp_community="public",
            is_active=True,
        )

    def test_dry_run_with_profile(self):
        out = StringIO()
        call_command("collect_device_configs", profile="CLI Collect Profile", dry_run=True, stdout=out)
        output = out.getvalue()
        self.assertIn("DRY-RUN", output)

    def test_dry_run_with_device(self):
        out = StringIO()
        call_command("collect_device_configs", device="PE-01", dry_run=True, stdout=out)
        output = out.getvalue()
        self.assertIn("DRY-RUN", output)

    def test_missing_profile_shows_error(self):
        out = StringIO()
        with self.assertRaises(CommandError):
            call_command("collect_device_configs", profile="NaoExiste", dry_run=True, stdout=out)

    def test_requires_profile_or_device(self):
        out = StringIO()
        with self.assertRaises(CommandError):
            call_command("collect_device_configs", dry_run=True, stdout=out)

    @patch("apps.collector.management.commands.collect_device_configs.run_collection")
    def test_real_collect_calls_service(self, mock_collect):
        mock_collect.return_value = CollectorRun(pk=99, collected_count=1, analyzed_count=0, failed_count=0)
        mock_collect.return_value.status = "success"
        mock_collect.return_value.summary = "Coletados: 1"

        out = StringIO()
        call_command("collect_device_configs", profile="CLI Collect Profile", stdout=out)
        output = out.getvalue()
        self.assertIn("Run #99", output)
        mock_collect.assert_called_once()


class RunCollectorCommandTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="CLI Full Profile",
            subnets=["10.0.0.0/24"],
            snmp_community="public",
            is_active=True,
        )

    def test_dry_run_executes_without_error(self):
        out = StringIO()
        call_command("run_collector", profile="CLI Full Profile", dry_run=True, stdout=out)
        output = out.getvalue()
        self.assertIn("DRY-RUN", output)

    def test_missing_profile_shows_error(self):
        out = StringIO()
        with self.assertRaises(CommandError):
            call_command("run_collector", profile="NaoExiste", dry_run=True, stdout=out)

    def test_dry_run_with_analyze(self):
        out = StringIO()
        call_command("run_collector", profile="CLI Full Profile", dry_run=True, analyze=True, stdout=out)
        output = out.getvalue()
        self.assertIn("DRY-RUN", output)
        self.assertIn("Análise", output)
