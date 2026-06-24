from io import StringIO

from django.core.management import call_command, CommandError
from django.test import TestCase

from apps.collector.models import DiscoveryProfile


class DiscoverNetworkCommandTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="CLI Test Profile",
            subnets=["10.0.0.0/24"],
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
        self.profile = DiscoveryProfile.objects.create(
            name="CLI Collect Profile",
            subnets=["10.0.0.0/24"],
            is_active=True,
        )

    def test_dry_run_with_profile(self):
        out = StringIO()
        call_command("collect_device_configs", profile="CLI Collect Profile", dry_run=True, stdout=out)
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


class RunCollectorCommandTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="CLI Full Profile",
            subnets=["10.0.0.0/24"],
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
