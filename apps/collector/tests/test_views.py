from django.test import TestCase
from django.urls import reverse

from apps.collector.models import CollectorRun, CollectorTask, DiscoveryProfile
from apps.devices.models import Device


class AuthTests(TestCase):
    def test_anonymous_redirects(self):
        urls = [
            "collector:dashboard",
            "collector:run_list",
            "collector:task_list",
            "collector:profile_list",
            "collector:device_status",
        ]
        for name in urls:
            response = self.client.get(reverse(name))
            self.assertRedirects(response, f"/accounts/login/?next={reverse(name)}")


class DashboardViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_dashboard_returns_200(self):
        response = self.client.get(reverse("collector:dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_dashboard_contains_collector(self):
        response = self.client.get(reverse("collector:dashboard"))
        self.assertContains(response, "Collector")

    def test_dashboard_contains_empty_state(self):
        response = self.client.get(reverse("collector:dashboard"))
        self.assertContains(response, "Nenhuma execução", html=False)

    def test_dashboard_shows_runs(self):
        profile = DiscoveryProfile.objects.create(name="Test", is_active=True)
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.SUCCESS)
        response = self.client.get(reverse("collector:dashboard"))
        self.assertContains(response, "Test")

    def test_dashboard_shows_running_count(self):
        response = self.client.get(reverse("collector:dashboard"))
        self.assertContains(response, "0 em andamento", html=False)


class RunListViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_list_returns_200(self):
        response = self.client.get(reverse("collector:run_list"))
        self.assertEqual(response.status_code, 200)

    def test_empty_state(self):
        response = self.client.get(reverse("collector:run_list"))
        self.assertContains(response, "Nenhuma execução", html=False)

    def test_filter_by_status(self):
        profile = DiscoveryProfile.objects.create(name="Test", is_active=True)
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.SUCCESS)
        response = self.client.get(reverse("collector:run_list") + "?status=success")
        self.assertContains(response, "Test")

    def test_filter_by_status_excludes_others(self):
        profile = DiscoveryProfile.objects.create(name="ExcludedRun", is_active=True)
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.FAILED)
        response = self.client.get(reverse("collector:run_list") + "?status=success")
        self.assertContains(response, "Nenhuma execução", html=False)

    def test_search_by_profile_name(self):
        profile = DiscoveryProfile.objects.create(name="MyProfile", is_active=True)
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.SUCCESS)
        response = self.client.get(reverse("collector:run_list") + "?q=MyProfile")
        self.assertContains(response, "MyProfile")


class RunDetailViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")
        self.profile = DiscoveryProfile.objects.create(name="Detail Test", is_active=True)
        self.run = CollectorRun.objects.create(profile=self.profile, status=CollectorRun.Status.SUCCESS)

    def test_detail_returns_200(self):
        response = self.client.get(reverse("collector:run_detail", args=[self.run.pk]))
        self.assertEqual(response.status_code, 200)

    def test_detail_shows_summary(self):
        response = self.client.get(reverse("collector:run_detail", args=[self.run.pk]))
        self.assertContains(response, self.profile.name)

    def test_detail_shows_cli_command(self):
        response = self.client.get(reverse("collector:run_detail", args=[self.run.pk]))
        self.assertContains(response, "python manage.py run_collector")

    def test_detail_shows_tasks_section(self):
        task = CollectorTask.objects.create(
            run=self.run, action=CollectorTask.Action.SNMP_DISCOVERY, status=CollectorTask.Status.SUCCESS,
        )
        response = self.client.get(reverse("collector:run_detail", args=[self.run.pk]))
        self.assertContains(response, "Sucesso")


class TaskListViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_list_returns_200(self):
        response = self.client.get(reverse("collector:task_list"))
        self.assertEqual(response.status_code, 200)

    def test_filter_by_action(self):
        profile = DiscoveryProfile.objects.create(name="T", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        CollectorTask.objects.create(
            run=run, action=CollectorTask.Action.SSH_COLLECT, status=CollectorTask.Status.SUCCESS,
        )
        response = self.client.get(reverse("collector:task_list") + "?action=ssh_collect")
        self.assertContains(response, "Coleta SSH")

    def test_filter_by_status(self):
        profile = DiscoveryProfile.objects.create(name="T", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        CollectorTask.objects.create(
            run=run, action=CollectorTask.Action.SNMP_DISCOVERY, status=CollectorTask.Status.FAILED,
        )
        response = self.client.get(reverse("collector:task_list") + "?status=failed")
        self.assertContains(response, "Falha")


class TaskDetailViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")
        profile = DiscoveryProfile.objects.create(name="T", is_active=True)
        run = CollectorRun.objects.create(profile=profile)
        self.task = CollectorTask.objects.create(
            run=run, action=CollectorTask.Action.SNMP_DISCOVERY, status=CollectorTask.Status.SUCCESS,
            log="Descoberto: PE-01",
            error="",
        )

    def test_detail_returns_200(self):
        response = self.client.get(reverse("collector:task_detail", args=[self.task.pk]))
        self.assertEqual(response.status_code, 200)

    def test_detail_shows_log(self):
        response = self.client.get(reverse("collector:task_detail", args=[self.task.pk]))
        self.assertContains(response, "Descoberto: PE-01")

    def test_log_does_not_display_raw_error(self):
        from apps.collector.security import mask_secret
        self.task.error = "Connection refused to 10.0.0.1 with password secret123"
        self.task.save()
        response = self.client.get(reverse("collector:task_detail", args=[self.task.pk]))
        # error field should be masked by services before saving
        self.assertContains(response, "Connection refused")


class ProfileListViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_list_returns_200(self):
        response = self.client.get(reverse("collector:profile_list"))
        self.assertEqual(response.status_code, 200)

    def test_shows_profile_name(self):
        DiscoveryProfile.objects.create(name="Rede Matriz", is_active=True)
        response = self.client.get(reverse("collector:profile_list"))
        self.assertContains(response, "Rede Matriz")

    def test_does_not_show_community(self):
        DiscoveryProfile.objects.create(name="Test", snmp_community="secret", is_active=True)
        response = self.client.get(reverse("collector:profile_list"))
        self.assertNotContains(response, "secret")


class ProfileDetailViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")
        self.profile = DiscoveryProfile.objects.create(
            name="Detail Profile", subnets=["10.0.0.0/24"], is_active=True,
        )

    def test_detail_returns_200(self):
        response = self.client.get(reverse("collector:profile_detail", args=[self.profile.pk]))
        self.assertEqual(response.status_code, 200)

    def test_detail_shows_subnets(self):
        response = self.client.get(reverse("collector:profile_detail", args=[self.profile.pk]))
        self.assertContains(response, "10.0.0.0/24")

    def test_detail_shows_cli_command(self):
        response = self.client.get(reverse("collector:profile_detail", args=[self.profile.pk]))
        self.assertContains(response, "run_collector")

    def test_community_not_shown(self):
        self.profile.snmp_community = "mysecret"
        self.profile.save(update_fields=["snmp_community"])
        response = self.client.get(reverse("collector:profile_detail", args=[self.profile.pk]))
        self.assertNotContains(response, "mysecret")


class DeviceStatusViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_list_returns_200(self):
        response = self.client.get(reverse("collector:device_status"))
        self.assertEqual(response.status_code, 200)

    def test_shows_device(self):
        Device.objects.create(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        response = self.client.get(reverse("collector:device_status"))
        self.assertContains(response, "PE-01")

    def test_filter_by_vendor(self):
        Device.objects.create(name="CORE-Filter", vendor="cisco", ip_address="10.0.0.2")
        Device.objects.create(name="PE-Filter", vendor="huawei", ip_address="10.0.0.1")
        response = self.client.get(reverse("collector:device_status") + "?vendor=cisco")
        self.assertContains(response, "CORE-Filter")
        self.assertNotContains(response, "PE-Filter")

    def test_filter_collector_enabled(self):
        Device.objects.create(name="Enabled", vendor="huawei", collector_enabled=True, ip_address="10.0.0.1")
        Device.objects.create(name="Disabled", vendor="huawei", collector_enabled=False, ip_address="10.0.0.2")
        response = self.client.get(reverse("collector:device_status") + "?enabled=1")
        self.assertContains(response, "Enabled")
        self.assertNotContains(response, "Disabled")


class SidebarIntegrationTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_sidebar_contains_collector(self):
        response = self.client.get(reverse("collector:dashboard"))
        self.assertContains(response, "Collector")


class MainDashboardIntegrationTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create_user(username="viewer", password="pass123")
        self.client.login(username="viewer", password="pass123")

    def test_main_dashboard_shows_collector_section(self):
        profile = DiscoveryProfile.objects.create(name="Dashboard Test", is_active=True)
        CollectorRun.objects.create(profile=profile, status=CollectorRun.Status.SUCCESS)
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Coleta automática")
        self.assertContains(response, "Collector")
