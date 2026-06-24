from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Q
from django.utils import timezone
from django.views.generic import DetailView, ListView, TemplateView

from apps.devices.models import Device

from .models import CollectorRun, CollectorTask, DiscoveryProfile


class CollectorDashboardView(LoginRequiredMixin, TemplateView):
    template_name = "collector/dashboard.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["active_profiles"] = DiscoveryProfile.objects.filter(is_active=True).count()
        ctx["total_runs"] = CollectorRun.objects.count()
        ctx["running_now"] = CollectorRun.objects.filter(status=CollectorRun.Status.RUNNING).count()
        ctx["failed_or_partial"] = CollectorRun.objects.filter(
            status__in=[CollectorRun.Status.FAILED, CollectorRun.Status.PARTIAL]
        ).count()
        ctx["collector_devices"] = Device.objects.filter(collector_enabled=True).count()

        cutoff_24h = timezone.now() - timedelta(hours=24)
        cutoff_7d = timezone.now() - timedelta(days=7)
        ctx["collected_24h"] = Device.objects.filter(last_collected_at__gte=cutoff_24h).count()
        ctx["collected_7d"] = Device.objects.filter(last_collected_at__gte=cutoff_7d).count()

        ctx["latest_runs"] = CollectorRun.objects.select_related("profile").order_by("-started_at")[:10]
        ctx["latest_errors"] = (
            CollectorTask.objects.exclude(error="")
            .select_related("run__profile", "device")
            .order_by("-finished_at")[:10]
        )
        ctx["latest_collected"] = (
            Device.objects.filter(last_collected_at__isnull=False)
            .order_by("-last_collected_at")[:10]
        )

        ctx["task_counts"] = {
            "total": CollectorTask.objects.count(),
            "success": CollectorTask.objects.filter(status=CollectorTask.Status.SUCCESS).count(),
            "failed": CollectorTask.objects.filter(status=CollectorTask.Status.FAILED).count(),
            "skipped": CollectorTask.objects.filter(status=CollectorTask.Status.SKIPPED).count(),
        }
        return ctx


class CollectorRunListView(LoginRequiredMixin, ListView):
    model = CollectorRun
    template_name = "collector/run_list.html"
    context_object_name = "runs"
    paginate_by = 25
    ordering = ["-started_at"]

    def get_queryset(self):
        qs = super().get_queryset().select_related("profile")
        status = self.request.GET.get("status")
        profile_pk = self.request.GET.get("profile")
        date_from = self.request.GET.get("date_from")
        date_to = self.request.GET.get("date_to")
        q = self.request.GET.get("q")
        if status:
            qs = qs.filter(status=status)
        if profile_pk:
            qs = qs.filter(profile__pk=profile_pk)
        if date_from:
            qs = qs.filter(started_at__gte=date_from)
        if date_to:
            qs = qs.filter(started_at__lte=date_to)
        if q:
            qs = qs.filter(profile__name__icontains=q)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["profiles"] = DiscoveryProfile.objects.all()
        ctx["filter_status"] = self.request.GET.get("status", "")
        ctx["filter_profile"] = self.request.GET.get("profile", "")
        ctx["filter_date_from"] = self.request.GET.get("date_from", "")
        ctx["filter_date_to"] = self.request.GET.get("date_to", "")
        ctx["filter_q"] = self.request.GET.get("q", "")
        return ctx


class CollectorRunDetailView(LoginRequiredMixin, DetailView):
    model = CollectorRun
    template_name = "collector/run_detail.html"
    context_object_name = "run"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        run = self.object
        ctx["tasks_success"] = run.tasks.filter(status=CollectorTask.Status.SUCCESS)
        ctx["tasks_failed"] = run.tasks.filter(status=CollectorTask.Status.FAILED)
        ctx["tasks_skipped"] = run.tasks.filter(status=CollectorTask.Status.SKIPPED)
        ctx["tasks_pending"] = run.tasks.filter(
            status__in=[CollectorTask.Status.PENDING, CollectorTask.Status.RUNNING]
        )
        if run.finished_at and run.started_at:
            delta = run.finished_at - run.started_at
            ctx["duration"] = f"{delta.seconds // 60}m {delta.seconds % 60}s"
        else:
            ctx["duration"] = "—"
        return ctx


class CollectorTaskListView(LoginRequiredMixin, ListView):
    model = CollectorTask
    template_name = "collector/task_list.html"
    context_object_name = "tasks"
    paginate_by = 50
    ordering = ["-started_at"]

    def get_queryset(self):
        qs = (
            super()
            .get_queryset()
            .select_related("run__profile", "device")
        )
        action = self.request.GET.get("action")
        status = self.request.GET.get("status")
        profile_pk = self.request.GET.get("profile")
        device_name = self.request.GET.get("device")
        ip = self.request.GET.get("ip")
        if action:
            qs = qs.filter(action=action)
        if status:
            qs = qs.filter(status=status)
        if profile_pk:
            qs = qs.filter(run__profile__pk=profile_pk)
        if device_name:
            qs = qs.filter(device__name__icontains=device_name)
        if ip:
            qs = qs.filter(ip_address__icontains=ip)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["profiles"] = DiscoveryProfile.objects.all()
        ctx["filter_action"] = self.request.GET.get("action", "")
        ctx["filter_status"] = self.request.GET.get("status", "")
        ctx["filter_profile"] = self.request.GET.get("profile", "")
        ctx["filter_device"] = self.request.GET.get("device", "")
        ctx["filter_ip"] = self.request.GET.get("ip", "")
        return ctx


class CollectorTaskDetailView(LoginRequiredMixin, DetailView):
    model = CollectorTask
    template_name = "collector/task_detail.html"
    context_object_name = "task"


class DiscoveryProfileListView(LoginRequiredMixin, ListView):
    model = DiscoveryProfile
    template_name = "collector/profile_list.html"
    context_object_name = "profiles"
    ordering = ["name"]


class DiscoveryProfileDetailView(LoginRequiredMixin, DetailView):
    model = DiscoveryProfile
    template_name = "collector/profile_detail.html"
    context_object_name = "profile"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["recent_runs"] = (
            CollectorRun.objects.filter(profile=self.object)
            .select_related("profile")
            .order_by("-started_at")[:5]
        )
        return ctx


class CollectorDeviceStatusView(LoginRequiredMixin, ListView):
    model = Device
    template_name = "collector/device_status.html"
    context_object_name = "devices"
    paginate_by = 50
    ordering = ["name"]

    def get_queryset(self):
        qs = super().get_queryset()
        vendor = self.request.GET.get("vendor")
        enabled = self.request.GET.get("enabled")
        has_collected = self.request.GET.get("collected")
        has_error = self.request.GET.get("error")
        no_collection = self.request.GET.get("no_collection")
        q = self.request.GET.get("q")

        if vendor:
            qs = qs.filter(vendor=vendor)
        if enabled == "1":
            qs = qs.filter(collector_enabled=True)
        elif enabled == "0":
            qs = qs.filter(collector_enabled=False)
        if has_collected:
            qs = qs.filter(last_collected_at__isnull=False)
        if no_collection:
            qs = qs.filter(last_collected_at__isnull=True)
        if q:
            qs = qs.filter(name__icontains=q)

        qs = qs.prefetch_related("snapshots")
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["vendors"] = Device.objects.values_list("vendor", flat=True).distinct().order_by("vendor")
        ctx["filter_vendor"] = self.request.GET.get("vendor", "")
        ctx["filter_enabled"] = self.request.GET.get("enabled", "")
        ctx["filter_collected"] = self.request.GET.get("collected", "")
        ctx["filter_no_collection"] = self.request.GET.get("no_collection", "")
        ctx["filter_q"] = self.request.GET.get("q", "")

        for d in ctx["devices"]:
            last_task = (
                CollectorTask.objects.filter(device=d)
                .exclude(status=CollectorTask.Status.SUCCESS)
                .order_by("-finished_at")
                .first()
            )
            d.last_error = last_task.error[:200] if last_task and last_task.error else None
        return ctx
