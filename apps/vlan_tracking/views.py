from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, ListView
from django.views.generic.edit import CreateView, FormView

from apps.config_archive.models import ConfigSnapshot
from apps.core.permissions import operator_required, viewer_required
from apps.devices.models import Device

from .models import DeviceLink, VlanDefinition, VlanEndpoint, VlanInterface, VlanPath, VlanTrackDevice, VlanTrackSession, VlanTrackingIssue
from .services import create_session_from_devices, get_session_summary, get_vlan_path_summary, run_session_analysis


class SessionListView(LoginRequiredMixin, ListView):
    model = VlanTrackSession
    template_name = "vlan_tracking/session_list.html"
    context_object_name = "sessions"
    permission_required = "vlan_tracking.view_vlantracksession"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        for s in ctx["sessions"]:
            s.summary = get_session_summary(s)
        return ctx


class SessionCreateView(LoginRequiredMixin, CreateView):
    model = VlanTrackSession
    template_name = "vlan_tracking/session_form.html"
    fields = ["name", "description"]

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["devices"] = Device.objects.all().order_by("name")
        ctx["snapshots"] = ConfigSnapshot.objects.select_related("device").all().order_by("-created_at")
        return ctx

    def form_valid(self, form):
        form.instance.created_by = self.request.user if self.request.user.is_authenticated else None
        self.object = form.save()
        selected = self.request.POST.getlist("track_devices")
        for order, item in enumerate(selected):
            parts = item.split(":")
            if len(parts) == 2:
                device_id, snapshot_id = parts
                device = Device.objects.filter(id=device_id).first()
                snapshot = ConfigSnapshot.objects.filter(id=snapshot_id).first()
                if device and snapshot:
                    from apps.analysis.models import ParsedConfig
                    pc = ParsedConfig.objects.filter(snapshot=snapshot).first()
                    VlanTrackDevice.objects.create(
                        session=self.object,
                        device=device,
                        snapshot=snapshot,
                        parsed_config=pc,
                        order=order,
                    )
        run_session_analysis(self.object)
        return redirect("vlan_tracking:session_detail", pk=self.object.pk)


class SessionDetailView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/session_detail.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["summary"] = get_session_summary(self.object)
        ctx["devices"] = self.object.track_devices.select_related("device").all()
        ctx["vlans"] = VlanDefinition.objects.filter(session=self.object).order_by("vlan_id")[:50]
        ctx["issues"] = VlanTrackingIssue.objects.filter(session=self.object)[:20]
        ctx["links"] = DeviceLink.objects.filter(session=self.object).select_related("device_a", "device_b")
        ctx["endpoints"] = VlanEndpoint.objects.filter(session=self.object).select_related("device", "vlan_definition")[:20]
        return ctx


class RunCorrelationView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession

    def post(self, request, *args, **kwargs):
        session = self.get_object()
        run_session_analysis(session)
        return redirect("vlan_tracking:session_detail", pk=session.pk)


class VlanListView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/vlan_list.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["vlans"] = VlanDefinition.objects.filter(session=self.object).order_by("vlan_id")
        ctx["interfaces"] = VlanInterface.objects.filter(session=self.object).select_related("device")
        return ctx


class VlanDetailView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/vlan_detail.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        vid = self.kwargs.get("vid")
        ctx["vlan_data"] = get_vlan_path_summary(self.object, vid)
        return ctx


class LinkListView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/link_list.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["links"] = DeviceLink.objects.filter(session=self.object).select_related(
            "device_a", "device_b"
        ).order_by("discovery_method", "confidence")
        return ctx


class LinkCreateView(LoginRequiredMixin, CreateView):
    model = DeviceLink
    template_name = "vlan_tracking/link_form.html"
    fields = ["device_a", "interface_a", "device_b", "interface_b", "notes"]

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        session = get_object_or_404(VlanTrackSession, pk=self.kwargs["pk"])
        ctx["session"] = session
        ctx["devices"] = Device.objects.filter(
            id__in=VlanTrackDevice.objects.filter(session=session).values("device_id")
        )
        return ctx

    def form_valid(self, form):
        session = get_object_or_404(VlanTrackSession, pk=self.kwargs["pk"])
        form.instance.session = session
        form.instance.discovery_method = "manual"
        form.instance.confidence = "high"
        form.instance.status = "confirmed"
        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy("vlan_tracking:link_list", kwargs={"pk": self.kwargs["pk"]})
