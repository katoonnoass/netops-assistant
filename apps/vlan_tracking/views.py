from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, ListView, View
from django.views.generic.edit import CreateView, DeleteView, FormView

from apps.config_archive.models import ConfigSnapshot
from apps.core.permissions import operator_required, viewer_required
from apps.devices.models import Device

from .lldp_parser import parse_adjacency_csv, parse_lldp_neighbors
from .models import (
    DeviceLink,
    TopologyEvidence,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackSession,
    VlanTrackingIssue,
)
from .services import (
    create_session_from_devices,
    get_session_summary,
    get_vlan_path_summary,
    run_session_analysis,
)
from .topology import discover_links_by_csv_evidence, discover_links_by_lldp


class SessionListView(LoginRequiredMixin, ListView):
    model = VlanTrackSession
    template_name = "vlan_tracking/session_list.html"
    context_object_name = "sessions"

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
        ctx["evidences"] = TopologyEvidence.objects.filter(session=self.object)
        ctx["links_by_method"] = {
            m[0]: DeviceLink.objects.filter(session=self.object, discovery_method=m[0]).count()
            for m in DeviceLink.DISCOVERY_METHODS
        }
        ctx["low_conf_links"] = DeviceLink.objects.filter(session=self.object, confidence="low").count()
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
        vlan_data = get_vlan_path_summary(self.object, vid)
        if vlan_data:
            for p in vlan_data["paths"]:
                p.low_confidence = getattr(p.via_link, "confidence", "") == "low" if p.via_link else False
                p.link_method = getattr(p.via_link, "discovery_method", "") if p.via_link else ""
        ctx["vlan_data"] = vlan_data
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


class TopologyView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/topology.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        links = DeviceLink.objects.filter(session=self.object).select_related(
            "device_a", "device_b"
        ).order_by("discovery_method", "confidence")
        ctx["links"] = links
        devices = {}
        for l in links:
            devices[l.device_a_id] = l.device_a
            devices[l.device_b_id] = l.device_b
        ctx["device_list"] = list(devices.values())

        # Build mermaid
        mermaid_lines = ["graph LR"]
        for l in links:
            vlan_ids = list(VlanPath.objects.filter(
                session=self.object, via_link=l
            ).values_list("vlan_definition__vlan_id", flat=True).distinct()[:10])
            label = f"{l.interface_a} ↔ {l.interface_b}"
            if vlan_ids:
                label += f"<br/>VLANs: {','.join(str(v) for v in vlan_ids[:5])}"
            safe_a = l.device_a.name.replace("-", "_").replace(" ", "_")
            safe_b = l.device_b.name.replace("-", "_").replace(" ", "_")
            mermaid_lines.append(
                f'  {safe_a}["{l.device_a.name}"] -- "{label}<br/>{l.get_discovery_method_display()}/{l.get_confidence_display()}" --> {safe_b}["{l.device_b.name}"]'
            )
        ctx["mermaid"] = "\n".join(mermaid_lines)
        return ctx


class TopologyMermaidView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession

    def get(self, request, *args, **kwargs):
        session = self.get_object()
        links = DeviceLink.objects.filter(session=session).select_related("device_a", "device_b")
        mermaid_lines = ["graph LR"]
        for l in links:
            vlan_ids = list(VlanPath.objects.filter(
                session=session, via_link=l
            ).values_list("vlan_definition__vlan_id", flat=True).distinct()[:10])
            label = f"{l.interface_a} ↔ {l.interface_b}"
            if vlan_ids:
                label += f"<br/>VLANs: {','.join(str(v) for v in vlan_ids[:5])}"
            safe_a = l.device_a.name.replace("-", "_").replace(" ", "_")
            safe_b = l.device_b.name.replace("-", "_").replace(" ", "_")
            mermaid_lines.append(
                f'  {safe_a}["{l.device_a.name}"] -- "{label}<br/>{l.get_discovery_method_display()}/{l.get_confidence_display()}" --> {safe_b}["{l.device_b.name}"]'
            )
        from django.http import HttpResponse
        return HttpResponse("\n".join(mermaid_lines), content_type="text/plain; charset=utf-8")


class EvidenceListView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/evidence_list.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["evidences"] = TopologyEvidence.objects.filter(session=self.object).order_by("-created_at")
        return ctx


class EvidenceCreateView(LoginRequiredMixin, CreateView):
    model = TopologyEvidence
    template_name = "vlan_tracking/evidence_form.html"
    fields = ["device", "evidence_type", "raw_text"]

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
        form.instance.created_by = self.request.user if self.request.user.is_authenticated else None
        self.object = form.save()

        # Parse and process
        raw = form.instance.raw_text
        etype = form.instance.evidence_type
        if etype == "lldp":
            parsed = parse_lldp_neighbors(raw)
            if parsed:
                form.instance.parsed_data = {"count": len(parsed), "neighbors": parsed[:100]}
                form.instance.save(update_fields=["parsed_data"])
            discover_links_by_lldp(session)
        elif etype == "csv":
            parsed = parse_adjacency_csv(raw)
            if parsed:
                form.instance.parsed_data = {"count": len(parsed), "rows": parsed[:100]}
                form.instance.save(update_fields=["parsed_data"])
            discover_links_by_csv_evidence(session)

        return redirect("vlan_tracking:evidence_list", pk=session.pk)

    def get_success_url(self):
        return reverse_lazy("vlan_tracking:evidence_list", kwargs={"pk": self.kwargs["pk"]})


class EvidenceDeleteView(LoginRequiredMixin, DeleteView):
    model = TopologyEvidence

    def get_object(self, queryset=None):
        return get_object_or_404(TopologyEvidence, pk=self.kwargs["evid"], session_id=self.kwargs["pk"])

    def get_success_url(self):
        return reverse_lazy("vlan_tracking:evidence_list", kwargs={"pk": self.kwargs["pk"]})

    def post(self, request, *args, **kwargs):
        return self.delete(request, *args, **kwargs)
