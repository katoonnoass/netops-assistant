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
from .presentation import (
    _build_mermaid,
    _get_totals,
    get_link_display_data,
    get_topology_filter_options,
    get_vlan_path_display_data,
)
from .services import (
    create_session_from_devices,
    get_session_summary,
    get_vlan_path_summary,
    run_session_analysis,
)
from .topology import discover_links_by_csv_evidence, discover_links_by_lldp


from .troubleshooter import (
    build_vlan_troubleshooting_report,
    export_vlan_report_csv_rows,
    export_vlan_report_text,
)


class VlanTroubleshootSearchView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/troubleshoot_search.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["vlans"] = VlanDefinition.objects.filter(session=self.object).order_by("-device_count", "vlan_id")
        ctx["vlans_with_issues"] = list(
            VlanTrackingIssue.objects.filter(session=self.object)
            .values_list("vlan_definition__vlan_id", flat=True)
            .distinct()[:20]
        )
        return ctx


class VlanTroubleshootDetailView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/troubleshoot_detail.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        vid = self.kwargs.get("vid")
        ctx["report"] = build_vlan_troubleshooting_report(self.object, vid)
        ctx["vlan_id"] = vid
        return ctx


class VlanTroubleshootExportTextView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession

    def get(self, request, *args, **kwargs):
        session = self.get_object()
        vid = kwargs.get("vid")
        text = export_vlan_report_text(session, vid)
        from django.http import HttpResponse
        filename = f"vlan_report_{session.pk}_{vid}.txt"
        response = HttpResponse(text, content_type="text/plain; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class VlanTroubleshootExportCsvView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession

    def get(self, request, *args, **kwargs):
        import csv
        import io
        session = self.get_object()
        vid = kwargs.get("vid")
        rows = export_vlan_report_csv_rows(session, vid)
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        from django.http import HttpResponse
        filename = f"vlan_report_{session.pk}_{vid}.csv"
        response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class TopologySvgView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/topology_svg.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        from .svg_topology import build_svg_topology
        ctx["svg_data"] = build_svg_topology(
            self.object,
            vlan_id=self.request.GET.get("vlan"),
            method=self.request.GET.get("method"),
            confidence=self.request.GET.get("confidence"),
            device=self.request.GET.get("device"),
            status=self.request.GET.get("status"),
        )
        ctx["active_filters"] = {k: v for k, v in self.request.GET.items() if v}
        return ctx


class TopologySvgDownloadView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession

    def get(self, request, *args, **kwargs):
        from django.http import HttpResponse
        session = self.get_object()
        vlan_id = request.GET.get("vlan")
        from .svg_topology import build_svg_topology
        svg_data = build_svg_topology(
            session,
            vlan_id=vlan_id,
            method=request.GET.get("method"),
            confidence=request.GET.get("confidence"),
            device=request.GET.get("device"),
            status=request.GET.get("status"),
        )
        filename = f"vlan_tracking_{session.pk}"
        if vlan_id:
            filename += f"_vlan_{vlan_id}"
        filename += ".svg"
        response = HttpResponse(svg_data["svg"], content_type="image/svg+xml; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


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
        ctx["vlan_data_new"] = get_vlan_path_display_data(self.object, vid)
        ctx["vlan_data"] = get_vlan_path_summary(self.object, vid)
        return ctx


class LinkListView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession
    template_name = "vlan_tracking/link_list.html"
    context_object_name = "session"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        qs = DeviceLink.objects.filter(session=self.object).select_related(
            "device_a", "device_b", "evidence"
        ).order_by("discovery_method", "-confidence")
        filters = {}
        if self.request.GET.get("method"):
            qs = qs.filter(discovery_method=self.request.GET["method"])
            filters["method"] = self.request.GET["method"]
        if self.request.GET.get("confidence"):
            qs = qs.filter(confidence=self.request.GET["confidence"])
            filters["confidence"] = self.request.GET["confidence"]
        ctx["links"] = qs
        ctx["methods"] = DeviceLink.objects.filter(session=self.object).values_list("discovery_method", flat=True).distinct().order_by()
        ctx["active_filters"] = filters
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

    def _get_filters(self):
        return {
            "method": self.request.GET.get("method"),
            "confidence": self.request.GET.get("confidence"),
            "device": self.request.GET.get("device"),
            "vlan": self.request.GET.get("vlan"),
            "status": self.request.GET.get("status"),
        }

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        filters = self._get_filters()
        ctx["active_filters"] = {k: v for k, v in filters.items() if v}
        ctx["filter_options"] = get_topology_filter_options(self.object)
        ctx["link_data"] = get_link_display_data(self.object, filters)
        ctx["totals"] = _get_totals(self.object)
        ctx["mermaid"] = _build_mermaid(self.object, filters.get("vlan"))
        return ctx


class TopologyMermaidView(LoginRequiredMixin, DetailView):
    model = VlanTrackSession

    def get(self, request, *args, **kwargs):
        session = self.get_object()
        vlan_filter = request.GET.get("vlan")
        mermaid_text = _build_mermaid(session, vlan_filter)
        from django.http import HttpResponse
        return HttpResponse(mermaid_text, content_type="text/plain; charset=utf-8")


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
