from django.contrib import admin

from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)


@admin.register(ParsedConfig)
class ParsedConfigAdmin(admin.ModelAdmin):
    list_display = [
        "__str__",
        "snapshot",
        "vendor_info",
        "interface_count",
        "parser_version",
        "created_at",
    ]
    list_filter = ["parser_version", "created_at"]
    search_fields = ["snapshot__raw_config"]
    readonly_fields = ["created_at"]

    def vendor_info(self, obj):
        return obj.snapshot.vendor or "-"

    vendor_info.short_description = "fabricante"
    vendor_info.admin_order_field = "snapshot__vendor"

    def interface_count(self, obj):
        interfaces = obj.parsed_data.get("interfaces", [])
        return len(interfaces)

    interface_count.short_description = "interfaces"


@admin.register(DetectedCircuit)
class DetectedCircuitAdmin(admin.ModelAdmin):
    list_display = [
        "__str__",
        "circuit_type",
        "circuit_interface",
        "circuit_transit",
        "snapshot",
        "created_at",
    ]
    list_filter = ["circuit_type", "created_at"]
    search_fields = ["snapshot__raw_config", "details"]

    def circuit_interface(self, obj):
        return obj.details.get("interface", "-")

    circuit_interface.short_description = "interface"

    def circuit_transit(self, obj):
        return obj.details.get("transit_network", "-")

    circuit_transit.short_description = "rede de trânsito"


@admin.register(ConfigComparison)
class ConfigComparisonAdmin(admin.ModelAdmin):
    list_display = ["__str__", "base_snapshot", "target_snapshot", "created_at"]
    list_filter = ["created_at"]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("base_snapshot", "target_snapshot")


@admin.register(DetectedService)
class DetectedServiceAdmin(admin.ModelAdmin):
    list_display = [
        "__str__",
        "service_type",
        "name",
        "confidence",
        "snapshot",
        "created_at",
    ]
    list_filter = ["service_type", "confidence", "created_at"]
    search_fields = ["name", "description"]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("snapshot")


@admin.register(AnalysisIssue)
class AnalysisIssueAdmin(admin.ModelAdmin):
    list_display = [
        "__str__",
        "severity",
        "code",
        "title",
        "snapshot",
        "created_at",
    ]
    list_filter = ["severity", "code", "created_at"]
    search_fields = ["title", "description", "code"]
