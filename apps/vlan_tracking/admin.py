from django.contrib import admin

from .models import (
    DeviceLink,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackSession,
    VlanTrackingIssue,
)


@admin.register(VlanTrackSession)
class VlanTrackSessionAdmin(admin.ModelAdmin):
    list_display = ("name", "created_by", "device_count", "created_at")
    search_fields = ("name", "description")

    def device_count(self, obj):
        return obj.devices.count()
    device_count.short_description = "Dispositivos"


@admin.register(VlanTrackDevice)
class VlanTrackDeviceAdmin(admin.ModelAdmin):
    list_display = ("session", "device", "order", "role_hint")
    list_filter = ("session",)


@admin.register(DeviceLink)
class DeviceLinkAdmin(admin.ModelAdmin):
    list_display = ("session", "device_a", "interface_a", "device_b", "interface_b", "discovery_method", "confidence", "status")
    list_filter = ("discovery_method", "confidence", "status", "session")


@admin.register(VlanDefinition)
class VlanDefinitionAdmin(admin.ModelAdmin):
    list_display = ("session", "vlan_id", "name", "device_count", "interface_count")
    list_filter = ("session",)


@admin.register(VlanInterface)
class VlanInterfaceAdmin(admin.ModelAdmin):
    list_display = ("session", "device", "interface_name", "vlan_id", "port_mode", "tagged")
    list_filter = ("port_mode", "session")
    search_fields = ("interface_name",)


@admin.register(VlanEndpoint)
class VlanEndpointAdmin(admin.ModelAdmin):
    list_display = ("session", "vlan_definition", "device", "interface_name", "endpoint_type")
    list_filter = ("endpoint_type", "session")


@admin.register(VlanPath)
class VlanPathAdmin(admin.ModelAdmin):
    list_display = ("session", "vlan_definition", "from_device", "to_device", "tagged", "status")
    list_filter = ("status", "tagged", "session")


@admin.register(VlanTrackingIssue)
class VlanTrackingIssueAdmin(admin.ModelAdmin):
    list_display = ("session", "code", "severity", "title", "created_at")
    list_filter = ("code", "severity", "session")
