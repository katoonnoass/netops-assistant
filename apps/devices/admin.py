from django.contrib import admin

from apps.devices.models import Device


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ["name", "vendor", "ip_address", "hostname", "created_at"]
    list_filter = ["vendor"]
    search_fields = ["name", "hostname", "ip_address"]
