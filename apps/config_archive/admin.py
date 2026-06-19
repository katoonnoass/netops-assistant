from django.contrib import admin

from apps.config_archive.models import ConfigSnapshot


@admin.register(ConfigSnapshot)
class ConfigSnapshotAdmin(admin.ModelAdmin):
    list_display = ["__str__", "device", "vendor", "source", "created_at"]
    list_filter = ["vendor", "source", "created_at"]
    search_fields = ["raw_config"]
    readonly_fields = ["created_at"]
