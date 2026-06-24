from django.contrib import admin

from .models import CollectorRun, CollectorTask, DiscoveryProfile, NetworkCredential


@admin.register(NetworkCredential)
class NetworkCredentialAdmin(admin.ModelAdmin):
    list_display = ["name", "username", "snmp_version", "vendor_hint", "priority", "is_active"]
    list_filter = ["snmp_version", "vendor_hint", "is_active"]
    search_fields = ["name", "username"]
    readonly_fields = ["encrypted_password", "encrypted_enable_secret", "created_at", "updated_at"]

    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj)
        return [f for f in fields if f not in ("encrypted_password", "encrypted_enable_secret")]

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ["encrypted_password", "encrypted_enable_secret"]
        return self.readonly_fields


@admin.register(DiscoveryProfile)
class DiscoveryProfileAdmin(admin.ModelAdmin):
    list_display = ["name", "snmp_version", "max_workers", "timeout", "is_active"]
    list_filter = ["snmp_version", "is_active"]
    search_fields = ["name", "description"]


class CollectorTaskInline(admin.TabularInline):
    model = CollectorTask
    fields = ["ip_address", "action", "status", "started_at", "finished_at", "log", "error"]
    readonly_fields = ["started_at", "finished_at", "log", "error"]
    extra = 0
    can_delete = False
    max_num = 0


@admin.register(CollectorRun)
class CollectorRunAdmin(admin.ModelAdmin):
    list_display = [
        "profile", "status", "discovered_count", "collected_count",
        "analyzed_count", "failed_count", "started_at", "finished_at",
    ]
    list_filter = ["status", "profile"]
    search_fields = ["profile__name", "summary"]
    readonly_fields = ["started_at", "finished_at", "summary"]
    inlines = [CollectorTaskInline]

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(CollectorTask)
class CollectorTaskAdmin(admin.ModelAdmin):
    list_display = ["run", "ip_address", "action", "status", "started_at", "finished_at"]
    list_filter = ["action", "status"]
    search_fields = ["ip_address", "log", "error"]
    readonly_fields = ["run", "device", "ip_address", "action", "status", "started_at", "finished_at", "log", "error"]

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False
