"""URL configuration for netops_assistant project."""
from django.contrib import admin
from django.urls import path

from apps.analysis import inventory_views, search_views, views as analysis_views
from apps.config_archive import views as config_views
from apps.core import comparison_views, views as core_views
from apps.devices import views as device_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", core_views.dashboard, name="dashboard"),
    path("configs/new/", config_views.new_analysis, name="new_analysis"),
    path("configs/", config_views.snapshot_list, name="snapshot_list"),
    path("analysis/<int:pk>/", analysis_views.analysis_detail, name="analysis_detail"),
    path(
        "analysis/<int:pk>/documentation/",
        analysis_views.analysis_documentation,
        name="analysis_documentation",
    ),
    path("circuits/", inventory_views.inventory_circuit_list, name="circuit_list"),
    path("circuits/<int:pk>/", inventory_views.inventory_circuit_detail, name="circuit_detail"),
    path("circuits/export.csv", inventory_views.inventory_circuit_export, name="circuit_export"),
    path("services/", inventory_views.inventory_service_list, name="service_list"),
    path("services/<int:pk>/", inventory_views.inventory_service_detail, name="service_detail"),
    path("services/export.csv", inventory_views.inventory_service_export, name="service_export"),
    path("issues/", inventory_views.inventory_issue_list, name="issue_list"),
    path("issues/<int:pk>/", inventory_views.inventory_issue_detail, name="issue_detail"),
    path("issues/export.csv", inventory_views.inventory_issue_export, name="issue_export"),
    path("search/", search_views.search_view, name="search"),
    path("devices/", device_views.device_list, name="device_list"),
    path("devices/<int:pk>/", device_views.device_detail, name="device_detail"),
    path("devices/export.csv", device_views.device_export, name="device_export"),
    path("comparisons/", comparison_views.comparison_list, name="comparison_list"),
    path("comparisons/new/", comparison_views.comparison_new, name="comparison_new"),
    path(
        "comparisons/<int:pk>/",
        comparison_views.comparison_detail,
        name="comparison_detail",
    ),
]
