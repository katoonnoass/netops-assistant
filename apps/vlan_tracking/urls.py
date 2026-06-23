from django.urls import path

from . import views

app_name = "vlan_tracking"

urlpatterns = [
    path("", views.SessionListView.as_view(), name="session_list"),
    path("new/", views.SessionCreateView.as_view(), name="session_create"),
    path("<int:pk>/", views.SessionDetailView.as_view(), name="session_detail"),
    path("<int:pk>/run/", views.RunCorrelationView.as_view(), name="run_correlation"),
    path("<int:pk>/vlans/", views.VlanListView.as_view(), name="vlan_list"),
    path("<int:pk>/vlan/<int:vid>/", views.VlanDetailView.as_view(), name="vlan_detail"),
    path("<int:pk>/links/", views.LinkListView.as_view(), name="link_list"),
    path("<int:pk>/links/add/", views.LinkCreateView.as_view(), name="link_create"),
    path("<int:pk>/topology/", views.TopologyView.as_view(), name="topology"),
    path("<int:pk>/topology/mermaid/", views.TopologyMermaidView.as_view(), name="topology_mermaid"),
    path("<int:pk>/evidence/", views.EvidenceListView.as_view(), name="evidence_list"),
    path("<int:pk>/evidence/add/", views.EvidenceCreateView.as_view(), name="evidence_create"),
    path("<int:pk>/evidence/<int:evid>/delete/", views.EvidenceDeleteView.as_view(), name="evidence_delete"),
    path("<int:pk>/topology/svg/", views.TopologySvgView.as_view(), name="topology_svg"),
    path("<int:pk>/topology/svg/download/", views.TopologySvgDownloadView.as_view(), name="topology_svg_download"),
    path("<int:pk>/troubleshoot/", views.VlanTroubleshootSearchView.as_view(), name="troubleshoot_search"),
    path("<int:pk>/troubleshoot/<int:vid>/", views.VlanTroubleshootDetailView.as_view(), name="troubleshoot_detail"),
    path("<int:pk>/troubleshoot/<int:vid>/export.txt", views.VlanTroubleshootExportTextView.as_view(), name="troubleshoot_export_txt"),
    path("<int:pk>/troubleshoot/<int:vid>/export.csv", views.VlanTroubleshootExportCsvView.as_view(), name="troubleshoot_export_csv"),
    path("<int:pk>/export.txt", views.SessionExportTextView.as_view(), name="session_export_txt"),
    path("<int:pk>/export.csv", views.SessionExportCsvView.as_view(), name="session_export_csv"),
]
