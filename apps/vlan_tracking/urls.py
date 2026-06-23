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
]
