from django.urls import path

from . import views

app_name = "collector"

urlpatterns = [
    path("", views.CollectorDashboardView.as_view(), name="dashboard"),
    path("runs/", views.CollectorRunListView.as_view(), name="run_list"),
    path("runs/<int:pk>/", views.CollectorRunDetailView.as_view(), name="run_detail"),
    path("tasks/", views.CollectorTaskListView.as_view(), name="task_list"),
    path("tasks/<int:pk>/", views.CollectorTaskDetailView.as_view(), name="task_detail"),
    path("profiles/", views.DiscoveryProfileListView.as_view(), name="profile_list"),
    path("profiles/<int:pk>/", views.DiscoveryProfileDetailView.as_view(), name="profile_detail"),
    path("devices/", views.CollectorDeviceStatusView.as_view(), name="device_status"),
]
