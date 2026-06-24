from pathlib import Path

from django.test import SimpleTestCase, override_settings
from django.template import TemplateDoesNotExist


def _read(path):
    return path.read_text(encoding="utf-8")


@override_settings(
    STATICFILES_DIRS=[],
    TEMPLATES=[{
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [str(Path(__file__).resolve().parent.parent.parent.parent / "templates")],
        "APP_DIRS": False,
        "OPTIONS": {"context_processors": []},
    }],
)
class VlanTrackingDashboardTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent
        self.dashboard = self.base / "templates" / "core" / "dashboard.html"
        self.css = self.base / "static" / "css" / "app.css"

    def test_dashboard_exists(self):
        self.assertTrue(self.dashboard.exists())

    def test_dashboard_contains_rastreamento_vlans(self):
        content = _read(self.dashboard)
        self.assertIn("Rastreamento de VLANs", content)

    def test_dashboard_contains_sessoes(self):
        content = _read(self.dashboard)
        self.assertIn("Sess\u00f5es", content)

    def test_dashboard_contains_vlans(self):
        content = _read(self.dashboard)
        self.assertIn("VLANs", content)

    def test_dashboard_contains_issues(self):
        content = _read(self.dashboard)
        self.assertIn("Issues", content)

    def test_dashboard_contains_links_baixa_confianca(self):
        content = _read(self.dashboard)
        self.assertIn("Links baixa confian\u00e7a", content)

    def test_dashboard_not_contains_sessoes0(self):
        content = _read(self.dashboard)
        self.assertNotIn("Sess\u00f5es0", content)

    def test_dashboard_not_contains_vlans0(self):
        content = _read(self.dashboard)
        self.assertNotIn("VLANs0", content)

    def test_dashboard_not_contains_issues0(self):
        content = _read(self.dashboard)
        self.assertNotIn("Issues0", content)

    def test_dashboard_not_contains_vlan_trackina(self):
        content = _read(self.dashboard)
        self.assertNotIn("VLAN Trackina", content)

    def test_dashboard_uses_vlan_mini_card_classes(self):
        content = _read(self.dashboard)
        self.assertIn("vlan-mini-card", content)

    def test_dashboard_uses_vlan_mini_label(self):
        content = _read(self.dashboard)
        self.assertIn("vlan-mini-label", content)

    def test_dashboard_uses_vlan_mini_value(self):
        content = _read(self.dashboard)
        self.assertIn("vlan-mini-value", content)

    def test_dashboard_uses_vlan_tracking_metrics(self):
        content = _read(self.dashboard)
        self.assertIn("vlan-tracking-metrics", content)

    def test_css_contains_vlan_tracking_metrics(self):
        content = _read(self.css)
        self.assertIn(".vlan-tracking-metrics", content)

    def test_css_contains_vlan_mini_card(self):
        content = _read(self.css)
        self.assertIn(".vlan-mini-card", content)

    def test_css_contains_vlan_mini_label(self):
        content = _read(self.css)
        self.assertIn(".vlan-mini-label", content)

    def test_css_contains_vlan_mini_value(self):
        content = _read(self.css)
        self.assertIn(".vlan-mini-value", content)
