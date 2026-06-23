from unittest.mock import patch

from django.test import TestCase

from apps.analysis.models import AnalysisIssue, ParsedConfig
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot


class AnalysisAtomicityTests(TestCase):
    def setUp(self):
        self.snapshot = ConfigSnapshot.objects.create(
            raw_config="#\nsysname ATOMIC-TEST\n#\n",
            vendor="huawei",
        )
        self.original_parsed = ParsedConfig.objects.create(
            snapshot=self.snapshot,
            parsed_data={"original": True},
        )
        self.original_issue = AnalysisIssue.objects.create(
            snapshot=self.snapshot,
            severity="warning",
            code="original_issue",
            title="Issue original",
        )

    def test_parser_failure_preserves_previous_analysis(self):
        class FailingParser:
            def __init__(self, raw_config):
                self.raw_config = raw_config

            def parse(self):
                raise RuntimeError("parser failure")

        with patch(
            "apps.analysis.services.get_parser_for_vendor",
            return_value=("huawei", FailingParser),
        ):
            with self.assertRaisesRegex(RuntimeError, "parser failure"):
                analyze_config_snapshot(self.snapshot)

        self.assertTrue(
            ParsedConfig.objects.filter(pk=self.original_parsed.pk).exists()
        )
        self.assertTrue(
            AnalysisIssue.objects.filter(pk=self.original_issue.pk).exists()
        )

    def test_detector_failure_rolls_back_partial_reanalysis(self):
        with patch(
            "apps.analysis.services.detect_services",
            side_effect=RuntimeError("detector failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "detector failure"):
                analyze_config_snapshot(self.snapshot)

        parsed = ParsedConfig.objects.get(snapshot=self.snapshot)
        self.assertEqual(parsed.pk, self.original_parsed.pk)
        self.assertEqual(parsed.parsed_data, {"original": True})
        self.assertTrue(
            AnalysisIssue.objects.filter(pk=self.original_issue.pk).exists()
        )
