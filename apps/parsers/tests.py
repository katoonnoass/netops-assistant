"""Test suite for parsers app.

This file makes tests discoverable by Django's test runner.
"""

from apps.parsers.cisco.tests.test_parser import CiscoIOSParserTest  # noqa: F401
from apps.parsers.huawei.tests.test_parser import HuaweiVRPParserTest  # noqa: F401
from apps.parsers.zte.tests.test_parser import ZTEOLTParserTests  # noqa: F401
