"""Debug blocks for community filter"""
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netops_assistant.settings')
django.setup()

from apps.parsers.huawei import HuaweiVRPParser

raw = """#
sysname TEST
#
ip community-filter basic CLIENTE-COMM index 10 permit 65000:300
"""
parser = HuaweiVRPParser(raw)
blocks = parser._split_blocks(raw)
print("Blocks:")
for b in blocks:
    print(f'  type={b["type"]} header={b["header"]!r}')
    if b["type"] == 'community-filter':
        parsed = parser._parse_community_filter_block(b)
        print(f'  Parsed: {parsed}')
