"""Debug community-filter CLIENTE-COMM parsing"""
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netops_assistant.settings')
django.setup()

from apps.parsers.huawei import HuaweiVRPParser

raw = """#
sysname TEST
#
ip community-filter basic CLIENTE-COMM index 10 permit 65000:300
"""
parsed = HuaweiVRPParser(raw).parse()
print("community_filters:", len(parsed.get('community_filters', [])))
for cf in parsed.get('community_filters', []):
    print(f'  name={cf.get("name")} type={cf.get("type")}')
    for r in cf.get('rules', []):
        print(f'    index={r.get("index")} action={r.get("action")} value={r.get("value")}')
