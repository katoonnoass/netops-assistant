"""Debug with direct import"""
import sys, os, django
sys.path.insert(0, '.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netops_assistant.settings')

# Force reimport
for mod in list(sys.modules.keys()):
    if 'parser' in mod.lower() or 'huawei' in mod.lower():
        del sys.modules[mod]

from apps.parsers.huawei import HuaweiVRPParser

# Test regex directly 
import re
header = 'ip community-filter basic CLIENTE-COMM index 10 permit 65000:300'
m = re.match(r"ip\s+community-filter\s+(?:basic|advanced)?\s*(\S+)", header, re.IGNORECASE)
print(f'Direct regex match: {m.groups() if m else "FAIL"}')

# Test parsing
raw = """#
sysname TEST
#
ip community-filter basic CLIENTE-COMM index 10 permit 65000:300
"""
parser = HuaweiVRPParser(raw)
result = parser.parse()
print(f'community_filters: {len(result.get("community_filters", []))}')
for cf in result.get('community_filters', []):
    print(f'  name={cf.get("name")} type={cf.get("type")}')
