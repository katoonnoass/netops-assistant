import re
header = 'ip community-filter basic CLIENTE-COMM index 10 permit 65000:300'
m = re.match(r'ip\s+community-filter\s+(?:basic|advanced)?\s*(\S+)', header, re.IGNORECASE)
if m:
    print(f'Match: {m.group(1)}')
else:
    print('No match')
    # The issue might be that (?:basic|advanced)? is matching 'b' then failing
    # Actually let's try with more explicit capture
    m2 = re.match(r'ip\s+community-filter\s+(?:(?:basic|advanced)\s+)?(\S+)', header, re.IGNORECASE)
    if m2:
        print(f'v2 match: {m2.group(1)}')
    # Try without optional type
    m3 = re.match(r'ip\s+community-filter\s+(\S+)', header, re.IGNORECASE)
    if m3:
        print(f'v3 match: {m3.group(1)}')
