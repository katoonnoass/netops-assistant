"""Test name regex"""
import re
# Test the name regex
name_re = r"ip\s+community-filter\s+(?:basic|advanced)?\s*(\S+)"
test = "ip community-filter basic CLIENTE-COMM index 10 permit 65000:300"
m = re.match(name_re, test, re.IGNORECASE)
if m:
    print(f"Name match: {m.group(1)}")
else:
    print("Name regex FAILED")
    # Try alternative
    name_re2 = r"ip\s+community-filter\s+(?:(?:basic|advanced)\s+)?(\S+)"
    m2 = re.match(name_re2, test, re.IGNORECASE)
    if m2:
        print(f"Name match v2: {m2.group(1)}")

# Test the rule regex  
rule_re = r"(?:ip\s+community-filter\s+(?:basic|advanced\s+)?\S+(?:\s+index\s+\d+)?\s+)?(deny|permit)\s+(.+)"
m3 = re.match(rule_re, test, re.IGNORECASE)
if m3:
    print(f"Rule match: action={m3.group(1)} value={m3.group(2)}")
else:
    print("Rule regex FAILED on full line")
    # Test with just the content part
    content = "permit 65000:300"
    m4 = re.match(rule_re, content, re.IGNORECASE)
    if m4:
        print(f"Rule match on content: action={m4.group(1)} value={m4.group(2)}")
