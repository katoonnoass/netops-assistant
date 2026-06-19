"""Check if template has policies section"""
with open('templates/analysis/search.html', 'r', encoding='utf-8') as f:
    t = f.read()
if 'Pol\u00edticas / Filtros' in t or 'Pol\u00edticas' in t:
    print('Policies section FOUND in template')
else:
    print('Policies section NOT FOUND')
    
# Check what's between bgp_peers section
idx = t.find('bgp_peers')
print(f'First bgp_peers at: {idx}')
print(t[max(0,idx-100):idx+50])
