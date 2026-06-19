"""Find _search_bgp function and its pattern"""
with open('apps/analysis/search.py','r',encoding='utf-8') as f:
    lines = f.readlines()
for i,l in enumerate(lines,1):
    if 'def _search_bgp(' in l:
        print(f'Found _search_bgp at line {i}')
        # Print the function (next 60 lines)
        for j in range(i, min(i+60, len(lines)+1)):
            print(f'{j}: {lines[j-1].rstrip()[:120]}')
        break
