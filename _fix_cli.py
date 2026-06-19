"""Add policies display to network_search CLI."""
with open('apps/analysis/management/commands/network_search.py', 'r', encoding='utf-8') as f:
    t = f.read()

# Add policies display section - find where BGP peers are displayed
old = '''    if results.get("bgp_peers"):
        print("--- Peers BGP encontrados ---")
        for peer in results["bgp_peers"]:
            print(f"  [{peer.get('peer_ip', peer.get('title', '?'))}] device: {peer.get('device_name', '?')}")'''
new = '''    if results.get("policies"):
        print("--- Pol\u00edticas / Filtros ---")
        for item in results["policies"]:
            ptype = item.get("type", "?")
            title = item.get("title", "?")
            device = item.get("device", "?")
            print(f"  [{ptype}] {title} (device: {device})")

    if results.get("bgp_peers"):
        print("--- Peers BGP encontrados ---")
        for peer in results["bgp_peers"]:
            print(f"  [{peer.get('peer_ip', peer.get('title', '?'))}] device: {peer.get('device_name', '?')}")'''
t = t.replace(old, new, 1)

with open('apps/analysis/management/commands/network_search.py', 'w', encoding='utf-8') as f:
    f.write(t)
print("[OK] network_search.py CLI updated")
