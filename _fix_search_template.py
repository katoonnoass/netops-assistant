"""Update search.html to show when policies section exists."""
with open('templates/analysis/search.html', 'r', encoding='utf-8') as f:
    t = f.read()

# Find the BGP peers section display
old = '{% if results.bgp_peers %}\n<div class="card mb-2">\n    <h3 class="section-title">Peers BGP'
# Check if our policies section already exists
if 'Pol\u00edticas / Filtros' in t or 'Pol\u00edticas' in t:
    print("[OK] Policies section already in template")
else:
    # Add policies section before BGP
    new = '''{% if results.policies %}
<div class="card mb-2">
    <h3 class="section-title">Pol\u00edticas / Filtros <span class="badge badge-info">{{ results.policies|length }}</span></h3>
    {% for item in results.policies %}
    <div class="card" style="margin-bottom:0.5rem;padding:0.75rem;border-left:4px solid var(--info);">
        <div class="flex justify-between items-center">
            <strong>
                <span class="badge badge-{% if item.type == 'route_policy' %}warning{% elif item.type == 'bgp_policy_dependency' %}primary{% else %}info{% endif %}">{{ item.type }}</span>
                {{ item.title }}
            </strong>
            <span style="font-size:0.8rem;color:var(--text-secondary);">score {{ item.score }}</span>
        </div>
        <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:0.25rem;">{{ item.description }}</p>
        <div style="font-size:0.8rem;color:var(--text-secondary);">
            Dispositivo: {{ item.device|default:"?" }}
            {% if item.url %}
            &mdash; <a href="{{ item.url }}">Ver an\u00e1lise</a>
            {% endif %}
        </div>
    </div>
    {% endfor %}
</div>
{% endif %}

{% if results.bgp_peers %}
<div class="card mb-2">
    <h3 class="section-title">Peers BGP'''
    t = t.replace(old, new, 1)
    with open('templates/analysis/search.html', 'w', encoding='utf-8') as f:
        f.write(t)
    print("[OK] Policies section added to search template")
