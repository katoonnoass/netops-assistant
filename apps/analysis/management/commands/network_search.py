"""Comando de gerenciamento: network_search.

Uso:
    python manage.py network_search "<query>"
    python manage.py network_search "200.200.200.0/30"
    python manage.py network_search "Eth-Trunk100.1234"
    python manage.py network_search "RADIUS-ISP"

Executa busca técnica global e imprime resultados no terminal.
"""

from django.core.management.base import BaseCommand

from apps.analysis.search import classify_search_query, global_network_search


class Command(BaseCommand):
    help = "Busca técnica global determinística"

    def add_arguments(self, parser):
        parser.add_argument("query", type=str, help="Termo de busca")
        parser.add_argument(
            "--vendor",
            type=str,
            default="",
            help="Filtrar por vendor",
        )
        parser.add_argument(
            "--device",
            type=str,
            default="",
            help="Filtrar por nome do dispositivo",
        )
        parser.add_argument(
            "--last-snapshot-only",
            action="store_true",
            default=False,
            help="Apenas último snapshot por dispositivo",
        )

    def handle(self, *args, **options):
        query = options["query"]
        filters = {}
        if options["vendor"]:
            filters["vendor"] = options["vendor"]
        if options["device"]:
            filters["device"] = options["device"]
        if options["last_snapshot_only"]:
            filters["last_snapshot_only"] = True

        classification = classify_search_query(query)
        results = global_network_search(query, filters=filters if filters else None)

        self.stdout.write(f"\n=== BUSCA TÉCNICA GLOBAL ===")
        self.stdout.write(f"Query:        {query}")
        self.stdout.write(f"Tipo:         {classification['type']}")
        if classification.get("value") and classification["value"] != classification["query"]:
            self.stdout.write(f"Valor normal: {classification['value']}")

        self.stdout.write(f"\n--- Resumo ---")
        for key, count in results["summary"].items():
            if key != "total":
                self.stdout.write(f"  {key}: {count}")
        self.stdout.write(f"  Total: {results['summary']['total']}")

        sections = [
            ("dispositivos", results["devices"]),
            ("interfaces", results["interfaces"]),
            ("circuitos", results["circuits"]),
            ("rotas estáticas", results["static_routes"]),
            ("BGP", results["bgp_peers"]),
            ("políticas / filtros", results["policies"]),
            ("serviços", results["services"]),
            ("issues", results["issues"]),
            ("ocorrências em texto bruto", results["raw_matches"]),
        ]

        for section_name, items in sections:
            if not items:
                continue
            self.stdout.write(f"\n--- {section_name.title()} ({len(items)}) ---")
            for item in items[:5]:  # Top 5 per section
                device = item.get("device", "")
                title = item.get("title", "")
                score = item.get("score", 0)
                evidence = item.get("evidence", [])
                meta = item.get("metadata", {})
                self.stdout.write(
                    f"  [{score:.1f}] {title}"
                )
                if device:
                    self.stdout.write(f"        Dispositivo: {device}")
                if meta and "vpn_instance" in meta and meta["vpn_instance"]:
                    self.stdout.write(f"        VPN: {meta['vpn_instance']}")
                if meta and "remote_as" in meta and meta.get("remote_as"):
                    self.stdout.write(f"        AS remoto: {meta['remote_as']}")
                if evidence:
                    for ev in evidence[:1]:
                        # Truncate evidence for display
                        lines = ev.splitlines()
                        for line in lines[:3]:
                            self.stdout.write(f"        >> {line.strip()}")
            if len(items) > 5:
                self.stdout.write(f"  ... e mais {len(items) - 5} resultado(s)")
