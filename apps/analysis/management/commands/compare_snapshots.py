"""Comando: compara dois snapshots existentes.

Uso:
    python manage.py compare_snapshots <base_id> <target_id>
"""

from django.core.management.base import BaseCommand, CommandError

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.models import ConfigComparison
from apps.config_archive.models import ConfigSnapshot


class Command(BaseCommand):
    help = "Compara dois snapshots de configuração"

    def add_arguments(self, parser):
        parser.add_argument("base_id", type=int, help="ID do snapshot base (antes)")
        parser.add_argument("target_id", type=int, help="ID do snapshot alvo (depois)")

    def handle(self, *args, **options):
        base_id = options["base_id"]
        target_id = options["target_id"]

        try:
            base = ConfigSnapshot.objects.get(pk=base_id)
        except ConfigSnapshot.DoesNotExist:
            raise CommandError(f"Snapshot base #{base_id} não encontrado.")
        try:
            target = ConfigSnapshot.objects.get(pk=target_id)
        except ConfigSnapshot.DoesNotExist:
            raise CommandError(f"Snapshot alvo #{target_id} não encontrado.")

        self.stdout.write(f"Comparando #{base_id} vs #{target_id}...")
        comparison = compare_config_snapshots(base, target)

        d = comparison.diff_data
        self.stdout.write(self.style.SUCCESS(f"\nComparação #{comparison.pk} criada.\n"))
        self.stdout.write(f"Interfaces:   +{len(d['interfaces']['added'])} "
                          f"-{len(d['interfaces']['removed'])} "
                          f"~{len(d['interfaces']['changed'])}")
        self.stdout.write(f"Rotas:        +{len(d['static_routes']['added'])} "
                          f"-{len(d['static_routes']['removed'])} "
                          f"~{len(d['static_routes']['changed'])}")
        self.stdout.write(f"Peers BGP:    +{len(d['bgp']['peers_added'])} "
                          f"-{len(d['bgp']['peers_removed'])}")
        self.stdout.write(f"Circuitos:    +{len(d['circuits']['added'])} "
                          f"-{len(d['circuits']['removed'])}")
        self.stdout.write(f"Serviços:     +{len(d['services']['added'])} "
                          f"-{len(d['services']['removed'])}")
        self.stdout.write(f"Issues:       {d['issues']['new_count']} nova(s), "
                          f"{d['issues']['resolved_count']} resolvida(s)")

        if d["impacts"]:
            self.stdout.write("\n--- Impactos ---")
            for imp in d["impacts"][:5]:
                self.stdout.write(f"  [{imp['severity']}] {imp['impact']}")
            if len(d["impacts"]) > 5:
                self.stdout.write(f"  ... e mais {len(d['impacts']) - 5} impacto(s)")
