"""Comando: compara dois arquivos de configuração.

Uso:
    python manage.py compare_config_files <base_file> <target_file> \
        --vendor huawei --device-name "NE40-DIFF-TESTE"
"""

from django.core.management.base import BaseCommand, CommandError

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.models import ConfigComparison
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device


class Command(BaseCommand):
    help = "Analisa dois arquivos de configuração e os compara"

    def add_arguments(self, parser):
        parser.add_argument("base_file", type=str, help="Arquivo base (antes)")
        parser.add_argument("target_file", type=str, help="Arquivo alvo (depois)")
        parser.add_argument("--vendor", type=str, default="huawei")
        parser.add_argument("--device-name", type=str, default="")

    def handle(self, *args, **options):
        base_file = options["base_file"]
        target_file = options["target_file"]
        vendor = options["vendor"]
        device_name = options["device_name"]

        def _read(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
            except FileNotFoundError:
                raise CommandError(f"Arquivo não encontrado: {path}")

        base_text = _read(base_file)
        target_text = _read(target_file)

        device = None
        if device_name:
            device, _ = Device.objects.get_or_create(
                name=device_name, defaults={"vendor": vendor}
            )

        base_snap = ConfigSnapshot.objects.create(
            device=device, raw_config=base_text, vendor=vendor,
            source="upload", notes="Base para comparação",
        )
        target_snap = ConfigSnapshot.objects.create(
            device=device, raw_config=target_text, vendor=vendor,
            source="upload", notes="Alvo para comparação",
        )

        self.stdout.write(f"Snapshots criados: #{base_snap.pk} (base), #{target_snap.pk} (alvo)")
        self.stdout.write("Analisando e comparando...")

        comparison = compare_config_snapshots(base_snap, target_snap)
        diff = comparison.diff_data

        self.stdout.write(self.style.SUCCESS(f"\nComparação #{comparison.pk} criada.\n"))
        self.stdout.write(f"Linhas: +{diff['raw_diff']['added_count']} "
                          f"-{diff['raw_diff']['removed_count']}")
        self.stdout.write(f"Interfaces:   +{len(diff['interfaces']['added'])} "
                          f"-{len(diff['interfaces']['removed'])} "
                          f"~{len(diff['interfaces']['changed'])}")
        self.stdout.write(f"Rotas:        +{len(diff['static_routes']['added'])} "
                          f"-{len(diff['static_routes']['removed'])} "
                          f"~{len(diff['static_routes']['changed'])}")
        self.stdout.write(f"Peers BGP:    +{len(diff['bgp']['peers_added'])} "
                          f"-{len(diff['bgp']['peers_removed'])}")
        self.stdout.write(f"Redes BGP:    +{len(diff['bgp']['networks_added'])} "
                          f"-{len(diff['bgp']['networks_removed'])}")
        self.stdout.write(f"Circuitos:    +{len(diff['circuits']['added'])} "
                          f"-{len(diff['circuits']['removed'])}")
        self.stdout.write(f"Serviços:     +{len(diff['services']['added'])} "
                          f"-{len(diff['services']['removed'])}")
        self.stdout.write(f"Issues:       {diff['issues']['new_count']} nova(s), "
                          f"{diff['issues']['resolved_count']} resolvida(s)")

        if diff["impacts"]:
            self.stdout.write("\n--- Impactos Prováveis ---")
            for imp in diff["impacts"]:
                sev = imp["severity"]
                label = self.style.ERROR if sev == "critical" else (
                    self.style.WARNING if sev == "warning" else ""
                )
                self.stdout.write(f"  {label}[{sev}]{' ' if label else ''} {imp['impact']}"
                                  if not label else
                                  f"  {label}[{sev}] {imp['impact']}")

        if diff["recommendations"]:
            self.stdout.write("\n--- Recomendações ---")
            for r in diff["recommendations"]:
                self.stdout.write(f"  [{r['severity']}] {r['recommendation']}")

        if diff.get("validation_plan"):
            self.stdout.write(f"\n--- Plano de Validação ({len(diff['validation_plan'])} itens) ---")
            for v in diff["validation_plan"][:3]:
                self.stdout.write(f"  [{v['severity']}] {v['title']}")
            if len(diff["validation_plan"]) > 3:
                self.stdout.write(f"  ... e mais {len(diff['validation_plan']) - 3} item(ns)")

        if diff.get("rollback_plan"):
            self.stdout.write(f"\n--- Rollback Sugerido ({len(diff['rollback_plan'])} itens) ---")
            high_risk = [r for r in diff["rollback_plan"] if r["risk_level"] in ("critical", "high")]
            if high_risk:
                self.stdout.write(f"  {len(high_risk)} item(ns) de alto risco identificados.")
                for r in high_risk[:2]:
                    self.stdout.write(f"  - {r['change_type']}: {r['object']}")
