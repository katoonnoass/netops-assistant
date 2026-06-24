from django.core.management.base import BaseCommand, CommandError

from apps.collector.models import DiscoveryProfile
from apps.collector.services import run_full_collector


class Command(BaseCommand):
    help = "Executa o coletor completo: descoberta + coleta + análise"

    def add_arguments(self, parser):
        parser.add_argument("--profile", required=True, help="Nome do perfil de descoberta")
        parser.add_argument("--dry-run", action="store_true", help="Simula sem conectar em equipamentos reais")
        parser.add_argument(
            "--allow-large-subnet", action="store_true",
            help="Permite subnets maiores que /24 (cuidado: pode escanear muitos IPs)",
        )
        parser.add_argument("--discover", action="store_true", default=True, help="Executa descoberta SNMP")
        parser.add_argument("--no-discover", action="store_false", dest="discover", help="Pula descoberta SNMP")
        parser.add_argument("--collect", action="store_true", default=True, help="Executa coleta SSH")
        parser.add_argument("--no-collect", action="store_false", dest="collect", help="Pula coleta SSH")
        parser.add_argument("--analyze", action="store_true", help="Executa análise após coleta")

    def handle(self, *args, **options):
        profile_name = options["profile"]
        dry_run = options["dry_run"]
        allow_large = options.get("allow_large_subnet", False)
        discover = options.get("discover", True)
        collect = options.get("collect", True)
        analyze = options.get("analyze", False)

        try:
            profile = DiscoveryProfile.objects.get(name=profile_name)
        except DiscoveryProfile.DoesNotExist:
            raise CommandError(f"Perfil '{profile_name}' não encontrado.")

        if not profile.is_active:
            raise CommandError(f"Perfil '{profile_name}' está inativo.")

        self.stdout.write(f"Perfil: {profile.name}")
        self.stdout.write(f"Sub-redes: {', '.join(profile.subnets) if profile.subnets else '(nenhuma)'}")
        self.stdout.write(f"Modo: {'DRY-RUN' if dry_run else 'EXECUÇÃO'}")
        if allow_large:
            self.stdout.write("Subnets grandes: PERMITIDAS")
        self.stdout.write(f"Etapas: " + ", ".join(
            filter(None, [
                "Descoberta SNMP" if discover else None,
                "Coleta SSH" if collect else None,
                "Análise" if analyze else None,
            ])
        ))
        self.stdout.write("")

        if dry_run:
            lines = run_full_collector(profile, dry_run=True, discover=discover, collect=collect, analyze=analyze)
            for line in lines:
                self.stdout.write(line)
            return

        if not discover and not collect:
            self.stdout.write("Nenhuma etapa selecionada. Use --discover e/ou --collect.")
            return

        try:
            run = run_full_collector(
                profile, dry_run=False,
                discover=discover, collect=collect, analyze=analyze,
                allow_large_subnet=allow_large,
            )
        except ValueError as e:
            raise CommandError(str(e)) from None

        if run:
            self.stdout.write(f"Run #{run.pk} finalizada.")
            self.stdout.write(f"  Status: {run.get_status_display()}")
            self.stdout.write(f"  Escaneados: {run.discovered_count + run.failed_count}")
            self.stdout.write(f"  Descobertos: {run.discovered_count}")
            self.stdout.write(f"  Coletados: {run.collected_count}")
            self.stdout.write(f"  Analisados: {run.analyzed_count}")
            self.stdout.write(f"  Falhas: {run.failed_count}")
            if run.summary:
                self.stdout.write(f"  Resumo: {run.summary}")
