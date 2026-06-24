from django.core.management.base import BaseCommand, CommandError

from apps.collector.models import DiscoveryProfile
from apps.collector.services import run_discovery


class Command(BaseCommand):
    help = "Descobre equipamentos via SNMP em sub-redes configuradas"

    def add_arguments(self, parser):
        parser.add_argument("--profile", required=True, help="Nome do perfil de descoberta")
        parser.add_argument("--dry-run", action="store_true", help="Simula sem conectar em equipamentos reais")
        parser.add_argument(
            "--allow-large-subnet", action="store_true",
            help="Permite subnets maiores que /24 (cuidado: pode escanear muitos IPs)",
        )

    def handle(self, *args, **options):
        profile_name = options["profile"]
        dry_run = options["dry_run"]
        allow_large = options.get("allow_large_subnet", False)

        try:
            profile = DiscoveryProfile.objects.get(name=profile_name)
        except DiscoveryProfile.DoesNotExist:
            raise CommandError(f"Perfil '{profile_name}' não encontrado.")

        if not profile.is_active:
            raise CommandError(f"Perfil '{profile_name}' está inativo.")

        self.stdout.write(f"Perfil: {profile.name}")
        self.stdout.write(f"Sub-redes: {', '.join(profile.subnets) if profile.subnets else '(nenhuma)'}")
        self.stdout.write(f"Versão SNMP: {profile.snmp_version}")
        self.stdout.write(f"Modo: {'DRY-RUN' if dry_run else 'EXECUÇÃO'}")
        if allow_large:
            self.stdout.write("Subnets grandes: PERMITIDAS")
        self.stdout.write("")

        if dry_run:
            lines = run_discovery(profile=profile, dry_run=True)
            for line in lines:
                self.stdout.write(line)
            return

        try:
            run = run_discovery(profile=profile, allow_large_subnet=allow_large)
        except ValueError as e:
            raise CommandError(str(e)) from None

        self.stdout.write(f"Run #{run.pk} finalizada.")
        self.stdout.write(f"  Status: {run.get_status_display()}")
        self.stdout.write(f"  Escaneados: {run.discovered_count + run.failed_count}")
        self.stdout.write(f"  Descobertos: {run.discovered_count}")
        self.stdout.write(f"  Falhas: {run.failed_count}")
        if run.summary:
            self.stdout.write(f"  Resumo: {run.summary}")
