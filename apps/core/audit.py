"""Helpers de auditoria — registro centralizado de ações operacionais."""

from django.contrib.auth.models import User

from apps.core.models import AuditLog


def record_audit_event(
    user: User | None,
    action: str,
    object_type: str = "",
    object_id: str = "",
    description: str = "",
    request=None,
    metadata: dict | None = None,
) -> AuditLog:
    """Registra um evento de auditoria no banco.

    Args:
        user: Usuário que executou a ação. Se AnonymousUser, converte para None.
        action: Código da ação (ex: 'snapshot_uploaded', 'comparison_created').
        object_type: Tipo do objeto (ex: 'ConfigSnapshot', 'ConfigComparison').
        object_id: ID ou PK do objeto.
        description: Descrição legível do evento.
        request: HttpRequest (opcional) — extrai IP e user-agent.
        metadata: Dict adicional (opcional).

    Returns:
        AuditLog instance.
    """
    # Handle AnonymousUser
    if user is not None and not user.is_authenticated:
        user = None

    ip_address = None
    user_agent = ""
    if request:
        ip_address = request.META.get("REMOTE_ADDR", "")
        x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if x_forwarded:
            ip_address = x_forwarded.split(",")[0].strip()
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]

    return AuditLog.objects.create(
        user=user,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else "",
        description=description,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata or {},
    )
