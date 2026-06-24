import os
import re
import warnings

from django.core.exceptions import ImproperlyConfigured

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None  # noqa: N811


ENV_KEY = "COLLECTOR_SECRET_KEY"


def _get_fernet_key():
    raw = os.getenv(ENV_KEY, "")
    if not raw:
        return None
    key = raw.strip()
    try:
        Fernet(key)
    except Exception:
        raise ImproperlyConfigured(
            f"{ENV_KEY} não é uma chave Fernet válida. "
            f"Gere uma com: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        ) from None
    return key


def get_fernet():
    if Fernet is None:
        raise ImproperlyConfigured(
            "Biblioteca cryptography não está instalada. "
            "Adicione cryptography ao requirements.txt e instale."
        )
    key = _get_fernet_key()
    if key is None:
        return None
    return Fernet(key)


def encrypt_value(value):
    if not value:
        return ""
    f = get_fernet()
    if f is None:
        warnings.warn(
            f"{ENV_KEY} não definida — salvando valor sem criptografia. "
            "Defina a variável em produção.",
            stacklevel=2,
        )
        return value
    return f.encrypt(value.encode()).decode()


def decrypt_value(value):
    if not value:
        return ""
    f = get_fernet()
    if f is None:
        return value
    try:
        return f.decrypt(value.encode()).decode()
    except Exception:
        return value


def mask_secret(value):
    if not value:
        return ""
    if len(value) <= 2:
        return "****"
    return value[0] + "****" + value[-1] if len(value) > 6 else "****"


def mask_text(text, secrets):
    if not text or not secrets:
        return text
    result = text
    for secret in secrets:
        if not secret:
            continue
        result = result.replace(secret, mask_secret(secret))
    return result
