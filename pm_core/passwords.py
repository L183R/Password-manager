import secrets
import string

SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}<>?"
DEFAULT_LENGTH = 20


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    if length < 4:
        raise ValueError("La longitud mínima es 4 para incluir todos los tipos de caracteres.")

    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SPECIAL_CHARS]
    password = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)
