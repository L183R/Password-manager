import json
import os
import tempfile
from typing import Any

from .crypto import decrypt_payload, encrypt_data


class StorageError(OSError):
    """Raised when credential files cannot be read or written."""


def load_credentials(path: str, password: str) -> list[dict[str, str]]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            payload: dict[str, Any] = json.load(file)
    except FileNotFoundError as exc:
        raise StorageError("El archivo seleccionado no existe.") from exc
    except json.JSONDecodeError as exc:
        raise StorageError("El archivo seleccionado no es un JSON válido.") from exc
    except OSError as exc:
        raise StorageError(f"No se pudo leer el archivo: {exc}") from exc
    return decrypt_payload(payload, password)


def save_credentials(path: str, data: list[dict[str, str]], password: str) -> None:
    payload = encrypt_data(data, password)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".credenciales-", suffix=".tmp", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
        os.replace(temp_path, path)
    except OSError as exc:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise StorageError(f"No se pudo guardar el archivo: {exc}") from exc
