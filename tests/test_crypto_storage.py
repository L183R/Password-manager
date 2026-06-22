import json

import pytest

from pm_core.crypto import CryptoError, decrypt_payload, encrypt_data
from pm_core.passwords import SPECIAL_CHARS, generate_password
from pm_core.storage import load_credentials, save_credentials


def test_encrypt_decrypt_round_trip():
    data = [{"nombre": "Correo", "link": "https://example.com", "cuenta": "user", "contrasena": "secret", "observaciones": "nota"}]
    payload = encrypt_data(data, "clave-maestra")

    assert payload["cipher"] == "AES-256-GCM"
    assert decrypt_payload(payload, "clave-maestra") == data


def test_wrong_password_is_rejected():
    payload = encrypt_data([{"nombre": "Banco"}], "correcta")

    with pytest.raises(CryptoError, match="clave es incorrecta"):
        decrypt_payload(payload, "incorrecta")


def test_tampered_payload_is_rejected():
    payload = encrypt_data([{"nombre": "Banco"}], "correcta")
    payload["data"] = payload["data"][:-2] + "AA"

    with pytest.raises(CryptoError):
        decrypt_payload(payload, "correcta")


def test_save_load_credentials(tmp_path):
    path = tmp_path / "credenciales.json"
    data = [{"nombre": "Git", "link": "https://github.com", "cuenta": "octo", "contrasena": "pwd", "observaciones": ""}]

    save_credentials(str(path), data, "clave")

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["version"] == 2
    assert load_credentials(str(path), "clave") == data


def test_generated_password_has_required_character_groups():
    password = generate_password(32)

    assert len(password) == 32
    assert any(char.islower() for char in password)
    assert any(char.isupper() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(char in SPECIAL_CHARS for char in password)
