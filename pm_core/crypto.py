import base64
import json
from typing import Any

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

FORMAT_VERSION = 2
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
PBKDF2_ITERATIONS = 600_000


class CryptoError(ValueError):
    """Raised when encrypted payloads cannot be processed safely."""


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if not password:
        raise CryptoError("La clave maestra no puede estar vacía.")
    return PBKDF2(password, salt, dkLen=KEY_BYTES, count=iterations, hmac_hash_module=SHA256)


def encrypt_data(data: list[dict[str, str]], password: str) -> dict[str, Any]:
    salt = get_random_bytes(SALT_BYTES)
    nonce = get_random_bytes(NONCE_BYTES)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "version": FORMAT_VERSION,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "data": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_payload(payload: dict[str, Any], password: str) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        raise CryptoError("El archivo cifrado no tiene un formato válido.")
    if payload.get("version") != FORMAT_VERSION:
        raise CryptoError("Versión de archivo no soportada.")
    required = ("salt", "nonce", "tag", "data", "iterations")
    missing = [field for field in required if field not in payload]
    if missing:
        raise CryptoError(f"El archivo cifrado está incompleto: faltan {', '.join(missing)}.")

    try:
        salt = base64.b64decode(payload["salt"], validate=True)
        nonce = base64.b64decode(payload["nonce"], validate=True)
        tag = base64.b64decode(payload["tag"], validate=True)
        ciphertext = base64.b64decode(payload["data"], validate=True)
        iterations = int(payload["iterations"])
    except (TypeError, ValueError) as exc:
        raise CryptoError("El archivo cifrado contiene datos inválidos.") from exc

    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise CryptoError("La clave es incorrecta o el archivo fue modificado.") from exc

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError("El contenido descifrado no es JSON válido.") from exc
    if not isinstance(data, list):
        raise CryptoError("El contenido descifrado no tiene una lista de credenciales.")
    return data
