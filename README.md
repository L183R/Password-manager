# Gestor de Credenciales

Aplicación de escritorio en Python/Tkinter para guardar credenciales en un archivo JSON cifrado.

## Instalación

```bash
python -m pip install -r requirements.txt
```

## Ejecución

```bash
python password_manager.py
```

## Seguridad

- Los archivos nuevos se guardan con AES-256-GCM, que cifra y autentica el contenido.
- La clave de cifrado se deriva desde la clave maestra con PBKDF2-HMAC-SHA256 y una sal aleatoria.
- Cada guardado usa un nonce aleatorio nuevo.
- Las contraseñas sugeridas se generan con `secrets`, no con `random`.

> Importante: si olvidás la clave maestra, no hay mecanismo de recuperación.

## Uso básico

1. Abrí la aplicación.
2. Creá un archivo nuevo o abrí uno existente.
3. Agregá filas con nombre, link, cuenta, contraseña y observaciones.
4. Usá el botón de ojo para mostrar/ocultar una contraseña.
5. Usá el botón de brillo para sugerir una contraseña segura.
6. Usá "Ir y copiar" para abrir el link y copiar la contraseña al portapapeles.
7. Guardá los cambios.

## Pruebas

```bash
pytest
```
