"""Los tokens de la pasarela: el alta, la baja, la rotación y la lista, sobre `tokens.json`.

Lo usan el instalador (el primer iPhone) y `hehermes-dispositivo` (los demás); lo lee la pasarela
(`pasarela.Tokens`), que lo vuelve a mirar en cuanto cambia. Del token solo se guarda su SHA-256: quien lea el fichero
no puede conectarse, y el QR no se puede volver a pintar (otro QR es otro token, con `rotar`).

El formato::

    {"v": 1, "tokens": [{"nombre": "mi-iphone", "sha256": "<hex>", "alta": "<ISO 8601>", "rotado": "<ISO 8601>"}]}
"""

from __future__ import annotations

import datetime
import json
import os
import re
import stat
import tempfile

from .pasarela import _es_base64url, hash_token, token_nuevo

NOMBRE_VALIDO = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
DIRECCION_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")


def _ahora():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def leer(ruta: str) -> dict:
    """Lo que hay, o un registro vacío si no existe. Uno que no se entiende para todo: no se pisa sin saber qué es."""
    if os.path.islink(ruta):
        raise ValueError("%s es un enlace: no lo sigo" % ruta)
    try:
        with open(ruta, "rb") as f:
            datos = json.loads(f.read())
    except FileNotFoundError:
        return {"v": 1, "tokens": []}
    except (OSError, ValueError) as error:
        raise ValueError("no entiendo %s (%s): no lo toco" % (ruta, error))
    if not isinstance(datos, dict) or datos.get("v") != 1 or not isinstance(datos.get("tokens"), list):
        raise ValueError("%s no es de una versión que conozca: no lo toco" % ruta)
    return datos


def guardar(ruta: str, datos: dict, modo: int | None = None, uid: int | None = None, gid: int | None = None) -> None:
    """Atómico, al lado y renombrado: la pasarela nunca lee uno a medias. Conserva el dueño, el grupo y el modo del que
    había (con root, el grupo es `hh-pasarela`, que lo lee); uno nuevo sale 0600 salvo que se diga otra cosa."""
    carpeta = os.path.dirname(ruta)
    try:
        antes = os.lstat(ruta)
    except FileNotFoundError:
        antes = None
    if antes is not None and not stat.S_ISREG(antes.st_mode):
        raise ValueError("%s no es un fichero normal: no lo toco" % ruta)
    fd, temporal = tempfile.mkstemp(dir=carpeta, prefix=".tokens-")
    try:
        if antes is not None:
            modo = stat.S_IMODE(antes.st_mode) if modo is None else modo
            uid = antes.st_uid if uid is None else uid
            gid = antes.st_gid if gid is None else gid
        os.fchmod(fd, 0o600 if modo is None else modo)
        if uid is not None and gid is not None and (uid, gid) != (os.getuid(), os.getgid()):
            os.fchown(fd, uid, gid)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(datos, indent=2, ensure_ascii=False) + "\n")
        os.replace(temporal, ruta)
    except BaseException:
        if os.path.exists(temporal):
            os.unlink(temporal)
        raise


def _buscar(datos, nombre):
    return next((t for t in datos["tokens"] if t.get("nombre") == nombre), None)


def alta(ruta: str, nombre: str, ahora: str | None = None) -> str:
    """Un token nuevo para `nombre`. Devuelve el token: es la única vez que existe fuera del iPhone."""
    if not isinstance(nombre, str) or not NOMBRE_VALIDO.match(nombre):
        raise ValueError("el nombre tiene que ser de minúsculas, números y guiones, hasta 31 (no «%s»)" % nombre)
    datos = leer(ruta)
    if _buscar(datos, nombre):
        raise ValueError("ya hay un iPhone «%s» en la pasarela; dalo de baja antes, o usa rotar" % nombre)
    token = token_nuevo()
    datos["tokens"].append({"nombre": nombre, "sha256": hash_token(token), "alta": ahora or _ahora()})
    guardar(ruta, datos)
    return token


def baja(ruta: str, nombre: str) -> bool:
    datos = leer(ruta)
    entrada = _buscar(datos, nombre)
    if entrada is None:
        return False
    datos["tokens"].remove(entrada)
    guardar(ruta, datos)
    return True


def rotar(ruta: str, nombre: str, ahora: str | None = None) -> str:
    datos = leer(ruta)
    entrada = _buscar(datos, nombre)
    if entrada is None:
        raise ValueError("no hay ningún iPhone «%s» en la pasarela" % nombre)
    token = token_nuevo()
    entrada["sha256"] = hash_token(token)
    entrada["rotado"] = ahora or _ahora()
    guardar(ruta, datos)
    return token


def lista(ruta: str) -> list:
    return [{k: v for k, v in t.items() if k != "sha256"} for t in leer(ruta)["tokens"]]


def texto_qr(direccion: str, puerto: int, huella: str, token: str) -> str:
    """El texto del QR del alta por SSH (server/API-CONTRACT.md, §12.1). Lleva el token: solo en un terminal."""
    if not isinstance(direccion, str) or not DIRECCION_VALIDA.match(direccion):
        raise ValueError("dirección no válida para el QR: %r" % (direccion,))
    if not isinstance(puerto, int) or isinstance(puerto, bool) or not 0 < puerto < 65536:
        raise ValueError("puerto no válido para el QR: %r" % (puerto,))
    if not _es_base64url(huella) or not _es_base64url(token):
        raise ValueError("la huella o el token no son base64url de 32 bytes")
    return "hehermes-tls:1?h=%s&p=%d&f=%s&t=%s" % (direccion, puerto, huella, token)
