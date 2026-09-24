"""Lo que el relé acepta de un vigía, y por qué no deja pasar nada más.

La petición: ``{token, entorno, prioridad, payload, colapso?, caduca?}``, y nada más. El relé no recibe ni la sesión ni
el tipo del aviso: no los necesita para mandarlo, y lo que no recibe no puede guardarlo ni filtrarlo.

**El payload tiene que ser el sobre y nada más.** El relé no puede leer el sobre (va cifrado con la clave del iPhone),
pero sí puede comprobar que no viaja nada fuera de él: solo ``aps`` y ``c``; en ``aps``, el texto de reserva exacto y
las pocas claves que usa la app; y ``c`` con la forma de un sobre. Así, un vigía roto que pusiera el texto de una
respuesta en ``alert`` —o en cualquier otro sitio— no llega a Apple en claro: se rechaza aquí. Tampoco pasa ``badge``,
que es de la extensión. Y el hilo y el colapso tienen que ser lo que calcula el vigía, 32 caracteres hexadecimales de
un HMAC: un id de sesión o un texto en su lugar se rechazan.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

from ..comun import ENTORNOS, PATRON_TOKEN, ErrorHTTP

CAMPOS = frozenset({"token", "entorno", "prioridad", "payload", "colapso", "caduca"})
PRIORIDADES = (5, 10)
# El tope de Apple para un push normal.
TOPE_CARGA = 4096
CLAVES_APS = frozenset({"alert", "mutable-content", "thread-id", "sound", "interruption-level"})
# `critical` pide un permiso especial de Apple que la app no tiene; se queda fuera.
NIVELES = frozenset({"passive", "active", "time-sensitive"})
# El hilo y el colapso: 32 caracteres hexadecimales en minúsculas, lo que da `vigia.avisos.hilo` y `colapso`.
PATRON_HMAC = re.compile(r"[0-9a-f]{32}")
CADUCA_MAXIMA = 30 * 86400


@dataclass(frozen=True)
class AvisoValidado:
    token: str
    entorno: str
    prioridad: int
    carga: bytes
    colapso: str | None
    caduca: int | None


def _rechazo(motivo: str) -> ErrorHTTP:
    return ErrorHTTP(400, "peticion_invalida", motivo)


def _es_entero(valor) -> bool:
    # En Python `True` es un entero: aquí no cuenta como uno.
    return isinstance(valor, int) and not isinstance(valor, bool)


def _base64(valor, nombre: str) -> bytes:
    if not isinstance(valor, str):
        raise _rechazo(f"c.{nombre} tiene que ser base64")
    try:
        return base64.b64decode(valor.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise _rechazo(f"c.{nombre} no es base64") from None


def validar_carga(carga, reservas: list) -> bytes:
    """El payload ya comprobado, en los bytes que se le mandan a Apple."""
    if not isinstance(carga, dict) or set(carga) != {"aps", "c"}:
        raise _rechazo("el payload tiene que traer «aps» y «c», y nada más")
    aps, sobre = carga["aps"], carga["c"]
    if not isinstance(aps, dict) or not set(aps) <= CLAVES_APS:
        raise _rechazo("aps trae claves que el relé no deja pasar")
    alerta = aps.get("alert")
    if (not isinstance(alerta, dict) or set(alerta) != {"title", "body"}
            or (alerta.get("title"), alerta.get("body")) not in reservas):
        raise _rechazo("aps.alert tiene que ser el texto de reserva, sin nada de la conversación")
    if not (_es_entero(aps.get("mutable-content")) and aps["mutable-content"] == 1):
        raise _rechazo("aps.mutable-content tiene que ser 1: sin él la extensión no abre el sobre")
    hilo = aps.get("thread-id")
    if hilo is not None and not (isinstance(hilo, str) and PATRON_HMAC.fullmatch(hilo)):
        raise _rechazo("aps.thread-id tiene que ser el HMAC del hilo (32 hexadecimales), no un id de sesión")
    if "sound" in aps and aps["sound"] != "default":
        raise _rechazo("aps.sound solo puede ser «default»: el tono lo elige la extensión")
    if "interruption-level" in aps and aps["interruption-level"] not in NIVELES:
        raise _rechazo("aps.interruption-level no es válido")
    if not isinstance(sobre, dict) or set(sobre) != {"v", "n", "t"}:
        raise _rechazo("c tiene que ser un sobre {v, n, t}")
    if not (_es_entero(sobre["v"]) and 1 <= sobre["v"] <= 255):
        raise _rechazo("c.v no es una versión")
    if len(_base64(sobre["n"], "n")) != 12:
        raise _rechazo("c.n tiene que medir 12 bytes")
    if len(_base64(sobre["t"], "t")) < 16:
        raise _rechazo("c.t no llega ni a la etiqueta")
    datos = json.dumps(carga, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(datos) > TOPE_CARGA:
        raise ErrorHTTP(413, "payload_demasiado_grande", f"el payload pasa de {TOPE_CARGA} bytes")
    return datos


def validar(peticion: dict, reservas: list) -> AvisoValidado:
    sobrantes = set(peticion) - CAMPOS
    if sobrantes:
        raise _rechazo("el relé no recibe " + ", ".join(f"«{campo}»" for campo in sorted(sobrantes)[:5]))
    token = peticion.get("token")
    if not isinstance(token, str) or not PATRON_TOKEN.fullmatch(token):
        raise _rechazo("token no válido (hexadecimal en minúsculas)")
    entorno = peticion.get("entorno")
    if entorno not in ENTORNOS:
        raise _rechazo("entorno no válido («sandbox» o «production»)")
    prioridad = peticion.get("prioridad", 10)
    if not _es_entero(prioridad) or prioridad not in PRIORIDADES:
        raise _rechazo("prioridad no válida (5 o 10)")
    colapso = peticion.get("colapso")
    if colapso is not None and not (isinstance(colapso, str) and PATRON_HMAC.fullmatch(colapso)):
        raise _rechazo("colapso no válido (el HMAC del suceso, 32 hexadecimales)")
    caduca = peticion.get("caduca")
    if caduca is not None and not (_es_entero(caduca) and 0 <= caduca <= CADUCA_MAXIMA):
        raise _rechazo("caduca no válido (segundos, hasta 30 días)")
    carga = validar_carga(peticion.get("payload"), reservas)
    return AvisoValidado(token, entorno, prioridad, carga, colapso, caduca)
