"""Lo que el relé acepta de un vigía, y por qué no deja pasar nada más.

La petición: ``{token, entorno, prioridad, payload, colapso?, caduca?}``, y nada más. El relé no recibe ni la sesión ni
el tipo del aviso: no los necesita para mandarlo, y lo que no recibe no puede guardarlo ni filtrarlo.

**El payload tiene que ser el sobre y nada más.** El relé no puede leer el sobre (va cifrado con la clave del iPhone),
pero sí puede comprobar que no viaja nada fuera de él: solo ``aps`` y ``c``; en ``aps``, el texto de reserva exacto y
las pocas claves que usa la app; y ``c`` con la forma de un sobre. Así, un vigía roto que pusiera el texto de una
respuesta en ``alert`` —o en cualquier otro sitio— no llega a Apple en claro: se rechaza aquí. Tampoco pasa ``badge``,
que es de la extensión. Y el hilo y el colapso tienen que ser lo que calcula el vigía, 32 caracteres hexadecimales de
un HMAC: un id de sesión o un texto en su lugar se rechazan.

**Las Actividades en Vivo** (``tipo: "liveactivity"``, avisos 1.6.7, contrato §20) siguen la misma regla. Se autorizan
con el ``token`` del iPhone, como cualquier aviso —el permiso de App Attest y el límite son los suyos—, y van al token
de la actividad (``actividad``). Su payload es solo ``aps`` con lo que pide Apple para actualizarla o acabarla, y en su
``content-state`` solo números, la fase y el sobre: el paso y la respuesta viajan cifrados, y nada en claro pasa.

**El push de inicio** (``event: "start"``, contrato §20.5) es la única excepción, y la más vigilada: Apple lo exige con ``alert``,
``attributes-type`` y ``attributes``, que viajan sin cifrar por sus servidores. Por eso aquí es una lista cerrada: el tipo
de atributos solo puede ser ``TurnoEnVivo``, el ``alert`` es un texto fijo (no el de una conversación), y en los atributos
lo privado (la conversación, el agente y su nombre) va vacío porque va dentro del sobre ``c``. ``update`` y ``end`` no pueden
llevar ninguna de esas claves.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

from ..comun import ENTORNOS, PATRON_TOKEN, ErrorHTTP

CAMPOS = frozenset({"token", "entorno", "prioridad", "payload", "colapso", "caduca", "tipo", "actividad"})
TIPOS = ("alert", "liveactivity")
# Lo que lleva el ``aps`` de una Actividad en Vivo, y lo único que puede llevar su ``content-state``.
CLAVES_APS_ACTIVIDAD = frozenset({"timestamp", "event", "content-state", "dismissal-date", "stale-date"})
CLAVES_ESTADO = frozenset({"fase", "subagentes", "run", "vuelta", "fin", "c"})
EVENTOS = ("update", "end", "start")
# Lo que lleva el ``aps`` de un push de inicio: todas, ni una más ni una menos. Sin ``dismissal-date`` ni ``stale-date``.
CLAVES_APS_INICIO = frozenset({"timestamp", "event", "content-state", "attributes-type", "attributes", "alert",
                               "input-push-token"})
# El único tipo de atributos que arranca la app (``TurnoEnVivo``), y los campos de ``TurnoEnVivo`` que viajan en su
# push de inicio. ``hilo``, ``perfil`` y ``nombre`` van vacíos en claro: lo suyo está dentro de ``c``.
TIPO_DE_ATRIBUTOS = "TurnoEnVivo"
CLAVES_ATRIBUTOS = frozenset({"hilo", "perfil", "nombre", "color", "expresion", "inicio", "c"})
PRIVADOS_DE_LOS_ATRIBUTOS = ("hilo", "perfil", "nombre")
# El ``alert`` que Apple exige al arrancar una actividad: fijo y sin datos de nadie. Lo repite el vigía
# (``vigia.actividades.ALERTA_DE_INICIO``); una prueba comprueba que son el mismo.
ALERTA_DE_INICIO = ("Hermes", "Hermes está trabajando")
# La fase es una palabra (``FaseDeLaActividad`` de la app), y el run, el id de Hermes.
PATRON_FASE = re.compile(r"[a-z]{1,20}")
PATRON_RUN = re.compile(r"[A-Za-z0-9_-]{1,80}")
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
    tipo: str = "alert"
    # El token de la Actividad en Vivo a la que va; ``None`` en un aviso.
    actividad: str | None = None


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
    _validar_sobre(sobre)
    return _en_bytes(carga)


def _validar_sobre(sobre) -> None:
    if not isinstance(sobre, dict) or set(sobre) != {"v", "n", "t"}:
        raise _rechazo("c tiene que ser un sobre {v, n, t}")
    if not (_es_entero(sobre["v"]) and 1 <= sobre["v"] <= 255):
        raise _rechazo("c.v no es una versión")
    if len(_base64(sobre["n"], "n")) != 12:
        raise _rechazo("c.n tiene que medir 12 bytes")
    if len(_base64(sobre["t"], "t")) < 16:
        raise _rechazo("c.t no llega ni a la etiqueta")


def _es_instante(valor) -> bool:
    return (_es_entero(valor) or isinstance(valor, float)) and 0 <= valor < 10 ** 11


def _validar_inicio(aps: dict) -> None:
    """Lo que solo lleva el push de inicio, que Apple lee en claro: el tipo de atributos, los atributos, la alerta y el
    ``input-push-token``. Cualquier cosa fuera de la lista cerrada se rechaza."""
    if aps["attributes-type"] != TIPO_DE_ATRIBUTOS:
        raise _rechazo(f"attributes-type solo puede ser «{TIPO_DE_ATRIBUTOS}»")
    atributos = aps["attributes"]
    if not isinstance(atributos, dict) or set(atributos) != CLAVES_ATRIBUTOS:
        raise _rechazo("attributes tiene que traer " + ", ".join(sorted(CLAVES_ATRIBUTOS)) + ", y nada más")
    for campo in PRIVADOS_DE_LOS_ATRIBUTOS:
        if atributos[campo] != "":
            raise _rechazo(f"attributes.{campo} tiene que ir vacío: lo suyo va dentro de «c»")
    for campo in ("color", "expresion"):
        if not (isinstance(atributos[campo], str) and PATRON_FASE.fullmatch(atributos[campo])):
            raise _rechazo(f"attributes.{campo} tiene que ser una palabra")
    if not _es_instante(atributos["inicio"]):
        raise _rechazo("attributes.inicio tiene que ser un instante en segundos")
    _validar_sobre(atributos["c"])
    alerta = aps["alert"]
    if (not isinstance(alerta, dict) or set(alerta) != {"title", "body"}
            or (alerta["title"], alerta["body"]) != ALERTA_DE_INICIO):
        raise _rechazo("aps.alert tiene que ser el texto fijo de un inicio, sin nada de la conversación")
    # Sin él, desde iOS 18 la actividad nace sin token de actualización y nadie la podría mover.
    if not (_es_entero(aps["input-push-token"]) and aps["input-push-token"] == 1):
        raise _rechazo("aps.input-push-token tiene que ser 1")


def validar_carga_de_actividad(carga) -> bytes:
    """El payload de una Actividad en Vivo ya comprobado: ``aps`` y nada más; en él, lo que pide Apple; y en su
    ``content-state``, la fase, los números, el run y el sobre. Ni una alerta ni un texto en claro."""
    if not isinstance(carga, dict) or set(carga) != {"aps"}:
        raise _rechazo("el payload de una actividad tiene que traer «aps», y nada más")
    aps = carga["aps"]
    if not isinstance(aps, dict):
        raise _rechazo("aps tiene que ser un objeto")
    if aps.get("event") not in EVENTOS:
        raise _rechazo("aps.event tiene que ser «update», «end» o «start»")
    if aps["event"] == "start":
        if set(aps) != CLAVES_APS_INICIO:
            raise _rechazo("un inicio lleva exactamente " + ", ".join(sorted(CLAVES_APS_INICIO)))
        _validar_inicio(aps)
    elif not set(aps) <= CLAVES_APS_ACTIVIDAD:
        raise _rechazo("aps trae claves que el relé no deja pasar en una actividad")
    if not _es_entero(aps.get("timestamp")) or not _es_instante(aps["timestamp"]):
        raise _rechazo("aps.timestamp tiene que ser un instante en segundos")
    for fecha in ("dismissal-date", "stale-date"):
        if fecha in aps and not (_es_entero(aps[fecha]) and _es_instante(aps[fecha])):
            raise _rechazo(f"aps.{fecha} tiene que ser un instante en segundos")
    estado = aps.get("content-state")
    if (not isinstance(estado, dict) or not set(estado) <= CLAVES_ESTADO
            or not {"fase", "subagentes", "vuelta"} <= set(estado)):
        raise _rechazo("aps.content-state trae claves que el relé no deja pasar, o le faltan fase, subagentes y vuelta")
    if not (isinstance(estado["fase"], str) and PATRON_FASE.fullmatch(estado["fase"])):
        raise _rechazo("content-state.fase tiene que ser una palabra")
    if not (_es_entero(estado["subagentes"]) and 0 <= estado["subagentes"] <= 999):
        raise _rechazo("content-state.subagentes tiene que ser un número")
    if not (_es_entero(estado["vuelta"]) and 0 <= estado["vuelta"] < 2 ** 31):
        raise _rechazo("content-state.vuelta tiene que ser un número")
    if estado.get("run") is not None and not (isinstance(estado["run"], str) and PATRON_RUN.fullmatch(estado["run"])):
        raise _rechazo("content-state.run no es un id de run")
    if estado.get("fin") is not None and not _es_instante(estado["fin"]):
        raise _rechazo("content-state.fin tiene que ser un instante en segundos")
    if estado.get("c") is not None:
        _validar_sobre(estado["c"])
    return _en_bytes(carga)


def _en_bytes(carga: dict) -> bytes:
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
    tipo = peticion.get("tipo", "alert")
    if tipo not in TIPOS:
        raise _rechazo("tipo no válido («alert» o «liveactivity»)")
    if tipo == "liveactivity":
        actividad = peticion.get("actividad")
        if not isinstance(actividad, str) or not PATRON_TOKEN.fullmatch(actividad):
            raise _rechazo("actividad no válida (el token de la actividad, hexadecimal en minúsculas)")
        return AvisoValidado(token, entorno, prioridad, validar_carga_de_actividad(peticion.get("payload")), colapso,
                             caduca, tipo, actividad)
    if "actividad" in peticion:
        raise _rechazo("un aviso no lleva «actividad»")
    carga = validar_carga(peticion.get("payload"), reservas)
    return AvisoValidado(token, entorno, prioridad, carga, colapso, caduca)
