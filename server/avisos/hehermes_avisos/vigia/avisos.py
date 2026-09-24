"""A quién se avisa y con qué sobre. Funciones puras: lo que entra es un aviso y un dispositivo, lo que sale es la
petición al relé, lista para mandar.

El push es el que espera la extensión de la app (``ExtensionDeAvisos``, ``ComposicionDelAviso``)::

    {"aps": {"alert": {"title": "Hermes", "body": "Tienes una respuesta nueva"},
             "mutable-content": 1, "thread-id": "<hilo>", "sound": "default", "interruption-level": "time-sensitive"},
     "c": {"v": 1, "n": "…", "t": "…"}}

- ``alert`` es siempre el texto de reserva, neutro: es lo que ven Apple y el relé, y lo que enseña el iPhone si la
  extensión no llega a descifrar. Lo de verdad va dentro de ``c``.
- ``thread-id`` y el ``apns-collapse-id`` son HMAC con una subclave de la clave del iPhone (``K_ids``, con HKDF:
  ``hilo``, ``colapso``): agrupan y colapsan igual, pero no dicen de qué conversación son a quien los ve en claro.
- ``sound`` solo con el sonido activado; ``interruption-level`` solo en las aprobaciones; **nunca** ``badge``: el número
  del icono lo pone la extensión, que es la que sabe qué hay sin leer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from .. import cifrado, texto
from .almacen import Dispositivo

TITULO_DE_RESERVA = "Hermes"
CUERPO_DE_RESERVA = "Tienes una respuesta nueva"
TIPOS = ("respuesta", "aprobacion", "segundo-plano", "error", "prueba")

# Prioridad de APNs: 10 es «ahora». Existe la 5 («cuando le venga bien al iPhone»), pero Apple avisa de que esos pueden
# agruparse, retrasarse o no entregarse, y aquí todo lo que se avisa es algo que Daniel está esperando. El relé acepta
# las dos.
PRIORIDAD = 10

# Lo que Apple guarda un aviso si el iPhone no está localizable (`apns-expiration`), salvo las aprobaciones y la prueba,
# que tienen el suyo. Sin él, Apple lo guarda lo que quiera: una respuesta que llega al día siguiente ya no es un aviso.
CADUCA_DE_SERIE = 3600

TITULO_PRUEBA = "Aviso de prueba"
TEXTO_PRUEBA = "Si lees esto, los avisos llegan de tu servidor a este iPhone, cifrados de punta a punta."

# Lo que se decide de un aviso para un iPhone.
ENVIAR = "enviar"
DESCARTAR = "descartar"
# Todavía no se sabe: la app parece delante, pero lo que se avisa llegó después de su último latido.
ESPERAR = "esperar"


@dataclass(frozen=True)
class Aviso:
    tipo: str
    # La sesión del api_server, o `None` si no es de ninguna conversación (la prueba).
    sesion: str | None
    titulo: str
    texto: str
    # Cuándo pasó lo que se avisa: con él se sabe si la app estaba delante y ya lo avisó ella.
    instante: float
    # Identifica el suceso dentro de su sesión («respuesta:<fila>», «aprobacion:<request_id>»…). Con ella se recuerda
    # lo que el relé ya aceptó, para no volver a mandarlo.
    clave: str
    # Segundos que vale el aviso en APNs si el iPhone no está localizable, o `None` para lo de serie (ver
    # `peticion_al_rele`).
    caduca: int | None = None
    # De qué sale el `apns-collapse-id`, si no es de `clave`: las aprobaciones de una conversación colapsan entre sí
    # (una nueva deja vieja a la anterior), aunque cada una sea un suceso distinto.
    colapsa_con: str | None = None

    @property
    def identidad(self) -> str:
        return f"{self.sesion or ''}\n{self.clave}"


def aviso_de_prueba(ahora: float, caduca: int) -> Aviso:
    return Aviso(tipo="prueba", sesion=None, titulo=TITULO_PRUEBA, texto=TEXTO_PRUEBA, instante=ahora,
                 clave="prueba", caduca=caduca)


def decidir(aviso: Aviso, dispositivo: Dispositivo, ahora: float) -> str:
    """Qué hacer con este aviso para este iPhone: ``ENVIAR``, ``DESCARTAR`` o ``ESPERAR``.

    - El de prueba va siempre: lo pide Daniel desde la app, que está delante, y quiere verlo.
    - Los demás no van si su tipo está apagado, si el chat está silenciado o si la app estaba delante cuando pasó: eso
      ya lo avisó ella.
    - Con la app delante ahora, lo de antes de ponerse delante tampoco: lo enseña ella al abrir la conversación.
    - Pero lo que llegó después de su último latido, con la app todavía dentro del plazo que dio, se **espera**: si
      llega otro latido, lo vio; si el plazo se acaba sin ninguno, la app se había ido sin poder decirlo (iOS la
      suspende en segundos, y la VPN puede estar caída justo entonces) y se avisa. Antes eso se daba por visto y se
      perdía.
    """
    if aviso.tipo == "prueba":
        return ENVIAR
    if not dispositivo.ajustes.avisa_de(aviso.tipo) or dispositivo.ajustes.silenciada(aviso.sesion):
        return DESCARTAR
    if dispositivo.lo_vio(aviso.instante):
        return DESCARTAR
    if dispositivo.delante(ahora):
        return DESCARTAR if aviso.instante < dispositivo.delante_desde else ESPERAR
    return ENVIAR


def contenido(aviso: Aviso, vista_previa: str) -> bytes:
    """Lo que va cifrado: ``{"sesion", "texto", "tipo", "titulo"}``, con las claves ordenadas y sin espacios.

    **Se manda lo que se va a enseñar y nada más.** Con «solo el nombre», la extensión enseña el título y una frase fija
    en lugar de la respuesta; con «nunca», ni el título. Lo que no se enseña no viaja, aunque vaya cifrado: si la
    extensión recibe un texto vacío pone la frase de su tipo (``ComposicionDelAviso.textoNeutro``), que es lo mismo que
    haría con la vista previa puesta.
    """
    titulo = aviso.titulo if vista_previa in ("siempre", "nombre") else ""
    cuerpo = aviso.texto if vista_previa == "siempre" else ""
    return json.dumps({"tipo": aviso.tipo, "sesion": aviso.sesion or "",
                       "titulo": texto.recortar(titulo, texto.TOPE_TITULO),
                       "texto": texto.recortar(cuerpo, texto.TOPE_TEXTO)},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


# La subclave de los identificadores que viajan en claro (hilo y colapso): K_ids = HKDF-SHA256(K, sal vacía, este info).
INFO_IDS = "hehermes-avisos ids v1"


def clave_de_ids(clave: bytes) -> bytes:
    """``K_ids``, la subclave del hilo y del colapso: no se usa para ellos la clave del sobre (``cifrado.subclave``)."""
    return cifrado.subclave(clave, INFO_IDS)


def _hmac(clave_ids: bytes, mensaje: str) -> str:
    """HMAC-SHA256 de ``mensaje`` en UTF-8 con ``K_ids``, en hexadecimal en minúsculas, los 32 primeros caracteres."""
    return hmac.new(clave_ids, mensaje.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def hilo(clave: bytes, sesion: str) -> str:
    """El ``thread-id`` de una conversación para un iPhone: HMAC-SHA256 con ``K_ids`` (la subclave de su clave) de
    ``"hilo:" + sesión``, en hexadecimal, los 32 primeros caracteres.

    iOS agrupa por hilo, así que tiene que ser el mismo para todos los avisos de una conversación. Pero viaja en claro, y
    el id de la sesión lleva su fecha (``api_<epoch>_…``): Apple y el relé verían qué avisos son de la misma
    conversación y desde cuándo existe. Así solo ven 32 caracteres que cambian de un iPhone a otro. La app, que tiene la
    clave, calcula lo mismo para reagrupar y abrir la conversación de un aviso que no pudo descifrar.
    """
    return _hmac(clave_de_ids(clave), "hilo:" + sesion)


def carga(aviso: Aviso, dispositivo: Dispositivo, nonce: bytes | None = None) -> dict:
    """El push entero para este iPhone, con el sobre cifrado con su clave y un nonce nuevo."""
    aps: dict = {"alert": {"title": TITULO_DE_RESERVA, "body": CUERPO_DE_RESERVA}, "mutable-content": 1}
    if aviso.sesion:
        # iOS agrupa por hilo: los avisos de un chat van juntos, como en Mensajes. La prueba no es de ningún chat.
        aps["thread-id"] = hilo(dispositivo.clave, aviso.sesion)
    if dispositivo.ajustes.sonido == "mensajes":
        aps["sound"] = "default"
    if aviso.tipo == "aprobacion":
        # Lo único del tipo que viaja en claro, y es a propósito: sin él, iOS no deja que la aprobación atraviese un
        # modo de concentración, que es para lo que es urgente.
        aps["interruption-level"] = "time-sensitive"
    sobre = cifrado.sellar(contenido(aviso, dispositivo.ajustes.vista_previa), dispositivo.clave, nonce)
    return {"aps": aps, "c": sobre}


def colapso(aviso: Aviso, clave: bytes) -> str:
    """El ``apns-collapse-id``: dos pushes con el mismo se enseñan como uno.

    HMAC-SHA256 con ``K_ids`` (la subclave de la clave del iPhone, como el hilo) de ``"colapso:" + sesión + "\\n" +
    suceso``, en hexadecimal, los 32 primeros caracteres; la sesión va vacía en la prueba. Sale del suceso, no del envío: si el mismo se manda dos veces (un
    reintento cuyo primer intento sí llegó, un reinicio entre mandar y apuntarlo), el iPhone enseña uno. Las
    aprobaciones de una conversación colapsan entre sí («aprobacion»), porque una nueva deja vieja a la anterior: el
    turno está parado esperando solo a la última. Con HMAC, como el hilo, no dice nada a quien lo ve en claro.
    """
    return _hmac(clave_de_ids(clave), "colapso:" + (aviso.sesion or "") + "\n" + (aviso.colapsa_con or aviso.clave))


def peticion_al_rele(aviso: Aviso, dispositivo: Dispositivo, nonce: bytes | None = None) -> dict:
    """Lo que ve el relé: el token, el entorno, la prioridad, el push (con el sobre cifrado) y su colapso y caducidad.
    Ni la sesión ni el tipo: no le hacen falta para nada."""
    caduca = aviso.caduca if aviso.caduca is not None else CADUCA_DE_SERIE
    return {"token": dispositivo.token, "entorno": dispositivo.entorno, "prioridad": PRIORIDAD,
            "payload": carga(aviso, dispositivo, nonce), "colapso": colapso(aviso, dispositivo.clave),
            "caduca": int(caduca)}
