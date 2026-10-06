"""Cuándo lanza el vigía el turno que contesta a la entrega de un subagente. Funciones puras: sin red ni reloj.

**Por qué el vigía.** En el api_server, cuando un subagente en segundo plano acaba, Hermes solo escribe la entrega en el
historial (``display_kind: async_delegation_complete``) y **no lanza ningún turno**: el cliente es dueño del turno
siguiente (``gateway/wake.py`` del VPS, #85957; no hay ajuste que lo cambie). La app lo lanza cuando está viva
(``⟦hehermes:continuar⟧``, contrato §6), pero con la pantalla apagada iOS la suspende, y un subagente puede tardar
horas (``delegation.child_timeout_seconds: 7200``). El 2026-09-27, en una conversación de Daniel, la entrega llegó a
las 02:36 y nadie la contestó hasta que Daniel preguntó «¿cómo vas?» a las 08:43. El vigía corre siempre y ya lee ese
historial.

**Qué lanza.** El mismo turno que la app (``TEXTO_CONTINUAR``), con la misma ``Idempotency-Key``
(``continuar-<delegation_id>`` de la entrega más reciente sin atender): la app lo reconoce en el historial como una
continuación, no lo pinta como mensaje de Daniel, y si la app y el vigía llegaran a la vez el servidor no crea dos turnos
(la misma clave da el mismo run, o un 409). Con la frase de antes (``TEXTO_CONTINUAR_ANTIGUO``) mientras haya dado de
alta un iPhone con una app que no conoce la de ahora (``texto_de_la_continuacion``).

**Cuándo no**, que es casi todo:

- si la entrega ya está **atendida**: detrás de ella empezó un turno (un mensaje de Daniel o una continuación, suya o
  de la app). Ese turno la tiene en su contexto;
- durante la **gracia**: los primeros segundos tras la entrega son de la app, que si está delante la contesta en 5-30 s
  con las instrucciones y el esfuerzo de la conversación, que el vigía no conoce;
- si hay un **turno en marcha** (el último turno aún no tiene respuesta): la entrega le llegó a mitad y se contesta
  cuando acabe. Uno que lleva más de ``VIDA_DE_UN_TURNO`` sin respuesta se da por muerto;
- si la entrega es **vieja** (``antiguedad_maxima``): tras un reinicio largo del vigía, no se despiertan conversaciones
  de ayer;
- si la **cadena** es larga: Hermes puede volver a delegar al recibir la entrega, y eso daría otra entrega y otra
  continuación sin fin. Tras ``cadena_maxima`` continuaciones seguidas sin un mensaje de Daniel en medio, el vigía se
  para y solo avisa de la entrega, como antes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import deteccion

LANZAR = "lanzar"
ESPERAR = "esperar"
# La entrega no la contesta el vigía (la cadena es larga): se avisa de ella como antes y la contesta la app al abrir.
RENUNCIAR = "renunciar"

# Lo que dura como mucho un turno en el VPS (`agent.gateway_timeout: 7200`): un turno sin respuesta más viejo que esto
# no está en marcha, se murió.
VIDA_DE_UN_TURNO = 7200.0

_DELEGACION = re.compile(r"\[ASYNC DELEGATION BATCH COMPLETE\s*[—-]+\s*(deleg_[A-Za-z0-9_-]{1,64})\]")


@dataclass(frozen=True)
class ReglasDeEntrega:
    """Cuándo contesta el vigía una entrega: tras ``gracia`` segundos, que son de la app; no si tiene más de
    ``antiguedad_maxima``; y no tras ``cadena_maxima`` continuaciones seguidas (``[entregas]`` de ``vigia.ini``)."""

    gracia: float = 60.0
    antiguedad_maxima: float = 10800.0
    cadena_maxima: int = 3


@dataclass(frozen=True)
class Entrega:
    """Lo que el vigía decide sobre la entrega sin atender más reciente de una conversación."""

    accion: str
    # La fila de la entrega: si se espera o se lanza, el aviso de «ha terminado un trabajo» no sale.
    fila: int
    delegacion: str

    @property
    def clave(self) -> str:
        """La ``Idempotency-Key`` del turno: la misma que pondría la app (``Motor.revisarDelegaciones``)."""
        return f"continuar-{self.delegacion}"


def texto_de_la_continuacion(dispositivos: list) -> str:
    """Con qué frase lanza el vigía la continuación: la de ahora, sin el nombre de quien hizo la app
    (``deteccion.TEXTO_CONTINUAR``), si todos los iPhone dados de alta la entienden; si no, la de antes.

    **Por qué.** Lo que el vigía lanza lo leen las apps de todos esos iPhone, y una app de la 1.0 (12) o anterior solo
    esconde la frase de antes: la de ahora la pintaría como un mensaje del usuario. Cada app dice en sus ajustes qué
    textos entiende (``Ajustes.textos``, desde la app siguiente a la 1.0 (12)); la que no lo dice es de antes. Sin
    ningún iPhone dado de alta el vigía no lanza nada (``Vigilante.vuelta``), así que da igual."""
    if all(dispositivo.ajustes.entiende_los_textos_sin_nombre for dispositivo in dispositivos):
        return deteccion.TEXTO_CONTINUAR
    return deteccion.TEXTO_CONTINUAR_ANTIGUO


def delegacion_de(fila: dict) -> str | None:
    """El ``delegation_id`` de una fila de entrega, que abre su texto: ``[ASYNC DELEGATION BATCH COMPLETE — deleg_…]``."""
    contenido = fila.get("content")
    if not isinstance(contenido, str):
        return None
    encontrada = _DELEGACION.match(contenido.lstrip())
    return encontrada.group(1) if encontrada else None


def _instante(fila: dict) -> float | None:
    valor = fila.get("timestamp")
    return float(valor) if isinstance(valor, (int, float)) and not isinstance(valor, bool) else None


def _es_respuesta(fila: dict) -> bool:
    """Una respuesta que cierra un turno: texto de ``assistant`` que no es un paso intermedio. Un «Operation
    interrupted» también cierra el suyo."""
    contenido = fila.get("content")
    return (fila.get("role") == "assistant" and isinstance(contenido, str) and bool(contenido.strip())
            and fila.get("finish_reason") != "tool_calls" and fila.get("display_kind") is None)


def decidir(filas: list, *, ahora: float, gracia: float, antiguedad_maxima: float,
            cadena_maxima: int) -> Entrega | None:
    """Qué hacer con la entrega sin atender más reciente de estas filas (las últimas de la conversación), o ``None`` si
    no hay ninguna de la que ocuparse."""
    ordenadas = sorted((f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), int)),
                       key=lambda f: f["id"])
    turnos = [f for f in ordenadas if deteccion.abre_turno(f)]
    ultimo_turno = turnos[-1]["id"] if turnos else None
    sin_atender = [f for f in ordenadas if deteccion.es_entrega(f)
                   and (ultimo_turno is None or ultimo_turno < f["id"])]
    if not sin_atender:
        return None
    entrega = sin_atender[-1]
    delegacion = delegacion_de(entrega)
    instante = _instante(entrega)
    if delegacion is None or instante is None or ahora - instante > antiguedad_maxima:
        return None
    if ahora - instante < gracia:
        return Entrega(ESPERAR, entrega["id"], delegacion)
    if turnos:
        # El último turno empezó antes de la entrega. Si aún no tiene respuesta, sigue en marcha (la entrega le llegó
        # a mitad): se espera a que acabe, salvo que lleve tanto que ya no puede estar vivo.
        turno = turnos[-1]
        contestado = any(_es_respuesta(f) for f in ordenadas if f["id"] > turno["id"])
        empezado = _instante(turno)
        if not contestado and (empezado is None or ahora - empezado < VIDA_DE_UN_TURNO):
            return Entrega(ESPERAR, entrega["id"], delegacion)
    # Las continuaciones seguidas desde el último mensaje de Daniel: cada una es una entrega que Hermes recibió y
    # volvió a delegar.
    cadena = 0
    for turno in reversed(turnos):
        if not deteccion.es_continuacion(turno.get("content") or ""):
            break
        cadena += 1
    if cadena >= cadena_maxima:
        return Entrega(RENUNCIAR, entrega["id"], delegacion)
    return Entrega(LANZAR, entrega["id"], delegacion)
