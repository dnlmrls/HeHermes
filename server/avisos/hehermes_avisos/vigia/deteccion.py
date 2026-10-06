"""De las filas del historial de una sesión, qué hay que avisar. Funciones puras: sin red, sin reloj, sin base de datos.

**Lo que se puede saber leyendo el historial, y nada más** (el SSE de un run es de un solo uso: si el vigía lo abriera se
lo quitaría a la app, contrato §3):

- **Respuesta**: una fila ``assistant`` con texto que no es un paso intermedio (``finish_reason`` distinto de
  ``tool_calls``) ni un turno parado (``Operation interrupted…``, que la app pinta «Detenido.» y que provocó Daniel).
- **Trabajo en segundo plano terminado**, de dos maneras:
  - la **entrega de un subagente**: una fila ``user`` con ``display_kind: async_delegation_complete`` (contrato §6).
    En el api_server Hermes no lanza el turno siguiente: lo lanza la app cuando está viva o, si no, el vigía
    (``entregas``). Cuando el vigía no la contesta (una cadena de delegaciones sin fin), esta fila es la única señal
    de que el trabajo ha acabado;
  - una respuesta **sin petición de Daniel detrás**: la del turno de continuación que lanza la app
    (``⟦hehermes:continuar⟧``), o una sesión con respuestas y sin ninguna petición.
- Lo que **no** se avisa: la respuesta a una retirada de «Deshacer envío» (la app no la pinta), salvo que un desvío
  entrara en ella, que es cuando la app sí la pinta (``HistorialHermes.mensajes``).

Las aprobaciones pendientes y los errores **no dejan rastro fiable en el historial**; salen del estado del run
(``GET /v1/runs/{id}``), y para eso el vigía necesita el ``run_id``, que solo tiene la app (ver ``vigilante``).

**De una sesión se avisa como mucho una respuesta por vuelta**: la última. Si en cinco segundos Hermes ha contestado
dos veces (un desvío, un reintento), el iPhone quiere leer lo último, no recibir dos banners seguidos.

**Una compactación no es una respuesta nueva.** Hermes compacta en el sitio (contrato §7): la cola de la conversación
vuelve a escribirse con ``id`` nuevos y sus horas de siempre. Por el ``id`` parecerían nuevas, y la última respuesta se
avisaba otra vez si era de hace menos de ``antiguedad_maxima``. Por eso el vigía recuerda también la hora de la última
respuesta que ha visto (``ultima_respuesta``): una respuesta que no es posterior a ella es una copia. Solo cuentan las
respuestas, no los pasos intermedios, que pueden llevar la misma hora que la respuesta de su turno.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import texto

# Los textos que escribe la app al lanzar turnos que no son de Daniel (`Motor.textoContinuar`, `HistorialHermes`). Se
# reconocen como los reconoce la app: con la frase entera, donde la escribe el envío.
MARCA_CONTINUAR = "⟦hehermes:continuar⟧"
# «Al usuario» y no un nombre: la app es de cualquiera, y su Hermes ya sabe quién es.
TEXTO_CONTINUAR = MARCA_CONTINUAR + " Ha llegado el resultado de la tarea en segundo plano. Contesta al usuario con él."
# La de la app 1.0 (12) y anteriores, y la de este vigía hasta la 1.5.5, con el nombre de quien hizo la app: la guardan
# los historiales, la mandan esa app y un vigía de antes, y es la única que esa app sabe esconder. Se reconoce como la de
# ahora, y se manda solo mientras haya dado de alta un iPhone que no entiende la de ahora
# (`entregas.texto_de_la_continuacion`).
TEXTO_CONTINUAR_ANTIGUO = MARCA_CONTINUAR + " Ha llegado el resultado de la tarea en segundo plano. Contesta a Daniel con él."
TEXTOS_CONTINUAR = (TEXTO_CONTINUAR, TEXTO_CONTINUAR_ANTIGUO)
APERTURA_RETIRADA = "⟦hehermes:retira⟧ Ignora mi mensaje «"
CIERRE_RETIRADA = "»: lo he retirado."
PREFIJO_INTERRUPCION = "Operation interrupted"
TIPO_ENTREGA = "async_delegation_complete"
TIPO_DESVIO = "steer"

# El texto del aviso de una entrega. El de la fila no sirve: es un informe en inglés para el modelo, con rutas del VPS
# («A background fan-out of 2 subagent(s) you dispatched…»). Lo que Daniel necesita saber es que ha acabado; el
# resultado se lo da Hermes al abrir el chat, cuando la app lanza la continuación.
TEXTO_ENTREGA = "Ha terminado un trabajo en segundo plano. Abre el chat para ver el resultado."


@dataclass(frozen=True)
class Suceso:
    """Algo de una sesión que merece un aviso, antes de decidir a qué iPhone va."""

    tipo: str
    # El id de la fila que lo provoca, y su instante (el `timestamp` de Hermes): con él se sabe si la app lo vio.
    fila: int
    instante: float
    # Lo que se lee en el aviso, ya sin markdown y recortado.
    texto: str
    # Identifica el suceso dentro de su sesión. De ella sale el `apns-collapse-id`: si el mismo suceso sale dos veces
    # (un reintento, un reinicio a destiempo), el iPhone enseña uno solo.
    clave: str


def _texto(fila: dict) -> str:
    contenido = fila.get("content")
    return contenido if isinstance(contenido, str) else ""


def es_interrupcion(contenido: str) -> bool:
    """Lo que guarda Hermes como respuesta de un turno parado (``HistorialHermes.esInterrupcion``)."""
    limpio = contenido.strip()
    if not limpio.startswith(PREFIJO_INTERRUPCION):
        return False
    resto = limpio[len(PREFIJO_INTERRUPCION):]
    return resto == "." or resto.startswith(":") or resto.startswith(" during")


def es_continuacion(contenido: str) -> bool:
    """La continuación entera, la de ahora o la de antes (``TEXTOS_CONTINUAR``): lo que solo empieza por la marca lo
    escribió el usuario."""
    return contenido.startswith(TEXTOS_CONTINUAR)


def es_retirada(contenido: str) -> bool:
    limpio = contenido.strip()
    return (limpio.startswith(APERTURA_RETIRADA) and limpio.endswith(CIERRE_RETIRADA)
            and len(limpio) >= len(APERTURA_RETIRADA) + len(CIERRE_RETIRADA))


def es_entrega(fila: dict) -> bool:
    return fila.get("role") == "user" and fila.get("display_kind") == TIPO_ENTREGA


def abre_turno(fila: dict) -> bool:
    """Una fila ``user`` sin ``display_kind``: un mensaje de Daniel o un turno que lanza la app. Los desvíos van dentro
    del turno en curso, y las entregas y las filas ocultas no abren ninguno."""
    return fila.get("role") == "user" and fila.get("display_kind") is None


class _Entrega:
    def __init__(self, fila: dict, nueva: bool):
        self.fila = fila
        self.nueva = nueva
        # El primer turno que empezó después de la entrega (contrato §6, punto 5): con él, la entrega está en manos de
        # ese turno. La respuesta del turno que ya estaba en marcha cuando llegó no cuenta.
        self.turno_siguiente: dict | None = None


def sucesos(filas: list, *, ultimo_id: int | None, referencia: float, ahora: float, antiguedad_maxima: float,
            pagina_llena: bool, entregas_del_vigia: int | None = None, ultima_respuesta: float | None = None) -> list:
    """Lo que hay que avisar de una sesión, a partir de sus últimas filas.

    - ``ultimo_id``: la última fila ya vista. ``None`` si el vigía aún no ha leído esta sesión nunca: entonces es nuevo
      lo escrito después de ``referencia`` (el instante de la línea de base).
    - ``ultima_respuesta``: la hora de la última respuesta ya vista (``ultima_respuesta()``). Una respuesta que no es
      posterior es la copia que deja una compactación, aunque traiga un ``id`` nuevo.
    - ``antiguedad_maxima``: lo escrito hace más de esto no se avisa aunque sea nuevo para el vigía. Tras un reinicio
      largo, un aviso de hace una hora es ruido, no un aviso.
    - ``pagina_llena``: la lectura trajo tantas filas como se pidieron, así que puede faltar el principio del turno.
    - ``entregas_del_vigia``: las entregas hasta esta fila las contesta el vigía (``entregas``), y de ellas no se avisa:
      el aviso que importa es el de la respuesta, que llega detrás.
    """
    ordenadas = sorted((f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), int)),
                       key=lambda f: f["id"])

    def nueva(fila: dict) -> bool:
        instante = fila.get("timestamp")
        instante = float(instante) if isinstance(instante, (int, float)) else None
        if ultimo_id is not None:
            if fila["id"] <= ultimo_id:
                return False
        elif instante is None or instante <= referencia:
            return False
        return instante is None or instante >= ahora - antiguedad_maxima

    turno: dict | None = None
    desvio_en_el_turno = False
    entregas: list[_Entrega] = []
    respuestas: list[tuple] = []
    for fila in ordenadas:
        rol = fila.get("role")
        if rol == "user":
            if abre_turno(fila):
                turno = fila
                desvio_en_el_turno = False
                for entrega in entregas:
                    if entrega.turno_siguiente is None:
                        entrega.turno_siguiente = fila
            elif fila.get("display_kind") == TIPO_DESVIO:
                desvio_en_el_turno = True
            elif es_entrega(fila):
                entregas.append(_Entrega(fila, nueva(fila)))
        elif rol == "assistant":
            contenido = _respuesta(fila)
            if not contenido or es_interrupcion(contenido) or not nueva(fila) or _copia(fila, ultima_respuesta):
                continue
            respuestas.append((fila, turno, desvio_en_el_turno))

    resultado: list[Suceso] = []
    if respuestas:
        fila, turno_de_la_respuesta, hubo_desvio = respuestas[-1]
        tipo = _tipo_de_respuesta(turno_de_la_respuesta, hubo_desvio, pagina_llena)
        leido = texto.de_respuesta(_texto(fila))
        if tipo and leido:
            resultado.append(Suceso(tipo=tipo, fila=fila["id"], instante=_instante(fila, ahora), texto=leido,
                                    clave=f"{tipo}:{fila['id']}"))
    # Una entrega con un turno detrás ya está en manos de ese turno (una continuación, o un mensaje de Daniel que la
    # tiene en su contexto): lo que se avisa es su respuesta, cuando llegue.
    sin_contestar = [e for e in entregas if e.nueva and e.turno_siguiente is None
                     and (entregas_del_vigia is None or e.fila["id"] > entregas_del_vigia)]
    if sin_contestar:
        fila = sin_contestar[-1].fila
        resultado.append(Suceso(tipo="segundo-plano", fila=fila["id"], instante=_instante(fila, ahora),
                                texto=TEXTO_ENTREGA, clave=f"entrega:{fila['id']}"))
    return resultado


def _tipo_de_respuesta(turno: dict | None, hubo_desvio: bool, pagina_llena: bool) -> str | None:
    if turno is None:
        # Sin petición en toda la sesión es un trabajo que corrió solo. Con la página llena, en cambio, la petición
        # puede estar fuera de la ventana: lo honrado es tratarla como una respuesta normal.
        return "respuesta" if pagina_llena else "segundo-plano"
    contenido = _texto(turno)
    if es_continuacion(contenido):
        return "segundo-plano"
    if es_retirada(contenido) and not hubo_desvio:
        return None
    return "respuesta"


def _instante(fila: dict, ahora: float) -> float:
    instante = fila.get("timestamp")
    return float(instante) if isinstance(instante, (int, float)) else ahora


def _respuesta(fila: dict) -> str:
    """El texto de una fila ``assistant`` que es una respuesta: ni un paso intermedio, ni oculta, ni vacía. Si no lo
    es, ``""``."""
    if fila.get("role") != "assistant" or fila.get("finish_reason") == "tool_calls" \
            or fila.get("display_kind") is not None:
        return ""
    return _texto(fila).strip()


def _copia(fila: dict, ultima_respuesta: float | None) -> bool:
    instante = fila.get("timestamp")
    return (ultima_respuesta is not None and isinstance(instante, (int, float))
            and float(instante) <= ultima_respuesta)


def ultima_respuesta(filas: list, anterior: float | None, hasta: int | None = None) -> float | None:
    """La hora de la respuesta más reciente de ``filas`` (solo las de ``id`` menor que ``hasta``, si se da: lo que queda
    pendiente de avisar no cuenta como visto), o ``anterior`` si es más reciente."""
    instantes = [float(f["timestamp"]) for f in filas
                 if isinstance(f, dict) and isinstance(f.get("id"), int) and (hasta is None or f["id"] < hasta)
                 and isinstance(f.get("timestamp"), (int, float)) and _respuesta(f)]
    if anterior is not None:
        instantes.append(anterior)
    return max(instantes) if instantes else None
