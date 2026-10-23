"""Las Actividades en Vivo de los turnos largos, con la app suspendida (avisos 1.6.7, contrato §20; 2026-10-23).

La app pide la actividad en el iPhone y la mueve ella mientras está viva. Cuando iOS la suspende, la mueve el vigía, que
ya lee las filas de cada conversación: le registra el token de la actividad (``POST …/dispositivos/{token}/actividades``)
y aquí se decide qué se le manda —el paso, los subagentes y, al acabar, la respuesta— sin hablar con nadie. El envío es
del bucle (``Vigilante._mover_actividades``).

**Lo que lee el relé.** Una actividad no tiene extensión que descifre antes de pintar, pero la de widgets de la app sí
puede abrir un sobre al pintar: el paso y la respuesta van en ``c``, cifrados con la clave del iPhone como los avisos. En
claro solo va la fase (una palabra), cuántos subagentes y el run que para «Detener». El relé no deja pasar nada más
(``rele.validacion.validar_carga_de_actividad``).
"""
from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass

from .. import cifrado
from . import deteccion

#: Lo que se queda la respuesta en la pantalla bloqueada (``DecisionDeLaActividad.respuestaVisible`` en la app).
RESPUESTA_VISIBLE = 10
#: Lo que cabe de la respuesta y del paso: tres líneas y una (``DecisionDeLaActividad.largoDeLaRespuesta``).
LARGO_RESPUESTA = 160
LARGO_PASO = 80
#: Apple reparte un presupuesto de actualizaciones con prioridad alta: los pasos van con la baja y el final, con la alta,
#: que es la que enciende la pantalla.
PRIORIDAD_PASO = 5
PRIORIDAD_FINAL = 10
#: Un paso que llega tarde ya no dice nada; el final sí, mientras la actividad siga.
CADUCA_PASO = 600
CADUCA_FINAL = 3600
#: Lo que vive un registro sin moverse: lo que iOS deja una actividad en pantalla.
VIDA_DE_UN_REGISTRO = 8 * 3600
#: Cuántas actividades se recuerdan por iPhone: una por conversación con un turno largo, y alguna de más.
MAXIMO_POR_DISPOSITIVO = 8


@dataclass(frozen=True)
class EstadoDelTurno:
    #: ``FaseDeLaActividad`` de la app: ``pensando``, ``trabajando``, ``subagentes``, ``respuesta`` o ``detenido``.
    fase: str
    paso: str | None
    subagentes: int
    respuesta: str | None = None

    @property
    def acabado(self) -> bool:
        return self.fase in ("respuesta", "detenido")


def _contenido(fila: dict) -> str:
    contenido = fila.get("content")
    return contenido if isinstance(contenido, str) else ""


def _recortar(texto: str, largo: int) -> str | None:
    plano = " ".join(parte.strip() for parte in texto.splitlines() if parte.strip())
    if not plano:
        return None
    return plano if len(plano) <= largo else plano[:largo - 1].rstrip() + "…"


def etiqueta(nombre: str, argumentos) -> str:
    """Lo que dice el paso de una herramienta, en pocas palabras y sin el comando entero. Va cifrado, pero se ve en la
    pantalla bloqueada: lo justo para saber por dónde va."""
    if isinstance(argumentos, str):
        try:
            argumentos = json.loads(argumentos)
        except ValueError:
            argumentos = {}
    if not isinstance(argumentos, dict):
        argumentos = {}

    def ruta() -> str:
        valor = argumentos.get("path") or argumentos.get("file_path") or ""
        return posixpath.basename(str(valor)) if valor else "un fichero"

    if nombre == "terminal":
        comando = str(argumentos.get("command") or "").strip()
        return f"Ejecutando {comando}" if comando else "Ejecutando un comando"
    if nombre == "web_search":
        return "Buscando en la web"
    if nombre.startswith("web_") or nombre.startswith("browser"):
        return "Leyendo una web"
    if nombre == "read_file":
        return f"Leyendo {ruta()}"
    if nombre in ("write_file", "patch"):
        return f"Escribiendo {ruta()}"
    if nombre == "search_files":
        return "Buscando en los ficheros"
    if nombre == "delegate_task":
        return "Repartiendo el trabajo"
    return f"Usando {nombre}"


def _ultimo_paso(filas: list) -> str | None:
    for fila in reversed(filas):
        llamadas = fila.get("tool_calls") if fila.get("role") == "assistant" else None
        if isinstance(llamadas, list) and llamadas:
            funcion = llamadas[-1].get("function") if isinstance(llamadas[-1], dict) else None
            if isinstance(funcion, dict) and isinstance(funcion.get("name"), str):
                return _recortar(etiqueta(funcion["name"], funcion.get("arguments")), LARGO_PASO)
    return None


def subagentes_trabajando(filas: list) -> int:
    """Los subagentes que siguen trabajando: los de cada ``delegate_task`` en segundo plano (su fila de herramienta dice
    ``delegation_id`` y ``count``) cuya entrega no ha llegado y que nadie ha detenido. Solo cuenta lo que hay en
    ``filas``: una delegación que se quedó fuera de la ventana no se ve."""
    lanzadas: dict = {}
    entregadas: set = set()
    for fila in filas:
        if fila.get("role") == "tool" and fila.get("tool_name") == "delegate_task":
            try:
                datos = json.loads(_contenido(fila))
            except ValueError:
                continue
            if isinstance(datos, dict) and datos.get("mode") == "background" \
                    and isinstance(datos.get("delegation_id"), str):
                cuantos = datos.get("count")
                lanzadas[datos["delegation_id"]] = cuantos if isinstance(cuantos, int) and cuantos > 0 else 1
        entregada = deteccion.delegacion_entregada(fila)
        if entregada:
            entregadas.add(entregada)
    fuera = entregadas | deteccion.delegaciones_detenidas(filas)
    return sum(cuantos for delegacion, cuantos in lanzadas.items() if delegacion not in fuera)


def estado_del_turno(filas: list) -> EstadoDelTurno | None:
    """En qué está la conversación según sus últimas filas. ``None`` sin filas: no se sabe nada."""
    filas = [fila for fila in filas if isinstance(fila, dict)]
    if not filas:
        return None
    subagentes = subagentes_trabajando(filas)
    paso = _ultimo_paso(filas)
    ultima = filas[-1]
    if ultima.get("role") == "assistant" and ultima.get("finish_reason") != "tool_calls" \
            and ultima.get("display_kind") is None and _contenido(ultima).strip():
        texto = _contenido(ultima).strip()
        if deteccion.es_interrupcion(texto):
            return EstadoDelTurno("detenido", None, 0)
        if subagentes > 0:
            # Ha contestado, pero deja trabajo en segundo plano: la respuesta de verdad llegará con la continuación.
            return EstadoDelTurno("subagentes", paso, subagentes)
        return EstadoDelTurno("respuesta", None, 0, _recortar(texto, LARGO_RESPUESTA))
    if ultima.get("role") == "assistant" and isinstance(ultima.get("tool_calls"), list) and ultima["tool_calls"]:
        return EstadoDelTurno("trabajando", paso, subagentes)
    return EstadoDelTurno("pensando", paso, subagentes)


def huella(estado: EstadoDelTurno) -> str:
    """Lo que se mandó la última vez, para no repetirlo: cada actualización gasta presupuesto de Apple."""
    return json.dumps([estado.fase, estado.paso, estado.subagentes, estado.respuesta], ensure_ascii=False)


def contenido(estado: EstadoDelTurno, *, run: str | None, vuelta: int, ahora: float, clave: bytes,
              nonce: bytes | None = None) -> dict:
    """El ``content-state``: los nombres de ``TurnoEnVivo.ContentState`` en la app, los instantes en segundos Unix."""
    secreto = {nombre: valor for nombre, valor in (("paso", estado.paso), ("respuesta", estado.respuesta)) if valor}
    datos: dict = {"fase": estado.fase, "subagentes": estado.subagentes}
    # «Detener» para el run mientras hay turno; con solo subagentes, la app los para a ellos.
    if run and not estado.acabado and estado.fase != "subagentes":
        datos["run"] = run
    datos["vuelta"] = vuelta
    if secreto:
        claro = json.dumps(secreto, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        datos["c"] = cifrado.sellar(claro, clave, nonce)
    if estado.acabado:
        datos["fin"] = int(ahora)
    return datos


def carga(estado: EstadoDelTurno, *, run: str | None, vuelta: int, ahora: float, clave: bytes,
          nonce: bytes | None = None) -> dict:
    """El push entero: ``update`` mientras trabaja y ``end`` al acabar, que se queda en pantalla ``RESPUESTA_VISIBLE``
    segundos. ``timestamp`` es lo que usa iOS para no aplicar una actualización vieja después de una nueva."""
    aps: dict = {"timestamp": int(ahora), "event": "end" if estado.acabado else "update",
                 "content-state": contenido(estado, run=run, vuelta=vuelta, ahora=ahora, clave=clave, nonce=nonce)}
    if estado.acabado:
        aps["dismissal-date"] = int(ahora) + RESPUESTA_VISIBLE
    return {"aps": aps}


def peticion_al_rele(token: str, entorno: str, actividad: str, carga_: dict, final: bool) -> dict:
    """Lo que ve el relé. Con el ``token`` del iPhone, que es con el que comprueba el permiso y cuenta el límite, y el de
    la actividad, a donde va."""
    return {"token": token, "entorno": entorno, "tipo": "liveactivity", "actividad": actividad,
            "prioridad": PRIORIDAD_FINAL if final else PRIORIDAD_PASO, "payload": carga_,
            "caduca": CADUCA_FINAL if final else CADUCA_PASO}
