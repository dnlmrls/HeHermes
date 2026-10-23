"""El vigía vigilando a Hermes (desde la 1.6.4): que avise solo cuando Hermes cambia o el servidor se toca a mano.

Hermes es la rama main y se actualiza solo cada noche. El 2026-10-15 empezó a guardar la fila ``user`` de todo turno con
``display_kind: "internal_notification"``; la app y el vigía dejaron de reconocer los turnos y nadie se enteró en siete
días. Y el 2026-10-22 se vio que un fichero del vigía en el VPS llevaba un parche puesto a mano. Aquí se mira, sin
molestar a nadie, lo que habría avisado de las dos cosas:

- **La versión y el commit de Hermes** (``GET /health`` y el ``.git`` de su código, leído sin ``git``), y cuándo cambian.
- **Los valores que no conoce**: cada ``display_kind`` de las filas que ya lee y cada ``code`` de error de Hermes que
  no sabe. Se apunta la primera vez y cuántas veces, y se registra **una sola vez por valor**.
- **La autocomprobación**: tras un cambio de versión o de commit, y si no cada ``AUTOCOMPROBAR_CADA``, mira las últimas
  sesiones de la API y comprueba que cada fila ``user`` se clasifica (abre turno, desvío, entrega u oculta). Una que no,
  es «Hermes ha cambiado algo que HeHermes no reconoce».
- **Los ficheros tocados a mano** (``integridad``): los nombres de lo que ya no coincide con el manifiesto de la
  instalación.

Lo que decide va en funciones puras (arriba); ``Observatorio`` solo las junta con el reloj, la red y SQLite. Lo apuntado
vive en la tabla ``estado`` (una clave, un JSON con topes): sin migración. Lo que sale por ``GET /avisos/v1/servidor``
(``informe``, contrato §17) no lleva rutas ni contenido de ninguna fila: solo nombres y cifras.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import threading
import time

from . import deteccion, integridad
from .fichero import TIPO_OCULTO
from .hermes import PRINCIPAL, ErrorHermes

registro = logging.getLogger("vigia.observatorio")

CLAVE = "observatorio"
DISPLAY_KIND = "display_kind"
CODIGO_DE_ERROR = "codigo_de_error"

#: Los ``display_kind`` que el vigía sabe, en un solo sitio: ``None`` (el Hermes de antes) más estos. Si Hermes inventa
#: otro, se apunta. ``hidden`` lo usa ``fichero`` para saltarse filas ocultas.
TIPOS_CONOCIDOS = frozenset({deteccion.TIPO_INTERNO, deteccion.TIPO_ENTREGA, deteccion.TIPO_DESVIO, TIPO_OCULTO})
#: Los ``code`` del envoltorio de error de Hermes que el vigía conoce, los que documenta el contrato (§3, §8 y el SSE de un
#: run): la clave ya usada (``idempotency_key_conflict`` y el ``admission_conflict`` del Hermes nuevo, que el vigía trata
#: igual: la continuación ya la lanzó la app), la clave de la pasarela mala, un run o una ruta que no existen
#: (``run_not_found``, ``not_found``), un desvío a un run terminado, el título y la aprobación no válidos, los de la
#: entrada (``invalid_idempotency_key``, ``body_too_large``) y los pasajeros de siempre (``rate_limit_exceeded`` y
#: ``gateway_draining``, con ``Retry-After``). Sin esto, un 404 de una sesión borrada entre la bandeja y su lectura, o el
#: 503 del reinicio nocturno, se apuntarían como «Hermes ha cambiado» el primer día y no se irían nunca.
CODIGOS_CONOCIDOS = frozenset({"idempotency_key_conflict", "admission_conflict", "gateway_auth_failed",
                               "run_not_found", "not_found", "run_not_accepting_steer", "invalid_title",
                               "invalid_approval_request", "invalid_idempotency_key", "body_too_large",
                               "rate_limit_exceeded", "gateway_draining"})

LARGO_MAXIMO = 64
#: Valores distintos que se guardan: un Hermes que invente uno por fila no llena la base de datos.
TOPE_DE_DESCONOCIDOS = 40
TOPE_DE_NOMBRES = 50
SESIONES_A_MIRAR = 5
FILAS_A_MIRAR = 40

CADA_VERSION = 600.0
CADA_FICHEROS = 1800.0
AUTOCOMPROBAR_CADA = 6 * 3600.0
REINTENTAR_AUTOCOMPROBACION = 600.0
#: Los contadores que suben sin valores nuevos se escriben como mucho cada tanto (el WAL de SQLite ya dio un susto).
GUARDAR_CADA = 300.0
REPETIR_UN_FALLO = 600.0

#: Dónde vive el código de Hermes si ``[hermes] codigo`` no lo dice. Una lista corta y fija: no se recorre el disco.
CODIGOS_USUALES = ("/usr/local/lib/hermes-agent", "/opt/hermes-agent")

_HEX_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REFERENCIA = re.compile(r"refs/[A-Za-z0-9._/-]{1,200}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}")
CORTO = 12


# -- Funciones puras

def limpiar(valor) -> str:
    """Un ``display_kind`` o un código, como se guarda y se enseña: solo letras, cifras y ``_.:-`` y hasta
    ``LARGO_MAXIMO``. Lo que Hermes ponga ahí no es nuestro: no puede traer texto de una conversación."""
    if not isinstance(valor, str):
        return "(no es texto)"
    if not valor:
        return "(vacío)"
    return re.sub(r"[^A-Za-z0-9_.:-]", "?", valor)[:LARGO_MAXIMO]


def tipo_conocido(valor) -> bool:
    return valor is None or (isinstance(valor, str) and valor in TIPOS_CONOCIDOS)


def tipos_desconocidos(filas) -> list:
    """``(id de la fila, valor limpio)`` de cada fila de ``filas`` con un ``display_kind`` que el vigía no conoce, sea
    del rol que sea: un valor nuevo en una fila ``assistant`` también apaga avisos sin que se note
    (``deteccion._respuesta`` la descarta)."""
    return [(f["id"], limpiar(f.get("display_kind"))) for f in filas
            if isinstance(f, dict) and isinstance(f.get("id"), int) and not isinstance(f.get("id"), bool)
            and not tipo_conocido(f.get("display_kind"))]


def clase_de_fila(fila: dict) -> str | None:
    """Qué es una fila ``user`` para el vigía: ``abre_turno``, ``desvio``, ``entrega`` (con la cabecera que lleva su
    delegación) u ``oculta``; ``None`` si no es nada de eso y Hermes ha cambiado algo. Las filas de otro rol no se
    clasifican: ``None`` no quiere decir nada para ellas."""
    if fila.get("role") != "user":
        return None
    if deteccion.abre_turno(fila):
        return "abre_turno"
    tipo = fila.get("display_kind")
    if tipo == deteccion.TIPO_DESVIO:
        return "desvio"
    if tipo == deteccion.TIPO_ENTREGA:
        # Sin la cabecera `[ASYNC DELEGATION BATCH COMPLETE — deleg_…]` no se sabe de qué delegación es (ni se puede
        # saber si el usuario la detuvo): es el otro sitio por donde Hermes puede romper sin ruido.
        return "entrega" if deteccion.delegacion_entregada(fila) is not None else None
    if tipo == TIPO_OCULTO:
        return "oculta"
    return None


def resultado_de_autocomprobacion(filas, ahora: float, anterior: dict | None) -> dict:
    """``{"hora", "filas", "sin_reconocer", "desde"}`` de mirar ``filas``: cuántas ``user`` hay, cuántas no se
    clasifican y desde cuándo pasa (la hora de la primera comprobación que las vio; ``None`` si no hay ninguna)."""
    usuario = [f for f in filas if isinstance(f, dict) and f.get("role") == "user"]
    sin = sum(1 for f in usuario if clase_de_fila(f) is None)
    desde = None
    if sin:
        previo = anterior.get("desde") if isinstance(anterior, dict) and anterior.get("sin_reconocer") else None
        desde = previo if isinstance(previo, (int, float)) else ahora
    return {"hora": ahora, "filas": len(usuario), "sin_reconocer": sin, "desde": desde}


def anotar_valor(desconocidos: list, tipo: str, valor: str, ahora: float, veces: int = 1) -> tuple:
    """``(lista nueva, es la primera vez)`` de apuntar ``valor``. Con ``TOPE_DE_DESCONOCIDOS`` ya guardados, uno nuevo
    no entra (``None`` en el segundo valor: ni se cuenta ni se registra)."""
    nueva = [dict(d) for d in desconocidos]
    for d in nueva:
        if d["tipo"] == tipo and d["valor"] == valor:
            d["veces"] += veces
            return nueva, False
    if len(nueva) >= TOPE_DE_DESCONOCIDOS:
        return nueva, None
    nueva.append({"tipo": tipo, "valor": valor, "primera": ahora, "veces": veces})
    return nueva, True


def depurar_conocidos(desconocidos) -> list:
    """Lo guardado, sin lo que esta versión del vigía ya conoce y sin lo que no tiene su forma: un vigía actualizado que
    aprende un valor no puede seguir enseñando el globo por él."""
    limpios = []
    for d in desconocidos if isinstance(desconocidos, list) else []:
        if not isinstance(d, dict) or d.get("tipo") not in (DISPLAY_KIND, CODIGO_DE_ERROR):
            continue
        valor, primera, veces = d.get("valor"), d.get("primera"), d.get("veces")
        if not isinstance(valor, str) or not isinstance(primera, (int, float)) or not isinstance(veces, int) \
                or isinstance(veces, bool):
            continue
        conocidos = TIPOS_CONOCIDOS if d["tipo"] == DISPLAY_KIND else CODIGOS_CONOCIDOS
        if valor in conocidos:
            continue
        limpios.append({"tipo": d["tipo"], "valor": limpiar(valor), "primera": primera, "veces": max(1, veces)})
    return limpios[:TOPE_DE_DESCONOCIDOS]


def anotar_version(anterior: dict | None, version: str | None, commit: str | None, ahora: float) -> tuple:
    """``(registro nuevo, cambió)``. Un valor que no se pudo leer (``None``) no cambia nada: Hermes sin ``.git`` legible
    no es un Hermes distinto. Cambia la versión o el commit si los dos, el de antes y el de ahora, se conocen y
    difieren; entonces ``anterior`` guarda lo de antes y ``visto`` es ahora. La primera vez solo se apunta."""
    previo = anterior if isinstance(anterior, dict) and anterior.get("visto") is not None else None
    if previo is None:
        if version is None and commit is None:
            return {"version": None, "commit": None, "visto": None, "anterior": None}, False
        return {"version": version, "commit": commit, "visto": ahora, "anterior": None}, False
    cambio = (version is not None and previo.get("version") is not None and version != previo["version"]) or \
             (commit is not None and previo.get("commit") is not None and commit != previo["commit"])
    nuevo_v = version if version is not None else previo.get("version")
    nuevo_c = commit if commit is not None else previo.get("commit")
    if not cambio:
        return {"version": nuevo_v, "commit": nuevo_c, "visto": previo["visto"],
                "anterior": previo.get("anterior")}, False
    return {"version": nuevo_v, "commit": nuevo_c, "visto": ahora,
            "anterior": {"version": previo.get("version"), "commit": previo.get("commit")}}, True


def toca_autocomprobar(ultima: dict | None, pendiente: bool, ahora: float, ultimo_intento: float | None) -> bool:
    """Tras un cambio de Hermes (``pendiente``) y, si no, cada ``AUTOCOMPROBAR_CADA``; si un intento falló (Hermes no
    contestaba), no antes de ``REINTENTAR_AUTOCOMPROBACION``."""
    if ultimo_intento is not None and ahora - ultimo_intento < REINTENTAR_AUTOCOMPROBACION:
        return False
    if pendiente or not isinstance(ultima, dict) or not isinstance(ultima.get("hora"), (int, float)):
        return True
    return ahora - ultima["hora"] >= AUTOCOMPROBAR_CADA


def leer_commit(carpeta: str) -> str | None:
    """Los 12 primeros caracteres del commit del repositorio de ``carpeta``, leído de su ``.git`` **sin ejecutar
    ``git``** (como ``hh-vigia`` se negaría a abrir un repositorio de root, «dubious ownership»): ``.git/HEAD``, la
    referencia suelta o ``packed-refs``, un HEAD suelto, y ``.git`` como fichero (``gitdir:``, con su ``commondir``).
    Cualquier cosa rara es ``None``: es información de más, nunca un fallo."""
    try:
        punto = os.path.join(carpeta, ".git")
        if os.path.isfile(punto):
            contenido = _leer(punto)
            if not contenido.startswith("gitdir:"):
                return None
            git = os.path.join(carpeta, contenido[len("gitdir:"):].strip())
        else:
            git = punto
        if not os.path.isdir(git):
            return None
        comun = git
        if os.path.isfile(os.path.join(git, "commondir")):
            comun = os.path.normpath(os.path.join(git, _leer(os.path.join(git, "commondir")).strip()))
        cabeza = _leer(os.path.join(git, "HEAD")).strip()
        if _HEX_COMMIT.fullmatch(cabeza):
            return cabeza[:CORTO]
        if not cabeza.startswith("ref:"):
            return None
        referencia = cabeza[4:].strip()
        if not _REFERENCIA.fullmatch(referencia) or ".." in referencia.split("/"):
            return None
        for base in (git, comun):
            suelta = os.path.join(base, referencia)
            if os.path.isfile(suelta):
                valor = _leer(suelta).strip()
                if _HEX_COMMIT.fullmatch(valor):
                    return valor[:CORTO]
        empaquetadas = os.path.join(comun, "packed-refs")
        if os.path.isfile(empaquetadas):
            for linea in _leer(empaquetadas, 4 * 1024 * 1024).splitlines():
                partes = linea.split(" ")
                if len(partes) == 2 and partes[1] == referencia and _HEX_COMMIT.fullmatch(partes[0]):
                    return partes[0][:CORTO]
    except (OSError, UnicodeDecodeError):
        return None
    return None


def _leer(ruta: str, tope: int = 4096) -> str:
    with open(ruta, "rb") as f:
        return f.read(tope).decode("utf-8")


def _numero(valor) -> float:
    return float(valor) if isinstance(valor, (int, float)) and not isinstance(valor, bool) else 0.0


# -- Lo que lleva estado

class Observatorio:
    """Lo apuntado de Hermes y del servidor. Lo llama el bucle del vigía (``vuelta``, ``ver_filas``) y los clientes de
    Hermes (``ver_codigo``); lo lee la API (``informe``): todo bajo un cerrojo, y la red siempre fuera de él."""

    def __init__(self, almacen, hermes, *, codigo_de_hermes: str | None = None, manifiesto: str | None = None,
                 reloj=time.time, sumar=integridad.suma_de, commit=leer_commit):
        self.almacen, self.hermes, self.reloj = almacen, hermes, reloj
        self._codigo, self._manifiesto, self._sumar, self._leer_commit = codigo_de_hermes, manifiesto, sumar, commit
        self._cerrojo = threading.Lock()
        self._vistas: set = set()
        self._fallos: dict = {}
        self._proxima_version = self._proximos_ficheros = 0.0
        self._ultimo_intento: float | None = None
        self._guardado = 0.0
        self._sucio = False
        self._desbordado = False
        self._ficheros: dict | None = None
        guardado = self._cargar()
        self._hermes_visto = guardado.get("hermes") if isinstance(guardado.get("hermes"), dict) else None
        self._desconocidos = depurar_conocidos(guardado.get("desconocidos"))
        auto = guardado.get("autocomprobacion")
        self._auto = auto if isinstance(auto, dict) and isinstance(auto.get("hora"), (int, float)) else None
        self._pendiente = guardado.get("pendiente") is True

    def _cargar(self) -> dict:
        try:
            datos = json.loads(self.almacen.leer_estado(CLAVE) or "{}")
        except ValueError:
            return {}
        return datos if isinstance(datos, dict) else {}

    # -- Lo que se ve pasar

    def ver_filas(self, perfil: str, sesion: str, filas, ahora: float | None = None, desde_id: int | None = None) -> None:
        """Apunta los ``display_kind`` desconocidos de ``filas`` (las que se acaban de leer de una sesión). Solo las
        posteriores a ``desde_id`` (la última ya vista) y una vez por fila: el bucle vuelve a leer las 20 últimas cada
        vez que la sesión cambia, y sin esto «veces» crecería con cada lectura."""
        ahora = self.reloj() if ahora is None else ahora
        try:
            for id_, valor in tipos_desconocidos(filas):
                if desde_id is not None and id_ <= desde_id:
                    continue
                with self._cerrojo:
                    if len(self._vistas) > 4000:
                        self._vistas.clear()
                    clave = (perfil, sesion, id_)
                    if clave in self._vistas:
                        continue
                    self._vistas.add(clave)
                self._apuntar(DISPLAY_KIND, valor, ahora)
            self._guardar(ahora)
        except Exception:  # noqa: BLE001 — mirar no puede romper la lectura
            self._fallo("ver_filas", "no se pudieron apuntar los valores de las filas")

    def ver_codigo(self, codigo, ahora: float | None = None) -> None:
        """Apunta un ``code`` de error de Hermes que el vigía no conoce."""
        if not isinstance(codigo, str) or codigo in CODIGOS_CONOCIDOS:
            return
        try:
            ahora = self.reloj() if ahora is None else ahora
            self._apuntar(CODIGO_DE_ERROR, limpiar(codigo), ahora)
            self._guardar(ahora)
        except Exception:  # noqa: BLE001
            self._fallo("ver_codigo", "no se pudo apuntar un código de error")

    def _apuntar(self, tipo: str, valor: str, ahora: float) -> None:
        with self._cerrojo:
            self._desconocidos, nuevo = anotar_valor(self._desconocidos, tipo, valor, ahora)
            self._sucio = True
            if nuevo:
                self._guardar_ya = True
        if nuevo:
            registro.warning("Hermes ha cambiado algo que HeHermes no reconoce: %s nuevo, «%s»",
                             "display_kind" if tipo == DISPLAY_KIND else "código de error", valor)
        elif nuevo is None and not self._desbordado:
            self._desbordado = True
            registro.warning("demasiados valores desconocidos distintos (%d): los nuevos ya no se apuntan",
                             TOPE_DE_DESCONOCIDOS)

    # -- El bucle

    def vuelta(self) -> None:
        """Lo periódico: la versión, los ficheros y la autocomprobación. Cada parte tiene su ritmo y ninguna rompe a las
        demás ni al bucle."""
        ahora = self.reloj()
        # Lo que toca se decide al llegar a cada parte, no antes: un cambio de versión recién visto pide la
        # autocomprobación en esta misma vuelta.
        for nombre, toca, hacer in (("versión", lambda: ahora >= self._proxima_version, self._mirar_hermes),
                                    ("ficheros", lambda: ahora >= self._proximos_ficheros, self._mirar_ficheros),
                                    ("autocomprobación", lambda: self._toca_auto(ahora), self._autocomprobar)):
            if not toca():
                continue
            try:
                hacer(ahora)
            except ErrorHermes:
                pass  # sin Hermes no hay nada que mirar; se reintenta en su momento
            except Exception:  # noqa: BLE001
                self._fallo(nombre, "fallo en la vigilancia de " + nombre)
        self._guardar(ahora)

    def _toca_auto(self, ahora: float) -> bool:
        with self._cerrojo:
            return toca_autocomprobar(self._auto, self._pendiente, ahora, self._ultimo_intento)

    def _carpeta_del_codigo(self) -> str | None:
        for candidata in ((self._codigo,) if self._codigo else CODIGOS_USUALES):
            if candidata and os.path.exists(os.path.join(candidata, ".git")):
                return candidata
        return None

    def _mirar_hermes(self, ahora: float) -> None:
        self._proxima_version = ahora + CADA_VERSION
        version = self.hermes.salud(3.0)  # `ErrorHermes` si no contesta: no se apunta nada
        carpeta = self._carpeta_del_codigo()
        commit = self._leer_commit(carpeta) if carpeta else None
        with self._cerrojo:
            antes = self._hermes_visto
            self._hermes_visto, cambio = anotar_version(antes, version, commit, ahora)
            self._sucio = True
            if cambio:
                self._pendiente = True
                self._guardar_ya = True
            visto = copy.deepcopy(self._hermes_visto)
        if cambio:
            ant = visto["anterior"] or {}
            registro.warning("Hermes ha cambiado: versión %s → %s, commit %s → %s", ant.get("version"),
                             visto["version"], ant.get("commit"), visto["commit"])
        elif antes is None and visto["visto"] is not None:
            registro.info("Hermes %s (commit %s) visto por primera vez", visto["version"], visto["commit"])

    def _mirar_ficheros(self, ahora: float) -> None:
        self._proximos_ficheros = ahora + CADA_FICHEROS
        if not self._manifiesto:
            return
        cambiados = integridad.comprobar(self._manifiesto, self._sumar)
        nuevo = None if cambiados is None else {"cambiados": cambiados[:TOPE_DE_NOMBRES], "hora": ahora}
        with self._cerrojo:
            antes = (self._ficheros or {}).get("cambiados")
            self._ficheros = nuevo
        if nuevo is not None and nuevo["cambiados"] != antes and nuevo["cambiados"]:
            registro.warning("ficheros del servidor cambiados a mano desde la instalación: %s",
                             ", ".join(nuevo["cambiados"]))

    def _autocomprobar(self, ahora: float) -> None:
        self._ultimo_intento = ahora
        sesiones = self.hermes.sesiones()
        recientes = sorted(sesiones, key=lambda s: _numero(s.get("last_active")), reverse=True)[:SESIONES_A_MIRAR]
        todas = []
        for sesion in recientes:
            filas = self.hermes.mensajes(sesion["id"], FILAS_A_MIRAR)
            todas.extend(filas)
            self.ver_filas(PRINCIPAL, sesion["id"], filas, ahora)
        with self._cerrojo:
            antes = self._auto
            self._auto = resultado_de_autocomprobacion(todas, ahora, antes)
            self._pendiente = False
            self._sucio = True
            nuevo = self._auto
            if (antes or {}).get("sin_reconocer", 0) != nuevo["sin_reconocer"]:
                self._guardar_ya = True
        if nuevo["sin_reconocer"] and not (antes or {}).get("sin_reconocer"):
            registro.warning("Hermes ha cambiado algo que HeHermes no reconoce: %d de %d filas de usuario sin "
                             "clasificar", nuevo["sin_reconocer"], nuevo["filas"])
        elif not nuevo["sin_reconocer"] and (antes or {}).get("sin_reconocer"):
            registro.info("autocomprobación: todas las filas de usuario se reconocen otra vez")

    # -- Lo guardado y lo que se cuenta

    _guardar_ya = False

    def _guardar(self, ahora: float) -> None:
        with self._cerrojo:
            if not self._sucio or not (self._guardar_ya or ahora - self._guardado >= GUARDAR_CADA):
                return
            contenido = json.dumps({"hermes": self._hermes_visto, "desconocidos": self._desconocidos,
                                    "autocomprobacion": self._auto, "pendiente": self._pendiente}, sort_keys=True)
            self._sucio = False
            self._guardar_ya = False
            self._guardado = ahora
        try:
            self.almacen.guardar_estado(CLAVE, contenido)
        except Exception:  # noqa: BLE001 — el disco lleno no para la vigilancia
            self._fallo("guardar", "no se pudo guardar lo apuntado de Hermes")

    def _fallo(self, clave: str, mensaje: str) -> None:
        ahora = self.reloj()
        if ahora - self._fallos.get(clave, -REPETIR_UN_FALLO) >= REPETIR_UN_FALLO:
            self._fallos[clave] = ahora
            registro.warning(mensaje, exc_info=True)

    def informe(self) -> dict:
        """Lo que va en ``vigilancia`` de ``GET /avisos/v1/servidor`` (contrato §17): nombres y cifras, nada más."""
        with self._cerrojo:
            visto = self._hermes_visto or {}
            ant = visto.get("anterior")
            hermes = {"version": _version(visto.get("version")), "commit": _commit(visto.get("commit")),
                      "visto": _hora(visto.get("visto")),
                      "anterior": {"version": _version(ant.get("version")), "commit": _commit(ant.get("commit"))}
                      if isinstance(ant, dict) else None}
            auto = self._auto
            ficheros = self._ficheros
            return {"hermes": hermes,
                    "desconocidos": [{"tipo": d["tipo"], "valor": d["valor"], "primera": _hora(d["primera"]),
                                      "veces": d["veces"]} for d in self._desconocidos],
                    "autocomprobacion": None if not auto else {
                        "hora": _hora(auto.get("hora")), "filas": int(auto.get("filas", 0)),
                        "sin_reconocer": int(auto.get("sin_reconocer", 0)), "desde": _hora(auto.get("desde"))},
                    "ficheros": None if ficheros is None else {"cambiados": list(ficheros["cambiados"]),
                                                               "hora": _hora(ficheros["hora"])}}


def _hora(valor) -> int | None:
    return int(valor) if isinstance(valor, (int, float)) and not isinstance(valor, bool) else None


def _version(valor) -> str | None:
    return valor if isinstance(valor, str) and _VERSION.fullmatch(valor) else None


def _commit(valor) -> str | None:
    return valor if isinstance(valor, str) and re.fullmatch(r"[0-9a-f]{12}", valor) else None
