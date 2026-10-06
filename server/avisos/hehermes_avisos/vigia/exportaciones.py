"""Los ficheros nuevos que Hermes deja en su carpeta para el iPhone (``exports/``), avisados en cuanto están, aunque el
turno o el subagente que los hizo siga trabajando (desde la 1.5.1; contrato §11, «Un fichero nuevo en exports/»).

Hasta ahora un fichero solo llegaba al iPhone cuando Hermes escribía su línea ``MEDIA:`` en la respuesta, y eso es al
final del turno, o nunca (el 2026-10-03 tres informes quedaron en un paso intermedio). Y un subagente que tarda horas no
escribe ninguna respuesta en la conversación hasta que acaba.

**Cómo se ve la carpeta.** El vigía no puede leer la casa de Hermes: la mira el lector (``hehermes-leer-media``, con su
jaula), con la línea ``?exports`` en lugar de una ruta. El lector contesta primero ``{"carpeta": "<ruta>"}`` y, cada
dos segundos, ``{"ficheros": [{"nombre", "tamano", "mtime", "ctime"}, …]}``: los ficheros normales de la carpeta, sin
los ocultos ni los temporales, con un solo enlace duro, como los que deja leer. A los diez minutos acaba, y se le vuelve
a llamar.

**Cuándo un fichero es nuevo** (``Exportaciones.observar``): cuando una versión —nombre, tamaño y hora de modificación—
que no se conocía lleva ``ESTABILIDAD`` segundos sin cambiar: lo que se está escribiendo cambia de tamaño o de hora, y no
se avisa a medias. La primera vez que el vigía mira la carpeta, lo que ya hay se da por conocido. Lo que llegó hace más
de ``ANTIGUEDAD_MAXIMA`` (el vigía estuvo parado) se apunta sin avisar; la llegada es la más reciente de sus dos horas,
porque lo que se mueve a la carpeta conserva su ``mtime`` y solo su ``ctime`` dice cuándo llegó.

**A qué conversación va** (``atribuir``), lo mejor que se puede: se busca el nombre del fichero en las últimas filas de
las conversaciones de la bandeja con actividad reciente —lo que escribieron, los argumentos de sus herramientas y lo que
estas devolvieron—, y si no, en las de los subagentes (las sesiones hijas, que se suben a su conversación por
``parent_session_id``). Hermes guarda cada llamada a una herramienta antes de hacerla, así que cuando el fichero ya está
escrito, la fila que lo nombra ya se puede leer. Sin encontrarla, el aviso no es de ninguna, y tocarlo abre la bandeja.

**El aviso** es de tipo ``segundo-plano`` (sus ajustes mandan, y el silencio de la conversación), cifrado como todos,
«Nuevo fichero listo: <nombre>», y colapsa por fichero: una versión nueva sustituye a la anterior. Lo manda el bucle
(``Vigilante``), con sus reintentos.

**Y la app lo enseña** (``GET /avisos/v1/ficheros?sesion=``, ``AppVigia.ficheros_dejados``): una tarjeta «Hermes ha
dejado un fichero» en la conversación, que se descarga aunque Hermes aún no haya escrito su línea ``MEDIA:`` (lo de
``exports/`` es para el iPhone por contrato, ``Ficheros.en_exportaciones``).

En el registro sale cuántos y a quién, nunca el nombre de un fichero.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
from dataclasses import asdict, dataclass

registro = logging.getLogger("vigia.exportaciones")

#: Lo que se pide al lector para vigilar la carpeta (``hehermes-leer-media``, ``VIGILAR``).
PETICION = b"?exports\n"
#: Segundos que una versión nueva tiene que quedarse igual para avisar de ella.
ESTABILIDAD = 5.0
#: Un fichero que al verse llegó hace más de esto no se avisa (el vigía estuvo parado): se apunta y ya.
ANTIGUEDAD_MAXIMA = 3600.0
#: Un aviso que no ha podido salir en este tiempo se deja: ya no es «nuevo».
CADUCIDAD_DEL_AVISO = 3600.0
#: Cuántos ficheros se recuerdan, los de llegada más reciente: más de los que cuenta el lector (``MAX_VIGILADOS``, 1000),
#: para que todo lo que cuenta se reconozca y nada vuelva a parecer nuevo.
MAX_RECORDADOS = 2000
#: La clave del estado (``Almacen.leer_estado``) donde se guarda lo visto. Un JSON y no una tabla: sin cambiar el esquema
#: de la base, volver a un vigía de antes sigue funcionando.
CLAVE = "exportaciones"
#: Las conversaciones (y los subagentes) que se miran para atribuir un fichero, las de actividad más reciente, hasta
#: cuándo es reciente y cuántas filas de cada una.
MAX_CONVERSACIONES = 8
RECIENTE = 6 * 3600.0
FILAS_POR_CONVERSACION = 100
#: Cuántos saltos de subagente a madre como mucho (un subagente puede lanzar otros).
MAX_SALTOS = 10
#: Cada cuánto tiene que llegar una línea del lector; sin ella, se vuelve a llamar.
PLAZO_DE_LECTURA = 30.0
#: Esperas antes de volver a llamar al lector tras un fallo, y si el lector no sabe vigilar (uno de antes de la 1.5.1).
ESPERAS = (5.0, 15.0, 60.0, 300.0)
ESPERA_SIN_VIGILANCIA = 3600.0
TEXTO = "Nuevo fichero listo: {}"
MAX_NOMBRE = 255
#: Los agentes (contrato §18.9): cada perfil tiene su exports/, y su vigilancia. El principal es `default`.
PATRON_PERFIL = re.compile(r"[a-z0-9]{1,24}")
PRINCIPAL = "default"
#: Cada cuánto se mira qué agentes hay, para vigilar el exports/ de los nuevos y dejar el de los que se van.
REPASO_DE_AGENTES = 30.0
#: Lo que no se avisa aunque el lector lo contara: lo mismo que él se salta (ocultos, temporales), por si acaso.
TEMPORALES = (".tmp", ".temp", ".part", ".partial", ".crdownload", ".download", ".swp", ".swx", ".lock", "~")


@dataclass(frozen=True)
class FicheroDejado:
    nombre: str
    tamano: int
    #: La hora de modificación, en nanosegundos (la del lector, del mismo reloj que el del vigía).
    mtime: int
    #: La ruta en el servidor, como la escribiría Hermes en su línea ``MEDIA:``.
    ruta: str
    #: Cuándo lo dio el vigía por acabado.
    instante: float
    #: La conversación a la que va (``atribuir``), o ``None``.
    sesion: str | None = None
    #: Si ya se buscó su conversación (con o sin suerte).
    atribuido: bool = False
    #: Si ya no hay que avisar de él: salió el aviso, era viejo o caducó.
    anunciado: bool = False
    #: Cuándo llegó a la carpeta, en nanosegundos: la más reciente de su ``mtime`` y su ``ctime``.
    llegada: int = 0

    @property
    def version(self) -> tuple:
        return (self.tamano, self.mtime)

    @property
    def clave(self) -> str:
        return f"fichero:{self.nombre}:{self.mtime}"

    def con(self, **cambios) -> "FicheroDejado":
        return FicheroDejado(**{**asdict(self), **cambios})


def nombre_valido(nombre: object) -> bool:
    """Un nombre de fichero de la carpeta misma que se puede avisar: sin barras ni controles, en UTF-8, ni oculto ni
    temporal. Lo demás no se cuenta, venga de donde venga."""
    if not isinstance(nombre, str) or not nombre or len(nombre) > MAX_NOMBRE or "/" in nombre or "\\" in nombre:
        return False
    if nombre.startswith((".", "~")) or nombre.lower().endswith(TEMPORALES):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in nombre):
        return False
    try:
        nombre.encode("utf-8")
    except UnicodeEncodeError:
        # Un nombre que no es UTF-8 (el lector lo manda con sus bytes escapados): la app no podría ni pedirlo.
        return False
    return True


def _entero(valor: object) -> int | None:
    return valor if isinstance(valor, int) and not isinstance(valor, bool) and valor >= 0 else None


class Exportaciones:
    """Lo que se sabe de la carpeta: qué versiones se conocen, cuáles están cambiando y cuáles faltan por avisar. Lo
    llaman el hilo que habla con el lector (``observar``), el bucle (``por_anunciar``, ``atribuir``, ``anunciado``) y la
    API (``de_la_sesion``), con un cerrojo. Se guarda en el estado de la base: un reinicio no vuelve a avisar de nada, y
    lo que no llegó a salir se intenta otra vez mientras no caduque."""

    def __init__(self, almacen, *, estabilidad: float = ESTABILIDAD, antiguedad_maxima: float = ANTIGUEDAD_MAXIMA,
                 clave: str = CLAVE):
        self.almacen = almacen
        #: Donde se guarda lo visto: la del principal, `exportaciones`; la de un agente, `exportaciones:<perfil>`.
        self.clave = clave
        self.estabilidad = estabilidad
        self.antiguedad_maxima = antiguedad_maxima
        self._cerrojo = threading.Lock()
        # nombre → (versión, desde cuándo se ve así), de lo que aún no se ha dado por acabado.
        self._cambiando: dict = {}
        self._carpeta: str | None = None
        # Lo que contó el lector la última vez (``None``: aún nada).
        self._presentes: set | None = None
        guardado = self._leer()
        self._base = guardado.get("base")
        self._conocidos: dict = {}
        for nombre, datos in (guardado.get("ficheros") or {}).items():
            try:
                self._conocidos[nombre] = FicheroDejado(nombre=nombre, **datos)
            except TypeError:
                continue

    # -- Lo que guarda

    def _leer(self) -> dict:
        try:
            datos = json.loads(self.almacen.leer_estado(self.clave) or "{}")
        except ValueError:
            return {}
        return datos if isinstance(datos, dict) else {}

    def _guardar(self) -> None:
        recientes = sorted(self._conocidos.values(), key=lambda f: (max(f.llegada, f.mtime), f.nombre),
                           reverse=True)[:MAX_RECORDADOS]
        self._conocidos = {f.nombre: f for f in recientes}
        datos = {"base": self._base, "ficheros": {f.nombre: {k: v for k, v in asdict(f).items() if k != "nombre"}
                                                  for f in recientes}}
        self.almacen.guardar_estado(self.clave, json.dumps(datos, ensure_ascii=False, sort_keys=True))

    # -- Lo que ve el lector

    def carpeta_vista(self, carpeta: object) -> None:
        """La carpeta de exportaciones, como la dice el lector: absoluta y limpia, o nada."""
        if not isinstance(carpeta, str) or not carpeta.startswith("/") or len(carpeta) > 4096:
            return
        carpeta = carpeta.rstrip("/")
        partes = carpeta.split("/")[1:]
        if not partes or any(parte in ("", ".", "..") for parte in partes):
            return
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in carpeta):
            return
        with self._cerrojo:
            self._carpeta = carpeta

    @property
    def carpeta(self) -> str | None:
        return self._carpeta

    def observar(self, entradas: object, ahora: float) -> list:
        """Lo que dice el lector ahora de la carpeta. Devuelve los ficheros que acaban de darse por nuevos (para
        despertar al bucle)."""
        if not isinstance(entradas, list) or self._carpeta is None:
            return []
        nuevos = []
        cambio = False
        with self._cerrojo:
            primera = self._base is None
            vistos = set()
            for entrada in entradas:
                if not isinstance(entrada, dict):
                    continue
                nombre = entrada.get("nombre")
                tamano, mtime = _entero(entrada.get("tamano")), _entero(entrada.get("mtime"))
                if not nombre_valido(nombre) or tamano is None or mtime is None or nombre in vistos:
                    continue
                ctime = _entero(entrada.get("ctime"))
                llegada = max(mtime, ctime if ctime is not None else 0)
                vistos.add(nombre)
                version = (tamano, mtime)
                conocido = self._conocidos.get(nombre)
                if conocido is not None and conocido.version == version:
                    self._cambiando.pop(nombre, None)
                    continue
                fichero = FicheroDejado(nombre=nombre, tamano=tamano, mtime=mtime,
                                        ruta=f"{self._carpeta}/{nombre}", instante=ahora, llegada=llegada)
                if primera:
                    # La primera mirada de la vida del vigía: lo que ya hay no es nuevo.
                    self._conocidos[nombre] = fichero.con(atribuido=True, anunciado=True)
                    cambio = True
                    continue
                antes = self._cambiando.get(nombre)
                if antes is None or antes[0] != version:
                    self._cambiando[nombre] = (version, ahora)
                    continue
                if ahora - antes[1] < self.estabilidad:
                    continue
                del self._cambiando[nombre]
                viejo = ahora - llegada / 1e9 > self.antiguedad_maxima
                self._conocidos[nombre] = fichero.con(atribuido=viejo, anunciado=viejo)
                cambio = True
                if not viejo:
                    nuevos.append(self._conocidos[nombre])
            for nombre in [n for n in self._cambiando if n not in vistos]:
                del self._cambiando[nombre]
            self._presentes = vistos
            if primera:
                self._base = ahora
                cambio = True
            if cambio:
                self._guardar()
        if nuevos:
            registro.info("%d fichero(s) nuevo(s) en exports", len(nuevos))
        return nuevos

    # -- Lo que hace el bucle

    def por_anunciar(self, ahora: float) -> list:
        """Lo que falta por avisar, del más antiguo al más reciente. Lo que lleva más de ``CADUCIDAD_DEL_AVISO`` sin
        salir se deja: ya no es «nuevo»."""
        with self._cerrojo:
            pendientes, caducados = [], False
            for fichero in list(self._conocidos.values()):
                if fichero.anunciado:
                    continue
                if ahora - fichero.instante > CADUCIDAD_DEL_AVISO:
                    self._conocidos[fichero.nombre] = fichero.con(atribuido=True, anunciado=True)
                    caducados = True
                    continue
                pendientes.append(fichero)
            if caducados:
                self._guardar()
            return sorted(pendientes, key=lambda f: (f.instante, f.nombre))

    def atribuir(self, fichero: FicheroDejado, sesion: str | None) -> FicheroDejado:
        """Apunta a qué conversación va (o que no se le encontró ninguna). Si entretanto ha cambiado, nada."""
        with self._cerrojo:
            actual = self._conocidos.get(fichero.nombre)
            if actual is None or actual.version != fichero.version:
                return fichero
            hecho = actual.con(sesion=sesion, atribuido=True)
            self._conocidos[fichero.nombre] = hecho
            self._guardar()
            return hecho

    def anunciado(self, fichero: FicheroDejado) -> None:
        with self._cerrojo:
            actual = self._conocidos.get(fichero.nombre)
            if actual is not None and actual.version == fichero.version and not actual.anunciado:
                self._conocidos[fichero.nombre] = actual.con(anunciado=True)
                self._guardar()

    def de_la_sesion(self, sesion: str, limite: int = 50) -> list:
        """Los ficheros atribuidos a esa conversación que siguen en la carpeta, del más reciente al más antiguo."""
        with self._cerrojo:
            presentes = self._presentes
            suyos = [f for f in self._conocidos.values()
                     if f.sesion == sesion and (presentes is None or f.nombre in presentes)]
        return sorted(suyos, key=lambda f: (f.instante, f.nombre), reverse=True)[:limite]


# -- A qué conversación va


def _cadenas(valor: object, profundidad: int = 0):
    """Todos los textos de un valor de una fila (el contenido, las llamadas a herramientas con sus argumentos), y los de
    lo que dentro de ellos sea JSON: los argumentos de una herramienta y lo que devuelve suelen serlo, con los
    caracteres que no son ASCII escapados (``\\u00f3``)."""
    if profundidad > 6:
        return
    if isinstance(valor, str):
        yield valor
        if valor[:1] in ("{", "[") and len(valor) <= 1_000_000:
            try:
                dentro = json.loads(valor)
            except ValueError:
                return
            yield from _cadenas(dentro, profundidad + 1)
    elif isinstance(valor, dict):
        for dentro in valor.values():
            yield from _cadenas(dentro, profundidad + 1)
    elif isinstance(valor, list):
        for dentro in valor:
            yield from _cadenas(dentro, profundidad + 1)


def _patron(nombre: str) -> re.Pattern:
    """El nombre entero, no un trozo de otro: ni «a.txt» en «data.txt», ni «informe.pdf» en «informe.pdf.bak»."""
    return re.compile(r"(?<![\w.\-+~@%])" + re.escape(nombre) + r"(?![\w\-+~@%]|\.[\w])")


def menciona(filas: list, fichero: FicheroDejado) -> bool:
    """Si alguna fila nombra el fichero: por su nombre entero, en lo que se escribió, en los argumentos de una
    herramienta o en lo que devolvió (también su ruta, que acaba en él)."""
    patron = _patron(fichero.nombre)
    for fila in filas:
        if not isinstance(fila, dict):
            continue
        for texto in _cadenas([fila.get("content"), fila.get("tool_calls")]):
            if fichero.nombre in texto and patron.search(texto):
                return True
    return False


def _actividad(sesion: dict) -> float:
    valor = sesion.get("last_active") or sesion.get("started_at") or 0
    return float(valor) if isinstance(valor, (int, float)) and not isinstance(valor, bool) else 0.0


def atribuir(hermes, ficheros: list, ahora: float, bandeja: list | None = None) -> dict:
    """``{nombre: sesión o None}``: la conversación a la que va cada fichero. La de la bandeja con actividad reciente
    cuyas últimas filas lo nombran (la más reciente primero), o la de un subagente suyo que lo nombra, subiendo de hija
    a madre. Lo mejor que se puede: un fichero que nadie nombra (lo hizo una tarea programada, o un programa que se
    inventó el nombre) no va a ninguna. Cada conversación se lee una vez para todos."""
    pendientes = {f.nombre: f for f in ficheros}
    resultado = dict.fromkeys(pendientes)
    if not pendientes:
        return resultado
    if bandeja is None:
        bandeja = hermes.sesiones()
    bandeja = [s for s in bandeja if isinstance(s, dict) and isinstance(s.get("id"), str)]
    ids = {s["id"] for s in bandeja}

    def buscar_en(sesion: str, a_quien: str) -> None:
        filas = hermes.mensajes(sesion, FILAS_POR_CONVERSACION)
        for nombre in [n for n, f in pendientes.items() if menciona(filas, f)]:
            resultado[nombre] = a_quien
            del pendientes[nombre]

    recientes = sorted((s for s in bandeja if ahora - _actividad(s) < RECIENTE), key=_actividad, reverse=True)
    for sesion in recientes[:MAX_CONVERSACIONES]:
        if not pendientes:
            return resultado
        buscar_en(sesion["id"], sesion["id"])
    if not pendientes:
        return resultado
    todas = [s for s in hermes.sesiones_con_hijas() if isinstance(s, dict) and isinstance(s.get("id"), str)]
    madres = {s["id"]: s.get("parent_session_id") for s in todas}

    def conversacion_de(hija: str) -> str | None:
        actual = hija
        for _ in range(MAX_SALTOS):
            actual = madres.get(actual)
            if not isinstance(actual, str):
                return None
            if actual in ids:
                return actual
        return None

    hijas = sorted((s for s in todas if s["id"] not in ids and isinstance(s.get("parent_session_id"), str)
                    and ahora - _actividad(s) < RECIENTE), key=_actividad, reverse=True)
    for hija in hijas[:MAX_CONVERSACIONES]:
        if not pendientes:
            break
        conversacion = conversacion_de(hija["id"])
        if conversacion is not None:
            buscar_en(hija["id"], conversacion)
    return resultado


# -- El hilo que habla con el lector


class VigiaDeExportaciones:
    """Mantiene abierta la vigilancia del lector y le pasa a ``Exportaciones`` lo que cuenta. Un lector que se corta o se
    acaba (a los diez minutos) se vuelve a llamar; uno que no sabe vigilar (de antes de la 1.5.1) contesta ``invalida``, y
    se le vuelve a preguntar cada hora."""

    def __init__(self, ruta_socket: str, exportaciones: Exportaciones, despertar, *, reloj=time.time,
                 plazo: float = PLAZO_DE_LECTURA, perfil: str | None = None):
        if perfil is not None and (not PATRON_PERFIL.fullmatch(perfil) or perfil == PRINCIPAL):
            raise ValueError("perfil sin la forma de uno de Hermes: %r" % (perfil,))
        self.ruta_socket = ruta_socket
        self.exportaciones = exportaciones
        self.despertar = despertar
        self.reloj = reloj
        self.plazo = plazo
        #: Lo que se le pide al lector: la del principal, o la de un agente (`?exports <perfil>`, desde la 1.6.0), cuya
        #: carpeta saca el lector de su propia casa: aquí solo va el nombre del perfil.
        self.peticion = PETICION if perfil is None else b"?exports " + perfil.encode("ascii") + b"\n"

    def correr(self, parar: threading.Event) -> None:
        fallos = 0
        while not parar.is_set():
            try:
                acabada = self.una_vigilancia(parar)
            except OSError as error:
                fallos += 1
                if fallos == 1:
                    registro.info("el lector no deja vigilar exports ahora (%s): se reintenta", type(error).__name__)
                parar.wait(ESPERAS[min(fallos, len(ESPERAS)) - 1])
                continue
            if acabada:
                fallos = 0
                parar.wait(1.0)
            else:
                registro.info("el lector no sabe vigilar exports (es de antes de la 1.5.1): se vuelve a mirar en una hora")
                parar.wait(ESPERA_SIN_VIGILANCIA)

    def una_vigilancia(self, parar: threading.Event) -> bool:
        """Una conexión al lector, hasta que se acaba. Devuelve si era una vigilancia (``False``: el lector no sabe).
        Un lector que cierra sin decir nada es un fallo (``OSError``): se espera antes de volver a llamarlo."""
        conexion = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conexion.settimeout(self.plazo)
        try:
            conexion.connect(self.ruta_socket)
            conexion.sendall(self.peticion)
            lineas = conexion.makefile("rb")
            vigilando = False
            for linea in lineas:
                if parar.is_set():
                    return True
                try:
                    datos = json.loads(linea)
                except ValueError:
                    return vigilando
                if not isinstance(datos, dict):
                    return vigilando
                vigilando = True
                if "carpeta" in datos:
                    self.exportaciones.carpeta_vista(datos["carpeta"])
                if "ficheros" in datos and self.exportaciones.observar(datos["ficheros"], self.reloj()):
                    self.despertar()
            if not vigilando:
                raise ConnectionError("el lector cerró sin contestar")
            return True
        finally:
            conexion.close()


# -- Las de cada agente (contrato §18.9, desde la 1.6.0)


class ExportacionesDeLosAgentes:
    """Lo de ``exports/`` de cada perfil: la del principal y una por agente servido, cada una con lo suyo guardado aparte
    (``exportaciones:<perfil>``) y con su propia vigilancia del lector (``?exports <perfil>``), que se pone y se quita
    según los agentes que haya (``al_dia``, cada ``REPASO_DE_AGENTES`` desde ``correr``). La del principal la vigila
    quien la creó, como antes."""

    def __init__(self, almacen, principal: Exportaciones | None, ruta_socket: str | None, despertar, *,
                 estabilidad: float = ESTABILIDAD, antiguedad_maxima: float = ANTIGUEDAD_MAXIMA, reloj=time.time,
                 arrancar: bool = True):
        self.almacen, self.ruta_socket, self.despertar, self.reloj = almacen, ruta_socket, despertar, reloj
        self.estabilidad, self.antiguedad_maxima = estabilidad, antiguedad_maxima
        #: Sin `arrancar`, no se lanza ninguna vigilancia (las pruebas le pasan lo que vería el lector).
        self.arrancar = arrancar
        self._cerrojo = threading.Lock()
        self._de: dict = {PRINCIPAL: principal} if principal is not None else {}
        # perfil -> el evento que para su vigilancia.
        self._paradas: dict = {}

    def de(self, perfil: str) -> Exportaciones | None:
        with self._cerrojo:
            return self._de.get(perfil)

    def perfiles(self) -> list:
        with self._cerrojo:
            return sorted(self._de, key=lambda perfil: (perfil != PRINCIPAL, perfil))

    def al_dia(self, perfiles) -> None:
        """Los agentes servidos ahora: los nuevos empiezan a vigilarse; los que se fueron, dejan de hacerlo."""
        quiere = {p for p in perfiles if isinstance(p, str) and PATRON_PERFIL.fullmatch(p) and p != PRINCIPAL}
        with self._cerrojo:
            for perfil in sorted(quiere - set(self._de)):
                hechas = Exportaciones(self.almacen, estabilidad=self.estabilidad,
                                       antiguedad_maxima=self.antiguedad_maxima, clave=CLAVE + ":" + perfil)
                self._de[perfil] = hechas
                if self.arrancar and self.ruta_socket:
                    parar = threading.Event()
                    self._paradas[perfil] = parar
                    vigia = VigiaDeExportaciones(self.ruta_socket, hechas, self.despertar, reloj=self.reloj,
                                                 perfil=perfil)
                    threading.Thread(target=vigia.correr, args=(parar,), name="exportaciones-" + perfil,
                                     daemon=True).start()
                registro.info("se vigila el exports/ de un agente más (%d)", len(self._de) - 1)
            for perfil in [p for p in self._de if p != PRINCIPAL and p not in quiere]:
                del self._de[perfil]
                parar = self._paradas.pop(perfil, None)
                if parar is not None:
                    parar.set()

    def correr(self, parar: threading.Event, perfiles, cada: float = REPASO_DE_AGENTES) -> None:
        """El hilo que mantiene las vigilancias al día con los agentes servidos (``perfiles()``)."""
        while not parar.is_set():
            try:
                self.al_dia(perfiles())
            except Exception:  # noqa: BLE001 — un repaso que falla no para la vigilancia de las demás
                registro.exception("no se pudo repasar qué agentes hay para vigilar su exports/")
            if parar.wait(cada):
                break
        with self._cerrojo:
            for evento in self._paradas.values():
                evento.set()
