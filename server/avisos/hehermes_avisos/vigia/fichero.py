"""``GET /avisos/v1/fichero?sesion=&ruta=``: un fichero que Hermes marcó con ``MEDIA:``, de solo lectura
(``server/API-CONTRACT.md`` §11).

Hermes corre como root y el vigía no puede leer sus ficheros. Tampoco se le da nada de root, ni ``sudo``: con
``NoNewPrivileges`` y ``ProtectHome`` no serviría, y quitárselos sería abrir el proceso que atiende al túnel. Lo lee
un lector aparte (``despliegue/hehermes-leer-media``), de root, lanzado por systemd en cada conexión a su socket y con
su propia jaula. El vigía solo decide **si** se puede pedir, y el lector, **qué** se puede leer:

1. Que la ruta esté marcada: una fila ``assistant`` de esa sesión, entre las 500 últimas, con una línea ``MEDIA:``
   que, con las mismas reglas que la app (``ExtraccionMedia.swift``), dé exactamente esa ruta. Si no, 404 sin mirar
   el disco: la respuesta no dice si el fichero existe.
2. Que el lector la dé por buena (sus reglas, en su propio fichero), y los bytes, por partes, de él a la app.

En el registro sale el resultado, la extensión y el tamaño: ni la ruta ni nada del contenido.
"""

from __future__ import annotations

import collections
import logging
import math
import os
import re
import socket
import threading
import time
import urllib.parse

from ..comun import ErrorHTTP
from .hermes import ErrorHermes

registro = logging.getLogger("vigia.fichero")

TOPE = 50 * 1024 * 1024
MAX_RUTA = 4096
FILAS = 500
TROZO = 64 * 1024
PREFIJO = "MEDIA:"
# Lo que `CharacterSet.whitespaces` de Swift quita de los bordes: el tabulador y los espacios de Unicode (Zs).
ESPACIOS = " \t               　"

TIPOS = {
    "pdf": "application/pdf", "md": "text/markdown", "markdown": "text/markdown", "txt": "text/plain",
    "log": "text/plain", "csv": "text/csv", "tsv": "text/tab-separated-values", "json": "application/json",
    "html": "text/html", "htm": "text/html", "xml": "application/xml", "yaml": "application/yaml",
    "yml": "application/yaml", "css": "text/css", "js": "text/javascript",
    "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
    "heic": "image/heic", "svg": "image/svg+xml", "mp3": "audio/mpeg", "m4a": "audio/mp4", "wav": "audio/wav",
    "ogg": "audio/ogg", "mp4": "video/mp4", "mov": "video/quicktime", "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
# El código se abre como texto (la app lo colorea por la extensión).
for _extension in ("py", "sh", "zsh", "bash", "swift", "ts", "toml", "sql", "go", "rs", "c", "h", "cpp", "java",
                   "rb", "ini", "conf", "cfg", "diff", "patch"):
    TIPOS[_extension] = "text/plain"

# Lo que dice el lector y cómo se le contesta a la app.
POR_ESTADO = {
    "invalida": (400, "parametro_invalido", "La ruta no tiene la forma que se espera"),
    "no_existe": (404, "fichero_no_disponible", "Ese fichero no está disponible"),
    "prohibida": (403, "ruta_prohibida", "Esa ruta no se puede leer"),
    "no_es_fichero": (403, "ruta_prohibida", "Eso no es un fichero normal"),
    "carrera": (403, "ruta_prohibida", "La ruta cambió mientras se abría"),
    "demasiado_grande": (413, "fichero_demasiado_grande", "El fichero pasa de 50 MB"),
    "no_autorizado": (503, "lector_no_disponible", "El lector de ficheros no atiende al vigía"),
}
# Como los ids de sesión de la ampliación de los turnos (`api.PATRON_ID`).
PATRON_SESION = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")


def _no_disponible() -> ErrorHTTP:
    """El mismo 404 para lo que no está marcado, la sesión que no existe y el fichero que ya no está."""
    return ErrorHTTP(404, "fichero_no_disponible", "Ese fichero no está disponible")


def _invalido(que: str) -> ErrorHTTP:
    return ErrorHTTP(400, "parametro_invalido", que)


def ruta_de_linea(linea: str) -> str | None:
    """La ruta de una línea ``MEDIA:``, o ``None``: lo mismo que ``ExtraccionMedia.ruta(en:)`` de la app, para que lo
    que ella enseña como tarjeta sea justo lo que aquí cuenta como marcado."""
    linea = linea.strip(ESPACIOS)
    if len(linea) > 2 and linea.startswith("`") and linea.endswith("`"):
        linea = linea[1:-1]
    if not linea.startswith(PREFIJO):
        return None
    ruta = linea[len(PREFIJO):].strip(ESPACIOS)
    return ruta if ruta.startswith(("/", "~")) else None


def esta_marcada(filas: list, ruta: str) -> bool:
    for fila in filas:
        contenido = fila.get("content")
        if fila.get("role") != "assistant" or not isinstance(contenido, str) or PREFIJO not in contenido:
            continue
        if any(ruta_de_linea(linea) == ruta for linea in contenido.split("\n")):
            return True
    return False


def tipo_por_extension(nombre: str) -> str:
    _, punto, extension = nombre.rpartition(".")
    return TIPOS.get(extension.lower(), "application/octet-stream") if punto else "application/octet-stream"


def disposicion(nombre: str) -> str:
    """``Content-Disposition`` con el nombre (RFC 6266): en ASCII sin nada que cierre las comillas, y en UTF-8 entero."""
    ascii_ = "".join(c if 0x20 <= ord(c) < 0x7F and c not in '"\\' else "_" for c in nombre)
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (ascii_, urllib.parse.quote(nombre, safe=""))


def parametros(consulta: str) -> tuple:
    """``(sesion, ruta)`` de la consulta. Con porcentajes, y un ``+`` es un ``+`` (``URLComponents`` no lo codifica)."""
    vistos: dict = {}
    for trozo in consulta.split("&") if consulta else []:
        nombre, igual, valor = trozo.partition("=")
        if not igual or nombre in vistos:
            raise _invalido("Parámetros repetidos o sin valor")
        try:
            vistos[nombre] = urllib.parse.unquote(valor, errors="strict")
        except UnicodeDecodeError:
            raise _invalido("La consulta no es UTF-8") from None
    return vistos.get("sesion"), vistos.get("ruta")


class Limites:
    """Cuántas descargas en el último minuto y cuántas a la vez. Cuentan todas las peticiones, también las que no
    estaban marcadas: así no se puede ir probando rutas a ver cuál está."""

    def __init__(self, por_minuto: int = 30, simultaneas: int = 2, reloj=time.monotonic):
        self.por_minuto = por_minuto
        self.simultaneas = simultaneas
        self.reloj = reloj
        self._recientes: collections.deque = collections.deque()
        self._en_curso = 0
        self._candado = threading.Lock()

    def entrar(self) -> None:
        with self._candado:
            ahora = self.reloj()
            while self._recientes and ahora - self._recientes[0] >= 60:
                self._recientes.popleft()
            if self._en_curso >= self.simultaneas:
                raise ErrorHTTP(429, "demasiadas_descargas", "Hay otras descargas en marcha", {"Retry-After": "5"})
            if len(self._recientes) >= self.por_minuto:
                espera = max(1, math.ceil(60 - (ahora - self._recientes[0])))
                raise ErrorHTTP(429, "demasiadas_descargas", "Demasiadas descargas seguidas",
                                {"Retry-After": str(espera)})
            self._recientes.append(ahora)
            self._en_curso += 1

    def salir(self) -> None:
        with self._candado:
            self._en_curso = max(0, self._en_curso - 1)


class Descarga:
    """Lo que el lector ya ha dado por bueno: el tamaño, y la conexión de la que salen los bytes."""

    def __init__(self, conexion: socket.socket, tamano: int, adelantado: bytes, nombre: str, al_cerrar):
        self.conexion = conexion
        self.tamano = tamano
        self._adelantado = adelantado
        self.nombre = nombre
        self.tipo = tipo_por_extension(nombre)
        self._al_cerrar = al_cerrar

    def trozos(self):
        """Los bytes según llegan del lector, sin pasar del tamaño. Si se corta antes, se acaba antes."""
        quedan = self.tamano
        if self._adelantado:
            trozo = self._adelantado[:quedan]
            self._adelantado = b""
            quedan -= len(trozo)
            yield trozo
        while quedan > 0:
            try:
                trozo = self.conexion.recv(min(TROZO, quedan))
            except OSError:
                return
            if not trozo:
                return
            quedan -= len(trozo)
            yield trozo

    def cerrar(self) -> None:
        try:
            self.conexion.close()
        finally:
            al_cerrar, self._al_cerrar = self._al_cerrar, None
            if al_cerrar:
                al_cerrar()


class ClienteLector:
    """Habla con ``/run/hehermes-leer-media.sock``: una línea con la ruta, y ``ok <tamaño>`` y los bytes, o el
    estado. El protocolo está en el propio lector."""

    def __init__(self, ruta_socket: str, plazo: float = 15.0):
        self.ruta_socket = ruta_socket
        self.plazo = plazo

    def abrir(self, ruta: str) -> tuple:
        """``(conexion, tamano, lo ya leído tras la cabecera)``, o ``ErrorHTTP``."""
        conexion = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conexion.settimeout(self.plazo)
        try:
            try:
                conexion.connect(self.ruta_socket)
            except OSError:
                raise ErrorHTTP(503, "lector_no_disponible", "El lector de ficheros no está instalado o no contesta",
                                {"Retry-After": "30"}) from None
            conexion.sendall(ruta.encode("utf-8") + b"\n")
            recibido = b""
            while b"\n" not in recibido and len(recibido) < 64:
                trozo = conexion.recv(TROZO)
                if not trozo:
                    break
                recibido += trozo
        except ErrorHTTP:
            conexion.close()
            raise
        except OSError:
            conexion.close()
            raise ErrorHTTP(502, "lectura_fallida", "El lector de ficheros no ha contestado") from None
        cabecera, salto, resto = recibido.partition(b"\n")
        estado, _, tamano = cabecera.decode("ascii", "replace").partition(" ")
        if salto and estado == "ok" and tamano.isdigit() and int(tamano) <= TOPE:
            return conexion, int(tamano), resto
        conexion.close()
        if salto and estado in POR_ESTADO and not tamano:
            raise ErrorHTTP(*POR_ESTADO[estado])
        raise ErrorHTTP(502, "lectura_fallida", "El lector de ficheros no ha podido leerlo")


class Ficheros:
    """Lo que hace la ruta, sin HTTP."""

    def __init__(self, hermes, lector: ClienteLector, limites: Limites, casa: str = "/root"):
        self.hermes = hermes
        self.lector = lector
        self.limites = limites
        self.casa = casa.rstrip("/") or "/"

    def preparar(self, sesion: object, ruta: object) -> Descarga:
        if not (isinstance(sesion, str) and PATRON_SESION.fullmatch(sesion)):
            raise _invalido("Falta la sesión, o no tiene forma de sesión")
        if not (isinstance(ruta, str) and ruta.startswith(("/", "~")) and len(ruta.encode("utf-8")) <= MAX_RUTA
                and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in ruta)):
            raise _invalido("Falta la ruta, o no tiene forma de ruta")
        self.limites.entrar()
        try:
            descarga = self._preparar(sesion, ruta)
        except ErrorHTTP as error:
            self.limites.salir()
            registro.info("fichero: %d %s", error.estado, error.codigo)
            raise
        except BaseException:
            self.limites.salir()
            raise
        registro.info("fichero: 200, .%s, %d bytes", _extension(descarga.nombre), descarga.tamano)
        return descarga

    def _preparar(self, sesion: str, ruta: str) -> Descarga:
        try:
            filas = self.hermes.mensajes(sesion, FILAS)
        except ErrorHermes as error:
            if error.estado == 404:
                raise _no_disponible() from None
            raise ErrorHTTP(502, "hermes_no_disponible", "No se ha podido leer el historial de Hermes") from None
        if not esta_marcada(filas, ruta):
            raise _no_disponible()
        en_disco = self.casa.rstrip("/") + ruta[1:] if ruta == "~" or ruta.startswith("~/") else ruta
        conexion, tamano, adelantado = self.lector.abrir(en_disco)
        return Descarga(conexion, tamano, adelantado, os.path.basename(en_disco.rstrip("/")) or "fichero",
                        self.limites.salir)


def _extension(nombre: str) -> str:
    _, punto, extension = nombre.rpartition(".")
    return extension.lower()[:10] if punto else ""
