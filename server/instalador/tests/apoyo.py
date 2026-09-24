"""Lo que comparten las pruebas del instalador: el camino al paquete y el sistema falso.

Como en ``server/avisos/tests``: un ``/etc`` temporal (la raíz del `Sistema` es una carpeta de usar y tirar) y las
órdenes del sistema falsas (ninguna llega a ejecutarse). Nada sale de la máquina ni toca nada fuera de la carpeta.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile

RAIZ = pathlib.Path(__file__).resolve().parents[1]
REPO = RAIZ.parents[1]
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))
DATOS = pathlib.Path(__file__).resolve().parent / "datos"
#: La app y la spec viven en el repositorio de HeHermes, no en el espejo público del instalador: las pruebas que atan el
#: instalador a ellas se saltan donde no están.
APP = REPO / "HeHermes"
SPEC = REPO / "docs" / "superpowers" / "specs" / "2026-09-24-instalador-servidor-design.md"

from hehermes_servidor.sistema import Resultado, Sistema  # noqa: E402


class SistemaFalso(Sistema):
    """El `Sistema` con la raíz en una carpeta temporal y las órdenes contestadas por ``responder``.

    ``responder`` va de un prefijo de la orden («systemctl is-active») a una función ``(args, entrada) -> Resultado``;
    gana el prefijo más largo. Lo que no tiene respuesta sale bien y sin salida. ``http`` hace lo mismo con las URL.
    """

    def __init__(self, **opciones):
        self._carpeta = tempfile.mkdtemp(prefix="hh-instalador-")
        self.responder: dict = {}
        self.respuestas_http: dict = {}
        self.ordenes: list = []
        self.peticiones_http: list = []
        # Lo que contesta a lo que no está en `responder` (el `ServidorFalso`), y a las URL sin respuesta fija.
        self.resto = None
        self.http_falso = None
        opciones.setdefault("version_python", (3, 11, 2))
        opciones.setdefault("nucleo", "6.1.0-25-amd64")
        super().__init__(raiz=self._carpeta, ejecutor=self._ejecutar, http=self._http, **opciones)

    def limpiar(self):
        shutil.rmtree(self._carpeta, ignore_errors=True)

    def _ejecutar(self, args, entrada=None, heredar=False):
        args = list(args)
        self.ordenes.append(args)
        mejor = None
        for prefijo in self.responder:
            partes = prefijo.split()
            if args[:len(partes)] == partes and (mejor is None or len(partes) > len(mejor.split())):
                mejor = prefijo
        if mejor is None:
            if self.resto is not None:
                return self.resto(args, entrada, heredar)
            return Resultado(0, "", "")
        return self.responder[mejor](args, entrada)

    def _http(self, url, cabeceras):
        self.peticiones_http.append((url, dict(cabeceras)))
        respuesta = self.respuestas_http.get(url)
        if callable(respuesta):
            return respuesta(url, cabeceras)
        if respuesta is None and self.http_falso is not None:
            return self.http_falso(url, cabeceras)
        return respuesta if respuesta is not None else (None, b"")

    # Ayudas para montar la raíz

    def poner(self, ruta: str, texto, modo: int = 0o644) -> None:
        self.escribir(ruta, texto.encode() if isinstance(texto, str) else texto, modo=modo)

    def foto(self) -> dict:
        """Todo lo que hay bajo la raíz: ruta, tipo, modo y contenido o destino. Para comparar antes y después."""
        foto = {}
        for carpeta, carpetas, ficheros in os.walk(self.raiz):
            for nombre in carpetas + ficheros:
                real = os.path.join(carpeta, nombre)
                ruta = "/" + os.path.relpath(real, self.raiz)
                datos = os.lstat(real)
                if os.path.islink(real):
                    foto[ruta] = ("enlace", os.readlink(real))
                elif os.path.isdir(real):
                    foto[ruta] = ("carpeta", oct(datos.st_mode & 0o7777))
                else:
                    with open(real, "rb") as f:
                        foto[ruta] = ("fichero", oct(datos.st_mode & 0o7777), f.read())
        return foto


def bien(salida: str = "") -> "callable":
    return lambda args, entrada: Resultado(0, salida, "")


def mal(error: str = "", codigo: int = 1, salida: str = "") -> "callable":
    return lambda args, entrada: Resultado(codigo, salida, error)
