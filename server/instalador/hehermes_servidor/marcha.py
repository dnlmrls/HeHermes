"""Cómo va una pasada de `instalar`, y cómo acaba si algo falla (desde la 0.11.1).

Casi siempre lo lanza el Hermes del usuario desde su chat, con su herramienta de terminal: sin TTY, con la salida a una
tubería y con un plazo (180 s de serie; al pasarse, SIGTERM a todo el grupo de procesos y, un segundo después,
SIGKILL), y lo que imprime lo lee el modelo y, si la persona se la pega, la app. Por eso:

- **Cada paso dice cuál es y cuándo empieza**, con una línea `hehermes-paso: 4/9 venv (12 s)` (los segundos, desde que
  arrancó el instalador): si lo cortan, lo impreso dice hasta dónde llegó. El lanzador pone la salida con búfer de
  línea, así que cada una sale al momento.
- **Todo fallo acaba en `hehermes-error:<código>`** por chat, sola y la última, con `hehermes-detalle:paso=<paso>`
  justo antes si se paró a mitad: `apt`, `pip`, `a-medias` (lo demás que se para a mitad), `python` (lo que no se
  esperaba), `ocupado` (otro instalador en marcha) e `interrumpido` (una señal). Por un terminal no: quien lo lee es una
  persona.
- **Lo que se dice es verdad**: qué pasos quedan hechos y apuntados, y si Hermes se ha tocado (lo suyo va lo último:
  `modo_tls.aplicar_hermes`).
- **Lo que la persona tiene que saber, también para la app**: por chat, líneas `hehermes-aviso:<código>` (con
  `clave=valor` detrás si hace falta), juntas y justo antes del enlace.
"""

from __future__ import annotations

import contextlib
import os
import signal
import threading
import time
import traceback

from .aplicar import Parada
from .deteccion import PREFIJO_DETALLE, PREFIJO_ERROR  # noqa: F401

PREFIJO_PASO = "hehermes-paso:"
PREFIJO_AVISO = "hehermes-aviso:"

#: Desde cuándo cuenta el reloj de los pasos: lo pone `cli.main` al empezar (el plazo de Hermes cuenta desde ahí, más
#: lo poco de la descarga).
INICIO = time.monotonic()


def poner_el_reloj() -> None:
    global INICIO
    INICIO = time.monotonic()


def segundos() -> int:
    return int(time.monotonic() - INICIO)


class Interrupcion(Parada):
    """Una señal a mitad: SIGTERM (el plazo de la terminal de Hermes, su `/stop`, un `kill`), SIGHUP (un SSH que se
    cierra: iOS suspende la app del terminal) o SIGINT (Ctrl-C). Es una `Parada`: el paso en marcha vuelve a como
    estaba, y lo de antes se queda hecho y apuntado."""

    def __init__(self, senal: str):
        super().__init__("me han parado a mitad (%s)" % senal, codigo="interrumpido")
        self.senal = senal


class Ocupado(Exception):
    """Otro `hehermes-servidor` tiene el cerrojo: dos a la vez se pisarían el manifiesto."""


class Marcha:
    """Los pasos de una pasada, lo hecho, si Hermes se ha tocado y lo que hay que avisar. La crea `cli._instalar` con
    los pasos que tocan (`modo_tls.pasos_de`); sin ella (`aplicar_tls` llamado aparte, en las pruebas), no se imprime
    nada de esto."""

    def __init__(self, claves=(), salida=None):
        self.claves = list(claves)
        self.salida = salida
        self.hechos = []
        self.actual = None
        #: Lo que ya se ha escrito en Hermes (su .env, su SOUL.md), para decirlo con verdad si algo falla.
        self.en_hermes = []
        #: (código, {clave: valor}) de cada aviso para la app, en orden y sin repetir.
        self.avisos = []

    def empezar(self, clave: str) -> None:
        if self.actual is not None:
            self.hechos.append(self.actual)
        self.actual = clave
        if clave not in self.claves:
            self.claves.append(clave)
        if self.salida is not None:
            self.salida("%s %d/%d %s (%d s)" % (PREFIJO_PASO, self.claves.index(clave) + 1, len(self.claves), clave,
                                                segundos()))

    def acabar(self) -> None:
        if self.actual is not None:
            self.hechos.append(self.actual)
            self.actual = None

    def avisar(self, codigo: str, **datos) -> None:
        aviso = (codigo, datos)
        if aviso not in self.avisos:
            self.avisos.append(aviso)

    def lineas_de_avisos(self) -> list:
        return [PREFIJO_AVISO + codigo + "".join(" %s=%s" % (k, v) for k, v in datos.items())
                for codigo, datos in self.avisos]

    def resumen(self) -> str:
        """Qué queda hecho y qué no, para el mensaje del fallo."""
        partes = []
        if self.actual is not None:
            partes.append("Me he parado en el paso %d/%d (%s), a los %d s." % (
                self.claves.index(self.actual) + 1, len(self.claves), self.actual, segundos()))
        if self.hechos:
            partes.append("Lo de antes (%s) queda hecho y apuntado, y lo de ese paso, como estaba."
                          % ", ".join(self.hechos))
        elif self.actual is not None:
            partes.append("Lo de ese paso ha vuelto a como estaba.")
        if self.en_hermes:
            partes.append("A Hermes ya le he dejado %s." % " y ".join(self.en_hermes))
        else:
            partes.append("Hermes, sin tocar: ni su .env ni su SOUL.md.")
        return " ".join(partes)


def describir(error: BaseException) -> str:
    """Una línea con lo que no se esperaba, para personas y para quien dé soporte: el tipo, el mensaje y dónde, sin el
    traceback entero (por chat lo lee el modelo)."""
    donde = traceback.extract_tb(error.__traceback__)
    lugar = ""
    if donde:
        ultimo = donde[-1]
        lugar = " (en %s:%d)" % (os.path.basename(ultimo.filename), ultimo.lineno)
    texto = str(error)
    return "%s%s%s" % (type(error).__name__, ": " + texto if texto else "", lugar)


def a_prueba(salida):
    """La salida de siempre, sin que un terminal que se ha ido (SIGHUP) o una tubería rota tumben al instalador con un
    traceback a mitad de decir qué ha pasado: lo que no se puede escribir se pierde, y lo demás sigue."""
    estado = {"muda": False}

    def escribir(*args, **kwargs):
        if estado["muda"]:
            return
        try:
            salida(*args, **kwargs)
        except OSError:
            estado["muda"] = True
    return escribir


@contextlib.contextmanager
def senales(salida, por_chat=False):
    """SIGTERM, SIGHUP y SIGINT, mientras dura `instalar` (y las demás órdenes): la primera es una `Interrupcion`, que
    deshace el paso en marcha y acaba diciéndolo; las de detrás no interrumpen lo que se deshace. Por chat, la línea del
    código sale ya en el manejador: el plazo de Hermes manda SIGKILL un segundo después del SIGTERM, y si lo de deshacer
    tarda, la de después no llegaría. Al salir, las señales vuelven a como estaban (en las pruebas, el mismo proceso
    sigue)."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    recibidas = []

    def manejador(numero, marco):
        if recibidas:
            return
        nombre = signal.Signals(numero).name
        recibidas.append(nombre)
        if por_chat:
            try:
                salida("\n" + PREFIJO_ERROR + "interrumpido")
            except (OSError, RuntimeError):
                pass
        raise Interrupcion(nombre)

    antes = {}
    for senal in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        antes[senal] = signal.signal(senal, manejador)
    try:
        yield
    finally:
        for senal, anterior in antes.items():
            signal.signal(senal, anterior)
