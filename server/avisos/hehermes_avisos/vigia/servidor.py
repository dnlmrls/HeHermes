"""``/avisos/v1/servidor``: Ajustes › Tu servidor, del lado del vigía (spec 2026-10-04 §3, ``server/API-CONTRACT.md``
§17). Desde la 1.5.5.

- ``GET /avisos/v1/servidor``: el estado del servidor, **sin secretos**: las versiones del instalador, de los avisos y
  de Hermes, si Hermes contesta, el espacio libre del disco de su casa, si está en marcha cada servicio, la última copia
  que hizo el ayudante del respaldo y la actualización en curso.
- ``POST /avisos/v1/servidor/actualizar`` (``{"version", "sha256"}``): se lo pasa al ayudante que actualiza
  (``despliegue/hehermes-actualizar``) y contesta 202. Lo decide él: aquí solo se mira la forma antes de molestarle.
- ``GET /avisos/v1/servidor/actualizar``: cómo va la actualización.

El vigía no tiene nada de root, y esto no le da nada: lo que no puede mirar él lo pregunta a los ayudantes por sus
sockets (el del espacio libre, el de la entrada, que ve la casa de Hermes; el de la última copia, el del respaldo; el de
la actualización, el suyo), y los servicios con ``systemctl is-active``, que no necesita root. Las rutas llevan el mismo
control de acceso que las demás: el secreto del túnel, que la pasarela solo pone a lo que trae el token de un iPhone
dado de alta (``api.ManejadorVigia``).

Lo que contestan los ayudantes se vuelve a filtrar: a la app solo le llega lo esperado y con su forma (nunca una ruta,
como la carpeta de la entrada, ni lo que diga el instalador).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import subprocess

from .. import VERSION
from ..comun import ErrorHTTP
from .hermes import ErrorHermes
from .respaldo import _error_de

registro = logging.getLogger("vigia.servidor")

PREFIJO = "/avisos/v1/servidor"
RUTA = re.compile(r"/avisos/v1/servidor(?:/(actualizar))?/?")
FORMATO = 1
NO_DISPONIBLE = "actualizar_no_disponible"
#: Lo que se espera a cada parte (un ayudante, Hermes, systemctl): la pantalla no se queda colgada de una.
PLAZO = 5.0
PATRON_UNIDAD = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.@-]{0,199}\.(service|socket|timer)")
PATRON_VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})")
PATRON_VERSION_INSTALADA = re.compile(r'^VERSION = "([0-9.]{5,14})"$', re.M)
PATRON_SHA = re.compile(r"[0-9a-f]{64}")
ESTADOS = ("libre", "descargando", "comprobando", "instalando", "hecho", "fallo")
MOTIVOS = frozenset({"descarga", "suma", "firma", "sin_firmas", "version", "instalacion", "interrumpida", "interna"})
ACTIVOS = ("active", "reloading")
USUARIO = "usuario:"


def unidad_valida(texto) -> tuple:
    """``(nombre, de usuario)`` de una unidad de la configuración (``usuario:`` delante, una de ``systemctl --user``),
    o ``ValueError``: va a la orden de ``systemctl`` tal cual."""
    if not isinstance(texto, str):
        raise ValueError("unidad no válida: %r" % (texto,))
    usuario = texto.startswith(USUARIO)
    nombre = texto[len(USUARIO):] if usuario else texto
    if not PATRON_UNIDAD.fullmatch(nombre):
        raise ValueError("unidad no válida: %r" % texto)
    return nombre, usuario


def _ejecutar(orden: list) -> str:
    r = subprocess.run(orden, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=PLAZO, check=False)
    return r.stdout.decode("utf-8", "replace")


def systemctl(unidades, usuario: bool, ejecutar=_ejecutar) -> list:
    """El estado de cada unidad (``active``, ``inactive``, ``failed``…), una línea por unidad y en orden. Sale con
    otro código que 0 si alguna no está en marcha, y eso no es un fallo: se miran las líneas."""
    orden = ["systemctl"] + (["--user"] if usuario else []) + ["is-active", "--"] + list(unidades)
    lineas = ejecutar(orden).splitlines()
    if len(lineas) < len(unidades):
        raise ValueError("systemctl no ha dicho el estado de todas")
    return [linea.strip() for linea in lineas[:len(unidades)]]


def version_del_instalador(carpeta: str) -> str | None:
    """La del instalador instalado, de su ``hehermes_servidor/__init__.py`` (``/opt/hehermes-servidor``, o la de la casa
    del usuario sin root). Solo si tiene la forma de una versión."""
    try:
        with open(os.path.join(carpeta, "hehermes_servidor", "__init__.py"), encoding="utf-8") as f:
            hallada = PATRON_VERSION_INSTALADA.search(f.read(64 * 1024))
    except (OSError, ValueError):
        return None
    return hallada.group(1) if hallada and PATRON_VERSION.fullmatch(hallada.group(1)) else None


def _entero(valor) -> bool:
    return isinstance(valor, int) and not isinstance(valor, bool)


def actualizacion_limpia(respuesta) -> dict | None:
    """El estado del ayudante que actualiza, con lo esperado y su forma; si no la tiene, nada."""
    if not isinstance(respuesta, dict) or respuesta.get("estado") not in ESTADOS:
        return None
    hora, version, motivo = respuesta.get("hora"), respuesta.get("version"), respuesta.get("motivo")
    return {"estado": respuesta["estado"], "hora": hora if _entero(hora) else None,
            "version": version if isinstance(version, str) and PATRON_VERSION.fullmatch(version) else None,
            "motivo": motivo if respuesta["estado"] == "fallo" and motivo in MOTIVOS else None,
            "firmas": respuesta.get("firmas") is True}


class Servidor:
    """La lógica de las rutas, sin HTTP. Cada dependencia puede faltar (``None``): esa parte sale ``null``.

    - ``hermes``: el cliente del api_server (``salud``).
    - ``instalador``: la carpeta del instalador instalado, para su versión.
    - ``actualizador``, ``entrada``, ``respaldo``: los clientes de los sockets de los ayudantes (``ClienteAyudante``).
    - ``servicios``: las unidades de HeHermes (``usuario:`` delante, una de usuario); ``hermes_unidad``, la de Hermes.
    """

    def __init__(self, hermes, instalador: str, actualizador, entrada, respaldo, servicios, hermes_unidad=None,
                 systemctl=systemctl):
        self.hermes, self.instalador = hermes, instalador
        self.actualizador, self.entrada, self.respaldo = actualizador, entrada, respaldo
        self.servicios = [unidad_valida(u) + ("hehermes",) for u in servicios]
        if hermes_unidad:
            self.servicios.append(unidad_valida(hermes_unidad) + ("hermes",))
        self._systemctl = systemctl

    # -- Cada parte

    def _hermes(self) -> dict:
        try:
            return {"version": self.hermes.salud(PLAZO), "contesta": True}
        except ErrorHermes:
            return {"version": None, "contesta": False}

    def _disco(self) -> dict | None:
        """Lo libre de la casa de Hermes, que ve el ayudante de la entrada (el vigía no puede mirarla)."""
        if self.entrada is None:
            return None
        try:
            respuesta, _ = self.entrada.pedir({"orden": "estado"}, plazo=PLAZO)
        except ErrorHTTP:
            return None
        libre = respuesta.get("libre") if isinstance(respuesta, dict) and respuesta.get("ok") else None
        return {"libre": libre} if _entero(libre) and libre >= 0 else None

    def _copia(self) -> dict | None:
        if self.respaldo is None:
            return None
        try:
            respuesta, _ = self.respaldo.pedir({"orden": "ultima"}, plazo=PLAZO)
        except ErrorHTTP:
            return None
        ultima = respuesta.get("ultima") if isinstance(respuesta, dict) and respuesta.get("ok") else None
        return {"ultima": ultima} if _entero(ultima) and ultima > 0 else None

    def _servicios(self) -> list:
        """Una llamada por cada tipo (del sistema y de usuario), y en el orden de la configuración."""
        estados = {}
        for usuario in (False, True):
            de_ese = [nombre for nombre, de_usuario, _ in self.servicios if de_usuario == usuario]
            if not de_ese:
                continue
            try:
                for nombre, estado in zip(de_ese, self._systemctl(de_ese, usuario)):
                    estados[(nombre, usuario)] = estado
            except (OSError, ValueError, subprocess.SubprocessError):
                registro.warning("servidor: systemctl%s no dice el estado de los servicios", " --user" if usuario
                                 else "")
        return [{"unidad": nombre, "activo": estados[(nombre, usuario)] in ACTIVOS, "de": de}
                for nombre, usuario, de in self.servicios if (nombre, usuario) in estados]

    def actualizacion(self) -> dict | None:
        if self.actualizador is None:
            return None
        try:
            respuesta, _ = self.actualizador.pedir({"orden": "estado"}, plazo=PLAZO)
        except ErrorHTTP:
            return None
        return actualizacion_limpia(respuesta) if isinstance(respuesta, dict) and respuesta.get("ok") else None

    def estado(self) -> dict:
        """Todas las partes a la vez: lo que tarda la pantalla es lo de la más lenta, y ninguna pasa de `PLAZO`."""
        partes = {"hermes": self._hermes, "disco": self._disco, "copia": self._copia, "servicios": self._servicios,
                  "actualizacion": self.actualizacion}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(partes)) as grupo:
            futuros = {nombre: grupo.submit(funcion) for nombre, funcion in partes.items()}
            hechas = {nombre: futuro.result() for nombre, futuro in futuros.items()}
        return {"formato": FORMATO, "instalador": {"version": version_del_instalador(self.instalador)},
                "avisos": {"version": VERSION}, "hermes": hechas["hermes"], "disco": hechas["disco"],
                "servicios": hechas["servicios"], "copia": hechas["copia"], "actualizacion": hechas["actualizacion"]}

    # -- La actualización

    def _pedir_al_actualizador(self, peticion: dict) -> dict:
        if self.actualizador is None:
            raise ErrorHTTP(503, NO_DISPONIBLE, "Este servidor no tiene el ayudante que actualiza")
        try:
            respuesta, _ = self.actualizador.pedir(peticion, plazo=PLAZO * 2)
        except ErrorHTTP as error:
            raise ErrorHTTP(503, NO_DISPONIBLE, "El ayudante que actualiza no contesta",
                            {"Retry-After": "30"}) from error
        if not isinstance(respuesta, dict) or not respuesta.get("ok"):
            raise _error_de(respuesta if isinstance(respuesta, dict) else {}, NO_DISPONIBLE)
        return respuesta

    def actualizar(self, cuerpo: bytes) -> dict:
        try:
            pedido = json.loads(cuerpo.decode("utf-8")) if cuerpo else None
        except (UnicodeDecodeError, ValueError):
            pedido = None
        if not isinstance(pedido, dict) or set(pedido) != {"version", "sha256"} \
                or not (isinstance(pedido["version"], str) and PATRON_VERSION.fullmatch(pedido["version"])) \
                or not (isinstance(pedido["sha256"], str) and PATRON_SHA.fullmatch(pedido["sha256"])):
            raise ErrorHTTP(400, "parametro_invalido", "El cuerpo es {\"version\": \"X.Y.Z\", \"sha256\": \"<64 hex>\"}")
        respuesta = self._pedir_al_actualizador({"orden": "actualizar", "version": pedido["version"],
                                                 "sha256": pedido["sha256"]})
        registro.info("servidor: actualizar a la %s, pedida", pedido["version"])
        hora = respuesta.get("hora")
        return {"estado": "descargando", "hora": hora if _entero(hora) else None, "version": pedido["version"]}

    # -- Las rutas

    def atender(self, metodo: str, ruta: str, leer_cuerpo) -> tuple:
        """``(estado, objeto JSON, cabeceras)``."""
        sin_cache = {"Cache-Control": "no-store"}
        encontrada = RUTA.fullmatch(ruta)
        if not encontrada:
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        if encontrada.group(1) is None:
            _exigir(metodo, "GET")
            return 200, self.estado(), sin_cache
        if metodo == "POST":
            return 202, self.actualizar(leer_cuerpo()), sin_cache
        _exigir(metodo, "GET", "GET, POST")
        estado = actualizacion_limpia(self._pedir_al_actualizador({"orden": "estado"}))
        if estado is None:
            raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante que actualiza contesta algo que no entiendo")
        return 200, estado, sin_cache


def _exigir(metodo: str, permitido: str, todos: str | None = None) -> None:
    if metodo != permitido:
        raise ErrorHTTP(405, "metodo_no_permitido", f"Aquí solo vale {todos or permitido}",
                        {"Allow": todos or permitido})
