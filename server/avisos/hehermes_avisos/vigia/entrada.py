"""``/avisos/v1/entrada/…``: mandarle un fichero a Hermes, del lado del vigía (``server/API-CONTRACT.md`` §16).

Lo que no es texto que quepa en el mensaje, la app lo sube aquí en trozos de 4 MiB, y Hermes recibe en el mismo mensaje
dónde ha quedado. El vigía no escribe en la casa de Hermes ni se le da nada para hacerlo: todo lo hace el ayudante
``hehermes-entrada`` (``despliegue/hehermes-entrada``), que systemd lanza por cada conexión a su socket como el dueño
de la casa de Hermes, sin ninguna capacidad, y que solo ve ``<HERMES_HOME>/entrada``. El vigía solo:

- comprueba la forma de lo que llega (ids, números, el nombre, la cabecera del SHA-256, los cuerpos con tope) antes de
  molestar al ayudante;
- deja cuatro trozos a la vez (cada uno es un proceso del ayudante y 4 MiB en memoria);
- le pasa los topes de ``vigia.ini`` (``[entrada]``), que el ayudante recorta a los suyos: el vigía no puede pedirle
  más;
- traduce: la ruta a una orden fija del ayudante, y su respuesta a HTTP, con el envoltorio de siempre;
- le pide la limpieza cada hora (``limpiar_cada_hora``): lo que se quedó a medias, a las 24 horas, y las carpetas de los
  días, a los ``dias``.

Nunca apunta un nombre, una ruta ni nada de dentro: el principio del id, los tamaños, los números de trozo y el
resultado.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import unicodedata

from ..comun import ErrorHTTP
from .fichero import PRINCIPAL, perfil_valido
from .respaldo import ClienteAyudante, _error_de, _exigir, _id, _numero, limpiar_cada_hora  # noqa: F401

registro = logging.getLogger("vigia.entrada")

PREFIJO = "/avisos/v1/entrada/"
TROZO = 4 * 1024 * 1024
#: Lo más grande que acepta el vigía en estas rutas: un trozo, sin comprimir, con el margen de la copia. Lo mismo en la
#: pasarela (``MAX_CUERPO_ENTRADA``).
TOPE_CUERPO = TROZO + 64 * 1024
MAX_A_LA_VEZ = 4
MAX_NOMBRE = 255
NO_DISPONIBLE = "entrada_no_disponible"
#: Terminar calcula el SHA-256 del fichero entero (2 GB son unos segundos): menos que los 3 minutos que espera la app.
PLAZO_TERMINAR = 170.0
PATRON_SHA = re.compile(r"[0-9a-f]{64}")
RUTA = re.compile(r"/avisos/v1/entrada/(estado|subidas)(?:/([^/]+)(?:/(trozos|terminar)(?:/([^/]+))?)?)?/?")


def ayudante(ruta_socket: str, plazo: float = 120.0) -> ClienteAyudante:
    """El cliente del socket del ayudante de la entrada: el de la copia, con su código de «no disponible»."""
    return ClienteAyudante(ruta_socket, plazo, no_disponible=NO_DISPONIBLE, de_quien="de la entrada")


def nombre_valido(nombre) -> str:
    """Lo mismo que mira el ayudante (que lo vuelve a mirar): de 1 a 255 bytes, sin «/», NUL ni caracteres de control.
    No es una ruta: el nombre del disco lo decide él."""
    malo = ErrorHTTP(400, "nombre_invalido", "El nombre tiene que tener de 1 a 255 bytes, sin «/» ni caracteres de "
                                             "control")
    if not isinstance(nombre, str) or not nombre:
        raise malo
    try:
        largo = len(nombre.encode("utf-8"))
    except UnicodeEncodeError:
        raise malo from None
    if largo > MAX_NOMBRE or "/" in nombre or any(unicodedata.category(c) == "Cc" for c in nombre):
        raise malo
    return nombre


def _entero(valor) -> bool:
    return isinstance(valor, int) and not isinstance(valor, bool)


class Entradas:
    """La lógica de las rutas, sin HTTP: ``atender`` devuelve ``(estado, objeto JSON o None, cabeceras)``. ``tope`` y
    ``margen`` en bytes y ``dias``, los de ``vigia.ini``."""

    def __init__(self, cliente: ClienteAyudante, tope: int, margen: int, dias: int, a_la_vez: int = MAX_A_LA_VEZ,
                 perfiles=lambda: []):
        self.ayudante = cliente
        self.tope, self.margen, self.dias = tope, margen, dias
        self._trozos = threading.BoundedSemaphore(a_la_vez)
        #: Los agentes servidos (contrato §18.9), cuya entrada también se limpia cada hora.
        self.perfiles = perfiles

    def _pedir(self, peticion: dict, cuerpo: bytes | None = None, plazo: float | None = None) -> dict:
        respuesta, _ = self.ayudante.pedir(peticion, cuerpo, plazo)
        if not respuesta.get("ok"):
            error = _error_de(respuesta, NO_DISPONIBLE)
            registro.info("entrada: %s: %d %s", _de_que(peticion), error.estado, error.codigo)
            raise error
        return respuesta

    @staticmethod
    def _limpia(respuesta: dict) -> dict:
        return {k: v for k, v in respuesta.items() if k not in ("ok", "http", "bytes")}

    def atender(self, metodo: str, ruta: str, leer_cuerpo, cabeceras, perfil: str = PRINCIPAL) -> tuple:
        """`perfil`, el de `?perfil=` (contrato §18.9): la entrada de la casa de ese agente. Al ayudante le llega su
        nombre, y él saca su casa; sin él (el principal), las órdenes de siempre."""
        encontrada = RUTA.fullmatch(ruta)
        if not encontrada:
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        perfil = perfil_valido(perfil)

        def pedir(peticion: dict, cuerpo: bytes | None = None, plazo: float | None = None) -> dict:
            return self._pedir(peticion if perfil == PRINCIPAL else dict(peticion, perfil=perfil), cuerpo, plazo)

        que, id_, sub, n = encontrada.groups()
        if que == "estado":
            if id_ is not None:
                raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
            _exigir(metodo, "GET")
            respuesta = pedir({"orden": "estado", "tope": self.tope, "margen": self.margen})
            return 200, dict(self._limpia(respuesta), dias=self.dias), {}
        if id_ is None:
            _exigir(metodo, "POST")
            return self._crear(_objeto(leer_cuerpo()), pedir)
        _id(id_)
        if sub is None:
            if metodo == "DELETE":
                pedir({"orden": "borrar", "id": id_})
                registro.info("entrada: subida %s borrada", id_[:8])
                return 204, None, {}
            _exigir(metodo, "GET")
            return 200, self._limpia(pedir({"orden": "subida", "id": id_})), {}
        if sub == "terminar" and n is None:
            _exigir(metodo, "POST")
            _objeto(leer_cuerpo())
            respuesta = pedir({"orden": "terminar", "id": id_}, plazo=PLAZO_TERMINAR)
            registro.info("entrada: subida %s terminada: %s bytes", id_[:8], respuesta.get("tamano"))
            return 200, {"ruta": respuesta.get("ruta"), "nombre": respuesta.get("nombre"),
                         "tamano": respuesta.get("tamano")}, {}
        if sub == "trozos" and n is not None:
            _exigir(metodo, "PUT")
            numero = _numero(n)
            sha = (cabeceras.get("X-HeHermes-SHA256") or "").strip().lower()
            if not PATRON_SHA.fullmatch(sha):
                raise ErrorHTTP(400, "trozo_invalido", "Falta X-HeHermes-SHA256, o no tiene su forma")
            datos = leer_cuerpo()
            if not datos or len(datos) > TROZO:
                raise ErrorHTTP(400, "trozo_invalido", "Un trozo tiene de 1 byte a 4 MiB")
            self._con_turno(lambda: pedir({"orden": "trozo", "id": id_, "n": numero, "sha256": sha,
                                                 "margen": self.margen}, datos))
            registro.debug("entrada: subida %s, trozo %d (%d bytes)", id_[:8], numero, len(datos))
            return 204, None, {}
        raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")

    def _crear(self, cuerpo: dict, pedir=None) -> tuple:
        pedir = pedir or self._pedir
        nombre, tamano, sha = cuerpo.get("nombre"), cuerpo.get("tamano"), cuerpo.get("sha256")
        nombre_valido(nombre)
        if not _entero(tamano) or tamano < 1:
            raise ErrorHTTP(400, "parametro_invalido", "«tamano» son los bytes del fichero, al menos uno")
        if not isinstance(sha, str) or not PATRON_SHA.fullmatch(sha):
            raise ErrorHTTP(400, "parametro_invalido", "«sha256» son 64 hexadecimales en minúsculas")
        respuesta = pedir({"orden": "crear", "nombre": nombre, "tamano": tamano, "sha256": sha,
                                 "tope": self.tope, "margen": self.margen})
        nueva = respuesta.get("http") == 201
        id_ = str(respuesta.get("id"))[:8]
        if nueva:
            registro.info("entrada: subida %s nueva: %d bytes en %s trozos", id_, tamano, respuesta.get("trozos"))
        elif respuesta.get("estado") == "lista":
            registro.info("entrada: subida %s ya estaba lista", id_)
        else:
            registro.info("entrada: subida %s retomada: %d de %s trozos", id_, len(respuesta.get("recibidos") or []),
                          respuesta.get("trozos"))
        return (201 if nueva else 200), self._limpia(respuesta), {}

    def _con_turno(self, funcion):
        if not self._trozos.acquire(blocking=False):
            raise ErrorHTTP(429, "demasiados_trozos", "Demasiados trozos a la vez", {"Retry-After": "2"})
        try:
            return funcion()
        finally:
            self._trozos.release()

    def limpiar(self) -> None:
        """Lo que se lanza cada hora: la del principal y la de cada agente. Si el ayudante no está (o la entrada de un
        agente aún no existe), no pasa nada: no hay nada que limpiar."""
        try:
            agentes = [p for p in self.perfiles() if p != PRINCIPAL]
        except Exception:  # noqa: BLE001 — sin la lista de los agentes, al menos la del principal
            agentes = []
        for perfil in [PRINCIPAL] + agentes:
            peticion = {"orden": "limpiar", "dias": self.dias}
            try:
                respuesta = self._pedir(peticion if perfil == PRINCIPAL else dict(peticion, perfil=perfil))
            except ErrorHTTP:
                continue
            borradas = {k: v for k, v in self._limpia(respuesta).items() if isinstance(v, int) and v}
            if borradas:
                registro.info("entrada: limpieza%s: %s", "" if perfil == PRINCIPAL else " de un agente",
                              ", ".join("%s %s" % (v, k) for k, v in sorted(borradas.items())))


def _objeto(datos: bytes) -> dict:
    """El cuerpo JSON de una orden (vacío vale por ``{}``). Otra cosa es ``parametro_invalido`` (contrato §16)."""
    if not datos:
        return {}
    try:
        objeto = json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ErrorHTTP(400, "parametro_invalido", "El cuerpo no es JSON") from None
    if not isinstance(objeto, dict):
        raise ErrorHTTP(400, "parametro_invalido", "El cuerpo tiene que ser un objeto JSON")
    return objeto


def _de_que(peticion: dict) -> str:
    """La orden, el principio del id y el número de trozo: lo único que sale al registro de una petición."""
    texto = str(peticion.get("orden"))
    id_ = peticion.get("id")
    if isinstance(id_, str):
        texto += " " + id_[:8]
    if _entero(peticion.get("n")):
        texto += " trozo %d" % peticion["n"]
    return texto
