"""``/avisos/v1/respaldo/…``: la copia de Hermes en iCloud, del lado del vigía (``server/API-CONTRACT.md`` §15).

El vigía no lee la casa de Hermes ni puede pararlo, y no se le da nada de root: todo lo hace el ayudante
``hehermes-respaldo`` (``despliegue/hehermes-respaldo``), que systemd lanza por cada conexión a su socket con el dueño
de Hermes. El vigía solo:

- comprueba la forma de lo que llega (ids, números, cuerpos con tope) antes de molestar al ayudante;
- limita las descargas y las subidas de trozos a cuatro a la vez (cada una es un proceso del ayudante y 4 MiB);
- traduce: la ruta a una orden fija del ayudante, y su respuesta a HTTP, con el envoltorio de siempre;
- le pide una limpieza cada hora (las instantáneas caducan a las 24 horas; la copia de antes de restaurar, a los 7 días).

Nunca apunta una ruta ni un contenido: el ayudante no los manda, y aquí solo salen la orden, el estado y los bytes.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import threading

from ..comun import ErrorHTTP

registro = logging.getLogger("vigia.respaldo")

PREFIJO = "/avisos/v1/respaldo/"
TROZO = 4 * 1024 * 1024
#: Lo más grande que acepta el vigía en estas rutas: un trozo comprimido (que puede pasar un poco de 4 MiB si no
#: comprime) o un manifiesto. Lo mismo en la pasarela (``MAX_CUERPO_RESPALDO``).
TOPE_CUERPO = TROZO + 64 * 1024
MAX_A_LA_VEZ = 4
MAX_RESPUESTA = 8 * 1024 * 1024
PATRON_ID = re.compile(r"[0-9a-f]{32}")
PATRON_SHA = re.compile(r"[0-9a-f]{64}")
RUTA = re.compile(r"/avisos/v1/respaldo/(estado|deshacer|instantaneas|restauraciones)"
                  r"(?:/([^/]+)(?:/(trozos|aplicar)(?:/([^/]+))?)?)?/?")


class ClienteAyudante:
    """Habla con el socket de un ayudante de systemd (``/run/hehermes-respaldo.sock``; y desde la 1.5.2 también el de la
    entrada, ``vigia/entrada.py``): una línea JSON (y los bytes que diga), y otra de vuelta. ``no_disponible`` es el
    código con el que se contesta si el ayudante no está o no contesta, y ``de_quien``, cómo se le nombra."""

    def __init__(self, ruta_socket: str, plazo: float = 120.0, no_disponible: str = "respaldo_no_disponible",
                 de_quien: str = "de la copia"):
        self.ruta_socket = ruta_socket
        self.plazo = plazo
        self.no_disponible = no_disponible
        self.de_quien = de_quien

    def pedir(self, peticion: dict, cuerpo: bytes | None = None, plazo: float | None = None) -> tuple:
        """``(respuesta, bytes o None)``. ``ErrorHTTP`` si el ayudante no está o no contesta. ``plazo``, para una orden
        que tarda más que las demás (terminar una subida grande)."""
        if cuerpo is not None:
            peticion = dict(peticion, bytes=len(cuerpo))
        linea = json.dumps(peticion, separators=(",", ":")).encode("utf-8") + b"\n"
        no_disponible, de_quien = self.no_disponible, self.de_quien
        conexion = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conexion.settimeout(self.plazo if plazo is None else plazo)
        try:
            try:
                conexion.connect(self.ruta_socket)
            except OSError:
                raise ErrorHTTP(503, no_disponible, "El ayudante %s no está instalado o no contesta" % de_quien,
                                {"Retry-After": "30"}) from None
            conexion.sendall(linea + (cuerpo or b""))
            recibido = bytearray()
            while b"\n" not in recibido:
                trozo = conexion.recv(256 * 1024)
                if not trozo:
                    break
                recibido += trozo
                if len(recibido) > MAX_RESPUESTA:
                    break
            cabecera, salto, resto = bytes(recibido).partition(b"\n")
            if not salto:
                raise ErrorHTTP(503, no_disponible, "El ayudante %s no ha contestado" % de_quien)
            try:
                respuesta = json.loads(cabecera.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise ErrorHTTP(502, no_disponible, "El ayudante contesta algo que no entiendo") from None
            if not isinstance(respuesta, dict):
                raise ErrorHTTP(502, no_disponible, "El ayudante contesta algo que no entiendo")
            datos = None
            largo = respuesta.get("bytes")
            if respuesta.get("ok") and isinstance(largo, int) and not isinstance(largo, bool) and 0 <= largo <= \
                    TOPE_CUERPO:
                partes, quedan = [resto], largo - len(resto)
                while quedan > 0:
                    trozo = conexion.recv(min(quedan, 1024 * 1024))
                    if not trozo:
                        raise ErrorHTTP(502, no_disponible, "El trozo llegó cortado del ayudante")
                    partes.append(trozo)
                    quedan -= len(trozo)
                datos = b"".join(partes)
                if len(datos) != largo:
                    raise ErrorHTTP(502, no_disponible, "El trozo llegó cortado del ayudante")
            return respuesta, datos
        except OSError:
            raise ErrorHTTP(503, no_disponible, "El ayudante %s no ha contestado" % de_quien) from None
        finally:
            conexion.close()


def _error_de(respuesta: dict, no_disponible: str = "respaldo_no_disponible") -> ErrorHTTP:
    """El rechazo del ayudante, como la respuesta HTTP que dice el contrato. Lo que no tenga forma, 502."""
    estado, codigo, mensaje = respuesta.get("http"), respuesta.get("codigo"), respuesta.get("mensaje")
    if not (isinstance(estado, int) and 400 <= estado <= 599 and isinstance(codigo, str)
            and re.fullmatch(r"[a-z_]{1,64}", codigo)):
        return ErrorHTTP(502, no_disponible, "El ayudante contesta algo que no entiendo")
    cabeceras = {}
    for nombre, valor in (respuesta.get("cabeceras") or {}).items():
        if nombre == "Retry-After" and str(valor).isdigit():
            cabeceras[nombre] = str(valor)
    error = ErrorHTTP(estado, codigo, mensaje if isinstance(mensaje, str) else codigo, cabeceras)
    extra = respuesta.get("extra")
    if isinstance(extra, dict):
        error.extra = {k: v for k, v in extra.items() if isinstance(k, str) and re.fullmatch(r"[a-z_]{1,32}", k)}
    return error


class Respaldos:
    """La lógica de las rutas, sin HTTP: ``atender`` devuelve ``(estado, objeto JSON o None, bytes o None,
    cabeceras)``."""

    def __init__(self, ayudante: ClienteAyudante, a_la_vez: int = MAX_A_LA_VEZ):
        self.ayudante = ayudante
        self._trozos = threading.BoundedSemaphore(a_la_vez)

    def _pedir(self, peticion: dict, cuerpo: bytes | None = None) -> tuple:
        respuesta, datos = self.ayudante.pedir(peticion, cuerpo)
        if not respuesta.get("ok"):
            raise _error_de(respuesta)
        return respuesta, datos

    @staticmethod
    def _limpia(respuesta: dict) -> dict:
        return {k: v for k, v in respuesta.items() if k not in ("ok", "http", "bytes")}

    def _con_turno(self, codigo: str, funcion):
        if not self._trozos.acquire(blocking=False):
            raise ErrorHTTP(429, codigo, "Demasiados trozos a la vez", {"Retry-After": "2"})
        try:
            return funcion()
        finally:
            self._trozos.release()

    def atender(self, metodo: str, ruta: str, leer_cuerpo, cabeceras) -> tuple:
        encontrada = RUTA.fullmatch(ruta)
        if not encontrada:
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        que, id_, sub, n = encontrada.groups()
        if que == "estado" and id_ is None:
            _exigir(metodo, "GET")
            respuesta, _ = self._pedir({"orden": "estado"})
            return 200, self._limpia(respuesta), None, {}
        if que == "deshacer" and id_ is None:
            _exigir(metodo, "POST")
            leer_cuerpo()
            self._pedir({"orden": "deshacer"})
            registro.info("respaldo: deshacer la última restauración")
            return 202, {}, None, {}
        if que == "instantaneas":
            if id_ is None:
                _exigir(metodo, "POST")
                cuerpo = _json(leer_cuerpo())
                respuesta, _ = self._pedir({"orden": "instantanea", "partes": cuerpo.get("partes"),
                                            "claves": cuerpo.get("claves")})
                registro.info("respaldo: instantánea %s pedida", respuesta.get("id"))
                return 202, {"id": respuesta.get("id")}, None, {}
            _id(id_)
            if sub is None:
                if metodo == "DELETE":
                    self._pedir({"orden": "instantanea-borrar", "id": id_})
                    return 204, None, None, {}
                _exigir(metodo, "GET")
                respuesta, _ = self._pedir({"orden": "instantanea-estado", "id": id_})
                return 200, self._limpia(respuesta), None, {}
            if sub == "trozos" and n is not None:
                _exigir(metodo, "GET")
                numero = _numero(n)

                def bajar():
                    return self._pedir({"orden": "trozo", "id": id_, "n": numero})

                respuesta, datos = self._con_turno("demasiadas_descargas", bajar)
                if datos is None or not PATRON_SHA.fullmatch(str(respuesta.get("sha256"))):
                    raise ErrorHTTP(502, "respaldo_no_disponible", "El ayudante no ha dado el trozo")
                return 200, None, datos, {"X-HeHermes-SHA256": respuesta["sha256"],
                                          "X-HeHermes-Tamano": str(int(respuesta.get("tamano") or 0))}
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        # restauraciones
        if id_ is None:
            _exigir(metodo, "POST")
            cuerpo = _json(leer_cuerpo())
            respuesta, _ = self._pedir({"orden": "restauracion", "manifiesto": cuerpo.get("manifiesto"),
                                        "partes": cuerpo.get("partes")})
            registro.info("respaldo: restauración %s preparada", respuesta.get("id"))
            return 201, self._limpia(respuesta), None, {}
        _id(id_)
        if sub is None:
            if metodo == "DELETE":
                self._pedir({"orden": "restauracion-borrar", "id": id_})
                return 204, None, None, {}
            _exigir(metodo, "GET")
            respuesta, _ = self._pedir({"orden": "restauracion-estado", "id": id_})
            return 200, self._limpia(respuesta), None, {}
        if sub == "aplicar" and n is None:
            _exigir(metodo, "POST")
            cuerpo = _json(leer_cuerpo())
            confirmacion = cuerpo.get("confirmacion")
            if confirmacion is not None and not (isinstance(confirmacion, str) and len(confirmacion) <= 255):
                raise ErrorHTTP(400, "parametro_invalido", "«confirmacion» es el nombre del servidor")
            self._pedir({"orden": "aplicar", "id": id_, "confirmacion": confirmacion})
            registro.info("respaldo: restauración %s: se aplica", id_)
            return 202, {}, None, {}
        if sub == "trozos" and n is not None:
            _exigir(metodo, "PUT")
            numero = _numero(n)
            sha = cabeceras.get("X-HeHermes-SHA256")
            if sha is not None and not PATRON_SHA.fullmatch(sha.strip().lower()):
                raise ErrorHTTP(400, "trozo_invalido", "X-HeHermes-SHA256 no tiene su forma")
            datos = leer_cuerpo()
            if not datos:
                raise ErrorHTTP(400, "trozo_invalido", "Falta el trozo")

            def subir():
                return self._pedir({"orden": "restauracion-trozo", "id": id_, "n": numero,
                                    "sha256": sha.strip().lower() if sha else None}, datos)

            self._con_turno("demasiadas_subidas", subir)
            return 204, None, None, {}
        raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")

    def limpiar(self) -> None:
        """Lo que se lanza cada hora. Si el ayudante no está, no pasa nada: no hay nada que limpiar."""
        try:
            respuesta, _ = self._pedir({"orden": "limpiar"})
        except ErrorHTTP:
            return
        borradas = {k: v for k, v in respuesta.items() if k != "ok" and v}
        if borradas:
            registro.info("respaldo: limpieza: %s", ", ".join("%s %s" % (v, k) for k, v in sorted(borradas.items())))


def _exigir(metodo: str, permitido: str) -> None:
    if metodo != permitido:
        raise ErrorHTTP(405, "metodo_no_permitido", f"Aquí solo vale {permitido}", {"Allow": permitido})


def _id(valor: str) -> str:
    if not PATRON_ID.fullmatch(valor):
        raise ErrorHTTP(400, "parametro_invalido", "El id tiene que ser de 32 hexadecimales")
    return valor


def _numero(texto: str) -> int:
    if not texto.isdigit() or not texto.isascii() or len(texto) > 7 or (len(texto) > 1 and texto[0] == "0"):
        raise ErrorHTTP(400, "parametro_invalido", "El número de trozo es un decimal")
    return int(texto)


def _json(datos: bytes) -> dict:
    if not datos:
        return {}
    try:
        objeto = json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ErrorHTTP(400, "json_invalido", "El cuerpo no es JSON") from None
    if not isinstance(objeto, dict):
        raise ErrorHTTP(400, "json_invalido", "El cuerpo tiene que ser un objeto JSON")
    return objeto


def limpiar_cada_hora(respaldos, parar: threading.Event, cada: float = 3600.0, primera: float = 60.0) -> None:
    """El hilo de la limpieza: una al arrancar (tras un minuto) y luego cada hora, hasta que el vigía se pare. Vale
    para cualquiera con su ``limpiar()``: la copia (``Respaldos``) y, desde la 1.5.2, la entrada (``Entradas``)."""
    if parar.wait(primera):
        return
    while True:
        respaldos.limpiar()
        if parar.wait(cada):
            return
