"""Lo que comparten el vigía y el relé: secretos en ficheros privados, registro sin datos sensibles y un servidor HTTP
pequeño que habla JSON.

El servidor es el de la biblioteca estándar (``http.server``) a propósito: los dos servicios atienden unas pocas
peticiones por minuto, siempre detrás de nginx o en ``127.0.0.1``, y una dependencia menos es una actualización de
seguridad menos que vigilar en el VPS.
"""

from __future__ import annotations

import configparser
import http.server
import json
import logging
import os
import re
import socket
import stat
import sys
import threading
import time
import urllib.request

# ---------------------------------------------------------------------------------------------------------------------
# Secretos


class ErrorDeSecreto(Exception):
    """Un secreto que no se puede usar: no existe, no es un fichero o lo pueden leer otros usuarios."""


def leer_secreto(ruta: str) -> bytes:
    """Lee un secreto de un fichero que solo puede leer su dueño.

    Se niega, como ``ssh`` con una clave privada, si el fichero lo pueden leer el grupo u otros: un secreto así ya no es
    un secreto, y arrancar con él solo aplazaría el problema. Se comprueba sobre el descriptor ya abierto, no sobre la
    ruta, para que nadie pueda cambiar el fichero entre la comprobación y la lectura.
    """
    try:
        fd = os.open(ruta, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ErrorDeSecreto(f"no se puede abrir {ruta}: {error.strerror}") from None
    try:
        datos = os.fstat(fd)
        # Una carpeta también se abre para leer: se mira el tipo antes de envolver el descriptor en un fichero.
        if not stat.S_ISREG(datos.st_mode):
            raise ErrorDeSecreto(f"{ruta} no es un fichero normal")
        if datos.st_mode & 0o077:
            raise ErrorDeSecreto(
                f"{ruta} tiene permisos {stat.S_IMODE(datos.st_mode):04o}: tiene que ser 0600 o 0400, solo para su dueño")
        with os.fdopen(fd, "rb") as fichero:
            fd = None
            return fichero.read()
    finally:
        if fd is not None:
            os.close(fd)


def escribir_privado(ruta: str, contenido: bytes) -> None:
    """Escribe un fichero 0600 de forma atómica: o queda el nuevo entero, o el de antes."""
    carpeta = os.path.dirname(os.path.abspath(ruta))
    temporal = os.path.join(carpeta, f".{os.path.basename(ruta)}.{os.getpid()}.tmp")
    fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fichero:
            fichero.write(contenido)
            fichero.flush()
            os.fsync(fichero.fileno())
        os.replace(temporal, ruta)
    except BaseException:
        if os.path.exists(temporal):
            os.unlink(temporal)
        raise


# ---------------------------------------------------------------------------------------------------------------------
# Registro


def cola(token: str | None) -> str:
    """Lo único que sale de un token en el registro: sus seis últimos caracteres.

    Con eso se distingue un iPhone de otro en los logs, que es para lo que se miran, y un log filtrado no le da a nadie
    un token con el que intentar nada.
    """
    if not token:
        return "…"
    return "…" + token[-6:]


def configurar_registro(nivel: str = "INFO") -> None:
    """Todo a la salida de errores, sin hora: journald ya la pone, y así cada línea es corta."""
    logging.basicConfig(level=getattr(logging, nivel.upper(), logging.INFO), stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")


# ---------------------------------------------------------------------------------------------------------------------
# Configuración


def leer_ini(ruta: str) -> configparser.ConfigParser:
    """Un INI con los comentarios en su propia línea y sin interpolación: un ``%`` en un valor es un ``%``."""
    ini = configparser.ConfigParser(interpolation=None)
    with open(ruta, encoding="utf-8") as fichero:
        ini.read_file(fichero)
    return ini


def direccion(texto: str) -> tuple[str, int]:
    """«127.0.0.1:8790» → («127.0.0.1», 8790)."""
    anfitrion, _, puerto = texto.strip().rpartition(":")
    if not anfitrion or not puerto.isdigit():
        raise ValueError(f"dirección no válida: {texto!r} (se espera anfitrión:puerto)")
    return anfitrion.strip("[]"), int(puerto)


# ---------------------------------------------------------------------------------------------------------------------
# HTTP


class ErrorHTTP(Exception):
    """Una respuesta de error ya decidida: su estado, su código de máquina y un mensaje para quien lea el log del otro
    lado. Nunca lleva datos del usuario."""

    def __init__(self, estado: int, codigo: str, mensaje: str, cabeceras: dict | None = None):
        super().__init__(mensaje)
        self.estado = estado
        self.codigo = codigo
        self.mensaje = mensaje
        self.cabeceras = cabeceras or {}


def cuerpo_de_error(codigo: str, mensaje: str, tipo: str = "invalid_request_error") -> dict:
    """El mismo envoltorio que usa el api_server de Hermes (contrato §8), para que la app los entienda igual."""
    return {"error": {"message": mensaje, "type": tipo, "param": None, "code": codigo}}


class ServidorHTTP(http.server.ThreadingHTTPServer):
    """Un hilo por conexión, que muere con el proceso: un cliente lento no bloquea a los demás ni el apagado.

    Con ``heredado`` (el socket que abre systemd, ``socket_heredado``) no abre ningún puerto: atiende en ese, que ya está
    atado y escuchando. Sin él, abre ``direccion_`` como siempre (las pruebas, o arrancado a mano).
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, direccion_: tuple[str, int], manejador, app, heredado: socket.socket | None = None):
        self.app = app
        if heredado is None:
            super().__init__(direccion_, manejador)
            return
        # Ni bind ni listen: son de systemd. El socket que crea `TCPServer` se tira y se usa el suyo.
        super().__init__(direccion_, manejador, bind_and_activate=False)
        self.socket.close()
        self.socket = heredado
        self.server_address = heredado.getsockname()
        self.server_name, self.server_port = str(self.server_address[0]), self.server_address[1]


class ManejadorJSON(http.server.BaseHTTPRequestHandler):
    """Lo común a las dos APIs: leer JSON con tope, contestar JSON y **no escribir la línea de cada petición**.

    ``BaseHTTPRequestHandler`` apunta por defecto la línea de cada petición en la salida de errores, y en el vigía esa
    línea lleva el token entero del iPhone (``PUT /avisos/v1/dispositivos/<token>/ajustes``). Aquí se calla, y cada
    servicio apunta lo suyo con el token recortado (``cola``).
    """

    protocol_version = "HTTP/1.1"
    server_version = "HeHermesAvisos"
    sys_version = ""
    # Un cliente que abre la conexión y no manda nada no ocupa un hilo para siempre.
    timeout = 30
    tope_cuerpo = 64 * 1024

    def log_message(self, formato, *args):
        # Silencio a propósito: ver la clase.
        pass

    def log_error(self, formato, *args):
        # También lo llama `send_error` con la línea de la petición mal formada dentro: fuera.
        pass

    def send_error(self, code, message=None, explain=None):
        """Los errores que decide ``http.server`` antes de llegar a ``atender`` (una línea demasiado larga, un método
        que no existe, una sintaxis rota) salen con el mismo envoltorio JSON que los demás. Y con la frase del estado,
        no con su ``message``: el de un 400 de sintaxis repite la línea de la petición, token incluido."""
        self.close_connection = True
        try:
            frase = http.HTTPStatus(code).phrase
        except ValueError:
            frase = "Error"
        cuerpo = json.dumps(cuerpo_de_error("peticion_invalida", frase)).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(cuerpo)

    # -- Despacho

    def atender(self) -> None:  # pragma: no cover — cada servicio pone el suyo
        raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")

    def _despachar(self) -> None:
        self._cuerpo_leido = False
        try:
            self.atender()
        except ErrorHTTP as error:
            self.enviar_json(error.estado, cuerpo_de_error(error.codigo, error.mensaje), error.cabeceras)
        except Exception:  # noqa: BLE001 — la petición falla, el servicio no
            logging.getLogger(self.nombre_registro()).exception("fallo inesperado atendiendo una petición")
            self.enviar_json(500, cuerpo_de_error("error_interno", "Error interno", "server_error"))

    do_GET = _despachar
    do_POST = _despachar
    do_PUT = _despachar
    do_DELETE = _despachar

    def nombre_registro(self) -> str:
        return "http"

    @property
    def ruta(self) -> str:
        """La ruta sin la consulta: ninguna de estas APIs usa parámetros en la URL."""
        return self.path.split("?", 1)[0]

    # -- Cuerpo

    def leer_cuerpo(self) -> bytes:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            # nginx manda siempre la longitud (guarda el cuerpo antes de pasarlo). Sin ella no se sabe dónde acaba esta
            # petición y empieza la siguiente, así que se corta la conexión.
            self.close_connection = True
            raise ErrorHTTP(411, "falta_longitud", "Hace falta Content-Length")
        texto = self.headers.get("Content-Length")
        if texto is None:
            self._cuerpo_leido = True
            return b""
        try:
            largo = int(texto)
        except ValueError:
            self.close_connection = True
            raise ErrorHTTP(400, "longitud_invalida", "Content-Length no es un número") from None
        if largo < 0:
            self.close_connection = True
            raise ErrorHTTP(400, "longitud_invalida", "Content-Length negativo")
        if largo > self.tope_cuerpo:
            self.close_connection = True
            raise ErrorHTTP(413, "cuerpo_demasiado_grande", "El cuerpo es demasiado grande")
        datos = self.rfile.read(largo)
        self._cuerpo_leido = True
        if len(datos) < largo:
            self.close_connection = True
            raise ErrorHTTP(400, "cuerpo_incompleto", "El cuerpo llegó incompleto")
        return datos

    def leer_json(self) -> dict:
        datos = self.leer_cuerpo()
        try:
            objeto = json.loads(datos.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ErrorHTTP(400, "json_invalido", "El cuerpo no es JSON") from None
        if not isinstance(objeto, dict):
            raise ErrorHTTP(400, "json_invalido", "El cuerpo tiene que ser un objeto JSON")
        return objeto

    # -- Respuesta

    def enviar_json(self, estado: int, objeto: dict | None = None, cabeceras: dict | None = None) -> None:
        # Lo que no se leyó del cuerpo sigue en el socket y se leería como la petición siguiente: se cierra.
        if not self._cuerpo_leido and (self.headers.get("Content-Length") or "0").strip() != "0":
            self.close_connection = True
        cuerpo = b"" if objeto is None else json.dumps(objeto, ensure_ascii=False).encode("utf-8")
        self.send_response(estado)
        for nombre, valor in (cabeceras or {}).items():
            self.send_header(nombre, valor)
        # Un 204 no lleva cuerpo ni longitud (RFC 9110 §15.3.5).
        if estado != 204:
            if cuerpo:
                self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if cuerpo and estado != 204:
            self.wfile.write(cuerpo)


# ---------------------------------------------------------------------------------------------------------------------
# Validación compartida

# Apple no promete la longitud de un token (hoy son 32 bytes, 64 caracteres), así que se acepta un margen y se exige lo
# que sí es seguro: hexadecimal, en minúsculas, con un número par de caracteres. Siempre con `fullmatch`: con `match` y
# un «$» al final, un «\n» detrás pasaba, llegaba a la URL de Apple y httpx la rechazaba con una excepción sin capturar.
PATRON_TOKEN = re.compile(r"(?:[0-9a-f]{2}){32,100}")
ENTORNOS = ("sandbox", "production")


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    """Una redirección no se sigue: urllib la seguiría llevando la cabecera Authorization (la clave de Hermes, la
    credencial del relé) a donde dijera la respuesta. Sin seguirla, un 3xx es un error más."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def abridor() -> urllib.request.OpenerDirector:
    """El cliente HTTP de los dos servicios: sin proxies del entorno (hablan con su propia máquina, o con el relé) y sin
    seguir redirecciones."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _SinRedirecciones())


# ---------------------------------------------------------------------------------------------------------------------
# El socket de systemd

# El primer descriptor que pasa systemd (`SD_LISTEN_FDS_START`). Las pruebas lo cambian por uno suyo.
PRIMER_DESCRIPTOR = 3
# Cuánto contesta 503 un servicio que no ha podido arrancar, antes de salir para que systemd lo vuelva a intentar.
FUERA_DE_SERVICIO = 60.0


class ErrorDeSocket(Exception):
    """El socket que pasa systemd no es el que se espera."""


def socket_heredado(entorno: dict | None = None, pid: int | None = None) -> socket.socket | None:
    """El socket de escucha que abre systemd para este servicio (``hehermes-vigia.socket``, ``hehermes-rele.socket``), o
    ``None`` si no hay.

    Es lo que hace que el puerto sea siempre de systemd: con el servicio parado, reiniciándose o sin arrancar todavía,
    ningún otro proceso de la máquina puede escuchar en él y quedarse con lo que le llega (el secreto del túnel y la
    clave de cada alta, en el del vigía; la credencial del vigía, en el del relé). systemd lo pasa en el descriptor 3 y
    lo dice con ``LISTEN_PID`` (este proceso) y ``LISTEN_FDS`` (cuántos). Si ``LISTEN_PID`` no es este proceso, no es
    para él: sin socket, y el servicio abre el suyo. Las variables se quitan del entorno al leerlas, como hace
    ``sd_listen_fds``, para que no las herede nada más.
    """
    entorno = os.environ if entorno is None else entorno
    pid = os.getpid() if pid is None else pid
    if entorno.get("LISTEN_PID") != str(pid):
        return None
    cuantos = entorno.get("LISTEN_FDS", "")
    for variable in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        entorno.pop(variable, None)
    if cuantos != "1":
        raise ErrorDeSocket(f"systemd pasa {cuantos or 'ningún'} socket(s) y se espera uno")
    try:
        enchufe = socket.socket(fileno=PRIMER_DESCRIPTOR)
    except OSError as error:
        raise ErrorDeSocket(f"el descriptor {PRIMER_DESCRIPTOR} que pasa systemd no es un socket: {error}") from None
    try:
        escucha = bool(enchufe.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
    except OSError:
        # macOS no deja preguntarlo; systemd, que es quien lo pasa, es de Linux, y ahí sí.
        escucha = True
    if enchufe.type != socket.SOCK_STREAM or enchufe.family not in (socket.AF_INET, socket.AF_INET6) or not escucha:
        enchufe.close()
        raise ErrorDeSocket("el socket que pasa systemd no es uno TCP que escucha")
    # systemd lo pasa heredable (para el exec); a partir de aquí, que no lo herede nada más, y bloqueante, que es lo que
    # espera `socketserver`.
    os.set_inheritable(enchufe.fileno(), False)
    enchufe.setblocking(True)
    return enchufe


class ManejadorFueraDeServicio(ManejadorJSON):
    """A todo, 503: es lo que atiende un servicio que no ha podido arrancar pero tiene el socket de systemd."""

    def nombre_registro(self) -> str:
        return "fuera_de_servicio"

    def atender(self) -> None:
        raise ErrorHTTP(503, "fuera_de_servicio", "El servicio no ha podido arrancar: el motivo está en su registro",
                        {"Retry-After": str(int(FUERA_DE_SERVICIO))})


def fuera_de_servicio(heredado: socket.socket | None, servicio: str) -> int:
    """Para cuando un servicio no puede arrancar (la configuración o un secreto están mal). Devuelve el código de salida.

    Sin el socket de systemd, sale enseguida. Con él, no lo suelta: contesta 503 a todo durante ``FUERA_DE_SERVICIO``
    segundos y luego sale, para que systemd lo vuelva a intentar. Salir enseguida no vale: cada conexión que esperara en
    el socket haría que systemd lo arrancara otra vez al momento, y a las cinco seguidas systemd lo da por imposible,
    cierra el socket y el puerto se queda libre para cualquiera.
    """
    if heredado is None:
        return 1
    registro = logging.getLogger(servicio)
    registro.error("fuera de servicio: contesta 503 durante %.0f s y sale, para que systemd lo vuelva a intentar",
                   FUERA_DE_SERVICIO)
    servidor = ServidorHTTP(None, ManejadorFueraDeServicio, None, heredado=heredado)
    threading.Thread(target=servidor.serve_forever, name="fuera_de_servicio", daemon=True).start()
    time.sleep(FUERA_DE_SERVICIO)
    servidor.shutdown()
    servidor.server_close()
    return 1
