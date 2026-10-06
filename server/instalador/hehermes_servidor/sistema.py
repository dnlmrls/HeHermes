"""Todo lo que el instalador lee, escribe o ejecuta pasa por aquí.

Con la raíz en `/` y las órdenes de verdad es el servidor; en las pruebas, la raíz es una carpeta temporal y las órdenes
son falsas. Así la decisión se prueba entera sin root y sin tocar nada.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


class Resultado:
    __slots__ = ("codigo", "salida", "error")

    def __init__(self, codigo: int, salida: str = "", error: str = ""):
        self.codigo, self.salida, self.error = codigo, salida, error

    @property
    def bien(self) -> bool:
        return self.codigo == 0

    def __repr__(self):
        return "Resultado(%d, %r, %r)" % (self.codigo, self.salida[:60], self.error[:60])


def sha256(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


#: Lo más que espera una orden si quien la lanza no dice otra cosa (desde la 0.11.1): ninguna se queda colgada para
#: siempre (un `systemctl` con D-Bus atascado, un `docker` con su demonio colgado, un `ufw` que no vuelve). Por encima de
#: lo que tarda la más larga que va sin plazo propio: la compactación de noche, con su `timeout` de 15 minutos.
PLAZO_DE_SERIE = 1200


def _texto(datos) -> str:
    if datos is None:
        return ""
    return datos.decode("utf-8", "replace") if isinstance(datos, bytes) else datos


def _ejecutar_de_verdad(args, entrada=None, heredar=False, plazo=None):
    # Siempre en C: lo que se lee de `ufw status` o `ss` no puede cambiar con el idioma del servidor.
    entorno = dict(os.environ, LC_ALL="C", LANG="C")
    if heredar:
        # El QR: la salida va directa al terminal de quien lo lanza (`qr` exige un terminal). Y el `instalar` de la
        # versión nueva que lanza `actualizar`, que tarda lo que tarde: sin plazo.
        r = subprocess.run(args, input=entrada, text=True, env=entorno)
        return Resultado(r.returncode)
    plazo = PLAZO_DE_SERIE if plazo is None else plazo
    try:
        r = subprocess.run(args, input=entrada, capture_output=True, text=True, env=entorno, timeout=plazo)
    except FileNotFoundError:
        return Resultado(127, "", "no existe %s" % args[0])
    except subprocess.TimeoutExpired as error:
        # Como `timeout`: 124. subprocess ya la ha matado.
        return Resultado(124, _texto(error.stdout), "%s no ha acabado en %g s y la he cortado%s" % (
            os.path.basename(args[0]), plazo, (": " + _texto(error.stderr).strip()[-300:]) if error.stderr else ""))
    return Resultado(r.returncode, r.stdout, r.stderr)


def _http_de_verdad(url, cabeceras, plazo=5):
    """Un GET sin proxies (es 127.0.0.1) y sin seguir redirecciones, que se llevarían la clave a otro sitio."""

    class SinRedirecciones(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}), SinRedirecciones)
    peticion = urllib.request.Request(url, headers=cabeceras)
    try:
        with abridor.open(peticion, timeout=plazo) as respuesta:
            return respuesta.status, respuesta.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536)
    except (OSError, ValueError):
        return None, b""


def _pedir_de_verdad(metodo, url, cabeceras, plazo=5):
    """Una petición sin cuerpo con cualquier método (la sonda de las capacidades de Hermes: `TRACE`), sin proxies y sin
    seguir redirecciones. (estado, cabeceras, cuerpo); (None, {}, b"") si no contesta."""

    class SinRedirecciones(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}), SinRedirecciones)
    peticion = urllib.request.Request(url, headers=cabeceras, method=metodo)
    try:
        with abridor.open(peticion, timeout=plazo) as respuesta:
            return respuesta.status, dict(respuesta.headers.items()), respuesta.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()) if error.headers else {}, error.read(65536)
    except (OSError, ValueError):
        return None, {}, b""


#: Lo que se espera al servicio de metadatos de una nube (`nube`): está en la propia máquina y contesta en milisegundos;
#: en un servidor sin él (uno en casa) nadie contesta, y no se puede hacer esperar a quien instala.
PLAZO_METADATOS = 2


def _metadatos_de_verdad(metodo, url, cabeceras, plazo=PLAZO_METADATOS):
    """Una petición al servicio de metadatos (169.254.169.254): sin proxies (Azure y Google las rechazan, y un proxy se
    llevaría la petición a otro sitio), sin redirecciones y con el plazo corto."""
    return _pedir_de_verdad(metodo, url, cabeceras, plazo=plazo)


def _sondear_de_verdad(puerto, maxima=None, plazo=5, anfitrion="127.0.0.1"):
    """Lo que ve un cliente sin token en <anfitrion>:<puerto> (127.0.0.1, o la dirección pública del QR): la versión de
    TLS, la huella del certificado y los bytes de la respuesta a un GET. None si no hay apretón (o no con esa versión
    como máximo)."""
    import socket
    import ssl
    from .pasarela import huella_de_der
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    if maxima:
        contexto.maximum_version = maxima
    try:
        with socket.create_connection((anfitrion, int(puerto)), timeout=plazo) as crudo:
            with contexto.wrap_socket(crudo) as tls:
                datos = {"tls": tls.version(), "huella": huella_de_der(tls.getpeercert(binary_form=True))}
                tls.sendall(b"GET / HTTP/1.1\r\nHost: comprobar\r\n\r\n")
                partes = []
                while sum(map(len, partes)) < 65536:
                    trozo = tls.recv(4096)
                    if not trozo:
                        break
                    partes.append(trozo)
                datos["respuesta"] = b"".join(partes)
                return datos
    except (OSError, ssl.SSLError, ValueError):
        return None


class Sistema:
    def __init__(self, raiz: str = "/", ejecutor=None, http=None, version_python=None, nucleo=None, sonda=None,
                 pedir=None, metadatos=None, sistema_operativo=None):
        self.raiz = os.path.realpath(raiz)
        self._ejecutor = ejecutor or _ejecutar_de_verdad
        self._http = http or _http_de_verdad
        self._pedir = pedir or _pedir_de_verdad
        self._metadatos = metadatos or _metadatos_de_verdad
        self._sonda = sonda or _sondear_de_verdad
        self.version_python = tuple(version_python or sys.version_info[:3])
        self.nucleo = nucleo or os.uname().release
        #: «Linux», «Darwin»…: en un Mac (la app de escritorio de Hermes) no hay servidor que instalar.
        self.sistema_operativo = sistema_operativo or os.uname().sysname
        #: Este proceso y su entorno: por chat, lo lanza Hermes, y con varios perfiles en marcha es lo que dice cuál
        #: (`deteccion._el_que_me_lanza`).
        self.pid = os.getpid()
        self.entorno = dict(os.environ)

    # Rutas

    def ruta(self, ruta: str) -> str:
        """La ruta de verdad de una ruta absoluta del servidor. Nada puede salirse de la raíz."""
        if not ruta.startswith("/"):
            raise ValueError("ruta no absoluta: %s" % ruta)
        if ".." in ruta.split("/"):
            raise ValueError("ruta con «..»: %s" % ruta)
        normal = os.path.normpath(ruta)
        if self.raiz == "/":
            return normal
        return os.path.join(self.raiz, normal.lstrip("/"))

    # Lectura

    def existe(self, ruta: str) -> bool:
        return os.path.lexists(self.ruta(ruta))

    def es_carpeta(self, ruta: str) -> bool:
        real = self.ruta(ruta)
        return os.path.isdir(real) and not os.path.islink(real)

    def leer(self, ruta: str) -> bytes | None:
        """El contenido de un fichero normal, o `None`: ni enlaces (se leen con `enlace`) ni carpetas."""
        try:
            fd = os.open(self.ruta(ruta), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return None
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
        with os.fdopen(fd, "rb") as f:
            return f.read()

    def leer_texto(self, ruta: str) -> str | None:
        datos = self.leer(ruta)
        return None if datos is None else datos.decode("utf-8", "replace")

    def enlace(self, ruta: str) -> str | None:
        real = self.ruta(ruta)
        return os.readlink(real) if os.path.islink(real) else None

    def listar(self, carpeta: str) -> list:
        try:
            return sorted(os.listdir(self.ruta(carpeta)))
        except OSError:
            return []

    def modo(self, ruta: str) -> int | None:
        try:
            return os.lstat(self.ruta(ruta)).st_mode & 0o7777
        except OSError:
            return None

    # Escritura

    def libre(self, ruta: str) -> int | None:
        """Los bytes libres (para quien no es root) del sistema de ficheros donde iría `ruta`: el de su carpeta más
        cercana que exista. None si no se sabe."""
        real = self.ruta(ruta)
        while real and not os.path.exists(real):
            real = os.path.dirname(real)
        try:
            datos = os.statvfs(real or "/")
        except OSError:
            return None
        return datos.f_bavail * datos.f_frsize

    def carpeta(self, ruta: str, modo: int = 0o755) -> None:
        real = self.ruta(ruta)
        os.makedirs(real, exist_ok=True)
        os.chmod(real, modo)

    def escribir(self, ruta: str, datos: bytes, modo: int = 0o644, mismo_dueno: bool = False) -> None:
        """Atómico: se escribe al lado con el modo final y se renombra. Si ahí había un enlace, se sustituye el enlace,
        nunca se escribe en su destino. `mismo_dueno`: el fichero nuevo, del dueño del que había (el .env de Hermes es
        de su usuario, y uno de root no lo podría leer)."""
        real = self.ruta(ruta)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        antes = os.lstat(real) if mismo_dueno and os.path.isfile(real) else None
        fd, temporal = tempfile.mkstemp(dir=os.path.dirname(real), prefix=".hehermes-")
        try:
            if antes is not None:
                os.fchown(fd, antes.st_uid, antes.st_gid)
            os.fchmod(fd, modo)
            with os.fdopen(fd, "wb") as f:
                f.write(datos)
            os.replace(temporal, real)
        except BaseException:
            if os.path.exists(temporal):
                os.unlink(temporal)
            raise

    def crear_nuevo(self, ruta: str, datos: bytes, uid: int | None = None, gid: int | None = None) -> None:
        """Un fichero que no existía (`O_EXCL`, sin seguir enlaces), creado con los permisos de `uid`/`gid` si se dan
        y esto corre como root: lo que pide quien lanzó `sudo` no puede pisar ni crear nada que él no pudiera."""
        real = self.ruta(ruta)
        banderas = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if uid is not None and gid is not None and os.geteuid() == 0:
            grupos = os.getgroups()
            os.setgroups([gid])
            os.setegid(gid)
            os.seteuid(uid)
            try:
                fd = os.open(real, banderas, 0o644)
            finally:
                os.seteuid(0)
                os.setegid(0)
                os.setgroups(grupos)
        else:
            fd = os.open(real, banderas, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(datos)

    def enlazar(self, ruta: str, destino: str) -> None:
        real = self.ruta(ruta)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        temporal = os.path.join(os.path.dirname(real), ".hehermes-enlace-%d" % os.getpid())
        if os.path.lexists(temporal):
            os.unlink(temporal)
        os.symlink(destino, temporal)
        os.replace(temporal, real)

    def borrar(self, ruta: str) -> None:
        real = self.ruta(ruta)
        if os.path.islink(real) or os.path.isfile(real):
            os.unlink(real)
        elif os.path.isdir(real):
            try:
                os.rmdir(real)  # solo vacías: lo de dentro se borra por su nombre, nunca a ciegas
            except OSError:
                pass

    def borrar_arbol(self, ruta: str) -> None:
        """Una carpeta entera, solo si es de HeHermes por su nombre: nunca se borra a ciegas nada ajeno."""
        import shutil
        if not os.path.basename(ruta.rstrip("/")).startswith("hehermes"):
            raise ValueError("no borro %s: no es de HeHermes" % ruta)
        real = self.ruta(ruta)
        if os.path.islink(real):
            os.unlink(real)
        elif os.path.isdir(real):
            shutil.rmtree(real)

    # Órdenes

    def ejecutar(self, args, entrada: str | None = None, heredar: bool = False, plazo: float | None = None) -> Resultado:
        """`plazo`: lo más que espera, en segundos (sin él, `PLAZO_DE_SERIE`); si se pasa, 124."""
        if plazo is None:
            return self._ejecutor(list(args), entrada=entrada, heredar=heredar)
        return self._ejecutor(list(args), entrada=entrada, heredar=heredar, plazo=plazo)

    def ejecutar_con_reintentos(self, args, intentos: int = 3, pausa: float = 2.0, plazo: float | None = None,
                                salida=None, que: str = "") -> Resultado:
        """Para lo que va por la red y se puede repetir tal cual (pip, con sus hashes): si falla, otra vez, con una
        espera que se dobla (2 s, 4 s…), como el `retry` del instalador de Homebrew. Una señal no se reintenta: corta."""
        for intento in range(intentos):
            r = self.ejecutar(args, plazo=plazo)
            if r.bien or intento + 1 == intentos:
                return r
            espera = pausa * 2 ** intento
            if salida is not None:
                salida("    %s ha fallado (%s): lo vuelvo a intentar en %g s"
                       % (que or os.path.basename(args[0]), (r.error or r.salida).strip()[-160:] or r.codigo, espera))
            time.sleep(espera)
        return r

    def cual(self, nombre: str) -> str | None:
        """Dónde está un programa, buscando dentro de la raíz (así las pruebas deciden qué hay instalado)."""
        for carpeta in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"):
            ruta = carpeta + "/" + nombre
            real = self.ruta(ruta)
            if os.path.exists(real) and os.access(real, os.X_OK):
                return ruta
        return None

    def http_get(self, url: str, cabeceras: dict | None = None):
        return self._http(url, cabeceras or {})

    def pedir(self, metodo: str, url: str, cabeceras: dict | None = None):
        """(estado, cabeceras, cuerpo) de una petición sin cuerpo: la usa la sonda de las capacidades de Hermes."""
        return self._pedir(metodo, url, cabeceras or {})

    def metadatos(self, metodo: str, url: str, cabeceras: dict | None = None):
        """(estado, cabeceras, cuerpo) del servicio de metadatos de la nube (`nube`), con un plazo corto; (None, {}, b"")
        si no contesta nadie."""
        return self._metadatos(metodo, url, cabeceras or {})

    def cuenta(self, uid):
        """(nombre, casa) del usuario con ese uid, como `getent passwd` (también los de LDAP o sssd), o None si no tiene
        nombre: el 10000 de Hermes en Docker no existe en el servidor. En una raíz que no es «/» (las pruebas), el
        /etc/passwd de la raíz."""
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            return None
        if self.raiz == "/":
            import pwd
            try:
                datos = pwd.getpwuid(uid)
            except (KeyError, OverflowError, ValueError):
                return None
            return datos.pw_name, datos.pw_dir
        for linea in (self.leer_texto("/etc/passwd") or "").splitlines():
            campos = linea.split(":")
            if len(campos) >= 6 and campos[2] == str(uid):
                return campos[0], campos[5]
        return None

    def sondear_pasarela(self, puerto, maxima=None, anfitrion=None):
        if anfitrion is None:
            return self._sonda(puerto, maxima)
        return self._sonda(puerto, maxima, anfitrion=anfitrion, plazo=3)

    def resolver(self, nombre: str) -> list:
        """Las IP de un nombre (o la IP misma), sin repetir. Vacía si no se resuelve."""
        import socket
        try:
            return list(dict.fromkeys(i[4][0] for i in socket.getaddrinfo(nombre, None, type=socket.SOCK_STREAM)))
        except (OSError, UnicodeError):
            return []
