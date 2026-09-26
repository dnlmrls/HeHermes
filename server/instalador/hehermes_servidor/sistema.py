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


def _ejecutar_de_verdad(args, entrada=None, heredar=False):
    # Siempre en C: lo que se lee de `ufw status` o `ss` no puede cambiar con el idioma del servidor.
    entorno = dict(os.environ, LC_ALL="C", LANG="C")
    if heredar:
        # El QR: la salida va directa al terminal de quien lo lanza (`qr` exige un terminal).
        r = subprocess.run(args, input=entrada, text=True, env=entorno)
        return Resultado(r.returncode)
    try:
        r = subprocess.run(args, input=entrada, capture_output=True, text=True, env=entorno)
    except FileNotFoundError:
        return Resultado(127, "", "no existe %s" % args[0])
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


class Sistema:
    def __init__(self, raiz: str = "/", ejecutor=None, http=None, version_python=None, nucleo=None):
        self.raiz = os.path.realpath(raiz)
        self._ejecutor = ejecutor or _ejecutar_de_verdad
        self._http = http or _http_de_verdad
        self.version_python = tuple(version_python or sys.version_info[:3])
        self.nucleo = nucleo or os.uname().release

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

    def ejecutar(self, args, entrada: str | None = None, heredar: bool = False) -> Resultado:
        return self._ejecutor(list(args), entrada=entrada, heredar=heredar)

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
