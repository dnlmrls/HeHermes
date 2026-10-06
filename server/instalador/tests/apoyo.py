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
        #: (orden, plazo) de las que llevan un plazo propio (`Sistema.ejecutar(…, plazo=…)`).
        self.plazos: list = []
        self.peticiones_http: list = []
        #: Las de la sonda de las capacidades de Hermes (`Sistema.pedir`): (método, URL, cabeceras).
        self.peticiones_sonda: list = []
        #: Las del servicio de metadatos de la nube (`Sistema.metadatos`): (método, URL, cabeceras). Sin
        #: `metadatos_falso` no contesta nadie, como en un servidor que no está en ninguna nube.
        self.peticiones_metadatos: list = []
        self.metadatos_falso = None
        # Lo que contesta a lo que no está en `responder` (el `ServidorFalso`), y a las URL sin respuesta fija.
        self.resto = None
        self.http_falso = None
        self.pedir_falso = None
        opciones.setdefault("version_python", (3, 11, 2))
        opciones.setdefault("nucleo", "6.1.0-25-amd64")
        opciones.setdefault("sistema_operativo", "Linux")
        super().__init__(raiz=self._carpeta, ejecutor=self._ejecutar, http=self._http, pedir=self._pedir,
                         metadatos=self._metadatos_falsos, **opciones)
        # Ni el proceso de las pruebas ni su entorno: los pone cada prueba que los quiera.
        self.pid = None
        self.entorno = {}

    def limpiar(self):
        shutil.rmtree(self._carpeta, ignore_errors=True)

    def _ejecutar(self, args, entrada=None, heredar=False, plazo=None):
        args = list(args)
        self.ordenes.append(args)
        if plazo is not None:
            self.plazos.append((args, plazo))
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

    def _pedir(self, metodo, url, cabeceras):
        self.peticiones_sonda.append((metodo, url, dict(cabeceras)))
        if self.pedir_falso is not None:
            return self.pedir_falso(metodo, url, cabeceras)
        return None, {}, b""

    def _metadatos_falsos(self, metodo, url, cabeceras):
        self.peticiones_metadatos.append((metodo, url, dict(cabeceras)))
        if self.metadatos_falso is not None:
            return self.metadatos_falso(metodo, url, cabeceras)
        return None, {}, b""

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


#: Lo que lleva en sus claves un paquete sin firmar (`firma.MARCADOR`).
MARCADOR_DE_CLAVE = b"# PENDIENTE-DE-DANIEL\n"


def claves_de_marcador(sis, prefijo):
    """Las dos claves de lo instalado, de vuelta al marcador. Desde que Daniel creó las suyas (2026-10-05), el paquete
    lleva claves de verdad: las pruebas de un servidor sin firmas que comprobar las ponen ellas, y no dependen de lo que
    tenga el repositorio."""
    for nombre in ("clave-publica.pem", "clave-rescate.pem"):
        sis.poner(prefijo + "/" + nombre, MARCADOR_DE_CLAVE)


def ed25519():
    """Una clave Ed25519 de usar y tirar, generada ahora: ``(privada, pública en PEM)``. Nunca una de Daniel. Sin
    `cryptography` (va en el venv de server/avisos) la prueba que la pida se salta."""
    import unittest
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise unittest.SkipTest("sin cryptography (va en el venv de server/avisos)")
    privada = Ed25519PrivateKey.generate()
    publica = privada.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    return privada, publica


def firmar(privada, ruta: str) -> str:
    """Lo que hace `openssl pkeyutl -sign -rawin`: los 64 bytes de Ed25519 sobre el fichero entero, en `<ruta>.sig`."""
    with open(ruta, "rb") as f:
        sello = privada.sign(f.read())
    with open(ruta + ".sig", "wb") as f:
        f.write(sello)
    return ruta + ".sig"


def openssl_que_verifica(args, entrada=None):
    """`openssl pkeyutl -verify -pubin -inkey <pem> -rawin -in <fichero> -sigfile <firma>` como el OpenSSL 3 del
    servidor, con `cryptography`: el LibreSSL del Mac no sabe Ed25519. Contesta lo mismo que él, en lo bueno y en lo
    malo, y a lo que no es esa orden, como un openssl que no la entiende."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    forma = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", None, "-rawin", "-in", None, "-sigfile", None]
    if len(args) != len(forma) or any(f is not None and a != f for a, f in zip(args, forma)):
        return Resultado(1, "", "pkeyutl: Unknown option\n")
    try:
        with open(args[5], "rb") as f:
            publica = serialization.load_pem_public_key(f.read())
        with open(args[8], "rb") as f:
            datos = f.read()
        with open(args[10], "rb") as f:
            sello = f.read()
    except (OSError, ValueError):
        return Resultado(1, "", "Could not read\n")
    try:
        publica.verify(sello, datos)
    except (InvalidSignature, AttributeError, TypeError):
        return Resultado(1, "Signature Verification Failure\n", "")
    return Resultado(0, "Signature Verified Successfully\n", "")


def bien(salida: str = "") -> "callable":
    return lambda args, entrada: Resultado(0, salida, "")


def mal(error: str = "", codigo: int = 1, salida: str = "") -> "callable":
    return lambda args, entrada: Resultado(codigo, salida, error)
