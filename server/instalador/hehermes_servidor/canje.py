"""El canje del alta por chat (spec, sección B): lo que entrega la PSK de un iPhone, cifrada para la llave de su frase.

Corre aparte del instalador, en su propio venv con `cryptography` (`/opt/hehermes-canje/venv`), como un usuario de usar
y tirar (`DynamicUser`) dentro de la unidad temporal `hehermes-canje` que lanza `porchat.lanzar`. El instalador, con el
Python del sistema, no importa este módulo: lo ejecuta.

**El sobre.** Lo mismo que los avisos (X25519, HKDF-SHA256 y ChaCha20-Poly1305), pero para una clave pública: el
servidor hace una clave efímera por sobre, acuerda con la llave del iPhone y deriva la del sobre con un HKDF que lleva
dentro la huella del certificado del canje, el código del enlace, el paso del protocolo y las dos claves públicas. Así
un sobre de otro servidor, de otro canje o del otro paso no se abre aunque vaya para la misma llave::

    {"v": 1, "e": base64(efímera pública), "n": base64(nonce de 12), "t": base64(cifrado ‖ etiqueta de 16)}

Lo abre `CifradoDelCanje.swift` en la app; lo fija el vector compartido `HeHermesMensajesTests/Fixtures/canje-vpn.json`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION = 1
PREFIJO_INFO = b"hehermes-canje/v1/"
PROPOSITOS = ("reto", "psk")
BYTES_CODIGO = 16


class ErrorDeCanje(Exception):
    """Una llave, un código o un sobre que no valen. Nunca lleva nada secreto en el mensaje."""


# MARK: Codificación


def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def de_b64url(texto: object, bytes_: int) -> bytes:
    """Base64url sin relleno de exactamente `bytes_` bytes, y sin nada que `urlsafe_b64decode` se tragara en silencio:
    se vuelve a codificar y tiene que dar lo mismo. Una llave con basura daría otra llave, y el iPhone no abriría nada."""
    if not isinstance(texto, str) or not texto or len(texto) != (bytes_ * 4 + 2) // 3:
        raise ErrorDeCanje("no es base64url de %d bytes" % bytes_)
    try:
        datos = base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))
    except (binascii.Error, ValueError):
        raise ErrorDeCanje("no es base64url") from None
    if len(datos) != bytes_ or b64url(datos) != texto:
        raise ErrorDeCanje("no es base64url de %d bytes" % bytes_)
    return datos


def codigo_nuevo() -> str:
    """128 bits al azar: 22 caracteres. Adivinarlo en los 10 minutos y 5 intentos del canje no es una opción."""
    return b64url(secrets.token_bytes(BYTES_CODIGO))


def huella_spki(spki_der: bytes) -> str:
    """Lo que ancla la app: el SHA-256 de la clave pública del certificado (su SPKI), no del certificado entero."""
    return b64url(hashlib.sha256(spki_der).digest())


# MARK: El sobre


def info(proposito: str, huella: bytes, codigo: str, efimera: bytes, llave: bytes) -> bytes:
    """Todo lo que ata un sobre a su canje. Detrás del propósito, un cero y campos de largo fijo: no hay dos formas de
    leer los mismos bytes."""
    if proposito not in PROPOSITOS:
        raise ErrorDeCanje("propósito desconocido")
    if len(huella) != 32 or len(efimera) != 32 or len(llave) != 32:
        raise ErrorDeCanje("huella o claves que no miden 32 bytes")
    return PREFIJO_INFO + proposito.encode("ascii") + b"\x00" + huella + codigo.encode("ascii") + efimera + llave


def _clave(compartido: bytes, datos_info: bytes) -> bytes:
    # La sal vacía, como en los avisos: HMAC rellena con ceros una clave corta, así que da lo mismo que la de ceros por
    # defecto de la RFC 5869, y CryptoKit la acepta igual.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=datos_info).derive(compartido)


def _crudo(publica: X25519PublicKey) -> bytes:
    return publica.public_bytes(Encoding.Raw, PublicFormat.Raw)


def sellar_para(llave: bytes, proposito: str, huella: bytes, codigo: str, claro: bytes,
                efimera: bytes | None = None, nonce: bytes | None = None) -> dict:
    """Cifra `claro` para la llave del iPhone. La efímera y el nonce son nuevos en cada sobre; fijarlos es cosa de las
    pruebas, para tener un vector."""
    try:
        publica = X25519PublicKey.from_public_bytes(llave)
    except ValueError:
        raise ErrorDeCanje("la llave no es una clave X25519") from None
    privada = X25519PrivateKey.from_private_bytes(efimera) if efimera else X25519PrivateKey.generate()
    nonce = os.urandom(12) if nonce is None else nonce
    if len(nonce) != 12:
        raise ErrorDeCanje("el nonce tiene que medir 12 bytes")
    e = _crudo(privada.public_key())
    try:
        compartido = privada.exchange(publica)
    except ValueError:
        # Una llave de orden bajo da un secreto de ceros: quien la mandó no quiere un sobre, quiere romperlo.
        raise ErrorDeCanje("la llave no sirve para acordar una clave") from None
    clave = _clave(compartido, info(proposito, huella, codigo, e, llave))
    sellado = ChaCha20Poly1305(clave).encrypt(nonce, claro, None)
    return {"v": VERSION, "e": base64.b64encode(e).decode("ascii"), "n": base64.b64encode(nonce).decode("ascii"),
            "t": base64.b64encode(sellado).decode("ascii")}


def abrir_con(privada: bytes, proposito: str, huella: bytes, codigo: str, sobre: dict) -> bytes:
    """Lo que hace la app con un sobre. Aquí sirve a las pruebas y al cliente de Python que hace de iPhone."""
    if not isinstance(sobre, dict) or sobre.get("v") != VERSION:
        raise ErrorDeCanje("versión de sobre desconocida")
    try:
        e = base64.b64decode(str(sobre.get("e", "")), validate=True)
        nonce = base64.b64decode(str(sobre.get("n", "")), validate=True)
        sellado = base64.b64decode(str(sobre.get("t", "")), validate=True)
        mia = X25519PrivateKey.from_private_bytes(privada)
        compartido = mia.exchange(X25519PublicKey.from_public_bytes(e))
    except (binascii.Error, ValueError):
        raise ErrorDeCanje("sobre ilegible") from None
    if len(nonce) != 12 or len(sellado) < 16:
        raise ErrorDeCanje("sobre ilegible")
    clave = _clave(compartido, info(proposito, huella, codigo, e, _crudo(mia.public_key())))
    try:
        return ChaCha20Poly1305(clave).decrypt(nonce, sellado, None)
    except InvalidTag:
        raise ErrorDeCanje("el sobre no se abre con esta llave") from None


# MARK: El canje


DURACION = 600.0
MAX_FALLOS = 5
MAX_FALLOS_POR_IP = 3
PAUSA_POR_IP = 1.0
#: Conexiones por IP en todo el canje: el iPhone hace dos (y alguna más si reintenta). Pasado el tope, ni el apretón.
MAX_CONEXIONES_POR_IP = 20
#: IP distintas que recuerda: la memoria del canje no crece sin fin con un barrido desde muchas direcciones.
MAX_IPS = 1024
RUTA_RETO = "/canje/v1/reto"
RUTA_CANJEAR = "/canje/v1/canjear"
#: Cómo sale el proceso al cerrarse: la limpieza (root, en `ExecStopPost`) solo apunta el canje con un 0.
SALIDAS = {"canjeado": 0, "caducado": 3, "demasiados_intentos": 4}
_CERRADO = {"canjeado": (409, {"error": "canjeado"}), "caducado": (410, {"error": "caducado"}),
            "demasiados_intentos": (429, {"error": "demasiados_intentos"})}


class Canje:
    """Un canje, sin red: recibe peticiones ya leídas y devuelve (estado HTTP, JSON). Todo lo que decide está aquí.

    Dos pasos para que quien lea el enlace en el chat no pueda gastarlo: el reto va cifrado para la llave de la frase,
    y sin la privada, que no ha salido del iPhone, no hay reto que devolver. Sus intentos, además, cuentan.
    """

    def __init__(self, llave: bytes, codigo: str, huella: bytes, carga: bytes, reloj=None, azar=os.urandom):
        import time
        self.llave, self.codigo, self.huella, self.carga = llave, codigo, huella, carga
        self.reloj = reloj or time.monotonic
        self.azar = azar
        self.inicio = self.reloj()
        self.reto = None
        self.fallos = 0
        self.fallos_por_ip = {}
        self.ultima_por_ip = {}
        self.conexiones_por_ip = {}
        self.motivo = None

    @property
    def cerrado(self) -> bool:
        return self.motivo is not None

    def vencido(self) -> bool:
        return self.reloj() - self.inicio > DURACION

    def cerrar(self, motivo):
        if self.motivo is None:
            self.motivo = motivo
            # Lo que ya no hace falta, fuera de la memoria del proceso cuanto antes.
            self.reto = None
            self.carga = b""
        return _CERRADO[self.motivo]

    def admitir(self, ip: str) -> bool:
        """Antes del apretón TLS: si esta IP puede abrir otra conexión. No es un fallo del protocolo: no cierra el
        canje, solo deja fuera a quien insiste."""
        vistas = self.conexiones_por_ip.get(ip)
        if vistas is None and len(self.conexiones_por_ip) >= MAX_IPS:
            return False
        if (vistas or 0) >= MAX_CONEXIONES_POR_IP:
            return False
        self.conexiones_por_ip[ip] = (vistas or 0) + 1
        return True

    def atender(self, ruta: str, ip: str, cuerpo: bytes):
        if self.cerrado:
            return _CERRADO[self.motivo]
        if self.vencido():
            return self.cerrar("caducado")
        if ruta not in (RUTA_RETO, RUTA_CANJEAR):
            # Lo mismo que a un escáner: un 404 sin nada dentro.
            return 404, None
        ahora = self.reloj()
        anterior = self.ultima_por_ip.get(ip)
        self.ultima_por_ip[ip] = ahora
        if anterior is not None and ahora - anterior < PAUSA_POR_IP:
            return 429, {"error": "despacio"}
        try:
            datos = json.loads(cuerpo.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            datos = None
        if not isinstance(datos, dict) or not _igual(datos.get("c"), self.codigo):
            return self._fallo(ip)
        if ruta == RUTA_RETO:
            self.reto = self.azar(32)
            return 200, sellar_para(self.llave, "reto", self.huella, self.codigo, self.reto)
        try:
            reto = base64.b64decode(str(datos.get("reto", "")), validate=True)
        except (binascii.Error, ValueError):
            reto = b""
        if self.reto is None or not hmac.compare_digest(reto, self.reto):
            return self._fallo(ip)
        sobre = sellar_para(self.llave, "psk", self.huella, self.codigo, self.carga)
        self.cerrar("canjeado")
        return 200, sobre

    def _fallo(self, ip):
        self.fallos += 1
        self.fallos_por_ip[ip] = self.fallos_por_ip.get(ip, 0) + 1
        if self.fallos >= MAX_FALLOS or self.fallos_por_ip[ip] >= MAX_FALLOS_POR_IP:
            return self.cerrar("demasiados_intentos")
        return 403, {"error": "no_vale", "quedan": MAX_FALLOS - self.fallos}


def _igual(dado, esperado: str) -> bool:
    return isinstance(dado, str) and hmac.compare_digest(dado.encode("utf-8"), esperado.encode("ascii"))


# MARK: El certificado


def preparar(carpeta: str, dias: int = 1) -> str:
    """La clave y el certificado de este canje, autofirmado y sin ningún dato: quien escanee el puerto no saca de él ni
    de quién es el servidor. Un día de validez, que es de sobra para diez minutos. Devuelve la huella de su SPKI.

    La pasarela usa lo mismo con diez años (`--dias 3650`): la app solo ancla la huella, y no mira las fechas."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
    from cryptography.x509.oid import NameOID

    clave = ec.generate_private_key(ec.SECP256R1())
    # Un nombre al azar: ni «hehermes» ni nada que diga a un escáner qué hay detrás. La app no lo mira: ancla la SPKI.
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, secrets.token_hex(8))])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre).public_key(clave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(minutes=5))
            .not_valid_after(ahora + datetime.timedelta(days=dias))
            .sign(clave, hashes.SHA256()))
    _escribir_privado(os.path.join(carpeta, "clave.pem"),
                      clave.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    _escribir_privado(os.path.join(carpeta, "cert.pem"), cert.public_bytes(Encoding.PEM))
    return huella_spki(clave.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def _escribir_privado(ruta, datos):
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(datos)
    os.chmod(ruta, 0o600)


# MARK: El servidor


MAX_CUERPO = 4096
_TEXTOS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict", 410: "Gone",
           429: "Too Many Requests"}


def servir(el_canje: Canje, cert: str, clave: str, puerto: int, direccion: str = "", listo=None, tic: float = 1.0,
           plazo_saludo: float = 5.0, diario=None, tls_minimo=None) -> int:
    """TLS 1.3 y una petición a la vez hasta que el canje se cierra o vence. Devuelve la salida del proceso.

    Una a la vez a propósito: así no hay carreras en el estado del canje, y para un iPhone que hace dos peticiones sobra.
    Cada conexión tiene `plazo_saludo` segundos para el apretón de manos y la petición: quien conecta y se calla no
    deja el canje colgado.

    `tls_minimo` es TLS 1.3 salvo en las pruebas del Mac: el Python de Xcode va con LibreSSL 2.8, que no sabe TLS 1.3.
    En el servidor (Debian 12+ y Ubuntu 22.04+, con OpenSSL 3) es siempre 1.3.
    """
    import socket
    import ssl

    diario = diario or (lambda texto: print(texto, flush=True))
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = tls_minimo or ssl.TLSVersion.TLSv1_3
    contexto.load_cert_chain(cert, clave)
    if direccion == "" and socket.has_dualstack_ipv6():
        escucha = socket.create_server(("", puerto), family=socket.AF_INET6, dualstack_ipv6=True)
    else:
        escucha = socket.create_server((direccion or "0.0.0.0", puerto))
    with escucha:
        escucha.settimeout(tic)
        diario("canje abierto en el puerto %d" % escucha.getsockname()[1])
        if listo:
            listo(escucha.getsockname()[1])
        while not el_canje.cerrado:
            if el_canje.vencido():
                el_canje.cerrar("caducado")
                break
            try:
                conexion, origen = escucha.accept()
            except socket.timeout:
                continue
            except OSError:
                continue
            with conexion:
                if not el_canje.admitir(_ip(origen)):
                    continue
                conexion.settimeout(plazo_saludo)
                try:
                    with contexto.wrap_socket(conexion, server_side=True) as tls:
                        _atender(el_canje, tls, _ip(origen))
                except (OSError, ssl.SSLError, ValueError):
                    pass
    diario("canje cerrado: %s" % el_canje.motivo)
    return SALIDAS[el_canje.motivo]


def _ip(origen) -> str:
    ip = origen[0]
    return ip[7:] if ip.startswith("::ffff:") else ip


def _atender(el_canje, tls, ip):
    f = tls.makefile("rb")
    linea = f.readline(1024).decode("latin-1").split()
    # Todo lo que no es una petición del protocolo recibe el mismo 404 sin nada: ni qué servidor es, ni qué rutas hay.
    if len(linea) != 3:
        return _responder(tls, 404, None)
    metodo, ruta, _ = linea
    largo = 0
    for _ in range(50):
        cabecera = f.readline(1024)
        if cabecera in (b"\r\n", b"\n", b""):
            break
        nombre, _, valor = cabecera.decode("latin-1").partition(":")
        if nombre.strip().lower() == "content-length":
            try:
                largo = int(valor.strip())
            except ValueError:
                return _responder(tls, 404, None)
    if metodo != "POST" or not 0 <= largo <= MAX_CUERPO:
        # Lo que no es del protocolo (un escáner con su GET) no cuenta como intento: no puede cerrar el canje.
        return _responder(tls, 404, None)
    cuerpo = f.read(largo) if largo else b""
    estado, respuesta = el_canje.atender(ruta, ip, cuerpo)
    _responder(tls, estado, respuesta)


def _responder(tls, estado, datos):
    """Sin cabecera `Server` (esto no es un servidor web que se anuncie). `None`: sin cuerpo y sin tipo."""
    if datos is None:
        tls.sendall(b"HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    % (estado, _TEXTOS.get(estado, "Error").encode()))
        return
    cuerpo = json.dumps(datos, separators=(",", ":")).encode()
    tls.sendall(("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store"
                 "\r\nConnection: close\r\n\r\n" % (estado, _TEXTOS.get(estado, "Error"), len(cuerpo))).encode()
                + cuerpo)


# MARK: La orden


def main(argv) -> int:
    """`preparar <carpeta>`: la clave, el certificado y su huella, como root, antes de lanzar la unidad.
    `servir`: el canje, desde las credenciales que le pasa systemd (`LoadCredential`), como un DynamicUser."""
    if argv[:1] == ["preparar"] and len(argv) in (2, 4) and (len(argv) == 2 or argv[2] == "--dias"):
        dias = int(argv[3]) if len(argv) == 4 else 1
        if not 1 <= dias <= 3650:
            print("error: --dias va de 1 a 3650", flush=True)
            return 2
        print(json.dumps({"huella": preparar(argv[1], dias)}))
        return 0
    if argv[:1] == ["servir"] and len(argv) in (1, 3) and (len(argv) == 1 or argv[1] == "--carpeta"):
        # Con root, systemd le pasa las credenciales (LoadCredential, a un DynamicUser); sin root, en modo TLS, una
        # carpeta 0700 del usuario en /run/user/<uid>, que borra la limpieza al acabar.
        credenciales = argv[2] if len(argv) == 3 else os.environ.get("CREDENTIALS_DIRECTORY")
        if not credenciales:
            print("error: servir lo lanza systemd, con las credenciales del canje", flush=True)
            return 2
        nombres = ("canje", "cert", "clave") if len(argv) == 1 else ("canje.json", "cert.pem", "clave.pem")
        with open(os.path.join(credenciales, nombres[0]), "rb") as f:
            datos = json.load(f)
        el_canje = Canje(de_b64url(datos["llave"], 32), datos["codigo"], de_b64url(datos["huella"], 32),
                         json.dumps(datos["carga"], separators=(",", ":")).encode())
        puerto, direccion = int(datos["puerto"]), datos.get("direccion", "")
        del datos
        return servir(el_canje, os.path.join(credenciales, nombres[1]), os.path.join(credenciales, nombres[2]), puerto,
                      direccion)
    print("uso: python -m hehermes_servidor.canje preparar <carpeta> [--dias N] | servir [--carpeta <carpeta>]",
          flush=True)
    return 2


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
