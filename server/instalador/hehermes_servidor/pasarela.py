"""hehermes-pasarela: la conexión directa de la app con Hermes, sin VPN (spec 2026-09-26, «La pasarela TLS»).

Escucha en un puerto TCP alto (el que eligió el instalador), habla solo TLS 1.3 con un certificado propio cuya huella
ancla la app, y a cada petición con el token de un iPhone la reenvía a `127.0.0.1`: a Hermes con su `API_SERVER_KEY`
(la app no la conoce), o al vigía de avisos con su secreto si la ruta es `/avisos/…`. Lo que no trae un token válido
recibe siempre el mismo 404, un segundo después. El contrato con la app está en `server/API-CONTRACT.md`, §12.

Solo la biblioteca estándar: corre con el `python3` del sistema, como un usuario sin privilegios (`hh-pasarela`, con
root) o como el de Hermes (sin root). `cryptography` solo hace falta para generar el certificado, y eso es cosa del
instalador y su venv.

**Nunca apunta el token, la ruta con su consulta ni ningún cuerpo**: la ruta de `/avisos/` lleva el token de avisos del
iPhone, y la de los ficheros, lo que Hermes le mandó.
"""

from __future__ import annotations

import base64
import binascii
import collections
import configparser
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time

from .entorno import leer_env

# MARK: Los números (los de server/API-CONTRACT.md, §12.6)

#: Intentos sin token válido desde una IP en `VENTANA_FALLOS` segundos que la bloquean `BLOQUEO` segundos. Desde la
#: 0.9.0, una IP bloqueada no se queda sin pasarela (detrás de un CGNAT hay muchos iPhone con la misma): lo que traiga un
#: token válido pasa, y lo que no, se cierra al momento, sin el 404 ni su segundo, y con solo
#: `CONEXIONES_POR_IP_BLOQUEADA` a la vez sin autenticar.
MAX_FALLOS = 10
VENTANA_FALLOS = 600
BLOQUEO = 900
#: Conexiones **sin autenticar** (el apretón TLS y la primera cabecera) por IP y en total. Una conexión que ya ha pasado
#: una petición con un token válido deja de contar aquí: los SSE y el pool de cada iPhone no se comen el cupo de los
#: demás iPhone de su IP.
CONEXIONES_POR_IP = 16
CONEXIONES_EN_TOTAL = 128
CONEXIONES_POR_IP_BLOQUEADA = 4
#: Las rechazadas esperan su segundo aparte, sin ocupar el cupo de arriba: por IP y en total. Si no caben, se cierran
#: sin contestar.
CASTIGADAS_POR_IP = 16
CASTIGADAS_EN_TOTAL = 256
#: Con el cupo lleno, una conexión sin autenticar de más de estos segundos deja su sitio a la nueva: un slowloris no
#: puede quedarse con el cupo de su IP (ni con el de todos). Un apretón y una cabecera de verdad tardan menos.
PLAZO_DESALOJO = 3.0
#: IP distintas que se recuerdan: un barrido desde muchas direcciones no hace crecer la memoria sin fin.
MAX_IPS = 4096
#: Contra slowloris: la línea de la petición y las cabeceras, enteras, en este plazo.
PLAZO_CABECERAS = 10
PLAZO_APRETON = 10
#: Una conexión persistente sin nada se cierra a los 75 s.
PLAZO_PARADA = 75
#: Mientras llega un cuerpo, cada trozo; mientras Hermes contesta, no hay plazo (el SSE dura lo que dura el turno).
PLAZO_TROZO = 30
RETRASO_404 = 1.0
#: Con lo que sale si no puede arrancar por su configuración (EX_CONFIG): su unidad no lo reinicia en bucle.
SALIDA_CONFIGURACION = 78
MAX_CABECERAS = 16 * 1024
MAX_LINEAS_CABECERA = 100
#: Una foto va en base64 dentro del JSON de /v1/runs: lo mismo que el `client_max_body_size 25m` del túnel.
MAX_CUERPO = 25 * 1024 * 1024
MAX_CUERPO_AVISOS = 64 * 1024
#: La copia en iCloud (contrato §15, desde la 0.10.0): un trozo de 4 MiB comprimido, que puede pasar un poco de 4 MiB
#: si no comprime, o el manifiesto de una restauración. Lo mismo que el vigía (`hehermes_avisos.vigia.respaldo`).
MAX_CUERPO_RESPALDO = 4 * 1024 * 1024 + 64 * 1024
PREFIJO_RESPALDO = "/avisos/v1/respaldo/"
#: Cada cuánto se mira si ha cambiado tokens.json (y se cortan las conexiones de un token dado de baja).
REVISION_TOKENS = 1.0

TOKEN_VALIDO = re.compile(r"[A-Za-z0-9_-]{43}")
_HASH_VALIDO = re.compile(r"[0-9a-f]{64}")


# MARK: Los tokens


def token_nuevo() -> str:
    """32 bytes del generador del sistema: 256 bits, 43 caracteres de base64url sin relleno."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def hash_token(token: str) -> str:
    """Lo único que se guarda de un token. Sin sal: un token de 256 bits al azar no se adivina con una tabla."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _firma(ruta):
    try:
        datos = os.stat(ruta)
    except OSError:
        return None
    return (datos.st_ino, datos.st_mtime_ns, datos.st_size)


class Tokens:
    """Los tokens de `tokens.json`, que escriben el instalador y `hehermes-dispositivo` (`tokens.py`). Se vuelve a leer
    en cuanto cambia: una baja vale al momento."""

    def __init__(self, ruta: str):
        self.ruta = ruta
        self._firma = None
        self._entradas = []
        self.recargar_si_cambia()

    def recargar_si_cambia(self) -> bool:
        firma = _firma(self.ruta)
        if firma == self._firma and firma is not None:
            return False
        self._firma = firma
        self._entradas = _leer_tokens(self.ruta)
        return True

    def quien(self, token) -> str | None:
        """El nombre del iPhone de ese token, o None. Contra todas las entradas y sin salir en la que coincide, con
        `hmac.compare_digest`: el tiempo no dice ni cuál es ni si hay alguno que se le parezca."""
        if not isinstance(token, str) or not TOKEN_VALIDO.fullmatch(token):
            return None
        buscado = hash_token(token).encode("ascii")
        hallado = None
        for nombre, guardado in self._entradas:
            if hmac.compare_digest(buscado, guardado):
                hallado = nombre
        return hallado

    def sigue(self, hash_hex: str) -> bool:
        """Si un hash sigue dado de alta: lo que mira cada conexión abierta tras una recarga."""
        buscado = hash_hex.encode("ascii")
        sigue = False
        for _, guardado in self._entradas:
            if hmac.compare_digest(buscado, guardado):
                sigue = True
        return sigue


def _leer_tokens(ruta):
    """Un fichero que falta o no se entiende no deja pasar a nadie (cerrado, no con lo de antes)."""
    try:
        with open(ruta, "rb") as f:
            datos = json.loads(f.read())
    except (OSError, ValueError):
        return []
    if not isinstance(datos, dict) or datos.get("v") != 1 or not isinstance(datos.get("tokens"), list):
        return []
    entradas = []
    for t in datos["tokens"]:
        if isinstance(t, dict) and isinstance(t.get("nombre"), str) and _HASH_VALIDO.fullmatch(str(t.get("sha256"))):
            entradas.append((t["nombre"], t["sha256"].encode("ascii")))
    return entradas


# MARK: Los límites


class Limites:
    """Quién puede abrir otra conexión sin autenticar: un tope por IP (más bajo si la IP está bloqueada por sus fallos) y
    otro en total; y aparte, cuántas rechazadas esperan su 404. Todo en memoria: al reiniciarse la pasarela, se empieza
    de cero."""

    def __init__(self, reloj=time.monotonic, contar_locales=False):
        self.reloj = reloj
        #: Solo las pruebas, que no tienen otra dirección que 127.0.0.1, cuentan los fallos de este servidor.
        self.contar_locales = contar_locales
        self._fallos = collections.OrderedDict()   # ip -> deque de instantes
        self._bloqueos = collections.OrderedDict()  # ip -> hasta cuándo
        self._abiertas = {}
        self.abiertas = 0
        self._castigadas = {}
        self.castigadas = 0

    def bloqueada(self, ip: str) -> bool:
        hasta = self._bloqueos.get(ip)
        if hasta is None:
            return False
        if self.reloj() >= hasta:
            del self._bloqueos[ip]
            return False
        return True

    def tope_de(self, ip: str) -> int:
        return CONEXIONES_POR_IP_BLOQUEADA if self.bloqueada(ip) else CONEXIONES_POR_IP

    def llena(self, ip: str) -> bool:
        """Si la IP ya tiene todas las que puede sin autenticar (y no el total)."""
        return self._abiertas.get(ip, 0) >= self.tope_de(ip)

    def admitir(self, ip: str) -> bool:
        """Una conexión nueva sin autenticar, si cabe."""
        if self.abiertas >= CONEXIONES_EN_TOTAL or self.llena(ip):
            return False
        self._abiertas[ip] = self._abiertas.get(ip, 0) + 1
        self.abiertas += 1
        return True

    def soltar(self, ip: str) -> None:
        self.abiertas -= _restar(self._abiertas, ip)

    def castigar(self, ip: str) -> bool:
        """Sitio para que una rechazada espere su 404, fuera del cupo de `admitir`. False si no cabe."""
        if self.castigadas >= CASTIGADAS_EN_TOTAL or self._castigadas.get(ip, 0) >= CASTIGADAS_POR_IP:
            return False
        self._castigadas[ip] = self._castigadas.get(ip, 0) + 1
        self.castigadas += 1
        return True

    def perdonar(self, ip: str) -> None:
        self.castigadas -= _restar(self._castigadas, ip)

    def fallo(self, ip: str) -> None:
        """Las de este mismo servidor no cuentan: `comprobar` se asoma sin token, y un bloqueo de 127.0.0.1 no
        protege de nada (un token de 256 bits no se adivina)."""
        if _local(ip) and not self.contar_locales:
            return
        ahora = self.reloj()
        vistos = self._fallos.pop(ip, None)
        if vistos is None:
            vistos = collections.deque()
            while len(self._fallos) >= MAX_IPS:
                self._fallos.popitem(last=False)
        while vistos and ahora - vistos[0] > VENTANA_FALLOS:
            vistos.popleft()
        vistos.append(ahora)
        if len(vistos) >= MAX_FALLOS:
            self._bloquear(ip, ahora)
            return
        self._fallos[ip] = vistos

    def _bloquear(self, ip, ahora):
        self._bloqueos.pop(ip, None)
        if len(self._bloqueos) >= MAX_IPS:
            # Primero los que ya han vencido; si no, el más viejo.
            for vieja in [i for i, hasta in self._bloqueos.items() if hasta <= ahora]:
                del self._bloqueos[vieja]
            while len(self._bloqueos) >= MAX_IPS:
                self._bloqueos.popitem(last=False)
        self._bloqueos[ip] = ahora + BLOQUEO


def _restar(cuentas: dict, ip: str) -> int:
    cuantas = cuentas.get(ip, 0)
    if cuantas <= 0:
        return 0
    if cuantas == 1:
        del cuentas[ip]
    else:
        cuentas[ip] = cuantas - 1
    return 1


def _local(ip) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


# MARK: El mantenimiento (desde la 0.9.0)

#: Lo que apunta la pasarela en su carpeta de estado para el borrado de verdad (`mantenimiento.py`): que hay algo borrado
#: de Hermes pendiente de limpiar del disco (sin ids ni nada del contenido: solo desde cuándo), y su actividad, para que
#: la limpieza espere a un rato tranquilo. `MANTENIMIENTO` lo escribe la limpieza, y la pasarela lo enseña a la app.
BORRADO_PENDIENTE = "borrado-pendiente"
ACTIVIDAD = "actividad.json"
MANTENIMIENTO = "mantenimiento.json"
RUTA_MANTENIMIENTO = "/hehermes/v1/mantenimiento"
#: Lo que es borrar una conversación de Hermes para siempre (el «Eliminar también de Hermes» de la app).
BORRAR_SESION = re.compile(r"/api/sessions/[A-Za-z0-9_.:%-]{1,256}(?:\?[\x21-\x7e]*)?")
#: Cada cuánto se apunta la actividad (solo si ha cambiado, o cada cinco minutos aunque no).
APUNTAR_ACTIVIDAD = 30.0
#: Lo que se enseña de `MANTENIMIENTO`, y nada más.
_CAMPOS_MANTENIMIENTO = ("ultimo_borrado", "ultimo_intento", "fallo", "fallos_seguidos", "no_puede", "metodo")


class Mantenimiento:
    """La carpeta de estado de la pasarela (con root, `StateDirectory=hehermes-pasarela`: /var/lib/hehermes-pasarela;
    sin root, ~/.local/state/hehermes-pasarela). Escribe siempre al lado y renombra, sin seguir enlaces."""

    def __init__(self, carpeta: str, reloj=time.time):
        self.carpeta, self.reloj = carpeta, reloj

    def _ruta(self, nombre):
        return os.path.join(self.carpeta, nombre)

    def _escribir(self, nombre, datos: bytes):
        temporal = self._ruta(".%s.%d.%s" % (nombre, os.getpid(), secrets.token_hex(4)))
        fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(datos)
            os.replace(temporal, self._ruta(nombre))
        except BaseException:
            if os.path.exists(temporal):
                os.unlink(temporal)
            raise

    def _leer(self, nombre, tope=4096):
        try:
            fd = os.open(self._ruta(nombre), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        with os.fdopen(fd, "rb") as f:
            return f.read(tope)

    def apuntar_borrado(self) -> None:
        """Hay algo borrado pendiente de limpiar. Si ya lo había, se queda la fecha de la primera."""
        if pendiente_desde(self._leer(BORRADO_PENDIENTE)) is None:
            self._escribir(BORRADO_PENDIENTE, b"%d\n" % int(self.reloj()))

    def apuntar_actividad(self, reenviando: int, ultima) -> None:
        self._escribir(ACTIVIDAD, json.dumps({"reenviando": int(reenviando), "ultima": ultima,
                                              "escrita": int(self.reloj())}).encode("ascii"))

    def estado(self) -> dict:
        """Lo que se le enseña a la app: si hay un borrado pendiente (y desde cuándo) y lo que apuntó la limpieza."""
        desde = pendiente_desde(self._leer(BORRADO_PENDIENTE))
        salida = {"borrado_pendiente": desde is not None, "pendiente_desde": desde}
        try:
            datos = json.loads(self._leer(MANTENIMIENTO) or b"{}")
        except ValueError:
            datos = {}
        for campo in _CAMPOS_MANTENIMIENTO:
            valor = datos.get(campo) if isinstance(datos, dict) else None
            salida[campo] = valor if isinstance(valor, (int, float, str, bool)) or valor is None else None
        return salida


def pendiente_desde(datos) -> int | None:
    """La fecha (segundos) de `borrado-pendiente`, o None si no hay o no se entiende."""
    try:
        texto = (datos or b"").decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return int(texto) if re.fullmatch(r"[0-9]{1,12}", texto) else None


# MARK: Los secretos de 127.0.0.1


_CLAVE_VALIDA = re.compile(r"[\x21-\x7e]+")


def leer_clave_hermes(texto: str) -> str | None:
    """La `API_SERVER_KEY`: de un `.env` (sin root, la pasarela lee el de Hermes) o de un fichero con la clave sola (con
    root, la copia que le pasa systemd). Solo caracteres que pueden ir en una cabecera."""
    if not isinstance(texto, str):
        return None
    if re.search(r"^\s*(?:export\s+)?API_SERVER_KEY\s*=", texto, re.M):
        clave = leer_env(texto).get("API_SERVER_KEY")
    elif "=" in texto:
        return None
    else:
        clave = texto.strip()
    if not clave or not _CLAVE_VALIDA.fullmatch(clave) or '"' in clave:
        return None
    return clave


def leer_secreto_vigia(texto: str) -> str | None:
    """El secreto que el vigía espera en `X-HeHermes-Vigia` (`server/avisos/despliegue/instalar.sh`)."""
    valor = (texto or "").strip()
    return valor if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", valor) else None


class Secreto:
    """Un fichero pequeño que se vuelve a leer si cambia. Así la pasarela coge la clave nueva de Hermes sin reiniciarse
    (ni cortar los SSE): sin root, del .env de Hermes; con root, de su copia, que cambia `pasarela-clave` (desde la 0.9.0,
    sin reiniciarla). Un fichero que no se deja leer no se da por visto: se vuelve a probar en la petición siguiente
    (por ejemplo, entre que se escribe y se le da a su dueño)."""

    def __init__(self, ruta, extraer):
        self.ruta, self.extraer = ruta, extraer
        self._firma, self._valor = None, None

    def valor(self):
        firma = _firma(self.ruta) if self.ruta else None
        if firma is None:
            self._firma, self._valor = None, None
            return None
        if firma != self._firma:
            try:
                with open(self.ruta, "r", encoding="utf-8", errors="replace") as f:
                    self._valor = self.extraer(f.read(65536))
            except OSError:
                self._firma, self._valor = None, None
                return None
            self._firma = firma
        return self._valor


# MARK: La huella del certificado, sin cryptography


def _tlv(datos: bytes, i: int):
    """(etiqueta, inicio del contenido, fin) del elemento DER que empieza en `i`."""
    if i + 2 > len(datos):
        raise ValueError("DER cortado")
    etiqueta, largo = datos[i], datos[i + 1]
    i += 2
    if largo & 0x80:
        n = largo & 0x7F
        if n == 0 or n > 4 or i + n > len(datos):
            raise ValueError("largo DER no válido")
        largo = int.from_bytes(datos[i:i + n], "big")
        i += n
    if i + largo > len(datos):
        raise ValueError("DER cortado")
    return etiqueta, i, i + largo


def huella_de_der(der: bytes) -> str:
    """El SHA-256 del SPKI de un certificado DER, en base64url sin relleno: lo que ancla la app. Para que `comprobar`
    compare la huella que sirve la pasarela con la del QR sin `cryptography`."""
    etiqueta, inicio, _ = _tlv(der, 0)
    if etiqueta != 0x30:
        raise ValueError("no es un certificado")
    etiqueta, i, fin_tbs = _tlv(der, inicio)
    if etiqueta != 0x30:
        raise ValueError("no es un certificado")
    campo = _tlv(der, i)
    if campo[0] == 0xA0:  # la versión, [0], si está
        i = campo[2]
    # serialNumber, signature, issuer, validity, subject; el siguiente es el SPKI.
    for _ in range(5):
        i = _tlv(der, i)[2]
        if i > fin_tbs:
            raise ValueError("certificado cortado")
    etiqueta, _, fin = _tlv(der, i)
    if etiqueta != 0x30 or fin > fin_tbs:
        raise ValueError("no encuentro el SPKI")
    return base64.urlsafe_b64encode(hashlib.sha256(der[i:fin]).digest()).rstrip(b"=").decode("ascii")


# MARK: La configuración


class Configuracion:
    """`pasarela.ini`, que escribe el instalador (`piezas.pasarela_ini`). Con root, systemd le pasa los secretos como
    credenciales (`LoadCredential`), y esas mandan sobre las rutas del fichero."""

    def __init__(self):
        self.puerto = None
        self.escucha = ""
        self.certificado = self.clave = self.tokens = None
        #: El certificado que viene después (solo el público: su clave no se usa hasta rotar). Su huella se publica a
        #: quien trae un token (`RUTA_HUELLAS`), para que el cliente la ancle también y la rotación no le pille.
        self.certificado_siguiente = None
        #: La carpeta de estado (`Mantenimiento`), si la hay.
        self.mantenimiento = None
        self.puerto_hermes = None
        self.clave_hermes = None
        self.vigia = None
        self.secreto_vigia = None

    @classmethod
    def leer(cls, ruta: str, credenciales=None) -> "Configuracion":
        ini = configparser.ConfigParser(interpolation=None)
        try:
            with open(ruta, encoding="utf-8") as f:
                ini.read_file(f)
        except (OSError, configparser.Error) as error:
            raise ValueError("no puedo leer %s: %s" % (ruta, error))
        c = cls()
        try:
            c.puerto = _puerto(ini.get("pasarela", "puerto"))
            c.escucha = ini.get("pasarela", "escucha", fallback="").strip()
            c.certificado = _absoluta(ini.get("pasarela", "certificado"))
            c.clave = _absoluta(ini.get("pasarela", "clave"))
            c.tokens = _absoluta(ini.get("pasarela", "tokens"))
            siguiente = ini.get("pasarela", "certificado_siguiente", fallback="").strip()
            c.certificado_siguiente = _absoluta(siguiente) if siguiente else None
            estado = ini.get("mantenimiento", "carpeta", fallback="").strip()
            c.mantenimiento = _absoluta(estado) if estado else None
            c.puerto_hermes = _puerto(ini.get("hermes", "puerto"))
            c.clave_hermes = _absoluta(ini.get("hermes", "clave"))
            vigia = ini.get("avisos", "vigia", fallback="").strip()
            if vigia:
                host, _, puerto = vigia.rpartition(":")
                if not ipaddress.ip_address(host).is_loopback:
                    raise ValueError("el vigía tiene que estar en 127.0.0.1, no en %s" % host)
                c.vigia = (host, _puerto(puerto))
                c.secreto_vigia = _absoluta(ini.get("avisos", "secreto"))
        except (configparser.Error, ValueError) as error:
            raise ValueError("%s: %s" % (ruta, error))
        if credenciales:
            for atributo, nombre in (("clave", "clave"), ("clave_hermes", "hermes"), ("secreto_vigia", "vigia")):
                candidata = os.path.join(credenciales, nombre)
                if os.path.exists(candidata):
                    setattr(c, atributo, candidata)
        return c


def _puerto(texto):
    puerto = int(str(texto).strip())
    if not 0 < puerto < 65536:
        raise ValueError("puerto no válido: %s" % texto)
    return puerto


def _absoluta(ruta):
    ruta = ruta.strip()
    if not ruta.startswith("/"):
        raise ValueError("ruta no absoluta: %s" % ruta)
    return ruta


def _es_base64url(texto, bytes_=32) -> bool:
    if not isinstance(texto, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", texto):
        return False
    try:
        datos = base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))
    except (binascii.Error, ValueError):
        return False
    return len(datos) == bytes_ and base64.urlsafe_b64encode(datos).rstrip(b"=").decode() == texto


# MARK: El servidor

import asyncio  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402

#: Lo que contesta la pasarela misma (no va a Hermes) a quien trae un token: la huella de su certificado y la del que
#: viene después, para rotarlo sin volver a emparejar (server/API-CONTRACT.md, §12.7).
RUTA_HUELLAS = "/hehermes/v1/huellas"
#: Lo que recibe todo lo que no trae un token válido: siempre estos bytes, ni más ni menos.
NO_ENCONTRADO = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_METODOS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
#: Con `fullmatch`, nunca con `match` y `$`: `$` casa también delante de un «\n» final, y «GET /x\n HTTP/1.1» (o una
#: cabecera «X\n: y») pasaba a Hermes con un salto de línea suelto dentro (el fuzz de la auditoría, §14.9).
_RUTA = re.compile(r"/[\x21-\x7e]*")
_NOMBRE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
#: Lo que no pasa de un salto al siguiente, lo que pone la pasarela y los secretos que pone ella.
_QUITAR_DE_LA_APP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer",
                     "transfer-encoding", "upgrade", "expect", "host", "authorization", "x-hehermes-vigia",
                     "x-forwarded-for", "content-length"}
_QUITAR_DE_HERMES = {"server", "connection", "keep-alive", "proxy-connection", "upgrade", "trailer"}
_TEXTOS = {400: "Bad Request", 413: "Payload Too Large", 502: "Bad Gateway", 503: "Service Unavailable"}
_MENSAJES = {"peticion_invalida": "La petición no tiene una forma que la pasarela acepte",
             "cuerpo_demasiado_grande": "El cuerpo es más grande de lo que la pasarela acepta",
             "hermes_no_contesta": "Hermes no contesta en este servidor",
             "avisos_no_instalados": "Los avisos no están instalados en este servidor",
             "vigia_no_contesta": "El vigía de avisos no contesta en este servidor",
             "rele_no_contesta": "El relé de avisos no contesta"}
PLAZO_CONECTAR = 5
#: Lo que espera la respuesta de Hermes entre dos trozos: lo mismo que el `proxy_read_timeout 1h` del túnel.
PLAZO_HERMES = 3600
TROZO = 65536


class _Rechazo(Exception):
    """Lo que acaba en el 404 idéntico."""


class _Plazo(Exception):
    """Las cabeceras no han llegado a tiempo: se cierra sin decir nada (y cuenta como un fallo)."""


class _Error(Exception):
    def __init__(self, estado, codigo):
        super().__init__(codigo)
        self.estado, self.codigo = estado, codigo


def contexto_tls(config, tls_minimo=None) -> ssl.SSLContext:
    """TLS 1.3 y nada más (las pruebas del Mac bajan a 1.2: el Python de Xcode trae LibreSSL 2.8)."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = tls_minimo or ssl.TLSVersion.TLSv1_3
    contexto.options |= ssl.OP_NO_COMPRESSION
    contexto.load_cert_chain(config.certificado, config.clave)
    try:
        contexto.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return contexto


def respuesta_de_error(estado, codigo) -> bytes:
    cuerpo = json.dumps({"error": {"message": _MENSAJES[codigo], "type": "pasarela", "param": None, "code": codigo}},
                        ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return (("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\n"
             "Connection: close\r\n\r\n") % (estado, _TEXTOS[estado], len(cuerpo))).encode("ascii") + cuerpo


class _Conexion:
    """Lo que la pasarela sabe de cada conexión atendida: de qué IP, desde cuándo, en qué cupo está (`previa`: sin
    autenticar; `dentro`: ya pasó una petición con un token válido; `castigo`: esperando su 404; `fuera`: ya no cuenta)
    y el hash del token con el que pasó (el que se sigue por si se da de baja)."""

    __slots__ = ("ip", "inicio", "fase", "huella", "tarea")

    def __init__(self, ip, inicio, tarea=None):
        self.ip, self.inicio, self.tarea = ip, inicio, tarea
        self.fase = "previa"
        self.huella = None


class Peticion:
    __slots__ = ("metodo", "ruta", "version", "cabeceras", "largo", "cerrar")

    def __init__(self, metodo, ruta, version, cabeceras):
        self.metodo, self.ruta, self.version, self.cabeceras = metodo, ruta, version, cabeceras
        self.largo = 0
        self.cerrar = False

    def valores(self, nombre):
        return [v for n, v in self.cabeceras if n.lower() == nombre]


def leer_cabeza(bruto: bytes) -> Peticion:
    """La línea de la petición y sus cabeceras, sin la línea vacía del final. Todo lo que no es HTTP/1.1 limpio es un
    rechazo: ni cabeceras dobladas, ni nombres raros, ni caracteres de control."""
    try:
        texto = bruto.decode("latin-1")
    except UnicodeDecodeError:
        raise _Rechazo()
    lineas = texto.split("\r\n")
    if len(lineas) - 1 > MAX_LINEAS_CABECERA:
        raise _Rechazo()
    partes = lineas[0].split(" ")
    if len(partes) != 3:
        raise _Rechazo()
    metodo, ruta, version = partes
    if metodo not in _METODOS or version not in ("HTTP/1.1", "HTTP/1.0") or not _RUTA.fullmatch(ruta):
        raise _Rechazo()
    cabeceras = []
    for linea in lineas[1:]:
        if not linea or linea[0] in " \t":
            raise _Rechazo()
        nombre, dos_puntos, valor = linea.partition(":")
        valor = valor.strip(" \t")
        if not dos_puntos or not _NOMBRE.fullmatch(nombre) or any(ord(c) < 32 and c != "\t" or ord(c) == 127
                                                                for c in valor):
            raise _Rechazo()
        cabeceras.append((nombre, valor))
    return Peticion(metodo, ruta, version, cabeceras)


def cabeza_hacia_arriba(peticion: Peticion, destino, ip: str, poner) -> bytes:
    """La línea y las cabeceras que salen hacia 127.0.0.1: las de la app menos lo que no pasa de un salto al siguiente y
    los secretos (que pone la pasarela), y el largo que ella ha medido, con `Connection: close`."""
    cabeceras = [(n, v) for n, v in peticion.cabeceras if n.lower() not in _QUITAR_DE_LA_APP]
    cabeceras += [("Host", "%s:%d" % tuple(destino)), ("X-Forwarded-For", ip)] + list(poner)
    if peticion.largo or peticion.metodo in ("POST", "PUT", "PATCH"):
        cabeceras.append(("Content-Length", str(peticion.largo)))
    cabeceras.append(("Connection", "close"))
    return (("%s %s HTTP/1.1\r\n" % (peticion.metodo, peticion.ruta)).encode("latin-1")
            + "".join("%s: %s\r\n" % c for c in cabeceras).encode("latin-1") + b"\r\n")


def token_de(peticion: Peticion):
    valores = peticion.valores("authorization")
    if len(valores) != 1:
        return None
    esquema, _, token = valores[0].partition(" ")
    return token if esquema.lower() == "bearer" else None


class Pasarela:
    """El servidor. Lo reutiliza la entrada pública del relé de avisos (`hehermes_avisos.rele.publico`), con sus
    credenciales en lugar de los tokens y su `destino`: el mismo TLS, los mismos límites y el mismo 404."""

    #: Cómo se llama en su registro.
    nombre = "pasarela"

    def __init__(self, config, tokens=None, limites=None, diario=None, tls_minimo=None, retraso_404=RETRASO_404,
                 plazo_cabeceras=PLAZO_CABECERAS, plazo_parada=PLAZO_PARADA, revision=REVISION_TOKENS,
                 desalojo=PLAZO_DESALOJO):
        self.config = config
        self.tokens = tokens if tokens is not None else Tokens(config.tokens)
        self.limites = limites if limites is not None else Limites()
        self.clave_hermes = Secreto(config.clave_hermes, leer_clave_hermes)
        self.secreto_vigia = Secreto(config.secreto_vigia, leer_secreto_vigia) if config.vigia else None
        self.diario = diario or (lambda texto: print(texto, flush=True))
        self.contexto = contexto_tls(config, tls_minimo)
        self.huellas = {"actual": _huella_de_pem(config.certificado),
                        "siguiente": _huella_de_pem(getattr(config, "certificado_siguiente", None))}
        carpeta = getattr(config, "mantenimiento", None)
        self.mantenimiento = Mantenimiento(carpeta) if carpeta else None
        #: Las peticiones que están ahora con Hermes (un SSE cuenta mientras dura) y cuándo llegó la última con token.
        self._reenviando = 0
        self._ultima = None
        self.retraso_404, self.plazo_cabeceras, self.plazo_parada = retraso_404, plazo_cabeceras, plazo_parada
        self.revision = revision
        self.desalojo = desalojo
        #: Cada conexión atendida (su tarea), con lo que se sabe de ella (`_Conexion`).
        self._conexiones = {}
        self._parado = None

    def parar(self):
        if self._parado is not None and not self._parado.done():
            self._parado.set_result(None)

    async def servir(self, listo=None):
        bucle = asyncio.get_running_loop()
        self._parado = bucle.create_future()
        escucha = _escuchar(self.config.escucha, self.config.puerto)
        escucha.setblocking(False)
        puerto = escucha.getsockname()[1]
        self.diario("%s escuchando en el puerto %d" % (self.nombre, puerto))
        if listo:
            listo(puerto)
        tareas = [asyncio.ensure_future(self._aceptar(escucha)), asyncio.ensure_future(self._vigilar_tokens())]
        if self.mantenimiento is not None:
            tareas.append(asyncio.ensure_future(self._apuntar_actividad()))
        try:
            await self._parado
        finally:
            for tarea in tareas + list(self._conexiones):
                tarea.cancel()
            await asyncio.gather(*tareas, *list(self._conexiones), return_exceptions=True)
            escucha.close()

    async def _aceptar(self, escucha):
        bucle = asyncio.get_running_loop()
        while True:
            try:
                crudo, origen = await bucle.sock_accept(escucha)
            except (OSError, ssl.SSLError):
                await asyncio.sleep(0.05)
                continue
            ip = _ip(origen)
            if not self.limites.admitir(ip) and not (self._desalojar(ip) and self.limites.admitir(ip)):
                # Sobre el tope (y nadie a quien desalojar): ni el apretón TLS.
                crudo.close()
                continue
            conexion = _Conexion(ip, self.limites.reloj())
            conexion.tarea = asyncio.ensure_future(self._conexion(crudo, ip))
            self._conexiones[conexion.tarea] = conexion
            conexion.tarea.add_done_callback(self._acabada)

    def _acabada(self, tarea):
        conexion = self._conexiones.pop(tarea, None)
        if conexion is not None:
            self._pasar(conexion, "fuera")

    def _pasar(self, conexion, fase):
        """Saca la conexión del cupo en el que estaba. El de `castigo` se toma aparte (`Limites.castigar`), antes."""
        if conexion.fase == fase:
            return
        if conexion.fase == "previa":
            self.limites.soltar(conexion.ip)
        elif conexion.fase == "castigo":
            self.limites.perdonar(conexion.ip)
        conexion.fase = fase

    def _desalojar(self, ip) -> bool:
        """Con el cupo lleno (el de la IP o el de todas), la conexión sin autenticar más vieja de esa IP (o de todas)
        deja su sitio, si lleva más de `desalojo` segundos: un slowloris no retiene el cupo, y un apretón de verdad no
        tarda tanto. True si ha dejado sitio."""
        de_la_ip = self.limites.llena(ip)
        ahora = self.limites.reloj()
        for conexion in self._conexiones.values():  # en orden de llegada: la primera que valga es la más vieja
            if conexion.fase == "previa" and (not de_la_ip or conexion.ip == ip) and \
                    ahora - conexion.inicio >= self.desalojo:
                self._pasar(conexion, "fuera")
                conexion.tarea.cancel()
                self.diario("%s desalojada: sin cabeceras en %.0f s" % (conexion.ip, ahora - conexion.inicio))
                return True
        return False

    def _esta(self):
        return self._conexiones.get(asyncio.current_task())

    async def _apuntar_actividad(self, cada=None):
        """Para la limpieza de noche: cuántas peticiones están con Hermes y cuándo llegó la última. Solo si cambia (y
        cada cinco minutos aunque no, para que se vea que la pasarela vive)."""
        antes, vez = None, 0
        while True:
            ahora = (self._reenviando, self._ultima)
            if ahora != antes or vez >= 10:
                try:
                    self.mantenimiento.apuntar_actividad(*ahora)
                    antes, vez = ahora, 0
                except OSError as error:
                    self.diario("no puedo apuntar la actividad (%s)" % type(error).__name__)
            vez += 1
            await asyncio.sleep(cada or APUNTAR_ACTIVIDAD)

    async def _contestar_mantenimiento(self, peticion, escritor, ip) -> bool:
        estado = self.mantenimiento.estado() if self.mantenimiento is not None else {"disponible": False}
        cuerpo = json.dumps(estado, separators=(",", ":")).encode("ascii")
        escritor.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                        "Cache-Control: no-store\r\nConnection: %s\r\n\r\n"
                        % (len(cuerpo), "close" if peticion.version == "HTTP/1.0" else "keep-alive")).encode("ascii")
                       + (b"" if peticion.metodo == "HEAD" else cuerpo))
        await escritor.drain()
        self.diario("%s %s 200 %d" % (ip, peticion.metodo, len(cuerpo)))
        return peticion.version != "HTTP/1.0" and "close" not in ",".join(peticion.valores("connection")).lower()

    async def _vigilar_tokens(self):
        """Una baja o una rotación cierran las conexiones abiertas con ese token, también un SSE a medias."""
        while True:
            await asyncio.sleep(self.revision)
            if self.tokens.recargar_si_cambia():
                for tarea, conexion in list(self._conexiones.items()):
                    if conexion.huella is not None and not self.tokens.sigue(conexion.huella):
                        tarea.cancel()

    async def _conexion(self, crudo, ip):
        bucle = asyncio.get_running_loop()
        escritor = None
        try:
            lector = asyncio.StreamReader(limit=MAX_CABECERAS)
            protocolo = asyncio.StreamReaderProtocol(lector)
            try:
                transporte, _ = await asyncio.wait_for(bucle.connect_accepted_socket(
                    lambda: protocolo, crudo, ssl=self.contexto, ssl_handshake_timeout=PLAZO_APRETON),
                    PLAZO_APRETON + 1)
            except (OSError, ssl.SSLError, asyncio.TimeoutError, ConnectionError):
                crudo.close()
                return
            escritor = asyncio.StreamWriter(transporte, protocolo, lector, bucle)
            primera = True
            while True:
                seguir = await self._una(lector, escritor, ip, primera)
                primera = False
                if not seguir:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as error:  # noqa: BLE001 — nada de lo que manda un cliente tumba la pasarela
            # Solo el tipo: el mensaje de una excepción puede llevar trozos de la petición.
            self.diario("%s conexión cerrada por un fallo (%s)" % (ip, type(error).__name__))
        finally:
            if escritor is not None:
                escritor.close()

    async def _cabeza(self, lector, primera):
        """La cabeza entera: el primer byte en su plazo (10 s en la primera petición, 75 s entre dos) y el resto en
        el de las cabeceras. None si el cliente cierra sin mandar nada."""
        try:
            primero = await asyncio.wait_for(lector.read(1), self.plazo_cabeceras if primera else self.plazo_parada)
        except asyncio.TimeoutError:
            if primera:
                raise _Plazo()
            return None
        if not primero:
            return None
        try:
            resto = await asyncio.wait_for(lector.readuntil(b"\r\n\r\n"), self.plazo_cabeceras)
        except asyncio.TimeoutError:
            raise _Plazo()
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, ValueError):
            raise _Rechazo()
        return (primero + resto)[:-4]

    async def castigo(self, ip, bloqueada=None) -> bool:
        """El segundo de espera de un rechazo, fuera del cupo de las conexiones sin autenticar (y de las autenticadas):
        el retraso no lo pagan los demás de esa IP. False si no hay que contestar nada: la IP ya estaba bloqueada (se
        cierra al momento; `bloqueada`, como estaba antes de contar este fallo) o ya hay demasiadas esperando."""
        conexion = self._esta()
        if bloqueada is None:
            bloqueada = self.limites.bloqueada(ip)
        if bloqueada or not self.limites.castigar(ip):
            if conexion is not None:
                self._pasar(conexion, "fuera")
            return False
        if conexion is not None:
            self._pasar(conexion, "castigo")
        else:
            self.limites.perdonar(ip)
        await asyncio.sleep(self.retraso_404)
        return True

    async def _rechazar(self, escritor, ip, contar=True):
        # El fallo que bloquea la IP aún recibe su 404; los de después, ya no.
        bloqueada = self.limites.bloqueada(ip)
        if contar:
            self.limites.fallo(ip)
        if not await self.castigo(ip, bloqueada):
            self.diario("%s rechazada: cerrada sin contestar" % ip)
            return False
        escritor.write(NO_ENCONTRADO)
        try:
            await escritor.drain()
        except (OSError, ConnectionError):
            pass
        self.diario("%s rechazada: 404" % ip)
        return False

    async def _una(self, lector, escritor, ip, primera) -> bool:
        """Una petición. True si la conexión sigue para otra."""
        try:
            bruto = await self._cabeza(lector, primera)
            if bruto is None:
                return False
            peticion = leer_cabeza(bruto)
        except _Plazo:
            self.limites.fallo(ip)
            self.diario("%s cerrada: las cabeceras no llegan" % ip)
            return False
        except _Rechazo:
            # Sin cabeza entera no se sabe si traía token: cuenta.
            return await self._rechazar(escritor, ip)
        aparte = await self.atender_aparte(peticion, lector, escritor, ip)
        if aparte is not None:
            return aparte
        huella = self.autorizar(peticion)
        if huella is None:
            return await self._rechazar(escritor, ip)
        conexion = self._esta()
        if conexion is not None:
            # Ya es de alguien de verdad: deja el cupo de las conexiones sin autenticar de su IP.
            self._pasar(conexion, "dentro")
            # Una autorización que no es un token (`""`) no se sigue: no hay baja que la corte a media conexión.
            conexion.huella = huella or None
        self._ultima = int(time.time())
        if peticion.ruta == RUTA_HUELLAS and peticion.metodo in ("GET", "HEAD"):
            return await self._contestar_huellas(peticion, escritor, ip)
        if peticion.ruta == RUTA_MANTENIMIENTO and peticion.metodo in ("GET", "HEAD"):
            return await self._contestar_mantenimiento(peticion, escritor, ip)
        try:
            return await self._reenviar(peticion, lector, escritor, ip)
        except _Error as error:
            escritor.write(respuesta_de_error(error.estado, error.codigo))
            await escritor.drain()
            self.diario("%s %s %d" % (ip, peticion.metodo, error.estado))
            return False

    async def _contestar_huellas(self, peticion, escritor, ip) -> bool:
        cuerpo = json.dumps(self.huellas, separators=(",", ":")).encode("ascii")
        escritor.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                        "Cache-Control: no-store\r\nConnection: %s\r\n\r\n"
                        % (len(cuerpo), "close" if peticion.version == "HTTP/1.0" else "keep-alive")).encode("ascii")
                       + (b"" if peticion.metodo == "HEAD" else cuerpo))
        await escritor.drain()
        self.diario("%s %s 200 %d" % (ip, peticion.metodo, len(cuerpo)))
        return peticion.version != "HTTP/1.0" and "close" not in ",".join(peticion.valores("connection")).lower()

    async def atender_aparte(self, peticion, lector, escritor, ip):
        """Lo que se atiende antes de mirar el token: aquí nada (None). La entrada pública del relé atiende así las
        rutas de los permisos de avisos, que no llevan credencial. Devuelve si la conexión sigue, como `_una`."""
        return None

    def _apuntar_borrado(self, ip):
        """Hermes ha borrado una conversación: queda en su disco (páginas libres de SQLite) hasta que la limpieza de
        noche lo compacte con Hermes parado (`mantenimiento.py`). Ni el id ni nada de lo que era."""
        if self.mantenimiento is None:
            return
        try:
            self.mantenimiento.apuntar_borrado()
        except OSError as error:
            self.diario("%s no puedo apuntar el borrado pendiente (%s)" % (ip, type(error).__name__))

    def autorizar(self, peticion):
        """El hash del token de la petición si es uno dado de alta (el que se sigue por si se da de baja), `""` si la
        petición vale por otra cosa que no se sigue, o None: el 404 idéntico."""
        self.tokens.recargar_si_cambia()
        token = token_de(peticion)
        if self.tokens.quien(token) is None:
            return None
        return hash_token(token)

    def tope(self, peticion) -> int:
        """El cuerpo más grande que se deja pasar a esa ruta."""
        if peticion.ruta.startswith(PREFIJO_RESPALDO):
            return MAX_CUERPO_RESPALDO
        return MAX_CUERPO_AVISOS if peticion.ruta.startswith("/avisos/") else MAX_CUERPO

    def destino(self, peticion, ip):
        """(dirección en 127.0.0.1, cabeceras que pone la pasarela, código de error si no contesta) de una petición que
        ya trae un token válido. La entrada pública del relé (`hehermes_avisos.rele.publico`) pone la suya."""
        if peticion.ruta.startswith("/avisos/"):
            if self.config.vigia is None:
                raise _Error(503, "avisos_no_instalados")
            secreto = self.secreto_vigia.valor()
            if secreto is None:
                raise _Error(503, "avisos_no_instalados")
            return self.config.vigia, [("X-HeHermes-Vigia", secreto)], "vigia_no_contesta"
        clave = self.clave_hermes.valor()
        if clave is None:
            self.diario("%s sin la clave de Hermes: no la puedo leer" % ip)
            raise _Error(502, "hermes_no_contesta")
        return ("127.0.0.1", self.config.puerto_hermes), [("Authorization", "Bearer " + clave)], "hermes_no_contesta"

    async def _reenviar(self, peticion, lector, escritor, ip) -> bool:
        if peticion.valores("transfer-encoding"):
            raise _Error(400, "peticion_invalida")
        largos = peticion.valores("content-length")
        if len(set(largos)) > 1 or (largos and not re.fullmatch(r"[0-9]{1,12}", largos[0])):
            raise _Error(400, "peticion_invalida")
        peticion.largo = int(largos[0]) if largos else 0
        if peticion.largo > self.tope(peticion):
            raise _Error(413, "cuerpo_demasiado_grande")
        conexion = ",".join(peticion.valores("connection")).lower()
        peticion.cerrar = "close" in conexion or (peticion.version == "HTTP/1.0" and "keep-alive" not in conexion)
        destino, poner, caido = self.destino(peticion, ip)
        try:
            arriba_lector, arriba = await asyncio.wait_for(asyncio.open_connection(*destino, limit=MAX_CABECERAS * 4),
                                                           PLAZO_CONECTAR)
        except (OSError, asyncio.TimeoutError):
            raise _Error(502, caido)
        self._reenviando += 1
        try:
            return await self._ida_y_vuelta(peticion, lector, escritor, arriba_lector, arriba, destino, poner, ip,
                                            caido)
        finally:
            self._reenviando -= 1
            arriba.close()

    async def _ida_y_vuelta(self, peticion, lector, escritor, arriba_lector, arriba, destino, poner, ip, caido):
        arriba.write(cabeza_hacia_arriba(peticion, destino, ip, poner))
        quedan = peticion.largo
        while quedan:
            trozo = await asyncio.wait_for(lector.read(min(TROZO, quedan)), PLAZO_TROZO)
            if not trozo:
                return False
            quedan -= len(trozo)
            arriba.write(trozo)
            await arriba.drain()
        try:
            await arriba.drain()
            cabeza = await asyncio.wait_for(arriba_lector.readuntil(b"\r\n\r\n"), PLAZO_HERMES)
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ValueError):
            raise _Error(502, caido)
        lineas = cabeza[:-4].decode("latin-1").split("\r\n")
        estado_linea = lineas[0].split(" ", 2)
        if len(estado_linea) < 2 or not estado_linea[1].isdigit() or not estado_linea[0].startswith("HTTP/1."):
            raise _Error(502, caido)
        estado = int(estado_linea[1])
        if peticion.metodo == "DELETE" and 200 <= estado < 300 and BORRAR_SESION.fullmatch(peticion.ruta):
            self._apuntar_borrado(ip)
        salida, largo, troceada = [], None, False
        for linea in lineas[1:]:
            nombre, _, valor = linea.partition(":")
            bajo = nombre.strip().lower()
            if bajo in _QUITAR_DE_HERMES or not bajo:
                continue
            if bajo == "content-length":
                largo = int(valor.strip()) if valor.strip().isdigit() else None
            if bajo == "transfer-encoding":
                troceada = "chunked" in valor.lower()
            salida.append(linea)
        sin_cuerpo = peticion.metodo == "HEAD" or estado in (204, 304) or 100 <= estado < 200
        # Tras una respuesta troceada o sin largo, la conexión se cierra: su final es el de Hermes.
        seguir = not peticion.cerrar and (sin_cuerpo or (largo is not None and not troceada))
        salida.append("Connection: %s" % ("keep-alive" if seguir else "close"))
        escritor.write(("%s\r\n%s\r\n\r\n" % (lineas[0], "\r\n".join(salida))).encode("latin-1"))
        await escritor.drain()
        enviados = 0
        if not sin_cuerpo:
            quedan = largo if (largo is not None and not troceada) else None
            while quedan is None or quedan > 0:
                trozo = await asyncio.wait_for(arriba_lector.read(TROZO if quedan is None else min(TROZO, quedan)),
                                               PLAZO_HERMES)
                if not trozo:
                    if quedan:
                        seguir = False
                    break
                escritor.write(trozo)
                # Sin búfer: cada trozo del SSE sale en cuanto llega.
                await escritor.drain()
                enviados += len(trozo)
                if quedan is not None:
                    quedan -= len(trozo)
        self.diario("%s %s %d %d" % (ip, peticion.metodo, estado, enviados))
        return seguir


def _huella_de_pem(ruta):
    """La huella del certificado de `ruta` (PEM), o None si no hay o no se entiende."""
    if not ruta:
        return None
    try:
        with open(ruta, encoding="ascii") as f:
            return huella_de_der(ssl.PEM_cert_to_DER_cert(f.read()))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _escuchar(direccion, puerto):
    if direccion == "" and socket.has_dualstack_ipv6():
        return socket.create_server(("", puerto), family=socket.AF_INET6, dualstack_ipv6=True, backlog=128)
    return socket.create_server((direccion or "0.0.0.0", puerto), backlog=128)


def _ip(origen) -> str:
    ip = origen[0]
    return ip[7:] if ip.startswith("::ffff:") else ip


# MARK: La orden


def main(argv) -> int:
    """`hehermes-pasarela --config <pasarela.ini>`: lo que lanza su unidad de systemd."""
    if len(argv) != 2 or argv[0] != "--config":
        print("uso: hehermes-pasarela --config <pasarela.ini>", flush=True)
        return 2
    try:
        config = Configuracion.leer(argv[1], credenciales=os.environ.get("CREDENTIALS_DIRECTORY"))
        pasarela = Pasarela(config)
    except (ValueError, OSError, ssl.SSLError) as error:
        # La configuración o un secreto: reiniciar no lo arregla. La unidad no reinicia con 78 (EX_CONFIG).
        print("error: no arranco: %s. Arréglalo (sudo hehermes-servidor comprobar) y reinicia hehermes-pasarela"
              % error, flush=True)
        return SALIDA_CONFIGURACION
    try:
        asyncio.run(pasarela.servir())
    except KeyboardInterrupt:
        pass
    return 0
