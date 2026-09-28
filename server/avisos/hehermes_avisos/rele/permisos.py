"""Los permisos de avisos por dispositivo, avalados con App Attest (spec 2026-09-28, «Avisos sin comandos»).

Un **permiso** dice: «el relé acepta avisos para el token con este SHA-256, en este entorno, hasta tal fecha», firmado
con Ed25519. Lo da la **oficina de permisos** (``Oficina``, dentro de la entrada pública del relé, que no puede leer la
.p8) a la app, a cambio de una atestación de App Attest (la primera vez) o de una aserción (después). La app se lo pasa
a su vigía, y el vigía lo manda con cada aviso (``Authorization: Permiso hhp1.…``). El relé solo tiene la clave
**pública** (``Verificador``): comprueba la firma, la fecha, la revocación y que el token del aviso es el del permiso.

Aquí vive todo lo de los permisos menos el HTTP: la forma del permiso, la lista de revocados, las claves atestadas (un
SQLite de la entrada pública), los retos, los límites y lo que contesta cada ruta de la oficina.

Lo que no se apunta nunca: el permiso, el reto, el token (solo sus seis últimos caracteres, ``cola``) ni los cuerpos.
"""

from __future__ import annotations

import base64
import binascii
import collections
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..comun import ENTORNOS, PATRON_TOKEN, cola, escribir_privado
from . import appattest

registro = logging.getLogger("rele.permisos")

PREFIJO = "hhp1."
FORMA = re.compile(r"hhp1\.[A-Za-z0-9_-]{16,700}\.[A-Za-z0-9_-]{86}")
#: Lo que dura un permiso, y desde cuándo la app lo renueva.
DURACION = 60 * 86400
RENOVAR_TRAS = 20 * 86400
#: Lo que vale un reto, y cuántos se guardan a la vez (los más viejos se olvidan antes).
VIDA_DEL_RETO = 300
MAX_RETOS = 10000
#: Avisos por minuto de un permiso (un solo iPhone: más que eso es un vigía roto).
POR_MINUTO_PERMISO = 20
ESQUEMA_AUTORIZACION = "permiso"
#: Los datos que firma la app: el reto, el token y el entorno, para que la firma no valga para otro reto, otro iPhone
#: ni otro entorno.
CABECERA_FIRMADA = "hehermes-permiso:1"
_RETO = re.compile(r"[A-Za-z0-9_-]{43}")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ErrorDePermiso(ValueError):
    """Un permiso que no vale: ``motivo`` es ``permiso_invalido``, ``permiso_caducado`` o ``permiso_revocado``."""

    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


def huella(texto: str) -> str:
    return hashlib.sha256(texto.encode("ascii")).hexdigest()


def huella_de_clave(clave_id: bytes) -> str:
    return hashlib.sha256(clave_id).hexdigest()


def datos_firmados(reto: str, token: str, entorno: str) -> bytes:
    """Lo que firma la app (su SHA-256 es el ``clientDataHash`` de App Attest)."""
    return ("%s\n%s\n%s\n%s" % (CABECERA_FIRMADA, reto, token, entorno)).encode("utf-8")


def _b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def _de_b64url(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


# MARK: El permiso


@dataclass(frozen=True)
class Carga:
    token: str        # SHA-256 hex del token
    entorno: str
    clave: str        # SHA-256 hex del keyId
    emitido: int
    caduca: int
    id: str

    @property
    def nombre(self) -> str:
        """Cómo sale en el registro del relé: la clave, recortada. Nunca el permiso."""
        return "permiso k:" + self.clave[:8]


def firmar(privada: ed25519.Ed25519PrivateKey, token: str, entorno: str, clave_id: bytes, ahora: float) -> tuple:
    """(permiso, caduca, renovar) para ``token`` en ``entorno``, atado a la clave de App Attest ``clave_id``."""
    emitido = int(ahora)
    carga = {"v": 1, "t": huella(token), "e": entorno, "k": huella_de_clave(clave_id), "i": emitido,
             "x": emitido + DURACION, "n": _b64url(secrets.token_bytes(16))}
    cuerpo = PREFIJO + _b64url(json.dumps(carga, separators=(",", ":"), sort_keys=True).encode("ascii"))
    firma = privada.sign(cuerpo.encode("ascii"))
    return cuerpo + "." + _b64url(firma), emitido + DURACION, emitido + RENOVAR_TRAS


def leer(texto, publica: ed25519.Ed25519PublicKey, ahora: float, revocados: "Revocados | None" = None) -> Carga:
    """La carga de un permiso bien firmado, en fecha y sin revocar; si no, ``ErrorDePermiso``. La firma se mira antes
    que nada de la carga: lo que no firmó el relé no se lee."""
    if not isinstance(texto, str) or not FORMA.fullmatch(texto):
        raise ErrorDePermiso("permiso_invalido")
    cuerpo, _, firma = texto.rpartition(".")
    try:
        publica.verify(_de_b64url(firma), cuerpo.encode("ascii"))
    except (InvalidSignature, binascii.Error, ValueError):
        raise ErrorDePermiso("permiso_invalido") from None
    try:
        datos = json.loads(_de_b64url(cuerpo[len(PREFIJO):]).decode("ascii"))
        carga = Carga(datos["t"], datos["e"], datos["k"], int(datos["i"]), int(datos["x"]), str(datos["n"]))
        if datos.get("v") != 1 or not _HEX64.fullmatch(carga.token) or not _HEX64.fullmatch(carga.clave) \
                or carga.entorno not in ENTORNOS:
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, binascii.Error):
        # Firmado por el relé pero sin su forma: no debería pasar nunca, y no se acepta.
        raise ErrorDePermiso("permiso_invalido") from None
    if ahora >= carga.caduca:
        raise ErrorDePermiso("permiso_caducado")
    if revocados is not None and revocados.revocado(clave=carga.clave, token=carga.token):
        raise ErrorDePermiso("permiso_revocado")
    return carga


def cargar_privada(datos: bytes) -> ed25519.Ed25519PrivateKey:
    clave = serialization.load_pem_private_key(datos, password=None)
    if not isinstance(clave, ed25519.Ed25519PrivateKey):
        raise ValueError("la clave de los permisos no es Ed25519")
    return clave


def cargar_publica(datos: bytes) -> ed25519.Ed25519PublicKey:
    clave = serialization.load_pem_public_key(datos)
    if not isinstance(clave, ed25519.Ed25519PublicKey):
        raise ValueError("la clave pública de los permisos no es Ed25519")
    return clave


def crear_claves(privada_ruta: str, publica_ruta: str) -> bool:
    """La primera vez, el par de claves de los permisos: la privada 0600 (la de la oficina) y la pública 0644 (la del
    relé). Si ya están, no se tocan (cambiarlas deja sin valor todos los permisos dados). Devuelve si las ha creado."""
    if os.path.exists(privada_ruta):
        if not os.path.exists(publica_ruta):
            with open(privada_ruta, "rb") as fichero:
                publica = cargar_privada(fichero.read()).public_key()
            _escribir_publica(publica_ruta, publica)
        return False
    privada = ed25519.Ed25519PrivateKey.generate()
    escribir_privado(privada_ruta, privada.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    _escribir_publica(publica_ruta, privada.public_key())
    return True


def _escribir_publica(ruta: str, publica: ed25519.Ed25519PublicKey) -> None:
    escribir_privado(ruta, publica.public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(ruta, 0o644)


# MARK: Los revocados


def _firma_del_fichero(ruta: str):
    try:
        datos = os.stat(ruta)
    except OSError:
        return None
    return (datos.st_ino, datos.st_mtime_ns, datos.st_size)


class Revocados:
    """``permisos-revocados.txt``: una línea ``k:<SHA-256 del keyId>`` o ``t:<SHA-256 del token>``, y lo que vaya
    detrás de un espacio es un comentario (la fecha). Se vuelve a leer en cuanto cambia.

    Que no exista es que no hay ninguno. Uno que no se entiende **lo revoca todo** hasta que se arregle: una revocación
    hecha a mano que rompiera el fichero no puede dejar vivo lo que se quería cortar."""

    def __init__(self, ruta: str | None):
        self.ruta = ruta
        self._cerrojo = threading.Lock()
        self._firma = ("sin leer",)
        self._claves: frozenset = frozenset()
        self._tokens: frozenset = frozenset()
        self._roto = False

    def _al_dia(self) -> None:
        if not self.ruta:
            return
        firma = _firma_del_fichero(self.ruta)
        with self._cerrojo:
            if firma == self._firma:
                return
            self._firma = firma
            if firma is None:
                self._claves, self._tokens, self._roto = frozenset(), frozenset(), False
                return
            try:
                claves, tokens = _leer_revocados(self.ruta)
            except (OSError, ValueError, UnicodeDecodeError) as error:
                registro.error("no se entiende la lista de revocados (%s): ningún permiso vale hasta que se arregle",
                               type(error).__name__)
                self._roto = True
                return
            self._claves, self._tokens, self._roto = frozenset(claves), frozenset(tokens), False

    def revocado(self, clave: str | None = None, token: str | None = None) -> bool:
        self._al_dia()
        return self._roto or (clave in self._claves) or (token in self._tokens)

    def cuantos(self) -> tuple:
        self._al_dia()
        return len(self._claves), len(self._tokens)


def _leer_revocados(ruta: str) -> tuple:
    claves, tokens = set(), set()
    with open(ruta, encoding="utf-8") as fichero:
        for numero, linea in enumerate(fichero, 1):
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            entrada = linea.split()[0]
            tipo, _, valor = entrada.partition(":")
            if tipo not in ("k", "t") or not _HEX64.fullmatch(valor):
                raise ValueError("línea %d" % numero)
            (claves if tipo == "k" else tokens).add(valor)
    return claves, tokens


def entrada_de_revocacion(texto: str) -> str:
    """``k:…`` o ``t:…`` de lo que da Daniel: un keyId (base64, como lo guarda la oficina), un token (hexadecimal) o
    ya una entrada ``k:``/``t:`` con su SHA-256."""
    texto = (texto or "").strip()
    if re.fullmatch(r"[kt]:[0-9a-f]{64}", texto):
        return texto
    if PATRON_TOKEN.fullmatch(texto):
        return "t:" + huella(texto)
    try:
        clave_id = base64.b64decode(texto, validate=True)
    except (binascii.Error, ValueError):
        clave_id = b""
    if len(clave_id) == 32:
        return "k:" + huella_de_clave(clave_id)
    raise ValueError("no es un keyId (base64 de 32 bytes), ni un token de APNs, ni una entrada k:/t:")


def revocar(ruta: str, entrada: str, hoy: str | None = None) -> bool:
    """Añade ``entrada`` (ya normalizada) a la lista. Devuelve si no estaba."""
    lineas = []
    if os.path.exists(ruta):
        with open(ruta, encoding="utf-8") as fichero:
            lineas = fichero.read().splitlines()
        if any(linea.split()[:1] == [entrada] for linea in lineas if linea.strip()):
            return False
    else:
        lineas = ["# Permisos de avisos revocados: k:<SHA-256 del keyId> o t:<SHA-256 del token>, uno por línea.",
                  "# Lo escribe `hehermes-rele permiso revocar|readmitir`."]
    lineas.append("%s %s" % (entrada, hoy or datetime.date.today().isoformat()))
    _escribir_como_estaba(ruta, ("\n".join(lineas) + "\n").encode("utf-8"))
    return True


def readmitir(ruta: str, entrada: str) -> bool:
    if not os.path.exists(ruta):
        return False
    with open(ruta, encoding="utf-8") as fichero:
        lineas = fichero.read().splitlines()
    quedan = [linea for linea in lineas if linea.split()[:1] != [entrada]]
    if len(quedan) == len(lineas):
        return False
    _escribir_como_estaba(ruta, ("\n".join(quedan) + "\n").encode("utf-8"))
    return True


def _escribir_como_estaba(ruta: str, datos: bytes) -> None:
    """Con el mismo modo, dueño y grupo que tenía (``root:hh-rele 0640``): uno nuevo, igual."""
    antes = os.stat(ruta) if os.path.exists(ruta) else None
    escribir_privado(ruta, datos)
    os.chmod(ruta, (antes.st_mode & 0o777) if antes else 0o640)
    if antes is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(ruta, antes.st_uid, antes.st_gid)


# MARK: Lo que comprueba el relé


class Verificador:
    """Lo del relé: la clave pública (que se vuelve a leer si cambia) y la lista de revocados."""

    def __init__(self, publica_ruta: str | None, revocados: Revocados, reloj=time.time):
        self.publica_ruta = publica_ruta
        self.revocados = revocados
        self.reloj = reloj
        self._firma = ("sin leer",)
        self._publica = None

    def _clave(self):
        firma = _firma_del_fichero(self.publica_ruta) if self.publica_ruta else None
        if firma != self._firma:
            self._firma = firma
            try:
                with open(self.publica_ruta, "rb") as fichero:
                    self._publica = cargar_publica(fichero.read())
            except (OSError, ValueError, TypeError):
                self._publica = None
        return self._publica

    @property
    def disponible(self) -> bool:
        return self._clave() is not None

    def comprobar(self, texto: str) -> Carga:
        publica = self._clave()
        if publica is None:
            raise ErrorDePermiso("permiso_invalido")
        return leer(texto, publica, self.reloj(), self.revocados)


def permiso_de(cabecera: str | None) -> str | None:
    """El permiso de ``Authorization: Permiso hhp1.…``, o ``None`` si la cabecera es de otro esquema."""
    esquema, _, valor = (cabecera or "").partition(" ")
    return valor.strip() if esquema.lower() == ESQUEMA_AUTORIZACION else None


# MARK: Las claves atestadas


class Claves:
    """El SQLite de la oficina: una fila por clave de App Attest atestada. Lo mínimo para comprobar sus aserciones:
    su keyId (base64), su clave pública, su contador, su entorno de App Attest y dos fechas. Nada del iPhone."""

    def __init__(self, ruta: str):
        self._cerrojo = threading.Lock()
        if ruta != ":memory:" and not os.path.exists(ruta):
            os.close(os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        self._con = sqlite3.connect(ruta, check_same_thread=False, isolation_level=None)
        self._con.execute("PRAGMA busy_timeout = 5000")
        self._con.executescript("""
            CREATE TABLE IF NOT EXISTS claves (
                id TEXT PRIMARY KEY,
                publica BLOB NOT NULL,
                contador INTEGER NOT NULL,
                entorno TEXT NOT NULL,
                alta REAL NOT NULL,
                visto REAL NOT NULL
            );
        """)

    def guardar(self, clave: appattest.ClaveAtestada, ahora: float) -> None:
        """Una clave recién atestada. Si ya estaba (la app repite una atestación cuya respuesta no le llegó), con la
        misma clave pública, se deja con su contador; con otra, no puede ser (el keyId es el hash de la pública)."""
        ident = base64.b64encode(clave.clave_id).decode("ascii")
        with self._cerrojo:
            self._con.execute("INSERT INTO claves (id, publica, contador, entorno, alta, visto) VALUES (?, ?, ?, ?, ?, ?)"
                              " ON CONFLICT(id) DO UPDATE SET visto = excluded.visto WHERE publica = excluded.publica",
                              (ident, clave.publica, clave.contador, clave.entorno, ahora, ahora))

    def buscar(self, clave_id: bytes):
        """(pública DER, contador, entorno) o None."""
        ident = base64.b64encode(clave_id).decode("ascii")
        with self._cerrojo:
            fila = self._con.execute("SELECT publica, contador, entorno FROM claves WHERE id = ?", (ident,)).fetchone()
        return (bytes(fila[0]), fila[1], fila[2]) if fila else None

    def subir_contador(self, clave_id: bytes, contador: int, ahora: float) -> bool:
        """Solo si sube: dos aserciones a la vez con el mismo contador no pasan las dos."""
        ident = base64.b64encode(clave_id).decode("ascii")
        with self._cerrojo:
            cursor = self._con.execute("UPDATE claves SET contador = ?, visto = ? WHERE id = ? AND contador < ?",
                                       (contador, ahora, ident, contador))
        return cursor.rowcount == 1

    def cuantas(self) -> dict:
        with self._cerrojo:
            filas = self._con.execute("SELECT entorno, COUNT(*) FROM claves GROUP BY entorno").fetchall()
        return {entorno: n for entorno, n in filas}

    def cerrar(self) -> None:
        with self._cerrojo:
            self._con.close()


# MARK: Los límites


class Ventanas:
    """Cuántas veces en los últimos ``ventana`` segundos, por clave (una IP, un keyId, «todas»). En memoria, con un
    tope de claves recordadas: un barrido desde muchas IP no hace crecer la memoria sin fin."""

    MAX_CLAVES = 8192

    def __init__(self, reloj=time.monotonic):
        self.reloj = reloj
        self._vistas = collections.OrderedDict()
        self._cerrojo = threading.Lock()

    def admitir(self, clave: str, maximo: int, ventana: float) -> float | None:
        """``None`` si cabe (y la cuenta); si no, los segundos que faltan."""
        with self._cerrojo:
            ahora = self.reloj()
            vistas = self._vistas.pop(clave, None)
            if vistas is None:
                vistas = collections.deque()
                while len(self._vistas) >= self.MAX_CLAVES:
                    self._vistas.popitem(last=False)
            while vistas and ahora - vistas[0] >= ventana:
                vistas.popleft()
            self._vistas[clave] = vistas
            if len(vistas) >= maximo:
                return max(1.0, vistas[0] + ventana - ahora)
            vistas.append(ahora)
            return None


#: (máximo, ventana en segundos) de cada cosa.
LIMITES = {
    "reto_ip": (20, 600), "reto_todas": (3000, 600),
    "atestacion_ip": (6, 3600), "atestacion_todas": (600, 3600),
    "asercion_ip": (30, 3600), "asercion_clave": (10, 3600),
}


# MARK: La oficina


@dataclass(frozen=True)
class Respuesta:
    estado: int
    cuerpo: dict
    cabeceras: dict
    #: Si cuenta como un fallo de la IP (los 10 en 10 minutos que la bloquean): una firma o una cadena que no valen.
    fallo: bool = False


def _error(estado: int, codigo: str, mensaje: str, cabeceras: dict | None = None, fallo: bool = False) -> Respuesta:
    return Respuesta(estado, {"error": {"code": codigo, "message": mensaje}}, cabeceras or {}, fallo)


class Oficina:
    """Las tres rutas sin credencial de la entrada pública: ``reto``, ``atestacion`` y ``asercion``. Sin HTTP: recibe
    el cuerpo ya leído y la IP, y devuelve una ``Respuesta``. Puede llamarse desde varios hilos."""

    def __init__(self, privada: ed25519.Ed25519PrivateKey, claves: Claves, revocados: Revocados, *,
                 app_id: str = appattest.APP_ID, raiz=None, reloj=time.time, ventanas: Ventanas | None = None,
                 ahora_certificados=None):
        self.privada = privada
        self.publica = privada.public_key()
        self.claves = claves
        self.revocados = revocados
        self.app_id = app_id
        self.raiz = raiz
        self.reloj = reloj
        self.ventanas = ventanas or Ventanas()
        #: Para las pruebas con el vector de un iPhone de 2021: la fecha con la que se miran los certificados.
        self.ahora_certificados = ahora_certificados
        self._retos = collections.OrderedDict()
        self._cerrojo = threading.Lock()

    # -- Las rutas

    def atender(self, ruta: str, cuerpo, ip: str) -> Respuesta:
        if ruta == "/v1/permisos/reto":
            return self.reto(ip)
        if not isinstance(cuerpo, dict):
            return _error(400, "peticion_invalida", "El cuerpo tiene que ser un objeto JSON")
        if ruta == "/v1/permisos/atestacion":
            return self.atestacion(cuerpo, ip)
        if ruta == "/v1/permisos/asercion":
            return self.asercion(cuerpo, ip)
        return _error(404, "ruta_desconocida", "Ruta desconocida")

    def reto(self, ip: str) -> Respuesta:
        limitado = self._limitar(("reto_ip", ip), ("reto_todas", ""))
        if limitado:
            return limitado
        reto = _b64url(secrets.token_bytes(32))
        with self._cerrojo:
            while len(self._retos) >= MAX_RETOS:
                self._retos.popitem(last=False)
            self._retos[reto] = self.reloj() + VIDA_DEL_RETO
        return Respuesta(200, {"reto": reto, "caduca": VIDA_DEL_RETO}, {"Cache-Control": "no-store"})

    def atestacion(self, cuerpo: dict, ip: str) -> Respuesta:
        limitado = self._limitar(("atestacion_ip", ip), ("atestacion_todas", ""))
        if limitado:
            return limitado
        peticion = self._comun(cuerpo, "atestacion", appattest.TOPE_ATESTACION)
        if isinstance(peticion, Respuesta):
            return peticion
        clave_id, blob, reto, token, entorno = peticion
        if self.revocados.revocado(clave=huella_de_clave(clave_id), token=huella(token)):
            return _error(403, "clave_revocada", "Esta clave o este token tienen los permisos revocados")
        if not self._gastar_reto(reto):
            return _error(401, "reto_invalido", "El reto no es de aquí, ya se usó o ha caducado")
        client_data_hash = hashlib.sha256(datos_firmados(reto, token, entorno)).digest()
        try:
            atestada = appattest.comprobar_atestacion(blob, clave_id, client_data_hash, app_id=self.app_id,
                                                      raiz=self.raiz, ahora=self._ahora_certificados())
        except appattest.ErrorDeAtestacion as error:
            registro.warning("atestación rechazada desde %s: %s", ip, error.motivo)
            return _error(401, "atestacion_invalida", "La atestación no vale", fallo=True)
        ahora = self.reloj()
        self.claves.guardar(atestada, ahora)
        registro.info("clave k:%s atestada (%s); permiso para %s (%s)", huella_de_clave(clave_id)[:8],
                      atestada.entorno, cola(token), entorno)
        return self._permiso(token, entorno, clave_id, ahora)

    def asercion(self, cuerpo: dict, ip: str) -> Respuesta:
        limitado = self._limitar(("asercion_ip", ip))
        if limitado:
            return limitado
        peticion = self._comun(cuerpo, "asercion", appattest.TOPE_ASERCION)
        if isinstance(peticion, Respuesta):
            return peticion
        clave_id, blob, reto, token, entorno = peticion
        limitado = self._limitar(("asercion_clave", huella_de_clave(clave_id)))
        if limitado:
            return limitado
        if self.revocados.revocado(clave=huella_de_clave(clave_id), token=huella(token)):
            return _error(403, "clave_revocada", "Esta clave o este token tienen los permisos revocados")
        guardada = self.claves.buscar(clave_id)
        if guardada is None:
            return _error(404, "clave_desconocida", "Esta clave no está atestada: hace falta una atestación")
        if not self._gastar_reto(reto):
            return _error(401, "reto_invalido", "El reto no es de aquí, ya se usó o ha caducado")
        publica, contador, entorno_attest = guardada
        client_data_hash = hashlib.sha256(datos_firmados(reto, token, entorno)).digest()
        try:
            nuevo = appattest.comprobar_asercion(blob, publica, contador, client_data_hash, app_id=self.app_id)
        except appattest.ErrorDeAtestacion as error:
            registro.warning("aserción de k:%s rechazada desde %s: %s", huella_de_clave(clave_id)[:8], ip,
                             error.motivo)
            return _error(401, "asercion_invalida", "La aserción no vale", fallo=True)
        ahora = self.reloj()
        if not self.claves.subir_contador(clave_id, nuevo, ahora):
            return _error(401, "asercion_invalida", "La aserción no vale", fallo=True)
        registro.info("permiso renovado para %s (%s), clave k:%s (%s)", cola(token), entorno,
                      huella_de_clave(clave_id)[:8], entorno_attest)
        return self._permiso(token, entorno, clave_id, ahora)

    # -- Los avisos con permiso (la entrada, antes de pasarlos al relé)

    def comprobar_permiso(self, texto: str) -> Carga:
        return leer(texto, self.publica, self.reloj(), self.revocados)

    # -- Por dentro

    def _ahora_certificados(self):
        if self.ahora_certificados is not None:
            return self.ahora_certificados
        return datetime.datetime.fromtimestamp(self.reloj(), datetime.timezone.utc)

    def _limitar(self, *claves) -> Respuesta | None:
        for tipo, quien in claves:
            maximo, ventana = LIMITES[tipo]
            espera = self.ventanas.admitir(tipo + ":" + quien, maximo, ventana)
            if espera is not None:
                return _error(429, "demasiadas_peticiones", "Demasiadas peticiones: espera un poco",
                              {"Retry-After": str(int(espera) + 1)})
        return None

    @staticmethod
    def _comun(cuerpo: dict, campo: str, tope: int):
        """(keyId, blob, reto, token, entorno) de un cuerpo con la forma de la ruta, o la Respuesta 400."""
        esperados = {"clave", campo, "reto", "token", "entorno"}
        if set(cuerpo) != esperados or not all(isinstance(cuerpo[c], str) for c in esperados):
            return _error(400, "peticion_invalida", "Hacen falta clave, %s, reto, token y entorno" % campo)
        token, entorno, reto = cuerpo["token"], cuerpo["entorno"], cuerpo["reto"]
        if not PATRON_TOKEN.fullmatch(token) or entorno not in ENTORNOS or not _RETO.fullmatch(reto):
            return _error(400, "peticion_invalida", "El token, el entorno o el reto no tienen su forma")
        clave_texto, blob_texto = cuerpo["clave"], cuerpo[campo]
        if len(blob_texto) > tope * 4 // 3 + 4 or not _BASE64.fullmatch(clave_texto) \
                or not _BASE64.fullmatch(blob_texto):
            return _error(400, "peticion_invalida", "La clave o el %s no son base64" % campo)
        try:
            clave_id = base64.b64decode(clave_texto, validate=True)
            blob = base64.b64decode(blob_texto, validate=True)
        except (binascii.Error, ValueError):
            return _error(400, "peticion_invalida", "La clave o el %s no son base64" % campo)
        if len(clave_id) != 32:
            return _error(400, "peticion_invalida", "La clave no mide 32 bytes")
        return clave_id, blob, reto, token, entorno

    def _gastar_reto(self, reto: str) -> bool:
        with self._cerrojo:
            caduca = self._retos.pop(reto, None)
        return caduca is not None and self.reloj() < caduca

    def _permiso(self, token: str, entorno: str, clave_id: bytes, ahora: float) -> Respuesta:
        permiso, caduca, renovar = firmar(self.privada, token, entorno, clave_id, ahora)
        return Respuesta(200, {"permiso": permiso, "caduca": caduca, "renovar": renovar}, {"Cache-Control": "no-store"})
