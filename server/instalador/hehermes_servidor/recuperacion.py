"""El código de recuperación (spec 2026-10-06): volver a conectar por chat sin abrirle el chat a nadie más.

El código vive en el llavero de iCloud de la persona y **no sale nunca del iPhone**. El servidor guarda solo su clave
pública (Ed25519), en la carpeta de estado de la pasarela (`ESTADO`), y la frase lleva una firma hecha con él y atada a
esa frase (el nombre del iPhone, la llave del canje y la hora: `mensaje`). Quien lea el chat se lleva una firma que no
vale para ninguna otra llave; quien lea el servidor, una clave pública con la que no se firma nada.

Lo pone la app con el token de su iPhone (`PUT /hehermes/v1/recuperacion`, en la pasarela: la primera vez, o el iPhone
que acaba de volver a conectar con él, que así lo cambia por otro) y lo mira el instalador cuando la decisión 7 cierra
el chat (`porchat.comprobar_recuperacion`).

Solo la biblioteca estándar, porque la pasarela lo importa y corre con el `python3` del sistema. Lo único que necesita
`cryptography` es comprobar la firma (`verificar_firma`): el instalador lo lanza con el Python del venv del canje
(`python -m hehermes_servidor.recuperacion verificar`).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import errno
import hashlib
import hmac
import json
import os
import re
import secrets

#: En la carpeta de estado de la pasarela, junto a `usos.json`: la pasarela lo escribe al poner un código, y el
#: instalador, al usarlo.
ESTADO = "recuperacion.json"
#: Lo más que se lee de él.
TOPE = 64 * 1024
#: Lo que va delante de lo que se firma, y la sal de la clave: una firma o una clave de otra cosa no valen aquí.
PREFIJO = b"hehermes-recuperacion/v1"
#: La prueba que lleva la frase (`--recuperacion`): la versión, la hora (segundos) y la firma (64 bytes, base64url).
_PRUEBA = re.compile(r"1\.([0-9]{1,12})\.([A-Za-z0-9_-]{86})")
_NOMBRE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
#: La marca de un token (`dispositivos.MARCA`), en lo que se deja en el buzón del vigía.
_MARCA = re.compile(r"[0-9a-f]{16}")
#: La hora de la prueba: de hace 40 minutos como mucho (la llave de la frase vive 30 en el iPhone, y Hermes tarda en
#: lanzarla) y no más de 10 por delante (un reloj que adelanta).
ANTES = 40 * 60
DESPUES = 10 * 60
#: Tras el primer, segundo, tercer y cuarto fallo seguidos, lo que no se mira nada, y a partir del quinto, el último: lo
#: que llega mientras ni se comprueba ni cuenta. Un fallo de hace más de `OLVIDO` ya no cuenta (y con él empieza otra
#: racha). **No hay cierre** (Daniel, 2026-10-06): el código no se puede adivinar (130 bits y una firma Ed25519), así que
#: cerrar la recuperación un día tras cinco fallos no protegía de nada y le dejaba a quien engañe a un Hermes dejar a la
#: persona sin ella. Las esperas sí se quedan: frenan a quien la repite sin parar.
ESPERAS = (60, 120, 240, 480)
OLVIDO = 24 * 3600
#: El buzón del vigía (con los avisos posteriores a la 1.6.2): una carpeta dentro de la suya de estado (`ambito.carpeta_estado_vigia`)
#: donde se deja lo que hay que avisar a los iPhone del servidor (`dejar_en_el_buzon`). La crea el vigía al arrancar, de
#: su usuario y 0700: sin ella (un vigía de antes, o sin avisos), no se avisa. Solo pueden escribir en ella root y el
#: usuario del vigía (sin root, el de Hermes, que ya podía avisar con su base de datos): no abre ninguna puerta.
BUZON = "buzon"
#: Lo más que se deja en el buzón sin que el vigía lo recoja: uno parado no llena el disco.
TOPE_BUZON = 50

#: El alfabeto del código (el de Crockford: sin I, L, O ni U) y su forma: 26 al azar y 2 de control, en grupos de 4.
ALFABETO = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
AL_AZAR = 26
LARGO = 28


# MARK: El código (lo crea la app; aquí, para los vectores y el cliente de las pruebas)


def control(simbolos: str) -> str:
    """Los dos símbolos de control: los 10 primeros bits del SHA-256 de los 26 de delante. Un código mal copiado se nota
    en el iPhone, antes de gastar un intento en el servidor."""
    resumen = hashlib.sha256(PREFIJO + b"/control\x00" + simbolos.encode("ascii")).digest()
    bits = (resumen[0] << 2) | (resumen[1] >> 6)
    return ALFABETO[bits >> 5] + ALFABETO[bits & 31]


def normalizar(texto: str) -> str | None:
    """Los 28 símbolos de un código escrito como sea (minúsculas, espacios, guiones; O, I y L por 0, 1 y 1), o None si
    no es uno o no cuadra su control."""
    if not isinstance(texto, str):
        return None
    limpio = "".join(c for c in texto.upper() if c not in " -\t\n")
    limpio = limpio.translate(str.maketrans("OIL", "011"))
    if len(limpio) != LARGO or any(c not in ALFABETO for c in limpio):
        return None
    return limpio if control(limpio[:AL_AZAR]) == limpio[AL_AZAR:] else None


def codigo_nuevo() -> str:
    cuerpo = "".join(secrets.choice(ALFABETO) for _ in range(AL_AZAR))
    return cuerpo + control(cuerpo)


def semilla(codigo: str) -> bytes:
    """HKDF-SHA256 (RFC 5869) de los 28 símbolos, con la sal `PREFIJO` e info «ed25519»: la semilla de su clave."""
    extraida = hmac.new(PREFIJO, codigo.encode("ascii"), hashlib.sha256).digest()
    return hmac.new(extraida, b"ed25519\x01", hashlib.sha256).digest()


# MARK: Lo que se firma


def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode("ascii")


def de_b64url(texto, bytes_: int) -> bytes | None:
    """Base64url sin relleno de exactamente `bytes_` bytes, y sin nada que el descodificador se tragara (se vuelve a
    codificar y tiene que dar lo mismo); si no, None."""
    if not isinstance(texto, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", texto):
        return None
    try:
        datos = base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))
    except (binascii.Error, ValueError):
        return None
    return datos if len(datos) == bytes_ and b64url(datos) == texto else None


def mensaje(iphone: str, llave: bytes, momento: int) -> bytes:
    """Lo que firma la app: el nombre del iPhone de la frase, su llave (la pública X25519 del canje) y la hora. Con otra
    llave, otro nombre u otra hora, la firma no vale. El nombre acaba en un cero y lo demás es de largo fijo: no hay dos
    formas de leer los mismos bytes."""
    if not isinstance(iphone, str) or not _NOMBRE.fullmatch(iphone):
        raise ValueError("el nombre del iPhone no vale")
    if len(llave) != 32 or not 0 <= momento < 2 ** 63:
        raise ValueError("una llave que no mide 32 bytes, o una hora que no vale")
    return PREFIJO + b"\x00" + iphone.encode("ascii") + b"\x00" + llave + momento.to_bytes(8, "big")


def leer_prueba(texto) -> tuple | None:
    """(la hora, la firma) de `--recuperacion`, o None si no tiene la forma de una prueba de la app."""
    if not isinstance(texto, str):
        return None
    hallado = _PRUEBA.fullmatch(texto)
    if not hallado:
        return None
    firma = de_b64url(hallado.group(2), 64)
    return (int(hallado.group(1)), firma) if firma is not None else None


def a_tiempo(momento: int, ahora: float) -> bool:
    return ahora - ANTES <= momento <= ahora + DESPUES


def verificar_firma(clave: str, datos: bytes, firma: bytes) -> bool:
    """Si `firma` es de la clave pública `clave` (base64url) sobre `datos`. Necesita `cryptography`: corre con el venv
    del canje."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    crudo = de_b64url(clave, 32)
    if crudo is None or len(firma) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(crudo).verify(firma, datos)
    except (InvalidSignature, ValueError):
        return False
    return True


# MARK: El estado


def vacio() -> dict:
    return {"v": 1, "clave": None, "creada": None, "por": None, "en_curso": None, "ultima": None, "fallos": 0,
            "ultimo_fallo": None}


def _entero(valor):
    return valor if isinstance(valor, int) and not isinstance(valor, bool) and valor >= 0 else None


def _quien_y_cuando(valor, cuando):
    if isinstance(valor, dict) and isinstance(valor.get("iphone"), str) and _NOMBRE.fullmatch(valor["iphone"]) \
            and _entero(valor.get(cuando)) is not None:
        return {"iphone": valor["iphone"], cuando: valor[cuando]}
    return None


def leer_estado(datos) -> dict | None:
    """Lo que hay, con su forma; `vacio()` si no hay nada, y None si hay algo que no se entiende. Uno que no se entiende
    **no** es uno vacío: si lo fuera, cualquier token podría poner su código en un servidor que ya tiene uno."""
    if datos is None:
        return vacio()
    try:
        bruto = json.loads(datos)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(bruto, dict) or bruto.get("v") != 1:
        return None
    estado = vacio()
    clave = bruto.get("clave")
    if clave is not None and de_b64url(clave, 32) is None:
        return None
    estado["clave"] = clave
    estado["creada"] = _entero(bruto.get("creada"))
    por = bruto.get("por")
    estado["por"] = por if isinstance(por, str) and _NOMBRE.fullmatch(por) else None
    estado["en_curso"] = _quien_y_cuando(bruto.get("en_curso"), "desde")
    estado["ultima"] = _quien_y_cuando(bruto.get("ultima"), "cuando")
    estado["fallos"] = _entero(bruto.get("fallos")) or 0
    estado["ultimo_fallo"] = _entero(bruto.get("ultimo_fallo"))
    return estado


def fallos_vigentes(estado: dict, ahora: float) -> int:
    ultimo = estado.get("ultimo_fallo")
    if not estado.get("fallos") or ultimo is None or ahora - ultimo >= OLVIDO:
        return 0
    return estado["fallos"]


def espera_hasta(estado: dict, ahora: float) -> int | None:
    """Hasta cuándo no se mira ninguna prueba (ni la buena) tras el último fallo, o None si se puede probar ya. Son
    minutos (`ESPERAS`), nunca más: no hay cierre."""
    fallos = fallos_vigentes(estado, ahora)
    if not fallos:
        return None
    hasta = estado["ultimo_fallo"] + ESPERAS[min(fallos, len(ESPERAS)) - 1]
    return hasta if ahora < hasta else None


def con_fallo(estado: dict, ahora: float) -> dict:
    nuevo = dict(estado)
    nuevo["fallos"] = fallos_vigentes(estado, ahora) + 1
    nuevo["ultimo_fallo"] = int(ahora)
    return nuevo


def empieza_racha(estado: dict, ahora: float) -> bool:
    """Si un fallo ahora sería el primero de una racha (ninguno vigente antes): es el que se avisa a los iPhone, y los
    demás de la racha no, para no llenarlos de avisos."""
    return fallos_vigentes(estado, ahora) == 0


def con_exito(estado: dict, iphone: str, ahora: float) -> dict:
    """Ha entrado `iphone` con el código: queda en curso (hasta que ponga otro) y es la última recuperación (la que la
    app de los demás iPhone avisa). Los fallos se olvidan."""
    nuevo = dict(estado)
    nuevo["en_curso"] = {"iphone": iphone, "desde": int(ahora)}
    nuevo["ultima"] = {"iphone": iphone, "cuando": int(ahora)}
    nuevo["fallos"], nuevo["ultimo_fallo"] = 0, None
    return nuevo


def gastado(estado: dict, usos) -> bool:
    """Si el iPhone de la recuperación en curso ya ha usado la pasarela desde entonces (`usos.json`, el de la decisión
    7): el código con el que entró ya no vale, y le toca a él poner otro."""
    en_curso = estado.get("en_curso")
    if not en_curso or not usos:
        return False
    return any(e.get("nombre") == en_curso["iphone"] and e.get("primero", -1) >= en_curso["desde"]
               for e in usos.get("tokens", {}).values())


def puede_poner(estado: dict, nombre: str | None) -> bool:
    """Quién puede poner un código: cualquiera con un token si el servidor no tiene ninguno (la app lo pone al
    conectar), y si no, solo el iPhone que acaba de volver a conectar con el de ahora (así lo cambia por otro). Otro token
    no le puede cambiar el código a la persona."""
    if not nombre:
        return False
    return estado["clave"] is None or (estado.get("en_curso") or {}).get("iphone") == nombre


def con_clave(estado: dict, clave: str, nombre: str, ahora: float) -> dict:
    nuevo = dict(estado)
    nuevo.update({"clave": clave, "creada": int(ahora), "por": nombre, "en_curso": None})
    return nuevo


def publico(estado: dict | None, yo: str | None = None, ahora: float | None = None) -> dict:
    """Lo que se le enseña a la app (`GET /hehermes/v1/recuperacion`): nada de ahí es secreto."""
    if estado is None:
        return {"ilegible": True, "yo": yo}
    import time
    ahora = time.time() if ahora is None else ahora
    salida = {k: estado[k] for k in ("clave", "creada", "por", "en_curso", "ultima")}
    salida["fallos"] = fallos_vigentes(estado, ahora)
    salida["yo"] = yo
    return salida


# MARK: El fichero


class Registro:
    """`ESTADO` en la carpeta de estado de la pasarela. Lo escriben la pasarela (al poner un código) y el instalador (al
    usarlo), así que todo cambio va con el cerrojo de la carpeta (`flock`), se escribe al lado y se renombra, sin seguir
    enlaces, 0600 y del dueño de la carpeta: con root, el instalador escribe en la de `hh-pasarela`, que tiene que poder
    leerlo."""

    def __init__(self, carpeta: str):
        self.carpeta = carpeta
        self.ruta = os.path.join(carpeta, ESTADO)

    def _crudo(self):
        try:
            fd = os.open(self.ruta, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            return None
        except OSError:
            return b"no se puede leer"
        with os.fdopen(fd, "rb") as f:
            return f.read(TOPE)

    def leer(self) -> dict | None:
        return leer_estado(self._crudo())

    @contextlib.contextmanager
    def _cerrojo(self):
        import fcntl
        fd = os.open(self.carpeta, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def cambiar(self, cambio):
        """`cambio(estado)` con el cerrojo puesto: devuelve el estado nuevo (que se escribe) o None (nada que escribir).
        Devuelve lo que queda, o None si lo que había no se entiende y el cambio no ha escrito nada."""
        with self._cerrojo():
            estado = self.leer()
            nuevo = cambio(estado)
            if nuevo is None:
                return estado
            self._escribir(nuevo)
            return nuevo

    def quitar(self) -> bool:
        with self._cerrojo():
            try:
                os.unlink(self.ruta)
            except FileNotFoundError:
                return False
            return True

    def _escribir(self, estado):
        dueno = os.stat(self.carpeta)
        temporal = os.path.join(self.carpeta, ".%s.%d.%s" % (ESTADO, os.getpid(), secrets.token_hex(4)))
        fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if (dueno.st_uid, dueno.st_gid) != (os.geteuid(), os.getegid()) and os.geteuid() == 0:
                os.fchown(fd, dueno.st_uid, dueno.st_gid)
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(estado, separators=(",", ":"), sort_keys=True).encode("ascii"))
            os.replace(temporal, self.ruta)
        except BaseException:
            if os.path.exists(temporal):
                os.unlink(temporal)
            raise


# MARK: El aviso a los demás iPhone (el buzón del vigía)


def suceso(que: str, ahora: float, iphone: str | None = None, marca: str | None = None,
           anterior: str | None = None) -> dict:
    """Lo que se le deja al vigía: `entrada` (ha entrado `iphone` con el código) o `intentos` (el primer fallo de una
    racha). En `entrada`, `marca` es la de su token nuevo (`dispositivos.marca_del_token`): a las altas de avisos de ese
    token no se les avisa, porque solo las puede haber hecho el que entra; y `anterior`, la del token que deja de valer
    si ya estaba con ese nombre: esas altas sí lo reciben (pueden ser de otro aparato con el mismo nombre) y después el
    vigía las borra. Nada secreto: el nombre, la hora y dos marcas que no son ni los tokens ni sus hashes."""
    if que not in ("entrada", "intentos") or (que == "entrada") != (iphone is not None) \
            or (que == "entrada") != (marca is not None) or (anterior is not None and que != "entrada"):
        raise ValueError("un suceso que no es de la recuperación")
    if iphone is not None and not _NOMBRE.fullmatch(iphone):
        raise ValueError("el nombre del iPhone no vale")
    if any(m is not None and not _MARCA.fullmatch(m) for m in (marca, anterior)) or (anterior and anterior == marca):
        raise ValueError("la marca del token no vale")
    datos = {"v": 1, "tipo": "recuperacion", "que": que, "cuando": int(ahora)}
    if iphone is not None:
        datos["iphone"] = iphone
        datos["marca"] = marca
    if anterior is not None:
        datos["marca_anterior"] = anterior
    return datos


def dejar_en_el_buzon(carpeta: str, datos: dict) -> bool:
    """Deja `datos` en el buzón del vigía (`BUZON`, ya con su ruta en `carpeta`) para que avise a los iPhone dados de
    alta. False sin buzón (el vigía no lo entiende o no está, o es un enlace) o lleno; lo demás, un `OSError` que quien
    llama dice y que no para nada. Un fichero por suceso, escrito al lado y renombrado (el vigía no ve uno a medias), sin
    seguir enlaces, 0600 y del dueño de la carpeta, como el registro: con root, el vigía (`hh-vigia`) tiene que poder
    leerlo y borrarlo."""
    try:
        fd_carpeta = os.open(carpeta, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        if error.errno == errno.ELOOP:
            return False
        raise
    try:
        if sum(1 for _ in os.scandir(fd_carpeta)) >= TOPE_BUZON:
            return False
        dueno = os.fstat(fd_carpeta)
        nombre = "recuperacion-%d-%s.json" % (datos["cuando"], secrets.token_hex(4))
        temporal = "." + nombre
        fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
                     dir_fd=fd_carpeta)
        try:
            if (dueno.st_uid, dueno.st_gid) != (os.geteuid(), os.getegid()) and os.geteuid() == 0:
                os.fchown(fd, dueno.st_uid, dueno.st_gid)
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(datos, separators=(",", ":"), sort_keys=True).encode("ascii"))
            os.replace(temporal, nombre, src_dir_fd=fd_carpeta, dst_dir_fd=fd_carpeta)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporal, dir_fd=fd_carpeta)
            raise
        return True
    finally:
        os.close(fd_carpeta)


# MARK: La orden (con el venv del canje)


def main(argv, entrada=None, salida=print) -> int:
    """`verificar`: lee `{"clave", "mensaje", "firma"}` (las dos últimas en base64) de la entrada y dice «buena» (0) o
    «mala» (1). Lo que no se entiende, 2."""
    import sys
    if argv != ["verificar"]:
        salida("uso: python -m hehermes_servidor.recuperacion verificar < {clave, mensaje, firma}")
        return 2
    try:
        datos = json.loads((entrada if entrada is not None else sys.stdin.read())[:TOPE])
        texto = base64.b64decode(str(datos["mensaje"]), validate=True)
        firma = base64.b64decode(str(datos["firma"]), validate=True)
        clave = datos["clave"]
    except (ValueError, KeyError, TypeError, binascii.Error):
        salida("no entiendo lo que me das")
        return 2
    if verificar_firma(clave, texto, firma):
        salida("buena")
        return 0
    salida("mala")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
