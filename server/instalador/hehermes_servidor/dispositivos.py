"""Los iPhone conectados al servidor, desde la app (Ajustes › Tu servidor, contrato §12.10): la lista y quitar uno.

Hasta ahora un iPhone perdido solo se quitaba por SSH (`hehermes-dispositivo baja`). La pasarela contesta ella misma
`/hehermes/v1/dispositivos`, como las huellas y la recuperación, y solo con el token de un iPhone dado de alta.

**La pasarela no puede escribir `tokens.json`** (con root es de root y systemd le deja /etc de solo lectura), y está
bien que no pueda: si pudiera, una pasarela tomada podría **darse** tokens que sobrevivieran a una actualización. Así que
quitar es apuntarlo en su carpeta de estado (`QUITADOS`, 0600, al lado y renombrado): desde ese momento el token no vale
para la pasarela, aunque siga en `tokens.json`, y la pasarela corta lo que tuviera abierto. El instalador y
`hehermes-dispositivo`, que sí escriben `tokens.json`, lo leen y quitan de ahí lo que ya no vale (`tokens.purgar`).
Con esto la pasarela solo puede **quitar**, nunca dar.

Lo de cada token va por su hash (el de `tokens.json`), y nada de lo que sale hacia la app lleva un token ni un hash:
solo el nombre, cuándo se dio de alta, cuándo se usó por última vez (si se sabe) y cuál es el que pregunta.

Las altas de avisos del iPhone quitado se borran del vigía (`borrar_en_el_vigia`): la pasarela le dice qué tokens
siguen y el vigía borra las altas que no son de ninguno de ellos. Para saber de quién es cada alta, la pasarela le pasa
al vigía el iPhone de cada petición —su nombre y la marca de su token (`marca_del_token`)— con una firma hecha con el
secreto que ya comparten (`cabecera_del_iphone`): la app no la puede falsificar, ni a través de una pasarela de antes,
que deja pasar las cabeceras de la app. Es la única forma que tiene el vigía de saberlo, y la usa también el aviso del
código de recuperación (contrato §12.9): la marca distingue el token nuevo del iPhone que entra del de antes con el
mismo nombre, que puede ser otro aparato.

Solo la biblioteca estándar: lo importa la pasarela, que corre con el `python3` del sistema.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets

#: En la carpeta de estado de la pasarela: los tokens quitados desde la app, y la última vez que se usó cada uno.
QUITADOS = "quitados.json"
VISTOS = "vistos.json"
#: Lo más que se lee de cada uno.
TOPE = 1024 * 1024
RUTA = "/hehermes/v1/dispositivos"
PREFIJO = RUTA + "/"
#: Lo que confirma que se quita el último iPhone del servidor (`?ultimo=si`): sin él, `409 es_el_ultimo`.
CONFIRMA_EL_ULTIMO = "ultimo=si"
NOMBRE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
_HASH = re.compile(r"[0-9a-f]{64}")
#: La marca de un token (`marca_del_token`): 16 cifras hexadecimales.
MARCA = re.compile(r"[0-9a-f]{16}")
#: La última vez que se usó cada token se guarda como mucho cada tantos segundos (en memoria va al momento).
GUARDAR_VISTOS = 300
#: Lo que espera la pasarela al vigía al borrar unas altas; si no contesta, lo vuelve a probar cada `REINTENTO`.
PLAZO_VIGIA = 5
REINTENTO = 60
#: La ruta del vigía que borra las altas que no son de ningún iPhone que siga, y lo que va delante de lo que se firma.
RUTA_DEL_VIGIA = "/avisos/v1/iphones/barrer"
_FIRMA_IPHONE = b"hehermes-iphone/v1\x00"
_FIRMA_BARRIDO = b"hehermes-barrido/v1\x00"
_MARCA = b"hehermes-marca/v1\x00"
#: Las cabeceras que solo pone la pasarela (y quita de lo que manda la app).
CABECERA_IPHONE = "X-HeHermes-Iphone"
CABECERA_FIRMA = "X-HeHermes-Firma"

#: Lo que dice la pasarela con sus errores (`pasarela._MENSAJES`).
MENSAJES = {"dispositivo_desconocido": "Este servidor no tiene ningún iPhone con ese nombre",
            "es_el_ultimo": "Es el único iPhone conectado a este servidor: para quitarlo, confírmalo (?ultimo=si)",
            "dispositivos_no_disponible": "Esta pasarela no puede quitar iPhone",
            "metodo_no_permitido": "Esta ruta no admite ese método"}


# MARK: Las firmas para el vigía


def _mac(secreto: str, prefijo: bytes, datos: bytes) -> str:
    resumen = hmac.new(secreto.encode("utf-8"), prefijo + datos, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(resumen).rstrip(b"=").decode("ascii")


def marca_del_token(hash_hex: str) -> str:
    """Lo que distingue un token de otro ante el vigía sin ser ni el token ni su hash: las 16 primeras cifras de
    SHA-256(`"hehermes-marca/v1" 0x00 <el hash del token, en hex>`). Cambia con cada token: rotar, recuperar con el código
    o volver tras quitarlo dan otra marca aunque el nombre siga, y así las altas del token de antes no pasan por las del
    nuevo. La sacan igual la pasarela (del hash con el que entra cada petición) y el instalador (del token que da)."""
    return hashlib.sha256(_MARCA + hash_hex.encode("ascii")).hexdigest()[:16]


def cabecera_del_iphone(secreto: str, nombre: str, marca: str) -> str:
    """`<nombre> <marca> <firma>`: el iPhone de la petición que la pasarela pasa al vigía. La firma es HMAC-SHA256 con el
    secreto del vigía de `"hehermes-iphone/v1" 0x00 <nombre> 0x00 <marca>`; sin él no se puede hacer una que valga."""
    return "%s %s %s" % (nombre, marca, _mac(secreto, _FIRMA_IPHONE, ("%s\x00%s" % (nombre, marca)).encode("ascii")))


def firma_del_barrido(secreto: str, cuerpo: bytes) -> str:
    return _mac(secreto, _FIRMA_BARRIDO, cuerpo)


# MARK: Lo que hay en tokens.json


def _segundos(texto) -> int | None:
    """Los segundos de una fecha ISO 8601 de `tokens.json` (`alta`, `rotado`), o None."""
    if not isinstance(texto, str):
        return None
    try:
        fecha = datetime.datetime.fromisoformat(texto)
    except ValueError:
        return None
    if fecha.tzinfo is None:
        fecha = fecha.replace(tzinfo=datetime.timezone.utc)
    return int(fecha.timestamp())


def entradas_de(ruta: str) -> list | None:
    """`[{"nombre", "sha256", "alta"}]` de `tokens.json`, con `alta` en segundos: la de su token de ahora (si se rotó,
    cuándo). Lo que no tiene su forma no sale. None si falta o no se entiende: no es lo mismo que ninguno (con ninguno,
    el vigía borraría todas las altas de avisos)."""
    try:
        with open(ruta, "rb") as f:
            datos = json.loads(f.read(TOPE))
    except (OSError, ValueError):
        return None
    if not isinstance(datos, dict) or datos.get("v") != 1 or not isinstance(datos.get("tokens"), list):
        return None
    salida = []
    for t in datos["tokens"]:
        if isinstance(t, dict) and isinstance(t.get("nombre"), str) and _HASH.fullmatch(str(t.get("sha256"))):
            fechas = [s for s in (_segundos(t.get("alta")), _segundos(t.get("rotado"))) if s is not None]
            salida.append({"nombre": t["nombre"], "sha256": t["sha256"], "alta": max(fechas) if fechas else None})
    return salida


def lista(entradas: list, validos: set, usos: dict | None, vistos: dict, yo: str | None) -> list:
    """Lo que se le enseña a la app: los iPhone cuyo token vale, con su nombre, su alta, su último uso si se sabe (lo
    que se ha visto y, si no, el primero de `usos.json`) y si es el que pregunta (`yo`, el hash de su token). **Ni un
    token ni un hash.**"""
    primeros = (usos or {}).get("tokens", {})
    salida = []
    for e in entradas:
        if e["sha256"] not in validos:
            continue
        candidatos = [vistos.get(e["sha256"]), (primeros.get(e["sha256"]) or {}).get("primero")]
        conocidos = [c for c in candidatos if isinstance(c, int) and not isinstance(c, bool)]
        salida.append({"nombre": e["nombre"], "alta": e["alta"], "uso": max(conocidos) if conocidos else None,
                       "este": e["sha256"] == yo})
    return salida


# MARK: Los quitados


def leer_quitados(datos) -> dict | None:
    """`{"v": 1, "tokens": {<sha256>: {"nombre", "cuando"}}, "barrer": bool}`; vacío si no hay nada, y None si hay algo
    que no se entiende. Uno que no se entiende **no** es uno vacío: si lo fuera, un token quitado volvería a valer."""
    if datos is None:
        return {"v": 1, "tokens": {}, "barrer": False}
    try:
        bruto = json.loads(datos)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(bruto, dict) or bruto.get("v") != 1 or not isinstance(bruto.get("tokens"), dict):
        return None
    tokens = {}
    for hash_hex, entrada in bruto["tokens"].items():
        if not isinstance(hash_hex, str) or not _HASH.fullmatch(hash_hex):
            return None
        entrada = entrada if isinstance(entrada, dict) else {}
        nombre, cuando = entrada.get("nombre"), entrada.get("cuando")
        tokens[hash_hex] = {"nombre": nombre if isinstance(nombre, str) else None,
                            "cuando": cuando if isinstance(cuando, int) and not isinstance(cuando, bool) else None}
    return {"v": 1, "tokens": tokens, "barrer": bruto.get("barrer") is True}


def _abrir(ruta):
    try:
        fd = os.open(ruta, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError:
        return b"no se puede leer"
    with os.fdopen(fd, "rb") as f:
        return f.read(TOPE + 1)


def hashes_quitados(carpeta: str) -> set | None:
    """Los hashes quitados desde la app, para el instalador y `hehermes-dispositivo`; None si el registro no se
    entiende (quien escribe `tokens.json` no debe hacer como si no hubiera nada)."""
    datos = leer_quitados(_abrir(os.path.join(carpeta, QUITADOS)))
    return None if datos is None else set(datos["tokens"])


class Quitados:
    """`QUITADOS` en la carpeta de estado de la pasarela. Solo lo escribe ella, con el cerrojo de la carpeta (el mismo
    `flock` que el del código de recuperación), al lado y renombrado, sin seguir enlaces y 0600."""

    def __init__(self, carpeta: str):
        self.carpeta = carpeta
        self.ruta = os.path.join(carpeta, QUITADOS)

    def leer(self) -> dict | None:
        return leer_quitados(_abrir(self.ruta))

    @contextlib.contextmanager
    def _cerrojo(self):
        import fcntl
        fd = os.open(self.carpeta, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def quitar(self, hash_hex: str, nombre: str, ahora: float) -> dict:
        """Apunta que ese token ya no vale y que hay que barrer el vigía. Lanza OSError si no puede, o ValueError si el
        registro no se entiende: entonces no se quita nada (lo que no queda escrito volvería a valer al reiniciarse)."""
        with self._cerrojo():
            datos = self.leer()
            if datos is None:
                raise ValueError("no entiendo %s: no lo toco" % self.ruta)
            datos["tokens"][hash_hex] = {"nombre": nombre, "cuando": int(ahora)}
            datos["barrer"] = True
            self._escribir(datos)
            return datos

    def barrido(self, pendiente: bool) -> None:
        """Si queda por borrar alguna alta del vigía (no contestó): la pasarela lo vuelve a probar."""
        with self._cerrojo():
            datos = self.leer()
            if datos is None or datos["barrer"] == pendiente:
                return
            datos["barrer"] = pendiente
            self._escribir(datos)

    def _escribir(self, datos):
        temporal = os.path.join(self.carpeta, ".%s.%d.%s" % (QUITADOS, os.getpid(), secrets.token_hex(4)))
        fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(datos, separators=(",", ":"), sort_keys=True).encode("utf-8"))
            os.replace(temporal, self.ruta)
        except BaseException:
            if os.path.exists(temporal):
                os.unlink(temporal)
            raise


# MARK: La última vez que se usó cada uno


class Vistos:
    """La última vez que se usó cada token (por su hash), en memoria al momento y en `VISTOS` como mucho cada
    `GUARDAR_VISTOS`: escribir en cada petición sería gastar el disco. Lo que no llegó a guardarse antes de reiniciar se
    pierde; por eso la lista dice «si se sabe»."""

    def __init__(self, carpeta: str):
        self.ruta = os.path.join(carpeta, VISTOS)
        self._vistos = {}
        datos = _abrir(self.ruta)
        try:
            bruto = json.loads(datos) if datos else {}
        except (ValueError, UnicodeDecodeError):
            bruto = {}
        for hash_hex, cuando in (bruto.get("tokens") or {}).items() if isinstance(bruto, dict) else ():
            if isinstance(hash_hex, str) and _HASH.fullmatch(hash_hex) and isinstance(cuando, int) \
                    and not isinstance(cuando, bool):
                self._vistos[hash_hex] = cuando
        self._cambiado = False
        self._guardado = None

    @property
    def vistos(self) -> dict:
        return self._vistos

    def apuntar(self, hash_hex: str, ahora: float) -> None:
        if self._vistos.get(hash_hex) != int(ahora):
            self._vistos[hash_hex] = int(ahora)
            self._cambiado = True

    def olvidar(self, hash_hex: str) -> None:
        if self._vistos.pop(hash_hex, None) is not None:
            self._cambiado = True

    def guardar_si_toca(self, ahora: float, siempre: bool = False) -> bool:
        if not self._cambiado or (not siempre and self._guardado is not None and ahora - self._guardado < GUARDAR_VISTOS):
            return False
        carpeta = os.path.dirname(self.ruta)
        temporal = os.path.join(carpeta, ".%s.%d.%s" % (VISTOS, os.getpid(), secrets.token_hex(4)))
        fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps({"v": 1, "tokens": self._vistos}, separators=(",", ":"), sort_keys=True)
                        .encode("ascii"))
            os.replace(temporal, self.ruta)
        except BaseException:
            if os.path.exists(temporal):
                os.unlink(temporal)
            raise
        self._cambiado, self._guardado = False, ahora
        return True
