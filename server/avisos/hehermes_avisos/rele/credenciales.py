"""Las credenciales de los vigías ante el relé: una por servidor, emitida a mano, guardada como huella.

El relé nunca guarda el secreto, solo su SHA-256. No hace falta un hash lento (scrypt, argon2) porque el secreto no lo
elige una persona: son 32 bytes al azar, y su huella no se puede recorrer a fuerza bruta. Si ``credenciales.ini`` se
filtra, no sirve para mandar ningún aviso.

Hay dos formas de emitirlas:

- ``asegurar``: la del vigía de la propia máquina del relé, que escribe el secreto en un fichero del vigía. Es lo que
  ejecuta ``despliegue/instalar.sh``, y se puede repetir.
- ``alta``/``baja``: las de los vigías de otros servidores (``hehermes-rele credencial alta <nombre>``), que llegan por
  la entrada pública del relé (``publico``). El secreto no se guarda en ningún sitio: sale una vez, dentro del «código de
  avisos», y el relé se queda con su huella.

El relé y su entrada pública vuelven a leer el fichero en cuanto cambia (``Almacen``): un alta vale al momento, y una
baja también, sin reiniciar nada.

El camino para miles (documentado en el README, no construido) cambia esto por permisos de avisos por dispositivo,
avalados con App Attest: entonces un vigía solo puede pedir avisos para los iPhone que se los han dado.
"""

from __future__ import annotations

import base64
import configparser
import datetime
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
from dataclasses import dataclass

from ..comun import ErrorDeSecreto, escribir_privado, leer_secreto

registro = logging.getLogger("rele.credenciales")

# Un prefijo reconocible: si una credencial acaba donde no debe (un log, un repositorio), un escáner de secretos la
# encuentra por él, y quien la ve sabe qué es.
PREFIJO = "hhr1."
#: Lo que da `nueva`: el prefijo y 32 bytes en base64url sin relleno (43 caracteres).
FORMA = re.compile(r"hhr1\.[A-Za-z0-9_-]{43}")
#: El nombre de una credencial: el del servidor del vigía. Va de sección en el INI y en el registro, así que nada raro.
NOMBRE_VALIDO = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")


@dataclass(frozen=True)
class Credencial:
    nombre: str
    huella: str
    # Tope propio de avisos por minuto, si esta credencial no usa el general.
    por_minuto: int | None = None


def nueva() -> str:
    return PREFIJO + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def huella(secreto: str) -> str:
    return "sha256:" + hashlib.sha256(secreto.encode("utf-8")).hexdigest()


def leer(ruta: str) -> dict:
    """Las credenciales de ``credenciales.ini``, por huella: ``{huella: Credencial}``."""
    ini = _leer_ini(ruta)
    credenciales = {}
    for nombre in ini.sections():
        valor = ini.get(nombre, "hash", fallback="").strip().lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", valor):
            raise ValueError(f"la credencial «{nombre}» no tiene un «hash = sha256:…» válido")
        por_minuto = ini.get(nombre, "por_minuto", fallback="").strip()
        if por_minuto and (not por_minuto.isdigit() or int(por_minuto) < 1):
            raise ValueError(f"la credencial «{nombre}» tiene un por_minuto que no es un número positivo")
        credenciales[valor] = Credencial(nombre, valor, int(por_minuto) if por_minuto else None)
    return credenciales


def buscar(credenciales: dict, secreto: str) -> Credencial | None:
    """La credencial de este secreto, o ``None``. La comparación final es de tiempo constante por costumbre: lo que se
    compara son huellas, que no dicen nada del secreto, pero no cuesta nada."""
    candidata = credenciales.get(huella(secreto))
    if candidata is None or not hmac.compare_digest(candidata.huella, huella(secreto)):
        return None
    return candidata


def _firma(ruta: str):
    try:
        datos = os.stat(ruta)
    except OSError:
        return None
    return (datos.st_ino, datos.st_mtime_ns, datos.st_size)


class Almacen:
    """``credenciales.ini``, vuelto a leer en cuanto cambia. Lo usan el relé (``AppRele``) y su entrada pública.

    Un fichero que desaparece o que no se entiende **no deja pasar a nadie** (cerrado, no con lo de antes): una baja
    hecha a mano que dejara el fichero roto no puede dejar viva la credencial que se quería quitar. Se dice en el
    registro, una vez por cada cambio.
    """

    def __init__(self, ruta: str):
        self.ruta = ruta
        self._cerrojo = threading.Lock()
        self._firma = None
        self._todas: dict = {}
        self.recargar_si_cambia()

    def recargar_si_cambia(self) -> bool:
        firma = _firma(self.ruta)
        with self._cerrojo:
            if firma == self._firma and firma is not None:
                return False
            self._firma = firma
            try:
                self._todas = leer(self.ruta)
            except (OSError, ValueError, configparser.Error) as error:
                self._todas = {}
                registro.error("no se pueden leer las credenciales (%s): ninguna vale hasta que se arregle", error)
            return True

    def todas(self) -> dict:
        self.recargar_si_cambia()
        return dict(self._todas)

    def __len__(self) -> int:
        return len(self._todas)

    def buscar(self, secreto: str) -> Credencial | None:
        """La credencial de este secreto (con el fichero al día), o ``None``."""
        self.recargar_si_cambia()
        if not isinstance(secreto, str) or not FORMA.fullmatch(secreto):
            return None
        return _contra_todas(self._todas, huella(secreto))

    # Lo que pide la maquinaria de la pasarela (``hehermes_servidor.pasarela.Pasarela``) a sus «tokens».

    def quien(self, secreto) -> str | None:
        credencial = self.buscar(secreto) if isinstance(secreto, str) else None
        return credencial.nombre if credencial else None

    def sigue(self, hash_hex: str) -> bool:
        """Si la credencial de este SHA-256 (en hexadecimal, sin prefijo) sigue dada de alta: lo que mira cada conexión
        abierta tras una recarga."""
        return _contra_todas(self._todas, "sha256:" + hash_hex) is not None


def _contra_todas(todas: dict, buscada: str) -> Credencial | None:
    """Contra todas las huellas y sin salir en la que coincide: el tiempo no dice ni cuál es ni si hay alguna parecida."""
    hallada = None
    for guardada, credencial in todas.items():
        if hmac.compare_digest(guardada.encode("ascii"), buscada.encode("ascii")):
            hallada = credencial
    return hallada


# ---------------------------------------------------------------------------------------------------------------------
# Escribir


def _leer_ini(ruta: str) -> configparser.ConfigParser:
    ini = configparser.ConfigParser(interpolation=None)
    with open(ruta, encoding="utf-8") as fichero:
        ini.read_file(fichero)
    return ini


def _escribir(ruta: str, ini: configparser.ConfigParser) -> None:
    """Todo el fichero, de una vez (un rename), con el mismo modo, dueño y grupo que tenía: es ``root:hh-rele 0640``, y
    uno nuevo de ``root:root`` dejaría al relé sin poder leerlo."""
    lineas = ["# Credenciales de los vigías ante el relé: una sección por servidor, con la huella de su secreto.\n",
              "# Las escriben instalar.sh y `hehermes-rele credencial alta|baja`. Los secretos no están aquí.\n\n"]
    for seccion in ini.sections():
        lineas.append(f"[{seccion}]\n")
        lineas.extend(f"{clave} = {valor}\n" for clave, valor in ini.items(seccion))
        lineas.append("\n")
    antes = os.stat(ruta) if os.path.exists(ruta) else None
    escribir_privado(ruta, "".join(lineas).encode("utf-8"))
    if antes is not None:
        os.chmod(ruta, antes.st_mode & 0o777)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(ruta, antes.st_uid, antes.st_gid)


def _nombre(nombre: str) -> str:
    if not isinstance(nombre, str) or not NOMBRE_VALIDO.fullmatch(nombre):
        raise ValueError(f"el nombre de una credencial es de minúsculas, números y guiones, hasta 31 (no «{nombre}»)")
    return nombre


def asegurar(ruta_credenciales: str, nombre: str, ruta_secreto: str) -> bool:
    """Deja el secreto de ``nombre`` en ``ruta_secreto`` (0600) y su huella en ``ruta_credenciales``.

    Se puede repetir: si el secreto ya existe se usa ese, y si la huella ya estaba no se toca nada. Devuelve si ha
    creado un secreto nuevo. Es lo que ejecuta el instalador; para rotar una credencial, se borra el fichero del secreto
    y se vuelve a ejecutar.
    """
    creado = False
    if not os.path.exists(ruta_secreto):
        escribir_privado(ruta_secreto, (nueva() + "\n").encode("ascii"))
        creado = True
    try:
        secreto = leer_secreto(ruta_secreto).decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ErrorDeSecreto(f"{ruta_secreto} no es texto") from None
    ini = _leer_ini(ruta_credenciales) if os.path.exists(ruta_credenciales) else configparser.ConfigParser(
        interpolation=None)
    valor = huella(secreto)
    if ini.has_section(nombre) and ini.get(nombre, "hash", fallback="") == valor:
        return creado
    if not ini.has_section(nombre):
        ini.add_section(nombre)
    ini.set(nombre, "hash", valor)
    ini.set(nombre, "alta", datetime.date.today().isoformat())
    _escribir(ruta_credenciales, ini)
    return creado


def alta(ruta_credenciales: str, nombre: str, por_minuto: int | None = None, hoy: str | None = None) -> str:
    """Una credencial nueva para el vigía de otro servidor. Devuelve el secreto, que no se guarda en ningún sitio: quien
    llama lo mete en el código de avisos y lo olvida. Un nombre que ya existe no se pisa (su vigía dejaría de poder
    avisar sin que nadie lo supiera): para otro secreto, ``baja`` y ``alta``."""
    _nombre(nombre)
    if por_minuto is not None and (not isinstance(por_minuto, int) or por_minuto < 1):
        raise ValueError("por_minuto tiene que ser un número positivo")
    ini = _leer_ini(ruta_credenciales) if os.path.exists(ruta_credenciales) else configparser.ConfigParser(
        interpolation=None)
    if ini.has_section(nombre):
        raise ValueError(f"ya hay una credencial «{nombre}». Para darle otra: baja {nombre} y alta {nombre} (el código "
                         "de antes deja de valer)")
    secreto = nueva()
    ini.add_section(nombre)
    ini.set(nombre, "hash", huella(secreto))
    ini.set(nombre, "alta", hoy or datetime.date.today().isoformat())
    if por_minuto is not None:
        ini.set(nombre, "por_minuto", str(por_minuto))
    _escribir(ruta_credenciales, ini)
    return secreto


def baja(ruta_credenciales: str, nombre: str) -> bool:
    """Quita la credencial ``nombre``. Devuelve si estaba. Vale al momento: el relé y su entrada pública vuelven a leer
    el fichero, y la entrada corta las conexiones abiertas con ella."""
    _nombre(nombre)
    if not os.path.exists(ruta_credenciales):
        return False
    ini = _leer_ini(ruta_credenciales)
    if not ini.has_section(nombre):
        return False
    ini.remove_section(nombre)
    _escribir(ruta_credenciales, ini)
    return True


def lista(ruta_credenciales: str) -> list:
    """Las credenciales, sin sus huellas: ``[{"nombre", "alta", "por_minuto"}]``, por nombre."""
    if not os.path.exists(ruta_credenciales):
        return []
    ini = _leer_ini(ruta_credenciales)
    return [{"nombre": nombre, "alta": ini.get(nombre, "alta", fallback=""),
             "por_minuto": ini.get(nombre, "por_minuto", fallback="") or None} for nombre in sorted(ini.sections())]
