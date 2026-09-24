"""Las credenciales de los vigías ante el relé: una por servidor, emitida a mano, guardada como huella.

El relé nunca guarda el secreto, solo su SHA-256. No hace falta un hash lento (scrypt, argon2) porque el secreto no lo
elige una persona: son 32 bytes al azar, y su huella no se puede recorrer a fuerza bruta. Si ``credenciales.ini`` se
filtra, no sirve para mandar ningún aviso.

El camino para miles (documentado en el README, no construido) cambia esto por permisos de avisos por dispositivo,
avalados con App Attest: entonces un vigía solo puede pedir avisos para los iPhone que se los han dado.
"""

from __future__ import annotations

import base64
import configparser
import datetime
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

from ..comun import ErrorDeSecreto, escribir_privado, leer_secreto

# Un prefijo reconocible: si una credencial acaba donde no debe (un log, un repositorio), un escáner de secretos la
# encuentra por él, y quien la ve sabe qué es.
PREFIJO = "hhr1."


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
    ini = configparser.ConfigParser(interpolation=None)
    with open(ruta, encoding="utf-8") as fichero:
        ini.read_file(fichero)
    credenciales = {}
    for nombre in ini.sections():
        valor = ini.get(nombre, "hash", fallback="").strip().lower()
        if not valor.startswith("sha256:") or len(valor) != len("sha256:") + 64:
            raise ValueError(f"la credencial «{nombre}» no tiene un «hash = sha256:…» válido")
        por_minuto = ini.get(nombre, "por_minuto", fallback="").strip()
        credenciales[valor] = Credencial(nombre, valor, int(por_minuto) if por_minuto else None)
    return credenciales


def buscar(credenciales: dict, secreto: str) -> Credencial | None:
    """La credencial de este secreto, o ``None``. La comparación final es de tiempo constante por costumbre: lo que se
    compara son huellas, que no dicen nada del secreto, pero no cuesta nada."""
    candidata = credenciales.get(huella(secreto))
    if candidata is None or not hmac.compare_digest(candidata.huella, huella(secreto)):
        return None
    return candidata


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
    ini = configparser.ConfigParser(interpolation=None)
    if os.path.exists(ruta_credenciales):
        with open(ruta_credenciales, encoding="utf-8") as fichero:
            ini.read_file(fichero)
    valor = huella(secreto)
    if ini.has_section(nombre) and ini.get(nombre, "hash", fallback="") == valor:
        return creado
    if not ini.has_section(nombre):
        ini.add_section(nombre)
    ini.set(nombre, "hash", valor)
    ini.set(nombre, "alta", datetime.date.today().isoformat())
    lineas = ["# Credenciales de los vigías ante el relé: una sección por servidor, con la huella de su secreto.\n",
              "# La escribe `python -m hehermes_avisos.rele credencial`. El secreto no está aquí.\n\n"]
    for seccion in ini.sections():
        lineas.append(f"[{seccion}]\n")
        lineas.extend(f"{clave} = {valor_}\n" for clave, valor_ in ini.items(seccion))
        lineas.append("\n")
    modo = os.stat(ruta_credenciales).st_mode & 0o777 if os.path.exists(ruta_credenciales) else 0o600
    escribir_privado(ruta_credenciales, "".join(lineas).encode("utf-8"))
    os.chmod(ruta_credenciales, modo)
    return creado
