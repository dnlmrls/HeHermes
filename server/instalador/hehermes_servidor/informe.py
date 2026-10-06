"""`hehermes-servidor informe`: lo que hace falta para entender un fallo, en texto plano y **sin secretos**, para pegarlo
en un chat (a Hermes, o a quien ayude) sin pensarlo dos veces.

Lleva las versiones (la del instalador que se ejecuta y la instalada, la de los avisos, la de Hermes, la de Python y el
sistema), cómo se lanza Hermes, los servicios de HeHermes y su estado, los puertos que escuchan, el último canje del
alta por chat, la última actualización y las últimas líneas de los registros de HeHermes. No lleva claves ni tokens,
ni direcciones de quien se conecta, ni nada de las conversaciones: los registros de Hermes no se leen, y todo lo que
sale pasa por `tapar` (las IP que no son de esta máquina, lo que va detrás de «clave», «token» y parecidos, las cadenas
largas que parecen secretos, y la casa y el nombre del usuario).

Solo lee: no toma el cerrojo ni cambia nada, y **sin root no se relanza con sudo**: dice lo que puede leer este
usuario, y que con `sudo` saldría todo. Así lo puede lanzar Hermes aunque no tenga permisos.
"""

from __future__ import annotations

import datetime
import json
import re

from . import VERSION
from .manifiesto import Manifiesto, ManifiestoRoto

#: Lo que se dice arriba del todo: que se puede pegar.
CABECERA = ("Sin claves, tokens, direcciones de quien se conecta ni conversaciones: se puede pegar en un chat.")
SIN_ROOT = ("Sin root: esto es lo que puede leer este usuario. Con «sudo hehermes-servidor informe» saldría todo.")

#: Las unidades de HeHermes, en el orden en que se enseñan. Las que no están se dicen como las dice systemctl.
UNIDADES = ("hehermes-pasarela.service", "hehermes-vigia.service", "hehermes-vigia.socket",
            "hehermes-cortafuegos.service", "hehermes-borrado.timer", "hehermes-leer-media.socket",
            "hehermes-respaldo.socket", "hehermes-entrada.socket", "hehermes-actualizar.socket",
            "hehermes-agentes.socket", "hehermes-canje.service")
#: De quién son los registros que se leen: los de HeHermes, nunca los de Hermes (llevan lo que se habla).
REGISTROS = ("hehermes-pasarela", "hehermes-vigia", "hehermes-canje", "hehermes-actualizacion",
             "hehermes-actualizar@*", "hehermes-agentes@*", "hehermes-entrada@*", "hehermes-respaldo@*")
LINEAS_DE_REGISTRO = 25
LINEAS_DEL_REGISTRO_DE_ACTUALIZAR = 15
PUERTO_VIGIA = 8790
PUERTO_HERMES = 8642
ESTADO_ACTUALIZAR = "/var/lib/hehermes-actualizar/estado.json"
REGISTRO_ACTUALIZAR = "/var/lib/hehermes-actualizar/registro.txt"

_VERSION = re.compile(r'^VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.M)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Cuatro grupos o más, o con «::»: una hora (08:15:02) no es una dirección.
_IPV6 = re.compile(r"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}|"
                   r"(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:?){0,6}[0-9A-Fa-f]{0,4})(?![\w:])")
_DE_ESTA_MAQUINA = ("127.0.0.1", "0.0.0.0")
_SECRETO = re.compile(r"(?i)\b(api_server_key|clave|key|token|secret|secreto|password|passwd|contrase(?:ñ|n)a|bearer|"
                      r"authorization|credencial|psk|llave)\b(\s*[=:]\s*|\s+)([^\s,;]+)")
# Una cadena de 32 o más letras y números (base64url o hexadecimal) que lleva letras y números: un token o una clave.
_LARGO = re.compile(r"(?<![A-Za-z0-9_+=-])(?=[A-Za-z0-9_+=-]*\d)(?=[A-Za-z0-9_+=-]*[A-Za-z])[A-Za-z0-9_+=-]{32,}")
# Lo que va detrás de `#` o `?` en un enlace (el del canje, el código de avisos): lleva lo que no se enseña.
_ENLACE = re.compile(r"(?i)\b(hehermes-(?:canje|tls|avisos|vpn):\S*?)[?#]\S*")


def tapar(texto: str, usuario: str | None = None, casa: str | None = None) -> str:
    """El texto sin nada que no deba salir de este servidor. Lo que se tapa se dice (`<oculto>`, `<ip>`): que falte
    algo se tiene que notar."""
    texto = _ENLACE.sub(r"\1?<oculto>", texto)
    texto = _SECRETO.sub(lambda m: m.group(1) + m.group(2) + "<oculto>", texto)
    texto = _LARGO.sub("<oculto>", texto)
    texto = _IPV4.sub(lambda m: m.group(0) if m.group(0) in _DE_ESTA_MAQUINA else "<ip>", texto)
    texto = _IPV6.sub(lambda m: m.group(0) if m.group(0) in ("::", "::1") else "<ip>", texto)
    if casa and casa not in ("/", "/root"):
        texto = texto.replace(casa.rstrip("/"), "~")
    if usuario and usuario != "root" and len(usuario) > 1:
        texto = re.sub(r"(?<![\w-])%s(?![\w-])" % re.escape(usuario), "<usuario>", texto)
    return texto


def _fecha(segundos) -> str:
    if not isinstance(segundos, (int, float)) or isinstance(segundos, bool) or segundos <= 0:
        return "?"
    return datetime.datetime.fromtimestamp(segundos, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _version_en(sis, carpeta: str, paquete: str) -> str | None:
    texto = sis.leer_texto("%s/%s/__init__.py" % (carpeta.rstrip("/"), paquete))
    hallada = _VERSION.search(texto or "")
    return hallada.group(1) if hallada else None


def _sistema(sis) -> list:
    lineas = []
    nombre = None
    for linea in (sis.leer_texto("/etc/os-release") or "").splitlines():
        if linea.startswith("PRETTY_NAME="):
            nombre = linea.split("=", 1)[1].strip().strip('"')
    arquitectura = sis.ejecutar(["uname", "-m"])
    lineas.append("sistema: %s, %s, núcleo %s" % (nombre or "desconocido",
                                                  arquitectura.salida.strip() if arquitectura.bien else "?",
                                                  getattr(sis, "nucleo", "?")))
    lineas.append("Python: %s" % ".".join(str(n) for n in getattr(sis, "version_python", ())[:3]))
    contenedor = ("docker" if sis.existe("/.dockerenv") else "podman" if sis.existe("/run/.containerenv") else None)
    lineas.append("systemd: %s%s" % ("sí" if sis.existe("/run/systemd/system") else "no",
                                     ", dentro de un contenedor (%s)" % contenedor if contenedor else ""))
    return lineas


def _hermes_version(sis, puerto: int) -> str:
    try:
        estado, cuerpo = sis.http_get("http://127.0.0.1:%d/health" % puerto, {})
    except (OSError, ValueError, TypeError):
        return "no contesta"
    if estado != 200:
        return "no contesta" if estado is None else "contesta %s" % estado
    try:
        version = json.loads(cuerpo.decode("utf-8", "replace")).get("version")
    except (ValueError, AttributeError):
        version = None
    return version if isinstance(version, str) and len(version) <= 32 else "contesta (sin versión)"


def _servicios(sis, ambito, unidad_hermes) -> list:
    unidades = list(UNIDADES) + ([unidad_hermes] if unidad_hermes else [])
    hecho = sis.ejecutar(ambito.systemctl + ["is-active", "--"] + unidades)
    estados = hecho.salida.split()
    if len(estados) < len(unidades):
        return ["(systemctl no dice el estado de los servicios)"]
    return ["%s: %s%s" % (unidad, estado, " (Hermes)" if unidad == unidad_hermes else "")
            for unidad, estado in zip(unidades, estados)]


def _puertos(sis, puerto_pasarela) -> list:
    """Los que escuchan de los de HeHermes y Hermes, con la dirección de esta máquina en la que escuchan."""
    nombres = {PUERTO_VIGIA: "vigía", PUERTO_HERMES: "API de Hermes"}
    if isinstance(puerto_pasarela, int):
        nombres[puerto_pasarela] = "pasarela"
    hecho = sis.ejecutar(["ss", "-Htln"])
    if not hecho.bien:
        return ["(ss no dice qué escucha)"]
    vistos = {}
    for linea in hecho.salida.splitlines():
        partes = linea.split()
        if len(partes) < 4:
            continue
        local = partes[3]
        direccion, _, puerto = local.rpartition(":")
        if puerto.isdigit() and int(puerto) in nombres:
            vistos.setdefault(int(puerto), []).append(direccion or "*")
    return ["%d (%s): %s" % (puerto, nombre, ", ".join(sorted(set(vistos[puerto]))) if puerto in vistos
                             else "no escucha") for puerto, nombre in sorted(nombres.items())]


def _actualizacion(sis, root: bool) -> list:
    if not root:
        return ["(su estado es de root)"]
    texto = sis.leer_texto(ESTADO_ACTUALIZAR)
    if texto is None:
        return ["ninguna desde la app"]
    try:
        estado = json.loads(texto)
    except ValueError:
        return ["(su estado no se entiende)"]
    if not isinstance(estado, dict):
        return ["(su estado no se entiende)"]
    lineas = ["%s%s%s, %s" % (estado.get("estado", "?"),
                              " (%s)" % estado["motivo"] if isinstance(estado.get("motivo"), str) else "",
                              " a la %s" % estado["version"] if isinstance(estado.get("version"), str) else "",
                              _fecha(estado.get("hora")))]
    registro = sis.leer_texto(REGISTRO_ACTUALIZAR)
    if registro:
        lineas.append("lo último que dijo el instalador:")
        lineas += ["  " + linea for linea in registro.strip().splitlines()[-LINEAS_DEL_REGISTRO_DE_ACTUALIZAR:]]
    return lineas


def _registros(sis, root: bool) -> list:
    orden = ["journalctl"] + ([] if root else ["--user"]) + ["--no-pager", "-o", "short-iso", "-n",
                                                            str(LINEAS_DE_REGISTRO)]
    for unidad in REGISTROS:
        orden += ["-u", unidad]
    hecho = sis.ejecutar(orden)
    if not hecho.bien:
        return ["(no se pueden leer: %s)" % ("journalctl no contesta" if root else
                                            "sin root, solo los de este usuario, y no hay")]
    lineas = [linea for linea in hecho.salida.splitlines() if linea.strip() and not linea.startswith("-- ")]
    return lineas[-LINEAS_DE_REGISTRO:] or ["(ninguna)"]


def construir(sis, ambito, root: bool, ahora=None, usuario=None, casa=None) -> list:
    """Las líneas del informe, ya tapadas. `usuario` y `casa`, los de quien lo lanza, si no son los del ámbito: también
    se tapan."""
    ahora = ahora if ahora is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
    lineas = ["HeHermes · informe del servidor (%s)" % _fecha(ahora), CABECERA]
    if not root:
        lineas.append(SIN_ROOT)
    try:
        man = Manifiesto.leer(sis, ambito.manifiesto)
        roto = None
    except ManifiestoRoto as error:
        man, roto = Manifiesto(), str(error)
    datos = man.datos
    pasarela = datos.get("pasarela") if isinstance(datos.get("pasarela"), dict) else {}
    puerto = pasarela.get("puerto") if isinstance(pasarela.get("puerto"), int) else None
    unidad_hermes = datos.get("unidad_hermes") if isinstance(datos.get("unidad_hermes"), str) else None

    lineas += ["", "Versiones", "  instalador que se ejecuta: %s" % VERSION]
    instalada = _version_en(sis, ambito.prefijo, "hehermes_servidor")
    lineas.append("  instalador instalado: %s" % (instalada or "no está, o no se puede leer"))
    avisos = _version_en(sis, ambito.prefijo, "hehermes_avisos") or _version_en(sis, "/opt/hehermes-avisos/src",
                                                                                  "hehermes_avisos")
    lineas.append("  avisos: %s" % (avisos or "no están, o no se pueden leer"))
    lineas.append("  Hermes: %s" % _hermes_version(sis, PUERTO_HERMES))
    lineas += ["  " + linea for linea in _sistema(sis)]

    lineas += ["", "Instalación"]
    if roto:
        lineas.append("  manifiesto roto: %s" % roto)
    elif not man.en_disco:
        lineas.append("  no hay manifiesto en %s%s" % (ambito.manifiesto, "" if root else " (o este usuario no "
                                                                                          "puede leerlo)"))
    else:
        lineas.append("  %s, en %s" % ("con root" if pasarela.get("root", ambito.root) else "sin root, en la casa "
                                       "del usuario de Hermes", ", ".join(man.modos) or "nada"))
    lineas.append("  pasarela: %s" % ("puerto %d" % puerto if puerto else "sin puerto apuntado"))
    lineas.append("  Hermes lo lleva: %s" % (unidad_hermes or "no está apuntado (suelto, o en un contenedor)"))
    por_chat = datos.get("por_chat") if isinstance(datos.get("por_chat"), dict) else None
    if por_chat:
        lineas.append("  alta por chat: %s, %s" % (
            _fecha(por_chat.get("alta")),
            "canjeada el %s" % _fecha(por_chat["canjeado"]) if por_chat.get("canjeado") else "sin canjear"))
    else:
        lineas.append("  alta por chat: ninguna")
    if not ambito.root and ambito.usuario:
        lineas.append("  linger: %s" % ("sí" if sis.existe("/var/lib/systemd/linger/%s" % ambito.usuario) else "no"))

    lineas += ["", "Servicios"] + ["  " + linea for linea in _servicios(sis, ambito, unidad_hermes)]
    lineas += ["", "Puertos que escuchan"] + ["  " + linea for linea in _puertos(sis, puerto)]
    lineas += ["", "Última actualización desde la app"] + ["  " + l for l in _actualizacion(sis, root and ambito.root)]
    lineas += ["", "Últimas líneas de los registros de HeHermes"] + ["  " + l for l in _registros(sis, ambito.root)]
    # Con root, el usuario de Hermes y su casa salen en las rutas y las unidades: también se tapan.
    usuarios = [u for u in (usuario, ambito.usuario, datos.get("usuario")) if isinstance(u, str) and u]
    casas = [c for c in (casa, ambito.casa, datos.get("casa")) if isinstance(c, str) and c]
    for i, linea in enumerate(lineas):
        for c in casas:
            linea = tapar(linea, casa=c)
        for u in usuarios:
            linea = tapar(linea, usuario=u)
        lineas[i] = tapar(linea)
    return lineas


def informe(sis, ambito, root: bool, salida, usuario=None, casa=None) -> int:
    for linea in construir(sis, ambito, root, usuario=usuario, casa=casa):
        salida(linea)
    return 0
