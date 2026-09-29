"""``python -m hehermes_avisos.vigia [--config RUTA] [servir | comprobar | dispositivos]``

- ``servir`` (lo que arranca systemd): la API para la app y el bucle que vigila a Hermes.
- ``comprobar``: la configuración, los secretos, Hermes y el relé, sin mandar ningún aviso. Para después de instalar.
  Sin credencial (el «modo permisos»), el relé no se mira: cada iPhone trae el suyo, con su permiso.
- ``dispositivos``: los iPhone dados de alta, con el token recortado y, si lo tienen, hasta cuándo vale su permiso
  (nunca el permiso).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request

from .. import VERSION, comun
from ..comun import ErrorDeSecreto, ErrorHTTP, ServidorHTTP, cola, configurar_registro, leer_secreto
from .almacen import Almacen
from .api import AppVigia, ManejadorVigia
from .configuracion import ConfigVigia
from .envio import ClienteRele, Mensajero
from .fichero import ClienteLector, Ficheros, Limites
from .hermes import ClienteHermes, ErrorHermes
from .vigilante import Vigilante

registro = logging.getLogger("vigia")


def _secreto(ruta: str) -> str:
    return leer_secreto(ruta).decode("utf-8").strip()


def _clave_de_hermes(ruta: str) -> str:
    """La clave del api_server: un fichero con la clave sola (la copia 0600 del vigía, con root) o, sin root, el mismo
    ``.env`` de Hermes (también 0600), del que se saca ``API_SERVER_KEY`` como lo hace la pasarela."""
    texto = _secreto(ruta)
    if "API_SERVER_KEY" not in texto and "=" not in texto:
        return texto
    from hehermes_servidor.pasarela import leer_clave_hermes
    clave = leer_clave_hermes(texto)
    if not clave:
        raise ErrorDeSecreto(f"{ruta} no tiene una API_SERVER_KEY que se pueda usar")
    return clave


def servir(config: ConfigVigia) -> int:
    # El puerto es de systemd (hehermes-vigia.socket): si lo pasa, se atiende en ese y no se abre ninguno.
    try:
        heredado = comun.socket_heredado()
    except comun.ErrorDeSocket as error:
        registro.error("%s", error)
        return 1
    try:
        credencial = _secreto(config.rele_credencial) if config.con_credencial else None
        clave_hermes = _clave_de_hermes(config.hermes_clave) if config.hermes_clave else None
        secreto_tunel = _secreto(config.secreto_tunel)
        if not secreto_tunel:
            raise ErrorDeSecreto(f"{config.secreto_tunel} está vacío: sin el secreto del túnel, la API quedaría abierta")
        almacen = Almacen(config.base_de_datos, config.max_dispositivos)
    except (ErrorDeSecreto, UnicodeDecodeError, OSError, sqlite3.Error, RuntimeError) as error:
        registro.error("%s", error)
        return comun.fuera_de_servicio(heredado, "vigia")
    hermes = ClienteHermes(config.hermes_base, clave_hermes, config.hermes_plazo)
    huellas_del_rele = tuple(h for h in (config.rele_huella, config.rele_huella_siguiente) if h) or None
    rele = (ClienteRele(config.rele_url, credencial, config.rele_plazo, huella=huellas_del_rele)
            if config.con_credencial else None)
    mensajero = Mensajero(almacen, rele, plazo=config.rele_plazo)
    vigilante = Vigilante(almacen, hermes, mensajero, intervalo=config.intervalo,
                          intervalo_en_calma=config.intervalo_en_calma, antiguedad_maxima=config.antiguedad_maxima,
                          filas_por_lectura=config.filas_por_lectura, caducidad_aprobacion=config.caducidad_aprobacion,
                          reglas_entrega=config.reglas_de_entrega())
    ficheros = Ficheros(hermes, ClienteLector(config.ficheros_lector),
                        Limites(config.ficheros_por_minuto, config.ficheros_simultaneos), casa=config.ficheros_casa)
    app = AppVigia(almacen, mensajero, secreto_tunel=secreto_tunel, caducidad_prueba=config.caducidad_prueba,
                   al_moverse=vigilante.despertar, ficheros=ficheros)
    servidor = ServidorHTTP(config.escucha, ManejadorVigia, app, heredado=heredado)
    _avisar_si_no_coincide(heredado, config.escucha)
    threading.Thread(target=servidor.serve_forever, name="api", daemon=True).start()
    parar = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: parar.set())
    signal.signal(signal.SIGINT, lambda *_: parar.set())
    registro.info("vigía %s escuchando en %s:%d%s; Hermes en %s%s; relé en %s", VERSION, *servidor.server_address[:2],
                  " (socket de systemd)" if heredado else "", config.hermes_base,
                  " (con clave)" if clave_hermes else "",
                  config.rele_url if config.con_credencial else "el de cada iPhone, con su permiso (sin credencial)")
    try:
        vigilante.correr(parar)
    finally:
        servidor.shutdown()
        servidor.server_close()
        almacen.cerrar()
        registro.info("vigía parado")
    return 0


def _avisar_si_no_coincide(heredado, escucha: tuple) -> None:
    """El socket de systemd manda; pero si no es el de la configuración, algo está desalineado (la unidad y el ini) y
    quien llama a esa dirección no encontrará al servicio."""
    if heredado is not None and tuple(heredado.getsockname()[:2]) != tuple(escucha):
        registro.warning("el socket de systemd es %s:%d y la configuración dice %s:%d: se atiende en el de systemd",
                         *heredado.getsockname()[:2], *escucha)


def comprobar(config: ConfigVigia) -> int:
    """Lo que se puede comprobar sin mandar nada. Cada línea dice «bien» o «mal» y por qué."""
    fallos = 0

    def decir(bien: bool, texto: str) -> None:
        nonlocal fallos
        fallos += 0 if bien else 1
        print(("bien: " if bien else "mal:  ") + texto)

    carpeta = os.path.dirname(os.path.abspath(config.base_de_datos))
    decir(os.path.isdir(carpeta) and os.access(carpeta, os.W_OK),
          f"la carpeta de la base de datos ({carpeta}) existe y se puede escribir")
    credencial = None
    if config.con_credencial:
        try:
            credencial = _secreto(config.rele_credencial)
            decir(bool(credencial), f"la credencial del relé ({config.rele_credencial}) se lee y es privada")
        except (ErrorDeSecreto, UnicodeDecodeError) as error:
            decir(False, str(error))
    else:
        decir(True, "relé: sin credencial; los avisos van con el permiso de cada iPhone (lo trae la app en su alta)")
    secreto_tunel = None
    try:
        secreto_tunel = _secreto(config.secreto_tunel)
        decir(bool(secreto_tunel), f"el secreto del túnel ({config.secreto_tunel}) se lee y es privado")
    except (ErrorDeSecreto, UnicodeDecodeError) as error:
        decir(False, str(error))
    clave_hermes = None
    if config.hermes_clave:
        try:
            clave_hermes = _clave_de_hermes(config.hermes_clave)
            decir(bool(clave_hermes), f"la clave de Hermes ({config.hermes_clave}) se lee y es privada")
        except (ErrorDeSecreto, UnicodeDecodeError) as error:
            decir(False, str(error))
    try:
        bandeja = ClienteHermes(config.hermes_base, clave_hermes, config.hermes_plazo).sesiones()
        decir(True, f"Hermes contesta en {config.hermes_base}: {len(bandeja)} conversaciones en la bandeja")
    except ErrorHermes as error:
        decir(False, f"Hermes en {config.hermes_base}: {error}")
    abridor = comun.abridor()
    # El propio vigía, por su puerto (el de systemd): contesta con el secreto y sin él no atiende.
    base = f"http://{config.escucha[0]}:{config.escucha[1]}"
    if secreto_tunel:
        try:
            peticion = urllib.request.Request(f"{base}/avisos/v1/salud", headers={"X-HeHermes-Vigia": secreto_tunel})
            with abridor.open(peticion, timeout=config.rele_plazo) as respuesta:
                decir(respuesta.status == 200, f"el vigía contesta en {base} con el secreto del túnel")
        except urllib.error.HTTPError as error:
            decir(False, f"el vigía contesta {error.code} en {base}" + (
                ": está fuera de servicio (el motivo, en journalctl -u hehermes-vigia)" if error.code == 503 else ""))
        except (urllib.error.URLError, OSError) as error:
            decir(False, f"nadie contesta en {base} (¿está en marcha hehermes-vigia.socket?): "
                         f"{getattr(error, 'reason', error)}")
        try:
            with abridor.open(f"{base}/avisos/v1/salud", timeout=config.rele_plazo):
                decir(False, f"el vigía contesta en {base} sin el secreto del túnel")
        except urllib.error.HTTPError as error:
            decir(error.code in (403, 503), "y sin el secreto no atiende" if error.code == 403 else
                  f"y sin el secreto contesta {error.code}")
        except (urllib.error.URLError, OSError):
            pass
    if config.ficheros_lector:
        decir(*_comprobar_lector(config.ficheros_lector))
    else:
        decir(True, "sin lector de ficheros ([ficheros] lector vacío): GET /avisos/v1/fichero contesta 503")
    if not config.con_credencial:
        return 1 if fallos else 0
    base_rele = config.rele_url.rsplit("/v1/", 1)[0]
    if config.rele_huella:
        # La entrada pública del relé no contesta a nada sin credencial (el 404 de siempre, que además le cuenta un
        # intento fallido a esta IP): se mira solo con ella, y anclada.
        abridor_rele = comun.abridor(tuple(h for h in (config.rele_huella, config.rele_huella_siguiente) if h))
    else:
        abridor_rele = abridor
        try:
            with abridor.open(f"{base_rele}/v1/salud", timeout=config.rele_plazo) as respuesta:
                decir(respuesta.status == 200, f"el relé contesta en {base_rele}")
        except urllib.error.HTTPError as error:
            decir(False, f"el relé contesta {error.code} en {base_rele}" + (
                ": está en marcha, pero sin la clave de APNs, y no puede mandar avisos" if _sin_clave(error) else ""))
        except (urllib.error.URLError, OSError) as error:
            decir(False, f"el relé no contesta en {base_rele}: {getattr(error, 'reason', error)}")
    if credencial:
        try:
            peticion = urllib.request.Request(f"{base_rele}/v1/credencial",
                                              headers={"Authorization": f"Bearer {credencial}"})
            with abridor_rele.open(peticion, timeout=config.rele_plazo) as respuesta:
                nombre = json.loads(respuesta.read().decode("utf-8")).get("credencial")
                decir(True, f"el relé acepta la credencial de este vigía («{nombre}»)")
        except urllib.error.HTTPError as error:
            decir(False, f"el relé contesta {error.code} a la credencial" + (
                ": no la acepta" if error.code == 401 or (error.code == 404 and config.rele_huella) else ""))
        except (urllib.error.URLError, OSError, ValueError) as error:
            decir(False, f"el relé no contesta a la credencial: {getattr(error, 'reason', error)}")
    return 1 if fallos else 0


def _comprobar_lector(ruta_socket: str) -> tuple:
    """El lector de los ficheros de Hermes, sin leer nada: pedir «/» tiene que dar su rechazo (``prohibida``, fuera de
    las permitidas; un lector de antes de la 1.4.0 decía ``no_es_fichero``). Se mira la línea del lector tal cual: por
    HTTP, desde la 1.4.0, los dos son el mismo 404 que lo que no existe."""
    try:
        estado = ClienteLector(ruta_socket, plazo=5).estado_de("/")
    except ErrorHTTP as error:
        return False, f"el lector de ficheros en {ruta_socket}: {error.estado} {error.codigo} (¿está en marcha " \
                      f"hehermes-leer-media.socket?)"
    if estado in ("prohibida", "no_es_fichero"):
        return True, f"el lector de ficheros contesta en {ruta_socket}"
    if estado.startswith("ok"):
        return False, f"el lector de ficheros en {ruta_socket} ha dado «/» por un fichero"
    return False, f"el lector de ficheros en {ruta_socket} contesta «{estado[:40]}» a «/»"


def _sin_clave(error: urllib.error.HTTPError) -> bool:
    try:
        return error.code == 503 and json.loads(error.read().decode("utf-8")).get("estado") == "sin_clave"
    except (OSError, ValueError, AttributeError):
        return False


def dispositivos(config: ConfigVigia) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        # Como root, SQLite crearía la base de datos o sus ficheros -wal y -shm de root, y el vigía (hh-vigia) ya no
        # podría escribir en ella.
        print("error: ejecútalo como el usuario del vigía: sudo -u hh-vigia /opt/hehermes-avisos/venv/bin/python -I -m "
              "hehermes_avisos.vigia dispositivos", file=sys.stderr)
        return 1
    almacen = Almacen(config.base_de_datos, config.max_dispositivos)
    ahora = time.time()
    lista = almacen.dispositivos()
    if not lista:
        print("Ningún iPhone dado de alta.")
    for d in lista:
        alta = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.alta))
        estado = "delante" if d.delante(ahora) else "detrás"
        print(f"{cola(d.token):10} {d.entorno:10} alta {alta}  {estado:7}  vista previa «{d.ajustes.vista_previa}», "
              f"sonido «{d.ajustes.sonido}», {len(d.ajustes.silenciados)} chats silenciados; {_permiso(d, ahora)}")
    almacen.cerrar()
    return 0


def _permiso(dispositivo, ahora: float) -> str:
    """Si tiene permiso y hasta cuándo vale. El permiso mismo, nunca: deja pedir avisos para ese iPhone."""
    permiso = dispositivo.permiso
    if permiso is None:
        return "sin permiso"
    hasta = time.strftime("%Y-%m-%d", time.localtime(permiso.caduca))
    if permiso.rechazado is not None:
        return f"permiso rechazado por el relé (valía hasta {hasta})"
    if permiso.caduca <= ahora:
        return f"permiso caducado ({hasta})"
    return f"permiso hasta {hasta}"


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hehermes_avisos.vigia", description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/hehermes-avisos/vigia.ini")
    parser.add_argument("orden", nargs="?", default="servir", choices=("servir", "comprobar", "dispositivos"))
    argumentos = parser.parse_args(argv)
    config = ConfigVigia.leer(argumentos.config)
    configurar_registro(config.registro)
    return {"servir": servir, "comprobar": comprobar, "dispositivos": dispositivos}[argumentos.orden](config)


if __name__ == "__main__":
    sys.exit(main())
