"""``python -m hehermes_avisos.rele [--config RUTA] [servir | comprobar | credencial …]``

- ``servir`` (lo que arranca systemd): la API para los vigías.
- ``comprobar``: la configuración, la clave .p8 (firma un JWT y lo tira) y las credenciales. Sin red: no llama a Apple.
- ``credencial --nombre NOMBRE --secreto RUTA``: emite (o reutiliza) la credencial de un vigía. Deja el secreto en
  ``RUTA`` (0600) y su huella en ``credenciales.ini``. Se puede repetir.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from .. import comun
from ..comun import ErrorDeSecreto, ServidorHTTP, configurar_registro, leer_secreto
from . import credenciales as modulo_credenciales
from .api import AppRele, ManejadorRele
from .apns import ClienteAPNs
from .configuracion import ConfigRele
from .firmante import FirmanteAPNs
from .limites import Limitador

registro = logging.getLogger("rele")


def _firmante(config: ConfigRele) -> FirmanteAPNs:
    if not config.clave_id or config.clave_id == "CAMBIAME":
        raise ValueError("falta el Key ID de la clave de APNs (clave_id en la configuración)")
    return FirmanteAPNs.desde_p8(leer_secreto(config.clave_p8), config.clave_id, config.equipo,
                                 renovar=config.renovar_jwt)


def servir(config: ConfigRele) -> int:
    # El puerto es de systemd (hehermes-rele.socket): si lo pasa, se atiende en ese y no se abre ninguno.
    try:
        heredado = comun.socket_heredado()
    except comun.ErrorDeSocket as error:
        registro.error("%s", error)
        return 1
    try:
        credenciales = modulo_credenciales.leer(config.credenciales)
        if not credenciales:
            raise ValueError(f"no hay ninguna credencial en {config.credenciales}: ningún vigía podría mandar nada")
    except (ErrorDeSecreto, ValueError, OSError) as error:
        registro.error("%s", error)
        return comun.fuera_de_servicio(heredado, "rele")
    try:
        firmante = _firmante(config)
    except (ErrorDeSecreto, ValueError, OSError) as error:
        if heredado is None:
            registro.error("%s", error)
            return 1
        # Con el socket de systemd, sin clave no se sale: se queda en marcha, con el puerto, y a los avisos contesta 503
        # («sin_clave_apns») hasta que se le reinicie con ella. Salir haría que cada aviso que llegara lo arrancara otra
        # vez, y a los cinco fallos seguidos systemd soltaría el socket.
        registro.error("%s: sin la clave de APNs, el relé contesta 503 a los avisos hasta que se reinicie con ella",
                       error)
        firmante = None
    apns = ClienteAPNs(firmante, config.tema, config.bases, plazo=config.plazo_apns) if firmante else None
    limitador = Limitador(config.por_credencial, config.por_token, config.recordar_bajas)
    servidor = ServidorHTTP(config.escucha, ManejadorRele, AppRele(credenciales, apns, limitador, config.reservas),
                            heredado=heredado)
    if heredado is not None and tuple(heredado.getsockname()[:2]) != tuple(config.escucha):
        registro.warning("el socket de systemd es %s:%d y la configuración dice %s:%d: se atiende en el de systemd",
                         *heredado.getsockname()[:2], *config.escucha)
    parar = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: parar.set())
    signal.signal(signal.SIGINT, lambda *_: parar.set())
    threading.Thread(target=servidor.serve_forever, name="api", daemon=True).start()
    registro.info("relé escuchando en %s:%d%s para %s (equipo %s, clave %s); %d credenciales%s",
                  *servidor.server_address[:2], " (socket de systemd)" if heredado else "", config.tema,
                  config.equipo, config.clave_id, len(credenciales), "" if apns else "; SIN CLAVE DE APNS")
    # En vueltas cortas y no con un `wait()` sin plazo: así la señal se atiende enseguida pase lo que pase con el cerrojo.
    while not parar.wait(1.0):
        pass
    servidor.shutdown()
    servidor.server_close()
    if apns:
        apns.cerrar()
    registro.info("relé parado")
    return 0


def comprobar(config: ConfigRele) -> int:
    fallos = 0

    def decir(bien: bool, texto: str) -> None:
        nonlocal fallos
        fallos += 0 if bien else 1
        print(("bien: " if bien else "mal:  ") + texto)

    try:
        firmante = _firmante(config)
        firmante.token()
        decir(True, f"la clave .p8 ({config.clave_p8}) se lee, es privada y firma (kid {config.clave_id}, "
                    f"iss {config.equipo})")
    except (ErrorDeSecreto, ValueError) as error:
        decir(False, str(error))
    try:
        credenciales = modulo_credenciales.leer(config.credenciales)
        decir(bool(credenciales), f"{len(credenciales)} credenciales en {config.credenciales}: "
                                  + ", ".join(sorted(c.nombre for c in credenciales.values())))
    except (ValueError, OSError) as error:
        decir(False, f"credenciales: {error}")
    decir(bool(config.tema), f"tema de APNs: {config.tema}")
    return 1 if fallos else 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hehermes_avisos.rele", description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/hehermes-avisos/rele.ini")
    parser.add_argument("orden", nargs="?", default="servir", choices=("servir", "comprobar", "credencial"))
    parser.add_argument("--nombre", help="credencial: el nombre del servidor del vigía")
    parser.add_argument("--secreto", help="credencial: dónde dejar el secreto (0600)")
    parser.add_argument("--credenciales", help="credencial: el credenciales.ini (por defecto, el de la configuración)")
    argumentos = parser.parse_args(argv)
    if argumentos.orden == "credencial":
        if not argumentos.nombre or not argumentos.secreto:
            parser.error("credencial necesita --nombre y --secreto")
        ruta = argumentos.credenciales or ConfigRele.leer(argumentos.config).credenciales
        creada = modulo_credenciales.asegurar(ruta, argumentos.nombre, argumentos.secreto)
        print(f"credencial «{argumentos.nombre}»: {'nueva' if creada else 'ya existía'}; secreto en "
              f"{argumentos.secreto}, huella en {ruta}")
        return 0
    config = ConfigRele.leer(argumentos.config)
    configurar_registro(config.registro)
    return {"servir": servir, "comprobar": comprobar}[argumentos.orden](config)


if __name__ == "__main__":
    sys.exit(main())
