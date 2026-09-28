"""``python -m hehermes_avisos.rele [--config RUTA] [servir | comprobar | credencial …]``

- ``servir`` (lo que arranca systemd): la API para los vigías.
- ``comprobar``: la configuración, la clave .p8 (firma un JWT y lo tira) y las credenciales. Sin red: no llama a Apple.
- ``credencial --nombre NOMBRE --secreto RUTA``: emite (o reutiliza) la credencial del vigía de esta máquina. Deja el
  secreto en ``RUTA`` (0600) y su huella en ``credenciales.ini``. Se puede repetir (lo hace ``instalar.sh``).
- ``credencial alta NOMBRE [--a-fichero RUTA] [--por-minuto N]``: la credencial del vigía de **otro** servidor, que
  llega por la entrada pública (``publico``). Pinta su código de avisos, solo en un terminal, o lo deja en ``RUTA``
  (0600, un fichero nuevo). El secreto no queda en ningún otro sitio.
- ``credencial baja NOMBRE``: deja de valer al momento. ``credencial lista``: los nombres, sin huellas.

Es lo que hay detrás de ``sudo hehermes-rele …`` (``despliegue/hehermes-rele``).
"""

from __future__ import annotations

import argparse
import logging
import os
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
        modulo_credenciales.leer(config.credenciales)
        # A partir de aquí, el fichero al día: un alta o una baja valen sin reiniciar el relé.
        credenciales = modulo_credenciales.Almacen(config.credenciales)
        if not len(credenciales):
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


PUBLICO = "/etc/hehermes-avisos/rele-publico.ini"


def _escribir_nuevo_privado(ruta: str, texto: str) -> None:
    """Un fichero **nuevo**, 0600: si ya hay uno, no se pisa (podría ser el código de otro, todavía sin entregar)."""
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fichero:
        fichero.write(texto)


def credencial(argumentos, salida=print, terminal=None) -> int:
    """``credencial alta|baja|lista``: las de los vigías de otros servidores, que llegan por la entrada pública."""
    ruta = argumentos.credenciales or ConfigRele.leer(argumentos.config).credenciales
    accion, nombre = argumentos.accion, argumentos.quien
    try:
        if accion == "lista":
            todas = modulo_credenciales.lista(ruta)
            for c in todas:
                salida("%-31s alta %s%s" % (c["nombre"], c["alta"] or "?",
                                            ", %s avisos por minuto" % c["por_minuto"] if c["por_minuto"] else ""))
            if not todas:
                salida("Ninguna credencial.")
            return 0
        if not nombre:
            salida(f"error: credencial {accion} necesita un nombre")
            return 2
        if accion == "baja":
            if modulo_credenciales.baja(ruta, nombre):
                salida(f"credencial «{nombre}» dada de baja: su código ya no vale (y sus conexiones se cortan)")
                return 0
            salida(f"no hay ninguna credencial «{nombre}»")
            return 1
        # alta
        terminal = sys.stdout.isatty() if terminal is None else terminal
        if not argumentos.a_fichero and not terminal:
            salida("error: el código de avisos lleva la credencial, y solo lo pinto en un terminal. Sin uno, déjalo en "
                   "un fichero: --a-fichero <ruta> (0600)")
            return 2
        from . import publico
        try:
            config_publico = publico.ConfigPublico.leer(argumentos.publico)
            huella = publico.huella_del_certificado(config_publico.certificado)
        except (ValueError, OSError) as error:
            salida(f"error: sin la entrada pública del relé no hay código que dar ({error}). Se pone con: sudo "
                   "instalar.sh --rele-publico")
            return 1
        if not config_publico.direccion:
            salida(f"error: {argumentos.publico} no dice la dirección de esta máquina (direccion = …)")
            return 1
        if argumentos.a_fichero and os.path.lexists(argumentos.a_fichero):
            salida(f"error: {argumentos.a_fichero} ya existe: no lo piso")
            return 1
        secreto = modulo_credenciales.alta(ruta, nombre, argumentos.por_minuto)
        texto = publico.codigo(config_publico.direccion, config_publico.puerto, huella, secreto)
        del secreto
        if argumentos.a_fichero:
            try:
                _escribir_nuevo_privado(argumentos.a_fichero, texto + "\n")
            except OSError as error:
                modulo_credenciales.baja(ruta, nombre)
                salida(f"error: no he podido escribir {argumentos.a_fichero} ({error.strerror}); la credencial no queda")
                return 1
            salida(f"credencial «{nombre}» dada de alta; su código de avisos está en {argumentos.a_fichero} (0600). "
                   "Lleva la credencial: pásalo por un canal privado y bórralo después")
        else:
            salida(f"credencial «{nombre}» dada de alta. Su código de avisos (lleva la credencial: ni lo compartas por "
                   "donde lo pueda ver otro ni le hagas captura; no se puede volver a pintar):")
            salida("")
            salida(texto)
            salida("")
            salida(f"En su servidor: sudo hehermes-servidor avisos (y pegarlo cuando lo pida). Si se pierde: sudo "
                   f"hehermes-rele credencial baja {nombre} y otra alta")
        del texto
        return 0
    except ValueError as error:
        salida(f"error: {error}")
        return 1
    except PermissionError:
        salida(f"error: no puedo escribir {ruta}: hace falta root (sudo hehermes-rele …)")
        return 1


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hehermes_avisos.rele", description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/hehermes-avisos/rele.ini")
    parser.add_argument("orden", nargs="?", default="servir", choices=("servir", "comprobar", "credencial"))
    parser.add_argument("accion", nargs="?", choices=("alta", "baja", "lista"),
                        help="credencial: alta, baja o lista (las de los vigías de otros servidores)")
    parser.add_argument("quien", nargs="?", metavar="NOMBRE", help="credencial alta|baja: el nombre de su servidor")
    parser.add_argument("--nombre", help="credencial: el nombre del servidor del vigía de esta máquina")
    parser.add_argument("--secreto", help="credencial: dónde dejar el secreto del vigía de esta máquina (0600)")
    parser.add_argument("--credenciales", help="credencial: el credenciales.ini (por defecto, el de la configuración)")
    parser.add_argument("--a-fichero", help="credencial alta: deja el código en este fichero nuevo (0600)")
    parser.add_argument("--por-minuto", type=int, help="credencial alta: su propio tope de avisos por minuto")
    parser.add_argument("--publico", default=PUBLICO, help="credencial alta: la configuración de la entrada pública")
    argumentos = parser.parse_args(argv)
    if argumentos.orden != "credencial" and (argumentos.accion or argumentos.quien):
        parser.error("alta, baja y lista son de credencial")
    if argumentos.orden == "credencial" and argumentos.accion:
        return credencial(argumentos)
    if argumentos.orden == "credencial":
        if not argumentos.nombre or not argumentos.secreto:
            parser.error("credencial necesita alta|baja|lista, o --nombre y --secreto")
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
