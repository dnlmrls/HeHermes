"""Las órdenes de hehermes-servidor. Solo cablean: la decisión está en detección, plan, aplicar y desinstalar.

Desde la 0.6.0 solo se instala la conexión directa (la pasarela TLS, `modo_tls`). La VPN IKEv2 de las versiones de
antes ya no se instala, ni se repara, ni se actualiza: solo se quita (`desinstalar --modo vpn`, o `desinstalar` a secas).
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time

from . import VERSION, firma, fondo, marcha, permisos
from . import ambito as amb
from . import piezas as p
from .aplicar import Parada
from .capacidades import RECOMENDADA, texto_de
from .desinstalar import desinstalar, resumen
from .deteccion import DIRECCION_VALIDA
from .manifiesto import Manifiesto, ManifiestoRoto
from .plan import (PREFIJO_DETALLE, PREFIJO_ERROR, Opciones, antes_de_aplicar, completar_opciones, comprobar_version,
                   despues_de_aplicar, pintar, segun_lo_instalado, sin_cambios)
from .sistema import Sistema

SI = ("s", "si", "sí")
#: Lo que dice `instalar --modo vpn`, que ya no existe.
SIN_VPN = ("error: --modo vpn ya no existe: desde la 0.6.0 el instalador solo pone la conexión directa (la pasarela TLS), "
           "que no necesita ninguna VPN. Para instalarla, el mismo comando sin --modo vpn. Si este servidor tiene la VPN "
           "IKEv2 de una versión anterior, se quita con: sudo hehermes-servidor desinstalar --modo vpn")
#: Lo que se dice de una VPN de antes cuando se pasa por ella (`comprobar`, `actualizar`).
VPN_DE_ANTES = ("la VPN IKEv2 de una versión anterior sigue aquí: desde la 0.6.0 ya no la instalo, ni la reparo, ni la "
                "actualizo, y la app ya no la usa. Quítala con: sudo hehermes-servidor desinstalar --modo vpn")


class SalirConUso(Exception):
    pass


class Analizador(argparse.ArgumentParser):
    def error(self, mensaje):
        raise SalirConUso(mensaje)


def _analizador():
    a = Analizador(prog="hehermes-servidor", add_help=True)
    ordenes = a.add_subparsers(dest="orden")
    i = ordenes.add_parser("instalar")
    # `--modo tls` se sigue aceptando: lo llevan los comandos de antes de la 0.6.0. `--modo vpn` lo para `main`, con su
    # propio mensaje.
    i.add_argument("--modo", choices=("tls", "vpn"), help="tls, el único: la pasarela (la VPN ya no se instala)")
    i.add_argument("--plan", action="store_true", help="enseña lo que haría, sin cambiar nada")
    i.add_argument("--iphone", help="da de alta este iPhone y pinta su QR")
    i.add_argument("--direccion", help="la dirección pública del servidor (la del QR)")
    i.add_argument("--hermes-home", help="qué Hermes, si hay varios")
    i.add_argument("--reemplazar", action="append", default=[], metavar="FICHERO",
                   help="sustituye este fichero ajeno o cambiado, guardando antes una copia")
    i.add_argument("--si", action="store_true", help="no pregunta")
    i.add_argument("--adoptar", action="store_true", help=argparse.SUPPRESS)
    i.add_argument("--por-chat", action="store_true",
                   help="el alta la pide Hermes desde un chat: sin preguntar, sin QR y con el canje al final")
    i.add_argument("--llave", help="con --por-chat: la clave pública de la frase que copió la app")
    i.add_argument("--activar-api", action="store_true",
                   help="enciende la API de Hermes si está apagada (solo las líneas que faltan en su .env)")
    # Desde la 0.12.0 (Daniel, 2026-10-08): el permiso para actualizar Hermes antes de nada, si es anterior a la que la
    # app aprovecha entera (`actualizar_hermes`). Opcional, para quien lo lance a mano: la frase de la app no lo lleva
    # hasta probarlo con un Hermes de verdad, y sin él se instala con lo que tenga.
    i.add_argument("--actualizar-hermes", action="store_true",
                   help="si Hermes es anterior a la %s, lo actualizo antes de nada (hermes update) y lo reinicio"
                        % texto_de(RECOMENDADA))
    i.add_argument("--qr-png", metavar="FICHERO", help="con --por-chat: deja además el enlace en un PNG con su QR")
    i.add_argument("--recuperacion", metavar="PRUEBA",
                   help="con --por-chat: la firma del código de recuperación que pone la app, para volver a conectar")
    i.add_argument("--corregir-exposicion", action="store_true",
                   help="si la API de Hermes escucha en todas las interfaces, la cierro a 127.0.0.1 (en su .env)")
    i.add_argument("--cortafuegos-a-mano", action="store_true",
                   help="el cortafuegos lo llevas tú: no lo toco aunque cierre el paso")
    i.add_argument("--volver-atras", action="store_true",
                   help="instala esta versión aunque la instalada sea más nueva")
    i.add_argument("--avisos", nargs="?", const="-", metavar="CÓDIGO",
                   help="los avisos push, con el código de avisos que te han dado (sin él, lo pido y se pega sin eco)")
    # La de dentro de la instalación por chat en segundo plano (`fondo`): instala, no lanza otra. No es para personas.
    i.add_argument(fondo.BANDERA, action="store_true", help=argparse.SUPPRESS)
    v = ordenes.add_parser("avisos", help="los avisos push en una instalación que ya tiene la pasarela")
    v.add_argument("codigo", nargs="?", metavar="CÓDIGO", help="el código de avisos (sin él, lo pido y se pega sin eco)")
    v.add_argument("--plan", action="store_true", help="enseña lo que haría, sin cambiar nada")
    v.add_argument("--si", action="store_true", help="no pregunta")
    v.add_argument("--reemplazar", action="append", default=[], metavar="FICHERO", help=argparse.SUPPRESS)
    ordenes.add_parser("comprobar")
    r = ordenes.add_parser("certificado", help="el certificado de la pasarela: rotar (el siguiente pasa a ser el de ahora)")
    r.add_argument("accion", choices=("rotar",))
    r.add_argument("--si", action="store_true", help="no pregunta")
    # Lo que lanza hehermes-cortafuegos.service al arrancar (poner) y al pararse (quitar). No es para personas.
    c = ordenes.add_parser("cortafuegos")
    c.add_argument("accion", choices=("poner", "quitar"))
    # La limpieza del canje, que lanza systemd como root al pararse la unidad (ExecStopPost). No es para personas.
    ordenes.add_parser("canje-limpiar")
    # Lo que lanza hehermes-pasarela-clave.path cuando cambia el .env de Hermes. No es para personas.
    ordenes.add_parser("pasarela-clave")
    # Lo que lanza hehermes-borrado.timer de noche (el borrado de verdad, `mantenimiento.py`). No es para personas.
    ordenes.add_parser("borrado-seguro")
    q = ordenes.add_parser("recuperacion", help="el código de recuperación: quitar (la app de tu iPhone pone otro)")
    q.add_argument("accion", choices=("quitar",))
    # Solo lee, sin secretos, y sin root también: lo que se pueda leer (`informe.py`).
    ordenes.add_parser("informe", help="lo que hace falta para entender un fallo, sin secretos, para pegarlo en un chat")
    u = ordenes.add_parser("actualizar")
    u.add_argument("--paquete", required=True)
    u.add_argument("--firma", required=True)
    d = ordenes.add_parser("desinstalar")
    d.add_argument("--modo", choices=("tls", "vpn"),
                   help="quita solo ese modo y deja el otro como está (sin --modo, todo); vpn, la de antes de la 0.6.0")
    d.add_argument("--si", action="store_true")
    d.add_argument("--quitar-paquetes", action="store_true")
    return a


ORDENES = ("instalar", "avisos", "comprobar", "certificado", "actualizar", "desinstalar", "canje-limpiar", "cortafuegos",
           "pasarela-clave", "borrado-seguro", "informe", "recuperacion")
#: Lo que se puede hacer sin root en una instalación de la pasarela de un usuario.
DEL_USUARIO = ("instalar", "avisos", "comprobar", "certificado", "desinstalar", "canje-limpiar", "borrado-seguro",
               "recuperacion")


def main(argv, doc, aqui, sis=None, entrada=input, salida=print, terminal=None, euid=None, relanzar=None,
         usuario=None, cuenta=None) -> int:
    """Lo que haga cada orden está en `_main`. Aquí, desde la 0.11.1, que nada se quede a medias sin decirlo
    (`marcha`): una salida que no se rompe si el terminal se va, SIGTERM, SIGHUP y Ctrl-C atendidos, y lo que se escape
    (otro instalador en marcha, una señal antes de empezar, lo que no se esperaba), dicho en una línea y, por chat, con
    su código, sin un traceback."""
    por_chat = "--por-chat" in argv
    salida = marcha.a_prueba(salida)
    marcha.poner_el_reloj()
    instalar = argv[:1] == ["instalar"]
    try:
        with marcha.senales(salida, por_chat=por_chat):
            return _main(argv, doc, aqui, sis, entrada, salida, terminal, euid, relanzar, usuario, cuenta)
    except marcha.Ocupado as error:
        return _acabar_con(salida, por_chat, "error: %s" % error, "ocupado")
    except (marcha.Interrupcion, KeyboardInterrupt) as error:
        return _acabar_con(salida, por_chat, "\nerror: me han parado (%s)%s. Vuelve a lanzar el mismo comando." % (
            getattr(error, "senal", "SIGINT"), " antes de cambiar nada" if instalar else ""),
            getattr(error, "codigo", "interrumpido"))
    except Exception as error:
        return _acabar_con(salida, por_chat, "\nerror: algo que no esperaba ha fallado dentro del instalador: %s.%s "
                           "Vuelve a lanzar el mismo comando; si vuelve a pasar, es un fallo del instalador: cuéntalo "
                           "con esta línea." % (marcha.describir(error), " No he cambiado nada." if instalar else ""),
                           "python")


def _acabar_con(salida, por_chat, texto, codigo, paso=None) -> int:
    """Un fallo, dicho: para personas y, por chat, la línea de la app (la última, con la del paso justo antes)."""
    salida(texto)
    if por_chat:
        salida("\n" + (PREFIJO_DETALLE + "paso=%s\n" % paso if paso else "") + PREFIJO_ERROR + codigo)
    return 1


def _main(argv, doc, aqui, sis, entrada, salida, terminal, euid, relanzar, usuario, cuenta) -> int:
    try:
        op = _analizador().parse_args(argv)
    except SalirConUso as error:
        salida("error: %s\n\n%s" % (error, doc.strip()))
        return 2
    if op.orden is None:
        salida(doc.strip())
        return 2
    # La orden tal cual: por chat, «el mismo comando otra vez» se engancha a la instalación en marcha (`fondo`).
    op.argv = list(argv)
    if op.orden == "informe":
        return _informe(sis or Sistema(), os.geteuid() if euid is None else euid, salida, cuenta)
    if op.orden == "instalar" and op.modo == "vpn":
        # Antes que nada: ni se mira ni se relanza con sudo algo que ya no existe.
        salida(SIN_VPN)
        return 2
    if op.orden == "instalar":
        uso = _uso_por_chat(op)
        if uso:
            salida("error: %s\n\n%s" % (uso, doc.strip()))
            return 2
    # Un código dado en la orden se mira antes de nada (y el error no lo repite: lleva la credencial).
    dado = op.avisos if op.orden == "instalar" else (op.codigo if op.orden == "avisos" else None)
    if dado not in (None, "-"):
        from .avisos import CodigoNoValido, leer_codigo
        try:
            leer_codigo(dado)
        except CodigoNoValido as error:
            salida("error: %s" % error)
            return 2
    if getattr(op, "adoptar", False):
        salida("error: --adoptar todavía no existe: una instalación hecha a mano no se toca (spec, «Lo que queda fuera»)")
        return 2
    sis = sis or Sistema()
    euid = os.geteuid() if euid is None else euid
    terminal = sys.stdin.isatty() and sys.stdout.isatty() if terminal is None else terminal
    if euid != 0:
        return _sin_root(op, argv, sis, aqui, entrada, salida, terminal, relanzar or _relanzar_de_verdad,
                         usuario or _usuario(), cuenta)
    os.umask(0o022)
    return _con_ambito(op, sis, amb.de_root(), aqui, entrada, salida, terminal)


def _informe(sis, euid, salida, cuenta) -> int:
    """`informe`: antes que nada, porque solo lee y nunca se relanza con sudo. Sin root, la instalación de este usuario
    si la tiene; si no, la de root, con lo que se pueda leer de ella."""
    from .informe import informe
    if euid == 0:
        return informe(sis, amb.de_root(), True, salida)
    suyo = _ambito_del_usuario(cuenta)
    ambito = suyo if suyo is not None and sis.existe(suyo.manifiesto) else amb.de_root()
    return informe(sis, ambito, False, salida, usuario=suyo.usuario if suyo else None,
                   casa=suyo.casa if suyo else None)


def _con_ambito(op, sis, ambito, aqui, entrada, salida, terminal) -> int:
    if fondo.toca(op):
        # Por chat, desde la 0.11.2: la instalación va en su propia unidad, que ni el plazo de la terminal de Hermes ni
        # su reinicio cortan, y esto la lanza (o se engancha a la que ya está en marcha) y la sigue (`fondo`). Si no se
        # puede lanzar, aquí mismo, como hasta la 0.11.1.
        def aqui_mismo():
            op.en_primer_plano = True
            return _con_ambito(op, sis, ambito, aqui, entrada, salida, terminal)
        return fondo.por_chat(sis, ambito, op.argv, aqui, salida, aqui_mismo)
    try:
        man = Manifiesto.leer(sis, ambito.manifiesto)
    except ManifiestoRoto as error:
        salida("error: %s" % error)
        return 1
    orden = {"instalar": _instalar, "avisos": _avisos, "comprobar": _comprobar, "certificado": _certificado,
             "actualizar": _actualizar,
             "desinstalar": _desinstalar, "canje-limpiar": _canje_limpiar, "cortafuegos": _cortafuegos,
             "pasarela-clave": _pasarela_clave, "borrado-seguro": _borrado_seguro,
             "recuperacion": _recuperacion}[op.orden]
    if op.orden in ("comprobar", "canje-limpiar", "cortafuegos", "pasarela-clave", "borrado-seguro", "actualizar") or \
            getattr(op, "plan", False):
        # canje-limpiar tampoco: corre dentro del `systemctl stop` de un instalar que ya tiene el cerrojo.
        # Lo que solo lee no toma el cerrojo: --plan no deja ni un fichero en /run.
        # Ni actualizar: no cambia nada él, y quien cambia es el `instalar --si` de la versión nueva, que lo toma; con
        # el de fuera tomado, se pararía en «ya hay otro hehermes-servidor en marcha».
        return orden(op, sis, man, aqui, entrada, salida, terminal, ambito)
    with _cerrojo(sis, ambito.cerrojo):
        return orden(op, sis, man, aqui, entrada, salida, terminal, ambito)


def _sin_root(op, argv, sis, aqui, entrada, salida, terminal, relanzar, usuario, cuenta) -> int:
    """Lo primero de todo, antes de detectar nada. Sin root: una pasarela ya instalada por este usuario sigue siendo
    suya; si no, se relanza con `sudo -n` si se puede; y si no, `instalar` pone la pasarela como el usuario (no
    necesita root), y lo demás se para sin tocar nada."""
    ambito = _ambito_del_usuario(cuenta)
    try:
        suya = ambito is not None and Manifiesto.leer(sis, ambito.manifiesto).en_disco
    except ManifiestoRoto:
        suya = True  # que lo diga _con_ambito
    if suya and op.orden in DEL_USUARIO:
        return _como_usuario(op, sis, ambito, aqui, entrada, salida, terminal)
    sudo = permisos.sondear_sudo(sis)
    permitido = sudo != "sin-contrasena" and permisos.instalado_permitido(sis)
    instalada = permisos.version_instalada(sis) if permitido else None
    como = permisos.decidir(1, sudo, permitido and instalada == VERSION)
    if como in ("sudo", "instalado"):
        orden = (permisos.orden_relanzada(os.path.join(aqui, "hehermes-servidor"), argv) if como == "sudo" else
                 permisos.orden_relanzada(permisos.INSTALADO, argv, python=False))
        codigo = relanzar(orden)
        return 0 if codigo is None else codigo
    if op.orden == "instalar" and ambito is not None:
        # La pasarela no necesita root (spec 2026-09-26, «Sin root»).
        return _como_usuario(op, sis, ambito, aqui, entrada, salida, terminal)
    if op.orden == "instalar":
        # Sin root todo va en la casa de quien lo lanza, y la de este no se puede usar: no se sabe cuál es, o no es una
        # ruta que se pueda poner en una unidad de systemd.
        salida("error: sin root instalo la pasarela en la casa de quien me lanza, y la de «%s» no sé usarla." % usuario)
    for linea in permisos.mensaje(sudo, usuario, aqui, argv, bool(getattr(op, "por_chat", False)),
                                  otra_version=instalada if permitido else None):
        salida(linea)
    return 1


def _como_usuario(op, sis, ambito, aqui, entrada, salida, terminal) -> int:
    os.umask(0o077)
    # systemctl --user necesita saber dónde está su gestor; lanzado desde Hermes (una unidad del sistema) puede no
    # tenerlo en el entorno.
    if "XDG_RUNTIME_DIR" not in os.environ and os.path.isdir("/run/user/%d" % ambito.uid):
        os.environ["XDG_RUNTIME_DIR"] = "/run/user/%d" % ambito.uid
    return _con_ambito(op, sis, ambito, aqui, entrada, salida, terminal)


def _ambito_del_usuario(cuenta):
    import pwd
    if cuenta is None:
        try:
            yo = pwd.getpwuid(os.getuid())
        except KeyError:
            return None
        cuenta = (yo.pw_name, yo.pw_dir, yo.pw_uid)
    try:
        return amb.de_usuario(*cuenta)
    except ValueError:
        return None


def _relanzar_de_verdad(orden) -> int:
    sys.stdout.flush()
    os.execvp(orden[0], orden)
    return 1  # execvp no vuelve


def _usuario() -> str:
    import pwd
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return "<tu-usuario>"


def _uso_por_chat(op):
    from .porchat import llave_valida
    from .recuperacion import leer_prueba
    if not op.por_chat:
        if op.llave or op.qr_png or op.recuperacion:
            return "--llave, --qr-png y --recuperacion solo van con --por-chat"
        return None
    if not op.iphone:
        return "--por-chat necesita --iphone <nombre>"
    if not op.llave:
        return "--por-chat necesita --llave (la de la frase que copió la app)"
    if not llave_valida(op.llave):
        return "la llave de --llave no es la de una frase de la app (43 caracteres en base64url)"
    if op.recuperacion is not None:
        if op.plan:
            # Comprobarla apunta los fallos: un --plan que la mirara sin contarlos dejaría probar sin límite.
            return "--recuperacion no va con --plan: la prueba se comprueba al instalar"
        if leer_prueba(op.recuperacion) is None:
            return "la prueba de --recuperacion no es la de una frase de la app"
    return None


class _cerrojo:
    """Dos instaladores a la vez se pisarían el manifiesto. Desde la 0.11.1 el cerrojo dice quién lo tiene y desde
    cuándo, y el que lo encuentra tomado acaba con `marcha.Ocupado` (por chat, `hehermes-error:ocupado`)."""

    RUTA = "/run/hehermes-servidor.lock"

    def __init__(self, sis, ruta=RUTA):
        self.sis, self.fichero, self.RUTA = sis, None, ruta

    def __enter__(self):
        import fcntl
        try:
            ruta = self.sis.ruta(self.RUTA)
            os.makedirs(os.path.dirname(ruta), exist_ok=True)
            # Sin vaciarlo al abrir: lo que dice es de quien lo tiene.
            self.fichero = open(ruta, "a+")
            fcntl.flock(self.fichero, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            quien = self._quien()
            self.fichero.close()
            self.fichero = None
            raise marcha.Ocupado("ya hay otro hehermes-servidor en marcha%s: espera a que acabe y vuelve a lanzar el "
                                 "mismo comando" % quien)
        except OSError:
            self.fichero = None
            return self
        try:
            self.fichero.seek(0)
            self.fichero.truncate()
            self.fichero.write("%d %d\n" % (os.getpid(), int(time.time())))
            self.fichero.flush()
        except OSError:
            pass
        return self

    def _quien(self) -> str:
        try:
            self.fichero.seek(0)
            pid, desde = (int(x) for x in self.fichero.read(64).split()[:2])
        except (OSError, ValueError):
            return ""
        return " (el proceso %d, desde hace %d s)" % (pid, max(0, int(time.time()) - desde))

    def __exit__(self, *exc):
        if self.fichero:
            # Se borra con el cerrojo aún tomado: quien espere a abrirlo verá un fichero nuevo, no este.
            self.sis.borrar(self.RUTA)
            self.fichero.close()


def _pregunta_si(entrada, salida, terminal, si, texto="¿Sigo? [s/N] "):
    if si:
        return True
    if not terminal:
        salida("Sin un terminal no pregunto: vuelve a lanzarlo con --si para que siga.")
        return False
    try:
        return entrada(texto).strip().lower() in SI
    except EOFError:
        return False


def _codigo_de_avisos(dado, entrada, salida, terminal):
    """El código de avisos, leído: el dado, o pedido (sin eco en un terminal). None si no vale (y ya se ha dicho)."""
    from .avisos import CodigoNoValido, leer_codigo, pedir_codigo
    if dado in (None, "-"):
        try:
            dado = pedir_codigo(entrada, terminal)
        except EOFError:
            dado = ""
    try:
        return leer_codigo(dado)
    except CodigoNoValido as error:
        salida("error: %s" % error)
        return None


def _avisos(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """`avisos [CÓDIGO]`: el vigía, en una instalación que ya tiene la pasarela. Es `instalar` con el código y con lo
    de antes (la dirección del QR, la que ya está), así que repara también lo que falte; y se puede repetir."""
    import argparse as _argparse
    import configparser
    if "tls" not in man.modos:
        salida("error: aquí no está la pasarela, y los avisos le llegan a la app por ella. Primero la conexión directa "
               "(el comando de la app, o %s instalar), y luego esto" % ("sudo hehermes-servidor" if ambito.root
                                                                       else ambito.orden))
        return 1
    ini = configparser.ConfigParser(interpolation=None)
    try:
        ini.read_string(sis.leer_texto(ambito.pasarela_ini) or "")
        direccion = ini.get("qr", "direccion", fallback="").strip() or None
    except configparser.Error:
        direccion = None
    if direccion == "PENDIENTE":
        direccion = None
    ns = _argparse.Namespace(iphone=None, direccion=direccion, hermes_home=None, reemplazar=op.reemplazar, si=op.si,
                             plan=op.plan, por_chat=False, llave=None, activar_api=False, actualizar_hermes=False,
                             qr_png=None,
                             # nftables o iptables a pelo, solo si ya los llevaba el instalador: poner los avisos no
                             # es motivo para empezar a tocar un cortafuegos (el vigía solo sale hacia el relé).
                             cortafuegos_a_mano=not man.datos.get("cortafuegos_propio"), corregir_exposicion=False,
                             avisos=op.codigo or "-",
                             # Lo de arriba no lo ha dado nadie: no cambia lo que se recuerda de cómo se instaló.
                             recordar=False)
    return _instalar(ns, sis, man, aqui, entrada, salida, terminal, ambito)


def _instalar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """La pasarela: la instala, la repara o da de alta un iPhone en ella. En un servidor con la VPN de antes, va a su
    lado sin tocarla, y el plan dice cómo quitarla (`modo_tls._convivir`). Con `--avisos`, también el vigía."""
    from . import actualizar_hermes, modo_tls, porchat
    codigo = None
    if getattr(op, "avisos", None):
        codigo = _codigo_de_avisos(op.avisos, entrada, salida, terminal)
        if codigo is None:
            return 2
    opciones = Opciones(iphone=op.iphone, direccion=op.direccion, hermes_home=op.hermes_home,
                        reemplazar=op.reemplazar, si=op.si or op.por_chat, solo_plan=op.plan, por_chat=op.por_chat,
                        llave=op.llave, activar_api=op.activar_api, qr_png=op.qr_png,
                        cortafuegos_a_mano=op.cortafuegos_a_mano, corregir_exposicion=op.corregir_exposicion,
                        avisos=codigo, volver_atras=getattr(op, "volver_atras", False),
                        recuperacion=getattr(op, "recuperacion", None),
                        actualizar_hermes=getattr(op, "actualizar_hermes", False))
    del codigo
    # Lo que no se da, como se instaló (`plan.completar_opciones`): `actualizar` lanza `instalar --si` a secas.
    como_se_instalo = completar_opciones(opciones, man)
    if op.por_chat:
        # Lo lanza Hermes: no hay nadie a quien preguntar.
        terminal = False
    opciones.terminal = terminal

    def detectar_ya():
        return modo_tls.detectar_tls(sis, man, ambito, direccion=opciones.direccion, hermes_home=opciones.hermes_home,
                                     activar_api=opciones.activar_api, cortafuegos_a_mano=opciones.cortafuegos_a_mano,
                                     corregir_exposicion=opciones.corregir_exposicion, por_chat=opciones.por_chat,
                                     solo_plan=op.plan)

    det = detectar_ya()
    det, de_antes = segun_lo_instalado(sis, man, ambito, opciones, det, detectar_ya)
    if det.direccion_privada and terminal and not op.plan:
        # Detrás de un NAT: la de salida no es la que va en el QR. Solo se pregunta en un terminal.
        try:
            dada = entrada("Este servidor sale por una dirección privada. ¿Cuál es su dirección pública (IP o nombre)? ")
        except EOFError:
            dada = ""
        if DIRECCION_VALIDA.fullmatch(dada.strip()):
            opciones.direccion = dada.strip()
            det = detectar_ya()
    plan = modo_tls.calcular_plan_tls(sis, det, man, opciones, aqui)
    plan.avisos[:0] = como_se_instalo + de_antes
    comprobar_version(sis, man, ambito, plan)
    # Desde la 0.12.0 (Daniel, 2026-10-08), con --actualizar-hermes: un Hermes anterior a la que la app aprovecha entera
    # se actualiza antes que nada, y con él de vuelta se vuelve a mirar todo. Si no se puede, se sigue con lo que hay desde
    # la mínima de respaldo, y se dice por qué (`actualizar_hermes`).
    decision = actualizar_hermes.decidir(sis, det, plan, opciones, ambito,
                                         en_segundo_plano=getattr(op, "en_segundo_plano", False))
    actualizacion = None
    if decision is not None and decision.toca:
        actualizacion = actualizar_hermes.actualizar(sis, decision, det, ambito, salida, por_chat=opciones.por_chat)
        if actualizacion.parada is not None:
            # Hermes no ha vuelto: de HeHermes no se ha instalado nada, y se dice como cualquier otra parada.
            salida("\nerror: %s" % actualizacion.parada)
            if opciones.por_chat:
                salida("\n" + PREFIJO_DETALLE + actualizacion.parada.detalle + "\n" + PREFIJO_ERROR +
                       actualizacion.parada.codigo)
            return 1
        det = detectar_ya()
        det, de_antes = segun_lo_instalado(sis, man, ambito, opciones, det, detectar_ya)
        plan = modo_tls.calcular_plan_tls(sis, det, man, opciones, aqui)
        plan.avisos[:0] = como_se_instalo + de_antes
        comprobar_version(sis, man, ambito, plan)
    actualizar_hermes.anotar(plan, decision, actualizacion)
    salida(pintar(plan, color=terminal).rstrip("\n"))
    if not op.plan and plan.bloqueos and all(getattr(b, "codigo", None) == "reinicia-hermes" for b in plan.bloqueos) \
            and any(a.tipo == "env" for a in plan.acciones):
        # Lo único que falta es que Hermes se reinicie, y eso no lo sé hacer (no es una unidad ni un contenedor): se
        # enciende su API en el .env y se para. La vez siguiente, con Hermes reiniciado, ya la encuentra encendida. (Si
        # ya estaba encendida por una pasada anterior y sin reiniciar, no hay nada que añadir: se para y se dice.)
        try:
            porchat.encender_para_reiniciar_a_mano(sis, det, plan, ambito, salida, por_chat=opciones.por_chat)
        except (OSError, ValueError) as error:
            salida("\nerror: no he podido encender la API de Hermes: %s" % error)
            if opciones.por_chat:
                salida("\n" + PREFIJO_ERROR + "api-apagada")
            return 1
    if op.plan or not plan.puede_seguir:
        if opciones.por_chat and not plan.puede_seguir:
            # Lo último, sola: la app lo reconoce (`ErrorDelInstalador`) donde se pega el enlace, y sabe que no se ha
            # tocado nada. Por un terminal no hace falta: quien lo lee es una persona. Justo antes, lo que lo concreta
            # (con `hermes-antiguo`, la versión de Hermes y lo que le falta), para una app que lo sepa leer.
            detalle = plan.detalle_del_error
            salida("\n" + (PREFIJO_DETALLE + detalle + "\n" if detalle else "") + PREFIJO_ERROR + plan.codigo_de_error)
        return 0 if plan.puede_seguir else 1
    if not plan.cambios:
        sin_cambios(sis, man, plan, recordar=getattr(op, "recordar", True))
        if opciones.iphone:
            salida("«%s» ya está en la pasarela. Su QR no se puede volver a pintar; para uno nuevo (y que el de antes "
                   "deje de valer), desde tu terminal: %shehermes-dispositivo rotar %s"
                   % (opciones.iphone, "sudo " if ambito.root else "", opciones.iphone))
        return 0
    if not _pregunta_si(entrada, salida, terminal, opciones.si):
        salida("No he cambiado nada.")
        return 1
    # La versión, lo que va a escribir esta pasada y cómo se instala: si se corta, la siguiente lo reconoce.
    antes_de_aplicar(man, plan, recordar=getattr(op, "recordar", True))
    # Desde la 0.11.1 (`marcha`): cada paso se dice al empezar; lo que puede fallar va antes y lo de Hermes (su .env y
    # su SOUL.md) lo último, detrás del canje; y todo fallo a mitad acaba dicho con verdad y, por chat, con su código.
    la_marcha = marcha.Marcha(modo_tls.pasos_de(plan), salida)
    fallo, el_enlace = None, None
    try:
        hecho = modo_tls.aplicar_tls(sis, plan, man, aqui, salida=salida, terminal=terminal, marcha=la_marcha,
                                     con_hermes=False)
        if opciones.por_chat:
            la_marcha.empezar("canje")
            token = hecho.get("token")
            if opciones.recuperando:
                # Con el código de recuperación: entra este iPhone, y el chat normal sigue cerrado.
                token = porchat.recuperar(sis, man, opciones.iphone, sis.ruta(ambito.tokens), ambito, salida, token)
            elif token is None:
                # Repetido antes de que ese iPhone use la pasarela, se canjeara o no: del token solo queda el hash, así
                # que va uno nuevo.
                token = porchat.reemitir(sis, man, opciones.iphone, sis.ruta(ambito.tokens), salida)
            carga = porchat.carga_tls(det.direccion, det.puerto_pasarela, modo_tls.huella(sis, ambito), token)
            del token
            el_enlace = porchat.lanzar(sis, man, det, opciones, salida, carga=carga, ambito=ambito)
            del carga
        modo_tls.aplicar_hermes(sis, plan, man, salida, la_marcha)
        la_marcha.acabar()
    except (Exception, KeyboardInterrupt) as error:
        fallo = error
    # Pase lo que pase, lo último: si a Hermes le falta reiniciarse (por lo de esta pasada, o porque una anterior se
    # paró antes de programarlo), se programa ahora. Antes de acabar le cortaría el turno en el que contesta.
    reinicio = None
    if _reinicio_por_programar(man):
        try:
            reinicio = porchat.reiniciar_hermes(sis, salida, det.hermes.gestor, ambito)
            if reinicio:
                man.datos[modo_tls.REINICIO_DE_HERMES]["programado"] = time.time()
                man.guardar(sis)
        except (Exception, KeyboardInterrupt) as error:
            fallo = fallo or error
    if fallo is not None:
        return _fallo_a_medias(salida, opciones.por_chat, la_marcha, fallo)
    despues_de_aplicar(sis, man)
    salida("\nHecho. «%s comprobar» lo repasa cuando quieras." % ("sudo hehermes-servidor" if ambito.root
                                                                       else ambito.orden))
    if reinicio is not None:
        la_marcha.avisar("hermes-se-reinicia" if reinicio else "reinicia-hermes")
    actualizar_hermes.avisos_para_la_app(la_marcha, decision, actualizacion, det.hermes)
    if el_enlace:
        # Para la app, juntos y justo antes del enlace: lo que la persona tiene que saber (`hehermes-aviso:`).
        hallado = re.search(r"&p=(\d+)&", el_enlace)
        canje = hallado.group(1) if hallado else "?"
        la_marcha.avisar("cortafuegos-proveedor", tcp=det.puerto_pasarela, canje=canje)
        if not ambito.root or det.cortafuegos_a_mano:
            la_marcha.avisar("cortafuegos-a-mano", tcp=det.puerto_pasarela, canje=canje)
        salida("\nPara la app (el enlace caduca en 10 minutos y no lleva ninguna clave):")
        for linea in la_marcha.lineas_de_avisos():
            salida(linea)
        salida(el_enlace)
    return 0


def _reinicio_por_programar(man) -> bool:
    """Si a Hermes le falta reiniciarse y no se ha programado (`modo_tls.REINICIO_DE_HERMES`)."""
    from .modo_tls import REINICIO_DE_HERMES
    datos = man.datos.get(REINICIO_DE_HERMES)
    return isinstance(datos, dict) and not datos.get("programado")


#: Lo que se le dice a la persona tras cada fallo a mitad, según su código: siempre «el mismo comando», que sigue donde
#: se quedó.
QUE_HACER = {
    "apt": "Suele ser pasajero (otro apt en marcha, la red): vuelve a lanzar el mismo comando en un rato, y sigue donde "
           "se quedó.",
    "pip": "Suele ser la red (pypi.org): vuelve a lanzar el mismo comando en un rato, y sigue donde se quedó.",
    "interrumpido": "Vuelve a lanzar el mismo comando: sigue donde se quedó.",
    "python": "Vuelve a lanzar el mismo comando; si vuelve a pasar, es un fallo del instalador: cuéntalo con esta línea.",
}


def _fallo_a_medias(salida, por_chat, la_marcha, fallo) -> int:
    """Lo que para `instalar` después de empezar a cambiar cosas: qué ha pasado, qué queda hecho y qué no (Hermes, el
    primero), qué hacer y, por chat, el paso y el código."""
    from .porchat import ParadaDelCanje
    if isinstance(fallo, KeyboardInterrupt):
        # Sin los manejadores de `marcha.senales` (fuera del hilo principal), Ctrl-C llega como siempre.
        texto, codigo = "me han parado a mitad (SIGINT)", "interrumpido"
    elif isinstance(fallo, (Parada, ParadaDelCanje)):
        # Una `marcha.Interrupcion` también: es una parada, con su código.
        texto, codigo = str(fallo), getattr(fallo, "codigo", "a-medias")
    else:
        texto, codigo = "algo que no esperaba ha fallado dentro del instalador: %s" % marcha.describir(fallo), "python"
    que_hacer = QUE_HACER.get(codigo, "Arréglalo y vuelve a lanzar el mismo comando: sigue donde se quedó.")
    return _acabar_con(salida, por_chat, "\nerror: %s\n%s %s" % (texto, la_marcha.resumen(), que_hacer), codigo,
                       paso=la_marcha.actual)


def _comprobar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """Lo de la pasarela y «Seguridad». Una VPN de antes ya no se comprueba, que ya no se repara: se dice que sigue ahí y
    cómo quitarla. Sin la pasarela sale con 1: la app ya no tiene otra forma de llegar a Hermes."""
    from . import modo_tls, seguridad
    if "tls" in man.modos:
        resultados = modo_tls.comprobar_tls(sis, man, ambito)
    else:
        resultados = [(False, "pasarela: no está instalada. La conexión directa se instala con: %s instalar"
                       % ("sudo hehermes-servidor" if ambito.root else ambito.orden))]
    for bien, texto in resultados:
        salida("  %-5s %s" % ("bien" if bien else "MAL", texto))
    if "vpn" in man.modos:
        salida("  %-5s %s" % (seguridad.AVISO, VPN_DE_ANTES))
    salida("")
    salida("Seguridad")
    revision = seguridad.revisar(sis, man, ambito)
    for estado, texto in revision:
        salida("  %-5s %s" % ("MAL" if estado == seguridad.MAL else estado, texto))
    return 0 if all(bien for bien, _ in resultados) and all(e != seguridad.MAL for e, _ in revision) else 1


def _certificado(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """`certificado rotar`: el siguiente pasa a ser el de la pasarela (`modo_tls.rotar_certificado`). Deja fuera a los
    iPhone que no anclaban aún la huella siguiente: se pregunta, salvo con --si."""
    from . import modo_tls
    salida("Voy a rotar el certificado de la pasarela: %s pasa a ser el suyo. Los iPhone que aún no anclaban esa "
           "huella dejarán de conectar hasta escanear un QR nuevo." % modo_tls.huella_de(sis, ambito.cert_siguiente))
    if not _pregunta_si(entrada, salida, terminal, op.si):
        salida("No he cambiado nada.")
        return 1
    return modo_tls.rotar_certificado(sis, man, ambito, salida)


def _canje_limpiar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    from .porchat import limpiar
    limpiar(sis, os.environ, ambito)
    # El enlace que guardó la instalación por chat ya no vale: fuera (`fondo`, desde la 0.11.2).
    fondo.al_cerrar_el_canje(sis, ambito)
    return 0


def _borrado_seguro(op, sis, man, aqui, entrada, salida, terminal, ambito):
    from . import mantenimiento
    if "tls" not in man.modos:
        return 0
    return mantenimiento.borrado_seguro(sis, man, ambito, salida)


def _recuperacion(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """`recuperacion quitar`: el código de recuperación de este servidor deja de valer, y el primer iPhone que mire Tu
    servidor pone otro (spec 2026-10-06, «Sin código»). Para quien lo ha perdido y ha vuelto por SSH. Solo desde un
    terminal: por chat (sin él) sería una forma de dejar a la persona sin su código."""
    from . import recuperacion as rec
    if "tls" not in man.modos:
        salida("error: aquí no hay pasarela, así que tampoco código de recuperación")
        return 1
    if not terminal:
        salida("error: el código de recuperación solo se quita desde un terminal (por SSH)")
        return 1
    registro = rec.Registro(sis.ruta(ambito.carpeta_estado_pasarela))
    estado = registro.leer()
    if estado is not None and estado["clave"] is None:
        salida("Este servidor no tiene código de recuperación: la app pondrá uno al abrir Ajustes › Tu servidor.")
        return 0
    quien = (estado or {}).get("por")
    salida("Voy a quitar el código de recuperación de este servidor%s: el de antes deja de valer, y la app de tu "
           "iPhone pondrá otro al abrir Ajustes › Tu servidor." % (" (lo puso «%s»)" % quien if quien else ""))
    if not _pregunta_si(entrada, salida, terminal, False):
        salida("No he cambiado nada.")
        return 1
    registro.quitar()
    salida("Hecho.")
    return 0


def _pasarela_clave(op, sis, man, aqui, entrada, salida, terminal, ambito):
    from . import modo_tls
    if not ambito.root:
        salida("error: sin root la pasarela lee el .env de Hermes directamente: no hay copia que poner al día")
        return 1
    return modo_tls.poner_al_dia_la_clave(sis, salida)


def _cortafuegos(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """`hehermes-cortafuegos.service`. Al arrancar (y si el cortafuegos del sistema se recarga): quita lo que un
    reinicio dejó del canje y vuelve a poner las reglas de HeHermes en nftables o iptables. Al pararse, las quita."""
    from . import cortafuegos as cf
    from . import porchat
    if op.accion == "quitar":
        cf.quitar(sis, cf.MARCA)
        return 0
    porchat.limpiar_restos(sis)
    propio = man.datos.get("cortafuegos_propio")
    try:
        if propio:
            lugares = cf.poner(sis, cf.MARCA, cf.permanentes_de(man.datos), propio.get("iptables", True))
            salida("reglas de HeHermes en: %s" % (", ".join(l.nombre for l in lugares) or "ninguna cadena cierra"))
        porchat.volver_a_abrir(sis, propio)
    except cf.NoSe as error:
        salida("error: no pongo las reglas de HeHermes: %s" % error)
        return 1
    return 0


def _actualizar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    if not ambito.root:
        salida("error: sin root, actualizar todavía no: vuelve a lanzar el comando de la app, que repara")
        return 1
    if "tls" not in man.modos:
        # Lo que hay es, como mucho, la VPN de antes, que ya no se actualiza. La versión nueva pondría otra cosa (la
        # pasarela, que abre un puerto a internet), y eso no se hace por la puerta de atrás de una actualización.
        salida("error: aquí no está la pasarela, así que no hay nada que actualizar%s. La conexión directa se instala "
               "con el comando de la app, o con: sudo hehermes-servidor instalar" % (
                   "" if "vpn" not in man.modos else
                   ": lo que hay es la VPN IKEv2 de una versión anterior, que desde la 0.6.0 ya no se instala ni se "
                   "actualiza (se quita con: sudo hehermes-servidor desinstalar --modo vpn)"))
        return 1
    # Las de la versión instalada, no las del paquete nuevo: la principal y la de rescate (`firma.CLAVES`).
    claves = firma.claves(sis, p.PREFIJO)
    if not claves:
        salida("error: las claves públicas de este paquete son el marcador (%s): no hay firma que comprobar, así que no "
               "actualizo. Mientras tanto, vuelve a lanzar el comando de la app." % firma.MARCADOR)
        return 1
    # Todo sobre una copia en una carpeta 0700 de root: si se comprobara y se abriera el fichero que se da, quien
    # pudiera escribir donde está lo podría cambiar entre la firma y el tar.
    carpeta = tempfile.mkdtemp(prefix="hehermes-servidor-")
    try:
        paquete, sello = os.path.join(carpeta, "paquete.tar.gz"), os.path.join(carpeta, "paquete.tar.gz.sig")
        try:
            shutil.copyfile(op.paquete, paquete)
            shutil.copyfile(op.firma, sello)
        except OSError as error:
            salida("error: no puedo leer el paquete o su firma (%s)" % error)
            return 1
        buena = firma.verificar_con_alguna(sis, paquete, sello, claves, python=ambito.python_venv)
        if buena is None:
            # No es que sea mala: no hay con qué mirarla (`firma.verificar`). Se dice qué falta.
            salida("error: no puedo comprobar la firma de %s, así que no lo instalo: aquí no está la orden openssl "
                   "(OpenSSL 3), y el entorno de Python de cryptography (%s) tampoco me sirve. Instala openssl "
                   "(sudo apt install openssl, o sudo dnf install openssl) y vuelve a intentarlo; o actualiza una vez "
                   "con el comando de la app, que rehace ese entorno" % (op.paquete, ambito.venv))
            return 1
        if not buena:
            salida("error: la firma de %s no es buena: no lo instalo" % op.paquete)
            return 1
        version = _version_del_paquete(paquete)
        if version is not None and _tupla(version) < _tupla(VERSION):
            salida("error: %s es la versión %s, más vieja que la instalada (%s): no vuelvo atrás, aunque esté "
                   "firmada (una versión vieja puede tener un fallo ya arreglado)" % (op.paquete, version, VERSION))
            return 1
        lanzador = _desempaquetar(paquete, carpeta)
        # La pasarela, que es lo único que se instala. Sin --modo: el de la versión nueva es el que toque.
        codigo = sis.ejecutar(["python3", "-I", lanzador, "instalar", "--si"], heredar=True).codigo
        if not codigo and "vpn" in man.modos:
            salida("Ojo: " + VPN_DE_ANTES)
        return codigo
    except ValueError as error:
        salida("error: %s" % error)
        return 1
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)


def _tupla(version):
    return tuple(int(x) for x in version.split("."))


def _version_del_paquete(paquete):
    try:
        with tarfile.open(paquete, "r:gz") as tar:
            raiz = tar.getmembers()[0].name.split("/", 1)[0]
    except (tarfile.TarError, OSError, IndexError):
        return None
    hallado = re.match(r"^hehermes-servidor-(\d+\.\d+\.\d+)$", raiz)
    return hallado.group(1) if hallado else None


def _desempaquetar(paquete, carpeta):
    """Solo ficheros y carpetas, todo dentro de `hehermes-servidor-X.Y.Z/`: nada fuera de la carpeta temporal."""
    with tarfile.open(paquete, "r:gz") as tar:
        miembros = tar.getmembers()
        raices = {m.name.split("/", 1)[0] for m in miembros}
        if len(raices) != 1 or not re.match(r"^hehermes-servidor-\d+\.\d+\.\d+$", next(iter(raices))):
            raise ValueError("el paquete no tiene la forma de hehermes-servidor")
        for m in miembros:
            if m.name.startswith("/") or ".." in m.name.split("/") or not (m.isfile() or m.isdir()):
                raise ValueError("el paquete lleva algo que no desempaqueto: %s" % m.name)
        tar.extractall(carpeta, members=miembros)
    return os.path.join(carpeta, next(iter(raices)), "hehermes-servidor")


def _desinstalar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """Sin --modo, todo. Con --modo, solo lo de ese modo: el otro se queda byte a byte como estaba. Si es el único que
    hay, es lo mismo que todo. `--modo vpn` es como se quita la VPN de antes de la 0.6.0 dejando la pasarela."""
    from .modos import NOMBRES
    modo = getattr(op, "modo", None)
    if modo and man.en_disco and modo not in man.modos:
        salida("En este servidor no instalé %s (lo que hay es %s): no hay nada suyo que quitar."
               % (NOMBRES[modo], " y ".join(NOMBRES[m] for m in man.modos) or "nada"))
        return 0
    if modo and man.modos == [modo]:
        salida("%s%s es lo único que instalé aquí: lo quito todo." % (NOMBRES[modo][0].upper(), NOMBRES[modo][1:]))
        modo = None
    salida(resumen(sis, man, ambito, modo=modo).rstrip("\n"))
    if not man.en_disco:
        return 0
    if not _pregunta_si(entrada, salida, terminal, op.si):
        salida("No he quitado nada.")
        return 1
    quedan = desinstalar(sis, man, quitar_paquetes=op.quitar_paquetes, salida=salida, ambito=ambito, modo=modo)
    if modo:
        otro = [m for m in man.modos if m != modo]
        salida("\nHecho. Queda %s, como estaba%s." % (" y ".join(NOMBRES[m] for m in otro),
                                                     ", y lo de arriba" if quedan else ""))
    else:
        salida("\nHecho." + (" Lo que se queda está arriba." if quedan else " El servidor está como antes de instalar."))
    return 0
