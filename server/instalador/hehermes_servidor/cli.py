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

from . import VERSION, firma, permisos
from . import ambito as amb
from . import piezas as p
from .aplicar import Parada
from .desinstalar import desinstalar, resumen
from .deteccion import DIRECCION_VALIDA
from .manifiesto import Manifiesto, ManifiestoRoto
from .plan import Opciones, pintar
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
    i.add_argument("--qr-png", metavar="FICHERO", help="con --por-chat: deja además el enlace en un PNG con su QR")
    i.add_argument("--corregir-exposicion", action="store_true",
                   help="si la API de Hermes escucha en todas las interfaces, la cierro a 127.0.0.1 (en su .env)")
    i.add_argument("--cortafuegos-a-mano", action="store_true",
                   help="el cortafuegos lo llevas tú: no lo toco aunque cierre el paso")
    ordenes.add_parser("comprobar")
    # Lo que lanza hehermes-cortafuegos.service al arrancar (poner) y al pararse (quitar). No es para personas.
    c = ordenes.add_parser("cortafuegos")
    c.add_argument("accion", choices=("poner", "quitar"))
    # La limpieza del canje, que lanza systemd como root al pararse la unidad (ExecStopPost). No es para personas.
    ordenes.add_parser("canje-limpiar")
    # Lo que lanza hehermes-pasarela-clave.path cuando cambia el .env de Hermes. No es para personas.
    ordenes.add_parser("pasarela-clave")
    u = ordenes.add_parser("actualizar")
    u.add_argument("--paquete", required=True)
    u.add_argument("--firma", required=True)
    d = ordenes.add_parser("desinstalar")
    d.add_argument("--modo", choices=("tls", "vpn"),
                   help="quita solo ese modo y deja el otro como está (sin --modo, todo); vpn, la de antes de la 0.6.0")
    d.add_argument("--si", action="store_true")
    d.add_argument("--quitar-paquetes", action="store_true")
    return a


ORDENES = ("instalar", "comprobar", "actualizar", "desinstalar", "canje-limpiar", "cortafuegos", "pasarela-clave")
#: Lo que se puede hacer sin root en una instalación de la pasarela de un usuario.
DEL_USUARIO = ("instalar", "comprobar", "desinstalar", "canje-limpiar")


def main(argv, doc, aqui, sis=None, entrada=input, salida=print, terminal=None, euid=None, relanzar=None,
         usuario=None, cuenta=None) -> int:
    try:
        op = _analizador().parse_args(argv)
    except SalirConUso as error:
        salida("error: %s\n\n%s" % (error, doc.strip()))
        return 2
    if op.orden is None:
        salida(doc.strip())
        return 2
    if op.orden == "instalar" and op.modo == "vpn":
        # Antes que nada: ni se mira ni se relanza con sudo algo que ya no existe.
        salida(SIN_VPN)
        return 2
    if op.orden == "instalar":
        uso = _uso_por_chat(op)
        if uso:
            salida("error: %s\n\n%s" % (uso, doc.strip()))
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


def _con_ambito(op, sis, ambito, aqui, entrada, salida, terminal) -> int:
    try:
        man = Manifiesto.leer(sis, ambito.manifiesto)
    except ManifiestoRoto as error:
        salida("error: %s" % error)
        return 1
    orden = {"instalar": _instalar, "comprobar": _comprobar, "actualizar": _actualizar,
             "desinstalar": _desinstalar, "canje-limpiar": _canje_limpiar, "cortafuegos": _cortafuegos,
             "pasarela-clave": _pasarela_clave}[op.orden]
    if op.orden in ("comprobar", "canje-limpiar", "cortafuegos", "pasarela-clave") or getattr(op, "plan", False):
        # canje-limpiar tampoco: corre dentro del `systemctl stop` de un instalar que ya tiene el cerrojo.
        # Lo que solo lee no toma el cerrojo: --plan no deja ni un fichero en /run.
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
    if not op.por_chat:
        if op.llave or op.qr_png:
            return "--llave y --qr-png solo van con --por-chat"
        return None
    if not op.iphone:
        return "--por-chat necesita --iphone <nombre>"
    if not op.llave:
        return "--por-chat necesita --llave (la de la frase que copió la app)"
    if not llave_valida(op.llave):
        return "la llave de --llave no es la de una frase de la app (43 caracteres en base64url)"
    return None


class _cerrojo:
    """Dos instaladores a la vez se pisarían el manifiesto."""

    RUTA = "/run/hehermes-servidor.lock"

    def __init__(self, sis, ruta=RUTA):
        self.sis, self.fichero, self.RUTA = sis, None, ruta

    def __enter__(self):
        try:
            import fcntl
            ruta = self.sis.ruta(self.RUTA)
            os.makedirs(os.path.dirname(ruta), exist_ok=True)
            self.fichero = open(ruta, "w")
            fcntl.flock(self.fichero, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("error: ya hay otro hehermes-servidor en marcha")
        except OSError:
            self.fichero = None
        return self

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


def _instalar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    """La pasarela: la instala, la repara o da de alta un iPhone en ella. En un servidor con la VPN de antes, va a su
    lado sin tocarla, y el plan dice cómo quitarla (`modo_tls._convivir`)."""
    from . import modo_tls, porchat
    opciones = Opciones(iphone=op.iphone, direccion=op.direccion, hermes_home=op.hermes_home,
                        reemplazar=op.reemplazar, si=op.si or op.por_chat, solo_plan=op.plan, por_chat=op.por_chat,
                        llave=op.llave, activar_api=op.activar_api, qr_png=op.qr_png,
                        cortafuegos_a_mano=op.cortafuegos_a_mano, corregir_exposicion=op.corregir_exposicion)
    if op.por_chat:
        # Lo lanza Hermes: no hay nadie a quien preguntar.
        terminal = False
    opciones.terminal = terminal

    def detectar_ya():
        return modo_tls.detectar_tls(sis, man, ambito, direccion=opciones.direccion, hermes_home=opciones.hermes_home,
                                     activar_api=opciones.activar_api, cortafuegos_a_mano=opciones.cortafuegos_a_mano,
                                     corregir_exposicion=opciones.corregir_exposicion)

    det = detectar_ya()
    if det.direccion_privada and terminal and not op.plan:
        # Detrás de un NAT: la de salida no es la que va en el QR. Solo se pregunta en un terminal.
        try:
            dada = entrada("Este servidor sale por una dirección privada. ¿Cuál es su dirección pública (IP o nombre)? ")
        except EOFError:
            dada = ""
        if DIRECCION_VALIDA.match(dada.strip()):
            opciones.direccion = dada.strip()
            det = detectar_ya()
    plan = modo_tls.calcular_plan_tls(sis, det, man, opciones, aqui)
    salida(pintar(plan, color=terminal).rstrip("\n"))
    if op.plan or not plan.puede_seguir:
        return 0 if plan.puede_seguir else 1
    if not plan.cambios:
        if opciones.iphone:
            salida("«%s» ya está en la pasarela. Su QR no se puede volver a pintar; para uno nuevo (y que el de antes "
                   "deje de valer), desde tu terminal: %shehermes-dispositivo rotar %s"
                   % (opciones.iphone, "sudo " if ambito.root else "", opciones.iphone))
        return 0
    if not _pregunta_si(entrada, salida, terminal, opciones.si):
        salida("No he cambiado nada.")
        return 1
    try:
        hecho = modo_tls.aplicar_tls(sis, plan, man, aqui, salida=salida, terminal=terminal)
        el_enlace = None
        if opciones.por_chat:
            token = hecho.get("token")
            if token is None:
                # Repetido en la media hora, sin canjear: del token solo queda el hash, así que va uno nuevo.
                from . import tokens
                token = tokens.rotar(sis.ruta(ambito.tokens), opciones.iphone)
            carga = porchat.carga_tls(det.direccion, det.puerto_pasarela, modo_tls.huella(sis, ambito), token)
            del token
            el_enlace = porchat.lanzar(sis, man, det, opciones, salida, carga=carga, ambito=ambito)
            del carga
    except (Parada, porchat.ParadaDelCanje) as parada:
        salida("\nerror: %s\nLo que ya estaba hecho se queda apuntado: arréglalo y vuelve a lanzar el mismo comando."
               % parada)
        return 1
    salida("\nHecho. «%s comprobar» lo repasa cuando quieras." % ("sudo hehermes-servidor" if ambito.root
                                                                       else ambito.orden))
    if any(a.tipo in ("env", "exposicion") and a.cambia for a in plan.acciones):
        # Lo último: reiniciar Hermes antes de acabar le cortaría el turno en el que contesta con el enlace.
        porchat.reiniciar_hermes_luego(sis, salida)
    if el_enlace:
        salida("\nEl enlace para la app (caduca en 10 minutos y no lleva ninguna clave):")
        salida(el_enlace)
    return 0


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


def _canje_limpiar(op, sis, man, aqui, entrada, salida, terminal, ambito):
    from .porchat import limpiar
    limpiar(sis, os.environ, ambito)
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
    ruta_clave = sis.ruta(p.PREFIJO + "/clave-publica.pem")
    clave = sis.leer_texto(p.PREFIJO + "/clave-publica.pem") or ""
    if firma.pendiente(clave):
        salida("error: la clave pública de este paquete es el marcador (%s): no hay firma que comprobar, así que no "
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
        if not firma.verificar(sis, paquete, sello, ruta_clave):
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
