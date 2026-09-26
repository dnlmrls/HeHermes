"""Las órdenes de hehermes-servidor. Solo cablean: la decisión está en detección, plan, aplicar y desinstalar."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tarfile
import tempfile

from . import VERSION, firma, permisos
from . import piezas as p
from .aplicar import Parada, aplicar, comprobar
from .desinstalar import desinstalar, resumen
from .deteccion import DIRECCION_VALIDA, detectar
from .manifiesto import Manifiesto, ManifiestoRoto
from .plan import Opciones, calcular_plan, pintar
from .sistema import Sistema

SI = ("s", "si", "sí")


class SalirConUso(Exception):
    pass


class Analizador(argparse.ArgumentParser):
    def error(self, mensaje):
        raise SalirConUso(mensaje)


def _analizador():
    a = Analizador(prog="hehermes-servidor", add_help=True)
    ordenes = a.add_subparsers(dest="orden")
    i = ordenes.add_parser("instalar")
    i.add_argument("--plan", action="store_true", help="enseña lo que haría, sin cambiar nada")
    i.add_argument("--iphone", help="da de alta este iPhone y pinta su QR")
    i.add_argument("--direccion", help="la dirección pública del servidor (la del QR)")
    i.add_argument("--avisos", action="store_true", help="instala también los avisos push (server/avisos)")
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
    u = ordenes.add_parser("actualizar")
    u.add_argument("--paquete", required=True)
    u.add_argument("--firma", required=True)
    d = ordenes.add_parser("desinstalar")
    d.add_argument("--si", action="store_true")
    d.add_argument("--quitar-paquetes", action="store_true")
    return a


def main(argv, doc, aqui, sis=None, entrada=input, salida=print, terminal=None, euid=None, relanzar=None,
         usuario=None) -> int:
    try:
        op = _analizador().parse_args(argv)
    except SalirConUso as error:
        salida("error: %s\n\n%s" % (error, doc.strip()))
        return 2
    if op.orden is None:
        salida(doc.strip())
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
    if euid != 0:
        return _sin_root(op, argv, sis, aqui, salida, relanzar or _relanzar_de_verdad, usuario or _usuario())
    terminal = sys.stdin.isatty() and sys.stdout.isatty() if terminal is None else terminal
    os.umask(0o022)
    try:
        man = Manifiesto.leer(sis)
    except ManifiestoRoto as error:
        salida("error: %s" % error)
        return 1
    orden = {"instalar": _instalar, "comprobar": _comprobar, "actualizar": _actualizar,
             "desinstalar": _desinstalar, "canje-limpiar": _canje_limpiar, "cortafuegos": _cortafuegos}[op.orden]
    if op.orden in ("comprobar", "canje-limpiar", "cortafuegos") or getattr(op, "plan", False):
        # canje-limpiar tampoco: corre dentro del `systemctl stop` de un instalar que ya tiene el cerrojo.
        # Lo que solo lee no toma el cerrojo: --plan no deja ni un fichero en /run.
        return orden(op, sis, man, aqui, entrada, salida, terminal)
    with _cerrojo(sis):
        return orden(op, sis, man, aqui, entrada, salida, terminal)


def _sin_root(op, argv, sis, aqui, salida, relanzar, usuario) -> int:
    """Lo primero de todo, antes de detectar nada: sin root, o se relanza con `sudo -n` o se para sin tocar nada."""
    sudo = permisos.sondear_sudo(sis)
    permitido = sudo != "sin-contrasena" and permisos.instalado_permitido(sis)
    instalada = permisos.version_instalada(sis) if permitido else None
    como = permisos.decidir(1, sudo, permitido and instalada == VERSION)
    if como in ("sudo", "instalado"):
        orden = (permisos.orden_relanzada(os.path.join(aqui, "hehermes-servidor"), argv) if como == "sudo" else
                 permisos.orden_relanzada(permisos.INSTALADO, argv, python=False))
        codigo = relanzar(orden)
        return 0 if codigo is None else codigo
    for linea in permisos.mensaje(sudo, usuario, aqui, argv, bool(getattr(op, "por_chat", False)),
                                  otra_version=instalada if permitido else None):
        salida(linea)
    return 1


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

    def __init__(self, sis):
        self.sis, self.fichero = sis, None

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


def _instalar(op, sis, man, aqui, entrada, salida, terminal):
    opciones = Opciones(iphone=op.iphone, direccion=op.direccion, avisos=op.avisos, hermes_home=op.hermes_home,
                        reemplazar=op.reemplazar, si=op.si or op.por_chat, solo_plan=op.plan, por_chat=op.por_chat,
                        llave=op.llave, activar_api=op.activar_api, qr_png=op.qr_png,
                        cortafuegos_a_mano=op.cortafuegos_a_mano, corregir_exposicion=op.corregir_exposicion)
    if op.por_chat:
        # Lo lanza Hermes: no hay nadie a quien preguntar.
        terminal = False
    det = detectar(sis, man, direccion=opciones.direccion, hermes_home=opciones.hermes_home,
                   activar_api=opciones.activar_api, cortafuegos_a_mano=opciones.cortafuegos_a_mano,
                   corregir_exposicion=opciones.corregir_exposicion)
    if det.direccion_privada and terminal and not op.plan:
        # Detrás de un NAT: la de salida no es la que va en el QR. Solo se pregunta en un terminal.
        try:
            dada = entrada("Este servidor sale por una dirección privada. ¿Cuál es su dirección pública (IP o nombre)? ")
        except EOFError:
            dada = ""
        if DIRECCION_VALIDA.match(dada.strip()):
            opciones.direccion = dada.strip()
            det = detectar(sis, man, direccion=opciones.direccion, hermes_home=opciones.hermes_home,
                           activar_api=opciones.activar_api, cortafuegos_a_mano=opciones.cortafuegos_a_mano,
                           corregir_exposicion=opciones.corregir_exposicion)
    plan = calcular_plan(sis, det, man, opciones, aqui)
    salida(pintar(plan, color=terminal).rstrip("\n"))
    if op.plan or not plan.puede_seguir:
        return 0 if plan.puede_seguir else 1
    if not plan.cambios:
        if opciones.iphone:
            salida("Para volver a pintar el QR de «%s», desde tu terminal:  sudo hehermes-dispositivo qr %s"
                   % (opciones.iphone, opciones.iphone))
        return 0
    if not _pregunta_si(entrada, salida, terminal, opciones.si):
        salida("No he cambiado nada.")
        return 1
    from . import porchat
    try:
        aplicar(sis, plan, man, aqui, salida=salida)
        el_enlace = porchat.lanzar(sis, man, det, opciones, salida) if opciones.por_chat else None
    except (Parada, porchat.ParadaDelCanje) as parada:
        salida("\nerror: %s\nLo que ya estaba hecho se queda apuntado: arréglalo y vuelve a lanzar el mismo comando."
               % parada)
        return 1
    salida("\nHecho. «sudo hehermes-servidor comprobar» lo repasa cuando quieras.")
    if any(a.tipo in ("env", "exposicion") and a.cambia for a in plan.acciones):
        # Lo último: reiniciar Hermes antes de acabar le cortaría el turno en el que contesta con el enlace.
        porchat.reiniciar_hermes_luego(sis, salida)
    if el_enlace:
        salida("\nEl enlace para la app (caduca en 10 minutos y no lleva ninguna clave):")
        salida(el_enlace)
    return 0


def _comprobar(op, sis, man, aqui, entrada, salida, terminal):
    from . import seguridad
    resultados = comprobar(sis, man)
    for bien, texto in resultados:
        salida("  %-5s %s" % ("bien" if bien else "MAL", texto))
    salida("")
    salida("Seguridad")
    revision = seguridad.revisar(sis, man)
    for estado, texto in revision:
        salida("  %-5s %s" % ("MAL" if estado == seguridad.MAL else estado, texto))
    return 0 if all(bien for bien, _ in resultados) and all(e != seguridad.MAL for e, _ in revision) else 1


def _canje_limpiar(op, sis, man, aqui, entrada, salida, terminal):
    from .porchat import limpiar
    limpiar(sis, os.environ)
    return 0


def _cortafuegos(op, sis, man, aqui, entrada, salida, terminal):
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
            lugares = cf.poner(sis, cf.MARCA, cf.permanentes(), propio.get("iptables", True))
            salida("reglas de HeHermes en: %s" % (", ".join(l.nombre for l in lugares) or "ninguna cadena cierra"))
        porchat.volver_a_abrir(sis, propio)
    except cf.NoSe as error:
        salida("error: no pongo las reglas de HeHermes: %s" % error)
        return 1
    return 0


def _actualizar(op, sis, man, aqui, entrada, salida, terminal):
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
        orden = ["python3", "-I", lanzador, "instalar", "--si"] + (["--avisos"] if man.datos.get("avisos") else [])
        return sis.ejecutar(orden, heredar=True).codigo
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


def _desinstalar(op, sis, man, aqui, entrada, salida, terminal):
    salida(resumen(sis, man).rstrip("\n"))
    if not man.en_disco:
        return 0
    if not _pregunta_si(entrada, salida, terminal, op.si):
        salida("No he quitado nada.")
        return 1
    quedan = desinstalar(sis, man, quitar_paquetes=op.quitar_paquetes, salida=salida)
    salida("\nHecho." + (" Lo que se queda está arriba." if quedan else " El servidor está como antes de instalar."))
    return 0
