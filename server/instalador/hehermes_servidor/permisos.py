"""Los permisos, antes que nada (el encargo de Daniel del 2026-09-26): root, sudo sin contraseña, o parar en seco.

Por chat es Hermes quien lanza el instalador, y Hermes puede no correr como root ni tener sudo. Por eso la frase lo
lanza sin `sudo` delante (si no, `sudo` pediría una contraseña que nadie puede escribir, y fallaría antes de que el
instalador pudiera explicar nada), y el instalador mira primero qué puede hacer:

- root: sigue;
- `sudo -n true` sale bien (sudo sin contraseña): se relanza a sí mismo con `sudo -n`;
- sudo solo para el instalador ya instalado (`/usr/local/sbin/hehermes-servidor`, de root, la salida 2): se relanza
  con ese, si es de esta misma versión;
- nada de eso: `instalar` pone la pasarela como el usuario, en su casa, que no necesita root (`cli._sin_root`); lo demás
  (y un `instalar` cuya casa no se puede usar) para sin tocar nada y explica las salidas.

Hasta la 0.6.0, sin root ni sudo la VPN (`--modo vpn`) se paraba aquí y, por chat, acababa con la línea
`hehermes-error:sin-permisos` para la app. La VPN ya no existe, y esa línea ya no sale nunca.

Nunca se pide ni se prueba una contraseña: `-n` hace que sudo falle en vez de preguntar.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex

from . import URL_BASE, VERSION

INSTALADO = "/usr/local/sbin/hehermes-servidor"
VERSION_INSTALADA = "/opt/hehermes-servidor/hehermes_servidor/__init__.py"
SUDOERS = "/etc/sudoers.d/hehermes-servidor"
_USUARIO = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def sondear_sudo(sis) -> str:
    """«sin-contrasena», «contrasena», «no-permitido» o «sin-sudo». Con LC_ALL=C (lo pone `Sistema`), sudo habla en
    inglés y sus mensajes se pueden leer."""
    r = sis.ejecutar(["sudo", "-n", "true"])
    if r.bien:
        return "sin-contrasena"
    if r.codigo == 127:
        return "sin-sudo"
    if "password is required" in (r.error + r.salida).lower():
        return "contrasena"
    return "no-permitido"


def instalado_permitido(sis) -> bool:
    """Si hay un instalador instalado y sudo deja lanzarlo sin contraseña (`sudo -n -l <orden>` sale bien solo si esa
    orden está permitida)."""
    if not sis.existe(INSTALADO):
        return False
    return sis.ejecutar(["sudo", "-n", "-l", INSTALADO]).bien


def version_instalada(sis) -> str | None:
    hallado = re.search(r'^VERSION = "([^"]+)"', sis.leer_texto(VERSION_INSTALADA) or "", re.M)
    return hallado.group(1) if hallado else None


def decidir(euid: int, sudo: str, instalado: bool) -> str:
    """«root», «sudo» (relanzarse con sudo -n), «instalado» (relanzar el de /usr/local/sbin) o «nada»."""
    if euid == 0:
        return "root"
    if sudo == "sin-contrasena":
        return "sudo"
    if instalado:
        return "instalado"
    return "nada"


def orden_relanzada(programa: str, argv: list, python: bool = True) -> list:
    """`-u root` por si el sudoers cambia el usuario por defecto; `--` para que nada de lo de detrás sea de sudo. El
    Python es el del sistema, nunca el de quien lo lanza: lo que corre como root no puede venir de su carpeta."""
    return (["sudo", "-n", "-u", "root", "--"] + (["/usr/bin/python3", "-I", "-B"] if python else []) + [programa]
            + list(argv))


def linea_sudoers(usuario: str) -> str:
    return "%s ALL=(root) NOPASSWD: %s" % (usuario if _USUARIO.match(usuario or "") else "<tu-usuario>", INSTALADO)


def comando_del_administrador(aqui: str, argv: list) -> str:
    """El mismo comando, con sudo, para quien administra el servidor. Si el paquete está al lado (la frase lo deja
    ahí), el comando entero: bajarlo otra vez a una carpeta suya y comprobar la suma, para que el administrador no
    ejecute como root nada de la carpeta de otro usuario. Si no, la parte de después de comprobar la suma."""
    carpeta = os.path.basename(aqui.rstrip("/"))
    if not re.match(r"^hehermes-servidor-\d+\.\d+\.\d+$", carpeta):
        carpeta = "hehermes-servidor-%s" % VERSION
    orden = "sudo ./%s/hehermes-servidor %s" % (carpeta, " ".join(shlex.quote(a) for a in argv))
    fichero = carpeta + ".tar.gz"
    try:
        with open(os.path.join(os.path.dirname(aqui.rstrip("/")), fichero), "rb") as f:
            suma = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return orden
    version = carpeta[len("hehermes-servidor-"):]
    return ('d=$(mktemp -d) && cd "$d" && curl -fsSLO %s/v%s/%s && echo "%s  %s" | sha256sum -c - && tar -xzf %s'
            ' && %s' % (URL_BASE, version, fichero, suma, fichero, fichero, orden))


_MOTIVOS = {
    "sin-sudo": "No corro como root, y en este servidor no hay sudo.",
    "contrasena": "No corro como root, y sudo me pide una contraseña. No la pido ni la intento: por chat nadie puede "
                  "escribirla, y una contraseña no tiene que pasar por aquí.",
    "no-permitido": "No corro como root, y el usuario «%s» no puede usar sudo.",
}


def mensaje(sudo: str, usuario: str, aqui: str, argv: list, por_chat: bool, otra_version: str | None = None) -> list:
    """Las líneas del «no puedo»: qué falta, qué no se ha hecho y las salidas, en este orden. Por chat lo lee Hermes y
    se lo cuenta al usuario."""
    motivo = _MOTIVOS.get(sudo, _MOTIVOS["no-permitido"])
    if "%s" in motivo:
        motivo = motivo % usuario
    lineas = ["error: me faltan permisos de administrador (root), y sin ellos no puedo instalar nada.",
              "No he hecho nada: este servidor está exactamente como estaba.",
              "", motivo]
    if otra_version:
        lineas.append("Puedo usar sudo con %s, pero es la versión %s y esta es la %s: no la uso."
                      % (INSTALADO, otra_version, VERSION))
    lineas += [
        "", "Para seguir, una de estas:",
        "  1. Que quien administre este servidor entre por SSH y ejecute este mismo comando, con sudo:",
        "       " + comando_del_administrador(aqui, argv),
        "  2. Que le dé a «%s» permiso de sudo solo para el instalador. Tiene que instalarlo antes una vez (con el "
        "comando de arriba, o con el de la app sin --iphone) y añadir, con «sudo visudo -f %s», esta línea:" % (
            usuario, SUDOERS),
        "       " + linea_sudoers(usuario),
        "     Después, en la media hora siguiente a instalar, vuelve a lanzarme." if por_chat else
        "     Después, vuelve a lanzarme.",
    ]
    return lineas
