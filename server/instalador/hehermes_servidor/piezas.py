"""Lo que el instalador deja en el servidor, como texto, y dónde. Funciones puras: ni leen ni escriben nada.

Todo lleva nombre `hehermes-*` o vive en `/etc/hehermes*` o `/opt/hehermes*` (spec, «Cómo no pisa nunca lo del
usuario»).

Desde la 0.6.0 solo se instala la pasarela. De la VPN IKEv2 de antes quedan aquí sus rutas, sus reglas y el agujero
del túnel: lo que hace falta para reconocer lo que dejó (`modos`, «Seguridad») y quitarlo (`desinstalar --modo vpn`).
Lo que la escribía ya no está.
"""

from __future__ import annotations

import ipaddress
import re

PREFIJO = "/opt/hehermes-servidor"
ORDEN = "/usr/local/sbin/hehermes-servidor"
DISPOSITIVO = "/usr/local/sbin/hehermes-dispositivo"
CARPETA = "/etc/hehermes"

CABECERA = "# Lo escribe hehermes-servidor. No lo edites a mano: el instalador se para si lo encuentra cambiado.\n"
_RUTA_VALIDA = re.compile(r"^/[A-Za-z0-9._/@+-]+$")
_DIRECCION_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")


def _ruta_segura(ruta: str) -> str:
    if not _RUTA_VALIDA.fullmatch(ruta):
        raise ValueError("ruta que no sé poner en una unidad de systemd: %r" % ruta)
    return ruta


# MARK: La VPN IKEv2 de antes de la 0.6.0: dónde dejó cada cosa

#: Las direcciones que la app llevaba fijas: `10.77.0.1` era Hermes dentro del túnel, y los iPhone salían de
#: `10.77.1.0/24`.
IP_TUNEL = "10.77.0.1"
RED_IPHONES = "10.77.1.0/24"
RED_HEHERMES = "10.77.0.0/16"
INTERFAZ = "hh-ipsec"
IF_ID = "0x77"
SCRIPT_XFRM = "/usr/local/sbin/hehermes-xfrm"
SERVIDOR_INI = "/etc/hehermes/servidor.ini"
REGISTRO = "/etc/hehermes/dispositivos"
UNIDAD_XFRM = "/etc/systemd/system/hehermes-xfrm.service"
UNIDAD_CLAVE_PATH = "/etc/systemd/system/hehermes-clave.path"
UNIDAD_CLAVE_SERVICE = "/etc/systemd/system/hehermes-clave.service"
DROP_IN_NGINX = "/etc/systemd/system/nginx.service.d/hehermes-xfrm.conf"
SITIO = "/etc/nginx/sites-available/hehermes-tunel"
SITIO_ENLACE = "/etc/nginx/sites-enabled/hehermes-tunel"
SITIO_CONF_D = "/etc/nginx/conf.d/hehermes-tunel.conf"
BEARER = "/etc/nginx/hehermes-bearer.conf"
#: El sitio de bienvenida de nginx, que la VPN apagaba si instalaba nginx (y desinstalar lo devuelve).
DEFAULT_NGINX = "/etc/nginx/sites-enabled/default"


def _decide(reglas, origen: str) -> str:
    ip = ipaddress.ip_address(origen)
    for accion, red in reglas:
        if red == "all":
            return accion
        try:
            neta = ipaddress.ip_network(red, strict=False)
        except ValueError:
            continue
        if neta.version == ip.version and ip in neta:
            return accion
    return "allow"


def _bloque(texto: str, cabecera_regex: str) -> str | None:
    inicio = re.search(cabecera_regex + r"\s*\{", texto)
    if not inicio:
        return None
    nivel, i = 1, inicio.end()
    while nivel and i < len(texto):
        nivel += {"{": 1, "}": -1}.get(texto[i], 0)
        i += 1
    return texto[inicio.end():i - 1]


def agujero_abierto(texto_sitio: str) -> bool:
    """Si el sitio del túnel deja que el propio servidor (10.77.0.1) use la clave de Hermes: nginx se la ponía a todo
    lo que le llegaba a 10.77.0.1:80, y los procesos del servidor llegan desde esa dirección."""
    limpio = re.sub(r"#[^\n]*", "", texto_sitio)
    location = _bloque(limpio, r"location\s+/(?=\s*\{)")
    if location is None:
        return True
    # Solo las reglas de este nivel: las de una location anidada no cuentan para `/`.
    plano = re.sub(r"\{[^{}]*\}", "", location)
    reglas = re.findall(r"(?:^|[;{\s])(allow|deny)\s+([^;\s]+)\s*;", plano)
    return _decide(reglas, IP_TUNEL) == "allow"


# MARK: El cortafuegos, tras un reinicio


UNIDAD_CORTAFUEGOS = "/etc/systemd/system/hehermes-cortafuegos.service"
_ORDEN_PYTHON = "/usr/bin/python3 -I -B %s/hehermes-servidor" % PREFIJO
#: Lo que carga el cortafuegos del sistema al arrancar: nftables.conf, rules.v4 (iptables-persistent) o
#: /etc/sysconfig/iptables. La unidad va detrás, y con ellos: si se reinician o se recargan (y vacían todo), vuelve a
#: poner las suyas.
_DEL_SISTEMA = "nftables.service netfilter-persistent.service iptables.service"


def unidad_cortafuegos() -> str:
    return (
        CABECERA
        + "# Al arrancar, después del cortafuegos del sistema: vuelve a poner las reglas de HeHermes en nftables o\n"
        "# iptables (sin escribir en lo que guarda el usuario) y quita la del canje si un reinicio la dejó en ufw.\n"
        "[Unit]\n"
        "Description=HeHermes: sus reglas del cortafuegos\n"
        "After=%s ufw.service firewalld.service\n"
        "PartOf=%s\n"
        "ReloadPropagatedFrom=%s\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=%s cortafuegos poner\n"
        "ExecReload=%s cortafuegos poner\n"
        "ExecStop=%s cortafuegos quitar\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % (_DEL_SISTEMA, _DEL_SISTEMA, _DEL_SISTEMA, _ORDEN_PYTHON, _ORDEN_PYTHON, _ORDEN_PYTHON)


# MARK: ufw


class ReglaUfw:
    __slots__ = ("nombre", "args")

    def __init__(self, nombre: str, args: list):
        self.nombre, self.args = nombre, args

    @property
    def texto(self) -> str:
        return "ufw " + " ".join(self.args)

    def __repr__(self):
        return "ReglaUfw(%r)" % self.texto


def reglas_ufw(modo: str, puerto: int | None = None) -> list:
    """TLS: solo el TCP de la pasarela. VPN (la de antes, para reconocer sus reglas al quitarla): el UDP de IKE abierto
    a internet y el TCP 80, solo por hh-ipsec y hacia 10.77.0.1."""
    if modo == "tls":
        return [ReglaUfw("TCP %d (la pasarela)" % _puerto_pasarela(puerto),
                         ["allow", "proto", "tcp", "from", "any", "to", "any", "port", str(puerto), "comment",
                          "hehermes"])]
    return [
        ReglaUfw("UDP 500 y 4500 (IKEv2)",
                 ["allow", "proto", "udp", "from", "any", "to", "any", "port", "500,4500", "comment", "hehermes"]),
        ReglaUfw("TCP 80 solo por %s hacia %s" % (INTERFAZ, IP_TUNEL),
                 ["allow", "in", "on", INTERFAZ, "proto", "tcp", "from", "any", "to", IP_TUNEL, "port", "80",
                  "comment", "hehermes"]),
    ]


# MARK: firewalld


class ReglaFirewalld:
    """Una regla de firewalld, en la zona por defecto."""

    __slots__ = ("nombre", "opcion")

    def __init__(self, nombre: str, opcion: str):
        self.nombre, self.opcion = nombre, opcion

    @property
    def texto(self) -> str:
        return "firewall-cmd " + self.opcion

    def con(self, verbo: str) -> str:
        """La misma opción con otro verbo: `query` para mirarla, `remove` para quitarla."""
        return self.opcion.replace("--add-", "--%s-" % verbo, 1)

    def __repr__(self):
        return "ReglaFirewalld(%r)" % self.opcion


def reglas_firewalld(modo: str, puerto: int | None = None) -> list:
    """Lo mismo que las de ufw. La VPN de antes: firewalld no sabe de «entra por hh-ipsec», así que el TCP 80 iba solo
    desde los iPhone y hacia 10.77.0.1."""
    if modo == "tls":
        return [ReglaFirewalld("TCP %d (la pasarela)" % _puerto_pasarela(puerto), "--add-port=%d/tcp" % puerto)]
    return [
        ReglaFirewalld("UDP 500 (IKEv2)", "--add-port=500/udp"),
        ReglaFirewalld("UDP 4500 (IKEv2 tras un NAT)", "--add-port=4500/udp"),
        ReglaFirewalld("TCP 80 solo desde %s hacia %s" % (RED_IPHONES, IP_TUNEL),
                       '--add-rich-rule=rule family="ipv4" source address="%s" destination address="%s/32" '
                       'port port="80" protocol="tcp" accept' % (RED_IPHONES, IP_TUNEL)),
    ]


def regla_firewalld_de(texto: str):
    """La regla de un texto del manifiesto (`firewall-cmd --add-…`), o None si no es de firewalld."""
    if not texto.startswith("firewall-cmd --add-"):
        return None
    return ReglaFirewalld(texto, texto[len("firewall-cmd "):])


# MARK: La pasarela TLS (spec 2026-09-26)

#: El puerto de la pasarela, al azar en este rango (los dos entran): el mismo que el del canje.
PUERTO_MINIMO, PUERTO_MAXIMO = 58000, 65500
USUARIO_PASARELA = "hh-pasarela"
UNIDAD_PASARELA = "hehermes-pasarela.service"
UNIDAD_PASARELA_CLAVE_PATH = "/etc/systemd/system/hehermes-pasarela-clave.path"
UNIDAD_PASARELA_CLAVE_SERVICE = "/etc/systemd/system/hehermes-pasarela-clave.service"
SECRETO_VIGIA = "/etc/hehermes-avisos/vigia/secreto-tunel"
VIGIA = "127.0.0.1:8790"


def _puerto_pasarela(puerto) -> int:
    if not isinstance(puerto, int) or isinstance(puerto, bool) or not PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO:
        raise ValueError("puerto de la pasarela fuera de %d-%d: %r" % (PUERTO_MINIMO, PUERTO_MAXIMO, puerto))
    return puerto


def unidad_pasarela(ambito, con_vigia: bool) -> str:
    """Con root: un usuario propio sin ningún privilegio (el puerto es alto), el sistema de ficheros de solo lectura, y
    los secretos (la clave del certificado, la de Hermes y el del vigía) como credenciales de systemd, que los copia
    desde ficheros de root. Sin root: una unidad de usuario, con lo que un usuario puede ponerse (sin espacios de
    nombres: un gestor de usuario puede no tenerlos)."""
    orden = "%s -I -B %s/hehermes-pasarela --config %s" % (_ruta_segura(ambito_python()), _ruta_segura(ambito.prefijo),
                                                           _ruta_segura(ambito.pasarela_ini))
    comun = (
        "NoNewPrivileges=yes\n"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
        "RestrictRealtime=yes\n"
        "RestrictSUIDSGID=yes\n"
        "LockPersonality=yes\n"
        "MemoryDenyWriteExecute=yes\n"
        "SystemCallArchitectures=native\n"
        "SystemCallFilter=@system-service\n"
        "SystemCallFilter=~@privileged @resources\n"
        "UMask=0077\n"
    )
    if not ambito.root:
        return (
            CABECERA
            + "# La pasarela TLS de HeHermes (server/API-CONTRACT.md, §12), como el usuario de Hermes: lee su .env.\n"
            "[Unit]\n"
            "Description=HeHermes: la pasarela TLS hacia Hermes\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=%s\n"
            "Restart=on-failure\n"
            "RestartSec=2\n"
            "%s"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        ) % (orden, comun)
    credenciales = ("LoadCredential=clave:%s\nLoadCredential=hermes:%s\n" % (ambito.clave, ambito.clave_hermes)
                    + ("LoadCredential=vigia:%s\n" % SECRETO_VIGIA if con_vigia else ""))
    return (
        CABECERA
        + "# La pasarela TLS de HeHermes (server/API-CONTRACT.md, §12). Corre como %s, sin ningún privilegio: el\n"
        "# puerto es alto, y la clave del certificado y la de Hermes le llegan como credenciales de systemd.\n"
        "[Unit]\n"
        "Description=HeHermes: la pasarela TLS hacia Hermes\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=%s\n"
        "Group=%s\n"
        "ExecStart=%s\n"
        "%s"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "CapabilityBoundingSet=\n"
        "AmbientCapabilities=\n"
        "ProtectSystem=strict\n"
        "ProtectHome=yes\n"
        "PrivateTmp=yes\n"
        "PrivateDevices=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectKernelLogs=yes\n"
        "ProtectControlGroups=yes\n"
        "ProtectClock=yes\n"
        "ProtectHostname=yes\n"
        "ProtectProc=invisible\n"
        "RestrictNamespaces=yes\n"
        "%s"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % (USUARIO_PASARELA, USUARIO_PASARELA, USUARIO_PASARELA, orden, credenciales, comun)


def ambito_python() -> str:
    from .ambito import PYTHON
    return PYTHON


def unidad_pasarela_clave_path(env: str) -> str:
    return (
        CABECERA
        + "# Si cambia la clave del api_server en el .env de Hermes, se copia a la pasarela y se reinicia.\n"
        "[Unit]\n"
        "Description=HeHermes: vigila la clave del api_server de Hermes, para la pasarela\n"
        "\n"
        "[Path]\n"
        "PathChanged=%s\n"
        "Unit=hehermes-pasarela-clave.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % _ruta_segura(env)


def unidad_pasarela_clave_service() -> str:
    return (
        CABECERA
        + "[Unit]\n"
        "Description=HeHermes: copia la clave del api_server a la pasarela\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=%s pasarela-clave\n"
    ) % _ORDEN_PYTHON


def pasarela_ini(ambito, puerto: int, puerto_hermes: int, env: str, direccion: str, vigia: bool) -> str:
    """Lo que lee la pasarela (`pasarela.Configuracion`) y `hehermes-dispositivo` (la dirección del QR y dónde está el
    código). Con root, la clave de Hermes es una copia suya (`clave-hermes`, 0600); sin root, el .env mismo."""
    _puerto_pasarela(puerto)
    if not isinstance(puerto_hermes, int) or not 0 < puerto_hermes < 65536:
        raise ValueError("puerto de Hermes no válido: %r" % (puerto_hermes,))
    if not _DIRECCION_VALIDA.fullmatch(direccion or ""):
        raise ValueError("dirección del servidor no válida: %r" % direccion)
    texto = (
        CABECERA
        + "# Lo leen hehermes-pasarela y hehermes-dispositivo.\n"
        "[pasarela]\n"
        "puerto = %d\n"
        "# Vacío: todas las direcciones (IPv4 e IPv6).\n"
        "escucha =\n"
        "certificado = %s\n"
        "clave = %s\n"
        "tokens = %s\n"
        "\n"
        "[hermes]\n"
        "puerto = %d\n"
        "clave = %s\n"
        "env = %s\n"
    ) % (puerto, _ruta_segura(ambito.cert), _ruta_segura(ambito.clave), _ruta_segura(ambito.tokens), puerto_hermes,
         _ruta_segura(ambito.clave_hermes if ambito.root else env), _ruta_segura(env))
    if vigia:
        texto += "\n[avisos]\nvigia = %s\nsecreto = %s\n" % (VIGIA, SECRETO_VIGIA)
    texto += ("\n[qr]\n# La que va en el QR de cada iPhone.\ndireccion = %s\n\n[instalador]\ncodigo = %s\n"
              % (direccion, _ruta_segura(ambito.prefijo)))
    return texto
