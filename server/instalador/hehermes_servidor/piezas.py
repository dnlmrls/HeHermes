"""Lo que el instalador deja en el servidor, como texto. Funciones puras: ni leen ni escriben nada.

Todo lleva nombre `hehermes-*` o vive en `/etc/hehermes/` o `/opt/hehermes*` (spec, «Cómo no pisa nunca lo del
usuario»). Las direcciones son las que la app lleva fijas: `10.77.0.1` es Hermes, y los iPhone salen de `10.77.1.0/24`.
"""

from __future__ import annotations

import ipaddress
import re

IP_TUNEL = "10.77.0.1"
RED_IPHONES = "10.77.1.0/24"
RED_HEHERMES = "10.77.0.0/16"
INTERFAZ = "hh-ipsec"
IF_ID = "0x77"

PREFIJO = "/opt/hehermes-servidor"
ORDEN = "/usr/local/sbin/hehermes-servidor"
DISPOSITIVO = "/usr/local/sbin/hehermes-dispositivo"
SCRIPT_XFRM = "/usr/local/sbin/hehermes-xfrm"
CARPETA = "/etc/hehermes"
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
DEFAULT_NGINX = "/etc/nginx/sites-enabled/default"

CABECERA = "# Lo escribe hehermes-servidor. No lo edites a mano: el instalador se para si lo encuentra cambiado.\n"
_RUTA_VALIDA = re.compile(r"^/[A-Za-z0-9._/@+-]+$")
_DIRECCION_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")


# MARK: La regla que cierra el túnel


def reglas_de_acceso(permitidas=(RED_IPHONES,)) -> list:
    """Las reglas de `location /`, en el orden en que nginx las mira (gana la primera que abarca el origen).

    nginx pone la clave de Hermes a todo lo que le llega a 10.77.0.1:80. Los procesos del propio servidor llegan desde
    10.77.0.1 (es su dirección en ese camino), así que sin esto cualquier usuario del servidor tendría la API entera:
    es el agujero que sigue abierto en el VPS de Daniel. El `deny` del servidor va delante de todo, para que siga
    cerrado aunque un día se abra más red; y el `deny all` cierra cualquier otro origen que se pueda atar a mano."""
    red_hehermes = ipaddress.ip_network(RED_HEHERMES)
    reglas = [("deny", IP_TUNEL)]
    for red in permitidas:
        try:
            neta = ipaddress.ip_network(red)
        except ValueError:
            raise ValueError("red no válida para el túnel: %s" % red)
        if neta.version != 4 or not neta.subnet_of(red_hehermes):
            raise ValueError("solo se deja entrar a redes del túnel (%s), no a %s" % (RED_HEHERMES, red))
        reglas.append(("allow", str(neta)))
    reglas.append(("deny", "all"))
    return reglas


def texto_reglas(reglas, sangria: str = "        ") -> str:
    return "".join("%s%s %s;\n" % (sangria, accion, red) for accion, red in reglas)


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
    """Si el sitio del túnel deja que el propio servidor (10.77.0.1) use la clave de Hermes."""
    limpio = re.sub(r"#[^\n]*", "", texto_sitio)
    location = _bloque(limpio, r"location\s+/(?=\s*\{)")
    if location is None:
        return True
    # Solo las reglas de este nivel: las de una location anidada no cuentan para `/`.
    plano = re.sub(r"\{[^{}]*\}", "", location)
    reglas = re.findall(r"(?:^|[;{\s])(allow|deny)\s+([^;\s]+)\s*;", plano)
    return _decide(reglas, IP_TUNEL) == "allow"


# MARK: nginx


def sitio_nginx(puerto_hermes) -> str:
    if not isinstance(puerto_hermes, int) or not 0 < puerto_hermes < 65536:
        raise ValueError("puerto de Hermes no válido: %r" % (puerto_hermes,))
    return (
        CABECERA
        + "# HeHermes: el api_server de Hermes, solo dentro del túnel IKEv2. Escucha únicamente en %s (hh-ipsec), y ufw\n"
        "# solo deja entrar a este puerto por hh-ipsec. nginx añade la clave del api_server (hehermes-bearer.conf, 0600,\n"
        "# la escribe `hehermes-dispositivo clave`) y sustituye cualquier Authorization del cliente: la credencial del\n"
        "# iPhone es su clave IKEv2.\n"
        "server {\n"
        "    listen %s:80;\n"
        "    server_name _;\n"
        "\n"
        "    access_log /var/log/nginx/hehermes-tunel.access.log;\n"
        "    error_log  /var/log/nginx/hehermes-tunel.error.log;\n"
        "\n"
        "    # Fotos por /v1/runs (base64 dentro del JSON).\n"
        "    client_max_body_size 25m;\n"
        "\n"
        "    # El JSON del historial, comprimido; el SSE (text/event-stream) no, para que llegue token a token.\n"
        "    gzip_types application/json;\n"
        "    gzip_proxied any;\n"
        "    gzip_min_length 1024;\n"
        "    gzip_comp_level 5;\n"
        "    gzip_vary on;\n"
        "\n"
        "    # Los avisos (server/avisos), si están instalados: su location /avisos/ lleva sus propias reglas.\n"
        "    include /etc/nginx/hehermes-avisos/sitio/*.conf;\n"
        "\n"
        "    location / {\n"
        "        # Solo los iPhone. El propio servidor llega desde %s: sin el primer deny, cualquier proceso de\n"
        "        # esta máquina tendría la API de Hermes con su clave.\n"
        "%s"
        "\n"
        "        proxy_pass http://127.0.0.1:%d;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Connection \"\";\n"
        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
        "        include %s;\n"
        "\n"
        "        # SSE de /v1/runs/{id}/events: sin búfer y con conexiones largas.\n"
        "        proxy_buffering off;\n"
        "        proxy_cache off;\n"
        "        proxy_read_timeout 1h;\n"
        "        proxy_send_timeout 1h;\n"
        "    }\n"
        "}\n"
    ) % (IP_TUNEL, IP_TUNEL, IP_TUNEL, texto_reglas(reglas_de_acceso()), puerto_hermes, BEARER)


def bearer(clave: str) -> str:
    """El mismo formato que escribe `hehermes-dispositivo clave`, para que cualquiera de los dos pueda rehacerlo."""
    if not re.match(r"^[\x21-\x7e]+$", clave) or '"' in clave or "\\" in clave:
        raise ValueError("la clave tiene caracteres que no sé escribir en nginx")
    return 'proxy_set_header Authorization "Bearer %s";\n' % clave


def drop_in_nginx() -> str:
    return (
        CABECERA
        + "# nginx escucha en %s, que solo existe cuando está hh-ipsec.\n"
        "[Unit]\n"
        "Wants=hehermes-xfrm.service\n"
        "After=hehermes-xfrm.service\n"
    ) % IP_TUNEL


# MARK: La interfaz XFRM


def unidad_xfrm() -> str:
    return (
        CABECERA
        + "# La interfaz XFRM del túnel IKEv2. Un oneshot y no systemd-networkd: en Debian la red es de ifupdown, y\n"
        "# encender otro gestor de red es tocarle la red a otro. Va antes que strongSwan y nginx.\n"
        "[Unit]\n"
        "Description=HeHermes: interfaz XFRM %s (if_id %s, %s)\n"
        "Before=strongswan.service nginx.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=%s subir\n"
        "# Idempotente: aplicar un cambio no tumba la interfaz ni corta los túneles.\n"
        "ExecReload=%s subir\n"
        "ExecStop=%s bajar\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % (INTERFAZ, IF_ID, IP_TUNEL, SCRIPT_XFRM, SCRIPT_XFRM, SCRIPT_XFRM)


def script_xfrm() -> str:
    return (
        "#!/bin/sh\n"
        + CABECERA
        + "# Sube (o deja como está) la interfaz XFRM de HeHermes: %s con if_id %s, %s/32 y la ruta a %s.\n"
        "set -eu\n"
        "case \"${1:-}\" in\n"
        "  subir)\n"
        "    if ip link show %s >/dev/null 2>&1; then\n"
        "      # Si ya existe, que sea la nuestra: otra con el mismo nombre no se toca.\n"
        "      ip -d link show %s | grep -q 'xfrm if_id %s' \\\n"
        "        || { echo '%s existe y no es una interfaz XFRM con if_id %s' >&2; exit 1; }\n"
        "    else\n"
        "      ip link add %s type xfrm if_id %s\n"
        "    fi\n"
        "    ip addr replace %s/32 dev %s\n"
        "    ip link set %s up\n"
        "    ip route replace %s dev %s\n"
        "    ;;\n"
        "  bajar)\n"
        "    ip link del %s 2>/dev/null || true\n"
        "    ;;\n"
        "  *)\n"
        "    echo \"uso: $0 subir|bajar\" >&2\n"
        "    exit 2\n"
        "    ;;\n"
        "esac\n"
    ) % (INTERFAZ, IF_ID, IP_TUNEL, RED_IPHONES,
         INTERFAZ, INTERFAZ, IF_ID, INTERFAZ, IF_ID, INTERFAZ, IF_ID,
         IP_TUNEL, INTERFAZ, INTERFAZ, RED_IPHONES, INTERFAZ, INTERFAZ)


# MARK: La clave de Hermes


def _ruta_segura(ruta: str) -> str:
    if not _RUTA_VALIDA.fullmatch(ruta):
        raise ValueError("ruta que no sé poner en una unidad de systemd: %r" % ruta)
    return ruta


def unidad_clave_path(env: str) -> str:
    return (
        CABECERA
        + "# Si cambia la clave del api_server en el .env de Hermes, se copia a nginx (y al vigía de los avisos).\n"
        "[Unit]\n"
        "Description=HeHermes: vigila la clave del api_server de Hermes\n"
        "\n"
        "[Path]\n"
        "PathChanged=%s\n"
        "Unit=hehermes-clave.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % _ruta_segura(env)


def unidad_clave_service() -> str:
    return (
        CABECERA
        + "[Unit]\n"
        "Description=HeHermes: copia la clave del api_server a nginx (y al vigía de los avisos)\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=%s clave\n"
    ) % DISPOSITIVO


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


# MARK: servidor.ini


def servidor_ini(direccion: str, env: str, puerto: int, swanctl: str = "/etc/swanctl") -> str:
    if not _DIRECCION_VALIDA.fullmatch(direccion or ""):
        raise ValueError("dirección del servidor no válida: %r" % direccion)
    return (
        CABECERA
        + "# Lo leen hehermes-dispositivo y hehermes-servidor.\n"
        "[servidor]\n"
        "# La que va en el QR de cada iPhone y en el local.id de su conexión de strongSwan.\n"
        "direccion = %s\n"
        "\n"
        "[hermes]\n"
        "env = %s\n"
        "puerto = %d\n"
        "\n"
        "[dispositivos]\n"
        "registro = %s\n"
        "\n"
        "[strongswan]\n"
        "# Donde tiene swanctl su configuración: /etc/swanctl, o /etc/strongswan/swanctl en la familia Red Hat.\n"
        "carpeta = %s\n"
    ) % (direccion, _ruta_segura(env), puerto, REGISTRO, _ruta_segura(swanctl))


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


def reglas_ufw(modo: str = "vpn", puerto: int | None = None) -> list:
    """VPN: solo el UDP de IKE queda abierto a internet; el TCP 80, solo por hh-ipsec y hacia 10.77.0.1. TLS: solo el
    TCP de la pasarela."""
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
    """Una regla de firewalld, en la zona por defecto (la de las interfaces que no tienen otra, como hh-ipsec)."""

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


def reglas_firewalld(modo: str = "vpn", puerto: int | None = None) -> list:
    """Lo mismo que las de ufw. firewalld no sabe de «entra por hh-ipsec»: el TCP 80 solo desde los iPhone y hacia
    10.77.0.1. Uno de fuera no puede hacerse pasar por un iPhone: la respuesta volvería por el túnel."""
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
