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
                    + ("LoadCredential=vigia:%s\n" % _ruta_segura(ambito.secreto_vigia) if con_vigia else ""))
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
        texto += "\n[avisos]\nvigia = %s\nsecreto = %s\n" % (VIGIA, _ruta_segura(ambito.secreto_vigia))
    texto += ("\n[qr]\n# La que va en el QR de cada iPhone.\ndireccion = %s\n\n[instalador]\ncodigo = %s\n"
              % (direccion, _ruta_segura(ambito.prefijo)))
    return texto


# MARK: Los avisos: el vigía (spec 2026-09-28, «El relé para los probadores»; y desde la 0.8.0, «Avisos sin comandos»)

USUARIO_VIGIA = "hh-vigia"
UNIDAD_VIGIA = "hehermes-vigia.service"
SOCKET_VIGIA = "hehermes-vigia.socket"


def url_del_rele(direccion: str, puerto: int) -> str:
    """La de la entrada pública del relé de un código de avisos. Una IPv6 va entre corchetes."""
    if not _DIRECCION_VALIDA.fullmatch(direccion or ""):
        raise ValueError("dirección del relé no válida: %r" % direccion)
    if not isinstance(puerto, int) or isinstance(puerto, bool) or not 0 < puerto < 65536:
        raise ValueError("puerto del relé no válido: %r" % (puerto,))
    return "https://%s:%d/v1/avisos" % ("[%s]" % direccion if ":" in direccion else direccion, puerto)


def _ip_del_rele(direccion: str) -> str | None:
    try:
        return str(ipaddress.ip_address(direccion))
    except ValueError:
        return None


def vigia_ini(ambito, puerto_hermes: int, env: str, casa_hermes: str, direccion: str | None = None,
              puerto: int | None = None, huella: str | None = None, lector: str | None = None) -> str:
    """Lo que lee el vigía (`hehermes_avisos.vigia.configuracion`). Sin secretos: dice dónde están.

    Con un código de avisos (`direccion`, `puerto`, `huella`), el relé es el de otra máquina (el de Daniel), por HTTPS
    y con la huella de su certificado anclada, y la credencial va en su fichero. Sin código (`direccion` None), sin
    credencial ni relé fijo: `[rele] url` vacía, y cada aviso va con el permiso que la app le da en el alta de cada
    iPhone, con la dirección y la huella del relé que trae con él. `lector`: el socket del lector de ficheros."""
    if not isinstance(puerto_hermes, int) or not 0 < puerto_hermes < 65536:
        raise ValueError("puerto de Hermes no válido: %r" % (puerto_hermes,))
    if direccion is None:
        rele = ("# Sin credencial: cada aviso va a la entrada pública del relé con el permiso que la app le da al vigía\n"
                "# en el alta de cada iPhone (App Attest), anclado a la huella que trae con él. Con un código de\n"
                "# avisos (hehermes-servidor avisos), la credencial.\n"
                "url =\n")
    else:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", huella or ""):
            raise ValueError("huella del relé no válida")
        rele = "url = %s\nhuella = %s\ncredencial = %s\n" % (url_del_rele(direccion, puerto), huella,
                                                              _ruta_segura(ambito.credencial_rele))
    ficheros = ("# El lector de ficheros (GET /avisos/v1/fichero): sin él, esa ruta contesta 503.\nlector = %s\n"
                % _ruta_segura(lector) if lector else
                "# Sin el lector de ficheros (GET /avisos/v1/fichero): esa ruta contesta 503.\nlector =\n")
    return (
        CABECERA
        + "# El vigía de avisos de HeHermes (server/avisos/README.md): lee a Hermes, cifra cada aviso para cada iPhone y\n"
        "# se lo pasa al relé, que es el único que habla con Apple.\n"
        "[vigia]\n"
        "escucha = %s\n"
        "base_de_datos = %s\n"
        "secreto_tunel = %s\n"
        "\n"
        "[hermes]\n"
        "base = http://127.0.0.1:%d\n"
        "clave = %s\n"
        "\n"
        "[rele]\n"
        "%s"
        "\n"
        "[ficheros]\n"
        "%s"
        "casa = %s\n"
    ) % (VIGIA, _ruta_segura(ambito.base_vigia), _ruta_segura(ambito.secreto_vigia), puerto_hermes,
         _ruta_segura(ambito.clave_hermes_vigia if ambito.root else env), rele, ficheros, _ruta_segura(casa_hermes))


def unidad_vigia_socket() -> str:
    """Con root, el puerto del vigía es de systemd, esté el vigía en marcha o no: nadie más puede escuchar en
    127.0.0.1:8790 y quedarse con lo que le manda la pasarela (el secreto del vigía y la clave de cada alta)."""
    return (
        CABECERA
        + "[Unit]\n"
        "Description=HeHermes: el puerto del vigía de avisos\n"
        "\n"
        "[Socket]\n"
        "ListenStream=%s\n"
        "IPAddressDeny=any\n"
        "IPAddressAllow=localhost\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n"
    ) % VIGIA


#: Sin credencial, el relé no se sabe al instalar (la dirección del VPS de Daniel no puede ir en el espejo público): el
#: vigía sale a internet, pero no a la red de dentro (spec 2026-09-28, «El instalador 0.8.0»). Esta máquina sí
#: (Hermes, la pasarela): `IPAddressAllow=localhost` gana a esto.
REDES_DE_DENTRO = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7",
                   "fe80::/10")


def unidad_vigia(ambito, direccion_rele: str | None) -> str:
    """Con root, como `hh-vigia`, con el socket de systemd y la jaula de la del VPS de Daniel
    (`server/avisos/despliegue/hehermes-vigia.service`); la red, solo hacia esta máquina y hacia el relé si su dirección
    es una IP. Sin código de avisos (`direccion_rele` None), hacia esta máquina y hacia internet, pero no hacia las
    redes de dentro (`REDES_DE_DENTRO`). Sin root, una unidad de usuario que abre su propio puerto. Sin
    `MemoryDenyWriteExecute`: cffi (de cryptography) puede necesitar memoria ejecutable, y un vigía que no arranca no
    avisa de nada. Los dos quieren el socket del lector de ficheros, si está (`Wants=`: sin él, el vigía va igual)."""
    orden = "%s -I -B -m hehermes_avisos.vigia --config %s servir" % (_ruta_segura(ambito.python_venv),
                                                                      _ruta_segura(ambito.vigia_ini))
    comun = (
        "NoNewPrivileges=yes\n"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"
        "RestrictRealtime=yes\n"
        "RestrictSUIDSGID=yes\n"
        "LockPersonality=yes\n"
        "SystemCallArchitectures=native\n"
        "SystemCallFilter=@system-service\n"
        "SystemCallErrorNumber=EPERM\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
    )
    if not ambito.root:
        red = ("" if direccion_rele is not None else
               "# Sin credencial, a internet. Una unidad de usuario no puede filtrar direcciones (IPAddressDeny necesita\n"
               "# privilegios que un gestor de usuario no tiene): lo que impide ir a la red de dentro es el propio vigía,\n"
               "# que se niega a conectar a una dirección que no sea pública, y la huella anclada del relé.\n")
        return (
            CABECERA
            + "# El vigía de avisos de HeHermes, como el usuario de Hermes: lee su .env.\n"
            "[Unit]\n"
            "Description=HeHermes: vigía de avisos\n"
            "Wants=%s\n"
            "After=%s\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=%s\n"
            "Restart=always\n"
            "RestartSec=5\n"
            "%s"
            "%s"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        ) % (SOCKET_LECTOR, SOCKET_LECTOR, orden, red, comun)
    if direccion_rele is None:
        red = ("# Sin credencial: el relé de cada permiso lo dice la app, y no se sabe al instalar. Esta máquina (Hermes,\n"
               "# la pasarela) e internet, sí; las redes de dentro, no. La huella anclada cierra el paso a cualquier otro.\n"
               "IPAddressAllow=localhost\nIPAddressDeny=%s\n" % " ".join(REDES_DE_DENTRO))
    else:
        ip = _ip_del_rele(direccion_rele)
        red = ("# Solo esta máquina (Hermes, la pasarela) y el relé.\nIPAddressDeny=any\nIPAddressAllow=localhost %s\n"
               % ip if ip else "# El relé va por nombre (%s): sin filtro de direcciones.\n" % direccion_rele)
    return (
        CABECERA
        + "# El vigía de avisos de HeHermes: lee a Hermes (sin tocarlo) y pide los avisos al relé.\n"
        "[Unit]\n"
        "Description=HeHermes: vigía de avisos\n"
        "Wants=network-online.target %s\n"
        "Requires=%s\n"
        "After=network-online.target %s %s\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=%s\n"
        "Group=%s\n"
        "ExecStart=%s\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "StateDirectory=hehermes-vigia\n"
        "StateDirectoryMode=0700\n"
        "%s"
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
        "InaccessiblePaths=-%s -%s -/etc/nginx -/etc/wireguard -/etc/swanctl\n"
        "%s"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "Also=%s\n"
    ) % (SOCKET_LECTOR, SOCKET_VIGIA, SOCKET_VIGIA, SOCKET_LECTOR, USUARIO_VIGIA, USUARIO_VIGIA, orden, red,
         ambito.carpeta_pasarela, ambito.carpeta_config, comun, SOCKET_VIGIA)


# MARK: El lector de ficheros (spec 2026-09-28, «El instalador 0.8.0»)

SOCKET_LECTOR = "hehermes-leer-media.socket"
#: Lo que se sabe que hay en la carpeta de Hermes, fuera de sus caches: la jaula lo tapa además de que el lector lo
#: prohíba (lo mismo que `server/avisos/despliegue/instalar.sh`, SECRETOS_HERMES).
SECRETOS_HERMES = (".env", "auth.json", "config.yaml", "state.db", "state.db-wal", "state.db-shm", "SOUL.md",
                   "backups", "cron", "hooks", "engagements")


def unidad_lector_socket(ambito) -> str:
    """Con root, `/run/hehermes-leer-media.sock`, de root y del grupo `hh-vigia` (0660), como en el VPS de Daniel
    (`server/avisos/despliegue/hehermes-leer-media.socket`). Sin root, en el `/run/user` del usuario de Hermes (`%t`),
    0600: solo él (y su vigía, que es él) se conecta."""
    if ambito.root:
        dueno = ("ListenStream=/run/hehermes-leer-media.sock\nSocketUser=root\nSocketGroup=%s\nSocketMode=0660\n"
                 % USUARIO_VIGIA)
        que = ("# Solo root y el grupo hh-vigia pueden conectarse (0660), y el lector lo vuelve a mirar con SO_PEERCRED.\n"
               "# Por cada conexión, systemd lanza un lector de root con su jaula (hehermes-leer-media@.service).\n")
    else:
        dueno = "ListenStream=%t/hehermes-leer-media.sock\nSocketMode=0600\n"
        que = ("# En el /run/user del usuario de Hermes, 0600, y el lector solo atiende a su propio uid (--usuario).\n"
               "# Por cada conexión, systemd lanza un lector como este usuario (hehermes-leer-media@.service).\n")
    return (
        CABECERA
        + "# La puerta del lector de los ficheros que Hermes marca con MEDIA: (GET /avisos/v1/fichero del vigía).\n"
        + que
        + "[Unit]\n"
        "Description=HeHermes: el socket del lector de ficheros de Hermes\n"
        "\n"
        "[Socket]\n"
        + dueno
        + "Accept=yes\n"
        "# El vigía no pasa de dos a la vez; esto es el tope por si algo va mal.\n"
        "MaxConnections=4\n"
        "RemoveOnStop=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n"
    )


#: La jaula del lector de root, la misma que la de `server/avisos/despliegue/hehermes-leer-media@.service` (una prueba
#: las compara): leer, y solo leer.
_JAULA_LECTOR = (
    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH\n"
    "NoNewPrivileges=yes\n"
    "ProtectSystem=strict\n"
    "ProtectHome=read-only\n"
    "PrivateNetwork=yes\n"
    "IPAddressDeny=any\n"
    "RestrictAddressFamilies=AF_UNIX\n"
    "PrivateDevices=yes\n"
    "PrivateIPC=yes\n"
    "ProtectKernelTunables=yes\n"
    "ProtectKernelModules=yes\n"
    "ProtectKernelLogs=yes\n"
    "ProtectControlGroups=yes\n"
    "ProtectClock=yes\n"
    "ProtectHostname=yes\n"
    "ProtectProc=invisible\n"
    "ProcSubset=pid\n"
    "KeyringMode=private\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "LockPersonality=yes\n"
    "MemoryDenyWriteExecute=yes\n"
    "SystemCallArchitectures=native\n"
    "SystemCallFilter=@system-service\n"
    "SystemCallErrorNumber=EPERM\n"
)
#: Lo que una unidad de usuario sí puede ponerse (seccomp y límites, con NoNewPrivileges): nada de espacios de nombres
#: ni de capacidades, que un gestor de usuario no siempre tiene.
_JAULA_LECTOR_USUARIO = (
    "NoNewPrivileges=yes\n"
    "RestrictAddressFamilies=AF_UNIX\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "LockPersonality=yes\n"
    "MemoryDenyWriteExecute=yes\n"
    "SystemCallArchitectures=native\n"
    "SystemCallFilter=@system-service\n"
    "SystemCallErrorNumber=EPERM\n"
)


def unidad_lector(ambito, hermes_home: str) -> str:
    """Un lector por conexión (`Accept=yes`): lee una línea con la ruta y contesta con el fichero por el mismo socket.

    Con root, de root y con la jaula del VPS de Daniel, y la carpeta de Hermes (`--hermes-home`) prohibida salvo sus
    caches, también tapada en la jaula, igual que los secretos del instalador. Sin root, como el usuario de Hermes, que
    ya puede leer lo que Hermes escribe, con `--usuario` (solo atiende a su propio uid) y con lo que una unidad de
    usuario se puede poner. Lo que no puede (ProtectSystem, ProtectHome, InaccessiblePaths, PrivateNetwork…) lo dice
    ella misma: ahí, lo que no se lee lo decide solo el lector, con su lista de prohibidas."""
    casa = _ruta_segura(hermes_home.rstrip("/"))
    if not ambito.root:
        return (
            CABECERA
            + "# Un lector por conexión a %%t/hehermes-leer-media.sock, como el usuario de Hermes: lee lo que él puede\n"
            "# leer y nada de lo que el lector prohíbe (la carpeta de Hermes salvo sus caches, ~/.ssh, cualquier .env,\n"
            "# lo de hehermes en ~/.config y ~/.local…).\n"
            "# Lo que una unidad de usuario NO puede ponerse (necesita espacios de nombres o privilegios que un gestor\n"
            "# de usuario no tiene): ProtectSystem, ProtectHome, InaccessiblePaths, PrivateNetwork, PrivateDevices,\n"
            "# IPAddressDeny ni CapabilityBoundingSet. Aquí el núcleo no tapa nada: la lista de prohibidas la hace\n"
            "# cumplir solo el lector, y sin red lo deja RestrictAddressFamilies=AF_UNIX.\n"
            "[Unit]\n"
            "Description=HeHermes: lector de un fichero que Hermes marcó\n"
            "CollectMode=inactive-or-failed\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=%s --conexion\n"
            "StandardInput=socket\n"
            "StandardOutput=socket\n"
            "StandardError=journal\n"
            "SuccessExitStatus=2 3 4 5 6\n"
            "RuntimeMaxSec=900\n"
            "UMask=0077\n"
            "LimitCORE=0\n"
            "%s"
        ) % (_ruta_segura(ambito.lector), casa, _JAULA_LECTOR_USUARIO)
    tapadas = " ".join("-%s/%s" % (casa, secreto) for secreto in SECRETOS_HERMES)
    return (
        CABECERA
        + "# Un lector por conexión a /run/hehermes-leer-media.sock (hehermes-leer-media.socket, Accept=yes). Es root,\n"
        "# porque Hermes puede serlo y deja sus ficheros donde quiere, pero con lo justo para leer y nada más.\n"
        "[Unit]\n"
        "Description=HeHermes: lector de un fichero que Hermes marcó\n"
        "CollectMode=inactive-or-failed\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 -I -S -B %s --hermes-home=%s --conexion\n"
        "StandardInput=socket\n"
        "StandardOutput=socket\n"
        "StandardError=journal\n"
        "# Los rechazos de siempre no son un fallo; una carrera (7), un error (8) o alguien que no es el vigía (9), sí.\n"
        "SuccessExitStatus=2 3 4 5 6\n"
        "RuntimeMaxSec=900\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "%s"
        "# Sin PrivateTmp a propósito: Hermes deja ficheros en /tmp, y el lector tiene que ver el /tmp de verdad.\n"
        "# Lo que el lector prohíbe, otra vez, pero ahora lo hace cumplir el núcleo.\n"
        "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
        "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
        "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-avisos -/etc/hehermes-pasarela -/var/lib/hehermes-vigia\n"
        "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
        "InaccessiblePaths=-/root/.ssh -/root/.gnupg\n"
        "InaccessiblePaths=%s\n"
    ) % (_ruta_segura(ambito.lector), casa, _JAULA_LECTOR, tapadas)
