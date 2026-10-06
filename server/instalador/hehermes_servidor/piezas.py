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
    la clave del certificado y el secreto del vigía como credenciales de systemd, que los copia desde ficheros de root.
    La copia de la clave de Hermes no: desde la 0.9.0 es de `hh-pasarela` (0600) y la pasarela la vuelve a leer cuando
    cambia, así que rotar la clave de Hermes ya no la reinicia (ni corta los SSE abiertos). Sin root: una unidad de
    usuario, con lo que un usuario puede ponerse (sin espacios de nombres: un gestor de usuario puede no tenerlos).

    Un error de configuración (un secreto que no se lee, el ini roto) sale con 78, que no se reinicia en bucle."""
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
            "RestartPreventExitStatus=78\n"
            "%s"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        ) % (orden, comun)
    credenciales = ("LoadCredential=clave:%s\n" % ambito.clave
                    + ("LoadCredential=vigia:%s\n" % _ruta_segura(ambito.secreto_vigia) if con_vigia else ""))
    return (
        CABECERA
        + "# La pasarela TLS de HeHermes (server/API-CONTRACT.md, §12). Corre como %s, sin ningún privilegio: el\n"
        "# puerto es alto, y la clave del certificado le llega como credencial de systemd. Su copia de la clave de\n"
        "# Hermes es suya (0600) y la vuelve a leer cuando cambia: rotarla no la reinicia.\n"
        "[Unit]\n"
        "Description=HeHermes: la pasarela TLS hacia Hermes\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=120\n"
        "StartLimitBurst=5\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=%s\n"
        "Group=%s\n"
        "ExecStart=%s\n"
        "%s"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "# 78: la configuración o un secreto; reiniciar no lo arregla (journalctl -u hehermes-pasarela).\n"
        "RestartPreventExitStatus=78\n"
        "# Lo único que escribe: el borrado pendiente y su actividad, para la limpieza de noche (hehermes-borrado).\n"
        "StateDirectory=hehermes-pasarela\n"
        "StateDirectoryMode=0755\n"
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


def unidad_borrado(ambito) -> str:
    """La limpieza de noche de lo que la app borra de Hermes (`mantenimiento.py`): una vez, con un tope duro, y sin
    reintentos de systemd (los intentos los lleva ella, uno por noche). Con root, como root: tiene que parar y arrancar
    la unidad de Hermes y compactar su base como su usuario."""
    return (
        CABECERA
        + "# El borrado de verdad de lo que la app borra de Hermes (hehermes_servidor/mantenimiento.py). La lanza\n"
        "# hehermes-borrado.timer; si no hay nada pendiente, o no es un rato tranquilo, no hace nada.\n"
        "[Unit]\n"
        "Description=HeHermes: el borrado de verdad de lo borrado de Hermes (compacta su base de noche)\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=%s borrado-seguro\n"
        "# El tope duro: compactar tiene 15 minutos, y arrancar Hermes otra vez y esperar su /health, el resto.\n"
        "TimeoutStartSec=20min\n"
        "UMask=0022\n"
        "LimitCORE=0\n"
        "PrivateTmp=yes\n"
        "NoNewPrivileges=%s\n"
    ) % ("/usr/bin/python3 -I -B %s/hehermes-servidor" % _ruta_segura(ambito.prefijo),
         # Con root cambia de usuario (runuser) para compactar como el de Hermes: NoNewPrivileges no le deja.
         "no" if ambito.root else "yes")


def temporizador_borrado() -> str:
    return (
        CABECERA
        + "# Cada 15 minutos de 2:00 a 5:45 (hora del servidor): la limpieza decide si es un rato tranquilo.\n"
        "[Unit]\n"
        "Description=HeHermes: el borrado de verdad, de noche\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=*-*-* 02..05:00/15:00\n"
        "RandomizedDelaySec=120\n"
        "Persistent=false\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def ambito_python() -> str:
    from .ambito import PYTHON
    return PYTHON


def unidad_pasarela_clave_path(env: str) -> str:
    return (
        CABECERA
        + "# Si cambia la clave del api_server en el .env de Hermes, se copia a la pasarela, que la vuelve a leer sola\n"
        "# (sin reiniciarse: los SSE abiertos siguen).\n"
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
    código). Con root, la clave de Hermes es una copia suya (`clave-hermes`, de hh-pasarela y 0600); sin root, el .env
    mismo. En los dos casos la vuelve a leer cuando cambia."""
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
        "# El que viene después: su huella se da a quien trae un token (GET /hehermes/v1/huellas), para rotar sin\n"
        "# volver a emparejar (hehermes-servidor certificado rotar).\n"
        "certificado_siguiente = %s\n"
        "tokens = %s\n"
        "\n"
        "[hermes]\n"
        "puerto = %d\n"
        "clave = %s\n"
        "env = %s\n"
    ) % (puerto, _ruta_segura(ambito.cert), _ruta_segura(ambito.clave), _ruta_segura(ambito.cert_siguiente),
         _ruta_segura(ambito.tokens), puerto_hermes,
         _ruta_segura(ambito.clave_hermes if ambito.root else env), _ruta_segura(env))
    texto += ("\n[mantenimiento]\n# Donde apunta que hay algo borrado de Hermes por limpiar (sin ids), su actividad, y lo\n"
              "# que apunta la limpieza de noche (hehermes-borrado.timer).\ncarpeta = %s\n"
              % _ruta_segura(ambito.carpeta_estado_pasarela))
    if vigia:
        texto += "\n[avisos]\nvigia = %s\nsecreto = %s\n" % (VIGIA, _ruta_segura(ambito.secreto_vigia))
    texto += ("\n[agentes]\n# Las claves de los agentes (/p/<perfil>/…), una por perfil: las escribe hehermes-agentes.\n"
              "claves = %s\n" % _ruta_segura(ambito.claves_agentes_pasarela))
    texto += ("\n[qr]\n# La que va en el QR de cada iPhone.\ndireccion = %s\n\n[instalador]\ncodigo = %s\n"
              % (direccion, _ruta_segura(ambito.prefijo)))
    return texto


# MARK: Los avisos: el vigía (spec 2026-09-28, «El relé para los probadores»; y desde la 0.8.0, «Avisos sin comandos»)

USUARIO_VIGIA = "hh-vigia"
UNIDAD_VIGIA = "hehermes-vigia.service"
SOCKET_VIGIA = "hehermes-vigia.socket"
#: Una unidad que el vigía sabe mirar con `systemctl is-active` (`hehermes_avisos.vigia.servidor.unidad_valida`).
_UNIDAD_DEL_VIGIA = re.compile(r"^(usuario:)?[A-Za-z0-9][A-Za-z0-9:_.@-]{0,199}\.(service|socket|timer)$")


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
              puerto: int | None = None, huella: str | None = None, lector: str | None = None,
              respaldo: str | None = None, entrada: str | None = None, actualizar: str | None = None,
              servicios=(), hermes_unidad: str | None = None, agentes: str | None = None) -> str:
    """Lo que lee el vigía (`hehermes_avisos.vigia.configuracion`). Sin secretos: dice dónde están.

    Con un código de avisos (`direccion`, `puerto`, `huella`), el relé es el de otra máquina (el de Daniel), por HTTPS
    y con la huella de su certificado anclada, y la credencial va en su fichero. Sin código (`direccion` None), sin
    credencial ni relé fijo: `[rele] url` vacía, y cada aviso va con el permiso que la app le da en el alta de cada
    iPhone, con la dirección y la huella del relé que trae con él. `lector`: el socket del lector de ficheros;
    `respaldo`, el del ayudante de la copia en iCloud; `entrada`, el del ayudante que recibe lo que la app le manda a
    Hermes (sus topes, los de serie del vigía). Y desde la 0.10.10, lo de Ajustes › Tu servidor: `actualizar`, el socket
    del ayudante que actualiza (solo con root), y las unidades cuyo estado se enseña (`servicios`, con «usuario:»
    delante las de usuario, y la de Hermes, `hermes_unidad`, si el vigía la puede mirar). Y desde la 0.11.0 los agentes
    (contrato §18): `agentes`, el socket de su ayudante, y la carpeta de sus claves, que es la de los que se vigilan."""
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
    copia = ("# El ayudante de la copia en iCloud (/avisos/v1/respaldo/…): sin él, esas rutas contestan 503.\n"
             "ayudante = %s\n" % _ruta_segura(respaldo) if respaldo else
             "# Sin el ayudante de la copia en iCloud (/avisos/v1/respaldo/…): esas rutas contestan 503.\nayudante =\n")
    recibir = ("# El ayudante de la entrada (/avisos/v1/entrada/…): lo que la app le manda a Hermes.\n"
               "ayudante = %s\n" % _ruta_segura(entrada) if entrada else
               "# Sin el ayudante de la entrada (/avisos/v1/entrada/…): esas rutas contestan 503.\nayudante =\n")
    de_los_agentes = (
        "# Las claves de los agentes, una por perfil (<perfil>.clave, las escribe su ayudante): los que se vigilan.\n"
        "claves = %s\n" % _ruta_segura(ambito.claves_agentes_vigia)
        + ("# El ayudante de los agentes (/avisos/v1/agentes…): crea, cambia y borra los perfiles de Hermes.\n"
           "ayudante = %s\n" % _ruta_segura(agentes) if agentes else
           "# Sin el ayudante de los agentes (/avisos/v1/agentes…): esas rutas contestan 503.\nayudante =\n"))
    for unidad in tuple(servicios) + ((hermes_unidad,) if hermes_unidad else ()):
        if not _UNIDAD_DEL_VIGIA.fullmatch(unidad):
            raise ValueError("unidad que el vigía no sabría mirar: %r" % unidad)
    servidor = (
        "# Lo que enseña Ajustes › Tu servidor (GET /avisos/v1/servidor): la versión del instalador, de aquí.\n"
        "instalador = %s\n" % _ruta_segura(ambito.prefijo)
        + ("# El ayudante que actualiza el servidor desde la app (/avisos/v1/servidor/actualizar).\n"
           "ayudante = %s\n" % _ruta_segura(actualizar) if actualizar else
           "# Sin el ayudante que actualiza (sin root no hay: actualizar es instalar): la app enseña cómo hacerlo a\n"
           "# mano.\nayudante =\n")
        + "# El estado de estas unidades, con systemctl is-active (con «usuario:» delante, --user).\n"
        "servicios = %s\n" % " ".join(servicios)
        + "# La de Hermes (vacía si el vigía no la puede mirar: en tmux, en un contenedor, de otro usuario).\n"
        "hermes = %s\n" % (hermes_unidad or ""))
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
        "\n"
        "[respaldo]\n"
        "%s"
        "\n"
        "[entrada]\n"
        "%s"
        "\n"
        "[servidor]\n"
        "%s"
        "\n"
        "[agentes]\n"
        "%s"
    ) % (VIGIA, _ruta_segura(ambito.base_vigia), _ruta_segura(ambito.secreto_vigia), puerto_hermes,
         _ruta_segura(ambito.clave_hermes_vigia if ambito.root else env), rele, ficheros, _ruta_segura(casa_hermes),
         copia, recibir, servidor, de_los_agentes)


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
    avisa de nada. Los dos quieren los sockets del lector de ficheros y de los ayudantes de la copia, de la entrada y de
    los agentes, si están (`Wants=`: sin ellos, el vigía va igual y esas rutas dan 503)."""
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
            "Wants=%s %s %s %s\n"
            "After=%s %s %s %s\n"
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
        ) % (SOCKET_LECTOR, SOCKET_RESPALDO, SOCKET_ENTRADA, SOCKET_AGENTES, SOCKET_LECTOR, SOCKET_RESPALDO,
             SOCKET_ENTRADA, SOCKET_AGENTES, orden, red, comun)
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
        "Wants=network-online.target %s %s %s %s %s\n"
        "Requires=%s\n"
        "After=network-online.target %s %s %s %s %s %s\n"
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
    ) % (SOCKET_LECTOR, SOCKET_RESPALDO, SOCKET_ENTRADA, SOCKET_ACTUALIZAR, SOCKET_AGENTES, SOCKET_VIGIA, SOCKET_VIGIA,
         SOCKET_LECTOR, SOCKET_RESPALDO, SOCKET_ENTRADA, SOCKET_ACTUALIZAR, SOCKET_AGENTES, USUARIO_VIGIA,
         USUARIO_VIGIA, orden, red, ambito.carpeta_pasarela, ambito.carpeta_config, comun, SOCKET_VIGIA)


# MARK: El lector de ficheros (spec 2026-09-28, «El instalador 0.8.0»)

SOCKET_LECTOR = "hehermes-leer-media.socket"
#: Lo único que el lector lee de la carpeta de Hermes (desde la 0.9.0, una lista de permitidas): sus caches y la
#: carpeta de exportaciones que crea el instalador. Lo mismo que `server/avisos/despliegue/instalar.sh`,
#: PERMITIDAS_HERMES, y que el lector (PERMITIDAS_EN_LA_CASA).
PERMITIDAS_HERMES = ("image_cache", "audio_cache", "exports")
EXPORTACIONES = "exports"
#: La carpeta de los perfiles de Hermes (los agentes, desde la 0.11.0): cada uno con su casa dentro.
PERFILES_HERMES = "profiles"


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
    "CapabilityBoundingSet=\n"
    "AmbientCapabilities=\n"
    "NoNewPrivileges=yes\n"
    "ProtectSystem=strict\n"
    "PrivateNetwork=yes\n"
    "IPAddressDeny=any\n"
    "RestrictAddressFamilies=AF_UNIX\n"
    "PrivateDevices=yes\n"
    "PrivateIPC=yes\n"
    "PrivateTmp=yes\n"
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


def unidad_lector(ambito, hermes_home: str, usuario_hermes: str | None = None) -> str:
    """Un lector por conexión (`Accept=yes`): lee una línea con la ruta y contesta con el fichero por el mismo socket.

    Desde la 0.9.0 solo lee de una lista de permitidas: las caches de Hermes y su `exports/`. Con root, con la jaula del
    VPS de Daniel: como el dueño de la casa de Hermes (root si Hermes es root; si no, su usuario) y **sin ninguna
    capacidad**, con las casas tapadas (`ProtectHome=tmpfs`) salvo las permitidas (`BindReadOnlyPaths`), y lo de los
    secretos del sistema y del instalador, tapado. Sin root, como el usuario de Hermes, con `--usuario` (solo atiende a
    su propio uid) y con lo que una unidad de usuario se puede poner. Lo que no puede (ProtectSystem, ProtectHome,
    InaccessiblePaths, PrivateNetwork…) lo dice ella misma: ahí, lo que se lee lo decide solo el lector."""
    casa = _ruta_segura(hermes_home.rstrip("/"))
    if not ambito.root:
        return (
            CABECERA
            + "# Un lector por conexión a %%t/hehermes-leer-media.sock, como el usuario de Hermes: de su casa, solo las\n"
            "# caches de Hermes y su exports/ (la lista de permitidas del lector).\n"
            "# Lo que una unidad de usuario NO puede ponerse (necesita espacios de nombres o privilegios que un gestor\n"
            "# de usuario no tiene): ProtectSystem, ProtectHome, InaccessiblePaths, PrivateNetwork, PrivateDevices,\n"
            "# IPAddressDeny ni CapabilityBoundingSet. Aquí el núcleo no tapa nada: la lista de permitidas la hace\n"
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
            "SuccessExitStatus=2 3 4 5 6 10\n"
            "RuntimeMaxSec=900\n"
            "UMask=0077\n"
            "LimitCORE=0\n"
            "%s"
        ) % (_ruta_segura(ambito.lector), casa, _JAULA_LECTOR_USUARIO)
    # Y desde la 0.11.0 los perfiles de los agentes, enteros (se crean y se borran sin tocar esta unidad): dentro, el
    # lector solo lee las caches y el exports/ de cada uno.
    vistas = " ".join("-%s/%s" % (casa, permitida) for permitida in PERMITIDAS_HERMES + (PERFILES_HERMES,))
    usuario = ""
    if usuario_hermes and usuario_hermes != "root":
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", usuario_hermes):
            raise ValueError("usuario de Hermes no válido para una unidad: %r" % usuario_hermes)
        usuario = "User=%s\n" % usuario_hermes
    return (
        CABECERA
        + "# Un lector por conexión a /run/hehermes-leer-media.sock (hehermes-leer-media.socket, Accept=yes). Corre como\n"
        "# el dueño de la casa de Hermes, sin ninguna capacidad: solo lee sus caches y su exports/.\n"
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
        "SuccessExitStatus=2 3 4 5 6 10\n"
        "RuntimeMaxSec=900\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "%s"
        "%s"
        "# La lista de permitidas, otra vez, pero ahora la hace cumplir el núcleo: las casas vacías, y dentro solo las\n"
        "# carpetas permitidas, de solo lectura (la que aún no exista se salta).\n"
        "ProtectHome=tmpfs\n"
        "BindReadOnlyPaths=%s\n"
        "# Y fuera de las casas, los secretos del sistema y del instalador, tapados.\n"
        "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
        "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
        "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-avisos -/etc/hehermes-pasarela -/var/lib/hehermes-vigia\n"
        "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
    ) % (_ruta_segura(ambito.lector), casa, usuario, _JAULA_LECTOR, vistas)


# MARK: El ayudante de la copia en iCloud (spec 2026-09-29, desde la 0.10.0)

SOCKET_RESPALDO = "hehermes-respaldo.socket"


def unidad_respaldo_socket(ambito) -> str:
    """Como el del lector: con root, `/run/hehermes-respaldo.sock`, de root y del grupo `hh-vigia` (0660); sin root, en
    el `/run/user` del usuario de Hermes (`%t`), 0600."""
    if ambito.root:
        dueno = ("ListenStream=/run/hehermes-respaldo.sock\nSocketUser=root\nSocketGroup=%s\nSocketMode=0660\n"
                 % USUARIO_VIGIA)
        que = ("# Solo root y el grupo hh-vigia pueden conectarse (0660), y el ayudante lo vuelve a mirar con SO_PEERCRED.\n"
               "# Por cada conexión, systemd lanza un ayudante de root con su jaula (hehermes-respaldo@.service).\n")
    else:
        dueno = "ListenStream=%t/hehermes-respaldo.sock\nSocketMode=0600\n"
        que = ("# En el /run/user del usuario de Hermes, 0600, y el ayudante solo atiende a su propio uid (--usuario).\n"
               "# Por cada conexión, systemd lanza un ayudante como este usuario (hehermes-respaldo@.service).\n")
    return (
        CABECERA
        + "# La puerta del ayudante de la copia de Hermes en iCloud (/avisos/v1/respaldo/… del vigía).\n"
        + que
        + "[Unit]\n"
        "Description=HeHermes: el socket del ayudante de la copia en iCloud\n"
        "\n"
        "[Socket]\n"
        + dueno
        + "Accept=yes\n"
        "# Cuatro trozos a la vez (el vigía no deja más), la orden larga en marcha y el estado: esto es el tope.\n"
        "MaxConnections=8\n"
        "RemoveOnStop=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n"
    )


#: La jaula del ayudante de root, la misma que la de `server/avisos/despliegue/hehermes-respaldo@.service` (una prueba
#: las compara). Tiene que parar Hermes y escribir en su casa: /usr, /boot y /etc de solo lectura, las capacidades justas
#: y solo 127.0.0.1. Sin SystemCallFilter ni MemoryDenyWriteExecute: `hermes import` ejecuta el Python de Hermes.
_JAULA_RESPALDO = (
    "NoNewPrivileges=yes\n"
    "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_SETUID CAP_SETGID "
    "CAP_KILL\n"
    "AmbientCapabilities=\n"
    "ProtectSystem=full\n"
    "PrivateTmp=yes\n"
    "PrivateDevices=yes\n"
    "ProtectKernelTunables=yes\n"
    "ProtectKernelModules=yes\n"
    "ProtectKernelLogs=yes\n"
    "ProtectClock=yes\n"
    "ProtectHostname=yes\n"
    "KeyringMode=private\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "LockPersonality=yes\n"
    "SystemCallArchitectures=native\n"
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
    "IPAddressDeny=any\n"
    "IPAddressAllow=localhost\n"
)
#: Lo que una unidad de usuario sí puede ponerse.
_JAULA_RESPALDO_USUARIO = (
    "NoNewPrivileges=yes\n"
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "LockPersonality=yes\n"
    "SystemCallArchitectures=native\n"
)


def unidad_respaldo(ambito, hermes_home: str, usuario_hermes: str | None = None,
                    unidad_hermes: str = "hermes-gateway.service") -> str:
    """Un ayudante por conexión (`Accept=yes`). Con root, de root (restaurar para y arranca `hermes-gateway`, y ejecuta
    `hermes import` como el dueño de Hermes), con la jaula del VPS de Daniel. Sin root, como el usuario de Hermes, con
    `--usuario` (solo atiende a su propio uid, y para y arranca con `systemctl --user`: si Hermes es una unidad del
    sistema, restaurar no se puede y lo dice)."""
    casa = _ruta_segura(hermes_home.rstrip("/"))
    usuario = usuario_hermes or "root"
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", usuario):
        raise ValueError("usuario de Hermes no válido para una unidad: %r" % usuario)
    if not re.fullmatch(r"[A-Za-z0-9:_.@-]{1,200}\.service", unidad_hermes):
        raise ValueError("unidad de Hermes no válida para una unidad: %r" % unidad_hermes)
    comun = (
        "StandardInput=socket\n"
        "StandardOutput=socket\n"
        "StandardError=journal\n"
        "RuntimeMaxSec=4h\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
    )
    if not ambito.root:
        return (
            CABECERA
            + "# Un ayudante de la copia en iCloud por conexión a %%t/hehermes-respaldo.sock, como el usuario de Hermes.\n"
            "# Lo que una unidad de usuario NO puede ponerse (ProtectSystem, ProtectHome, InaccessiblePaths,\n"
            "# IPAddressDeny, CapabilityBoundingSet): aquí lo que se lee y se escribe lo decide solo el ayudante.\n"
            "[Unit]\n"
            "Description=HeHermes: ayudante de la copia de Hermes en iCloud\n"
            "CollectMode=inactive-or-failed\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=%s --trabajo=%s "
            "--unidad-hermes=%s --conexion\n"
            "%s"
            "%s"
        ) % (_ruta_segura(ambito.respaldo), casa, _ruta_segura(ambito.carpeta_respaldo), unidad_hermes, comun,
             _JAULA_RESPALDO_USUARIO)
    return (
        CABECERA
        + "# Un ayudante de la copia en iCloud por conexión a /run/hehermes-respaldo.sock (hehermes-respaldo.socket,\n"
        "# Accept=yes). De root: para y arranca hermes-gateway y escribe en la casa de Hermes al restaurar.\n"
        "[Unit]\n"
        "Description=HeHermes: ayudante de la copia de Hermes en iCloud\n"
        "CollectMode=inactive-or-failed\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 -I -S -B %s --hermes-home=%s --trabajo=%s --unidad-hermes=%s "
        "--usuario-hermes=%s --conexion\n"
        "StateDirectory=hehermes-respaldo\n"
        "StateDirectoryMode=0700\n"
        "%s"
        "%s"
        "# Nada de HeHermes ni de los secretos del sistema: la copia nunca lleva una llave para entrar en el servidor.\n"
        "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
        "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
        "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-avisos -/etc/hehermes-pasarela -/var/lib/hehermes-vigia "
        "-/var/lib/hehermes-pasarela -/var/lib/hehermes-rele-publico\n"
        "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
    ) % (_ruta_segura(ambito.respaldo), casa, _ruta_segura(ambito.carpeta_respaldo), unidad_hermes, usuario, comun,
         _JAULA_RESPALDO)


# MARK: El ayudante de la entrada (spec 2026-10-04, desde la 0.10.6)

SOCKET_ENTRADA = "hehermes-entrada.socket"
#: Donde el ayudante deja lo que la app le manda a Hermes, dentro de su casa (contrato §16): lo único de las casas que
#: ve. Lo crea el instalador, como `exports/`.
CARPETA_ENTRADA = "entrada"


def unidad_entrada_socket(ambito) -> str:
    """Como el del lector: con root, `/run/hehermes-entrada.sock`, de root y del grupo `hh-vigia` (0660), como en el VPS
    de Daniel (`server/avisos/despliegue/hehermes-entrada.socket`); sin root, en el `/run/user` del usuario de Hermes
    (`%t`), 0600."""
    if ambito.root:
        dueno = ("ListenStream=/run/hehermes-entrada.sock\nSocketUser=root\nSocketGroup=%s\nSocketMode=0660\n"
                 % USUARIO_VIGIA)
        que = ("# Solo root y el grupo hh-vigia pueden conectarse (0660), y el ayudante lo vuelve a mirar con SO_PEERCRED.\n"
               "# Por cada conexión, systemd lanza un ayudante como el dueño de la casa de Hermes, sin capacidades\n"
               "# (hehermes-entrada@.service).\n")
    else:
        dueno = "ListenStream=%t/hehermes-entrada.sock\nSocketMode=0600\n"
        que = ("# En el /run/user del usuario de Hermes, 0600, y el ayudante solo atiende a su propio uid (--usuario).\n"
               "# Por cada conexión, systemd lanza un ayudante como este usuario (hehermes-entrada@.service).\n")
    return (
        CABECERA
        + "# La puerta del ayudante que recibe lo que la app le manda a Hermes (/avisos/v1/entrada/… del vigía).\n"
        + que
        + "[Unit]\n"
        "Description=HeHermes: el socket del ayudante de la entrada de Hermes\n"
        "\n"
        "[Socket]\n"
        + dueno
        + "Accept=yes\n"
        "# Cuatro trozos a la vez (el vigía no deja más), crear o terminar y el estado: esto es el tope.\n"
        "MaxConnections=8\n"
        "RemoveOnStop=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n"
    )


#: La jaula del ayudante de la entrada, la del lector de root (una prueba la compara con la de
#: `server/avisos/despliegue/hehermes-entrada@.service`): lo que cambia es lo que ve, `<casa>/entrada` de lectura y
#: escritura, y los límites de lo que escribe.
_JAULA_ENTRADA = _JAULA_LECTOR
_JAULA_ENTRADA_USUARIO = _JAULA_LECTOR_USUARIO


def unidad_entrada(ambito, hermes_home: str, usuario_hermes: str | None = None) -> str:
    """Un ayudante por conexión (`Accept=yes`): recibe una orden (y los bytes de un trozo) y contesta por el mismo
    socket. Con root, con la jaula del VPS de Daniel: como el dueño de la casa de Hermes (root si Hermes es root; si no,
    su usuario) y **sin ninguna capacidad**, con las casas tapadas (`ProtectHome=tmpfs`) salvo `<casa>/entrada`
    (`BindPaths`, la única que puede escribir), y lo de los secretos del sistema y del instalador, tapado. Sin root,
    como el usuario de Hermes, con `--usuario` (solo atiende a su propio uid) y con lo que una unidad de usuario se puede
    poner: ahí, dónde escribe lo decide solo el ayudante."""
    casa = _ruta_segura(hermes_home.rstrip("/"))
    comun = (
        "StandardInput=socket\n"
        "StandardOutput=socket\n"
        "StandardError=journal\n"
        "RuntimeMaxSec=900\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "LimitFSIZE=16G\n"
    )
    if not ambito.root:
        return (
            CABECERA
            + "# Un ayudante de la entrada por conexión a %%t/hehermes-entrada.sock, como el usuario de Hermes:\n"
            "# escribe en su <casa>/entrada lo que la app le manda.\n"
            "# Lo que una unidad de usuario NO puede ponerse (ProtectSystem, ProtectHome, BindPaths,\n"
            "# InaccessiblePaths, PrivateNetwork, CapabilityBoundingSet): aquí dónde se escribe lo decide solo el\n"
            "# ayudante.\n"
            "[Unit]\n"
            "Description=HeHermes: ayudante de la entrada de Hermes\n"
            "CollectMode=inactive-or-failed\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=%s --conexion\n"
            "%s"
            "%s"
        ) % (_ruta_segura(ambito.entrada), casa, comun, _JAULA_ENTRADA_USUARIO)
    usuario = ""
    if usuario_hermes and usuario_hermes != "root":
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", usuario_hermes):
            raise ValueError("usuario de Hermes no válido para una unidad: %r" % usuario_hermes)
        usuario = "User=%s\n" % usuario_hermes
    return (
        CABECERA
        + "# Un ayudante de la entrada por conexión a /run/hehermes-entrada.sock (hehermes-entrada.socket,\n"
        "# Accept=yes). Corre como el dueño de la casa de Hermes, sin ninguna capacidad: de las casas solo ve\n"
        "# <casa>/entrada.\n"
        "[Unit]\n"
        "Description=HeHermes: ayudante de la entrada de Hermes\n"
        "CollectMode=inactive-or-failed\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 -I -S -B %s --hermes-home=%s --conexion\n"
        "%s"
        "%s"
        "%s"
        "# Las casas vacías, y dentro solo la carpeta de entrada, de lectura y escritura (si aún no existe, se\n"
        "# salta), y los perfiles de los agentes, cada uno con la suya.\n"
        "ProtectHome=tmpfs\n"
        "BindPaths=-%s/%s -%s/" + PERFILES_HERMES + "\n"
        "# Y fuera de las casas, los secretos del sistema y del instalador, tapados.\n"
        "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
        "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
        "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-avisos -/etc/hehermes-pasarela -/var/lib/hehermes-vigia "
        "-/var/lib/hehermes-pasarela -/var/lib/hehermes-rele-publico -/var/lib/hehermes-respaldo\n"
        "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
    ) % (_ruta_segura(ambito.entrada), casa, comun, usuario, _JAULA_ENTRADA, casa, CARPETA_ENTRADA, casa)


# MARK: El ayudante que actualiza el servidor (spec 2026-10-04, desde la 0.10.10)

SOCKET_ACTUALIZAR = "hehermes-actualizar.socket"


def unidad_actualizar_socket() -> str:
    """Solo con root (actualizar es instalar): `/run/hehermes-actualizar.sock`, de root y del grupo `hh-vigia` (0660),
    como en el VPS de Daniel (`server/avisos/despliegue/hehermes-actualizar.socket`)."""
    return (
        CABECERA
        + "# La puerta del ayudante que actualiza el servidor desde la app (/avisos/v1/servidor/actualizar del vigía).\n"
        "# Solo root y el grupo hh-vigia pueden conectarse (0660), y el ayudante lo vuelve a mirar con SO_PEERCRED.\n"
        "# Por cada conexión, systemd lanza un ayudante de root con su jaula (hehermes-actualizar@.service).\n"
        "[Unit]\n"
        "Description=HeHermes: el socket del ayudante que actualiza el servidor\n"
        "\n"
        "[Socket]\n"
        "ListenStream=/run/hehermes-actualizar.sock\n"
        "SocketUser=root\n"
        "SocketGroup=%s\n"
        "SocketMode=0660\n"
        "Accept=yes\n"
        "# El estado y, de vez en cuando, una petición de actualizar: esto es el tope.\n"
        "MaxConnections=4\n"
        "RemoveOnStop=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n"
    ) % USUARIO_VIGIA


#: La jaula del ayudante que actualiza, la de `server/avisos/despliegue/hehermes-actualizar@.service` (una prueba las
#: compara): solo mira y lanza, así que ninguna capacidad, sin red y de solo lectura salvo su carpeta. La actualización
#: va en su propia unidad, sin jaula (`systemd-run`).
_JAULA_ACTUALIZAR = (
    "CapabilityBoundingSet=\n"
    "AmbientCapabilities=\n"
    "NoNewPrivileges=yes\n"
    "ProtectSystem=strict\n"
    "ProtectHome=yes\n"
    "PrivateNetwork=yes\n"
    "IPAddressDeny=any\n"
    "RestrictAddressFamilies=AF_UNIX\n"
    "PrivateDevices=yes\n"
    "PrivateIPC=yes\n"
    "PrivateTmp=yes\n"
    "ProtectKernelTunables=yes\n"
    "ProtectKernelModules=yes\n"
    "ProtectKernelLogs=yes\n"
    "ProtectControlGroups=yes\n"
    "ProtectClock=yes\n"
    "ProtectHostname=yes\n"
    "ProtectProc=invisible\n"
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


def unidad_actualizar(ambito) -> str:
    """Un ayudante de root por conexión (`Accept=yes`), con root porque `systemd-run` solo se lo deja a root. No
    descarga ni instala: comprueba lo que pide la app, lo apunta y lanza la actualización en su propia unidad
    (`hehermes-actualizacion`), que no muere con el vigía ni con la pasarela."""
    return (
        CABECERA
        + "# Un ayudante por conexión a /run/hehermes-actualizar.sock (hehermes-actualizar.socket, Accept=yes): mira lo\n"
        "# que pide la app y lanza la actualización en su propia unidad (systemd-run, hehermes-actualizacion).\n"
        "[Unit]\n"
        "Description=HeHermes: ayudante que actualiza el servidor\n"
        "CollectMode=inactive-or-failed\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 -I -S -B %s --conexion\n"
        "StandardInput=socket\n"
        "StandardOutput=socket\n"
        "StandardError=journal\n"
        "StateDirectory=hehermes-actualizar\n"
        "StateDirectoryMode=0700\n"
        "RuntimeMaxSec=120\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "%s"
        "# Los secretos del sistema y de HeHermes, tapados.\n"
        "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
        "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
        "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-avisos -/etc/hehermes-pasarela -/var/lib/hehermes-vigia "
        "-/var/lib/hehermes-pasarela -/var/lib/hehermes-rele-publico -/var/lib/hehermes-respaldo\n"
        "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
    ) % (_ruta_segura(ambito.actualizar), _JAULA_ACTUALIZAR)


# MARK: El ayudante de los agentes (spec 2026-10-05, desde la 0.11.0)

SOCKET_AGENTES = "hehermes-agentes.socket"
TEMPORIZADOR_AGENTES_MEMORIA = "hehermes-agentes-memoria.timer"


def unidad_agentes_socket(ambito) -> str:
    """Como el de la copia: con root, `/run/hehermes-agentes.sock`, de root y del grupo `hh-vigia` (0660), como en el
    VPS de Daniel (`server/avisos/despliegue/hehermes-agentes.socket`); sin root, en el `/run/user` del usuario de Hermes
    (`%t`), 0600."""
    if ambito.root:
        dueno = ("ListenStream=/run/hehermes-agentes.sock\nSocketUser=root\nSocketGroup=%s\nSocketMode=0660\n"
                 % USUARIO_VIGIA)
        que = ("# Solo root y el grupo hh-vigia pueden conectarse (0660), y el ayudante lo vuelve a mirar con SO_PEERCRED.\n"
               "# Por cada conexión, systemd lanza un ayudante de root con su jaula (hehermes-agentes@.service).\n")
    else:
        dueno = "ListenStream=%t/hehermes-agentes.sock\nSocketMode=0600\n"
        que = ("# En el /run/user del usuario de Hermes, 0600, y el ayudante solo atiende a su propio uid (--usuario).\n"
               "# Por cada conexión, systemd lanza un ayudante como este usuario (hehermes-agentes@.service).\n")
    return (
        CABECERA
        + "# La puerta del ayudante de los agentes (/avisos/v1/agentes… del vigía, contrato §18).\n"
        + que
        + "[Unit]\n"
        "Description=HeHermes: el socket del ayudante de los agentes\n"
        "\n"
        "[Socket]\n"
        + dueno
        + "Accept=yes\n"
        "# La lista, un trabajo (crear o borrar, que sigue con la conexión cerrada), su estado y un cambio: esto es el\n"
        "# tope.\n"
        "MaxConnections=8\n"
        "RemoveOnStop=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=sockets.target\n"
    )


#: La jaula del ayudante de los agentes de root, la de `server/avisos/despliegue/hehermes-agentes@.service` (una prueba
#: las compara): de root y sin ninguna capacidad (si Hermes es de otro usuario, CAP_SETUID y CAP_SETGID, para hacer lo de
#: su casa como él), /usr, /boot y /etc de solo lectura salvo las dos carpetas de las claves, y solo 127.0.0.1. Sin
#: SystemCallFilter ni MemoryDenyWriteExecute: lanza el `hermes` de Hermes, con su Python y sus extensiones.
_JAULA_AGENTES = (
    "NoNewPrivileges=yes\n"
    "CapabilityBoundingSet=%s\n"
    "AmbientCapabilities=\n"
    "ProtectSystem=full\n"
    "ReadWritePaths=-%s -%s\n"
    "PrivateTmp=yes\n"
    "PrivateDevices=yes\n"
    "ProtectKernelTunables=yes\n"
    "ProtectKernelModules=yes\n"
    "ProtectKernelLogs=yes\n"
    "ProtectClock=yes\n"
    "ProtectHostname=yes\n"
    "KeyringMode=private\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "LockPersonality=yes\n"
    "SystemCallArchitectures=native\n"
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
    "IPAddressDeny=any\n"
    "IPAddressAllow=localhost\n"
)
#: Lo que una unidad de usuario sí puede ponerse.
_JAULA_AGENTES_USUARIO = (
    "NoNewPrivileges=yes\n"
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
    "RestrictNamespaces=yes\n"
    "RestrictRealtime=yes\n"
    "RestrictSUIDSGID=yes\n"
    "LockPersonality=yes\n"
    "SystemCallArchitectures=native\n"
)
#: Lo que tapa el ayudante de los agentes de root: nada de HeHermes que no sean las claves de los agentes.
_TAPADO_AGENTES = (
    "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
    "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
    "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-pasarela/clave.pem -/etc/hehermes-pasarela/siguiente "
    "-/etc/hehermes-pasarela/anterior -/etc/hehermes-pasarela/clave-hermes -/etc/hehermes-pasarela/tokens.json "
    "-/etc/hehermes-avisos/vigia -/etc/hehermes-avisos/rele -/etc/hehermes-avisos/rele-publico\n"
    "InaccessiblePaths=-/var/lib/hehermes-vigia -/var/lib/hehermes-pasarela -/var/lib/hehermes-rele-publico "
    "-/var/lib/hehermes-respaldo -/var/lib/hehermes-actualizar\n"
    "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
)


def _usuario_de_hermes(usuario_hermes) -> str:
    usuario = usuario_hermes or "root"
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", usuario):
        raise ValueError("usuario de Hermes no válido para una unidad: %r" % usuario)
    return usuario


def unidad_agentes(ambito, hermes_home: str, usuario_hermes: str | None = None,
                   unidad_hermes: str = "hermes-gateway.service") -> str:
    """Un ayudante por conexión (`Accept=yes`). Con root, de root y sin capacidades (con un Hermes de otro usuario,
    CAP_SETUID y CAP_SETGID: lo de su casa lo hace como él), con la jaula del VPS de Daniel; escribe las claves en las
    carpetas de la pasarela y del vigía. La unidad de Hermes es para encontrar su `hermes` y, con el primer agente (un
    Hermes que aún no sirve otros perfiles: lo decide al arrancar), para reiniciarla una vez, con drenaje y solo si está
    en marcha con Hermes dentro; si ya los sirve, no la toca. Sin root, como el usuario de Hermes, con `--usuario` (solo
    atiende a su propio uid) y sus claves en su casa."""
    casa = _ruta_segura(hermes_home.rstrip("/"))
    usuario = _usuario_de_hermes(usuario_hermes)
    if not re.fullmatch(r"[A-Za-z0-9:_.@-]{1,200}\.service", unidad_hermes):
        raise ValueError("unidad de Hermes no válida para una unidad: %r" % unidad_hermes)
    comun = (
        "StandardInput=socket\n"
        "StandardOutput=socket\n"
        "StandardError=journal\n"
        "RuntimeMaxSec=30min\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
    )
    if not ambito.root:
        return (
            CABECERA
            + "# Un ayudante de los agentes por conexión a %%t/hehermes-agentes.sock, como el usuario de Hermes: crea,\n"
            "# cambia y borra sus perfiles, con sus claves en su casa.\n"
            "# Lo que una unidad de usuario NO puede ponerse (ProtectSystem, ProtectHome, InaccessiblePaths,\n"
            "# IPAddressDeny, CapabilityBoundingSet): aquí lo que se lee y se escribe lo decide solo el ayudante.\n"
            "[Unit]\n"
            "Description=HeHermes: ayudante de los agentes\n"
            "CollectMode=inactive-or-failed\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=%s --trabajo=%s --claves-pasarela=%s "
            "--claves-vigia=%s --unidad-hermes=%s --conexion\n"
            "%s"
            "%s"
        ) % (_ruta_segura(ambito.agentes), casa, _ruta_segura(ambito.carpeta_agentes),
             _ruta_segura(ambito.claves_agentes_pasarela), _ruta_segura(ambito.claves_agentes_vigia), unidad_hermes,
             comun, _JAULA_AGENTES_USUARIO)
    return (
        CABECERA
        + "# Un ayudante de los agentes por conexión a /run/hehermes-agentes.sock (hehermes-agentes.socket,\n"
        "# Accept=yes). De root y sin capacidades%s: crea, cambia y borra los perfiles de Hermes de los agentes y\n"
        "# escribe sus claves para la pasarela y el vigía.\n"
        "[Unit]\n"
        "Description=HeHermes: ayudante de los agentes\n"
        "CollectMode=inactive-or-failed\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 -I -S -B %s --hermes-home=%s --usuario-hermes=%s --unidad-hermes=%s --conexion\n"
        "StateDirectory=hehermes-agentes\n"
        "StateDirectoryMode=0700\n"
        "%s"
        "%s"
        "%s"
    ) % ("" if usuario == "root" else " (salvo hacerse %s, el dueño de Hermes)" % usuario,
         _ruta_segura(ambito.agentes), casa, usuario, unidad_hermes, comun,
         _JAULA_AGENTES % ("" if usuario == "root" else "CAP_SETUID CAP_SETGID",
                           _ruta_segura(ambito.claves_agentes_pasarela), _ruta_segura(ambito.claves_agentes_vigia)),
         _TAPADO_AGENTES)


def unidad_agentes_memoria(ambito, hermes_home: str, usuario_hermes: str | None = None) -> str:
    """Lo que lanza `hehermes-agentes-memoria.timer` cada minuto: la memoria que comparten los agentes (contrato
    §18.8). Con root, de root y sin capacidades ni red (con un Hermes de otro usuario, CAP_SETUID y CAP_SETGID), todo de
    solo lectura menos la casa de Hermes; sin root, como el usuario de Hermes."""
    casa = _ruta_segura(hermes_home.rstrip("/"))
    usuario = _usuario_de_hermes(usuario_hermes)
    if not ambito.root:
        return (
            CABECERA
            + "# Cada minuto, lo que saben de ti los agentes que lo comparten (hehermes-agentes-memoria.timer), como el\n"
            "# usuario de Hermes.\n"
            "[Unit]\n"
            "Description=HeHermes: junta lo que saben de ti los agentes que lo comparten\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=%s --trabajo=%s --claves-pasarela=%s "
            "--claves-vigia=%s sincronizar-memoria\n"
            "TimeoutStartSec=5min\n"
            "UMask=0077\n"
            "LimitCORE=0\n"
            "Nice=10\n"
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
        ) % (_ruta_segura(ambito.agentes), casa, _ruta_segura(ambito.carpeta_agentes),
             _ruta_segura(ambito.claves_agentes_pasarela), _ruta_segura(ambito.claves_agentes_vigia))
    return (
        CABECERA
        + "# Cada minuto, lo que saben de ti los agentes que lo comparten (hehermes-agentes-memoria.timer): sin red y sin\n"
        "# lanzar hermes; solo lee y escribe las memorias de la casa de Hermes.\n"
        "[Unit]\n"
        "Description=HeHermes: junta lo que saben de ti los agentes que lo comparten\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/python3 -I -S -B %s --hermes-home=%s --usuario-hermes=%s sincronizar-memoria\n"
        "StateDirectory=hehermes-agentes\n"
        "StateDirectoryMode=0700\n"
        "TimeoutStartSec=5min\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
        "NoNewPrivileges=yes\n"
        "CapabilityBoundingSet=%s\n"
        "AmbientCapabilities=\n"
        "ProtectSystem=strict\n"
        "ReadWritePaths=-%s\n"
        "PrivateNetwork=yes\n"
        "IPAddressDeny=any\n"
        "RestrictAddressFamilies=AF_UNIX\n"
        "PrivateTmp=yes\n"
        "PrivateDevices=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectKernelLogs=yes\n"
        "ProtectControlGroups=yes\n"
        "ProtectClock=yes\n"
        "ProtectHostname=yes\n"
        "KeyringMode=private\n"
        "RestrictNamespaces=yes\n"
        "RestrictRealtime=yes\n"
        "RestrictSUIDSGID=yes\n"
        "LockPersonality=yes\n"
        "MemoryDenyWriteExecute=yes\n"
        "SystemCallArchitectures=native\n"
        "SystemCallFilter=@system-service\n"
        "SystemCallErrorNumber=EPERM\n"
        "InaccessiblePaths=-/etc/shadow -/etc/shadow- -/etc/gshadow -/etc/gshadow- -/etc/sudoers -/etc/sudoers.d\n"
        "InaccessiblePaths=-/etc/ssh -/etc/ssl/private -/etc/letsencrypt\n"
        "InaccessiblePaths=-/etc/hehermes -/etc/hehermes-avisos -/etc/hehermes-pasarela -/var/lib/hehermes-vigia "
        "-/var/lib/hehermes-pasarela -/var/lib/hehermes-rele-publico -/var/lib/hehermes-respaldo\n"
        "InaccessiblePaths=-/etc/nginx -/etc/swanctl -/etc/strongswan -/etc/ipsec.secrets -/etc/ipsec.d -/etc/wireguard\n"
    ) % (_ruta_segura(ambito.agentes), casa, usuario, "" if usuario == "root" else "CAP_SETUID CAP_SETGID", casa)


def temporizador_agentes_memoria() -> str:
    return (
        CABECERA
        + "# Cada minuto, lo que saben de ti los agentes que lo comparten (hehermes-agentes-memoria.service). Sin\n"
        "# Persistent: un minuto perdido no se recupera, lo hace el siguiente.\n"
        "[Unit]\n"
        "Description=HeHermes: la memoria que comparten los agentes, cada minuto\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=minutely\n"
        "AccuracySec=5s\n"
        "Persistent=false\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
