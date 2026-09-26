"""La detección: todo lo que el instalador necesita saber del servidor, sin cambiar nada.

Solo ejecuta órdenes que leen (`systemctl is-active`, `ss`, `ip -j`, `nginx -t`, `ufw status`…) y dos GET a Hermes en
127.0.0.1. Lo que impide instalar va a `bloqueos`; lo que hay que saber pero no impide, a `avisos`. La clave de Hermes
se lee para probarla y para nginx, y no sale nunca en ningún texto.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import shlex

from . import piezas as p
from .entorno import leer_env

SOPORTADAS = {("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04"), ("ubuntu", "26.04")}
#: El nombre en clave de cada Debian y Ubuntu: es como dicen en cuál se basan las derivadas (Linux Mint y Pop!_OS con
#: `UBUNTU_CODENAME`, Raspberry Pi OS y LMDE con `VERSION_CODENAME` o `DEBIAN_CODENAME`). Las viejas, para decir cuál es.
CODIGOS = {"bookworm": ("debian", "12"), "trixie": ("debian", "13"), "jammy": ("ubuntu", "22.04"),
           "noble": ("ubuntu", "24.04"), "resolute": ("ubuntu", "26.04"), "bullseye": ("debian", "11"),
           "buster": ("debian", "10"), "focal": ("ubuntu", "20.04"), "bionic": ("ubuntu", "18.04")}
#: La familia Red Hat: RHEL y sus reconstrucciones (Rocky Linux, AlmaLinux, CentOS Stream) 9 y 10, y Fedora desde la
#: 42. RHEL 8 no: su núcleo es un 4.18 y su python3 un 3.6.
EL_SOPORTADAS = ("9", "10")
FEDORA_MINIMA = 42
LISTA = ("Debian 12 y 13, Ubuntu 22.04, 24.04 y 26.04 y sus derivadas; Rocky Linux, AlmaLinux, RHEL y CentOS Stream 9 "
         "y 10, y Fedora %d o más nueva" % FEDORA_MINIMA)
ARQUITECTURAS = ("amd64", "arm64")
#: Lo que da `uname -m`, con el nombre de Debian, que es el que se enseña.
MAQUINAS = {"x86_64": "amd64", "aarch64": "arm64"}
PAQUETES = ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "qrencode", "nginx", "python3-venv")
#: Lo que se mira de la familia Red Hat. strongSwan, en RHEL y sus reconstrucciones, viene de EPEL.
PAQUETES_RPM = ("strongswan", "qrencode", "nginx", "policycoreutils-python-utils", "epel-release")
#: Lo que se instala para `semanage`, si SELinux está puesto y no está.
PAQUETE_SEMANAGE = "policycoreutils-python-utils"
#: Dónde tiene swanctl su configuración: en Fedora y EPEL, dentro de /etc/strongswan.
SWANCTL = {"debian": "/etc/swanctl", "rhel": "/etc/strongswan/swanctl"}
CABECERA_DISPOSITIVO = "# Generado por hehermes-dispositivo."
ROJO = "\033[31m"
NORMAL = "\033[0m"
DIRECCION_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Las de documentación (RFC 5737) no son de nadie y ningún servidor de verdad sale por una: cuentan como públicas, para
# que las pruebas y los ejemplos las usen en vez de la dirección de un servidor que exista.
_DOCUMENTACION = tuple(ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
_IF_ID = ("0x77", "119", 119)


class Hermes:
    """Un Hermes encontrado. La clave va aparte y no sale en `repr`."""

    def __init__(self, usuario, home, origen):
        self.usuario, self.home, self.origen = usuario, home, origen
        self.env = home.rstrip("/") + "/.env"
        self.habilitada = False
        self.host = "127.0.0.1"
        self.puerto = 8642
        self.clave_vale = None
        self._clave = None
        #: Con --activar-api y la API apagada: las líneas que hay que añadir al .env (la clave va en claro: no se
        #: pinta nunca, solo sus nombres).
        self.api_pendiente = []
        #: El entorno con el que corre (el de su unidad o el de su proceso): puede fijar API_SERVER_* por encima del .env.
        self.entorno = {}
        #: Si la unidad está en marcha (None: no es una unidad, o no se sabe).
        self.en_marcha = None
        #: Dónde escucha su API si es en todas las interfaces («0.0.0.0:8642»), o None.
        self.expuesta = None
        #: Con --corregir-exposicion: la línea que cierra la API a 127.0.0.1, si se puede poner en el .env.
        self.exposicion_pendiente = None

    @property
    def clave(self):
        return self._clave

    def __repr__(self):
        return "Hermes(%s, %s, %s:%s)" % (self.usuario, self.env, self.host, self.puerto)


class Deteccion:
    def __init__(self):
        self.distro = {}
        #: «debian» (apt, ufw) o «rhel» (dnf, firewalld, SELinux).
        self.familia = "debian"
        self.swanctl = SWANCTL["debian"]
        #: «enforcing», «permissive» o None (sin SELinux o apagado).
        self.selinux = None
        #: La etiqueta de SELinux del puerto de Hermes, si la tiene uno solo (no un rango): nginx necesita http_port_t.
        self.selinux_puerto = None
        self.firewalld = None
        self.reglas_firewalld = set()
        self.hermes = None
        self.hermes_encontrados = []
        self.direccion = None
        self.direccion_privada = False
        self.paquetes_instalados = set()
        self.nginx = {"instalado": False, "activo": False, "sitios": "sites-enabled", "prueba": None}
        self.strongswan = {"swanctl": False, "activo": False}
        self.ufw = None
        self.reglas_ufw = []
        #: nftables e iptables a pelo: las cadenas que cierran y donde van las reglas (`cortafuegos.Lugar`).
        self.lugares = []
        #: Si iptables es del usuario (no lo llevan por debajo ufw ni firewalld).
        self.con_iptables = True
        self.cortafuegos_a_mano = False
        self.a_mano = []
        self.bloqueos = []
        self.avisos = []

    @property
    def sitio(self):
        return p.SITIO if self.nginx["sitios"] == "sites-enabled" else p.SITIO_CONF_D


def detectar(sis, man, direccion=None, hermes_home=None, activar_api=False, cortafuegos_a_mano=False,
             corregir_exposicion=False) -> Deteccion:
    det = Deteccion()
    if not _distro(sis, det):
        return det
    _hermes(sis, det, hermes_home, activar_api, corregir_exposicion)
    _direccion(sis, det, direccion)
    _paquetes(sis, det)
    _nginx(sis, det, man)
    _puertos(sis, det)
    _strongswan(sis, det, man)
    _redes(sis, det, man)
    _a_mano(sis, det, man)
    _cortafuegos(sis, det, cortafuegos_a_mano)
    _selinux(sis, det)
    return det


# MARK: El sistema


def _base(datos):
    """(familia, base, derivada) de lo que dice os-release, o un texto con por qué no. `base` es la versión de la lista
    en la que se basa (`("ubuntu", "24.04")`, `("el", "9")`, `("fedora", "42")`); `derivada`, el nombre de la derivada
    cuando no es la de la lista misma. Sin nada ejecutado: solo el fichero."""
    ident = datos.get("ID", "").lower()
    version = datos.get("VERSION_ID", "")
    parecidas = datos.get("ID_LIKE", "").lower().split()
    nombre = datos.get("PRETTY_NAME") or datos.get("NAME") or ident or "?"
    if (ident, version) in SOPORTADAS:
        return "debian", (ident, version), None
    if ident in ("debian", "ubuntu"):
        return None, None, "%s no es una de las que sé instalar (%s): no he tocado nada" % (nombre, LISTA)
    if "debian" in parecidas or "ubuntu" in parecidas:
        for clave in ("UBUNTU_CODENAME", "DEBIAN_CODENAME", "VERSION_CODENAME"):
            base = CODIGOS.get(datos.get(clave, "").lower())
            if base:
                return "debian", base, nombre
        return "debian", None, nombre
    plataforma = re.match(r"^platform:(el|f)(\d+)$", datos.get("PLATFORM_ID", ""))
    if ident in ("rhel", "rocky", "almalinux", "centos", "fedora") or {"rhel", "fedora", "centos"} & set(parecidas):
        if plataforma:
            familia, numero = ("fedora" if plataforma.group(1) == "f" else "el"), plataforma.group(2)
        else:
            familia, numero = ("fedora" if ident == "fedora" else "el"), version.split(".")[0]
        vale = numero in EL_SOPORTADAS if familia == "el" else numero.isdigit() and int(numero) >= FEDORA_MINIMA
        if not vale:
            return None, None, "%s no es una de las que sé instalar (%s): no he tocado nada" % (nombre, LISTA)
        propia = ident in ("rhel", "rocky", "almalinux", "centos", "fedora")
        return "rhel", (familia, numero), None if propia else nombre
    return None, None, "%s no es una de las que sé instalar (%s): no he tocado nada" % (nombre, LISTA)


def _nombre_de(base):
    familia, version = base
    return {"debian": "Debian", "ubuntu": "Ubuntu", "el": "RHEL", "fedora": "Fedora"}[familia] + " " + version


def _distro(sis, det) -> bool:
    # En Ubuntu y en Debian /etc/os-release es un enlace a /usr/lib/os-release, y `leer` no sigue enlaces: se lee el de
    # /usr/lib, que es el sitio de verdad (os-release(5)), y /etc solo si no está.
    datos = leer_env(sis.leer_texto("/usr/lib/os-release") or sis.leer_texto("/etc/os-release") or "")
    det.distro = {"id": datos.get("ID", "?"), "version": datos.get("VERSION_ID", "?"),
                  "nombre": datos.get("PRETTY_NAME", "?")}
    familia, base, derivada = _base(datos)
    if familia is None:
        det.bloqueos.append(derivada)
        return False
    det.familia, det.swanctl = familia, SWANCTL[familia]
    if base is not None:
        det.distro["base"], det.distro["base_id"] = _nombre_de(base), base[0]
    if derivada and base is None:
        det.avisos.append("%s es una derivada de Debian o Ubuntu, pero no sé de qué versión: la trato como ellas, "
                          "aunque no está probada. Si falta algo, me paro antes de tocarlo" % derivada)
    elif derivada and familia == "debian" and base not in SOPORTADAS:
        det.avisos.append("%s se basa en %s, que no está en la lista (%s): la trato como las demás, aunque no está "
                          "probada. Si falta algo, me paro antes de tocarlo" % (derivada, _nombre_de(base), LISTA))
    elif derivada:
        det.avisos.append("%s es una derivada de %s: la instalo como ella" % (derivada, _nombre_de(base)))
    if familia == "debian":
        r = sis.ejecutar(["dpkg", "--print-architecture"])
        det.distro["arquitectura"] = r.salida.strip() or "?"
    else:
        r = sis.ejecutar(["uname", "-m"])
        maquina = r.salida.strip() or "?"
        det.distro["arquitectura"] = MAQUINAS.get(maquina, maquina)
    if det.distro["arquitectura"] not in ARQUITECTURAS:
        det.bloqueos.append("la arquitectura %s no está entre las que sé instalar (amd64 y arm64)"
                            % det.distro["arquitectura"])
    # 3.9 y no 3.10: es el python3 de RHEL 9 y sus reconstrucciones, y el instalador no usa nada más nuevo.
    if tuple(sis.version_python[:2]) < (3, 9):
        det.bloqueos.append("hace falta Python 3.9 o más nuevo, y este es %s" % ".".join(map(str, sis.version_python)))
    m = re.match(r"(\d+)\.(\d+)", sis.nucleo)
    if not m or (int(m.group(1)), int(m.group(2))) < (4, 19):
        det.bloqueos.append("el núcleo %s es anterior al 4.19: no tiene las interfaces XFRM" % sis.nucleo)
    if not sis.es_carpeta("/run/systemd/system"):
        det.bloqueos.append("este sistema no arranca con systemd")
    gestor = "apt-get" if familia == "debian" else "dnf"
    if not sis.cual(gestor):
        det.bloqueos.append("no encuentro %s" % gestor)
    det.distro["nucleo"] = sis.nucleo
    det.distro["python"] = ".".join(map(str, sis.version_python[:2]))
    return True


# MARK: Hermes


def _home(sis, usuario):
    for linea in (sis.leer_texto("/etc/passwd") or "").splitlines():
        campos = linea.split(":")
        if len(campos) >= 6 and campos[0] == usuario:
            return campos[5]
    return "/root" if usuario == "root" else "/home/" + usuario


def _propiedades(texto):
    return dict(linea.split("=", 1) for linea in texto.splitlines() if "=" in linea)


def _candidatos(sis):
    candidatos = []
    r = sis.ejecutar(["systemctl", "show", "hermes-gateway.service", "-p", "LoadState", "-p", "ActiveState",
                      "-p", "User", "-p", "Environment"])
    props = _propiedades(r.salida)
    if props.get("LoadState") == "loaded":
        usuario = props.get("User") or "root"
        entorno = dict(x.split("=", 1) for x in props.get("Environment", "").split() if "=" in x)
        hermes = Hermes(usuario, entorno.get("HERMES_HOME") or _home(sis, usuario) + "/.hermes",
                        "la unidad hermes-gateway")
        hermes.entorno = entorno
        hermes.en_marcha = props.get("ActiveState") in ("active", "reloading", "activating")
        candidatos.append(hermes)
    r = sis.ejecutar(["ps", "-eo", "pid=,user=,args="])
    for linea in r.salida.splitlines():
        partes = linea.split(None, 2)
        if len(partes) < 3 or not re.search(r"\bhermes\b", partes[2]) or "gateway" not in partes[2]:
            continue
        pid, usuario = partes[0], partes[1]
        entorno = {}
        for par in (sis.leer("/proc/%s/environ" % pid) or b"").split(b"\0"):
            if b"=" in par:
                clave, _, valor = par.decode("utf-8", "replace").partition("=")
                entorno[clave] = valor
        hermes = Hermes(usuario, entorno.get("HERMES_HOME") or _home(sis, usuario) + "/.hermes", "el proceso %s" % pid)
        hermes.entorno = entorno
        candidatos.append(hermes)
    vistos, unicos = set(), []
    for c in candidatos:
        if c.home.rstrip("/") not in vistos:
            vistos.add(c.home.rstrip("/"))
            unicos.append(c)
        elif c.origen.startswith("el proceso"):
            # La unidad y su proceso son el mismo Hermes: si el proceso está, está en marcha.
            next(u for u in unicos if u.home.rstrip("/") == c.home.rstrip("/")).en_marcha = True
    return unicos


def _carpetas_de_hermes(sis) -> list:
    """Las carpetas `.hermes` con un `.env` en las casas de los usuarios: un Hermes instalado, aunque no corra."""
    casas = ["/root"] + ["/home/" + n for n in sis.listar("/home")]
    return [c + "/.hermes" for c in casas if sis.existe(c + "/.hermes/.env")]


def _hermes(sis, det, hermes_home, activar_api=False, corregir_exposicion=False):
    candidatos = _candidatos(sis)
    det.hermes_encontrados = candidatos
    if hermes_home:
        elegido = next((c for c in candidatos if c.home.rstrip("/") == hermes_home.rstrip("/")), None)
        elegido = elegido or Hermes("?", hermes_home, "--hermes-home")
    elif not candidatos:
        carpetas = _carpetas_de_hermes(sis)
        if carpetas:
            det.bloqueos.append("Hermes parece instalado (%s), pero no está en marcha: no encuentro ni la unidad "
                                "hermes-gateway ni su proceso. Arráncalo y vuelve a lanzarme" % ", ".join(carpetas))
        else:
            det.bloqueos.append("No encuentro Hermes (ni la unidad hermes-gateway ni su proceso). Este instalador no "
                                "instala Hermes: instálalo y arráncalo antes")
        return
    elif len(candidatos) > 1:
        det.bloqueos.append("Hay varios Hermes; dime cuál con --hermes-home:\n" + "\n".join(
            "      %s (de %s, por %s)" % (c.home, c.usuario, c.origen) for c in candidatos))
        return
    else:
        elegido = candidatos[0]
    det.hermes = elegido
    if elegido.en_marcha is False:
        det.bloqueos.append("Hermes está instalado (la unidad hermes-gateway), pero parado. Arráncalo (systemctl start "
                            "hermes-gateway) y vuelve a lanzarme")
        return
    texto = sis.leer_texto(elegido.env)
    if texto is None:
        det.bloqueos.append("no puedo leer %s, el .env de Hermes" % elegido.env)
        return
    env = leer_env(texto)
    elegido.habilitada = env.get("API_SERVER_ENABLED", "").lower() in ("1", "true", "yes", "on")
    elegido._clave = env.get("API_SERVER_KEY") or None
    # Lo que fija su entorno manda sobre el .env (python-dotenv no pisa lo que ya está en el entorno).
    elegido.host = elegido.entorno.get("API_SERVER_HOST") or env.get("API_SERVER_HOST") or "127.0.0.1"
    try:
        elegido.puerto = int(env.get("API_SERVER_PORT") or 8642)
        if not 0 < elegido.puerto < 65536:
            raise ValueError
    except ValueError:
        det.bloqueos.append("API_SERVER_PORT de %s no es un puerto" % elegido.env)
        return
    if activar_api and not (elegido.habilitada and elegido.clave):
        _activar_api(det, elegido, env)
        return
    if not elegido.habilitada:
        det.bloqueos.append("La API de Hermes está apagada (API_SERVER_ENABLED en %s). Enciéndela y reinicia Hermes, "
                            "o vuelve a lanzarme con --activar-api" % elegido.env)
        return
    if not elegido.clave:
        det.bloqueos.append("Hermes no tiene API_SERVER_KEY en %s: sin clave, la API no se puede proteger" % elegido.env)
        return
    try:
        p.bearer(elegido.clave)
    except ValueError:
        det.bloqueos.append("la API_SERVER_KEY de %s tiene caracteres que no sé poner en nginx" % elegido.env)
        return
    if elegido.host not in TODAS and elegido.host not in ("127.0.0.1", "localhost"):
        det.bloqueos.append("Hermes escucha en %s y no en 127.0.0.1: nginx no lo alcanzaría" % elegido.host)
        return
    _exposicion(sis, det, elegido, env, corregir_exposicion)
    base = "http://127.0.0.1:%d" % elegido.puerto
    estado, _ = sis.http_get(base + "/health")
    if estado is None:
        det.bloqueos.append("Hermes está en marcha, pero su API no contesta en 127.0.0.1:%d: ¿la tiene encendida "
                            "(API_SERVER_ENABLED) y en ese puerto (API_SERVER_PORT)?" % elegido.puerto)
        return
    if estado != 200:
        det.bloqueos.append("En 127.0.0.1:%d contesta algo que no es la API de Hermes (/health da %s): mira qué usa "
                            "ese puerto, o el API_SERVER_PORT de %s" % (elegido.puerto, estado, elegido.env))
        return
    estado, _ = sis.http_get(base + "/api/sessions?limit=1", {"Authorization": "Bearer " + elegido.clave})
    elegido.clave_vale = estado == 200
    if estado in (401, 403):
        det.bloqueos.append("Hermes no la acepta: la API_SERVER_KEY de %s no es la que usa (¿falta reiniciarlo?)"
                            % elegido.env)
    elif estado != 200:
        det.bloqueos.append("Hermes contesta %s a /api/sessions con su clave" % estado)


TODAS = ("0.0.0.0", "::", "[::]", "*")


def _exposicion(sis, det, elegido, env, corregir):
    """La API de Hermes escuchando en todas las interfaces: se mira lo que dice su configuración y lo que de verdad
    escucha (`ss`). Se avisa muy claro; solo con --corregir-exposicion se cambia, y solo en el .env."""
    donde = None
    if elegido.host in TODAS:
        donde = "%s:%d" % (elegido.host, elegido.puerto)
    for host, puerto, _ in _escuchan(sis, "tcp"):
        if puerto == str(elegido.puerto) and host in TODAS:
            donde = "%s:%d" % (host, elegido.puerto)
    elegido.expuesta = donde
    if not donde:
        return
    riesgo = ("La API de Hermes escucha en %s, en todas las interfaces: cualquiera que llegue a este servidor puede "
              "hablar con ella sin pasar por la VPN, y solo la protege su clave. No lo cambio sin que me lo pidas, "
              "porque puede que otra cosa tuya la use así" % donde)
    if "API_SERVER_HOST" in elegido.entorno:
        como = ("Lo fija el entorno de %s (Environment=API_SERVER_HOST=%s): cámbialo ahí a 127.0.0.1 y reinícialo"
                % (elegido.origen, elegido.entorno["API_SERVER_HOST"]))
        puede = False
    elif env.get("API_SERVER_HOST") in ("127.0.0.1", "localhost"):
        como = ("Su .env ya dice 127.0.0.1, así que lo saca de otro sitio: mira cómo lo arrancas")
        puede = False
    else:
        como = ("Para que escuche solo en 127.0.0.1, vuelve a lanzarme con --corregir-exposicion: añado "
                "API_SERVER_HOST=127.0.0.1 al final de %s (con una copia antes) y reinicio Hermes 90 s después"
                % elegido.env)
        puede = True
    if corregir and puede and elegido.origen != "la unidad hermes-gateway":
        det.bloqueos.append("Con --corregir-exposicion tendría que reiniciar Hermes, y no corre como la unidad "
                            "hermes-gateway (lo encuentro por %s): no sé reiniciarlo. Añade tú API_SERVER_HOST=127.0.0.1 "
                            "a %s y reinícialo" % (elegido.origen, elegido.env))
    elif corregir and puede:
        elegido.exposicion_pendiente = "API_SERVER_HOST=127.0.0.1"
        det.avisos.append("La API de Hermes escucha en %s: la cierro a 127.0.0.1 (--corregir-exposicion)" % donde)
        return
    elif corregir:
        det.bloqueos.append("Con --corregir-exposicion no puedo cerrarla desde el .env. %s" % como)
    det.avisos.append(ROJO + "%s. %s" % (riesgo, como) + NORMAL)


def _activar_api(det, elegido, env):
    """Decisión 6: solo las líneas que faltan, y Hermes se reinicia 90 s después de acabar, para no cortarle el turno
    en el que contesta con el enlace. Hermes aún no escucha: no hay nada que probar hasta entonces."""
    if elegido.origen != "la unidad hermes-gateway":
        det.bloqueos.append("La API de Hermes está apagada y Hermes no corre como la unidad hermes-gateway (lo encuentro "
                            "por %s): no sé reiniciarlo. Enciende tú la API en %s y reinícialo" % (elegido.origen,
                                                                                               elegido.env))
        return
    if elegido.host not in ("127.0.0.1", "localhost"):
        det.bloqueos.append("API_SERVER_HOST de %s es %s: no enciendo una API que no escuche solo en 127.0.0.1"
                            % (elegido.env, elegido.host))
        return
    if elegido.clave:
        try:
            p.bearer(elegido.clave)
        except ValueError:
            det.bloqueos.append("la API_SERVER_KEY de %s tiene caracteres que no sé poner en nginx" % elegido.env)
            return
    if not elegido.habilitada:
        elegido.api_pendiente.append("API_SERVER_ENABLED=true")
    if "API_SERVER_HOST" not in env:
        elegido.api_pendiente.append("API_SERVER_HOST=127.0.0.1")
    if not elegido.clave:
        # URL-safe: la clave va entre comillas en el bearer de nginx y así no hay nada que escapar.
        elegido._clave = secrets.token_urlsafe(32)
        elegido.api_pendiente.append("API_SERVER_KEY=" + elegido.clave)
    elegido.habilitada = True


# MARK: La dirección


def _es_privada(ip):
    if any(ip in red for red in _DOCUMENTACION):
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or (ip.version == 4 and ip in _CGNAT)


def _direccion(sis, det, direccion):
    if direccion is not None:
        if not DIRECCION_VALIDA.match(direccion):
            det.bloqueos.append("--direccion tiene que ser una IP o un nombre de host")
            return
        det.direccion = direccion
        return
    r = sis.ejecutar(["ip", "-4", "-j", "route", "get", "1.1.1.1"])
    try:
        salida = json.loads(r.salida)[0]["prefsrc"]
        ip = ipaddress.ip_address(salida)
    except (ValueError, KeyError, IndexError, TypeError):
        det.bloqueos.append("no sé la dirección pública de este servidor: dímela con --direccion")
        return
    if _es_privada(ip):
        det.direccion_privada = True
        det.bloqueos.append("la dirección de salida de este servidor es privada (%s): parece que está detrás de un NAT. "
                            "Dime la pública con --direccion <IP o nombre>" % ip)
        return
    det.direccion = str(ip)


# MARK: Paquetes, nginx y puertos


def _paquetes(sis, det):
    if det.familia == "rhel":
        # `rpm -q` dice «package x is not installed» de lo que falta; con --qf, de lo que está, solo su nombre.
        r = sis.ejecutar(["rpm", "-q", "--qf", "%{NAME}\n"] + list(PAQUETES_RPM))
        det.paquetes_instalados |= {linea.strip() for linea in r.salida.splitlines()} & set(PAQUETES_RPM)
        if det.distro.get("base_id") == "el" and not {"strongswan", "epel-release"} & det.paquetes_instalados:
            det.bloqueos.append("strongSwan no está en los repositorios de serie de %s: está en EPEL. Actívalo (en "
                                "Rocky y AlmaLinux, dnf install epel-release; en RHEL, el epel-release de "
                                "dl.fedoraproject.org y CodeReady Builder) y vuelve a lanzarme. No lo activo yo: es "
                                "añadirle un repositorio a tu sistema" % det.distro["nombre"])
        return
    r = sis.ejecutar(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Status}\n"] + list(PAQUETES))
    for linea in r.salida.splitlines():
        nombre, _, estado = linea.partition("\t")
        if estado.strip() == "installed":
            det.paquetes_instalados.add(nombre.strip())


def _activo(sis, unidad):
    return sis.ejecutar(["systemctl", "is-active", unidad]).bien


def _nginx(sis, det, man):
    n = det.nginx
    n["instalado"] = "nginx" in det.paquetes_instalados or sis.cual("nginx") is not None
    if not n["instalado"]:
        # El que se va a instalar: el de Debian y Ubuntu trae sites-enabled; el de la familia Red Hat, solo conf.d.
        n["sitios"] = "conf.d" if det.familia == "rhel" else "sites-enabled"
        return
    n["activo"] = _activo(sis, "nginx")
    conf = re.sub(r"#[^\n]*", "", sis.leer_texto("/etc/nginx/nginx.conf") or "")
    if re.search(r"include\s+/etc/nginx/sites-enabled/\*", conf):
        n["sitios"] = "sites-enabled"
    elif re.search(r"include\s+/etc/nginx/conf\.d/\*\.conf", conf):
        n["sitios"] = "conf.d"
    else:
        n["sitios"] = None
        det.bloqueos.append("/etc/nginx/nginx.conf no incluye ni sites-enabled/* ni conf.d/*.conf: no sé dónde poner "
                            "el sitio del túnel sin tocarlo")
    r = sis.ejecutar(["nginx", "-t"])
    n["prueba"] = r.bien
    if not r.bien:
        det.bloqueos.append("«nginx -t» ya fallaba antes de tocar nada; arréglalo primero:\n      "
                            + (r.error or r.salida).strip().replace("\n", "\n      "))
    if not n["activo"] and "nginx" not in man.paquetes:
        det.bloqueos.append("nginx está instalado pero parado. Si sirve para otras cosas, arráncalo tú (no lo hago "
                            "yo: arrancaría también sus otros sitios) y vuelve a lanzarme")


def _escuchan(sis, protocolo):
    r = sis.ejecutar(["ss", "-H", "-ltnp" if protocolo == "tcp" else "-lunp"])
    for linea in r.salida.splitlines():
        campos = linea.split()
        if len(campos) < 5:
            continue
        local = campos[3]
        dueno = re.search(r'users:\(\("([^"]+)"', linea)
        yield local.rsplit(":", 1)[0], local.rsplit(":", 1)[-1], dueno.group(1) if dueno else "?"


def _puertos(sis, det):
    for host, puerto, dueno in _escuchan(sis, "tcp"):
        if puerto == "80" and host in ("0.0.0.0", "*", "[::]", "::", p.IP_TUNEL) and dueno != "nginx":
            det.bloqueos.append("%s tiene el TCP 80 en %s: el túnel necesita 10.77.0.1:80 para nginx. Arreglarlo "
                                "pide que el QR lleve el puerto, y eso cambia la app" % (dueno, host))
    for host, puerto, dueno in _escuchan(sis, "udp"):
        if puerto in ("500", "4500") and dueno not in ("charon", "charon-systemd"):
            det.bloqueos.append("%s tiene el UDP %s: IKEv2 necesita el 500 y el 4500 para strongSwan" % (dueno, puerto))


# MARK: strongSwan


def leer_swanctl(texto):
    """Lo justo del formato de swanctl: secciones anidadas y `clave = valor`, también en una sola línea."""
    raiz, pila, nombre = {}, [], None
    pila.append(raiz)
    for trozo in re.findall(r"\{|\}|[^{}\n]+", re.sub(r"#[^\n]*", "", texto)):
        trozo = trozo.strip()
        if not trozo:
            continue
        if trozo == "{":
            seccion = pila[-1].setdefault(nombre or "?", {})
            pila.append(seccion if isinstance(seccion, dict) else {})
            nombre = None
        elif trozo == "}":
            if len(pila) > 1:
                pila.pop()
        elif "=" in trozo:
            clave, _, valor = trozo.partition("=")
            pila[-1][clave.strip()] = valor.strip().strip('"')
        else:
            nombre = trozo
    return raiz


def _ficheros_swanctl(sis, man, carpeta=SWANCTL["debian"]):
    """Los ficheros de configuración de swanctl que no son de HeHermes (ni del instalador ni de hehermes-dispositivo)."""
    rutas = [carpeta + "/swanctl.conf"] + [carpeta + "/conf.d/" + f for f in sis.listar(carpeta + "/conf.d")
                                           if f.endswith(".conf")]
    for ruta in rutas:
        texto = sis.leer_texto(ruta)
        if texto is None or ruta in man.ficheros or texto.startswith(CABECERA_DISPOSITIVO):
            continue
        yield ruta, leer_swanctl(texto)


def _rangos(valor):
    for trozo in valor.split(","):
        trozo = trozo.strip()
        try:
            if "-" in trozo:
                a, b = (ipaddress.ip_address(x.strip()) for x in trozo.split("-", 1))
                yield ipaddress.ip_network("%s/32" % a) if a == b else ipaddress.summarize_address_range(a, b)
            else:
                yield ipaddress.ip_network(trozo, strict=False)
        except (ValueError, TypeError):
            continue


def _strongswan(sis, det, man):
    s = det.strongswan
    s["swanctl"] = sis.cual("swanctl") is not None
    s["activo"] = _activo(sis, "strongswan")
    if _activo(sis, "strongswan-starter"):
        det.bloqueos.append("strongSwan corre con ipsec.conf (strongswan-starter): no puede compartir los UDP 500 y "
                            "4500 con el charon de swanctl. Pásalo a swanctl o páralo")
    conf = sis.leer_texto(det.swanctl + "/swanctl.conf")
    if conf is not None and not re.search(r"^\s*include\s+conf\.d/\*\.conf", conf, re.M):
        det.bloqueos.append("%s/swanctl.conf no incluye conf.d/*.conf: no cargaría las conexiones de los "
                            "iPhone, y ese fichero no lo toco" % det.swanctl)
    red = ipaddress.ip_network(p.RED_HEHERMES)
    for ruta, conf in _ficheros_swanctl(sis, man, det.swanctl):
        for nombre, conexion in (conf.get("connections") or {}).items():
            if not isinstance(conexion, dict):
                continue
            if nombre.startswith("hh-"):
                det.a_mano.append("la conexión %s (%s)" % (nombre, ruta))
            for clave, remoto in conexion.items():
                if clave.startswith("remote") and isinstance(remoto, dict) and remoto.get("auth") == "psk" \
                        and remoto.get("id", "%any") in ("%any", ""):
                    det.bloqueos.append("la conexión %s de %s contesta a %%any con PSK: se quedaría con los iPhone de "
                                        "HeHermes. Dale un remote.id" % (nombre, ruta))
            for hijo in (conexion.get("children") or {}).values():
                # Una conexión `hh-*` ya sale como señal de una instalación a mano: no se repite aquí.
                if not nombre.startswith("hh-") and isinstance(hijo, dict) and any(hijo.get(k) in _IF_ID[:2] for k in ("if_id_in", "if_id_out")):
                    det.bloqueos.append("la conexión %s de %s ya usa el if_id 0x77, que es el de hh-ipsec"
                                        % (nombre, ruta))
        for nombre, pool in (conf.get("pools") or {}).items():
            if isinstance(pool, dict) and any(r.overlaps(red) for r in _redes_de(pool.get("addrs", ""))) \
                    and not nombre.startswith("hh-"):
                det.bloqueos.append("el pool %s de %s reparte direcciones de %s, que son de HeHermes"
                                    % (nombre, ruta, p.RED_HEHERMES))


def _redes_de(valor):
    for r in _rangos(valor):
        if isinstance(r, ipaddress.IPv4Network) or isinstance(r, ipaddress.IPv6Network):
            yield r
        else:
            yield from r


# MARK: Redes e interfaces


def _redes(sis, det, man):
    mia = p.UNIDAD_XFRM in man.ficheros
    red = ipaddress.ip_network(p.RED_HEHERMES)
    try:
        direcciones = json.loads(sis.ejecutar(["ip", "-j", "addr"]).salida or "[]")
        rutas = json.loads(sis.ejecutar(["ip", "-j", "route"]).salida or "[]")
        enlaces = json.loads(sis.ejecutar(["ip", "-d", "-j", "link"]).salida or "[]")
    except ValueError:
        det.bloqueos.append("no entiendo lo que dice «ip -j»")
        return
    ocupan = []
    for interfaz in direcciones:
        nombre = interfaz.get("ifname", "?")
        for a in interfaz.get("addr_info", []):
            try:
                ip = ipaddress.ip_address(a.get("local", ""))
            except ValueError:
                continue
            if ip.version == 4 and ip in red:
                if nombre == p.INTERFAZ and mia:
                    continue
                if nombre in ("wg0", p.INTERFAZ) and str(ip) == p.IP_TUNEL:
                    det.a_mano.append("%s con %s" % (nombre, ip))
                else:
                    ocupan.append("%s: %s" % (nombre, ip))
    for ruta in rutas:
        try:
            destino = ipaddress.ip_network(ruta.get("dst", ""), strict=False)
        except ValueError:
            continue
        dev = ruta.get("dev", "?")
        if destino.version == 4 and destino.overlaps(red) and dev not in ("wg0", p.INTERFAZ) \
                and not any(o.startswith(dev + ":") for o in ocupan):
            ocupan.append("%s: ruta a %s" % (dev, destino))
    if ocupan:
        det.bloqueos.append("otra red usa ya %s (%s): HeHermes necesita 10.77.0.1 fijo, que va en la app"
                            % (p.RED_HEHERMES, ", ".join(ocupan)))
    for enlace in enlaces:
        info = enlace.get("linkinfo") or {}
        if info.get("info_kind") != "xfrm" or (info.get("info_data") or {}).get("if_id") not in _IF_ID:
            continue
        nombre = enlace.get("ifname", "?")
        if nombre == p.INTERFAZ:
            if not mia and not any(s.startswith(p.INTERFAZ) for s in det.a_mano):
                det.a_mano.append("%s (if_id 0x77)" % p.INTERFAZ)
        else:
            det.bloqueos.append("la interfaz %s ya usa el if_id 0x77, que es el de hh-ipsec" % nombre)


# MARK: Una instalación hecha a mano


def _a_mano(sis, det, man):
    for ruta in (p.DISPOSITIVO, p.SITIO, p.SITIO_CONF_D):
        if sis.existe(ruta) and ruta not in man.ficheros:
            det.a_mano.append(ruta)
    if sis.existe("/etc/wireguard/hehermes"):
        det.a_mano.append("/etc/wireguard/hehermes (dispositivos de WireGuard)")
    if det.a_mano:
        det.bloqueos.insert(0, "Esto es una instalación hecha a mano. Encuentro:\n" + "\n".join(
            "      - " + s for s in det.a_mano) + "\n    Sin --adoptar no la toco, y --adoptar todavía no existe")
    for ruta in (p.SITIO, p.SITIO_CONF_D):
        texto = sis.leer_texto(ruta)
        if texto is not None and p.agujero_abierto(texto):
            det.avisos.append("El sitio %s deja que cualquier proceso de este servidor use la clave de Hermes (el "
                              "agujero del túnel: su location / no niega a %s). %s" % (
                                  ruta, p.IP_TUNEL, "Es tuyo y sigue abierto: no lo toco." if ruta not in man.ficheros
                                  else "Se cierra al repararlo."))


# MARK: Cortafuegos


def regla_ufw_canonica(texto):
    """Una regla de ufw reducida a lo que decide, para reconocerla escrita de las dos formas (`500,4500/udp` y
    `proto udp to any port 500,4500`). `None` si es de una aplicación (`OpenSSH`) o no se entiende."""
    try:
        t = shlex.split(texto)
    except ValueError:
        return None
    if t[:1] == ["ufw"]:
        t = t[1:]
    if not t or t[0] not in ("allow", "deny", "reject", "limit"):
        return None
    accion, t = t[0], t[1:]
    regla = {"dir": "in", "on": "", "proto": "any", "from": "any", "from_port": "", "to": "any", "to_port": ""}
    ultimo = None
    i = 0
    while i < len(t):
        tok = t[i]
        if tok in ("in", "out"):
            regla["dir"] = tok
        elif tok in ("on", "proto", "comment") and i + 1 < len(t):
            if tok != "comment":
                regla[tok] = t[i + 1]
            i += 1
        elif tok in ("from", "to") and i + 1 < len(t):
            regla[tok] = t[i + 1]
            ultimo = tok
            i += 1
        elif tok == "port" and i + 1 < len(t) and ultimo:
            regla[ultimo + "_port"] = t[i + 1]
            i += 1
        elif tok in ("log", "log-all"):
            pass
        elif re.match(r"^[\d,:]+(/(tcp|udp))?$", tok):
            puertos, _, proto = tok.partition("/")
            regla["to_port"] = puertos
            regla["proto"] = proto or "any"
        else:
            return None
        i += 1
    for clave in ("from_port", "to_port"):
        regla[clave] = ",".join(sorted(regla[clave].split(","))) if regla[clave] else ""
    return (accion,) + tuple(sorted(regla.items()))


QUE_ABRIR = ("UDP 500 y 4500 desde internet; el TCP 80 que entra por %s hacia %s; y, si vas a conectar el iPhone "
             "por chat, el TCP del canje (uno al azar del %d al %d, que te diré) solo mientras dure")
SIN_CORTAFUEGOS = ("No hay ningún cortafuegos que cierre el paso en este servidor: lo que escucha en todas las "
                   "direcciones está abierto a internet. No enciendo ninguno (podría dejarte fuera del SSH), y mejor "
                   "que no sea yo quien lo haga: si pones uno, abre UDP 500 y 4500. Lo de HeHermes escucha solo donde "
                   "hace falta: nginx en %s y strongSwan en UDP 500 y 4500")


def _cortafuegos(sis, det, a_mano=False):
    """Quién lleva el cortafuegos: firewalld (en marcha, o en la familia Red Hat), ufw, o nftables e iptables a pelo
    (`cortafuegos.analizar`), que se miran siempre que no los lleve ufw o firewalld por debajo."""
    from . import cortafuegos as cf
    from .porchat import PUERTO_MAXIMO, PUERTO_MINIMO
    firewalld = sis.cual("firewall-cmd") and (det.familia == "rhel" or _activo(sis, "firewalld"))
    if firewalld:
        _firewalld(sis, det)
    elif sis.cual("ufw"):
        r = sis.ejecutar(["ufw", "status"])
        det.ufw = "activo" if re.search(r"^Status: active", r.salida, re.M) else "inactivo"
        added = sis.ejecutar(["ufw", "show", "added"]).salida
        det.reglas_ufw = [linea.strip() for linea in added.splitlines() if linea.strip().startswith("ufw ")]
        if det.ufw == "inactivo":
            det.avisos.append("ufw está apagado: añado sus reglas, pero no lo enciendo (podría dejarte fuera del SSH). "
                              "Si un día lo enciendes, ya van dentro")
    gestor = det.ufw == "activo" or det.firewalld == "activo"
    det.con_iptables = not gestor
    lugares, dudas = cf.analizar(sis, con_iptables=det.con_iptables)
    que_abrir = QUE_ABRIR % (p.INTERFAZ, p.IP_TUNEL, PUERTO_MINIMO, PUERTO_MAXIMO)
    if a_mano:
        det.cortafuegos_a_mano = True
        if lugares or dudas:
            det.avisos.append("Tu cortafuegos lo llevas tú (--cortafuegos-a-mano): no lo toco. Tiene que dejar pasar %s"
                              % que_abrir)
    elif dudas:
        det.bloqueos.append("Tu cortafuegos cierra el paso, pero no sé abrirlo sin riesgo: %s. No he tocado nada. Abre "
                            "tú, en él, %s. Luego vuelve a lanzarme con --cortafuegos-a-mano" % ("; ".join(dudas),
                                                                                                que_abrir))
    else:
        det.lugares = lugares
    if not gestor and not lugares and not dudas and det.ufw is None and det.firewalld is None:
        det.avisos.append(SIN_CORTAFUEGOS % p.IP_TUNEL)
    det.avisos.append("Si tu proveedor tiene un cortafuegos propio, en su panel, abre ahí UDP 500 y 4500")


def orden_firewalld(det, opcion, permanente=True) -> list:
    """La orden de firewalld para una opción (`--add-port=500/udp`, `--query-…`): con firewalld en marcha,
    `firewall-cmd` (con `--permanent`, lo que sobrevive a un reinicio); apagado, `firewall-offline-cmd`, que escribe su
    configuración sin encenderlo, como ufw con sus reglas."""
    if det.firewalld == "activo":
        return ["firewall-cmd"] + (["--permanent"] if permanente else []) + [opcion]
    return ["firewall-offline-cmd", opcion]


def _firewalld(sis, det):
    from . import piezas as pz
    det.firewalld = "activo" if sis.ejecutar(["firewall-cmd", "--state"]).bien else "inactivo"
    for regla in pz.reglas_firewalld():
        if sis.ejecutar(orden_firewalld(det, regla.con("query"))).bien:
            det.reglas_firewalld.add(regla.opcion)
    if det.firewalld == "inactivo":
        det.avisos.append("firewalld está apagado: añado sus reglas (con firewall-offline-cmd), pero no lo enciendo "
                          "(podría dejarte fuera del SSH). Si un día lo enciendes, ya van dentro")


# MARK: SELinux


def puertos_selinux(texto: str, puerto: int, protocolo: str = "tcp") -> dict:
    """De `semanage port -l -n`: la etiqueta de cada tipo que da `puerto` suelto (`exacto`) o dentro de un rango. Los
    rangos son los genéricos (`unreserved_port_t`, 1024-32767…) y no cuentan: una entrada suelta manda sobre ellos."""
    exactos, rangos = [], []
    for linea in texto.splitlines():
        partes = linea.split(None, 2)
        if len(partes) < 3 or partes[1] != protocolo:
            continue
        for trozo in partes[2].split(","):
            trozo = trozo.strip()
            if "-" in trozo:
                desde, _, hasta = trozo.partition("-")
                if desde.isdigit() and hasta.isdigit() and int(desde) <= puerto <= int(hasta):
                    rangos.append(partes[0])
            elif trozo.isdigit() and int(trozo) == puerto:
                exactos.append(partes[0])
    return {"exacto": exactos, "rangos": rangos}


def _selinux(sis, det):
    """Con SELinux puesto, nginx (httpd_t) solo se conecta a los puertos con la etiqueta http_port_t, y el de Hermes
    (8642) no la tiene: se le pone a ese puerto y a nada más (no el booleano httpd_can_network_connect, que le dejaría
    conectarse a todos). Los ficheros que escribe, con `restorecon`."""
    if not sis.cual("getenforce"):
        return
    estado = sis.ejecutar(["getenforce"]).salida.strip().lower()
    if estado not in ("enforcing", "permissive"):
        return
    det.selinux = estado
    if det.hermes is None or not sis.cual("semanage"):
        return
    r = sis.ejecutar(["semanage", "port", "-l", "-n"])
    exactos = puertos_selinux(r.salida, det.hermes.puerto)["exacto"]
    otros = sorted(set(exactos) - {"http_port_t"})
    if otros:
        det.bloqueos.append("SELinux le da el puerto %d de Hermes a %s, y nginx solo puede llegar a los de "
                            "http_port_t: no le cambio la etiqueta a un puerto que es de otro. Pon otro "
                            "API_SERVER_PORT en %s" % (det.hermes.puerto, ", ".join(otros), det.hermes.env))
    det.selinux_puerto = "http_port_t" if "http_port_t" in exactos else None
