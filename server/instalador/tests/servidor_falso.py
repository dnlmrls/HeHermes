"""Un servidor de mentira, con estado: los paquetes, los servicios, el cortafuegos, las interfaces, Hermes.

De la familia Debian (apt, dpkg, ufw; los paquetes arrancan sus servicios al instalarse) o de la familia Red Hat (dnf,
rpm, firewalld y SELinux; dnf no arranca nada, y strongSwan tiene su configuración en /etc/strongswan/swanctl).

Contesta a las órdenes que usa el instalador como lo haría el de verdad, y cambia con ellas: `apt-get install nginx`
deja nginx instalado, en marcha y con su sitio `default`; `ufw allow …` añade la regla; `hehermes-xfrm subir` crea
`hh-ipsec`. Así se puede instalar, repetir, desinstalar y comparar con lo de antes sin tocar nada de verdad.

Las órdenes que no conoce fallan con 127, para que una orden nueva del instalador no pase sin que nadie la mire.
"""

from __future__ import annotations

import os
import json
import re
import shlex

import apoyo
from hehermes_servidor.sistema import Resultado

CLAVE = "clave-del-api-server-de-las-pruebas"
# La PSK que el alta falsa deja en el fichero de swanctl del iPhone: la del canje sale de ahí.
PSK = "UFNLLWRlLWxhcy1wcnVlYmFzLXF1ZS1ubyBlcy1kZS1u"
# La huella que da el `preparar` falso del canje.
HUELLA = "Uhfo7S7DmMr3sd399-EUvTg6Z9_hDbthSzm01q1Womo"
VENV_CANJE = "/opt/hehermes-canje/venv"
IP_PUBLICA = "198.51.100.23"

SWANCTL_CONF = "# swanctl.conf de Debian\ninclude conf.d/*.conf\n"
NGINX_CONF = ("user www-data;\nevents {}\nhttp {\n    include /etc/nginx/conf.d/*.conf;\n"
              "    include /etc/nginx/sites-enabled/*;\n}\n")
DEFAULT_NGINX = "server {\n    listen 80 default_server;\n    root /var/www/html;\n}\n"
XFRM_LINK = {"ifname": "hh-ipsec", "linkinfo": {"info_kind": "xfrm", "info_data": {"if_id": "0x77"}}}

# Las derivadas y la familia Red Hat, con lo que dice su os-release de verdad además de ID y VERSION_ID.
NOMBRES = {"debian": "Debian GNU/Linux", "ubuntu": "Ubuntu", "linuxmint": "Linux Mint", "pop": "Pop!_OS",
           "raspbian": "Raspbian GNU/Linux", "kali": "Kali GNU/Linux", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
           "rhel": "Red Hat Enterprise Linux", "centos": "CentOS Stream", "fedora": "Fedora Linux",
           "ol": "Oracle Linux Server", "amzn": "Amazon Linux", "arch": "Arch Linux", "opensuse-leap": "openSUSE Leap"}
DE_DEBIAN = {"linuxmint": 'ID_LIKE="ubuntu debian"\nVERSION_CODENAME={propio}\nUBUNTU_CODENAME={base}\n',
             "pop": 'ID_LIKE="ubuntu debian"\nVERSION_CODENAME={base}\nUBUNTU_CODENAME={base}\n',
             "raspbian": 'ID_LIKE=debian\nVERSION_CODENAME={base}\n',
             "kali": 'ID_LIKE=debian\nVERSION_CODENAME=kali-rolling\n'}
RHEL = {"rocky": "rhel centos fedora", "almalinux": "rhel centos fedora", "rhel": "fedora", "centos": "rhel fedora",
        "fedora": "", "ol": "fedora", "amzn": "fedora"}
SWANCTL_CONF_RHEL = "# swanctl.conf de Fedora y EPEL\ninclude conf.d/*.conf\n"
NGINX_CONF_RHEL = ("user nginx;\nevents {}\nhttp {\n    include /etc/nginx/conf.d/*.conf;\n    server {\n"
                   "        listen 80;\n        listen [::]:80;\n        root /usr/share/nginx/html;\n    }\n}\n")
#: La lista de SELinux de serie (lo justo): el 8642 de Hermes no está, y cae en un rango genérico.
SEMANAGE_DE_SERIE = [("http_port_t", "80, 81, 443, 488, 8008, 8009, 8443, 9000"),
                     ("unreserved_port_t", "61000-65535, 1024-32767"), ("ssh_port_t", "22")]

# Lo que deja cada paquete al instalarse (lo justo para lo que mira el instalador).
EFECTOS = {
    "nginx": {"ficheros": {"/etc/nginx/nginx.conf": NGINX_CONF, "/etc/nginx/sites-available/default": DEFAULT_NGINX},
              "enlaces": {"/etc/nginx/sites-enabled/default": "/etc/nginx/sites-available/default"},
              "programas": ["/usr/sbin/nginx"], "servicios": ["nginx"], "puertos_tcp": [("0.0.0.0:80", "nginx")]},
    "strongswan-swanctl": {"ficheros": {"/etc/swanctl/swanctl.conf": SWANCTL_CONF}, "carpetas": ["/etc/swanctl/conf.d"],
                           "programas": ["/usr/sbin/swanctl"]},
    "charon-systemd": {"servicios": ["strongswan"], "puertos_udp": [("0.0.0.0:500", "charon-systemd"),
                                                                     ("0.0.0.0:4500", "charon-systemd")]},
    "qrencode": {"programas": ["/usr/bin/qrencode"]},
    "libstrongswan-standard-plugins": {},
    "ufw": {"programas": ["/usr/sbin/ufw"]},
    "apache2": {"programas": ["/usr/sbin/apache2"], "servicios": ["apache2"], "puertos_tcp": [("*:80", "apache2")]},
}
# Los de la familia Red Hat: dnf deja los servicios parados, y sus puertos llegan al arrancarlos (`AL_ARRANCAR`).
EFECTOS_RPM = {
    "nginx": {"ficheros": {"/etc/nginx/nginx.conf": NGINX_CONF_RHEL}, "carpetas": ["/etc/nginx/conf.d"],
              "programas": ["/usr/sbin/nginx"]},
    "strongswan": {"ficheros": {"/etc/strongswan/swanctl/swanctl.conf": SWANCTL_CONF_RHEL},
                   "carpetas": ["/etc/strongswan/swanctl/conf.d"], "programas": ["/usr/sbin/swanctl"]},
    "qrencode": {"programas": ["/usr/bin/qrencode"]},
    "policycoreutils-python-utils": {"programas": ["/usr/sbin/semanage"]},
    "epel-release": {},
    "firewalld": {"programas": ["/usr/bin/firewall-cmd", "/usr/bin/firewall-offline-cmd"]},
}
AL_ARRANCAR = {"nginx": {"tcp": [("0.0.0.0:80", "nginx")]},
               "strongswan": {"udp": [("0.0.0.0:500", "charon-systemd"), ("0.0.0.0:4500", "charon-systemd")]}}


class ServidorFalso:
    def __init__(self, sis, distro=("debian", "12"), arquitectura="amd64"):
        self.sis = sis
        sis.resto = self
        self.distro = distro
        self.familia = "rhel" if distro[0] in RHEL else "debian"
        self.swanctl = "/etc/strongswan/swanctl" if self.familia == "rhel" else "/etc/swanctl"
        # En la familia Red Hat, `uname -m` y no dpkg: «x86_64» o «aarch64».
        self.arquitectura = arquitectura if self.familia == "debian" else {"amd64": "x86_64"}.get(arquitectura,
                                                                                                arquitectura)
        #: SELinux: «Enforcing», «Permissive», «Disabled» o None (sin getenforce). Las etiquetas puestas a mano.
        self.selinux = "Enforcing" if self.familia == "rhel" else None
        self.etiquetas: dict = {}
        self.etiquetados: list = []
        #: firewalld: None (no está), «activo» o «inactivo»; lo de ahora y lo permanente.
        self.firewalld = None
        self.fw_ahora: set = set()
        self.fw_permanente: set = set()
        self.paquetes: set = set()
        self.activos: set = set()
        self.habilitados: set = set()
        self.unidades_hermes: dict = {}
        self.procesos: list = []  # (pid, usuario, orden)
        self.tcp: list = [("0.0.0.0:22", "sshd")]
        self.udp: list = []
        self.enlaces_ip: dict = {"eth0": {"ifname": "eth0", "addr": [IP_PUBLICA + "/24"]}}
        self.rutas: list = []
        self.direccion_salida = IP_PUBLICA
        self.ufw = None  # None: no está; "activo" o "inactivo"
        self.reglas_ufw: list = []
        self.nginx_t = lambda: True
        self.swanctl_carga = lambda: True
        self.conexiones: set = set()
        self.sas: dict = {}
        self.hermes = {}  # puerto -> clave
        self.altas: list = []
        self.dispositivos_json = "/etc/hehermes/dispositivos/dispositivos.json"
        self.reinicios: list = []
        self.usuarios: dict = {"root": "/root"}
        self.lanzados: list = []  # las órdenes de systemd-run
        self.pip: list = []
        self.pngs: dict = {}
        self._montar_base()

    # Montaje

    def _montar_base(self):
        s = self.sis
        ident, version = self.distro[0], self.distro[1]
        nombre = NOMBRES.get(ident, ident)
        texto = 'PRETTY_NAME="%s %s"\nNAME="%s"\nID=%s\nVERSION_ID="%s"\n' % (nombre, version, nombre, ident, version)
        if ident in DE_DEBIAN:
            # La base, por su nombre en clave: el tercer elemento de `distro` (Mint 22 → noble).
            texto += DE_DEBIAN[ident].format(base=self.distro[2] if len(self.distro) > 2 else "", propio="wilma")
        if ident in RHEL:
            if RHEL[ident]:
                texto += 'ID_LIKE="%s"\n' % RHEL[ident]
            if ident == "amzn":
                texto += 'PLATFORM_ID="platform:al%s"\n' % version
            else:
                texto += 'PLATFORM_ID="platform:%s%s"\n' % ("f" if ident == "fedora" else "el", version.split(".")[0])
        # Como en las de verdad: el fichero está en /usr/lib y /etc/os-release es un enlace a él.
        s.poner("/usr/lib/os-release", texto)
        s.carpeta("/etc")
        os.symlink("../usr/lib/os-release", s.ruta("/etc/os-release"))
        s.carpeta("/run/systemd/system")
        gestores = ("/usr/bin/dnf", "/usr/bin/rpm") if self.familia == "rhel" else ("/usr/bin/apt-get", "/usr/bin/dpkg")
        for programa in gestores + ("/usr/bin/systemctl", "/usr/sbin/ip", "/usr/bin/ss", "/usr/bin/python3"):
            self.programa(programa)
        if self.familia == "rhel":
            # Una instalación de serie: SELinux puesto, y firewalld instalado y en marcha.
            self.programa("/usr/sbin/getenforce")
            self.programa("/usr/sbin/restorecon")
            self.instalar_paquete("firewalld")
            self.firewalld = "activo"
            self.fw_ahora = {"service=ssh", "service=cockpit", "service=dhcpv6-client"}
            self.fw_permanente = set(self.fw_ahora)
        self._escribir_passwd()

    def _escribir_passwd(self):
        self.sis.poner("/etc/passwd", "".join("%s:x:%d:%d::%s:/bin/bash\n" % (u, i, i, h)
                                              for i, (u, h) in enumerate(sorted(self.usuarios.items()))))

    def programa(self, ruta):
        self.sis.poner(ruta, "#!/bin/sh\n", modo=0o755)

    def instalar_paquete(self, paquete):
        self.paquetes.add(paquete)
        efectos = (EFECTOS_RPM if self.familia == "rhel" else EFECTOS).get(paquete, {})
        for ruta, texto in efectos.get("ficheros", {}).items():
            if not self.sis.existe(ruta):
                self.sis.poner(ruta, texto)
        for ruta in efectos.get("carpetas", []):
            self.sis.carpeta(ruta)
        for ruta, destino in efectos.get("enlaces", {}).items():
            if not self.sis.existe(ruta):
                self.sis.enlazar(ruta, destino)
        for ruta in efectos.get("programas", []):
            self.programa(ruta)
        for servicio in efectos.get("servicios", []):
            self.activos.add(servicio)
            self.habilitados.add(servicio)
        self.tcp += [p for p in efectos.get("puertos_tcp", []) if p not in self.tcp]
        self.udp += [p for p in efectos.get("puertos_udp", []) if p not in self.udp]

    def con_hermes(self, usuario="root", home=None, como="unidad", puerto=8642, clave=CLAVE, habilitada=True,
                   host=None, env_extra="", hermes_home=None):
        home = home or ("/root" if usuario == "root" else "/home/" + usuario)
        self.usuarios[usuario] = home
        self._escribir_passwd()
        carpeta = hermes_home or home + "/.hermes"
        lineas = ["# .env de Hermes"]
        if habilitada is not None:
            lineas.append("API_SERVER_ENABLED=%s" % ("true" if habilitada else "false"))
        if clave is not None:
            lineas.append('API_SERVER_KEY="%s"' % clave)
        if host:
            lineas.append("API_SERVER_HOST=%s" % host)
        if puerto != 8642:
            lineas.append("API_SERVER_PORT=%d" % puerto)
        self.sis.poner(carpeta + "/.env", "\n".join(lineas) + "\n" + env_extra, modo=0o600)
        if como == "unidad":
            entorno = "HERMES_HOME=%s" % hermes_home if hermes_home else ""
            self.unidades_hermes["hermes-gateway.service"] = {"User": "" if usuario == "root" else usuario,
                                                              "Environment": entorno}
            self.activos.add("hermes-gateway")
        else:
            pid = 4000 + len(self.procesos)
            self.procesos.append((pid, usuario, "/usr/bin/python3 -m hermes gateway run"))
            entorno = "PATH=/usr/bin\0HOME=%s\0" % home + ("HERMES_HOME=%s\0" % hermes_home if hermes_home else "")
            self.sis.poner("/proc/%d/environ" % pid, entorno)
        if habilitada:
            self.hermes[puerto] = clave
            self.tcp.append(("%s:%d" % ("0.0.0.0" if host == "0.0.0.0" else "127.0.0.1", puerto), "python3"))
        return carpeta + "/.env"

    # Las órdenes

    def __call__(self, args, entrada=None, heredar=False):
        nombre = args[0].rsplit("/", 1)[-1]
        metodo = getattr(self, "_" + nombre.replace("-", "_"), None)
        if metodo is None:
            return Resultado(127, "", "%s: orden que el servidor falso no conoce" % args[0])
        return metodo(args[1:], entrada)

    def _env(self, args, entrada):
        while args and "=" in args[0]:
            args = args[1:]
        return self(args, entrada)

    def _dpkg(self, args, entrada):
        if args == ["--print-architecture"]:
            return Resultado(0, self.arquitectura + "\n")
        return Resultado(127, "", "dpkg %s" % args)

    def _dpkg_query(self, args, entrada):
        paquetes = [a for a in args if not a.startswith("-")]
        salida = "".join("%s\tinstalled\n" % p for p in paquetes if p in self.paquetes)
        falta = [p for p in paquetes if p not in self.paquetes]
        return Resultado(1 if falta else 0, salida, "".join("dpkg-query: no packages found matching %s\n" % p
                                                            for p in falta))

    def _apt_get(self, args, entrada):
        if args[:1] == ["update"]:
            return Resultado(0)
        if args[:1] == ["install"]:
            for paquete in [a for a in args[1:] if not a.startswith("-")]:
                self.instalar_paquete(paquete)
            return Resultado(0)
        if args[:1] in (["remove"], ["purge"]):
            for paquete in [a for a in args[1:] if not a.startswith("-")]:
                self.paquetes.discard(paquete)
            return Resultado(0)
        return Resultado(127, "", "apt-get %s" % args)

    def _systemctl(self, args, entrada):
        args = [a for a in args if a not in ("--quiet", "-q", "--no-pager")]
        orden, resto = args[0], args[1:]
        ahora = "--now" in resto
        unidades = [u for u in resto if not u.startswith("-")]
        base = lambda u: u[:-len(".service")] if u.endswith(".service") else u  # noqa: E731
        if orden == "is-active":
            activo = all(base(u) in self.activos for u in unidades)
            return Resultado(0 if activo else 3, "active\n" if activo else "inactive\n")
        if orden == "is-enabled":
            habilitado = all(base(u) in self.habilitados for u in unidades)
            return Resultado(0 if habilitado else 1, "enabled\n" if habilitado else "disabled\n")
        if orden == "show":
            unidad = unidades[0]
            datos = self.unidades_hermes.get(unidad)
            if datos is None:
                return Resultado(0, "LoadState=not-found\nUser=\nEnvironment=\n")
            return Resultado(0, "LoadState=loaded\nUser=%s\nEnvironment=%s\n" % (datos["User"], datos["Environment"]))
        if orden in ("daemon-reload",):
            return Resultado(0)
        if orden in ("enable", "disable", "start", "stop", "reload", "restart", "try-reload-or-restart"):
            for unidad in unidades:
                u = base(unidad)
                if orden == "enable":
                    self.habilitados.add(u)
                if orden == "disable":
                    self.habilitados.discard(u)
                if orden == "start" or (orden == "enable" and ahora):
                    self._arrancar(u)
                if orden == "stop" or (orden == "disable" and ahora):
                    self._parar(u)
                if orden == "restart":
                    self.reinicios.append(u)
                    self._arrancar(u)
                if orden == "reload":
                    if u not in self.activos:
                        return Resultado(1, "", "%s is not active, cannot reload." % unidad)
                    if u == "hehermes-xfrm":
                        self._xfrm(["subir"], None)
            return Resultado(0)
        return Resultado(127, "", "systemctl %s" % args)

    def _arrancar(self, unidad):
        if unidad == "firewalld":
            raise AssertionError("el instalador no puede encender firewalld")
        self.activos.add(unidad)
        if self.familia == "rhel":
            self.tcp += [p for p in AL_ARRANCAR.get(unidad, {}).get("tcp", []) if p not in self.tcp]
            self.udp += [p for p in AL_ARRANCAR.get(unidad, {}).get("udp", []) if p not in self.udp]
        if unidad == "hehermes-xfrm":
            self._xfrm(["subir"], None)

    def _parar(self, unidad):
        self.activos.discard(unidad)
        if unidad == "hehermes-xfrm":
            self._xfrm(["bajar"], None)

    def _hehermes_xfrm(self, args, entrada):
        return self._xfrm(args, entrada)

    def _xfrm(self, args, entrada):
        if args == ["subir"]:
            self.enlaces_ip["hh-ipsec"] = dict(XFRM_LINK, addr=["10.77.0.1/32"])
            if ("10.77.1.0/24", "hh-ipsec") not in self.rutas:
                self.rutas.append(("10.77.1.0/24", "hh-ipsec"))
        elif args == ["bajar"]:
            self.enlaces_ip.pop("hh-ipsec", None)
            self.rutas = [r for r in self.rutas if r[1] != "hh-ipsec"]
        return Resultado(0)

    def _ps(self, args, entrada):
        return Resultado(0, "".join("%d %s %s\n" % p for p in self.procesos))

    def _ss(self, args, entrada):
        lista = self.tcp if "-ltnp" in args else self.udp
        estado = "LISTEN" if "-ltnp" in args else "UNCONN"
        return Resultado(0, "".join('%s 0 511 %s 0.0.0.0:* users:(("%s",pid=100,fd=6))\n' % (estado, local, dueño)
                                    for local, dueño in lista))

    def _ip(self, args, entrada):
        if args[:5] == ["-4", "-j", "route", "get", "1.1.1.1"]:
            return Resultado(0, json.dumps([{"dst": "1.1.1.1", "dev": "eth0", "prefsrc": self.direccion_salida}]))
        if args == ["-j", "addr"]:
            salida = []
            for nombre, datos in self.enlaces_ip.items():
                salida.append({"ifname": nombre, "addr_info": [
                    {"family": "inet", "local": a.split("/")[0], "prefixlen": int(a.split("/")[1])}
                    for a in datos.get("addr", [])]})
            return Resultado(0, json.dumps(salida))
        if args == ["-j", "route"]:
            return Resultado(0, json.dumps([{"dst": d, "dev": i} for d, i in self.rutas]))
        if args == ["-d", "-j", "link"]:
            return Resultado(0, json.dumps([{k: v for k, v in d.items() if k != "addr"}
                                            for d in self.enlaces_ip.values()]))
        if args[:4] == ["-d", "link", "show", "hh-ipsec"]:
            if "hh-ipsec" not in self.enlaces_ip:
                return Resultado(1, "", 'Device "hh-ipsec" does not exist.')
            return Resultado(0, "7: hh-ipsec@NONE: <NOARP,UP,LOWER_UP> mtu 1500\n    xfrm if_id 0x77\n")
        return Resultado(127, "", "ip %s" % args)

    def _nginx(self, args, entrada):
        if args[:1] == ["-t"]:
            return Resultado(0, "", "syntax is ok") if self.nginx_t() else Resultado(1, "", "nginx: [emerg] roto")
        return Resultado(127, "", "nginx %s" % args)

    def _swanctl(self, args, entrada):
        if args == ["--stats"]:
            return Resultado(0 if "strongswan" in self.activos else 1, "uptime: 1 day\n")
        if args == ["--load-all", "--noprompt"]:
            return Resultado(0 if self.swanctl_carga() else 1)
        if args == ["--list-conns"]:
            return Resultado(0, "".join("%s: IKEv2\n" % c for c in sorted(self.conexiones)))
        if args == ["--list-sas"]:
            return Resultado(0, "".join("%s: #1, %s, IKEv2\n" % item for item in sorted(self.sas.items())))
        return Resultado(127, "", "swanctl %s" % args)

    def _ufw(self, args, entrada):
        if self.ufw is None:
            return Resultado(127, "", "no está ufw")
        if args == ["status"]:
            if self.ufw == "inactivo":
                return Resultado(0, "Status: inactive\n")
            return Resultado(0, "Status: active\n\nTo Action From\n-- ------ ----\n")
        if args == ["show", "added"]:
            return Resultado(0, "Added user rules (see 'ufw status' for running firewall):\n"
                             + "".join(r + "\n" for r in self.reglas_ufw) if self.reglas_ufw
                             else "Added user rules (see 'ufw status' for running firewall):\n(None)\n")
        if args[:1] == ["allow"]:
            texto = "ufw " + " ".join(shlex.quote(a) if " " in a else a for a in args)
            self.reglas_ufw.append(texto)
            return Resultado(0, "Rules updated\nRules updated (v6)\n")
        if args[:2] == ["delete", "allow"]:
            texto = "ufw " + " ".join(args[1:])
            if texto not in self.reglas_ufw:
                return Resultado(0, "Could not delete non-existent rule\n")
            self.reglas_ufw.remove(texto)
            return Resultado(0, "Rule deleted\n")
        if args[:1] in (["enable"], ["disable"], ["reset"]):
            raise AssertionError("el instalador no puede %s ufw" % args[0])
        return Resultado(127, "", "ufw %s" % args)

    def _hehermes_dispositivo(self, args, entrada):
        registro = json.loads(self.sis.leer(self.dispositivos_json) or b'{"dispositivos": []}')
        if args[:1] == ["alta"]:
            self.altas.append(args)
            servidor = args[args.index("--servidor") + 1] if "--servidor" in args else IP_PUBLICA
            registro["dispositivos"].append({"nombre": args[1], "tipo": "ikev2", "ip": "10.77.1.3", "servidor": servidor,
                                             "conexion": "hh-" + args[1]})
            # Como el de verdad (`conf_swanctl`): la PSK del iPhone vive en su conexión de strongSwan, entre comillas.
            self.sis.poner(self.swanctl + "/conf.d/hehermes-%s.conf" % args[1],
                           '# Generado por hehermes-dispositivo. No editar a mano: usa el script.\n'
                           'connections {\n}\nsecrets {\n    ike-hehermes-%s {\n        id = %s\n'
                           '        secret = "%s"\n    }\n}\n' % (args[1], args[1], PSK), modo=0o600)
            self.sis.poner(self.dispositivos_json, json.dumps(registro), modo=0o600)
            self.conexiones.add("hh-" + args[1])
            return Resultado(0, "Alta IKEv2 de «%s»\n" % args[1])
        if args[:1] == ["qr"]:
            return Resultado(0)
        if args[:1] == ["baja"]:
            for d in registro["dispositivos"]:
                if d["nombre"] == args[1]:
                    d["baja"] = "ahora"
            self.sis.poner(self.dispositivos_json, json.dumps(registro), modo=0o600)
            self.sis.borrar(self.swanctl + "/conf.d/hehermes-%s.conf" % args[1])
            self.conexiones.discard("hh-" + args[1])
            return Resultado(0)
        if args[:1] == ["clave"] or args[:1] == ["iniciar"]:
            return Resultado(0)
        return Resultado(127, "", "hehermes-dispositivo %s" % args)

    # La familia Red Hat

    def _rpm(self, args, entrada):
        if args[:3] != ["-q", "--qf", "%{NAME}\n"]:
            return Resultado(127, "", "rpm %s" % args)
        paquetes = args[3:]
        salida = "".join(p + "\n" if p in self.paquetes else "package %s is not installed\n" % p for p in paquetes)
        return Resultado(sum(p not in self.paquetes for p in paquetes), salida)

    def _dnf(self, args, entrada):
        nombres = [a for a in args[1:] if not a.startswith("-")]
        if args[:1] == ["install"] and "-y" in args:
            for paquete in nombres:
                if paquete == "strongswan" and "epel-release" not in self.paquetes and self.distro[0] != "fedora":
                    return Resultado(1, "", "Error: Unable to find a match: strongswan")
                self.instalar_paquete(paquete)
            return Resultado(0)
        if args[:1] == ["remove"] and "-y" in args:
            for paquete in nombres:
                self.paquetes.discard(paquete)
            return Resultado(0)
        return Resultado(127, "", "dnf %s" % args)

    def _uname(self, args, entrada):
        return Resultado(0, self.arquitectura + "\n") if args == ["-m"] else Resultado(127, "", "uname %s" % args)

    def _getenforce(self, args, entrada):
        return Resultado(0, (self.selinux or "Disabled") + "\n")

    def _restorecon(self, args, entrada):
        self.etiquetados += args
        return Resultado(0)

    def _semanage(self, args, entrada):
        if not self.sis.cual("semanage"):
            return Resultado(127, "", "semanage: no está")
        if args == ["port", "-l", "-n"]:
            filas = list(SEMANAGE_DE_SERIE) + [(t, p) for p, t in sorted(self.etiquetas.items())]
            return Resultado(0, "".join("%-28s tcp      %s\n" % fila for fila in filas))
        if args[:2] == ["port", "-a"] and args[2:4] == ["-t", "http_port_t"] and args[4:6] == ["-p", "tcp"]:
            if args[6] in self.etiquetas:
                return Resultado(1, "", "ValueError: Port tcp/%s already defined" % args[6])
            self.etiquetas[args[6]] = "http_port_t"
            return Resultado(0)
        if args[:2] == ["port", "-d"] and args[4:6] == ["-p", "tcp"]:
            if self.etiquetas.pop(args[6], None) is None:
                return Resultado(1, "", "ValueError: Port tcp/%s is not defined" % args[6])
            return Resultado(0)
        return Resultado(127, "", "semanage %s" % args)

    def _firewall_cmd(self, args, entrada):
        if args == ["--state"]:
            return Resultado(0, "running\n") if self.firewalld == "activo" else Resultado(252, "not running\n")
        if self.firewalld != "activo":
            return Resultado(252, "", "FirewallD is not running")
        if args[:1] == ["--reload"] or args[:1] == ["--complete-reload"]:
            raise AssertionError("el instalador no puede recargar firewalld: se llevaría las reglas de ahora de otros")
        permanente = args[:1] == ["--permanent"]
        return self._fw(args[1:] if permanente else args, self.fw_permanente if permanente else self.fw_ahora)

    def _firewall_offline_cmd(self, args, entrada):
        return self._fw(args, self.fw_permanente)

    def _fw(self, args, reglas):
        m = re.match(r"^--(add|remove|query)-(port|rich-rule|service)=(.+)$", args[0]) if len(args) == 1 else None
        if not m:
            return Resultado(127, "", "firewall-cmd %s" % args)
        verbo, clave = m.group(1), m.group(2) + "=" + m.group(3)
        if verbo == "query":
            return Resultado(0, "yes\n") if clave in reglas else Resultado(1, "no\n")
        if verbo == "add":
            reglas.add(clave)
        else:
            reglas.discard(clave)
        return Resultado(0, "success\n")

    def _bash(self, args, entrada):
        # El instalador de los avisos.
        self.avisos_instalados = True
        self.activos |= {"hehermes-vigia.socket", "hehermes-vigia", "hehermes-rele.socket", "hehermes-rele"}
        return Resultado(0, "Hecho.\n")

    def _python3(self, args, entrada):
        if args[:3] == ["-I", "-m", "venv"]:
            self.programa(args[3] + "/bin/python")
            return Resultado(0)
        return Resultado(127, "", "python3 %s" % args)

    def _python(self, args, entrada):
        """El Python del venv del canje."""
        if not self.sis.existe(VENV_CANJE + "/bin/python"):
            return Resultado(127, "", "no existe el venv")
        if args[:4] == ["-I", "-m", "pip", "install"]:
            self.pip.append(args)
            self.canje_con_dependencias = True
            return Resultado(0)
        if args[:2] == ["-I", "-c"] and "sysconfig" in args[2]:
            return Resultado(0, VENV_CANJE + "/lib/python3.11/site-packages\n")
        if args[:3] == ["-I", "-B", "-c"] and "import" in args[3]:
            listo = getattr(self, "canje_con_dependencias", False) and self.sis.existe(
                VENV_CANJE + "/lib/python3.11/site-packages/hehermes-servidor.pth")
            return Resultado(0 if listo else 1, "", "" if listo else "ModuleNotFoundError: cryptography")
        if args[:5] == ["-I", "-B", "-m", "hehermes_servidor.canje", "preparar"]:
            self.sis.poner(args[5] + "/cert.pem", "-----BEGIN CERTIFICATE-----\nfalso\n", modo=0o600)
            self.sis.poner(args[5] + "/clave.pem", "-----BEGIN PRIVATE KEY-----\nfalsa\n", modo=0o600)
            return Resultado(0, json.dumps({"huella": HUELLA}) + "\n")
        return Resultado(127, "", "python %s" % args)

    def _systemd_run(self, args, entrada):
        self.lanzados.append(args)
        if "--unit=hehermes-canje" in args:
            if "hehermes-canje" in self.activos:
                return Resultado(1, "", "Unit hehermes-canje.service already exists.")
            self.activos.add("hehermes-canje")
        return Resultado(0)

    def _qrencode(self, args, entrada):
        if "-o" in args:
            ruta = args[args.index("-o") + 1]
            self.pngs[ruta] = entrada
            self.sis.poner(ruta, b"\x89PNG falso de " + entrada.encode())
            return Resultado(0)
        return Resultado(0, "QR\n")

    def _id(self, args, entrada):
        return Resultado(1, "", "no such user")

    def http(self, url, cabeceras):
        m = re.match(r"^http://127\.0\.0\.1:(\d+)(/.*)$", url)
        if m and int(m.group(1)) in self.hermes:
            clave = self.hermes[int(m.group(1))]
            if m.group(2) == "/health":
                return 200, b'{"status": "ok"}'
            if cabeceras.get("Authorization") == "Bearer %s" % clave:
                return 200, b'{"object": "list", "data": []}'
            return 401, b'{"error": {"code": "gateway_auth_failed"}}'
        if url == "http://10.77.0.1/health" and "hh-ipsec" in self.enlaces_ip and "nginx" in self.activos:
            return 403, b"<html>403 Forbidden</html>"
        return None, b""


def servidor(distro=("debian", "12"), **hermes) -> "tuple":
    """Un servidor limpio con Hermes (en marcha, con la API y su clave) y nada más. Devuelve (sis, servidor).

    `distro` es (ID, VERSION_ID) y, en una derivada de Debian o Ubuntu, el nombre en clave de su base. En la familia
    Red Hat trae además SELinux puesto, firewalld en marcha y, en RHEL 9 y sus reconstrucciones, el python3 3.9."""
    sis = apoyo.SistemaFalso()
    if distro[0] in RHEL and distro[0] != "fedora" and distro[1].split(".")[0] == "9":
        sis.version_python = (3, 9, 21)
    falso = ServidorFalso(sis, distro=distro)
    sis.http_falso = falso.http
    falso.con_hermes(**hermes)
    return sis, falso


# El VPS de Daniel tal como está (server/vpn/README.md): strongSwan, nginx y ufw montados a mano, WireGuard, la
# conexión hh-iphone-poc escrita a mano y el sitio del túnel sin allow ni deny.
POC = (apoyo.DATOS / "hehermes-poc-a-mano.conf").read_text()


def servidor_de_daniel():
    sis, falso = servidor(distro=("ubuntu", "26.04"))
    for paquete in ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "nginx", "qrencode",
                    "ufw", "wireguard-tools"):
        falso.instalar_paquete(paquete)
    sis.borrar("/etc/nginx/sites-enabled/default")
    sis.poner("/etc/nginx/sites-available/hehermes-tunel",
              (apoyo.REPO / "server" / "vpn" / "hehermes-tunel.nginx").read_bytes())
    sis.enlazar("/etc/nginx/sites-enabled/hehermes-tunel", "/etc/nginx/sites-available/hehermes-tunel")
    sis.poner("/etc/nginx/hehermes-bearer.conf", 'proxy_set_header Authorization "Bearer %s";\n' % CLAVE, modo=0o600)
    sis.poner("/etc/systemd/system/nginx.service.d/hehermes-wg0.conf",
              (apoyo.REPO / "server" / "vpn" / "nginx-despues-de-wg0.conf").read_bytes())
    # El que se desplegó el 2026-09-24, de antes de servidor.ini: no es el que trae el paquete.
    desplegado = (apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo").read_text().replace(
        "    aplicar_servidor_ini()\n", "")
    sis.poner("/usr/local/sbin/hehermes-dispositivo", desplegado, modo=0o750)
    sis.poner("/etc/swanctl/conf.d/hehermes-poc.conf", POC, modo=0o600)
    sis.poner("/etc/wireguard/wg0.conf", "[Interface]\nAddress = 10.77.0.1/24\n", modo=0o600)
    sis.poner("/etc/wireguard/hehermes/dispositivos.json", '{"dispositivos": []}\n', modo=0o600)
    falso.enlaces_ip["eth0"]["addr"] = ["203.0.113.7/32"]
    falso.direccion_salida = "203.0.113.7"
    falso.enlaces_ip["wg0"] = {"ifname": "wg0", "linkinfo": {"info_kind": "wireguard"}, "addr": ["10.77.0.1/24"]}
    falso.enlaces_ip["hh-ipsec"] = dict(XFRM_LINK, addr=["10.77.0.1/32"])
    falso.rutas += [("10.77.0.0/24", "wg0"), ("10.77.1.0/24", "hh-ipsec")]
    falso.activos |= {"wg-quick@wg0", "hehermes-vigia", "hehermes-rele"}
    falso.tcp = [("0.0.0.0:22", "sshd"), ("10.77.0.1:80", "nginx"), ("127.0.0.1:8642", "python3"),
                 ("127.0.0.1:8790", "systemd"), ("127.0.0.1:8791", "systemd")]
    falso.udp = [("0.0.0.0:500", "charon-systemd"), ("0.0.0.0:4500", "charon-systemd"), ("0.0.0.0:51820", "-")]
    falso.conexiones = {"hh-iphone-poc"}
    falso.sas = {"hh-iphone-poc": "ESTABLISHED"}
    falso.ufw = "activo"
    falso.reglas_ufw = ["ufw allow 22/tcp", "ufw allow 51820/udp", "ufw allow in on wg0 to 10.77.0.1 port 80 proto tcp",
                        "ufw allow 500,4500/udp", "ufw allow in on hh-ipsec to 10.77.0.1 port 80 proto tcp"]
    return sis, falso
