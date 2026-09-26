"""La VPN IKEv2 tal y como la dejaba el instalador hasta la 0.5.1, sobre el servidor falso.

Desde la 0.6.0 el instalador ya no la instala, pero un servidor puede tenerla, y `desinstalar --modo vpn` (o a secas) la
tiene que quitar sin dejar restos ni tocar la pasarela. Esto la monta sin el código que la instalaba (que ya no
existe): sus ficheros en su sitio y apuntados en el manifiesto, sus unidades en marcha, sus reglas en el cortafuegos
que haya, sus iPhone dados de alta con el `hehermes-dispositivo` del servidor falso, y, si se piden, los avisos. Los
ficheros de la VPN llevan un contenido cualquiera: desinstalar solo mira que sigan como los apuntó.
"""

import apoyo

import json
import time

import servidor_falso as sf
from hehermes_servidor import cortafuegos as cf
from hehermes_servidor import manifiesto as m
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.plan import ficheros_propios

ORIGEN = str(apoyo.RAIZ)
PAQUETES = ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "qrencode", "nginx")
#: En la familia Red Hat: strongSwan de un solo paquete, y lo de `semanage`.
PAQUETES_RPM = ("strongswan", "qrencode", "nginx", "policycoreutils-python-utils")
#: Lo que era solo suyo: lo que se va con `desinstalar --modo vpn`.
FICHEROS = (p.SERVIDOR_INI, p.SCRIPT_XFRM, p.UNIDAD_XFRM, p.UNIDAD_CLAVE_SERVICE, p.UNIDAD_CLAVE_PATH, p.BEARER,
            p.SITIO, p.SITIO_ENLACE, p.DROP_IN_NGINX)
UNIDADES = ("hehermes-xfrm.service", "hehermes-cortafuegos.service", "hehermes-clave.path")
REGLAS_UFW = [r.texto for r in p.reglas_ufw("vpn")]
#: Lo esencial del sitio del túnel que escribía: solo en 10.77.0.1:80, y el agujero del túnel cerrado. Es lo que mira
#: «Seguridad» mientras la VPN siga ahí.
SITIO = (p.CABECERA + "server {\n    listen 10.77.0.1:80;\n    server_name _;\n    location / {\n"
         "        deny 10.77.0.1;\n        allow 10.77.1.0/24;\n        deny all;\n"
         "        proxy_pass http://127.0.0.1:8642;\n        include /etc/nginx/hehermes-bearer.conf;\n    }\n}\n")


def _texto(que):
    return (p.CABECERA + "# %s, como lo dejaba la VPN del instalador hasta la 0.5.1.\n" % que).encode()


def montar(sis, falso, iphones=("mi-iphone",), avisos=False, sin_modos=False, hace=24 * 3600, reemplazar=()):
    """Añade la VPN de antes a lo que haya (nada, o la pasarela). `sin_modos`: el manifiesto de antes de la 0.5.0, que
    no decía de qué modo era. `hace`: cuántos segundos hace que se instaló. `reemplazar`: los ficheros ajenos que
    sustituyó (con `--reemplazar`), guardando antes su copia."""
    man = Manifiesto.leer(sis)
    if "instalado" not in man.datos:
        man.datos["instalado"] = time.time() - hace
    man.anadir_modo("vpn")
    if falso.familia == "rhel":
        man.datos["familia"] = "rhel"
    man.guardar(sis)
    for paquete in PAQUETES_RPM if falso.familia == "rhel" else PAQUETES:
        if paquete not in falso.paquetes:
            falso.instalar_paquete(paquete)
            man.paquetes.append(paquete)
    if falso.familia == "rhel":
        # dnf deja strongSwan parado: lo arrancaba ella, y era suyo.
        falso._systemctl(["enable", "--now", "strongswan.service"], None)
        man.unidades.append("strongswan.service")

    def fichero(ruta, datos, modo=0o644, gestionado=False):
        man.apuntar_carpetas(sis, ruta)
        copia = m.guardar_copia(sis, ruta) if ruta in reemplazar and sis.existe(ruta) else None
        sis.escribir(ruta, datos, modo=modo)
        if gestionado:
            man.apuntar_gestionado(ruta, copia)
        else:
            man.apuntar_fichero(ruta, datos, copia)

    # Lo común: el instalador en /opt, su orden, hehermes-dispositivo y la unidad del cortafuegos.
    for ruta, datos, modo in ficheros_propios(ORIGEN):
        fichero(ruta, datos, modo)
    if sis.enlace(p.ORDEN) is None:
        man.apuntar_carpetas(sis, p.ORDEN)
        sis.enlazar(p.ORDEN, p.PREFIJO + "/hehermes-servidor")
    man.apuntar_enlace(p.ORDEN, p.PREFIJO + "/hehermes-servidor")
    fichero(p.DISPOSITIVO, (apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo").read_bytes(), 0o750)
    fichero(p.UNIDAD_CORTAFUEGOS, p.unidad_cortafuegos().encode())
    # Lo suyo.
    fichero(p.SERVIDOR_INI, (p.CABECERA + "[servidor]\ndireccion = %s\n\n[hermes]\nenv = /root/.hermes/.env\n"
                             "puerto = 8642\n\n[dispositivos]\nregistro = %s\n\n[strongswan]\ncarpeta = %s\n"
                             % (sf.IP_PUBLICA, p.REGISTRO, falso.swanctl)).encode())
    fichero(p.SCRIPT_XFRM, _texto("hehermes-xfrm"), 0o755)
    for ruta in (p.UNIDAD_XFRM, p.UNIDAD_CLAVE_SERVICE, p.UNIDAD_CLAVE_PATH, p.DROP_IN_NGINX):
        fichero(ruta, _texto(ruta))
    fichero(p.BEARER, ('proxy_set_header Authorization "Bearer %s";\n' % sf.CLAVE).encode(), 0o600, gestionado=True)
    if falso.familia == "rhel":
        # El nginx de la familia Red Hat no tiene sites-enabled: el sitio iba en conf.d.
        fichero(p.SITIO_CONF_D, SITIO.encode())
    else:
        fichero(p.SITIO, SITIO.encode())
        man.apuntar_carpetas(sis, p.SITIO_ENLACE)
        sis.enlazar(p.SITIO_ENLACE, p.SITIO)
        man.apuntar_enlace(p.SITIO_ENLACE, p.SITIO)
    if "nginx" in man.paquetes and sis.existe(p.DEFAULT_NGINX):
        # El nginx que instalaba ella traía su sitio de bienvenida en *:80, y lo apagaba.
        man.quitados[p.DEFAULT_NGINX] = m.guardar_copia(sis, p.DEFAULT_NGINX)
        sis.borrar(p.DEFAULT_NGINX)
    for unidad in UNIDADES:
        falso._systemctl(["enable", "--now", unidad], None)
        if unidad not in man.unidades:
            man.unidades.append(unidad)
    # El cortafuegos que haya: ufw, firewalld o nftables e iptables a pelo (con los de la pasarela, si está).
    if falso.ufw is not None:
        for regla in p.reglas_ufw("vpn"):
            falso._ufw(regla.args, None)
            man.reglas.append(regla.texto)
    if falso.firewalld is not None:
        for regla in p.reglas_firewalld("vpn"):
            falso.fw_permanente.add(regla.opcion[len("--add-"):])
            if falso.firewalld == "activo":
                falso.fw_ahora.add(regla.opcion[len("--add-"):])
            man.reglas.append(regla.texto)
        man.datos["cortafuegos"] = "firewalld"
    if falso.nft_cadenas or falso.iptables is not None:
        gestor = falso.ufw == "activo" or falso.firewalld == "activo"
        man.datos.setdefault("cortafuegos_propio", {"iptables": not gestor})
        cf.poner(sis, cf.MARCA, cf.permanentes_de(man.datos), man.datos["cortafuegos_propio"]["iptables"])
    if falso.selinux in ("Enforcing", "Permissive"):
        # El puerto de Hermes, con la etiqueta de nginx.
        falso.etiquetas["8642"] = "http_port_t"
        man.datos["selinux_puertos"] = ["8642"]
    if avisos:
        falso._bash([], None)
        man.datos["avisos"] = True
    for nombre in iphones:
        falso._hehermes_dispositivo(["alta", nombre, "--ikev2", "--servidor", sf.IP_PUBLICA], None)
        man.dispositivos.append(nombre)
    man.guardar(sis)
    if sin_modos:
        datos = json.loads(sis.leer(man.ruta))
        datos.pop("modos", None)
        sis.escribir(man.ruta, (json.dumps(datos, indent=2, sort_keys=True) + "\n").encode(), modo=0o600)
    return Manifiesto.leer(sis)


def servidor():
    """Con los paquetes de la VPN ya puestos y ufw en marcha: así lo único que cambia en /etc es del instalador."""
    sis, falso = sf.servidor()
    for paquete in PAQUETES + ("ufw",):
        falso.instalar_paquete(paquete)
    falso.ufw = "activo"
    falso.reglas_ufw = ["ufw allow 22/tcp"]
    return sis, falso
