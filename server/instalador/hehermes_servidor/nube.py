"""La nube del servidor y su dirección pública detrás de un NAT, sin servicios de fuera.

En AWS (EC2 y Lightsail), Google Cloud, Azure y Oracle Cloud la tarjeta de red tiene una IP privada y la pública la pone
un NAT 1:1 del proveedor: la ruta de salida da la privada, y hasta la 0.11.0 el instalador se paraba con `nat` (por chat,
sin forma de dar `--direccion`). La pública la sabe el servicio de metadatos del proveedor, que está en la propia máquina
(169.254.169.254, de enlace local: no sale a internet). No es un servicio de eco de fuera, que es lo que se descartó en
la 0.9.0 (README, «Decisiones de la 0.9.0»): ni es una dependencia de nadie más ni le cuenta a nadie que aquí se instala
HeHermes.

El proveedor se reconoce por DMI (`/sys/class/dmi/id`, que se lee sin root), como hace cloud-init, y solo se le pregunta
al suyo. Si DMI no dice nada, se prueba una vez la forma de EC2, que imitan otras nubes (OpenStack); si ahí no contesta
nadie, no hay servicio de metadatos y no se espera más. Cada petición tiene su plazo corto (`sistema.PLAZO_METADATOS`).

Lo que contesta solo vale si es una IPv4 pública, sola: una privada, de CGNAT, de enlace local, de multidifusión,
reservada, una IPv6 o algo que no es una IP no se usa nunca (`publica`). El token de IMDSv2 de AWS dura un minuto, no se
guarda y no se pinta.
"""

from __future__ import annotations

import ipaddress
import json
import re

METADATOS = "http://169.254.169.254"
#: Lo que dice el chasis de una máquina de Azure y de una de Oracle Cloud (cloud-init: `DataSourceAzure`,
#: `DataSourceOracle`).
CHASIS_AZURE = "7783-7084-3265-9085-8269-3286-77"
CHASIS_ORACLE = "OracleCloud.com"
NOMBRES = {"aws": "AWS", "gcp": "Google Cloud", "azure": "Azure", "oracle": "Oracle Cloud",
           "digitalocean": "DigitalOcean", "hetzner": "Hetzner Cloud"}
#: Dónde ve cada uno su IP pública en el panel del proveedor, para cuando los metadatos no la dan (en Oracle Cloud no la
#: dan nunca: su `/opc/v2/vnics/` solo trae las privadas).
DONDE_MIRARLA = {
    "aws": "en la consola de EC2 (o de Lightsail), en tu instancia: «Dirección IPv4 pública»",
    "gcp": "en la consola de Google Cloud, en Compute Engine › Instancias de VM: «IP externa»",
    "azure": "en el portal de Azure, en tu máquina virtual: «Dirección IP pública»",
    "oracle": "en la consola de Oracle Cloud, en Instancias › tu instancia: «Dirección IP pública»",
    "digitalocean": "en el panel de DigitalOcean, en tu Droplet: «ipv4»",
    "hetzner": "en la consola de Hetzner Cloud, en tu servidor: «IPv4»",
}
#: Lo que se le pide a cada uno. Los de Azure y Google rechazan una petición sin su cabecera (y Azure, una que pase por un
#: proxy: `Sistema.metadatos` no usa ninguno).
_AWS_TOKEN = METADATOS + "/latest/api/token"
_AWS_IP = METADATOS + "/latest/meta-data/public-ipv4"
_GCP_IP = METADATOS + "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
_AZURE_IP = METADATOS + ("/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress"
                         "?api-version=2021-02-01&format=text")
#: Una IP pública de SKU estándar (la única que da Azure desde que retiró la básica, en 2025) no sale en la de arriba,
#: sino aquí (learn.microsoft.com, «Retrieve load balancer and virtual machine IP metadata»).
_AZURE_EQUILIBRADOR = METADATOS + "/metadata/loadbalancer?api-version=2020-10-01"
_DO_IP = METADATOS + "/metadata/v1/interfaces/public/0/ipv4/address"
_HETZNER_IP = METADATOS + "/hetzner/v1/metadata/public-ipv4"
_TOKEN = re.compile(r"[A-Za-z0-9_=+/.-]{1,512}")
_IPV4 = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Las de documentación (RFC 5737) no son de nadie y ningún servidor de verdad sale por una: cuentan como públicas, para
# que las pruebas y los ejemplos las usen en vez de la dirección de un servidor que exista.
_DOCUMENTACION = tuple(ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def es_privada(ip) -> bool:
    """Una dirección que no lleva a este servidor desde internet: privada, de bucle, de enlace local o de CGNAT."""
    if any(ip in red for red in _DOCUMENTACION):
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or (ip.version == 4 and ip in _CGNAT)


def publica(texto) -> str | None:
    """La IPv4 pública que ha contestado el servicio de metadatos, o None. Solo una IP sola, y nunca una privada, de
    bucle, de enlace local, de CGNAT, de multidifusión, reservada o sin especificar: con una de esas, el QR llevaría al
    iPhone a ninguna parte (o a otra máquina de la red)."""
    if isinstance(texto, bytes):
        texto = texto.decode("ascii", "replace")
    if not isinstance(texto, str):
        return None
    texto = texto.strip()
    if not _IPV4.fullmatch(texto):
        return None
    try:
        ip = ipaddress.IPv4Address(texto)
    except ValueError:
        return None
    if es_privada(ip) or ip.is_multicast or ip.is_reserved or ip.is_unspecified or str(ip) == "255.255.255.255":
        return None
    return str(ip)


def _dmi(sis, nombre) -> str:
    return (sis.leer_texto("/sys/class/dmi/id/" + nombre) or "").strip()


def proveedor(sis) -> str | None:
    """Qué nube es, por lo que dice el firmware de la máquina (DMI), sin preguntar nada a nadie; None si no se sabe."""
    chasis, fabricante = _dmi(sis, "chassis_asset_tag"), _dmi(sis, "sys_vendor")
    if chasis == CHASIS_ORACLE:
        return "oracle"
    if chasis == CHASIS_AZURE:
        return "azure"
    # Las de Nitro dicen «Amazon EC2»; las de Xen de antes (t2…), su BIOS «4.11.amazon» y un uuid que empieza por ec2.
    if fabricante == "Amazon EC2" or "amazon" in _dmi(sis, "bios_version").lower() or \
            (sis.leer_texto("/sys/hypervisor/uuid") or "").strip().lower().startswith("ec2"):
        return "aws"
    if fabricante == "Google" or _dmi(sis, "product_name") == "Google Compute Engine":
        return "gcp"
    if fabricante == "DigitalOcean":
        return "digitalocean"
    if fabricante == "Hetzner":
        return "hetzner"
    return None


def nombre(cual) -> str:
    return NOMBRES.get(cual, "tu proveedor")


def ip_publica(sis, cual, privada=None) -> str | None:
    """La IPv4 pública que da el servicio de metadatos de `cual` (o, si no se sabe qué nube es, el de la forma de EC2),
    validada con `publica`; None si no la da. `privada`: la de salida, para elegir la suya entre las de Azure."""
    if cual == "oracle":
        return None
    preguntar = {"gcp": _gcp, "azure": _azure, "digitalocean": _digitalocean, "hetzner": _hetzner}.get(cual, _ec2)
    try:
        return preguntar(sis, privada)
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None


def _ec2(sis, privada=None) -> str | None:
    """IMDSv2: un token de un minuto (PUT) y, con él, la IP. Si el PUT no tiene respuesta, no hay servicio de metadatos y
    no se pregunta más; si la tiene pero no da token (un IMDS de antes, el de OpenStack), la IP sin token."""
    estado, _, cuerpo = sis.metadatos("PUT", _AWS_TOKEN, {"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    if estado is None:
        return None
    token = cuerpo.decode("ascii", "replace").strip() if estado == 200 else ""
    cabeceras = {"X-aws-ec2-metadata-token": token} if _TOKEN.fullmatch(token) else {}
    del token
    estado, _, cuerpo = sis.metadatos("GET", _AWS_IP, cabeceras)
    return publica(cuerpo) if estado == 200 else None


def _gcp(sis, privada=None) -> str | None:
    estado, _, cuerpo = sis.metadatos("GET", _GCP_IP, {"Metadata-Flavor": "Google"})
    return publica(cuerpo) if estado == 200 else None


def _azure(sis, privada=None) -> str | None:
    cabeceras = {"Metadata": "true"}
    estado, _, cuerpo = sis.metadatos("GET", _AZURE_IP, cabeceras)
    if estado is None:
        return None
    if estado == 200 and publica(cuerpo):
        return publica(cuerpo)
    estado, _, cuerpo = sis.metadatos("GET", _AZURE_EQUILIBRADOR, cabeceras)
    if estado != 200:
        return None
    try:
        datos = json.loads(cuerpo)
    except ValueError:
        return None
    pares = ((datos.get("loadbalancer") or {}).get("publicIpAddresses") if isinstance(datos, dict) else None) or []
    pares = [par for par in pares if isinstance(par, dict)] if isinstance(pares, list) else []
    # La de esta máquina, si dice cuál es su privada; si no, la primera que sea pública.
    for par in sorted(pares, key=lambda par: par.get("privateIpAddress") != privada):
        ip = publica(par.get("frontendIpAddress"))
        if ip:
            return ip
    return None


def _digitalocean(sis, privada=None) -> str | None:
    estado, _, cuerpo = sis.metadatos("GET", _DO_IP)
    return publica(cuerpo) if estado == 200 else None


def _hetzner(sis, privada=None) -> str | None:
    estado, _, cuerpo = sis.metadatos("GET", _HETZNER_IP)
    return publica(cuerpo) if estado == 200 else None
