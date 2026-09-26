"""De qué modo es cada cosa del manifiesto: lo que quita `desinstalar --modo vpn` o `--modo tls` (quitar un modo sin
tocar el otro).

Se decide por la ruta, el nombre o el texto de cada cosa, y no por lo que apuntó cada pasada: así vale también para un
manifiesto de antes de que los dos modos convivieran, como el del VPS de Daniel. Lo que no es de ninguno de los dos es
común (el instalador en /opt, su orden, `hehermes-dispositivo`, `hehermes-cortafuegos.service`, las líneas del .env de
Hermes, el venv de `cryptography`) y solo se va con `desinstalar` a secas.
"""

from __future__ import annotations

from . import piezas as p

VPN, TLS = "vpn", "tls"
NOMBRES = {VPN: "la VPN IKEv2", TLS: "la pasarela TLS"}

FICHEROS_VPN = frozenset((p.SERVIDOR_INI, p.SCRIPT_XFRM, p.UNIDAD_XFRM, p.UNIDAD_CLAVE_PATH, p.UNIDAD_CLAVE_SERVICE,
                          p.DROP_IN_NGINX, p.SITIO, p.SITIO_ENLACE, p.SITIO_CONF_D, p.BEARER))
UNIDADES_VPN = frozenset(("hehermes-xfrm.service", "hehermes-clave.path", "strongswan.service"))
UNIDADES_TLS = frozenset((p.UNIDAD_PASARELA, "hehermes-pasarela-clave.path"))
USUARIOS_TLS = frozenset((p.USUARIO_PASARELA,))
#: El único paquete que pueden pedir los dos (el venv de `cryptography`); los demás son de strongSwan y nginx.
PAQUETES_COMUNES = frozenset(("python3-venv",))


def de_fichero(ruta: str, ambito) -> str | None:
    if ruta in FICHEROS_VPN:
        return VPN
    if ruta.startswith(ambito.carpeta_pasarela + "/") or ruta in (ambito.unidad, p.UNIDAD_PASARELA_CLAVE_PATH,
                                                                 p.UNIDAD_PASARELA_CLAVE_SERVICE):
        return TLS
    return None


def de_unidad(unidad: str) -> str | None:
    if unidad in UNIDADES_VPN:
        return VPN
    if unidad in UNIDADES_TLS:
        return TLS
    return None


def de_regla(texto: str, puerto) -> str | None:
    """Una regla de ufw o de firewalld del manifiesto. `puerto`, el de la pasarela (sin él, ninguna es suya)."""
    if texto in {r.texto for r in p.reglas_ufw() + p.reglas_firewalld()}:
        return VPN
    try:
        de_la_pasarela = {r.texto for r in p.reglas_ufw(TLS, puerto) + p.reglas_firewalld(TLS, puerto)}
    except ValueError:
        return None
    return TLS if texto in de_la_pasarela else None


def de_paquete(nombre: str) -> str | None:
    return None if nombre in PAQUETES_COMUNES else VPN


def de_usuario(usuario: str) -> str | None:
    return TLS if usuario in USUARIOS_TLS else None
