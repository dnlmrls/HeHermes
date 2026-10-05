"""La firma Ed25519 de las actualizaciones, comprobada con `openssl` (spec, «Cómo se distribuye»).

La primera instalación se fía de la suma SHA-256 que lleva la app en el comando. Las siguientes (`actualizar`) no
pasan por la app: se fían de una firma hecha con una clave de Daniel, que no está en ningún servidor. El paquete lleva
las partes públicas de **dos** (spec 2026-10-04, «Las claves»): la principal (`clave-publica.pem`; su privada, en el
llavero de su Mac) y la de rescate (`clave-rescate.pem`; la privada, en sus Contraseñas), que firma la versión que trae
otra principal si esta se pierde o se compromete. Vale la firma de cualquiera de las dos; mientras las dos sean el
marcador, `actualizar` se niega.

Ed25519 «puro» (`openssl pkeyutl -rawin`): la firma son 64 bytes sobre el fichero entero, sin resumen previo. Hace
falta OpenSSL 3, que traen todas las distribuciones de la decisión 4.
"""

from __future__ import annotations

MARCADOR = "PENDIENTE-DE-DANIEL"
#: La principal y la de rescate, en este orden, en la carpeta del instalador (y en el paquete).
CLAVES = ("clave-publica.pem", "clave-rescate.pem")


def pendiente(texto_clave: str) -> bool:
    """Si una clave pública del paquete todavía es el marcador (o no es una clave pública: una privada puesta en su
    sitio por error tampoco cuenta)."""
    return (MARCADOR in texto_clave or "-----BEGIN PUBLIC KEY-----" not in texto_clave
            or "PRIVATE" in texto_clave)


def claves(sis, prefijo: str) -> list:
    """Las rutas de verdad (las de `sis`) de las claves de la carpeta del instalador que no son el marcador: con las
    que se comprueba una actualización. Vacía: no hay con qué."""
    return [sis.ruta(prefijo + "/" + nombre) for nombre in CLAVES
            if not pendiente(sis.leer_texto(prefijo + "/" + nombre) or "")]


def verificar(sis, paquete: str, firma: str, clave_publica: str) -> bool:
    r = sis.ejecutar(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", clave_publica, "-rawin", "-in", paquete,
                      "-sigfile", firma])
    # Las dos cosas: el código y el texto. Un openssl que no entiende las opciones puede salir con 0 sin verificar.
    return r.bien and "Signature Verified Successfully" in r.salida


def verificar_con_alguna(sis, paquete: str, firma: str, rutas) -> bool:
    """Si la firma es de alguna de esas claves (las de `claves`). Sin ninguna, no."""
    return any(verificar(sis, paquete, firma, ruta) for ruta in rutas)
