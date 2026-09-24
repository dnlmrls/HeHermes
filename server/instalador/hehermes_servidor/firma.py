"""La firma Ed25519 de las actualizaciones, comprobada con `openssl` (spec, «Cómo se distribuye»).

La primera instalación se fía de la suma SHA-256 que lleva la app en el comando. Las siguientes (`actualizar`) no
pasan por la app: se fían de una firma hecha con la clave de Daniel, que no está en ningún servidor. Su parte pública
viaja en el paquete (`clave-publica.pem`); mientras sea el marcador, `actualizar` se niega.

Ed25519 «puro» (`openssl pkeyutl -rawin`): la firma son 64 bytes sobre el fichero entero, sin resumen previo. Hace
falta OpenSSL 3, que traen todas las distribuciones de la decisión 4.
"""

from __future__ import annotations

MARCADOR = "PENDIENTE-DE-DANIEL"


def pendiente(texto_clave: str) -> bool:
    """Si la clave pública del paquete todavía es el marcador (o no es una clave)."""
    return MARCADOR in texto_clave or "-----BEGIN PUBLIC KEY-----" not in texto_clave


def verificar(sis, paquete: str, firma: str, clave_publica: str) -> bool:
    r = sis.ejecutar(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", clave_publica, "-rawin", "-in", paquete,
                      "-sigfile", firma])
    # Las dos cosas: el código y el texto. Un openssl que no entiende las opciones puede salir con 0 sin verificar.
    return r.bien and "Signature Verified Successfully" in r.salida
