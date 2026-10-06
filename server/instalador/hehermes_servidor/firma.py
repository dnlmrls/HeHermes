"""La firma Ed25519 de las actualizaciones, comprobada con `openssl` (spec, «Cómo se distribuye»).

La primera instalación se fía de la suma SHA-256 que lleva la app en el comando. Las siguientes (`actualizar`) no
pasan por la app: se fían de una firma hecha con una clave de Daniel, que no está en ningún servidor. El paquete lleva
las partes públicas de **dos** (spec 2026-10-04, «Las claves»): la principal (`clave-publica.pem`; su privada, en el
llavero de su Mac) y la de rescate (`clave-rescate.pem`; la privada, en sus Contraseñas), que firma la versión que trae
otra principal si esta se pierde o se compromete. Vale la firma de cualquiera de las dos; mientras las dos sean el
marcador, `actualizar` se niega.

Ed25519 «puro» (`openssl pkeyutl -rawin`): la firma son 64 bytes sobre el fichero entero, sin resumen previo. Hace
falta OpenSSL 3, que traen todas las distribuciones de la decisión 4, pero no siempre su orden `openssl` (una imagen
mínima): sin ella, o con una que no sabe Ed25519, se comprueba con `cryptography`, la del venv del canje (desde la
0.11.1). Si no hay con qué, se dice así, y no «la firma no es buena».
"""

from __future__ import annotations

MARCADOR = "PENDIENTE-DE-DANIEL"
#: Lo que comprueba la firma con `cryptography` (con el Python del venv del canje): «buena» y 0, «mala» y 1. Otra cosa
#: (sin `cryptography`, una clave que no es Ed25519, un fichero que no se lee) es que no se ha podido.
CON_CRYPTOGRAPHY = (
    "import sys\n"
    "from cryptography.exceptions import InvalidSignature\n"
    "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n"
    "from cryptography.hazmat.primitives.serialization import load_pem_public_key\n"
    "with open(sys.argv[1], 'rb') as f:\n"
    "    clave = load_pem_public_key(f.read())\n"
    "if not isinstance(clave, Ed25519PublicKey):\n"
    "    sys.exit(3)\n"
    "with open(sys.argv[2], 'rb') as f, open(sys.argv[3], 'rb') as g:\n"
    "    datos, sello = f.read(), g.read()\n"
    "try:\n"
    "    clave.verify(sello, datos)\n"
    "except InvalidSignature:\n"
    "    print('mala')\n"
    "    sys.exit(1)\n"
    "print('buena')\n"
)
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


def verificar(sis, paquete: str, firma: str, clave_publica: str, python: str | None = None) -> bool | None:
    """True si la firma es buena con esa clave; False si es mala; None si no hay con qué comprobarlo: ni la orden
    `openssl` de OpenSSL 3 ni `cryptography` en el Python de `python` (el del venv del canje)."""
    r = sis.ejecutar(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", clave_publica, "-rawin", "-in", paquete,
                      "-sigfile", firma])
    # Las dos cosas: el código y el texto. Un openssl que no entiende las opciones puede salir con 0 sin verificar.
    if r.bien and "Signature Verified Successfully" in r.salida:
        return True
    if "Signature Verification Failure" in r.salida + r.error:
        return False
    # Sin openssl (127), uno que no sabe Ed25519 o -rawin (el de antes de la 3), o algo que no se sabe leer.
    if python is None or not sis.existe(python):
        return None
    r = sis.ejecutar([python, "-I", "-B", "-c", CON_CRYPTOGRAPHY, clave_publica, paquete, firma])
    if r.codigo == 0 and r.salida.strip() == "buena":
        return True
    if r.codigo == 1 and r.salida.strip() == "mala":
        return False
    return None


def verificar_con_alguna(sis, paquete: str, firma: str, rutas, python: str | None = None) -> bool | None:
    """Si la firma es de alguna de esas claves (las de `claves`): True; si no lo es de ninguna, False; y None si con
    ninguna se ha podido comprobar (`verificar`). Sin claves, False."""
    vistas = []
    for ruta in rutas:
        buena = verificar(sis, paquete, firma, ruta, python)
        if buena:
            return True
        vistas.append(buena)
    return None if vistas and all(v is None for v in vistas) else False
