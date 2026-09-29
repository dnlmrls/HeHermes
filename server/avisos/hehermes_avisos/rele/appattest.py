"""Comprobar una atestación y una aserción de App Attest (Apple, «Validating apps that connect to your server»).

Una **atestación** llega una vez por clave: Apple certifica que la clave vive en el Secure Enclave de un iPhone de
verdad y que la pidió la app ``<equipo>.<bundle>``, sin tocar. Después, cada **aserción** se firma con esa clave y
demuestra que sigue siendo la misma app en el mismo iPhone. Aquí solo se comprueba; qué se guarda y qué se da a cambio
es cosa de ``permisos``.

Todo lo que hay aquí trata datos sin autenticar que llegan de internet: se lee con ``cbor`` (estricto, con topes) y con
``cryptography``, y cualquier cosa rara es un ``ErrorDeAtestacion`` sin detalles del mensaje. Cada comprobación es una
función aparte con su prueba (``tests/test_appattest.py``), y las mutaciones de esas pruebas quitan una a una.

La raíz de Apple va **incrustada** (``RAIZ_APPLE``): es pública (apple.com/certificateauthority), caduca en 2045 y es
la única en la que se confía. No se consulta nada a Apple en ningún momento.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import cbor

#: «Apple App Attestation Root CA», tal cual la publica Apple
#: (https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem).
RAIZ_APPLE = b"""-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
"""
#: El SHA-256 de ese certificado en DER: lo comprueba una prueba, para que un cambio en el PEM no pase sin verse.
HUELLA_RAIZ_APPLE = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"

#: El App ID de HeHermes: equipo y bundle.
APP_ID = "8X7L8YHD9M.com.danielmorales.HeHermesMensajes"
#: Los dos «aaguid» de App Attest: el de las compilaciones de desarrollo (Xcode) y el de producción (TestFlight y App
#: Store, «appattest» y siete bytes a cero).
AAGUID_DESARROLLO = b"appattestdevelop"
AAGUID_PRODUCCION = b"appattest" + b"\x00" * 7
ENTORNOS_ATTEST = {AAGUID_DESARROLLO: "desarrollo", AAGUID_PRODUCCION: "produccion"}
#: La extensión de la hoja con el nonce.
OID_NONCE = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
#: Lo más grande que se acepta de una atestación y de una aserción, antes de leer nada (una de verdad mide unos 5,5 KB y
#: la aserción, menos de 200 bytes).
TOPE_ATESTACION = 12 * 1024
TOPE_ASERCION = 1024


class ErrorDeAtestacion(ValueError):
    """La atestación o la aserción no valen. ``motivo`` es corto y no lleva nada de lo recibido: va al registro."""

    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


@dataclass(frozen=True)
class ClaveAtestada:
    """Lo que queda de una atestación buena: lo que hace falta para comprobar sus aserciones."""
    clave_id: bytes
    #: La clave pública en DER (SubjectPublicKeyInfo).
    publica: bytes
    contador: int
    #: «desarrollo» o «produccion», del aaguid.
    entorno: str


def hash_del_app_id(app_id: str = APP_ID) -> bytes:
    return hashlib.sha256(app_id.encode("utf-8")).digest()


def raiz_apple() -> x509.Certificate:
    return x509.load_pem_x509_certificate(RAIZ_APPLE)


# MARK: Las piezas


@dataclass(frozen=True)
class DatosDelAutenticador:
    rp_id_hash: bytes
    banderas: int
    contador: int
    aaguid: bytes | None = None
    credencial: bytes | None = None


def leer_datos_del_autenticador(datos: bytes, con_credencial: bool) -> DatosDelAutenticador:
    """``authData`` de WebAuthn: rpIdHash (32), banderas (1), contador (4) y, en una atestación, aaguid (16), largo del
    credentialId (2) y el credentialId. Lo que va detrás (la clave en COSE) no se lee: la clave sale del certificado."""
    if not isinstance(datos, bytes) or len(datos) < 37:
        raise ErrorDeAtestacion("authData demasiado corto")
    rp, banderas, contador = datos[:32], datos[32], int.from_bytes(datos[33:37], "big")
    if not con_credencial:
        return DatosDelAutenticador(rp, banderas, contador)
    if len(datos) < 55:
        raise ErrorDeAtestacion("authData sin los datos de la credencial")
    largo = int.from_bytes(datos[53:55], "big")
    if largo == 0 or 55 + largo > len(datos):
        raise ErrorDeAtestacion("credentialId cortado")
    return DatosDelAutenticador(rp, banderas, contador, datos[37:53], datos[55:55 + largo])


def nonce_de_la_hoja(hoja: x509.Certificate) -> bytes:
    """El OCTET STRING de la extensión 1.2.840.113635.100.8.2: ``SEQUENCE { [1] EXPLICIT OCTET STRING (32) }``, en DER
    y con los largos cortos que salen con 32 bytes. Cualquier otra forma se rechaza."""
    try:
        valor = hoja.extensions.get_extension_for_oid(OID_NONCE).value
    except x509.ExtensionNotFound:
        raise ErrorDeAtestacion("la hoja no lleva el nonce") from None
    datos = getattr(valor, "value", None)
    if not isinstance(datos, bytes) or len(datos) != 38 or datos[:6] != b"\x30\x24\xa1\x22\x04\x20":
        raise ErrorDeAtestacion("el nonce de la hoja no tiene su forma")
    return datos[6:]


def clave_id_de(hoja: x509.Certificate) -> bytes:
    """El keyId de App Attest: el SHA-256 de la clave pública P-256 de la hoja, en su punto sin comprimir (65 bytes)."""
    publica = hoja.public_key()
    if not isinstance(publica, ec.EllipticCurvePublicKey) or publica.curve.name != "secp256r1":
        raise ErrorDeAtestacion("la clave de la hoja no es P-256")
    return hashlib.sha256(publica.public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.UncompressedPoint)).digest()


def _en_fecha(certificado: x509.Certificate, ahora: datetime.datetime) -> bool:
    return certificado.not_valid_before_utc <= ahora <= certificado.not_valid_after_utc


def _es_ca(certificado: x509.Certificate) -> bool:
    try:
        return bool(certificado.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def comprobar_cadena(x5c, raiz: x509.Certificate, ahora: datetime.datetime) -> x509.Certificate:
    """``hoja → intermedio → raíz``: cada uno emitido y firmado por el siguiente, todos en fecha, el intermedio (y la
    raíz) de CA y la hoja no. La raíz es la que se da (la de Apple, incrustada): la cadena no la trae. Devuelve la hoja."""
    if not isinstance(x5c, list) or len(x5c) != 2 or not all(isinstance(c, bytes) for c in x5c):
        raise ErrorDeAtestacion("x5c tiene que ser la hoja y el intermedio")
    try:
        hoja, intermedio = (x509.load_der_x509_certificate(c) for c in x5c)
    except ValueError:
        raise ErrorDeAtestacion("un certificado de x5c no se entiende") from None
    for certificado in (hoja, intermedio, raiz):
        if not _en_fecha(certificado, ahora):
            raise ErrorDeAtestacion("un certificado de la cadena está fuera de fecha")
    if not _es_ca(intermedio) or not _es_ca(raiz) or _es_ca(hoja):
        raise ErrorDeAtestacion("la cadena no tiene sus restricciones básicas")
    try:
        # Comprueba que el emisor del primero es el sujeto del segundo y la firma con su clave.
        hoja.verify_directly_issued_by(intermedio)
        intermedio.verify_directly_issued_by(raiz)
    except (ValueError, TypeError, InvalidSignature):
        raise ErrorDeAtestacion("la cadena no llega a la raíz de Apple") from None
    return hoja


# MARK: La atestación


def comprobar_atestacion(atestacion: bytes, clave_id: bytes, client_data_hash: bytes, *, app_id: str = APP_ID,
                         raiz: x509.Certificate | None = None,
                         ahora: datetime.datetime | None = None) -> ClaveAtestada:
    """Los nueve pasos de Apple. ``clave_id`` es el keyId que manda la app y ``client_data_hash``, el SHA-256 de los
    datos que ella firmó (el reto, el token y el entorno: ``permisos.datos_firmados``)."""
    if not isinstance(atestacion, bytes) or len(atestacion) > TOPE_ATESTACION:
        raise ErrorDeAtestacion("atestación demasiado grande")
    if len(clave_id) != 32 or len(client_data_hash) != 32:
        raise ErrorDeAtestacion("keyId o clientDataHash sin sus 32 bytes")
    try:
        objeto = cbor.leer(atestacion)
    except cbor.ErrorCBOR:
        raise ErrorDeAtestacion("la atestación no es CBOR válido") from None
    if not isinstance(objeto, dict) or set(objeto) != {"fmt", "attStmt", "authData"}:
        raise ErrorDeAtestacion("la atestación no tiene sus tres campos")
    if objeto["fmt"] != "apple-appattest":
        raise ErrorDeAtestacion("formato de atestación desconocido")
    declaracion, datos = objeto["attStmt"], objeto["authData"]
    if not isinstance(declaracion, dict) or "x5c" not in declaracion or not isinstance(datos, bytes):
        raise ErrorDeAtestacion("la atestación no trae x5c o authData")
    ahora = ahora or datetime.datetime.now(datetime.timezone.utc)
    # 1. La cadena hasta la raíz de Apple.
    hoja = comprobar_cadena(declaracion["x5c"], raiz or raiz_apple(), ahora)
    # 2 y 3. El nonce: SHA-256(authData ‖ clientDataHash), el de la hoja.
    nonce = hashlib.sha256(datos + client_data_hash).digest()
    if not hmac.compare_digest(nonce, nonce_de_la_hoja(hoja)):
        raise ErrorDeAtestacion("el nonce no es el de la hoja")
    # 4. El keyId es el SHA-256 de la clave pública de la hoja.
    if not hmac.compare_digest(clave_id_de(hoja), clave_id):
        raise ErrorDeAtestacion("el keyId no es el de la hoja")
    autenticador = leer_datos_del_autenticador(datos, con_credencial=True)
    # 5. El RP ID es el de esta app.
    if not hmac.compare_digest(autenticador.rp_id_hash, hash_del_app_id(app_id)):
        raise ErrorDeAtestacion("la atestación es de otra app")
    # 6. El contador empieza en 0.
    if autenticador.contador != 0:
        raise ErrorDeAtestacion("el contador de una atestación tiene que ser 0")
    # 7. El entorno de App Attest.
    entorno = ENTORNOS_ATTEST.get(autenticador.aaguid)
    if entorno is None:
        raise ErrorDeAtestacion("aaguid desconocido")
    # 8. El credentialId es el keyId.
    if not hmac.compare_digest(autenticador.credencial, clave_id):
        raise ErrorDeAtestacion("el credentialId no es el keyId")
    publica = hoja.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    return ClaveAtestada(clave_id, publica, 0, entorno)


# MARK: La aserción


def comprobar_asercion(asercion: bytes, publica_der: bytes, contador_guardado: int, client_data_hash: bytes, *,
                       app_id: str = APP_ID) -> int:
    """Una aserción de la clave ``publica_der`` sobre ``client_data_hash``. Devuelve el contador nuevo, que es mayor
    que el guardado (si no, alguien repite una aserción vieja).

    La firma es ECDSA P-256 con SHA-256 sobre ``nonce = SHA-256(authenticatorData ‖ clientDataHash)``: el mensaje
    firmado es el nonce, así que se comprueba el SHA-256 **del nonce**. Así lo hace el iPhone (lo fija el vector de uno de
    verdad en ``tests/datos/app-attest/``; firmar ``authenticatorData ‖ clientDataHash`` directamente no pasa)."""
    if not isinstance(asercion, bytes) or len(asercion) > TOPE_ASERCION:
        raise ErrorDeAtestacion("aserción demasiado grande")
    if len(client_data_hash) != 32:
        raise ErrorDeAtestacion("clientDataHash sin sus 32 bytes")
    try:
        objeto = cbor.leer(asercion)
    except cbor.ErrorCBOR:
        raise ErrorDeAtestacion("la aserción no es CBOR válido") from None
    if not isinstance(objeto, dict) or set(objeto) != {"signature", "authenticatorData"}:
        raise ErrorDeAtestacion("la aserción no tiene sus dos campos")
    firma, datos = objeto["signature"], objeto["authenticatorData"]
    if not isinstance(firma, bytes) or not isinstance(datos, bytes):
        raise ErrorDeAtestacion("la aserción no trae bytes")
    autenticador = leer_datos_del_autenticador(datos, con_credencial=False)
    if not hmac.compare_digest(autenticador.rp_id_hash, hash_del_app_id(app_id)):
        raise ErrorDeAtestacion("la aserción es de otra app")
    try:
        publica = serialization.load_der_public_key(publica_der)
    except ValueError:
        raise ErrorDeAtestacion("la clave guardada no se entiende") from None
    if not isinstance(publica, ec.EllipticCurvePublicKey):
        raise ErrorDeAtestacion("la clave guardada no es de curva elíptica")
    nonce = hashlib.sha256(datos + client_data_hash).digest()
    try:
        publica.verify(firma, nonce, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise ErrorDeAtestacion("la firma de la aserción no vale") from None
    if autenticador.contador <= contador_guardado:
        raise ErrorDeAtestacion("el contador no ha subido: aserción repetida")
    return autenticador.contador
