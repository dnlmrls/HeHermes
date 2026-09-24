"""El sobre ``c`` de cada aviso: ChaCha20-Poly1305 con la clave de un iPhone, sin datos asociados.

Es el formato que abre la extensión de la app (``CifradoDeAvisos.swift``)::

    {"v": 1, "n": base64(nonce de 12 bytes), "t": base64(cifrado ‖ etiqueta de 16 bytes)}

``ChaCha20Poly1305.encrypt`` de ``cryptography`` devuelve ya el cifrado seguido de la etiqueta, que es justo el orden que
espera CryptoKit al otro lado: no hay que partir ni pegar nada. Lo fija una prueba contra el vector de la app, calculado
fuera de CryptoKit (``tests/test_cifrado.py``).
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
BYTES_CLAVE = 32
BYTES_NONCE = 12
BYTES_ETIQUETA = 16


class ErrorDeCifrado(Exception):
    """Una clave o un sobre que no valen. Nunca lleva el contenido en el mensaje."""


def clave_desde_base64(texto: object) -> bytes:
    """La clave del iPhone tal y como llega en el alta: base64 estándar de exactamente 32 bytes.

    Se valida entera (``validate=True``): un base64 con basura que ``b64decode`` se tragara en silencio daría otra
    clave, los avisos saldrían cifrados con ella y la extensión se quedaría siempre en el texto de reserva.
    """
    if not isinstance(texto, str):
        raise ErrorDeCifrado("la clave tiene que ser un texto en base64")
    try:
        clave = base64.b64decode(texto.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ErrorDeCifrado("la clave no es base64") from None
    if len(clave) != BYTES_CLAVE:
        raise ErrorDeCifrado(f"la clave tiene que medir {BYTES_CLAVE} bytes")
    return clave


def subclave(clave: bytes, info: str) -> bytes:
    """Una clave de 32 bytes derivada de la del iPhone para otro uso: HKDF-SHA256 (RFC 5869) con la sal vacía (0 bytes)
    y ``info`` en UTF-8.

    La clave del iPhone es la del ChaCha20-Poly1305 del sobre; lo demás que sale de ella (el hilo y el colapso, que son
    HMAC) sale de una subclave, para no usar la misma clave en dos algoritmos. Con la sal vacía, porque la clave ya es
    uniforme (32 bytes al azar de la app) y así no hay nada más que acordar con ella: HMAC rellena con ceros una clave
    corta, así que da lo mismo que la sal de ceros por defecto de la RFC.
    """
    if len(clave) != BYTES_CLAVE:
        raise ErrorDeCifrado(f"la clave tiene que medir {BYTES_CLAVE} bytes")
    return HKDF(algorithm=hashes.SHA256(), length=BYTES_CLAVE, salt=b"", info=info.encode("utf-8")).derive(clave)


def sellar(claro: bytes, clave: bytes, nonce: bytes | None = None) -> dict:
    """Cifra ``claro`` con la clave del iPhone.

    El nonce es nuevo y al azar en cada llamada: repetir nonce con la misma clave rompe ChaCha20-Poly1305 entero (quien
    junte dos avisos saca el texto de los dos), así que no hay forma de pedir uno fijo salvo desde las pruebas.
    """
    if len(clave) != BYTES_CLAVE:
        raise ErrorDeCifrado(f"la clave tiene que medir {BYTES_CLAVE} bytes")
    if nonce is None:
        nonce = os.urandom(BYTES_NONCE)
    if len(nonce) != BYTES_NONCE:
        raise ErrorDeCifrado(f"el nonce tiene que medir {BYTES_NONCE} bytes")
    sellado = ChaCha20Poly1305(clave).encrypt(nonce, claro, None)
    return {"v": VERSION,
            "n": base64.b64encode(nonce).decode("ascii"),
            "t": base64.b64encode(sellado).decode("ascii")}


def abrir(sobre: dict, clave: bytes) -> bytes:
    """Descifra un sobre. El vigía no lo necesita para trabajar; está para las pruebas y para diagnosticar a mano."""
    if not isinstance(sobre, dict) or sobre.get("v") != VERSION:
        raise ErrorDeCifrado("versión de sobre desconocida")
    try:
        nonce = base64.b64decode(str(sobre.get("n", "")).encode("ascii"), validate=True)
        sellado = base64.b64decode(str(sobre.get("t", "")).encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ErrorDeCifrado("sobre ilegible") from None
    if len(nonce) != BYTES_NONCE or len(sellado) < BYTES_ETIQUETA:
        raise ErrorDeCifrado("sobre ilegible")
    try:
        return ChaCha20Poly1305(clave).decrypt(nonce, sellado, None)
    except InvalidTag:
        raise ErrorDeCifrado("el sobre no se abre con esta clave") from None
