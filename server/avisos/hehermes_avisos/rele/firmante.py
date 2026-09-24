"""El JWT con el que el relé se identifica ante APNs: ES256 con la clave .p8, ``kid`` = Key ID, ``iss`` = Team ID.

Apple pide dos cosas que tiran en sentidos contrarios, y por eso se cachea:

- un token de **más de una hora** se rechaza (``ExpiredProviderToken``);
- renovarlo **más de una vez cada veinte minutos** también (``TooManyProviderTokenUpdates``).

Así que se firma uno, se usa en todas las peticiones y se renueva a los 45 minutos (``renovar``), antes de la hora y
lejos de los veinte minutos.
"""

from __future__ import annotations

import base64
import json
import threading
import time

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

RENOVAR = 45 * 60.0
# Lo que Apple deja entre dos renovaciones: menos, y contesta `TooManyProviderTokenUpdates`.
MINIMO_ENTRE_RENOVACIONES = 20 * 60.0


def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).decode("ascii").rstrip("=")


class FirmanteAPNs:
    def __init__(self, clave_privada, clave_id: str, equipo: str, renovar: float = RENOVAR, reloj=time.time,
                 monotono=None):
        if not isinstance(clave_privada, ec.EllipticCurvePrivateKey) or not isinstance(clave_privada.curve,
                                                                                          ec.SECP256R1):
            raise ValueError("la clave de APNs tiene que ser una clave EC P-256 (el .p8 que da Apple)")
        if not clave_id or not equipo:
            raise ValueError("faltan el Key ID o el Team ID de APNs")
        self._clave = clave_privada
        self.clave_id = clave_id
        self.equipo = equipo
        self.renovar = renovar
        # El `iat` es la hora de verdad; la edad del token, en cambio, se mide con un reloj que no salta cuando el
        # sistema corrige la hora, para que un ajuste de NTP no deje un token de más de una hora sin renovar.
        self.reloj = reloj
        self.monotono = monotono or (time.monotonic if reloj is time.time else reloj)
        self._cerrojo = threading.Lock()
        self._token: str | None = None
        self._firmado = 0.0

    @classmethod
    def desde_p8(cls, datos: bytes, clave_id: str, equipo: str, **opciones) -> FirmanteAPNs:
        """El .p8 de Apple es una clave PKCS#8 en PEM, sin contraseña."""
        try:
            clave = serialization.load_pem_private_key(datos, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise ValueError("el .p8 no es una clave privada PEM legible") from None
        return cls(clave, clave_id, equipo, **opciones)

    def token(self) -> str:
        with self._cerrojo:
            if self._token is None or self.monotono() - self._firmado >= self.renovar:
                self._token = self._firmar(self.reloj())
                self._firmado = self.monotono()
            return self._token

    def renovar_ya(self, rechazado: str) -> bool:
        """Para cuando Apple dice que ``rechazado`` ha caducado antes de tiempo. Devuelve si lo ha tirado.

        Solo si sigue siendo el que hay (con dos avisos rechazados a la vez, el segundo no tira el que acaba de firmar el
        primero) y si tiene al menos veinte minutos: uno más nuevo que Apple da por caducado es el reloj del VPS, que va
        mal, y firmar otro en cada aviso solo cambiaría el error por `TooManyProviderTokenUpdates`.
        """
        with self._cerrojo:
            if self._token != rechazado or self.monotono() - self._firmado < MINIMO_ENTRE_RENOVACIONES:
                return False
            self._token = None
            return True

    def _firmar(self, ahora: float) -> str:
        cabecera = b64url(json.dumps({"alg": "ES256", "kid": self.clave_id}, separators=(",", ":")).encode())
        cuerpo = b64url(json.dumps({"iss": self.equipo, "iat": int(ahora)}, separators=(",", ":")).encode())
        entrada = f"{cabecera}.{cuerpo}".encode("ascii")
        # `cryptography` firma en DER; un JWS ES256 lleva r y s en crudo, 32 bytes cada uno (RFC 7518 §3.4).
        r, s = decode_dss_signature(self._clave.sign(entrada, ec.ECDSA(hashes.SHA256())))
        return f"{cabecera}.{cuerpo}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
