"""El cliente de APNs: HTTP/2, una conexión por entorno que se reutiliza, y lo que contesta Apple sin adornos.

- ``POST https://api.push.apple.com/3/device/<token>`` (producción) o ``api.sandbox.push.apple.com`` (pruebas): lo
  decide el entorno que dijo la app al darse de alta, así que nadie tiene que tocar nada al publicar en TestFlight.
- ``apns-topic`` = el bundle de la app, ``apns-push-type: alert``, la prioridad que pida el vigía, y
  ``apns-collapse-id``/``apns-expiration`` si los trae.
- Solo HTTP/2 (``http1=False``): APNs no habla otra cosa, y si algún día fallara la negociación es mejor un error claro
  que una petición HTTP/1.1 que Apple no entendería.
- Los certificados son los del sistema: se actualizan con el sistema, no con una dependencia más.

**Un plazo para todo el aviso, no por intento.** El vigía espera 8 s al relé, y la app 10 s al vigía; si el relé
tardara más que el vigía (antes podía llegar a unos 25 s, con el reintento), el vigía daría el aviso por perdido y lo
repetiría aunque hubiera llegado, y el aviso de prueba diría «error 502» con el aviso ya en el iPhone. Así que los
intentos se reparten ``plazo`` (6 s de serie) y cada uno tiene solo lo que queda.

La conexión se reutiliza mientras haya avisos seguidos (una ráfaga, varios iPhone, un reintento) y se cierra al minuto
de estar parada. Con el ritmo de un usuario, lo normal es una conexión por aviso, y Apple solo trata como abuso abrir y
cerrar muy deprisa. Mantenerla abierta horas pediría vigilarla con PING de HTTP/2, que ``httpx`` no manda: una conexión
medio muerta dejaría el aviso esperando hasta el plazo. Eso es para cuando sean miles (README).
"""

from __future__ import annotations

import json
import ssl
import time
from dataclasses import dataclass

import httpx

from .firmante import FirmanteAPNs

BASES = {"sandbox": "https://api.sandbox.push.apple.com", "production": "https://api.push.apple.com"}
PLAZO = 6.0
# Lo que se deja para abrir la conexión (TCP y TLS) dentro de un intento, y lo mínimo que tiene que quedar para que
# merezca la pena otro intento.
PLAZO_DE_CONEXION = 3.0
MINIMO_POR_INTENTO = 1.0

# Lo que Apple dice cuando un token ya no vale para esta app: hay que dejar de mandarle (y el vigía lo da de baja).
# `BadDeviceToken` es también lo que contesta a un token de pruebas mandado a producción, o al revés: tampoco va a
# valer nunca en ese entorno.
MOTIVOS_DE_BAJA = frozenset({"BadDeviceToken", "Unregistered", "ExpiredToken", "DeviceTokenNotForTopic"})


@dataclass(frozen=True)
class RespuestaAPNs:
    # El `:status` de Apple, o 0 si no se llegó a hablar con Apple.
    estado: int
    motivo: str = ""
    apns_id: str = ""

    @property
    def baja(self) -> bool:
        return self.estado == 410 or self.motivo in MOTIVOS_DE_BAJA


def cliente_http2(plazo: float = PLAZO, verify=None) -> httpx.Client:
    """El cliente con el que el relé habla con Apple. Está aparte para que la prueba de HTTP/2 use este mismo, y no uno
    que se le parezca. (httpx ofrece «http/1.1» y «h2» en el ALPN aunque solo se le deje HTTP/2, pero con
    ``http1=False`` habla HTTP/2 elija lo que elija el otro lado: lo fija ``test_rele_http2``.)"""
    return httpx.Client(
        http1=False, http2=True, verify=ssl.create_default_context() if verify is None else verify, trust_env=False,
        timeout=httpx.Timeout(plazo, connect=min(plazo, PLAZO_DE_CONEXION)),
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4, keepalive_expiry=60.0))


class ClienteAPNs:
    def __init__(self, firmante: FirmanteAPNs, tema: str, bases: dict | None = None, cliente: httpx.Client | None = None,
                 plazo: float = PLAZO, reloj=time.monotonic):
        self.firmante = firmante
        self.tema = tema
        self.bases = dict(bases or BASES)
        self.plazo = plazo
        self.reloj = reloj
        self._cliente = cliente or cliente_http2(plazo)

    def cerrar(self) -> None:
        self._cliente.close()

    def enviar(self, token: str, entorno: str, carga: bytes, prioridad: int, colapso: str | None = None,
               expiracion: int | None = None) -> RespuestaAPNs:
        limite = self.reloj() + self.plazo
        url = f"{self.bases[entorno]}/3/device/{token}"
        cabeceras = {"apns-topic": self.tema, "apns-push-type": "alert", "apns-priority": str(prioridad),
                     "content-type": "application/json"}
        if colapso:
            cabeceras["apns-collapse-id"] = colapso
        if expiracion is not None:
            cabeceras["apns-expiration"] = str(expiracion)
        ultima = RespuestaAPNs(0, "sin tiempo para hablar con Apple")
        for intento in (1, 2):
            restante = limite - self.reloj()
            if restante < MINIMO_POR_INTENTO:
                return ultima
            conexion = min(PLAZO_DE_CONEXION, restante / 2)
            tiempos = httpx.Timeout(restante - conexion, connect=conexion)
            jwt = self.firmante.token()
            cabeceras["authorization"] = f"bearer {jwt}"
            try:
                respuesta = self._cliente.post(url, content=carga, headers=cabeceras, timeout=tiempos)
            except httpx.InvalidURL:
                # La validación ya no deja pasar un token así; si alguna vez pasara, no es algo que se arregle
                # repitiendo, y una excepción sin capturar era un 500 con traza en cada aviso.
                return RespuestaAPNs(400, "InvalidURL")
            except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError) as error:
                # Una conexión que Apple cerró mientras estaba parada, o que no se pudo abrir: se prueba otra vez si
                # queda tiempo. Si el primer intento sí llegó, el segundo lleva el mismo `apns-collapse-id` y el iPhone
                # enseña uno.
                ultima = RespuestaAPNs(0, f"sin conexión con Apple ({type(error).__name__})")
                continue
            except httpx.HTTPError as error:
                return RespuestaAPNs(0, f"sin respuesta de Apple ({type(error).__name__})")
            motivo = _motivo(respuesta)
            ultima = RespuestaAPNs(respuesta.status_code, motivo, respuesta.headers.get("apns-id", ""))
            if (respuesta.status_code == 403 and motivo == "ExpiredProviderToken" and intento == 1
                    and self.firmante.renovar_ya(jwt)):
                continue
            return ultima
        return ultima


def _motivo(respuesta: httpx.Response) -> str:
    if respuesta.status_code == 200 or not respuesta.content:
        return ""
    try:
        cuerpo = json.loads(respuesta.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return ""
    motivo = cuerpo.get("reason") if isinstance(cuerpo, dict) else None
    return motivo if isinstance(motivo, str) else ""
