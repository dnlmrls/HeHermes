"""La API del relé.

- ``POST /v1/avisos`` con ``Authorization: Bearer <credencial del vigía>``: manda un aviso ya cifrado.
- ``GET /v1/credencial`` con la misma cabecera: para que el vigía compruebe su credencial sin mandar nada.
- ``GET /v1/salud``: si el relé está vivo. No dice nada más.

Lo que contesta a un aviso, para que el vigía sepa qué hacer sin conocer los motivos de Apple:

====  ================================================================  ==========================
200   ``{"resultado": "enviado", "apns_id": …}``                          nada
410   ``{"resultado": "baja", "motivo": "Unregistered", "baja": true}``   dar de baja el token
429   límite del relé o de Apple, con ``Retry-After``                     reintentar más tarde
413   el payload pasa de 4 KB                                             nada (es un fallo suyo)
422   Apple rechaza el aviso por algo que no es el token                  nada (es un fallo suyo)
502   no se ha podido hablar con Apple, o el relé está mal configurado   reintentar más tarde
503   el relé está en marcha pero sin la clave de APNs                   reintentar más tarde
400   la petición no es válida (y por qué)                                nada (es un fallo suyo)
401   credencial desconocida                                              nada
====  ================================================================  ==========================
"""

from __future__ import annotations

import logging
import time

from ..comun import ErrorHTTP, ManejadorJSON, cola
from . import credenciales as modulo_credenciales
from .apns import ClienteAPNs
from .limites import Limitador, huella_de_token
from .validacion import validar

registro = logging.getLogger("rele")

# Motivos de Apple que no son del aviso sino del propio relé: la clave, el Key ID, el Team ID o el tema están mal. No
# se arreglan reintentando desde el vigía, pero tampoco son culpa suya: 502, y un error bien visible en el log.
MOTIVOS_DE_CONFIGURACION = frozenset({
    "BadCertificate", "BadCertificateEnvironment", "Forbidden", "InvalidProviderToken", "MissingProviderToken",
    "ExpiredProviderToken", "TooManyProviderTokenUpdates", "BadTopic", "MissingTopic", "TopicDisallowed",
    "UnrelatedKeyIdInToken", "BadEnvironmentKeyIdInToken", "BadPath", "MethodNotAllowed"})


class AppRele:
    """Con ``apns=None``, el relé está en marcha sin la clave de APNs: autentica igual, pero a cada aviso contesta 503
    (``sin_clave_apns``), y su salud lo dice."""

    def __init__(self, credenciales: dict, apns: ClienteAPNs | None, limitador: Limitador, reservas: list,
                 reloj=time.time):
        self.credenciales = credenciales
        self.apns = apns
        self.limitador = limitador
        self.reservas = reservas
        self.reloj = reloj

    def autenticar(self, cabecera: str | None):
        tipo, _, secreto = (cabecera or "").partition(" ")
        credencial = None
        if tipo.lower() == "bearer" and secreto.strip():
            credencial = modulo_credenciales.buscar(self.credenciales, secreto.strip())
        if credencial is None:
            raise ErrorHTTP(401, "credencial_invalida", "Credencial desconocida", {"WWW-Authenticate": "Bearer"})
        return credencial

    def avisar(self, credencial, peticion: dict) -> tuple:
        """Devuelve (estado, cuerpo, cabeceras)."""
        if self.apns is None:
            registro.warning("aviso de «%s»: sin la clave de APNs, no sale", credencial.nombre)
            return 503, {"resultado": "reintentable", "motivo": "sin_clave_apns"}, {"Retry-After": "60"}
        aviso = validar(peticion, self.reservas)
        clave_token = huella_de_token(aviso.token, aviso.entorno)
        destino = f"{cola(aviso.token)} ({aviso.entorno})"
        if self.limitador.de_baja(clave_token):
            registro.info("aviso → %s de «%s»: ya dado de baja, no se pregunta a Apple", destino, credencial.nombre)
            return 410, {"resultado": "baja", "motivo": "Unregistered", "baja": True}, {}
        espera = self.limitador.admitir(credencial.nombre, clave_token, credencial.por_minuto)
        if espera is not None:
            registro.warning("aviso → %s de «%s»: limitado (%.0f s)", destino, credencial.nombre, espera)
            return 429, {"resultado": "limitado", "motivo": "limite_del_rele"}, {"Retry-After": str(int(espera) + 1)}
        expiracion = int(self.reloj()) + aviso.caduca if aviso.caduca is not None else None
        inicio = time.monotonic()
        respuesta = self.apns.enviar(aviso.token, aviso.entorno, aviso.carga, aviso.prioridad, aviso.colapso,
                                     expiracion)
        estado, cuerpo, cabeceras = self._traducir(respuesta, clave_token)
        nivel = logging.INFO if estado == 200 else (logging.ERROR if cuerpo.get("resultado") == "configuracion"
                                                    else logging.WARNING)
        registro.log(nivel, "aviso → %s de «%s»: %s%s en %.0f ms", destino, credencial.nombre,
                     cuerpo["resultado"], f" ({respuesta.motivo})" if respuesta.motivo else "",
                     (time.monotonic() - inicio) * 1000)
        return estado, cuerpo, cabeceras

    def _traducir(self, respuesta, clave_token: str) -> tuple:
        if respuesta.estado == 200:
            return 200, {"resultado": "enviado", "apns_id": respuesta.apns_id}, {}
        if respuesta.baja:
            self.limitador.dar_de_baja(clave_token)
            return 410, {"resultado": "baja", "motivo": respuesta.motivo or "Unregistered", "baja": True}, {}
        if respuesta.motivo in MOTIVOS_DE_CONFIGURACION:
            # Antes que el 429: `TooManyProviderTokenUpdates` llega como 429, pero es el JWT del relé, no un iPhone que
            # recibe demasiado, y esperar desde el vigía no lo arregla.
            return 502, {"resultado": "configuracion", "motivo": respuesta.motivo}, {}
        if respuesta.estado == 429:
            # `TooManyRequests`: demasiados avisos seguidos al mismo iPhone, según Apple.
            return 429, {"resultado": "limitado", "motivo": respuesta.motivo or "TooManyRequests"}, {"Retry-After": "60"}
        if respuesta.estado == 413:
            return 413, {"resultado": "rechazado", "motivo": respuesta.motivo or "PayloadTooLarge"}, {}
        if respuesta.estado == 0 or respuesta.estado >= 500:
            return 502, {"resultado": "reintentable", "motivo": respuesta.motivo or str(respuesta.estado)}, {}
        if respuesta.estado in (403, 404, 405):
            return 502, {"resultado": "configuracion", "motivo": respuesta.motivo or str(respuesta.estado)}, {}
        return 422, {"resultado": "rechazado", "motivo": respuesta.motivo or str(respuesta.estado)}, {}


class ManejadorRele(ManejadorJSON):
    tope_cuerpo = 16 * 1024

    def nombre_registro(self) -> str:
        return "rele.api"

    def atender(self) -> None:
        app: AppRele = self.server.app
        ruta, metodo = self.ruta, self.command
        if ruta == "/v1/salud" and metodo == "GET":
            if app.apns is None:
                return self.enviar_json(503, {"estado": "sin_clave", "servicio": "rele"})
            return self.enviar_json(200, {"estado": "ok", "servicio": "rele"})
        if ruta == "/v1/credencial" and metodo == "GET":
            credencial = app.autenticar(self.headers.get("Authorization"))
            return self.enviar_json(200, {"credencial": credencial.nombre})
        if ruta == "/v1/avisos":
            if metodo != "POST":
                raise ErrorHTTP(405, "metodo_no_permitido", "Aquí solo vale POST", {"Allow": "POST"})
            credencial = app.autenticar(self.headers.get("Authorization"))
            estado, cuerpo, cabeceras = app.avisar(credencial, self.leer_json())
            return self.enviar_json(estado, cuerpo, cabeceras)
        raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
