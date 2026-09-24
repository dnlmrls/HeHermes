"""Mandar un aviso a un iPhone: cifrarlo con su clave, pasárselo al relé y hacer caso de lo que conteste.

Lo único que el relé puede pedir al vigía es que **dé de baja un token** (Apple dice que ya no vale: la app se borró, o
el token es de otro entorno). Lo demás son fallos: unos se arreglan esperando (el relé reiniciándose, Apple caída) y se
reintentan desde el bucle; otros no (un aviso que el relé rechaza) y solo se apuntan.
"""

from __future__ import annotations

import http.client as http_client
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass

from .. import comun
from ..comun import cola
from . import avisos
from .almacen import Almacen, Dispositivo

registro = logging.getLogger("vigia.envio")

ENVIADO = "enviado"
BAJA = "baja"
LIMITADO = "limitado"
RECHAZADO = "rechazado"
REINTENTABLE = "reintentable"


@dataclass(frozen=True)
class Resultado:
    tipo: str
    motivo: str = ""
    # Lo que pide esperar el relé antes de volver a intentarlo (Retry-After), si lo dice.
    esperar: float | None = None


class ClienteRele:
    """``POST /v1/avisos`` con la credencial de este vigía. Todo lo que no sea una respuesta del relé es reintentable."""

    def __init__(self, url: str, credencial: str, plazo: float = 8.0, abridor=None):
        self.url = url
        self._credencial = credencial
        self.plazo = plazo
        self._abridor = abridor or comun.abridor()

    def enviar(self, peticion: dict) -> Resultado:
        cuerpo = json.dumps(peticion, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        solicitud = urllib.request.Request(self.url, data=cuerpo, method="POST",
                                           headers={"Content-Type": "application/json",
                                                    "Authorization": f"Bearer {self._credencial}"})
        try:
            with self._abridor.open(solicitud, timeout=self.plazo) as respuesta:
                estado, datos, cabeceras = respuesta.status, respuesta.read(), respuesta.headers
        except urllib.error.HTTPError as error:
            estado, cabeceras = error.code, error.headers
            try:
                datos = error.read()
            except (OSError, http_client.HTTPException):
                datos = b""
            error.close()
        except (urllib.error.URLError, OSError, http_client.HTTPException) as error:
            # Sin respuesta entera no se sabe si el aviso salió: se reintenta, y si salió, el colapso lo deja en uno.
            razon = getattr(error, "reason", None) or type(error).__name__
            return Resultado(REINTENTABLE, f"el relé no contesta: {razon}")
        return self._traducir(estado, datos, cabeceras)

    @staticmethod
    def _traducir(estado: int, datos: bytes, cabeceras) -> Resultado:
        try:
            respuesta = json.loads(datos.decode("utf-8")) if datos else {}
        except (UnicodeDecodeError, ValueError):
            respuesta = {}
        if not isinstance(respuesta, dict):
            respuesta = {}
        error = respuesta.get("error")
        motivo = str(respuesta.get("motivo") or (error.get("code") if isinstance(error, dict) else None) or estado)
        if 200 <= estado < 300:
            return Resultado(ENVIADO)
        if respuesta.get("baja") is True:
            return Resultado(BAJA, motivo)
        if estado == 429:
            try:
                esperar = float(cabeceras.get("Retry-After") or 0) or None
            except (TypeError, ValueError):
                esperar = None
            return Resultado(LIMITADO, motivo, esperar)
        if estado >= 500:
            return Resultado(REINTENTABLE, motivo)
        return Resultado(RECHAZADO, motivo)


class Mensajero:
    """Lo que comparten el bucle y el aviso de prueba: armar la petición, mandarla y dar de baja lo que haya muerto."""

    def __init__(self, almacen: Almacen, rele: ClienteRele):
        self.almacen = almacen
        self.rele = rele

    def enviar(self, aviso: avisos.Aviso, dispositivo: Dispositivo, peticion: dict | None = None) -> Resultado:
        """Manda ``aviso`` a ``dispositivo``. ``peticion``, si se da, es la ya armada de un intento anterior: un
        reintento repite el mismo sobre en vez de cifrar otro, así que si el primero sí llegó, colapsa con él."""
        peticion = peticion or avisos.peticion_al_rele(aviso, dispositivo)
        resultado = self.rele.enviar(peticion)
        donde = f"{cola(dispositivo.token)} ({dispositivo.entorno})"
        if resultado.tipo == ENVIADO:
            registro.info("aviso de %s → %s: enviado", aviso.tipo, donde)
        elif resultado.tipo == BAJA:
            self.almacen.borrar_dispositivo(dispositivo.token)
            registro.warning("aviso de %s → %s: Apple dice que el token ya no vale (%s); dado de baja",
                             aviso.tipo, donde, resultado.motivo)
        else:
            registro.warning("aviso de %s → %s: %s (%s)", aviso.tipo, donde, resultado.tipo, resultado.motivo)
        return resultado
