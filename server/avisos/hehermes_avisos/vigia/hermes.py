"""El vigía leyendo el api_server de Hermes como lo lee la app, sin tocarlo: solo ``GET``, y solo rutas del contrato.

Dos maneras de llegar, a elegir en la configuración:

- por el **nginx del túnel** (``http://10.77.0.1``), que pone él el Bearer: el vigía no tiene la clave, y cuando cambia
  basta con ``hehermes-dispositivo clave``, como para la app;
- **directo** a ``127.0.0.1:8642``, con la clave leída de un fichero 0600.
"""

from __future__ import annotations

import http.client
import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from .. import comun

registro = logging.getLogger("vigia.hermes")

LIMITE_BANDEJA = 200


class ErrorHermes(Exception):
    def __init__(self, mensaje: str, estado: int | None = None):
        super().__init__(mensaje)
        self.estado = estado


class ClienteHermes:
    def __init__(self, base: str, clave: str | None = None, plazo: float = 15.0, abridor=None):
        self.base = base.rstrip("/")
        self._clave = clave
        self.plazo = plazo
        self._abridor = abridor or comun.abridor()

    def _get(self, ruta: str, consulta: dict | None = None) -> object:
        url = self.base + ruta + ("?" + urllib.parse.urlencode(consulta) if consulta else "")
        peticion = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
        if self._clave:
            peticion.add_header("Authorization", f"Bearer {self._clave}")
        try:
            with self._abridor.open(peticion, timeout=self.plazo) as respuesta:
                return json.loads(respuesta.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 401:
                raise ErrorHermes("Hermes rechaza la clave (401): el nginx del túnel no la pone o la del fichero no "
                                  "vale", 401) from None
            raise ErrorHermes(f"Hermes contestó {error.code} a GET {ruta}", error.code) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            # `HTTPException` es la respuesta cortada a medias (IncompleteRead, RemoteDisconnected): no es un OSError.
            razon = getattr(error, "reason", None) or type(error).__name__
            raise ErrorHermes(f"no se puede hablar con Hermes: {razon}") from None
        except ValueError:
            raise ErrorHermes("Hermes contestó algo que no es JSON") from None

    def sesiones(self) -> list:
        """La bandeja, la misma que pide la app: ``GET /api/sessions?source=api_server&limit=200``."""
        datos = self._get("/api/sessions", {"source": "api_server", "limit": LIMITE_BANDEJA})
        filas = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(filas, list):
            raise ErrorHermes("la bandeja de Hermes no trae «data»")
        return [f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"]]

    def mensajes(self, sesion: str, limite: int) -> list:
        """Las ``limite`` filas más recientes de una sesión, en orden de id (el orden fiable, contrato §7)."""
        datos = self._get(f"/api/sessions/{urllib.parse.quote(sesion, safe='')}/messages",
                          {"order": "latest", "limit": limite})
        filas = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(filas, list):
            raise ErrorHermes("los mensajes de Hermes no traen «data»")
        validas = [f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), int)]
        return sorted(validas, key=lambda f: f["id"])

    def turno(self, run_id: str) -> dict | None:
        """El estado de un run (``GET /v1/runs/{id}``), o ``None`` si Hermes ya no lo conoce (404)."""
        try:
            datos = self._get(f"/v1/runs/{urllib.parse.quote(run_id, safe='')}")
        except ErrorHermes as error:
            if error.estado == 404:
                return None
            raise
        if not isinstance(datos, dict):
            raise ErrorHermes("el estado del run no es un objeto")
        return datos
