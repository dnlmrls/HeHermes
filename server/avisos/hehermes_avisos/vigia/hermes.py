"""El vigía leyendo el api_server de Hermes como lo lee la app: ``GET`` de rutas del contrato y **dos escrituras**: el
turno que contesta la entrega de un subagente (``lanzar_continuacion``, con el texto fijo de la app y su misma
``Idempotency-Key``; por qué, en ``entregas``) y, desde la 1.6.0, la personalidad de un agente nuevo, que escribe el
principal por ``/v1/chat/completions`` con un mensaje de sistema fijo (``completar``, contrato §18.7). Nada más: el
vigía no escribe lo que quiere, ni en otra ruta.

**Cada agente es un perfil de Hermes** (contrato §18): su cliente lleva ``perfil``, con el que todas sus rutas van bajo
``/p/<perfil>/`` y con la clave de ese perfil. El principal, sin prefijo.

Dos maneras de llegar, a elegir en la configuración:

- por el **nginx del túnel** (``http://10.77.0.1``), que pone él el Bearer: el vigía no tiene la clave, y cuando cambia
  basta con ``hehermes-dispositivo clave``, como para la app;
- **directo** a ``127.0.0.1:8642``, con la clave leída de un fichero 0600.
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request

from .. import comun
from . import deteccion

registro = logging.getLogger("vigia.hermes")

LIMITE_BANDEJA = 200
#: El de un agente (contrato §18): minúsculas y cifras, hasta 24. `default` es el principal, sin prefijo.
PATRON_PERFIL = re.compile(r"[a-z0-9]{1,24}")
PRINCIPAL = "default"


class ErrorHermes(Exception):
    def __init__(self, mensaje: str, estado: int | None = None, codigo: str | None = None):
        super().__init__(mensaje)
        self.estado = estado
        # El `code` del envoltorio de error de Hermes (contrato §8), si lo trae: `idempotency_key_conflict`…
        self.codigo = codigo


def _codigo_de_error(error: urllib.error.HTTPError) -> str | None:
    try:
        cuerpo = json.loads(error.read(65536).decode("utf-8"))
    except (OSError, ValueError, http.client.HTTPException):
        return None
    detalle = cuerpo.get("error") if isinstance(cuerpo, dict) else None
    codigo = detalle.get("code") if isinstance(detalle, dict) else None
    return codigo if isinstance(codigo, str) else None


class ClienteHermes:
    def __init__(self, base: str, clave: str | None = None, plazo: float = 15.0, abridor=None,
                 perfil: str | None = None):
        if perfil is not None and not PATRON_PERFIL.fullmatch(perfil):
            raise ValueError("perfil sin la forma de uno de Hermes: %r" % (perfil,))
        self.base = base.rstrip("/")
        self._clave = clave
        self.plazo = plazo
        self._abridor = abridor or comun.abridor()
        #: El perfil de Hermes de este cliente (`default`, el principal): el de cada aviso que sale de lo que lee.
        self.perfil = perfil or PRINCIPAL
        self._prefijo = "" if self.perfil == PRINCIPAL else "/p/" + self.perfil

    def _get(self, ruta: str, consulta: dict | None = None, plazo: float | None = None) -> object:
        url = self.base + self._prefijo + ruta + ("?" + urllib.parse.urlencode(consulta) if consulta else "")
        peticion = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
        if self._clave:
            peticion.add_header("Authorization", f"Bearer {self._clave}")
        try:
            with self._abridor.open(peticion, timeout=self.plazo if plazo is None else plazo) as respuesta:
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

    def salud(self, plazo: float = 3.0) -> str | None:
        """``GET /health`` (sin clave, la única ruta que no la pide; se manda igual): si contesta, con su versión
        (``{"status": "ok", "platform": "hermes-agent", "version": "0.21.3"}``), o ``None`` si no la dice con su forma.
        Si no contesta, ``ErrorHermes``. Para Ajustes › Tu servidor (``servidor.py``)."""
        datos = self._get("/health", plazo=plazo)
        version = datos.get("version") if isinstance(datos, dict) else None
        return version if isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}", version) \
            else None

    def sesiones(self) -> list:
        """La bandeja, la misma que pide la app: ``GET /api/sessions?source=api_server&limit=200``."""
        datos = self._get("/api/sessions", {"source": "api_server", "limit": LIMITE_BANDEJA})
        filas = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(filas, list):
            raise ErrorHermes("la bandeja de Hermes no trae «data»")
        return [f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"]]

    def sesiones_con_hijas(self) -> list:
        """La primera página de todas las sesiones, con las de los subagentes y su ``parent_session_id``:
        ``GET /api/sessions?include_children=true&limit=200``. Para saber de qué conversación es lo que hace un subagente
        (``exportaciones.atribuir``)."""
        datos = self._get("/api/sessions", {"include_children": "true", "limit": LIMITE_BANDEJA})
        filas = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(filas, list):
            raise ErrorHermes("la lista de sesiones de Hermes no trae «data»")
        return [f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"]]

    def mensajes(self, sesion: str, limite: int, desde: int = 0, compactadas: bool = False) -> list:
        """Las ``limite`` filas más recientes de una sesión, en orden de id (el orden fiable, contrato §7), saltándose las
        ``desde`` más recientes. Con ``compactadas``, de la conversación entera aunque Hermes la haya compactado
        (``include_compacted=true``, contrato §7): sin ello, lo archivado no sale. Un Hermes que no lo conozca no lo
        mira."""
        consulta = {"order": "latest", "limit": limite}
        if desde:
            consulta["offset"] = desde
        if compactadas:
            consulta["include_compacted"] = "true"
        datos = self._get(f"/api/sessions/{urllib.parse.quote(sesion, safe='')}/messages", consulta)
        filas = datos.get("data") if isinstance(datos, dict) else None
        if not isinstance(filas, list):
            raise ErrorHermes("los mensajes de Hermes no traen «data»")
        validas = [f for f in filas if isinstance(f, dict) and isinstance(f.get("id"), int)]
        return sorted(validas, key=lambda f: f["id"])

    def lanzar_continuacion(self, sesion: str, clave: str, texto: str = deteccion.TEXTO_CONTINUAR) -> str:
        """``POST /v1/runs`` con el turno de continuación de la app (``texto``: ``deteccion.TEXTO_CONTINUAR`` o, con un
        iPhone de antes dado de alta, la de antes, ``entregas.texto_de_la_continuacion``) en ``sesion`` y la
        ``Idempotency-Key`` ``clave``. Devuelve el ``run_id``.

        El cuerpo es siempre el mismo para la misma clave: un reintento cuyo primer intento sí llegó da el mismo run
        (``replayed``), no otro turno. No lleva las instrucciones ni el esfuerzo de la conversación, que solo tiene el
        iPhone: si la app lanza la suya con la misma clave, el servidor contesta 409 y sigue habiendo un solo turno. Lo
        mismo si entre dos intentos cambia la frase (un iPhone que se actualiza justo entonces): 409, y el vigía lo da
        por lanzado."""
        cuerpo = json.dumps({"input": texto, "session_id": sesion}, ensure_ascii=False,
                            sort_keys=True).encode("utf-8")
        datos = self._post("/v1/runs", cuerpo, {"Idempotency-Key": clave}, self.plazo)
        run_id = datos.get("run_id") if isinstance(datos, dict) else None
        if not isinstance(run_id, str) or not run_id:
            raise ErrorHermes("Hermes aceptó el turno sin decir su run_id")
        return run_id

    def _post(self, ruta: str, cuerpo: bytes, cabeceras: dict, plazo: float) -> object:
        peticion = urllib.request.Request(self.base + self._prefijo + ruta, data=cuerpo, method="POST",
                                          headers=dict({"Accept": "application/json",
                                                        "Content-Type": "application/json"}, **cabeceras))
        if self._clave:
            peticion.add_header("Authorization", f"Bearer {self._clave}")
        try:
            with self._abridor.open(peticion, timeout=plazo) as respuesta:
                return json.loads(respuesta.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            codigo = _codigo_de_error(error)
            error.close()
            raise ErrorHermes(f"Hermes contestó {error.code} ({codigo or 'sin código'}) a POST {ruta}", error.code,
                              codigo) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            razon = getattr(error, "reason", None) or type(error).__name__
            raise ErrorHermes(f"no se puede hablar con Hermes: {razon}") from None
        except ValueError:
            raise ErrorHermes("Hermes contestó algo que no es JSON") from None

    def completar(self, sistema: str, texto: str, plazo: float) -> str:
        """``POST /v1/chat/completions`` con un mensaje de sistema y uno del usuario, sin sesión ni streaming: lo que
        escribe el modelo de Hermes. Para la personalidad de un agente nuevo (contrato §18.7). ``ErrorHermes`` si no
        contesta o no da un texto."""
        cuerpo = json.dumps({"model": "hermes-agent", "stream": False,
                             "messages": [{"role": "system", "content": sistema}, {"role": "user", "content": texto}]},
                            ensure_ascii=False).encode("utf-8")
        datos = self._post("/v1/chat/completions", cuerpo, {}, plazo)
        try:
            contenido = datos["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ErrorHermes("Hermes no ha dado el texto de la respuesta") from None
        if not isinstance(contenido, str):
            raise ErrorHermes("Hermes no ha dado el texto de la respuesta")
        return contenido

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
