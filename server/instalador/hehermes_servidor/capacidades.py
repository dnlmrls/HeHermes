"""Lo que la app necesita del api_server de Hermes, comprobado antes de dar el QR o el enlace del canje (desde la 0.10.4).

La app solo se ha probado contra el Hermes de Daniel (el `main` del 2026-09-17, que dice «0.21.3»), y un probador puede
tener uno de hace meses. Si a su Hermes le falta una ruta que la app usa, el alta sale bien y la app falla después de
formas confusas: lo primero que pregunta al conectar, `GET /api/model/options`, da un 404 en un Hermes anterior a la
0.19.1. Por eso el instalador lo mira antes y, si falta algo que la app necesita, se para con
`hehermes-error:hermes-antiguo`; si lo que falta la app lo puede no tener, lo avisa y sigue.

**Cómo se mira, sin efectos.** Con `TRACE` en la ruta de cada cosa, con un id que no existe y sin la clave. El api_server
es aiohttp, y aiohttp contesta a un método que una ruta no tiene con un 405 cuyo `Allow` lista los métodos que sí
tiene, y a una ruta que no existe con su 404 de siempre, sin llegar a ningún manejador ni a ninguna comprobación de la
clave (comprobado con aiohttp 3.13 y los middlewares de Hermes de la 0.8.0 a `main`: CORS, el tope del cuerpo, las
cabeceras de seguridad y el prefijo del perfil). Así se sabe si están `POST /v1/runs` o `PATCH /api/sessions/{id}` sin
lanzar ningún turno ni crear o tocar ninguna sesión: no se llama a ningún manejador. `OPTIONS` no sirve (el middleware de
CORS de Hermes lo contesta él, con un 403), y `TRACE` es un método seguro (RFC 9110, §9.2.1). Antes de fiarse, se
calibra con `/health`, que acaba de contestar 200: si `TRACE /health` no da un 405 con `GET`, la sonda no vale en ese
servidor y solo queda la versión.

**Lo que no se puede mirar así:** los eventos del SSE y sus campos (el `delegation_id` de `subagent.start`), la
idempotencia de `POST /v1/runs`, el keepalive… Para eso está la versión que dice `/health` (o la de su código, con la API
apagada), comparada con la historia de Hermes: de cada capacidad se sabe en qué versión llegó (las etiquetas de
`NousResearch/hermes-agent`, leídas el 2026-10-01: la tabla de rutas de `gateway/platforms/api_server*.py` de cada una).
"""

from __future__ import annotations

import json
import re

#: El id que se pone en las rutas con uno: no es ni un run (`run_<32hex>`) ni una sesión (`api_<epoch>_<8hex>`). Con
#: `TRACE` da igual, porque no se busca nada, pero así ni en un registro se confunde con uno de verdad.
SONDA = "hehermes-sonda"


class Capacidad:
    __slots__ = ("clave", "metodo", "ruta", "obligatoria", "que", "desde")

    def __init__(self, clave, metodo, ruta, obligatoria, que, desde):
        self.clave, self.metodo, self.ruta, self.obligatoria, self.que, self.desde = (clave, metodo, ruta, obligatoria,
                                                                                       que, desde)

    @property
    def nombre(self) -> str:
        return "%s %s" % (self.metodo, self.ruta)


#: Lo que usa la app (server/API-CONTRACT.md, §1), con la versión de Hermes desde la que existe. Obligatoria: sin ella la
#: app falla de forma confusa. Las demás, la app las puede no tener (una pantalla dice que no están, o un botón falla
#: solo).
CAPACIDADES = (
    Capacidad("bandeja", "GET", "/api/sessions", True, "la bandeja de conversaciones", "0.15.0"),
    Capacidad("nueva", "POST", "/api/sessions", True, "empezar una conversación", "0.15.0"),
    Capacidad("historial", "GET", "/api/sessions/{id}/messages", True, "el historial de una conversación", "0.15.0"),
    Capacidad("ficha", "PATCH", "/api/sessions/{id}", True, "fijar, archivar y renombrar una conversación", "0.15.0"),
    Capacidad("enviar", "POST", "/v1/runs", True, "mandarle un mensaje", "0.8.0"),
    Capacidad("eventos", "GET", "/v1/runs/{id}/events", True, "ver la respuesta mientras la escribe", "0.8.0"),
    Capacidad("estado", "GET", "/v1/runs/{id}", True, "recuperar una respuesta si se corta la conexión", "0.12.0"),
    Capacidad("parar", "POST", "/v1/runs/{id}/stop", True, "pararlo a media respuesta", "0.12.0"),
    Capacidad("aprobar", "POST", "/v1/runs/{id}/approval", True, "aprobar o denegar una orden", "0.14.0"),
    Capacidad("modelo", "GET", "/api/model/options", True, "decir qué modelo usa (lo primero que pregunta la app al "
                                                           "conectar)", "0.19.1"),
    Capacidad("desviar", "POST", "/v1/runs/{id}/steer", True, "escribirle mientras trabaja", "0.20.1"),
    Capacidad("consumo", "GET", "/api/sessions/{id}", False, "el consumo de cada conversación, en su ficha", "0.15.0"),
    Capacidad("borrar", "DELETE", "/api/sessions/{id}", False, "«Eliminar también de Hermes»", "0.15.0"),
    Capacidad("tareas", "GET", "/api/jobs", False, "las tareas programadas", "0.4.0"),
)
POR_CLAVE = {c.clave: c for c in CAPACIDADES}

#: La mínima: la primera versión publicada con todo lo obligatorio (`POST /v1/runs/{id}/steer`, en la v0.20.1, la etiqueta
#: v2026.8.13). La comprueba `test_capacidades` contra la tabla de arriba.
MINIMA = (0, 20, 1)
#: Desde aquí, lo que la app usa y no se ve en las rutas: la idempotencia duradera de `POST /v1/runs` (`Idempotency-Key`,
#: el 409 `idempotency_key_conflict`, en la 0.21.0) y los subagentes en segundo plano (`delegation_id`, la 0.21.1). Con
#: una anterior la app funciona, pero un reintento puede llegarle dos veces y «Usa subagentes» espera a que acaben.
RECOMENDADA = (0, 21, 1)
_IDEMPOTENCIA = (0, 21, 0)

_VERSION = re.compile(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,6})")
#: Lo que se enseña de lo que dice Hermes de su versión: no se pinta nada que no sea de una versión.
_LEGIBLE = re.compile(r"[^0-9A-Za-z.+_-]")


def version(texto) -> tuple | None:
    """(mayor, menor, parche) de lo que dice Hermes («0.21.3», «0.21.4+canary.20260925T065930Z»), o None si no lo
    dice. El `main` de ahora dice «0.0.0» (o «unknown») si no sabe su versión: eso es no saberla."""
    if not isinstance(texto, str):
        return None
    hallada = _VERSION.match(texto.strip())
    if not hallada:
        return None
    numeros = tuple(int(x) for x in hallada.groups())
    return None if numeros == (0, 0, 0) else numeros


def texto_de(numeros) -> str:
    return ".".join(str(n) for n in numeros)


def legible(texto) -> str | None:
    """Lo que dijo Hermes, sin nada que no pueda ir en una versión (va al terminal y al chat)."""
    if not isinstance(texto, str):
        return None
    limpio = _LEGIBLE.sub("", texto.strip())[:40]
    return limpio or None


def version_de_health(cuerpo) -> str | None:
    """`{"status": "ok", "platform": "hermes-agent", "version": "0.21.3"}` (desde la 0.4.0)."""
    try:
        datos = json.loads(cuerpo or b"")
    except (ValueError, UnicodeDecodeError):
        return None
    return legible(datos.get("version")) if isinstance(datos, dict) else None


# MARK: La sonda


class Sondeo:
    """Lo que se sabe del api_server: su versión (lo que dice, y de dónde sale) y qué capacidades tiene, no tiene o no se
    sabe."""

    def __init__(self, version_texto=None, de_donde="su /health"):
        self.version_texto = version_texto
        self.de_donde = de_donde
        self.calibrada = False
        self.presentes, self.ausentes, self.sin_saber = set(), set(), set()

    @property
    def version(self):
        return version(self.version_texto)


def _permitidos(estado, cabeceras) -> set | None:
    """Los métodos del `Allow` de un 405, o None si la respuesta no es esa."""
    if estado != 405:
        return None
    allow = next((v for k, v in (cabeceras or {}).items() if k.lower() == "allow"), None)
    if allow is None:
        return None
    return {m.strip().upper() for m in allow.split(",") if m.strip()}


def ruta_de_sonda(ruta: str) -> str:
    return ruta.replace("{id}", SONDA)


def sondear(sis, puerto: int, version_texto=None) -> Sondeo:
    """`TRACE` a `/health` (la calibración) y a la ruta de cada capacidad, una vez por ruta. Sin la clave ni ningún
    cuerpo, y solo a 127.0.0.1."""
    sondeo = Sondeo(version_texto)
    base = "http://127.0.0.1:%d" % int(puerto)
    estado, cabeceras, _ = sis.pedir("TRACE", base + "/health")
    permitidos = _permitidos(estado, cabeceras)
    sondeo.calibrada = permitidos is not None and "GET" in permitidos
    if not sondeo.calibrada:
        sondeo.sin_saber = {c.clave for c in CAPACIDADES}
        return sondeo
    vistas = {}
    for capacidad in CAPACIDADES:
        ruta = ruta_de_sonda(capacidad.ruta)
        if ruta not in vistas:
            estado, cabeceras, _ = sis.pedir("TRACE", base + ruta)
            vistas[ruta] = (estado, _permitidos(estado, cabeceras))
        estado, permitidos = vistas[ruta]
        if permitidos is not None:
            (sondeo.presentes if capacidad.metodo in permitidos else sondeo.ausentes).add(capacidad.clave)
        elif estado == 404:
            # La ruta no existe: con TRACE ningún manejador busca nada, así que el 404 es el del enrutador de aiohttp.
            sondeo.ausentes.add(capacidad.clave)
        else:
            sondeo.sin_saber.add(capacidad.clave)
    return sondeo


# MARK: Qué se dice


def como_actualizar(usuario=None, gestor=None) -> str:
    """Cómo se actualiza Hermes: `hermes update` (o su `/update` del chat, que también lo reinicia); en un contenedor, su
    imagen nueva (lo de dentro se pierde al recrearlo)."""
    from .gestor import CONTENEDORES
    if gestor is not None and gestor.tipo in CONTENEDORES:
        return "va en %s: con la imagen nueva de Hermes" % gestor.describir()
    return "«hermes update» en el servidor, como %s, o «/update» en su chat" % (usuario or "el usuario que lo corre")


def _de_quien(sondeo) -> str:
    if sondeo.version_texto and sondeo.version is not None:
        return "la %s, según %s" % (sondeo.version_texto, sondeo.de_donde)
    if sondeo.version_texto:
        return "dice ser la «%s», según %s" % (sondeo.version_texto, sondeo.de_donde)
    return "no dice su versión"


def _lista(capacidades) -> str:
    return "; ".join("%s (%s)" % (c.que, c.nombre) for c in capacidades)


def detalle(sondeo, faltan) -> str:
    """Lo mismo que el texto, para la app: `version=<la de Hermes o ?> minima=<la de HeHermes> falta=<claves>`."""
    return "version=%s minima=%s falta=%s" % (sondeo.version_texto or "?", texto_de(MINIMA),
                                              ",".join(c.clave for c in faltan) or "?")


def faltan_por_version(numeros) -> list:
    """Las obligatorias que llegaron después de esa versión."""
    return [c for c in CAPACIDADES if c.obligatoria and version(c.desde) > numeros]


def veredicto(sondeo, usuario=None, gestor=None) -> tuple:
    """(bloqueos, avisos) de un sondeo. Un bloqueo es (texto, detalle para la app). Lo que la sonda dice que falta manda;
    si la sonda no vale aquí, la versión; y lo que no se ve en las rutas, por la versión, se avisa."""
    actualizar = como_actualizar(usuario, gestor)
    numeros = sondeo.version
    bloqueos, avisos = [], []
    faltan = [c for c in CAPACIDADES if c.obligatoria and c.clave in sondeo.ausentes]
    if not faltan and not sondeo.calibrada and numeros is not None and numeros < MINIMA:
        faltan = faltan_por_version(numeros)
    if faltan:
        bloqueos.append(("Tu Hermes (%s) no tiene lo que la app necesita: %s. HeHermes necesita Hermes %s o más "
                         "nuevo. Actualízalo (%s) y vuelve a lanzarme; no he tocado nada"
                         % (_de_quien(sondeo), _lista(faltan), texto_de(MINIMA), actualizar),
                         detalle(sondeo, faltan)))
        return bloqueos, avisos
    opcionales = [c for c in CAPACIDADES if not c.obligatoria and c.clave in sondeo.ausentes]
    if opcionales:
        avisos.append("A tu Hermes (%s) le falta %s: la app funciona, pero eso no lo tendrás. Se arregla "
                      "actualizándolo (%s)" % (_de_quien(sondeo), _lista(opcionales), actualizar))
    if numeros is not None and numeros < RECOMENDADA:
        que = ["lleva a los subagentes en segundo plano (con «Usa subagentes», el turno espera a que acaben)"]
        if numeros < _IDEMPOTENCIA:
            que.append("reconoce un mensaje repetido (si la app tiene que reintentar uno, le puede llegar dos veces)")
        avisos.append("Tu Hermes es la %s: la app funciona, pero hasta la %s Hermes no %s. Actualízalo cuando puedas "
                      "(%s)" % (sondeo.version_texto, texto_de(RECOMENDADA), " ni ".join(que), actualizar))
    if not sondeo.calibrada and numeros is None:
        avisos.append("No he podido comprobar qué sabe hacer tu Hermes (%s): su api_server no contesta a mi sonda como "
                      "el de Hermes, y no sé su versión. Si la app no le habla bien, actualízalo (%s)"
                      % (_de_quien(sondeo), actualizar))
    return bloqueos, avisos


# MARK: Con la API apagada: la versión de su código


def _ancestros(ruta: str, niveles: int = 4) -> list:
    salida = []
    for _ in range(niveles):
        ruta = ruta.rsplit("/", 1)[0]
        if not ruta:
            break
        salida.append(ruta)
    return salida


_VERSION_PYPROJECT = re.compile(r'^version\s*=\s*"([^"]{1,64})"', re.M)
_VERSION_INIT = re.compile(r'^__version__\s*=\s*"([^"]{1,64})"', re.M)
_VERSION_METADATA = re.compile(r"^Version:\s*(\S{1,64})\s*$", re.M)


def _version_en(sis, carpeta) -> str | None:
    """La versión del código de Hermes de `carpeta` (la de su checkout: `hermes_cli/` y `pyproject.toml`), por este
    orden: el sello de instalación del `main` de ahora (`install-stamp.json`, `baseVersion`), el `__version__` de
    `hermes_cli/__init__.py` (así hasta la 0.21) y el `version` de su `pyproject.toml` (el `main` de ahora dice 0.0.0)."""
    if not sis.existe(carpeta + "/hermes_cli/__init__.py"):
        return None
    try:
        sello = json.loads(sis.leer_texto(carpeta + "/install-stamp.json") or "null")
    except ValueError:
        sello = None
    candidatas = [sello.get("baseVersion") if isinstance(sello, dict) else None]
    for fichero, patron in (("/hermes_cli/__init__.py", _VERSION_INIT), ("/pyproject.toml", _VERSION_PYPROJECT)):
        hallada = patron.search(sis.leer_texto(carpeta + fichero) or "")
        candidatas.append(hallada.group(1) if hallada else None)
    return next((legible(c) for c in candidatas if version(c) is not None), None)


def _version_del_venv(sis, venv) -> str | None:
    """Instalado como paquete en un venv: su `site-packages` (el código, o el `.dist-info` de `hermes-agent`)."""
    for python in sis.listar(venv + "/lib"):
        if not python.startswith("python3"):
            continue
        paquetes = "%s/lib/%s/site-packages" % (venv, python)
        hallada = _version_en(sis, paquetes)
        if hallada:
            return hallada
        for nombre in sis.listar(paquetes):
            if nombre.startswith(("hermes_agent-", "hermes-agent-")) and nombre.endswith(".dist-info"):
                datos = _VERSION_METADATA.search(sis.leer_texto("%s/%s/METADATA" % (paquetes, nombre)) or "")
                if datos and version(datos.group(1)) is not None:
                    return legible(datos.group(1))
    return None


def version_del_codigo(sis, hermes) -> tuple:
    """(versión, carpeta) del código que corre ese Hermes, o (None, None). Con su API apagada no hay `/health` al que
    preguntar: se busca su código desde lo que ejecuta su proceso (`…/hermes-agent/venv/bin/python -m hermes_cli.main`, su
    lanzador `…/bin/hermes`), su carpeta de trabajo y donde lo deja su instalador (`<casa>/hermes-agent`). En un
    contenedor, dentro de él (`/proc/<pid>/root`). Solo lee."""
    from .gestor import CONTENEDORES
    pid = getattr(hermes, "pid", None)
    gestor = getattr(hermes, "gestor", None)
    dentro = "/proc/%s/root" % pid if pid and gestor is not None and gestor.tipo in CONTENEDORES else ""
    candidatas = []
    for trozo in getattr(hermes, "orden", None) or []:
        if trozo.startswith("/") and ".." not in trozo.split("/"):
            candidatas += [dentro + c for c in _ancestros(trozo)]
    if pid:
        candidatas.append("/proc/%s/cwd" % pid)
    casa = hermes.home.rstrip("/")
    partes = casa.rsplit("/", 2)
    if len(partes) == 3 and partes[1] == "profiles":
        casa = partes[0]
    candidatas.append(casa + "/hermes-agent")
    for carpeta in dict.fromkeys(candidatas):
        hallada = _version_en(sis, carpeta) or _version_del_venv(sis, carpeta)
        if hallada:
            return hallada, carpeta
    return None, None
