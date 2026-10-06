"""Los agentes (``server/API-CONTRACT.md`` §18, desde la 1.6.0): cada uno es un perfil de Hermes que su pasarela sirve
bajo ``/p/<perfil>/`` con su propia clave. Del lado del vigía:

- **Qué agentes se vigilan** (``ClavesDeLosAgentes``): los que tienen su clave en ``[agentes] claves`` de ``vigia.ini``
  (con root, ``/etc/hehermes-avisos/agentes/<perfil>.clave``, de root y del grupo ``hh-vigia``, 0640), que escribe el
  ayudante. Con ellas, un cliente de Hermes por agente (``ClientesDeLosAgentes``), el que usa el bucle.
- **Las rutas** (``Agentes``): ``GET``/``POST /avisos/v1/agentes``, ``GET /avisos/v1/agentes/trabajos/{id}``,
  ``GET``/``PATCH``/``DELETE /avisos/v1/agentes/{perfil}`` y ``POST /avisos/v1/agentes/personalidad``.

El vigía no puede tocar la casa de Hermes ni las claves: todo lo que cambia algo lo hace el ayudante
``hehermes-agentes`` (``despliegue/hehermes-agentes``), que systemd lanza por cada conexión a su socket, como el de la
copia (``respaldo.py``). El vigía solo:

- mira la forma de lo que llega antes de molestar al ayudante (que la vuelve a mirar): los campos, sus listas y sus
  topes, y el perfil;
- nunca le deja borrar el principal (409, sin preguntarle);
- vuelve a filtrar lo que contesta: a la app solo le llega lo esperado, con su forma;
- y escribe la personalidad de un agente nuevo con el principal (``/v1/chat/completions``, un mensaje de sistema fijo),
  una a la vez. Eso no necesita al ayudante.

Las rutas llevan el mismo control de acceso que las demás: el secreto del túnel, que la pasarela solo pone a lo que
trae el token de un iPhone dado de alta (``api.ManejadorVigia``). Nunca se apunta una clave ni una personalidad.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import threading

from ..comun import ErrorHTTP
from .hermes import ClienteHermes, ErrorHermes
from .respaldo import ClienteAyudante, _error_de

registro = logging.getLogger("vigia.agentes")

PREFIJO = "/avisos/v1/agentes"
RUTA = re.compile(r"/avisos/v1/agentes(?:/(personalidad|trabajos/([^/]*)|[^/]*))?/?")
NO_DISPONIBLE = "agentes_no_disponible"
PRINCIPAL = "default"
PATRON_PERFIL = re.compile(r"[a-z0-9]{1,24}")
PATRON_ID = re.compile(r"[0-9a-f]{32}")
#: Lo de §18, lo mismo que mira el ayudante.
COLORES = ("indigo", "azul", "violeta", "rosa", "coral", "menta", "grafito", "oro")
EXPRESIONES = ("serena", "curiosa", "alegre", "concentrada", "traviesa", "seria")
MEMORIAS_AL_CREAR = ("comparte", "copia", "cero")
MEMORIAS = ("propia",) + MEMORIAS_AL_CREAR
ESTADOS = ("en_cola", "creando", "borrando", "hecho", "fallo")
MOTIVOS = frozenset({"hermes", "memoria", "clave", "no_se_sirve", "copia", "interrumpido", "interna"})
#: En qué está un trabajo que crea el primer agente (opcional, §18.4): esperando a que Hermes esté tranquilo, o
#: reiniciándolo (una vez) para que lo sirva.
PASOS = ("esperando_a_hermes", "reiniciando_hermes")
MAX_TEXTO = 8 * 1024
MAX_NOMBRE = 40
TOPE_AGENTES = 12
CAMPOS_AL_CREAR = {"nombre", "color", "expresion", "descripcion", "personalidad", "memoria", "modelo"}
CAMBIABLES = ("nombre", "color", "expresion", "descripcion", "personalidad")
#: El mensaje de sistema con el que el principal escribe la personalidad de un agente nuevo (contrato §18.7). Fijo: lo
#: único que pone la app es la descripción.
SISTEMA_PERSONALIDAD = ("Escribe en español el SOUL.md de un agente de Hermes a partir de esta descripción. Solo el "
                        "texto, en segunda persona, de 15 a 40 líneas.")
#: Lo que se espera a que Hermes la escriba: menos que los 3 minutos de la app.
PLAZO_PERSONALIDAD = 170.0
#: Lo que se le da al ayudante por defecto (`comprobar`), y en cada orden: todas contestan al momento, sin lanzar
#: `hermes` (crear y borrar siguen con la conexión cerrada; la descripción le llega a Hermes después de contestar), y la
#: lista mira cada agente con un plazo de 1 s. Así un ayudante atascado no tiene a la app esperando.
PLAZO_AYUDANTE = 60.0
PLAZOS = {"listar": 10.0, "ver": 10.0, "trabajo": 10.0, "cambiar": 20.0, "crear": 30.0, "borrar": 30.0}
#: Una clave de un agente: lo que puede ir en una cabecera, en una línea (la de la pasarela, `leer_clave_de_agente`).
PATRON_CLAVE = re.compile(r"[\x21-\x7e]{1,512}")


def ayudante(ruta_socket: str, plazo: float = PLAZO_AYUDANTE) -> ClienteAyudante:
    """El cliente del socket del ayudante de los agentes: el de la copia, con su código de «no disponible»."""
    return ClienteAyudante(ruta_socket, plazo, no_disponible=NO_DISPONIBLE, de_quien="de los agentes")


# MARK: Las claves y los clientes de cada agente


class ClavesDeLosAgentes:
    """La carpeta de las claves de los agentes que lee el vigía. Una clave vale si es un fichero normal (sin seguir
    enlaces) que solo pueden leer su dueño y su grupo y escribir su dueño (0640 o menos: con root, `root:hh-vigia`; sin
    root, 0600 del usuario de Hermes), con la clave en una línea. El principal no va aquí."""

    def __init__(self, carpeta: str):
        self.carpeta = carpeta

    def clave(self, perfil) -> str | None:
        if not isinstance(perfil, str) or not PATRON_PERFIL.fullmatch(perfil) or perfil == PRINCIPAL:
            return None
        try:
            fd = os.open(os.path.join(self.carpeta, perfil + ".clave"),
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            return None
        try:
            datos = os.fstat(fd)
            if not stat.S_ISREG(datos.st_mode) or datos.st_mode & 0o037 or datos.st_size > 1024:
                return None
            texto = os.read(fd, 1025).decode("utf-8", "replace").strip()
        except OSError:
            return None
        finally:
            os.close(fd)
        return texto if PATRON_CLAVE.fullmatch(texto) and '"' not in texto else None

    def perfiles(self) -> list:
        """Los agentes servidos: los que tienen una clave que vale."""
        try:
            nombres = os.listdir(self.carpeta)
        except OSError:
            return []
        return sorted(nombre[:-len(".clave")] for nombre in nombres
                      if nombre.endswith(".clave") and self.clave(nombre[:-len(".clave")]) is not None)


class ClientesDeLosAgentes:
    """Un cliente de Hermes por agente servido (``/p/<perfil>/``, con su clave), el mismo mientras no cambie su clave:
    lo que vigila el bucle (``Vigilante``) y donde se busca la marca de un fichero (``fichero.Ficheros``)."""

    def __init__(self, claves: ClavesDeLosAgentes, base: str, plazo: float, abridor=None):
        self.claves, self.base, self.plazo, self.abridor = claves, base, plazo, abridor
        self._hechos: dict = {}
        self._cerrojo = threading.Lock()

    def cliente(self, perfil: str) -> ClienteHermes | None:
        clave = self.claves.clave(perfil)
        with self._cerrojo:
            if clave is None:
                self._hechos.pop(perfil, None)
                return None
            hecho = self._hechos.get(perfil)
            if hecho is None or hecho._clave != clave:
                hecho = ClienteHermes(self.base, clave, self.plazo, self.abridor, perfil=perfil)
                self._hechos[perfil] = hecho
            return hecho

    def clientes(self) -> dict:
        perfiles = self.claves.perfiles()
        with self._cerrojo:
            for perfil in [p for p in self._hechos if p not in perfiles]:
                del self._hechos[perfil]
        clientes = {}
        for perfil in perfiles:
            cliente = self.cliente(perfil)
            if cliente is not None:
                clientes[perfil] = cliente
        return clientes


# MARK: Lo que llega


def _invalido(que: str) -> ErrorHTTP:
    return ErrorHTTP(400, "parametro_invalido", que)


def _texto(valor, maximo: int, lineas: bool, vacio: bool, que: str) -> str:
    if not isinstance(valor, str):
        raise _invalido("«%s» tiene que ser un texto" % que)
    try:
        largo = len(valor.encode("utf-8"))
    except UnicodeEncodeError:
        raise _invalido("«%s» no es UTF-8" % que) from None
    if largo > maximo:
        raise _invalido("«%s» pasa de %d bytes" % (que, maximo))
    if any((ord(c) < 0x20 or ord(c) == 0x7F or c in "  ") and not (lineas and c in "\n\r\t")
           for c in valor):
        raise _invalido("«%s» lleva caracteres de control" % que)
    if not vacio and not valor.strip():
        raise _invalido("«%s» no puede ir vacío" % que)
    return valor


def _nombre(valor) -> str:
    nombre = _texto(valor, 4 * MAX_NOMBRE, False, False, "nombre")
    if len(nombre.strip()) > MAX_NOMBRE:
        raise _invalido("«nombre» pasa de %d caracteres" % MAX_NOMBRE)
    return nombre


def _de_la_lista(valor, lista, que: str) -> str:
    if valor not in lista:
        raise _invalido("«%s» tiene que ser uno de: %s" % (que, ", ".join(lista)))
    return valor


def _descripcion(valor) -> str:
    descripcion = _texto(valor, MAX_TEXTO, False, True, "descripcion")
    if descripcion.strip().startswith("-"):
        raise _invalido("«descripcion» no puede empezar por «-»")
    return descripcion


VALIDAR = {"nombre": _nombre, "descripcion": _descripcion,
           "personalidad": lambda v: _texto(v, MAX_TEXTO, True, False, "personalidad"),
           "color": lambda v: _de_la_lista(v, COLORES, "color"),
           "expresion": lambda v: _de_la_lista(v, EXPRESIONES, "expresion"),
           "memoria": lambda v: _de_la_lista(v, MEMORIAS_AL_CREAR, "memoria")}


def perfil_valido(perfil) -> str:
    if not isinstance(perfil, str) or not PATRON_PERFIL.fullmatch(perfil):
        raise _invalido("El perfil son de 1 a 24 minúsculas y cifras")
    return perfil


def _objeto(datos: bytes) -> dict:
    try:
        objeto = json.loads(datos.decode("utf-8")) if datos else None
    except (UnicodeDecodeError, ValueError):
        raise _invalido("El cuerpo no es JSON") from None
    if not isinstance(objeto, dict):
        raise _invalido("El cuerpo tiene que ser un objeto JSON")
    return objeto


def para_crear(cuerpo: dict) -> dict:
    """Lo de `POST /avisos/v1/agentes`, con su forma (contrato §18.3), o 400. Todos los campos, y nada más."""
    if set(cuerpo) != CAMPOS_AL_CREAR:
        raise _invalido("El cuerpo es {%s}" % ", ".join(sorted(CAMPOS_AL_CREAR)))
    if cuerpo["modelo"] is not None:
        raise _invalido("«modelo», por ahora, solo null: el del principal")
    return dict({campo: VALIDAR[campo](cuerpo[campo]) for campo in CAMPOS_AL_CREAR - {"modelo"}}, modelo=None)


def para_cambiar(cuerpo: dict) -> dict:
    """Lo de `PATCH /avisos/v1/agentes/{perfil}`: al menos uno de los que se cambian, y nada más."""
    if not cuerpo or set(cuerpo) - set(CAMBIABLES):
        raise _invalido("Se cambia alguno de: %s" % ", ".join(CAMBIABLES))
    return {campo: VALIDAR[campo](valor) for campo, valor in cuerpo.items()}


# MARK: Lo que contesta el ayudante, filtrado


def _entero(valor) -> bool:
    return isinstance(valor, int) and not isinstance(valor, bool)


def agente_limpio(dato) -> dict | None:
    """Un agente como lo dice §18.2, con lo esperado y su forma; lo que no la tiene, con lo de serie. Sin perfil, nada."""
    if not isinstance(dato, dict) or not (isinstance(dato.get("perfil"), str)
                                          and PATRON_PERFIL.fullmatch(dato["perfil"])):
        return None
    principal = dato["perfil"] == PRINCIPAL
    nombre = dato.get("nombre")
    descripcion = dato.get("descripcion")
    return {"perfil": dato["perfil"],
            "nombre": nombre if isinstance(nombre, str) and 0 < len(nombre) <= MAX_NOMBRE else dato["perfil"],
            "color": dato.get("color") if dato.get("color") in COLORES else ("indigo" if principal else "grafito"),
            "expresion": dato.get("expresion") if dato.get("expresion") in EXPRESIONES else "serena",
            "descripcion": descripcion if isinstance(descripcion, str)
            and len(descripcion.encode("utf-8", "replace")) <= MAX_TEXTO else "",
            "memoria": dato.get("memoria") if dato.get("memoria") in MEMORIAS else "propia",
            "principal": principal, "servido": dato.get("servido") is True or principal}


def trabajo_limpio(dato) -> dict:
    if not isinstance(dato, dict) or dato.get("estado") not in ESTADOS or dato.get("tipo") not in ("crear", "borrar") \
            or not (isinstance(dato.get("perfil"), str) and PATRON_PERFIL.fullmatch(dato["perfil"])):
        raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante de los agentes contesta algo que no entiendo")
    motivo = dato.get("motivo")
    if dato["estado"] != "fallo":
        motivo = None
    elif motivo not in MOTIVOS:
        motivo = "interna"
    limpio = {"estado": dato["estado"], "tipo": dato["tipo"], "perfil": dato["perfil"], "motivo": motivo}
    # `paso`, solo mientras crea y si es uno de los suyos: un campo nuevo que una app de antes ni ve.
    if dato["estado"] == "creando" and dato.get("paso") in PASOS:
        limpio["paso"] = dato["paso"]
    return limpio


# MARK: Las rutas


class Agentes:
    """La lógica de las rutas de §18, sin HTTP: ``atender`` devuelve ``(estado, objeto JSON, cabeceras)``.
    ``ayudante``: el cliente del socket del ayudante (sin él, 503 salvo la personalidad); ``principal``: el cliente de
    Hermes del principal, que escribe la personalidad."""

    def __init__(self, ayudante_: ClienteAyudante | None, principal: ClienteHermes | None):
        self.ayudante = ayudante_
        self.principal = principal
        # Una personalidad a la vez: cada una es un turno del modelo de Hermes.
        self._escribiendo = threading.Lock()

    def _pedir(self, peticion: dict) -> dict:
        if self.ayudante is None:
            raise ErrorHTTP(503, NO_DISPONIBLE, "Este servidor no tiene el ayudante de los agentes")
        respuesta, _ = self.ayudante.pedir(peticion, plazo=PLAZOS.get(peticion.get("orden"), PLAZO_AYUDANTE))
        if not isinstance(respuesta, dict) or not respuesta.get("ok"):
            raise _error_de(respuesta if isinstance(respuesta, dict) else {}, NO_DISPONIBLE)
        return respuesta

    def atender(self, metodo: str, ruta: str, leer_cuerpo) -> tuple:
        sin_cache = {"Cache-Control": "no-store"}
        encontrada = RUTA.fullmatch(ruta)
        if not encontrada:
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        que, id_ = encontrada.group(1), encontrada.group(2)
        if not que:
            if metodo == "GET":
                return 200, self.listar(), sin_cache
            _exigir(metodo, "POST", "GET, POST")
            return 202, self.crear(_objeto(leer_cuerpo())), sin_cache
        if que == "personalidad":
            _exigir(metodo, "POST")
            return 200, self.personalidad(_objeto(leer_cuerpo())), sin_cache
        if id_ is not None:
            _exigir(metodo, "GET")
            if not PATRON_ID.fullmatch(id_):
                raise _invalido("El id de un trabajo son 32 hexadecimales")
            return 200, trabajo_limpio(self._pedir({"orden": "trabajo", "id": id_})), sin_cache
        perfil = perfil_valido(que)
        if metodo == "GET":
            return 200, self.ver(perfil), sin_cache
        if metodo == "PATCH":
            return 200, self.cambiar(perfil, _objeto(leer_cuerpo())), sin_cache
        _exigir(metodo, "DELETE", "GET, PATCH, DELETE")
        return 202, self.borrar(perfil), sin_cache

    def listar(self) -> dict:
        respuesta = self._pedir({"orden": "listar"})
        lista, caben = respuesta.get("agentes"), respuesta.get("caben")
        if not isinstance(lista, list):
            raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante de los agentes contesta algo que no entiendo")
        agentes = [agente for agente in (agente_limpio(dato) for dato in lista) if agente is not None]
        return {"agentes": agentes, "caben": max(0, min(TOPE_AGENTES, caben)) if _entero(caben) else 0}

    def crear(self, cuerpo: dict) -> dict:
        datos = para_crear(cuerpo)
        respuesta = self._pedir(dict(datos, orden="crear"))
        trabajo, perfil = respuesta.get("trabajo"), respuesta.get("perfil")
        if not (isinstance(trabajo, str) and PATRON_ID.fullmatch(trabajo) and isinstance(perfil, str)
                and PATRON_PERFIL.fullmatch(perfil)):
            raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante de los agentes contesta algo que no entiendo")
        registro.info("agentes: crear %s (trabajo %s)", perfil, trabajo[:8])
        return {"trabajo": trabajo, "perfil": perfil}

    def ver(self, perfil: str) -> dict:
        respuesta = self._pedir({"orden": "ver", "perfil": perfil})
        agente = agente_limpio(respuesta)
        if agente is None:
            raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante de los agentes contesta algo que no entiendo")
        personalidad = respuesta.get("personalidad")
        agente["personalidad"] = (personalidad if isinstance(personalidad, str) and not agente["principal"]
                                  else None)
        if agente["personalidad"] is not None:
            agente["personalidad"] = _recortar(agente["personalidad"], MAX_TEXTO)
        return agente

    def cambiar(self, perfil: str, cuerpo: dict) -> dict:
        cambios = para_cambiar(cuerpo)
        if perfil == PRINCIPAL and "personalidad" in cambios:
            raise ErrorHTTP(409, "no_se_cambia_el_principal", "Del principal solo se cambian el nombre, la cara y la "
                                                              "descripción")
        agente = agente_limpio(self._pedir(dict(cambios, orden="cambiar", perfil=perfil)))
        if agente is None:
            raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante de los agentes contesta algo que no entiendo")
        registro.info("agentes: cambiar %s (%s)", perfil, ", ".join(sorted(cambios)))
        return agente

    def borrar(self, perfil: str) -> dict:
        if perfil == PRINCIPAL:
            raise ErrorHTTP(409, "no_se_borra_el_principal", "El principal no se borra")
        respuesta = self._pedir({"orden": "borrar", "perfil": perfil})
        trabajo = respuesta.get("trabajo")
        if not (isinstance(trabajo, str) and PATRON_ID.fullmatch(trabajo)):
            raise ErrorHTTP(502, NO_DISPONIBLE, "El ayudante de los agentes contesta algo que no entiendo")
        registro.info("agentes: borrar %s (trabajo %s)", perfil, trabajo[:8])
        return {"trabajo": trabajo}

    def personalidad(self, cuerpo: dict) -> dict:
        """El SOUL.md de un agente nuevo a partir de su descripción, escrito por el principal (contrato §18.7). La app lo
        deja retocar antes de crear."""
        if set(cuerpo) != {"descripcion"}:
            raise _invalido("El cuerpo es {\"descripcion\": \"…\"}")
        descripcion = _texto(cuerpo["descripcion"], MAX_TEXTO, True, False, "descripcion")
        if self.principal is None:
            raise ErrorHTTP(502, "hermes_no_disponible", "Este vigía no habla con Hermes")
        if not self._escribiendo.acquire(blocking=False):
            raise ErrorHTTP(429, "ocupado", "Ya se está escribiendo otra personalidad", {"Retry-After": "30"})
        try:
            texto = self.principal.completar(SISTEMA_PERSONALIDAD, descripcion, PLAZO_PERSONALIDAD)
        except ErrorHermes as error:
            registro.warning("agentes: el principal no ha escrito la personalidad (%s)", error.estado or "sin respuesta")
            raise ErrorHTTP(502, "hermes_no_disponible", "Hermes no ha escrito la personalidad") from None
        finally:
            self._escribiendo.release()
        texto = _recortar(texto.strip(), MAX_TEXTO)
        if not texto:
            raise ErrorHTTP(502, "hermes_no_disponible", "Hermes no ha escrito la personalidad")
        registro.info("agentes: personalidad escrita (%d bytes)", len(texto.encode("utf-8")))
        return {"personalidad": texto}


def _recortar(texto: str, maximo: int) -> str:
    """Hasta `maximo` bytes en UTF-8, sin partir una letra."""
    return texto.encode("utf-8")[:maximo].decode("utf-8", "ignore")


def _exigir(metodo: str, permitido: str, todos: str | None = None) -> None:
    if metodo != permitido:
        raise ErrorHTTP(405, "metodo_no_permitido", f"Aquí solo vale {todos or permitido}",
                        {"Allow": todos or permitido})
