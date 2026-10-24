"""«Enviar más tarde» (2026-10-23, contrato §19): los mensajes que el usuario deja para una hora y que el vigía lanza solo.

**Por qué el vigía y no una tarea de Hermes.** Tiene que salir con el iPhone apagado o la app cerrada, así que lo lanza
el servidor; y tiene que salir **dentro de esa conversación**, como un turno de su ``session_id``. Una tarea programada
de Hermes (``POST /api/jobs``, contrato §10) no sirve: solo lee ``name``, ``schedule``, ``prompt``, ``skills``,
``repeat``, ``deliver`` y ``paused`` (no hay ``session_id``), corre su propio turno en una sesión aparte y entrega a una
plataforma (``telegram:…``, ``local``). Y Hermes está congelado a propósito: no se le añaden rutas. El vigía, en cambio,
ya lanza turnos solo (``entregas``: la continuación de un subagente) con ``POST /v1/runs`` y su ``Idempotency-Key``.

**Qué guarda.** Por cada mensaje: su clave (el id que le dio la app, que es también la ``Idempotency-Key``), la
conversación (perfil y sesión), la hora y el cuerpo del turno **tal como lo armó la app** (``input``, ``instructions``
ya con su encabezado, ``effort``, ``model`` y ``provider``): el vigía no conoce las instrucciones ni el esfuerzo de la
conversación, así que la app se los pasa al programarlo y el turno sale como habría salido al enviarlo. Todo en el
SQLite del vigía (``almacen``, esquema 7): sobrevive a reiniciarse.

**La foto** (2026-10-24). Una foto programada viaja **en el cuerpo del turno**, como la del envío normal (``input`` multimodal con
``data:image/jpeg;base64,``), pero no puede llegar en el ``PUT``: la pasarela corta las rutas ``/avisos/`` a 64 KiB. La app
la sube antes **a trozos de 48 KiB** (``PUT …/{clave}/imagen/{n}``, bytes sin más), que el vigía guarda **en memoria** hasta
que el ``PUT`` del mensaje declare ``imagen: {trozos, tamano, sha256}``: entonces los junta, comprueba el SHA-256 y deja la foto
en base64 dentro del cuerpo guardado (``imagen``, con ``imagen_sha256``). Sin esquema nuevo: ``cuerpo`` ya era JSON. Hay un
tope por foto (``TOPE_DE_IMAGEN``) y otro del cuerpo guardado de todos los que esperan (``TOPE_GUARDADO``); y la foto **se
borra del cuerpo en cuanto el mensaje sale, falla o caduca** (``almacen``): el vigía no se queda 7 días con fotos de nadie.
Un documento no pasa por aquí: sube por ``/avisos/v1/entrada`` (§16) y el ``input`` lleva su ruta.

**Cuándo lanza** (``decidir``, pura): a su hora y no antes; **no encima de un turno en marcha** de esa conversación
(``entregas.turno_en_marcha``: espera a que acabe); no tras ``RETRASO_MAXIMO`` (24 h, lo que dura la idempotencia de
Hermes y lo que espera la app sin conexión): pasado eso queda ``caducado`` y la app lo enseña, no se pierde en silencio;
y no antes de ``hasta`` tras un fallo pasajero.

**Que no salga dos veces.** Al llegar la hora el vigía **reclama** la fila (``pendiente`` → ``lanzando``, de una vez y
bajo el cerrojo del almacén) antes de hablar con Hermes: desde ahí la app ya no puede cambiarla ni borrarla
(``409 ya_lanzado``), y el POST lleva siempre la misma ``Idempotency-Key``. Un reinicio entre el reclamo y la respuesta
deja la fila en ``lanzando``, y la vuelta siguiente repite el mismo POST: Hermes contesta ``replayed`` con el mismo run.
Si la app lo mandó a la vez con la misma clave («Enviar ya» en una carrera), Hermes da 409 ``idempotency_key_conflict`` y
cuenta como lanzado: un solo turno.

**Qué pasa después.** El run se vigila como cualquier turno (``almacen.vigilar_turnos``): la respuesta se avisa al iPhone
como siempre, y si falla, el aviso de error.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
import threading
import urllib.parse

from ..comun import ErrorHTTP
from . import entregas
from .almacen import Almacen, ProgramadoGuardado
from .hermes import PATRON_PERFIL, PRINCIPAL, ErrorHermes

registro = logging.getLogger("vigia.programados")

PREFIJO = "/avisos/v1/programados"

PENDIENTE = "pendiente"
LANZANDO = "lanzando"
LANZADO = "lanzado"
FALLIDO = "fallido"
CADUCADO = "caducado"

# Las decisiones de `decidir`.
NADA = "nada"
ESPERAR = "esperar"
MIRAR = "mirar"
LANZAR = "lanzar"
CADUCAR = "caducar"

#: Cuánto después de su hora se sigue intentando lanzar un mensaje (el vigía estuvo caído, o Hermes no contestaba). Pasado
#: esto no sale solo: una pregunta de ayer no tiene por qué seguir valiendo.
RETRASO_MAXIMO = 24 * 3600.0
#: Con cuánta antelación se puede programar: el fichero que sube con el mensaje vive los ``entrada.dias`` del vigía (30 por
#: defecto), y un mensaje programado a más no tendría su adjunto.
ANTELACION_MAXIMA = 30 * 86400.0
#: Cuánto se recuerda lo ya lanzado, fallido o caducado: lo que la app tarda en enterarse, con margen.
RECUERDO = 7 * 86400.0
#: Los pendientes a la vez, de todos los iPhone: un tope de seguridad, no de uso.
MAX_PENDIENTES = 200
#: Lo que se espera tras un fallo pasajero, por intento; el último se repite.
PAUSAS = (5.0, 20.0, 60.0, 300.0)
#: Las filas de la conversación que se leen para saber si hay un turno en marcha (`LIMITE_FILAS` de la vigilancia).
FILAS_A_MIRAR = 100

#: El cuerpo de la ruta: el texto que quepa en un mensaje y sus instrucciones, no un fichero (esos suben por
#: ``/avisos/v1/entrada``, contrato §16). **Por la pasarela llegan 64 KiB**, que es lo que corta ella en ``/avisos/``: por eso la
#: foto va a trozos.
TOPE_DEL_CUERPO = 256 * 1024
#: Lo que lleva cada trozo de una foto: por debajo de los 64 KiB de la pasarela, con holgura para las cabeceras.
TROZO_DE_IMAGEN = 48 * 1024
#: Una foto programada: la app guarda las suyas a 2048 px (unos cientos de KB); esto deja sitio de sobra y sigue cabiendo
#: en los 10 MB que acepta el api_server de Hermes una vez en base64.
TOPE_DE_IMAGEN = 6 * 1024 * 1024
#: Los trozos de una foto del tope.
MAX_TROZOS = -(-TOPE_DE_IMAGEN // TROZO_DE_IMAGEN)
#: Lo que pueden ocupar los cuerpos guardados de todo lo que espera (``pendiente`` y ``lanzando``), con sus fotos, más los
#: trozos en espera: el tope total, para que un iPhone no llene el disco del servidor con fotos que saldrán dentro de un mes.
TOPE_GUARDADO = 64 * 1024 * 1024
#: Cuánto espera un trozo suelto a que llegue el ``PUT`` del mensaje antes de olvidarse.
ESPERA_DE_TROZOS = 3600.0
TOPE_DEL_TEXTO = 100_000
TOPE_DE_INSTRUCCIONES = 16 * 1024
ESFUERZOS = ("low", "medium", "high", "xhigh")
PATRON_CLAVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,79}")


# -- La decisión, pura

def decidir(programado: ProgramadoGuardado, ahora: float, filas: list | None = None) -> str:
    """Qué hacer con un mensaje programado ahora. Pura: sin reloj ni red.

    ``MIRAR`` quiere decir «lo lanzaría, pero antes hay que ver si la conversación tiene un turno en marcha»: quien
    llama lee las filas y vuelve a preguntar con ellas. Un reclamado a medias (``lanzando``) no mira nada: ya se decidió
    y solo falta que Hermes lo acepte (con la misma clave, así que repetirlo no duplica)."""
    if programado.estado not in (PENDIENTE, LANZANDO):
        return NADA
    if ahora < programado.hora:
        return NADA
    if ahora - programado.hora > RETRASO_MAXIMO:
        return CADUCAR
    if ahora < programado.hasta:
        return ESPERAR
    if programado.estado == PENDIENTE:
        if filas is None:
            return MIRAR
        if entregas.turno_en_marcha(filas, ahora):
            return ESPERAR
    return LANZAR


def pausa_tras_fallar(fallos: int) -> float:
    return PAUSAS[min(max(fallos, 1), len(PAUSAS)) - 1]


def es_pasajero(error: ErrorHermes) -> bool:
    """Un fallo que se arregla solo: sin respuesta, 429, 5xx, la clave que el túnel aún no pone (401/403) o un tiempo
    agotado (408). Lo demás (un 400, un 404…) es de este mensaje y no cambiará reintentando."""
    return error.estado is None or error.estado in (401, 403, 408, 429) or error.estado >= 500


# -- Lo que entra por la API

def _invalido(que: str) -> ErrorHTTP:
    return ErrorHTTP(400, "parametro_invalido", que)


def _exigir(metodo: str, permitido: str, todos: str | None = None) -> None:
    if metodo != permitido:
        raise ErrorHTTP(405, "metodo_no_permitido", f"Aquí solo vale {todos or permitido}",
                        {"Allow": todos or permitido})


def clave_valida(valor: object) -> str:
    if not isinstance(valor, str) or not PATRON_CLAVE.fullmatch(valor):
        raise _invalido("La clave es el id del mensaje: de 8 a 80 letras, cifras, puntos, guiones y guiones bajos")
    return valor


def perfil_valido(valor: object) -> str:
    if valor is None:
        return PRINCIPAL
    if not isinstance(valor, str) or (valor != PRINCIPAL and not PATRON_PERFIL.fullmatch(valor)):
        raise _invalido("El perfil no tiene la forma de uno de Hermes")
    return valor


def sesion_valida(valor: object) -> str:
    if (not isinstance(valor, str) or not valor or len(valor) > 200 or valor.strip() != valor
            or any(ord(c) < 32 for c in valor)):
        raise _invalido("Falta la sesión de la conversación (la de Hermes, sin el perfil)")
    return valor


def hora_valida(valor: object, ahora: float) -> float:
    """Una hora en segundos desde 1970. Puede estar en el pasado hasta ``RETRASO_MAXIMO``: una que se programó sin
    conexión y llega tarde sale enseguida (es lo que dice que un iPhone que vuelve no pierde lo que dejó)."""
    if isinstance(valor, bool) or not isinstance(valor, (int, float)) or not math.isfinite(valor):
        raise _invalido("La hora son segundos desde 1970")
    if valor < ahora - RETRASO_MAXIMO:
        raise ErrorHTTP(400, "hora_pasada", "Esa hora ya pasó hace más de un día")
    if valor > ahora + ANTELACION_MAXIMA:
        raise ErrorHTTP(400, "hora_lejana", "Esa hora está a más de 30 días")
    return float(valor)


def _entero(valor: object, nombre: str, minimo: int, maximo: int) -> int:
    if isinstance(valor, bool) or not isinstance(valor, int) or not minimo <= valor <= maximo:
        raise _invalido(f"«{nombre}» tiene que ser un entero entre {minimo} y {maximo}")
    return valor


def imagen_declarada(valor: object) -> tuple[int, int, str]:
    """``{"trozos", "tamano", "sha256"}`` del ``PUT``: lo que el vigía tiene que juntar y comprobar."""
    if not isinstance(valor, dict):
        raise _invalido("«imagen» es {trozos, tamano, sha256}")
    tamano = valor.get("tamano")
    if isinstance(tamano, int) and not isinstance(tamano, bool) and tamano > TOPE_DE_IMAGEN:
        raise ErrorHTTP(413, "imagen_demasiado_grande", f"Una foto programada pesa como mucho {TOPE_DE_IMAGEN} bytes")
    tamano = _entero(tamano, "tamano", 1, TOPE_DE_IMAGEN)
    trozos = _entero(valor.get("trozos"), "trozos", 1, MAX_TROZOS)
    sha = valor.get("sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise _invalido("«sha256» son 64 hexadecimales en minúsculas")
    return trozos, tamano, sha


def _texto(valor: object, nombre: str, tope: int, vacio: bool = False) -> str:
    if not isinstance(valor, str) or (not vacio and not valor.strip()) or len(valor) > tope:
        raise _invalido(f"«{nombre}» tiene que ser un texto de hasta {tope} caracteres")
    return valor


def cuerpo_valido(datos: dict, base: dict | None = None, con_imagen: bool = False) -> dict:
    """El cuerpo del turno a partir de lo que manda la app. Con ``base`` (un cambio parcial), lo que no viene se queda y
    ``null`` quita ``instructions``, ``effort``, ``model`` y ``provider``. Con una foto (``con_imagen``, la del mensaje o la que
    ya tenía), el texto puede quedar vacío: una foto sola es un mensaje."""
    cuerpo = dict(base or {})
    if "input" in datos or base is None:
        cuerpo["input"] = _texto(datos.get("input"), "input", TOPE_DEL_TEXTO, vacio=con_imagen)
    for campo in ("instructions", "effort", "model", "provider"):
        if campo not in datos:
            continue
        if datos[campo] is None:
            cuerpo.pop(campo, None)
        elif campo == "instructions":
            cuerpo[campo] = _texto(datos[campo], campo, TOPE_DE_INSTRUCCIONES)
        elif campo == "effort":
            if datos[campo] not in ESFUERZOS:
                raise _invalido("«effort» es low, medium, high o xhigh")
            cuerpo[campo] = datos[campo]
        else:
            cuerpo[campo] = _texto(datos[campo], campo, 200)
    # Los dos o ninguno: uno solo dejaría el turno a medias entre el modelo elegido y el global.
    if ("model" in cuerpo) != ("provider" in cuerpo):
        raise _invalido("«model» y «provider» van juntos")
    return cuerpo


def como_json(p: ProgramadoGuardado) -> dict:
    objeto = {"clave": p.clave, "perfil": p.perfil, "sesion": p.sesion, "hora": p.hora, "estado": p.estado,
              "run_id": p.run_id, "lanzado": p.lanzado, "motivo": p.motivo}
    objeto.update(p.cuerpo)
    # La foto no vuelve en cada consulta de la app (el temporizador de la conversación pregunta a menudo): solo que la tiene.
    if objeto.pop("imagen", None) is not None:
        objeto["con_imagen"] = True
    objeto.pop("imagen_sha256", None)
    return objeto


# -- Los trozos de una foto, en espera

class TrozosEnEspera:
    """Los trozos de las fotos que la app está subiendo, hasta que el ``PUT`` del mensaje las junta. **En memoria**, a
    propósito: son transitorios (una hora), un reinicio solo hace que la app repita los que falten (``409
    imagen_incompleta``) y no hace falta esquema ni limpieza de disco. Cuentan para el tope total.

    **Con cerrojo**: el servidor del vigía atiende cada petición en su hilo (``ThreadingHTTPServer``) y la app sube los
    trozos de una foto seguidos, mientras el bucle de ``atender`` poda; sumar o podar recorriendo el diccionario mientras
    otro hilo mete un trozo da ``RuntimeError: dictionary changed size during iteration``."""

    def __init__(self):
        self._por_clave: dict[str, dict] = {}
        self._cerrojo = threading.Lock()

    def poner(self, clave: str, n: int, datos: bytes, ahora: float) -> None:
        with self._cerrojo:
            entrada = self._por_clave.setdefault(clave, {"desde": ahora, "trozos": {}})
            entrada["desde"] = ahora
            entrada["trozos"][n] = datos

    def bytes_en_espera(self, salvo: str | None = None) -> int:
        with self._cerrojo:
            return sum(len(t) for c, e in self._por_clave.items() if c != salvo for t in e["trozos"].values())

    def faltan(self, clave: str, trozos: int) -> list[int]:
        with self._cerrojo:
            tengo = self._por_clave.get(clave, {}).get("trozos", {})
            return [n for n in range(trozos) if n not in tengo]

    def juntar(self, clave: str, trozos: int) -> bytes:
        with self._cerrojo:
            tengo = self._por_clave[clave]["trozos"]
            return b"".join(tengo[n] for n in range(trozos))

    def olvidar(self, clave: str) -> None:
        with self._cerrojo:
            self._por_clave.pop(clave, None)

    def podar(self, ahora: float) -> None:
        with self._cerrojo:
            for clave in [c for c, e in self._por_clave.items() if ahora - e["desde"] > ESPERA_DE_TROZOS]:
                del self._por_clave[clave]


# -- El servicio

class Programados:
    """Las rutas ``/avisos/v1/programados`` y la vuelta que lanza lo que ha llegado a su hora. ``reloj`` y ``al_moverse``
    (despertar al bucle del vigía al crear o cambiar uno, para que su espera cuente con la hora nueva) vienen de fuera."""

    def __init__(self, almacen: Almacen, reloj, al_moverse=None):
        self.almacen = almacen
        self.reloj = reloj
        self.al_moverse = al_moverse or (lambda: None)
        # Lo pone el vigía: avisa de un turno recién lanzado con la app cerrada, para arrancarle su Actividad en Vivo.
        self.al_lanzar = lambda perfil, sesion, run_id, ahora: None
        self.trozos = TrozosEnEspera()

    # La API

    def atender(self, metodo: str, ruta: str, leer_cuerpo, consulta: str = "") -> tuple:
        sin_cache = {"Cache-Control": "no-store"}
        if ruta == PREFIJO:
            _exigir(metodo, "GET")
            datos = urllib.parse.parse_qs(consulta, keep_blank_values=False)
            sesion = datos["sesion"][0] if datos.get("sesion") else None
            perfil = perfil_valido(datos["perfil"][0]) if datos.get("perfil") else None
            if sesion is not None:
                sesion_valida(sesion)
                perfil = perfil or PRINCIPAL
            return 200, self.listar(perfil, sesion), sin_cache
        if not ruta.startswith(PREFIJO + "/"):
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        resto = ruta[len(PREFIJO) + 1:]
        if "/" in resto:
            # Un trozo de la foto: ``{clave}/imagen/{n}``.
            clave, _, cola = resto.partition("/")
            partes = cola.split("/")
            if len(partes) != 2 or partes[0] != "imagen" or not partes[1].isascii() or not partes[1].isdigit():
                raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
            _exigir(metodo, "PUT")
            self.poner_trozo(clave_valida(clave), int(partes[1]), leer_cuerpo())
            return 204, None, sin_cache
        clave = clave_valida(resto)
        if metodo == "PUT":
            estado, objeto = self.crear(clave, _objeto(leer_cuerpo()))
            return estado, objeto, sin_cache
        if metodo == "PATCH":
            return 200, self.cambiar(clave, _objeto(leer_cuerpo())), sin_cache
        if metodo == "DELETE":
            return 200, self.borrar(clave), sin_cache
        _exigir(metodo, "PUT", "PUT, PATCH, DELETE")
        raise AssertionError("inalcanzable")

    def listar(self, perfil: str | None = None, sesion: str | None = None) -> dict:
        return {"programados": [como_json(p) for p in self.almacen.programados(perfil, sesion)]}

    def crear(self, clave: str, datos: dict) -> tuple:
        """``PUT``: crea el mensaje o, si su clave ya estaba y no se ha reclamado, lo sustituye: idempotente, que es lo que
        necesita la app al volver la conexión sin saber si su primer intento llegó. 201 si es nuevo, 200 si no."""
        ahora = self.reloj()
        perfil, sesion = perfil_valido(datos.get("perfil")), sesion_valida(datos.get("sesion"))
        hora = hora_valida(datos.get("hora"), ahora)
        existente = self.almacen.programado(clave)
        imagen = self._imagen(clave, datos.get("imagen"), existente) if datos.get("imagen") is not None else None
        cuerpo = cuerpo_valido(datos, con_imagen=imagen is not None)
        if imagen is not None:
            cuerpo["imagen"], cuerpo["imagen_sha256"] = imagen
        if existente is None and self.almacen.contar_programados_pendientes() >= MAX_PENDIENTES:
            raise ErrorHTTP(429, "demasiados_programados", "Hay demasiados mensajes programados esperando")
        self._cabe_en_el_tope(clave, len(json.dumps(cuerpo)))
        resultado = self.almacen.escribir_programado(
            ProgramadoGuardado(clave=clave, perfil=perfil, sesion=sesion, hora=hora, cuerpo=cuerpo, creado=ahora))
        if resultado == "ya_lanzado":
            raise self._ya_lanzado(clave)
        self.trozos.olvidar(clave)
        if resultado != "igual":
            self.al_moverse()
        registro.info("programado %s (%s): %s para dentro de %d s", clave[:8], resultado, sesion[:16],
                      max(0, int(hora - ahora)))
        return (201 if resultado == "creado" else 200), como_json(self.almacen.programado(clave))

    def cambiar(self, clave: str, datos: dict) -> dict:
        """``PATCH``: la hora y/o el cuerpo, mientras esté pendiente. Después, 409 ``ya_lanzado``."""
        actual = self.almacen.programado(clave)
        if actual is None:
            raise ErrorHTTP(404, "no_encontrado", "No hay ningún mensaje programado con esa clave")
        if actual.estado != PENDIENTE:
            raise self._ya_lanzado(clave)
        hora = hora_valida(datos["hora"], self.reloj()) if "hora" in datos else actual.hora
        if "imagen" in datos:
            raise _invalido("La foto no se cambia con PATCH: se sustituye el mensaje entero con PUT")
        cuerpo = cuerpo_valido(datos, actual.cuerpo, con_imagen="imagen" in actual.cuerpo)
        if not self.almacen.cambiar_programado(clave, hora, cuerpo):
            # Entre la lectura y el cambio, el vigía lo reclamó: gana el vigía.
            raise self._ya_lanzado(clave)
        self.al_moverse()
        return como_json(self.almacen.programado(clave))

    def poner_trozo(self, clave: str, n: int, datos: bytes) -> None:
        """``PUT …/{clave}/imagen/{n}``: un trozo de la foto, que espera en memoria al ``PUT`` del mensaje."""
        if not datos or len(datos) > TROZO_DE_IMAGEN or n >= MAX_TROZOS:
            raise _invalido(f"Un trozo de foto son de 1 a {TROZO_DE_IMAGEN} bytes, y como mucho {MAX_TROZOS} trozos")
        actual = self.almacen.programado(clave)
        if actual is not None and actual.estado != PENDIENTE:
            raise self._ya_lanzado(clave)
        ahora = self.reloj()
        self.trozos.podar(ahora)
        propio = self.trozos.bytes_en_espera() - self.trozos.bytes_en_espera(salvo=clave) + len(datos)
        self._cabe_en_el_tope(clave, propio * 4 // 3)
        self.trozos.poner(clave, n, datos, ahora)

    def _imagen(self, clave: str, declarada: object, existente: ProgramadoGuardado | None) -> tuple[str, str]:
        """La foto del mensaje: la que dicen los trozos que esperan, o la que el mismo mensaje ya tenía si es el mismo
        ``PUT`` repetido (la app no sabe si el primero llegó, y los trozos ya se gastaron). ``(base64, sha256)``."""
        trozos, tamano, sha = imagen_declarada(declarada)
        if existente is not None and existente.cuerpo.get("imagen_sha256") == sha and "imagen" in existente.cuerpo:
            return existente.cuerpo["imagen"], sha
        faltan = self.trozos.faltan(clave, trozos)
        if faltan:
            error = ErrorHTTP(409, "imagen_incompleta", "Faltan trozos de la foto")
            error.extra = {"faltan": faltan[:64]}
            raise error
        datos = self.trozos.juntar(clave, trozos)
        if len(datos) != tamano or hashlib.sha256(datos).hexdigest() != sha:
            # Lo recibido no es la foto que dice la app: se tira entero y se vuelve a empezar.
            self.trozos.olvidar(clave)
            raise ErrorHTTP(422, "imagen_distinta", "Lo recibido no es la foto que declaraste")
        return base64.b64encode(datos).decode("ascii"), sha

    def _cabe_en_el_tope(self, clave: str, propio: int) -> None:
        """Lo guardado de todo lo que espera (cuerpos y trozos sueltos de los demás) más lo que va a ocupar este mensaje
        (``propio``) no pasa de ``TOPE_GUARDADO``."""
        usado = self.almacen.bytes_de_cuerpos_en_espera(salvo=clave) + self.trozos.bytes_en_espera(salvo=clave)
        if usado + propio > TOPE_GUARDADO:
            raise ErrorHTTP(507, "sin_espacio", "Tu servidor no tiene sitio para más mensajes programados con fotos")

    def borrar(self, clave: str) -> dict:
        self.trozos.olvidar(clave)
        resultado = self.almacen.borrar_programado(clave)
        if resultado == "no_existe":
            raise ErrorHTTP(404, "no_encontrado", "No hay ningún mensaje programado con esa clave")
        if resultado == "ya_lanzado":
            raise self._ya_lanzado(clave)
        return {"clave": clave, "borrado": True}

    def _ya_lanzado(self, clave: str) -> ErrorHTTP:
        actual = self.almacen.programado(clave)
        error = ErrorHTTP(409, "ya_lanzado", "Ese mensaje ya ha salido (o está saliendo): no se puede cambiar")
        error.extra = {"estado": actual.estado if actual else LANZADO}
        return error

    def olvidar_conversacion(self, perfil: str, sesion: str) -> int:
        return self.almacen.borrar_programados_de(perfil, sesion)

    # La vuelta del vigía

    def espera(self, ahora: float, intervalo: float) -> float | None:
        """Cuánto falta, como mucho, hasta que haya que mirar otra vez, o ``None`` si no hay nada programado. Lo de hoy,
        cada ``intervalo``; lo de más adelante, justo a su hora."""
        proxima = self.almacen.proxima_hora_programada()
        if proxima is None:
            return None
        return max(0.0, min(proxima - ahora, intervalo)) if proxima > ahora else intervalo

    def vuelta(self, clientes: dict, ahora: float) -> None:
        """Lanza lo que ha llegado a su hora. Un fallo de uno no frena a los demás."""
        for programado in self.almacen.programados_por_hacer(ahora):
            try:
                self._atender(programado, clientes.get(programado.perfil), ahora)
            except Exception:  # noqa: BLE001 — un mensaje roto no puede parar al resto
                registro.exception("fallo atendiendo el mensaje programado %s", programado.clave[:8])
        self.almacen.podar_programados(ahora - RECUERDO)
        self.trozos.podar(ahora)

    def _atender(self, programado: ProgramadoGuardado, cliente, ahora: float) -> None:
        decision = decidir(programado, ahora)
        if decision == CADUCAR:
            self._terminar(programado, CADUCADO, "El vigía no pudo lanzarlo en las 24 horas siguientes a su hora.", ahora)
            return
        if cliente is None:
            # El agente de esa conversación no se sirve ahora (se está creando, o se borró): se espera; si no vuelve,
            # caducará.
            return
        if decision == MIRAR:
            try:
                filas = cliente.mensajes(programado.sesion, FILAS_A_MIRAR)
            except ErrorHermes as error:
                registro.warning("programado %s: no se pudo leer la conversación (%s); se espera", programado.clave[:8],
                                 error)
                return
            decision = decidir(programado, ahora, filas)
        if decision != LANZAR:
            return
        if programado.estado == PENDIENTE and not self.almacen.reclamar_programado(programado.clave):
            # Lo cambió o lo borró la app entre la lectura y el reclamo: nada que lanzar.
            return
        try:
            run_id = cliente.lanzar_programado(programado.sesion, programado.clave, programado.cuerpo)
        except ErrorHermes as error:
            if error.estado == 409 and error.codigo == "idempotency_key_conflict":
                # La app lo envió a la vez con esta misma clave: ese turno es el bueno.
                self.almacen.programado_lanzado(programado.clave, None, ahora)
                registro.info("programado %s: ya lo había lanzado la app", programado.clave[:8])
                return
            if es_pasajero(error):
                fallos = programado.fallos + 1
                self.almacen.programado_con_fallo(programado.clave, fallos, ahora + pausa_tras_fallar(fallos))
                registro.warning("programado %s: no se pudo lanzar (%s); se reintenta", programado.clave[:8], error)
                return
            self._terminar(programado, FALLIDO, f"Hermes lo rechazó ({error.estado}).", ahora)
            return
        self.almacen.programado_lanzado(programado.clave, run_id, ahora)
        # Se vigila como los turnos de la app: la respuesta se avisa, y si falla, el aviso de error.
        self.almacen.vigilar_turnos([(run_id, programado.sesion, programado.perfil)], ahora)
        registro.info("programado %s lanzado: run %s", programado.clave[:8], run_id)
        self.al_lanzar(programado.perfil, programado.sesion, run_id, ahora)

    def _terminar(self, programado: ProgramadoGuardado, estado: str, motivo: str, ahora: float) -> None:
        self.almacen.programado_terminado(programado.clave, estado, motivo, ahora)
        registro.warning("programado %s: %s (%s)", programado.clave[:8], estado, motivo)


def _objeto(cuerpo: bytes) -> dict:
    try:
        datos = json.loads(cuerpo.decode("utf-8")) if cuerpo else {}
    except (UnicodeDecodeError, ValueError):
        raise ErrorHTTP(400, "json_invalido", "El cuerpo no es JSON") from None
    if not isinstance(datos, dict):
        raise ErrorHTTP(400, "json_invalido", "El cuerpo tiene que ser un objeto")
    return datos

