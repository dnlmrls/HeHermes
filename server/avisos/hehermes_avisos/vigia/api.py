"""Lo que la app le pide al vigía por el túnel, tal y como lo implementó (``ClienteHermes+Avisos.swift``):

- ``POST   /avisos/v1/dispositivos``                    alta, idempotente por token
- ``PUT    /avisos/v1/dispositivos/{token}/ajustes``    los ajustes de Ajustes › Notificaciones
- ``PUT    /avisos/v1/dispositivos/{token}/primer-plano`` si la app está delante (con plazo)
- ``POST   /avisos/v1/prueba``                           manda un aviso de prueba, y espera a lo que diga Apple
- ``DELETE /avisos/v1/dispositivos/{token}``             baja (un 404 también le vale a la app)
- ``GET    /avisos/v1/salud``                            para ver desde Safari que nginx llega al vigía
- ``GET    /avisos/v1/fichero?sesion=&ruta=``            un fichero que Hermes marcó con ``MEDIA:`` (``fichero.py``),
  los bytes por partes; es la única que no contesta JSON cuando va bien
- ``/avisos/v1/respaldo/…``                               la copia de Hermes en iCloud (``respaldo.py``, contrato §15):
  el estado, las instantáneas y sus trozos, y restaurar; los trozos van en binario, y los cuerpos, hasta 4 MiB + 64 KiB
- ``/avisos/v1/entrada/…``                                mandarle un fichero a Hermes (``entrada.py``, contrato §16,
  desde la 1.5.2): las subidas y sus trozos, en binario, con cuerpos de hasta 4 MiB + 64 KiB
- ``/avisos/v1/servidor``, ``…/servidor/actualizar``       Ajustes › Tu servidor (``servidor.py``, contrato §17, desde
  la 1.5.5): el estado del servidor, sin secretos, y actualizarlo con el ayudante que actualiza
- ``/avisos/v1/agentes…``                                 los agentes (``agentes.py``, contrato §18, desde la 1.6.0):
  listarlos, crearlos, verlos, cambiarlos y borrarlos con su ayudante, y escribir la personalidad de uno nuevo. Y las
  rutas que llevan ``sesion`` (el fichero, los ficheros dejados) y las de la entrada aceptan ``perfil=``
- ``POST   /avisos/v1/iphones/barrer``                    no es de la app sino de la pasarela, al quitar un iPhone desde
  la app (contrato §12.10): borra las altas que no son de ningún token que siga. Va firmada con el secreto del túnel
  (``X-HeHermes-Firma``): una pasarela de antes deja pasar las cabeceras de la app, pero la app no tiene el secreto

Cada alta y cada primer plano llevan, desde la pasarela que quita iPhone desde la app, de qué iPhone son
(``X-HeHermes-Iphone``: su nombre, la marca de su token y una firma con el mismo secreto); sin una firma que valga, el
alta no es de nadie. Es lo único que le dice al vigía de quién es un alta: lo usan el barrido y el aviso del código de
recuperación (§12.9), que no se manda a las altas del token del iPhone que entra.

Todo contesta 204 si va bien, y los errores con el envoltorio del api_server de Hermes, que es el que entiende la app.
Menos dos (spec 2026-09-28, «Avisos sin comandos», Contrato C): el alta contesta ``200 {"envio": …}``, con qué va a
mandar los avisos de ese iPhone, y el primer plano, ``200 {"permiso": "renovar"}`` cuando le hace falta a la app pedir
otro permiso al relé (un vigía de antes contestaba 204 a las dos, y la app lo sigue dando por bueno).

**Solo lo que llega por el túnel.** La credencial del iPhone es la de su VPN, como con Hermes. Pero el vigía escucha en
``127.0.0.1``, y cualquier proceso de la máquina podría hablarle: dar de alta veinte tokens falsos, echar al iPhone de
Daniel del tope de dispositivos y, con la app en la App Store, recibir el principio de sus respuestas. Hacen falta dos
cosas, y ninguna basta sola:

- nginx pone en cada petición de ``/avisos/`` una cabecera con un secreto (``X-HeHermes-Vigia``, desde un fichero de
  root en 0600) y el vigía no atiende nada sin ella: 403, sin apuntar la ruta, que lleva el token. Eso cierra la puerta
  a quien le hable directo en ``127.0.0.1:8790``.
- Pero nginx pone el secreto a todo lo que le llega a ``10.77.0.1:80``, también a los procesos de la propia máquina.
  Así que la ``location /avisos/`` solo deja pasar las direcciones de los iPhone del túnel (``deny 10.77.0.1``, sus dos
  redes, ``deny all``: ``despliegue/nginx-avisos.conf``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import time

from .. import VERSION, cifrado
from ..comun import ENTORNOS, PATRON_TOKEN, ErrorHTTP, ManejadorJSON, cola, es_ip_publica, es_nombre_dns
from . import avisos
from .agentes import PREFIJO as PREFIJO_AGENTES
from .agentes import Agentes
from .ajustes import MAX_ID_SESION, Ajustes
from .almacen import PRINCIPAL, Almacen, Iphone, Permiso
from .entrada import PREFIJO as PREFIJO_ENTRADA
from .entrada import TOPE_CUERPO as TOPE_ENTRADA
from .entrada import Entradas
from .envio import BAJA, ENVIADO, LIMITADO, PERMISO, REINTENTABLE, SIN_PERMISO, Mensajero
from .fichero import (PATRON_PERFIL, PATRON_SESION, Descarga, Ficheros, disposicion, parametros, perfil_de_la_consulta,
                      perfil_valido)
from .respaldo import PREFIJO as PREFIJO_RESPALDO
from .respaldo import TOPE_CUERPO as TOPE_RESPALDO
from .respaldo import Respaldos
from .servidor import PREFIJO as PREFIJO_SERVIDOR
from .servidor import Servidor

registro = logging.getLogger("vigia.api")

RUTA_DISPOSITIVO = re.compile(r"/avisos/v1/dispositivos/([^/]+)(?:/(ajustes|primer-plano))?/?")
# Lo que la app manda como plazo del primer plano (90 s) y lo que se acepta: un plazo enorme dejaría al vigía callado
# mucho tiempo si el «ya no estoy delante» se pierde, que es justo lo que el plazo existe para evitar.
CADUCA_POR_DEFECTO = 90.0
CADUCA_MAXIMA = 600.0
# Turnos que la app puede dejar vigilando de una vez (ampliación propuesta del contrato).
MAX_TURNOS = 20
PATRON_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")
CABECERA_TUNEL = "X-HeHermes-Vigia"
# Una petición sin la cabecera se apunta en el registro una vez cada diez minutos: un proceso insistiendo no lo inunda.
REPETIR_SIN_TUNEL = 600.0
# El permiso del relé (Contrato B): `hhp1.<carga>.<firma>`, las dos en base64url. Lo comprueba el relé; aquí solo que
# tenga su forma y un tamaño razonable, para no guardar ni mandar cualquier cosa en la cabecera Authorization.
PATRON_PERMISO = re.compile(r"hhp1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
MAX_PERMISO = 1024
PATRON_HUELLA = re.compile(r"[A-Za-z0-9_-]{43}")
# Quitar un iPhone desde la app (contrato §12.10): la ruta de la pasarela, sus cabeceras y lo que va delante de lo que se
# firma (lo mismo que `hehermes_servidor.dispositivos`, en el instalador: el vector de las pruebas es el mismo).
RUTA_BARRIDO = "/avisos/v1/iphones/barrer"
CABECERA_IPHONE = "X-HeHermes-Iphone"
CABECERA_FIRMA = "X-HeHermes-Firma"
_FIRMA_IPHONE = b"hehermes-iphone/v1\x00"
_FIRMA_BARRIDO = b"hehermes-barrido/v1\x00"
PATRON_IPHONE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
PATRON_MARCA = re.compile(r"[0-9a-f]{16}")
# Los tokens de una pasarela que caben en un barrido: muchos más de los que tendrá nadie.
MAX_QUEDAN = 256


def _es_entero(valor: object) -> bool:
    return isinstance(valor, int) and not isinstance(valor, bool)


def permiso_valido(dato: object) -> Permiso:
    """El ``permiso`` del alta (Contrato C), o ``400 permiso_invalido``. La dirección del relé la trae la app, y el alta
    la puede mandar cualquiera con un token de la pasarela: tiene que ser una IP pública o un nombre (que al conectar
    también tendrá que dar una pública), nunca una de la red de dentro."""
    invalido = ErrorHTTP(400, "permiso_invalido", "El permiso del relé no tiene su forma")
    if not isinstance(dato, dict):
        raise invalido
    valor, caduca, rele = dato.get("valor"), dato.get("caduca"), dato.get("rele")
    if not (isinstance(valor, str) and len(valor) <= MAX_PERMISO and PATRON_PERMISO.fullmatch(valor)):
        raise invalido
    if not _es_entero(caduca) or caduca <= 0 or not isinstance(rele, dict):
        raise invalido
    direccion, puerto, huella = rele.get("direccion"), rele.get("puerto"), rele.get("huella")
    if not isinstance(direccion, str) or not (es_ip_publica(direccion) or _es_nombre(direccion)):
        raise ErrorHTTP(400, "permiso_invalido", "La dirección del relé tiene que ser una IP pública o un nombre")
    if not _es_entero(puerto) or not 0 < puerto < 65536:
        raise invalido
    if not (isinstance(huella, str) and PATRON_HUELLA.fullmatch(huella)):
        raise invalido
    return Permiso(valor=valor, caduca=caduca, direccion=direccion, puerto=puerto, huella=huella)


def _es_nombre(direccion: str) -> bool:
    """Un nombre, y no algo que parezca una IP: «10.0.0.1» es una IP (privada), no un nombre que resolver."""
    try:
        ipaddress.ip_address(direccion)
        return False
    except ValueError:
        return es_nombre_dns(direccion)


def token_valido(texto: object) -> str:
    """El token en hexadecimal y en minúsculas, que es como lo manda la app y como lo quiere Apple en su ruta."""
    if not isinstance(texto, str) or not PATRON_TOKEN.fullmatch(texto.lower()):
        raise ErrorHTTP(400, "token_invalido", "El token tiene que ser el de APNs en hexadecimal")
    return texto.lower()


class AppVigia:
    """La lógica de la API, sin HTTP: así se prueba llamándola, y el manejador solo traduce."""

    def __init__(self, almacen: Almacen, mensajero: Mensajero, *, secreto_tunel: str, caducidad_prueba: int = 300,
                 reloj=time.time, al_moverse=None, ficheros: Ficheros | None = None,
                 respaldos: Respaldos | None = None, exportaciones=None, entradas: Entradas | None = None,
                 servidor: Servidor | None = None, agentes: Agentes | None = None, buzon=None):
        if not secreto_tunel:
            raise ValueError("sin el secreto del túnel, la API del vigía quedaría abierta a cualquier proceso local")
        self.almacen = almacen
        self.mensajero = mensajero
        self.caducidad_prueba = caducidad_prueba
        self.reloj = reloj
        self._secreto = secreto_tunel.encode("utf-8")
        # Lo que hay que hacer cuando una app se va a segundo plano o deja turnos: despertar al bucle (`Vigilante`).
        self.al_moverse = al_moverse or (lambda: None)
        self._ultimo_sin_tunel = -REPETIR_SIN_TUNEL
        # Los ficheros que Hermes marca con `MEDIA:` (`fichero.py`). Sin ellos, la ruta contesta 503.
        self.ficheros = ficheros
        # La copia de Hermes en iCloud (`respaldo.py`). Sin el ayudante, esas rutas contestan 503.
        self.respaldos = respaldos
        # Lo que la vigilancia de `exports/` ha visto llegar (`exportaciones.py`). Sin ella, la lista sale vacía.
        self.exportaciones = exportaciones
        # Lo que la app le manda a Hermes (`entrada.py`). Sin el ayudante, esas rutas contestan 503.
        self.entradas = entradas
        # Ajustes › Tu servidor (`servidor.py`). Sin él, como un vigía de antes: 404 `ruta_desconocida`.
        self.servidor = servidor
        # Los agentes (`agentes.py`, contrato §18). Sin ellos, como un vigía de antes: 404 `ruta_desconocida`.
        self.agentes = agentes
        # Lo que el instalador deja para avisar del código de recuperación (`recuperacion.Buzon`): mientras quede algo
        # por mandar, el barrido espera (`barrer`). Sin él, nada que esperar.
        self.buzon = buzon

    def _mac(self, prefijo: bytes, datos: bytes) -> str:
        resumen = hmac.new(self._secreto, prefijo + datos, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(resumen).rstrip(b"=").decode("ascii")

    def iphone_de(self, valor: str | None) -> Iphone | None:
        """El iPhone de la pasarela que manda la petición (``X-HeHermes-Iphone``: su nombre, la marca de su token y su
        firma), o None si no viene o su firma no vale: entonces no se sabe de quién es. Ni el nombre solo ni una firma
        que no es la de este nombre con esta marca valen para nada."""
        if not isinstance(valor, str):
            return None
        partes = valor.strip().split(" ")
        if len(partes) != 3 or not PATRON_IPHONE.fullmatch(partes[0]) or not PATRON_MARCA.fullmatch(partes[1]):
            return None
        nombre, marca, firma = partes
        buena = self._mac(_FIRMA_IPHONE, ("%s\x00%s" % (nombre, marca)).encode("ascii"))
        if not hmac.compare_digest(firma.encode("utf-8", "surrogateescape"), buena.encode("ascii")):
            return None
        return Iphone(nombre, marca)

    def barrer(self, cuerpo: bytes, firma: str | None) -> dict:
        """``POST /avisos/v1/iphones/barrer`` ``{"quedan": [<marcas>]}``, de la pasarela al quitar un iPhone desde la
        app: borra las altas que no son de ninguno de los tokens de ``quedan``. Solo con la firma del cuerpo
        (``X-HeHermes-Firma``). **Nunca antes de un aviso del código de recuperación por mandar** (``409``): quien
        acaba de entrar con el código no puede quitar a los demás iPhone antes de que se enteren. La pasarela lo vuelve
        a pedir cada minuto, y el bucle se despierta para mandarlo ya."""
        buena = self._mac(_FIRMA_BARRIDO, cuerpo)
        if not isinstance(firma, str) or not hmac.compare_digest(firma.encode("utf-8", "surrogateescape"),
                                                                 buena.encode("ascii")):
            raise ErrorHTTP(403, "sin_firma", "Esto solo lo pide la pasarela")
        try:
            quedan = json.loads(cuerpo.decode("utf-8")).get("quedan")
        except (UnicodeDecodeError, ValueError, AttributeError):
            quedan = None
        if not isinstance(quedan, list) or len(quedan) > MAX_QUEDAN or not all(
                isinstance(m, str) and PATRON_MARCA.fullmatch(m) for m in quedan):
            raise ErrorHTTP(400, "parametro_invalido", "«quedan» tiene que ser una lista de marcas de token")
        if self.buzon is not None and self.buzon.hay_por_avisar():
            self.al_moverse()
            registro.info("un iPhone quitado desde la app: sus altas de avisos esperan a que salga el aviso del código "
                          "de recuperación")
            raise ErrorHTTP(409, "aviso_pendiente", "Antes hay que mandar el aviso del código de recuperación")
        borradas = self.almacen.borrar_las_ajenas(quedan)
        registro.info("un iPhone quitado desde la app: %d altas de avisos borradas, quedan %d tokens", borradas,
                      len(quedan))
        return {"borradas": borradas}

    def viene_del_tunel(self, valor: str | None) -> bool:
        """Si la petición trae el secreto que pone nginx. Comparado en tiempo constante."""
        if not isinstance(valor, str):
            return False
        return hmac.compare_digest(valor.encode("utf-8", "surrogateescape"), self._secreto)

    def rechazar_fuera_del_tunel(self) -> None:
        ahora = self.reloj()
        if ahora - self._ultimo_sin_tunel >= REPETIR_SIN_TUNEL:
            self._ultimo_sin_tunel = ahora
            registro.warning("petición a la API del vigía sin la cabecera del túnel: 403 (no llegó por nginx)")
        raise ErrorHTTP(403, "fuera_del_tunel", "El vigía solo atiende lo que llega por el túnel")

    def alta(self, cuerpo: dict, iphone: Iphone | None = None) -> dict:
        """Guarda el iPhone y contesta con qué se mandarán sus avisos: ``{"envio": "credencial" | "permiso" |
        "ninguno"}``. Un alta sin ``permiso`` no borra el que había. ``iphone``: el de la pasarela que la hace, si su
        firma vale (``iphone_de``)."""
        token = token_valido(cuerpo.get("token"))
        entorno = cuerpo.get("entorno")
        if entorno not in ENTORNOS:
            raise ErrorHTTP(400, "entorno_invalido", "El entorno tiene que ser «sandbox» o «production»")
        try:
            clave = cifrado.clave_desde_base64(cuerpo.get("clave"))
        except cifrado.ErrorDeCifrado:
            raise ErrorHTTP(400, "clave_invalida", "La clave tiene que ser base64 de 32 bytes") from None
        permiso = permiso_valido(cuerpo["permiso"]) if cuerpo.get("permiso") is not None else None
        ajustes = Ajustes.desde_json(cuerpo.get("ajustes"))
        antes = self.almacen.dispositivo(token)
        ahora = self.reloj()
        nuevo = self.almacen.guardar_dispositivo(token, entorno, clave, ajustes, ahora, permiso=permiso, iphone=iphone)
        envio = self.mensajero.como_envia(self.almacen.dispositivo(token), ahora)
        registro.info("%s de %s (%s); ajustes: %s; avisos: %s%s", "alta" if nuevo else "alta renovada", cola(token),
                      entorno, ajustes.cambios(antes.ajustes if antes else None), envio,
                      "" if permiso is None else " (con un permiso nuevo, hasta %s)" % _fecha(permiso.caduca))
        _si_no_avisa_de_nada(token, ajustes)
        self.al_moverse()
        return {"envio": envio}

    def ajustes(self, token: str, cuerpo: dict) -> None:
        ajustes = Ajustes.desde_json(cuerpo)
        antes = self.almacen.dispositivo(token)
        if antes is None or not self.almacen.cambiar_ajustes(token, ajustes, self.reloj()):
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no está dado de alta")
        registro.info("ajustes de %s al día: %s", cola(token), ajustes.cambios(antes.ajustes))
        _si_no_avisa_de_nada(token, ajustes)

    def primer_plano(self, token: str, cuerpo: dict, iphone: Iphone | None = None) -> dict | None:
        """``{"permiso": "renovar"}`` si la app tiene que pedir otro permiso al relé y repetir el alta (sin credencial,
        y el suyo falta, caduca en menos de 7 días o el relé lo ha rechazado); si no, None (204)."""
        activa = cuerpo.get("activa") is True
        conversacion = cuerpo.get("conversacion")
        if not (isinstance(conversacion, str) and 0 < len(conversacion) <= MAX_ID_SESION):
            conversacion = None
        caduca = cuerpo.get("caduca")
        if not isinstance(caduca, (int, float)) or isinstance(caduca, bool) or caduca <= 0:
            caduca = CADUCA_POR_DEFECTO
        ahora = self.reloj()
        if not self.almacen.cambiar_primer_plano(token, activa, conversacion, min(float(caduca), CADUCA_MAXIMA),
                                                 ahora):
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no está dado de alta")
        if iphone is not None:
            self.almacen.vincular(token, iphone)
        turnos = _turnos(cuerpo.get("turnos"))
        self.almacen.vigilar_turnos(turnos, ahora)
        if not activa or turnos:
            self.al_moverse()
        dispositivo = self.almacen.dispositivo(token)
        if dispositivo is not None and self.mensajero.pide_renovar(dispositivo, ahora):
            return {"permiso": "renovar"}
        return None

    def prueba(self, cuerpo: dict) -> None:
        token = token_valido(cuerpo.get("token"))
        dispositivo = self.almacen.dispositivo(token)
        if dispositivo is None:
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no está dado de alta")
        resultado = self.mensajero.enviar(avisos.aviso_de_prueba(self.reloj(), self.caducidad_prueba), dispositivo)
        if resultado.tipo == ENVIADO:
            return
        if resultado.tipo == BAJA:
            raise ErrorHTTP(410, "token_caducado", "Apple dice que este token ya no vale: se ha dado de baja")
        if resultado.tipo == LIMITADO:
            raise ErrorHTTP(429, "demasiados_avisos", "Demasiados avisos seguidos",
                            {"Retry-After": str(int(resultado.esperar or 5))})
        if resultado.tipo == SIN_PERMISO:
            raise ErrorHTTP(502, "sin_permiso", "Este vigía no tiene credencial y el iPhone no le ha dado un permiso "
                                                "vigente del relé")
        if resultado.tipo == PERMISO:
            raise ErrorHTTP(502, "permiso_rechazado", f"El relé no acepta el permiso de este iPhone: {resultado.motivo}")
        codigo = "rele_no_disponible" if resultado.tipo == REINTENTABLE else "aviso_rechazado"
        raise ErrorHTTP(502, codigo, f"El aviso no ha salido: {resultado.motivo}")

    def fichero(self, consulta: dict) -> Descarga:
        if self.ficheros is None:
            raise ErrorHTTP(503, "lector_no_disponible", "Este vigía no tiene el lector de ficheros")
        return self.ficheros.preparar(consulta.get("sesion"), consulta.get("ruta"), consulta.get("perfil", PRINCIPAL))

    def ficheros_dejados(self, sesion: object, perfil: object = PRINCIPAL) -> dict:
        """``GET /avisos/v1/ficheros?sesion=&perfil=``: lo que Hermes ha dejado en el ``exports/`` de ese perfil para
        esa conversación (``exportaciones``), del más reciente al más antiguo. La app lo enseña como «Hermes ha dejado un
        fichero», aunque Hermes aún no haya escrito su línea ``MEDIA:``. Solo nombres, tamaños y horas de lo que ya es
        del iPhone."""
        if not (isinstance(sesion, str) and PATRON_SESION.fullmatch(sesion)):
            raise ErrorHTTP(400, "parametro_invalido", "Falta la sesión, o no tiene forma de sesión")
        perfil = perfil_valido(perfil)
        if self.exportaciones is None:
            return {"ficheros": []}
        if hasattr(self.exportaciones, "de"):
            de_ese = self.exportaciones.de(perfil)
        else:
            de_ese = self.exportaciones if perfil == PRINCIPAL else None
        if de_ese is None:
            return {"ficheros": []}
        return {"ficheros": [{"ruta": f.ruta, "nombre": f.nombre, "tamano": f.tamano, "instante": f.instante}
                             for f in de_ese.de_la_sesion(sesion)]}

    def baja(self, token: str) -> None:
        if not self.almacen.borrar_dispositivo(token):
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no estaba dado de alta")
        registro.info("baja de %s", cola(token))


def _fecha(instante: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(instante))


def _si_no_avisa_de_nada(token: str, ajustes: Ajustes) -> None:
    """Un iPhone que no quiere ningún aviso es casi siempre un fallo, no una decisión: el 2026-09-27 el de Daniel llegó
    así en cada alta, y solo se vio cuando una respuesta no le avisó. Apagarlo todo a propósito es el interruptor
    general de la app, que no manda esto: da de baja el iPhone."""
    if ajustes.todos_apagados:
        registro.warning("%s tiene los cuatro tipos de aviso apagados: solo le llegará el aviso de prueba", cola(token))


def _turnos(lista: object) -> list:
    """Los turnos de ``{"turnos": [{"run_id": …, "sesion": …, "perfil": …}]}``, si vienen (``perfil``, desde la 1.6.0:
    el de un agente; sin él, el principal). Lo que no tenga forma se ignora: es una ampliación opcional y una app que la
    mande mal no puede quedarse sin su primer plano."""
    if not isinstance(lista, list):
        return []
    turnos = []
    for turno in lista[:MAX_TURNOS]:
        if isinstance(turno, dict):
            run_id, sesion, perfil = turno.get("run_id"), turno.get("sesion"), turno.get("perfil", PRINCIPAL)
            if (isinstance(run_id, str) and PATRON_ID.fullmatch(run_id) and isinstance(sesion, str)
                    and PATRON_ID.fullmatch(sesion) and isinstance(perfil, str) and PATRON_PERFIL.fullmatch(perfil)):
                turnos.append((run_id, sesion, perfil))
    return turnos


class ManejadorVigia(ManejadorJSON):
    # Cambiar un agente (`PATCH /avisos/v1/agentes/{perfil}`, desde la 1.6.0): el único PATCH del vigía.
    do_PATCH = ManejadorJSON._despachar

    def nombre_registro(self) -> str:
        return "vigia.api"

    def atender(self) -> None:
        app: AppVigia = self.server.app
        if not app.viene_del_tunel(self.headers.get(CABECERA_TUNEL)):
            app.rechazar_fuera_del_tunel()
        ruta, metodo = self.ruta, self.command
        if ruta == "/avisos/v1/dispositivos":
            self._exigir(metodo, "POST")
            return self.enviar_json(200, app.alta(self.leer_json(), app.iphone_de(self.headers.get(CABECERA_IPHONE))))
        elif ruta == RUTA_BARRIDO:
            self._exigir(metodo, "POST")
            return self.enviar_json(200, app.barrer(self.leer_cuerpo(), self.headers.get(CABECERA_FIRMA)))
        elif ruta == "/avisos/v1/prueba":
            self._exigir(metodo, "POST")
            app.prueba(self.leer_json())
        elif ruta == "/avisos/v1/salud":
            self._exigir(metodo, "GET")
            return self.enviar_json(200, {"estado": "ok", "servicio": "vigia", "version": VERSION})
        elif ruta.startswith(PREFIJO_RESPALDO):
            return self._respaldo(app)
        elif ruta.startswith(PREFIJO_ENTRADA):
            return self._entrada(app)
        elif ruta == PREFIJO_SERVIDOR or ruta.startswith(PREFIJO_SERVIDOR + "/"):
            return self._servidor(app)
        elif ruta == PREFIJO_AGENTES or ruta.startswith(PREFIJO_AGENTES + "/"):
            return self._agentes(app)
        elif ruta == "/avisos/v1/fichero":
            self._exigir(metodo, "GET")
            consulta = self.path.partition("?")[2]
            sesion, ruta_fichero = parametros(consulta)
            return self._enviar_descarga(app.fichero({"sesion": sesion, "ruta": ruta_fichero,
                                                      "perfil": perfil_de_la_consulta(consulta)}))
        elif ruta == "/avisos/v1/ficheros":
            self._exigir(metodo, "GET")
            consulta = self.path.partition("?")[2]
            sesion, _ = parametros(consulta)
            return self.enviar_json(200, app.ficheros_dejados(sesion, perfil_de_la_consulta(consulta)))
        else:
            encontrada = RUTA_DISPOSITIVO.fullmatch(ruta)
            if not encontrada:
                raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
            token = token_valido(encontrada.group(1))
            if encontrada.group(2) is None:
                self._exigir(metodo, "DELETE")
                app.baja(token)
            elif encontrada.group(2) == "ajustes":
                self._exigir(metodo, "PUT")
                app.ajustes(token, self.leer_json())
            else:
                self._exigir(metodo, "PUT")
                renovar = app.primer_plano(token, self.leer_json(), app.iphone_de(self.headers.get(CABECERA_IPHONE)))
                if renovar is not None:
                    return self.enviar_json(200, renovar)
        self.enviar_json(204)

    def _respaldo(self, app: AppVigia) -> None:
        """La copia en iCloud: cuerpos de hasta 4 MiB + 64 KiB (un trozo o un manifiesto) y, en los trozos, bytes."""
        if app.respaldos is None:
            raise ErrorHTTP(503, "respaldo_no_disponible", "Este vigía no tiene el ayudante de la copia")
        self.tope_cuerpo = TOPE_RESPALDO
        estado, objeto, datos, cabeceras = app.respaldos.atender(self.command, self.ruta, self.leer_cuerpo,
                                                                   self.headers)
        if datos is None:
            return self.enviar_json(estado, objeto)
        self.send_response(estado)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(datos)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for nombre, valor in cabeceras.items():
            self.send_header(nombre, valor)
        self.end_headers()
        try:
            self.wfile.write(datos)
            self.wfile.flush()
        except OSError:
            self.close_connection = True

    def _entrada(self, app: AppVigia) -> None:
        """Lo que la app le manda a Hermes: cuerpos de hasta 4 MiB + 64 KiB (un trozo, sin comprimir)."""
        if app.entradas is None:
            raise ErrorHTTP(503, "entrada_no_disponible", "Este vigía no tiene el ayudante de la entrada")
        self.tope_cuerpo = TOPE_ENTRADA
        perfil = perfil_de_la_consulta(self.path.partition("?")[2])
        estado, objeto, cabeceras = app.entradas.atender(self.command, self.ruta, self.leer_cuerpo, self.headers,
                                                         perfil=perfil)
        return self.enviar_json(estado, objeto, cabeceras)

    def _agentes(self, app: AppVigia) -> None:
        """Los agentes (contrato §18): la lista, crear, ver, cambiar y borrar con su ayudante, y la personalidad."""
        if app.agentes is None:
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        estado, objeto, cabeceras = app.agentes.atender(self.command, self.ruta, self.leer_cuerpo)
        return self.enviar_json(estado, objeto, cabeceras)

    def _servidor(self, app: AppVigia) -> None:
        """Ajustes › Tu servidor: el estado (sin secretos) y la actualización."""
        if app.servidor is None:
            raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
        estado, objeto, cabeceras = app.servidor.atender(self.command, self.ruta, self.leer_cuerpo)
        return self.enviar_json(estado, objeto, cabeceras)

    def _enviar_descarga(self, descarga: Descarga) -> None:
        """Los bytes según llegan del lector, sin juntarlos. Con las cabeceras ya mandadas un fallo no se puede
        contestar: se corta la conexión, y la app ve que faltan bytes (`Content-Length`)."""
        enviados = 0
        try:
            self.send_response(200)
            self.send_header("Content-Type", descarga.tipo)
            self.send_header("Content-Length", str(descarga.tamano))
            self.send_header("Content-Disposition", disposicion(descarga.nombre))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # Que nginx lo pase según llega, sin guardarlo en sus temporales del disco.
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            for trozo in descarga.trozos():
                self.wfile.write(trozo)
                enviados += len(trozo)
            self.wfile.flush()
        except OSError:
            pass
        finally:
            descarga.cerrar()
        if enviados != descarga.tamano:
            self.close_connection = True
            registro.warning("fichero: cortado a los %d de %d bytes", enviados, descarga.tamano)

    @staticmethod
    def _exigir(metodo: str, permitido: str) -> None:
        if metodo != permitido:
            raise ErrorHTTP(405, "metodo_no_permitido", f"Aquí solo vale {permitido}", {"Allow": permitido})
