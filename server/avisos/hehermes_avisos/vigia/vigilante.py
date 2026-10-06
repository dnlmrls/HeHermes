"""El bucle del vigía. Cada pocos segundos:

1. lee la bandeja de Hermes (``GET /api/sessions``) y, de las sesiones que han cambiado (``last_active`` o
   ``message_count`` distintos de la vuelta anterior), lee sus últimas filas;
2. si una entrega de un subagente se ha quedado sin contestar, lanza el turno de continuación de la app
   (``entregas``): Hermes no lo lanza nunca en el api_server, y con el iPhone dormido la app tampoco;
3. decide qué avisar (``deteccion``), a qué iPhone (``avisos.decidir``) y lo manda (``envio``);
4. mira el estado de los turnos que la app dejó en marcha, si se los ha dicho: es lo único que deja ver las aprobaciones
   que esperan y los errores sin abrir el SSE del run, que es de un solo uso y es de la app.

**Cada agente es un perfil de Hermes** (contrato §18, desde la 1.6.0): lo de arriba se hace con el principal y con cada
perfil servido (``agentes``: los que tienen su clave), cada uno con su cliente (``/p/<perfil>/…``), y lo que se apunta
de cada conversación va por ``(perfil, sesión)``: cada perfil tiene su state.db, y sus sesiones (y hasta sus filas)
pueden llamarse igual. Cada aviso sale con su perfil. Un agente que no contesta no para a los demás.

**Cada conversación va por su cuenta.** Se lee, se avisa de lo suyo y se apunta en SQLite antes de pasar a la
siguiente, y un fallo en una (una fila que rompe algo, el disco lleno) no para las demás. Lo que el relé ya aceptó se
recuerda una hora (``_aceptados``): si apuntarlo falla, la vuelta siguiente vuelve a encontrar lo mismo y no lo vuelve a
mandar. Era lo que pasaba antes: con el disco lleno, el mismo aviso salía cada cinco segundos.

**Lo que no sale se vuelve a buscar.** Un aviso que no ha podido salir (el relé reiniciándose, Apple caída) no da su
conversación por leída: la vuelta siguiente lo vuelve a encontrar en el historial y lo intenta otra vez, con una espera
creciente entre intentos (``_esperas``). Así sobrevive también a un reinicio del vigía, y se acaba solo cuando la fila
pasa de ``antiguedad_maxima``.

**Lo del código de recuperación** (``recuperacion``, contrato §12.9): al empezar cada vuelta, lo que el instalador ha
dejado en el buzón se avisa a los iPhone dados de alta (menos a las altas del token del que entra) y se borra, y con él
las altas del token de antes de ese iPhone, si ya estaba con su nombre; lo que no sale se queda para la siguiente. Va
antes de leer a Hermes: no depende de que Hermes conteste.

**Lo justo para Hermes.** Sin ningún iPhone dado de alta no se lee nada (antes: 17 280 lecturas de la bandeja al día
para nadie). Con uno, cada 5 s mientras pasa algo (una conversación cambia, una app está delante o se acaba de ir,
hay turnos vigilados o algo pendiente) y cada 25 s tras tres minutos de calma; una app que se va despierta al bucle al
momento (``despertar``). De cada conversación que cambia se leen 20 filas, y 100 solo si en esas 20 no está la petición
que abrió el turno. Y en SQLite solo se escribe lo que cambia: antes se reescribía la bandeja entera en cada vuelta,
272 MiB al día de WAL sin que pasara nada.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, replace

from .. import texto
from ..comun import cola
from . import avisos, deteccion, entregas, exportaciones, recuperacion
from .almacen import PRINCIPAL, Almacen, EstadoSesion
from .envio import ENVIADO, LIMITADO, REINTENTABLE, Mensajero
from .hermes import ClienteHermes, ErrorHermes

registro = logging.getLogger("vigia")

# Esperas antes de cada reintento de un aviso que falló por algo pasajero; a partir del último, la misma.
REINTENTOS = (5.0, 20.0, 60.0)
# Lo que se recuerda que el relé aceptó un aviso. Basta con que cubra la antigüedad máxima de lo que se avisa.
RECORDAR_ACEPTADOS = 3600.0
# Una sesión que aparece en la bandeja después de la primera vuelta: lo escrito desde la vuelta anterior es nuevo. El
# margen cubre lo que tarda Hermes entre escribir una fila y enseñar la sesión en la bandeja.
MARGEN_SESION_NUEVA = 30.0
# Se olvidan las sesiones que llevan un mes sin salir en la bandeja, y los turnos pasadas dos horas, que es el tope de
# un turno en el VPS (`agent.gateway_timeout: 7200`).
OLVIDAR_SESIONES = 30 * 86400.0
VIDA_DE_UN_TURNO = 7200.0
CADA_CUANTO_PODAR = 3600.0
ESPERA_MAXIMA_TRAS_FALLOS = 60.0
# Un mismo fallo se apunta en el registro una vez cada diez minutos, no en cada vuelta.
REPETIR_UN_FALLO = 600.0
# El ritmo: cada `intervalo` mientras pasa algo, cada `intervalo_en_calma` tras `CALMA` segundos sin nada.
INTERVALO_EN_CALMA = 25.0
CALMA = 180.0
# Filas de la primera lectura de una conversación que ha cambiado; si en ellas no está la petición del turno, se lee
# `filas_por_lectura`.
LECTURA_CORTA = 20
# Cada cuánto se reescribe, como mucho, lo que no cambia: cuándo salió una conversación en la bandeja (sirve para
# olvidarla al mes) y cuándo fue la vuelta anterior (la línea de base de una conversación nueva tras un reinicio).
REFRESCAR_VISTO = 86400.0
GUARDAR_VUELTA = 300.0


def _numero(valor) -> float | None:
    return float(valor) if isinstance(valor, (int, float)) and not isinstance(valor, bool) else None


def _entero(valor) -> int | None:
    return valor if isinstance(valor, int) and not isinstance(valor, bool) else None


@dataclass(frozen=True)
class _Espera:
    fallos: int
    hasta: float


# Lo que se espera, tras lanzar una continuación, a ver su fila en el historial. Hermes la escribe al empezar el turno,
# en menos de un segundo; si en dos minutos no está, algo va mal y se deja de insistir: se avisa de la entrega.
VER_LA_CONTINUACION = 120.0
# Lo que se insiste en lanzar una continuación que falla por algo pasajero (Hermes reiniciándose, un 429, un 5xx).
INSISTIR_EN_LA_CONTINUACION = 1800.0


ReglasDeEntrega = entregas.ReglasDeEntrega


@dataclass(frozen=True)
class _Continuacion:
    """Lo que el vigía ha hecho con la entrega de una delegación: lanzada (``run_id``), esperando a reintentar o
    rendida (se avisa de la entrega, como antes)."""

    desde: float
    run_id: str | None = None
    lanzada: float | None = None
    fallos: int = 0
    hasta: float = 0.0
    rendida: bool = False


class Vigilante:
    def __init__(self, almacen: Almacen, hermes: ClienteHermes, mensajero: Mensajero, *, intervalo: float = 5.0,
                 intervalo_en_calma: float = INTERVALO_EN_CALMA, antiguedad_maxima: float = 900.0,
                 filas_por_lectura: int = 100, caducidad_aprobacion: int = 120, reloj=time.time,
                 reglas_entrega: ReglasDeEntrega | None = None, exportaciones=None, agentes=None, buzon=None):
        self.almacen = almacen
        # Lo que el instalador deja para avisar del código de recuperación (`recuperacion.Buzon`). Sin buzón, nada de
        # esto. De qué iPhone es cada alta (para no avisarle al que entra) lo dice su dueño firmado, en el almacén.
        self.buzon = buzon
        self._buzon_pendiente = False
        # Los ficheros nuevos de `exports/` que hay que avisar (`exportaciones`), si se vigila la carpeta: la del
        # principal (`Exportaciones`) o la de cada perfil (`ExportacionesDeLosAgentes`, con su `de(perfil)`).
        self.exportaciones = exportaciones
        # Los agentes servidos (`agentes.ClientesDeLosAgentes`, con su `clientes()`: perfil -> su cliente de Hermes).
        # Sin ellos, solo el principal, como antes de la 1.6.0.
        self.agentes = agentes
        # Sin reglas, el vigía no contesta ninguna entrega: solo avisa de ella.
        self.reglas_entrega = reglas_entrega
        # (sesión, delegation_id) → lo hecho con su entrega. En memoria: tras un reinicio, la misma clave de
        # idempotencia hace que relanzarla dé el mismo turno, no otro.
        self._continuaciones: dict = {}
        self.hermes = hermes
        self.mensajero = mensajero
        self.intervalo = intervalo
        self.intervalo_en_calma = max(intervalo, intervalo_en_calma)
        self.antiguedad_maxima = antiguedad_maxima
        self.filas_por_lectura = filas_por_lectura
        self.caducidad_aprobacion = caducidad_aprobacion
        self.reloj = reloj
        # (perfil, sesión) → su título en la bandeja.
        self._titulos: dict = {}
        # (token, identidad del suceso) → cuándo lo aceptó el relé.
        self._aceptados: dict = {}
        # (token, identidad del suceso) → hasta cuándo esperar antes de volver a intentarlo.
        self._esperas: dict = {}
        self._fallos_apuntados: dict = {}
        self._ultima_poda = 0.0
        self._despertador = threading.Event()
        # Cuándo pasó algo por última vez: al arrancar, ahora, para empezar deprisa.
        self._ultimo_movimiento = reloj()
        self._pendiente_en_la_vuelta = False
        # Si hay que rehacer la línea de base: se han quedado sin iPhone, y lo que pasó mientras no se avisa a nadie.
        self._rebasar = False
        self._vuelta_anterior: float | None = None
        self._vuelta_guardada = -GUARDAR_VUELTA
        # Lo que dijo la bandeja de cada conversación ((perfil, sesión)) en la vuelta anterior: moverse es que eso cambie,
        # no releer una conversación porque tiene algo pendiente.
        self._en_bandeja: dict = {}

    # -- El bucle

    def correr(self, parar: threading.Event) -> None:
        fallos = 0
        while not parar.is_set():
            try:
                self.vuelta()
                if fallos:
                    registro.info("Hermes vuelve a contestar tras %d vueltas fallidas", fallos)
                fallos = 0
                espera = self.siguiente_espera()
            except ErrorHermes as error:
                fallos += 1
                # Sin Hermes no hay nada que avisar: se espera cada vez más (hasta un minuto) y se dice una vez, no
                # cada cinco segundos.
                if fallos == 1 or fallos % 60 == 0:
                    registro.warning("%s (vuelta fallida %d; se reintenta)", error, fallos)
                espera = min(self.intervalo * 2 ** min(fallos, 6), ESPERA_MAXIMA_TRAS_FALLOS)
            except Exception:  # noqa: BLE001 — una vuelta rota no puede parar el vigía
                self._apuntar_fallo("vuelta", "fallo inesperado en una vuelta", excepcion=True)
                espera = self.intervalo
            self._esperar(espera, parar)

    def despertar(self) -> None:
        """Una app se ha ido a segundo plano, se ha dado de alta o ha dejado turnos: la vuelta siguiente, ya, y deprisa
        durante un rato."""
        self._ultimo_movimiento = self.reloj()
        self._despertador.set()

    def siguiente_espera(self) -> float:
        """Cuánto esperar hasta la vuelta siguiente: poco mientras pase algo, y más en calma."""
        ahora = self.reloj()
        if self._pendiente_en_la_vuelta or self._buzon_pendiente or ahora - self._ultimo_movimiento < CALMA:
            return self.intervalo
        if self.almacen.turnos():
            return self.intervalo
        for dispositivo in self.almacen.dispositivos():
            fin = dispositivo.fin_de_delante()
            # Delante ahora (el fin está por llegar) o hace poco: lo que espera a saber si la app lo vio se decide al
            # caducar el plazo, y no puede esperar 25 s más.
            if fin is not None and ahora - fin < CALMA:
                return self.intervalo
        return self.intervalo_en_calma

    def _esperar(self, segundos: float, parar: threading.Event) -> None:
        # A trozos de medio segundo, para enterarse también de `parar`, que es otro evento.
        fin = time.monotonic() + segundos
        while not parar.is_set():
            restante = fin - time.monotonic()
            if restante <= 0 or self._despertador.wait(min(restante, 0.5)):
                break
        self._despertador.clear()

    def _clientes(self) -> dict:
        """El cliente de Hermes de cada perfil que se vigila: el del principal y el de cada agente servido."""
        clientes = {PRINCIPAL: self.hermes}
        if self.agentes is not None:
            try:
                for perfil, cliente in self.agentes.clientes().items():
                    if perfil != PRINCIPAL:
                        clientes[perfil] = cliente
            except Exception:  # noqa: BLE001 — sin la lista de los agentes, al menos el principal
                self._apuntar_fallo("agentes", "no se pudo saber qué agentes hay; solo el principal", excepcion=True)
        return clientes

    def vuelta(self) -> None:
        ahora = self.reloj()
        self._olvidar_lo_viejo(ahora)
        self._avisar_lo_del_buzon(ahora)
        clientes = self._clientes()
        if not self.almacen.dispositivos():
            # Nadie a quien avisar: no se molesta a Hermes. Lo que pase mientras no es de nadie, así que al volver a
            # haber un iPhone se rehace la línea de base en vez de avisarle de lo de antes de darse de alta.
            self._rebasar = True
            self._pendiente_en_la_vuelta = False
            # Salvo los ficheros nuevos de exports/: no se avisa de ellos, pero sí se busca su conversación, para
            # que la app los enseñe en ella (`GET /avisos/v1/ficheros`) aunque no tenga los avisos puestos.
            self._anunciar_ficheros(clientes, ahora, None)
            return
        # Sin el principal no hay vuelta (Hermes no contesta: se espera, `correr`). Un agente que no contesta se salta.
        bandejas = {PRINCIPAL: self.hermes.sesiones()}
        for perfil, cliente in clientes.items():
            if perfil == PRINCIPAL:
                continue
            try:
                bandejas[perfil] = cliente.sesiones()
            except ErrorHermes as error:
                self._apuntar_fallo(f"bandeja {perfil}", "no se pudo leer la bandeja del agente %s: %s", perfil, error)
        self._titulos = {(perfil, sesion["id"]): texto.titulo_de_sesion(sesion)
                         for perfil, bandeja in bandejas.items() for sesion in bandeja}
        self._revisar_turnos(clientes, ahora)
        self._revisar_bandejas(bandejas, clientes, ahora, rebasar=self._rebasar)
        self._rebasar = False
        self._anunciar_ficheros(clientes, ahora, bandejas)
        self._podar(ahora)

    # -- Los ficheros nuevos de exports/

    def _exportaciones_de(self, perfil: str):
        """Lo de exports/ de un perfil: la de cada uno (`de(perfil)`), o, con la del principal sola, esa."""
        if self.exportaciones is None:
            return None
        if hasattr(self.exportaciones, "de"):
            return self.exportaciones.de(perfil)
        return self.exportaciones if perfil == PRINCIPAL else None

    def _anunciar_ficheros(self, clientes: dict, ahora: float, bandejas: dict | None) -> None:
        for perfil, cliente in clientes.items():
            hechas = self._exportaciones_de(perfil)
            if hechas is None:
                continue
            bandeja = None if bandejas is None else bandejas.get(perfil)
            if bandejas is not None and bandeja is None:
                continue
            self._anunciar_ficheros_de(perfil, cliente, hechas, ahora, bandeja, sin_iphone=bandejas is None)

    def _anunciar_ficheros_de(self, perfil: str, cliente, hechas, ahora: float, bandeja: list | None,
                              sin_iphone: bool) -> None:
        """Avisa de los ficheros nuevos que ha visto la vigilancia del ``exports/`` de un perfil (``exportaciones``):
        primero se busca a qué conversación van (en su historial), y el aviso sale como cualquier otro, con su perfil,
        sus ajustes y sus reintentos. Lo que no sale se intenta en la vuelta siguiente. Sin iPhone no hay a quién
        avisar: solo se busca su conversación, para la app, y se dan por avisados."""
        pendientes = hechas.por_anunciar(ahora)
        if not pendientes:
            return
        sin_atribuir = [fichero for fichero in pendientes if not fichero.atribuido]
        if sin_atribuir:
            try:
                sesiones = exportaciones.atribuir(cliente, sin_atribuir, ahora, bandeja)
            except ErrorHermes as error:
                # Sin Hermes ahora, a la vuelta siguiente; si no caduca antes, se busca otra vez.
                self._apuntar_fallo(f"exportaciones {perfil}", "no se pudo buscar de qué conversación es un fichero "
                                    "nuevo: %s", error)
                self._pendiente_en_la_vuelta = True
                return
            pendientes = [hechas.atribuir(fichero, sesiones.get(fichero.nombre))
                          if not fichero.atribuido else fichero for fichero in pendientes]
        for fichero in pendientes:
            if sin_iphone:
                hechas.anunciado(fichero)
                continue
            try:
                titulo = (self._titulos.get((perfil, fichero.sesion)) if fichero.sesion else None) or "Hermes"
                aviso = avisos.Aviso(tipo="segundo-plano", sesion=fichero.sesion, titulo=titulo,
                                     texto=exportaciones.TEXTO.format(fichero.nombre), instante=fichero.instante,
                                     clave=fichero.clave, colapsa_con=f"fichero:{fichero.nombre}", perfil=perfil)
                if self._avisar(aviso, ahora):
                    hechas.anunciado(fichero)
                    registro.info("fichero nuevo de exports avisado%s",
                                  " (con su conversación)" if fichero.sesion else " (sin conversación)")
                else:
                    self._pendiente_en_la_vuelta = True
            except Exception:  # noqa: BLE001 — un fichero que rompe algo no puede dejar sin avisos al resto
                self._apuntar_fallo("exportaciones", "fallo avisando de un fichero nuevo de exports", excepcion=True)
                hechas.anunciado(fichero)

    # -- El código de recuperación

    def _avisar_lo_del_buzon(self, ahora: float) -> None:
        """Avisa de lo que el instalador ha dejado en el buzón (``recuperacion``): a todos los iPhone dados de alta menos
        a las altas del token del que entra, con los reintentos de siempre. Lo que ya no queda por mandar a nadie se
        borra; sin ningún iPhone, no hay a quién, y también. Lo de hace más de un día ya no se avisa: Ajustes › Tu
        servidor lo enseña igual."""
        if self.buzon is None:
            return
        self._buzon_pendiente = False
        try:
            sucesos = self.buzon.pendientes()
        except OSError as error:
            self._apuntar_fallo("buzon", "no se pudo mirar el buzón del código de recuperación: %s", error)
            return
        for suceso in sucesos:
            try:
                if self.buzon.caducado(suceso):
                    registro.info("un aviso del código de recuperación de hace más de un día: se borra sin mandarlo")
                elif self._avisar(recuperacion.aviso(suceso), ahora):
                    registro.info("aviso del código de recuperación (%s) resuelto", suceso.que)
                else:
                    self._buzon_pendiente = True
                    continue
                self._borrar_las_del_token_de_antes(suceso)
                self.buzon.hecho(suceso)
            except Exception:  # noqa: BLE001 — un suceso que rompe algo no puede repetirse en cada vuelta
                self._apuntar_fallo("buzon " + suceso.fichero, "fallo avisando del código de recuperación: se deja",
                                    excepcion=True)
                self.buzon.hecho(suceso)

    def _borrar_las_del_token_de_antes(self, suceso) -> None:
        """Un iPhone que ha vuelto con el código con su mismo nombre tiene otro token, y el de antes ya no vale: sus altas
        de avisos sobran. Se borran **después** de avisar, no antes: pueden ser de otro aparato al que alguien le ha
        quitado el nombre con el código, y es el primero que tiene que enterarse."""
        if suceso.anterior is None:
            return
        borradas = self.almacen.borrar_las_de_la_marca(suceso.anterior)
        if borradas:
            registro.info("%d altas de avisos del token de antes de un iPhone que ha vuelto con el código: borradas",
                          borradas)

    # -- La bandeja

    def _revisar_bandejas(self, bandejas: dict, clientes: dict, ahora: float, rebasar: bool = False) -> None:
        arrancado = self.almacen.leer_estado("arrancado") == "1" and not rebasar
        anterior = (self._vuelta_anterior or _numero_de_texto(self.almacen.leer_estado("ultima_vuelta"))
                    or ahora)
        conocidas = {} if rebasar else self.almacen.sesiones()
        self._pendiente_en_la_vuelta = False
        for perfil, bandeja in bandejas.items():
            for sesion in bandeja:
                sid = sesion["id"]
                huella = (sesion.get("last_active"), sesion.get("message_count"))
                if self._en_bandeja.get((perfil, sid)) != huella:
                    self._en_bandeja[(perfil, sid)] = huella
                    self._ultimo_movimiento = ahora
                donde = sid if perfil == PRINCIPAL else f"{perfil}/{sid}"
                try:
                    self._revisar_sesion(perfil, clientes[perfil], sesion, conocidas.get((perfil, sid)), arrancado,
                                         anterior, ahora)
                except ErrorHermes as error:
                    # Se deja como estaba, para que la vuelta siguiente la vea cambiada y lo intente otra vez.
                    self._apuntar_fallo(f"leer {donde}", "no se pudieron leer los mensajes de %s: %s", donde, error)
                except Exception:  # noqa: BLE001 — una conversación que falla no para las demás
                    self._apuntar_fallo(f"apuntar {donde}", "fallo apuntando lo leído de %s; se vuelve a intentar en "
                                        "la vuelta siguiente, sin repetir lo ya avisado", donde, excepcion=True)
        self._vuelta_anterior = ahora
        if not arrancado or ahora - self._vuelta_guardada >= GUARDAR_VUELTA:
            self.almacen.guardar_estado("ultima_vuelta", repr(ahora))
            self._vuelta_guardada = ahora
        if not arrancado:
            self.almacen.guardar_estado("arrancado", "1")
            registro.info("%s: %d conversaciones dadas por vistas", "vuelve a haber iPhone" if rebasar else
                          "primera vuelta", sum(len(bandeja) for bandeja in bandejas.values()))

    def _revisar_sesion(self, perfil: str, cliente, sesion: dict, estado: EstadoSesion | None, arrancado: bool,
                        anterior: float, ahora: float) -> None:
        sid = sesion["id"]
        actividad = _numero(sesion.get("last_active"))
        mensajes = _entero(sesion.get("message_count"))
        if estado is None:
            if not arrancado:
                # La primera vuelta de la vida del vigía: lo que ya hay se da por visto sin leerlo. Si no, el primer
                # arranque avisaría de todo el historial.
                self.almacen.guardar_sesion(EstadoSesion(sid, None, actividad or ahora, actividad, mensajes, ahora,
                                                         perfil=perfil))
                return
            # Aparece después (nueva, de un agente nuevo, o vuelve de más allá de las 200): es nuevo lo de desde la
            # vuelta anterior.
            estado = EstadoSesion(sid, None, anterior - MARGEN_SESION_NUEVA, None, None, ahora, perfil=perfil)
        elif actividad == estado.ultima_actividad and mensajes == estado.mensajes:
            if ahora - estado.visto >= REFRESCAR_VISTO:
                self.almacen.guardar_sesion(replace(estado, visto=ahora))
            return
        donde = sid if perfil == PRINCIPAL else f"{perfil}/{sid}"
        filas, limite = self._leer(cliente, sid)
        ids = [fila["id"] for fila in filas] + ([estado.ultimo_id] if estado.ultimo_id is not None else [])
        pendiente = None
        entregas_del_vigia = None
        try:
            entregas_del_vigia, volver = self._atender_entrega(perfil, cliente, sid, filas, ahora)
            if volver:
                pendiente = entregas_del_vigia
        except Exception:  # noqa: BLE001 — contestar una entrega no puede dejar la conversación sin avisos
            self._apuntar_fallo(f"entrega {donde}", "fallo contestando la entrega de %s: se avisa de ella", donde,
                                excepcion=True)
            entregas_del_vigia = None
        try:
            sucesos = deteccion.sucesos(filas, ultimo_id=estado.ultimo_id, referencia=estado.referencia, ahora=ahora,
                                        antiguedad_maxima=self.antiguedad_maxima, pagina_llena=len(filas) >= limite,
                                        entregas_del_vigia=entregas_del_vigia,
                                        ultima_respuesta=estado.ultima_respuesta)
            for suceso in sucesos:
                aviso = avisos.Aviso(tipo=suceso.tipo, sesion=sid, titulo=self._titulos.get((perfil, sid), "Hermes"),
                                     texto=suceso.texto, instante=suceso.instante, clave=suceso.clave, perfil=perfil)
                if not self._avisar(aviso, ahora):
                    pendiente = suceso.fila if pendiente is None else min(pendiente, suceso.fila)
        except Exception:  # noqa: BLE001 — una fila que rompe algo no puede repetirse en cada vuelta
            self._apuntar_fallo(f"avisar {donde}", "fallo avisando de %s: lo de ahora se da por leído para no "
                                "repetirlo en cada vuelta", donde, excepcion=True)
            pendiente = None
        if pendiente is None:
            self.almacen.guardar_sesion(EstadoSesion(sid, max(ids) if ids else None, estado.referencia, actividad,
                                                     mensajes, ahora,
                                                     deteccion.ultima_respuesta(filas, estado.ultima_respuesta),
                                                     perfil=perfil))
            return
        # Queda algo por mandar: leída solo hasta justo antes, para que la vuelta siguiente lo vuelva a encontrar, y con
        # la actividad de antes, para que la bandeja la dé por cambiada y se vuelva a leer.
        self._pendiente_en_la_vuelta = True
        antes = [i for i in ids if i < pendiente]
        self.almacen.guardar_sesion(EstadoSesion(sid, max(antes) if antes else estado.ultimo_id, estado.referencia,
                                                 estado.ultima_actividad, estado.mensajes, ahora,
                                                 deteccion.ultima_respuesta(filas, estado.ultima_respuesta,
                                                                            hasta=pendiente), perfil=perfil))

    # -- Las entregas de los subagentes

    def _atender_entrega(self, perfil: str, cliente, sid: str, filas: list, ahora: float) -> tuple:
        """Contesta, si toca, la entrega sin atender más reciente de la conversación (``entregas``) lanzando el turno de
        continuación de la app. Devuelve la fila de la entrega de la que se ocupa el vigía (``None`` si de ninguna: se
        avisa de ella como antes) y si hay que volver a leer la conversación en la vuelta siguiente aunque no cambie
        (se espera la gracia, a que acabe un turno o a ver la fila de la continuación lanzada)."""
        if self.reglas_entrega is None:
            return None, False
        decision = entregas.decidir(filas, ahora=ahora, gracia=self.reglas_entrega.gracia,
                                    antiguedad_maxima=self.reglas_entrega.antiguedad_maxima,
                                    cadena_maxima=self.reglas_entrega.cadena_maxima)
        if decision is None:
            return None, False
        clave = (perfil, sid, decision.delegacion)
        donde = sid if perfil == PRINCIPAL else f"{perfil}/{sid}"
        if decision.accion == entregas.RENUNCIAR:
            if clave not in self._continuaciones:
                self._continuaciones[clave] = _Continuacion(desde=ahora, rendida=True)
                registro.warning("la entrega %s de %s no se contesta: %d continuaciones seguidas sin un mensaje del "
                                 "usuario; se avisa de ella", decision.delegacion, donde,
                                 self.reglas_entrega.cadena_maxima)
            return None, False
        if decision.accion == entregas.ESPERAR:
            return decision.fila, True
        hecho = self._continuaciones.get(clave) or _Continuacion(desde=ahora)
        if hecho.rendida:
            return None, False
        if hecho.lanzada is not None:
            if ahora - hecho.lanzada < VER_LA_CONTINUACION:
                return decision.fila, True
            self._continuaciones[clave] = replace(hecho, rendida=True)
            registro.warning("la continuación %s de %s no aparece en el historial; se avisa de la entrega",
                             hecho.run_id, donde)
            return None, False
        if ahora < hecho.hasta:
            return decision.fila, True
        try:
            # La frase la leen las apps de todos los iPhone: la de antes mientras alguno no entienda la de ahora.
            frase = entregas.texto_de_la_continuacion(self.almacen.dispositivos())
            run_id = cliente.lanzar_continuacion(sid, decision.clave, frase)
        except ErrorHermes as error:
            if error.estado == 409 and error.codigo == "idempotency_key_conflict":
                # La misma clave con otro cuerpo: la app ya lanzó esta continuación, con sus instrucciones. Es la buena.
                self._continuaciones[clave] = replace(hecho, run_id=None, lanzada=ahora)
                registro.info("la continuación de %s en %s ya la lanzó la app", decision.delegacion, donde)
                return decision.fila, True
            pasajero = error.estado is None or error.estado in (429, 503) or error.estado >= 500
            if pasajero and ahora - hecho.desde < INSISTIR_EN_LA_CONTINUACION:
                fallos = hecho.fallos + 1
                pausa = REINTENTOS[min(fallos, len(REINTENTOS)) - 1]
                self._continuaciones[clave] = replace(hecho, fallos=fallos, hasta=ahora + pausa)
                self._apuntar_fallo(f"continuar {donde}", "no se pudo lanzar la continuación de %s en %s (%s); se "
                                    "reintenta", decision.delegacion, donde, error)
                return decision.fila, True
            self._continuaciones[clave] = replace(hecho, rendida=True)
            registro.warning("no se pudo lanzar la continuación de %s en %s: %s; se avisa de la entrega",
                             decision.delegacion, donde, error)
            return None, False
        self._continuaciones[clave] = replace(hecho, run_id=run_id, lanzada=ahora)
        # Se vigila como los turnos de la app: si falla sin respuesta, llega el aviso de error.
        self.almacen.vigilar_turnos([(run_id, sid, perfil)], ahora)
        registro.info("entrega %s de %s sin contestar: continuación %s lanzada", decision.delegacion, donde, run_id)
        return decision.fila, True

    def _leer(self, cliente, sid: str) -> tuple:
        """Las últimas filas de una conversación, y cuántas se pidieron. Casi siempre bastan 20, las del turno que
        acaba de terminar; si en ellas no está la petición que lo abrió (un turno largo, lleno de herramientas), se
        leen `filas_por_lectura`, porque de esa petición depende de qué tipo es el aviso."""
        corta = min(LECTURA_CORTA, self.filas_por_lectura)
        filas = cliente.mensajes(sid, corta)
        if len(filas) >= corta < self.filas_por_lectura and not any(deteccion.abre_turno(f) for f in filas):
            return cliente.mensajes(sid, self.filas_por_lectura), self.filas_por_lectura
        return filas, corta

    # -- Los turnos que la app dejó en marcha

    def _revisar_turnos(self, clientes: dict, ahora: float) -> None:
        for turno in self.almacen.turnos():
            cliente = clientes.get(turno.perfil)
            if cliente is None:
                # De un agente que ya no está (borrado, o sin clave): nadie lo puede contestar.
                self.almacen.olvidar_turno(turno.run_id)
                continue
            try:
                self._revisar_turno(turno, cliente, ahora)
            except ErrorHermes as error:
                registro.debug("no se pudo leer el turno %s: %s", turno.run_id, error)
            except Exception:  # noqa: BLE001
                self._apuntar_fallo(f"turno {turno.run_id}", "fallo revisando el turno %s: se deja de mirar",
                                    turno.run_id, excepcion=True)
                self.almacen.olvidar_turno(turno.run_id)

    def _revisar_turno(self, turno, cliente, ahora: float) -> None:
        if ahora - turno.alta > VIDA_DE_UN_TURNO:
            self.almacen.olvidar_turno(turno.run_id)
            return
        estado = cliente.turno(turno.run_id)
        if estado is None:
            # Hermes ya no lo conoce (pasó su hora en memoria, o se reinició sin clave de idempotencia).
            self.almacen.olvidar_turno(turno.run_id)
            return
        situacion = estado.get("status")
        titulo = self._titulos.get((turno.perfil, turno.sesion), "Hermes")
        # Cuándo pasó: la última vez que cambió el run, que es cuando pidió permiso o cuando falló.
        instante = _numero(estado.get("updated_at")) or ahora
        if situacion == "waiting_for_approval":
            aprobacion = estado.get("approval") if isinstance(estado.get("approval"), dict) else {}
            pedida = str(aprobacion.get("request_id") or f"{turno.run_id}@{estado.get('updated_at')}")
            if pedida == turno.aprobacion_avisada:
                return
            aviso = avisos.Aviso(tipo="aprobacion", sesion=turno.sesion, titulo=titulo,
                                 texto=_texto_de_aprobacion(aprobacion), instante=instante,
                                 clave=f"aprobacion:{pedida}", caduca=self.caducidad_aprobacion,
                                 colapsa_con="aprobacion", aprobacion=_peticion_de_permiso(turno.run_id, aprobacion),
                                 perfil=turno.perfil)
            if self._avisar(aviso, ahora):
                self.almacen.marcar_aprobacion(turno.run_id, pedida)
        elif situacion in ("failed", "interrupted"):
            # Un turno que falló a medias (`failed` con `output`) deja su respuesta en el historial, y esa ya la
            # avisa la bandeja: aquí solo lo que no deja nada que leer.
            salida = estado.get("output")
            if situacion == "interrupted" or not (isinstance(salida, str) and salida.strip()):
                aviso = avisos.Aviso(tipo="error", sesion=turno.sesion, titulo=titulo, texto=_texto_de_error(estado),
                                     instante=instante, clave=f"error:{turno.run_id}", perfil=turno.perfil)
                if not self._avisar(aviso, ahora):
                    return
            self.almacen.olvidar_turno(turno.run_id)
        elif situacion in ("completed", "cancelled"):
            self.almacen.olvidar_turno(turno.run_id)

    # -- Mandar

    def _avisar(self, aviso: avisos.Aviso, ahora: float) -> bool:
        """Manda el aviso a cada iPhone que toque. Devuelve si ya no queda nada pendiente con él: todos lo tienen, o no
        les toca. Si queda algo (un envío que falló por algo pasajero, o que hay que esperar), quien llama no lo da por
        leído."""
        resuelto = True
        for dispositivo in self.almacen.dispositivos():
            clave = (dispositivo.token, aviso.identidad)
            if clave in self._aceptados:
                continue
            decision, motivo = avisos.decidir_con_motivo(aviso, dispositivo, ahora)
            if decision == avisos.DESCARTAR:
                self._esperas.pop(clave, None)
                # Sin esto, un aviso que no sale por los ajustes del iPhone no deja rastro (`decidir_con_motivo`).
                registro.info("no se avisa a %s de %s: %s", cola(dispositivo.token), aviso.tipo, motivo)
                continue
            espera = self._esperas.get(clave)
            if decision == avisos.ESPERAR or (espera is not None and ahora < espera.hasta):
                resuelto = False
                continue
            resultado = self.mensajero.enviar(aviso, dispositivo)
            if resultado.tipo == ENVIADO:
                self._aceptados[clave] = ahora
                self._esperas.pop(clave, None)
            elif resultado.tipo in (REINTENTABLE, LIMITADO):
                fallos = espera.fallos + 1 if espera else 1
                pausa = max(REINTENTOS[min(fallos, len(REINTENTOS)) - 1], resultado.esperar or 0)
                self._esperas[clave] = _Espera(fallos, ahora + pausa)
                resuelto = False
            else:
                # Dado de baja o rechazado: con este iPhone no hay nada más que hacer.
                self._esperas.pop(clave, None)
        return resuelto

    @property
    def pendientes(self) -> int:
        """Envíos que fallaron por algo pasajero y esperan su próximo intento."""
        return len(self._esperas)

    def _olvidar_lo_viejo(self, ahora: float) -> None:
        for clave in [c for c, cuando in self._aceptados.items() if ahora - cuando > RECORDAR_ACEPTADOS]:
            del self._aceptados[clave]
        # Una espera vencida hace más que la antigüedad máxima es de un aviso que ya no puede ser nuevo: se dejó de buscar.
        for clave in [c for c, espera in self._esperas.items() if ahora - espera.hasta > self.antiguedad_maxima]:
            del self._esperas[clave]
        # Lo hecho con una entrega se recuerda mientras esa entrega pueda volver a decidirse: después ya es vieja.
        if self.reglas_entrega is not None:
            for clave in [c for c, hecho in self._continuaciones.items()
                          if ahora - hecho.desde > self.reglas_entrega.antiguedad_maxima]:
                del self._continuaciones[clave]

    def _apuntar_fallo(self, clave: str, formato: str, *argumentos, excepcion: bool = False) -> None:
        ahora = self.reloj()
        if ahora - self._fallos_apuntados.get(clave, -REPETIR_UN_FALLO) < REPETIR_UN_FALLO:
            return
        self._fallos_apuntados[clave] = ahora
        (registro.exception if excepcion else registro.warning)(formato, *argumentos)

    def _podar(self, ahora: float) -> None:
        if ahora - self._ultima_poda < CADA_CUANTO_PODAR:
            return
        self._ultima_poda = ahora
        olvidadas = self.almacen.podar_sesiones(ahora - OLVIDAR_SESIONES)
        self.almacen.podar_turnos(ahora - VIDA_DE_UN_TURNO)
        for clave in [c for c, cuando in self._fallos_apuntados.items() if ahora - cuando > REPETIR_UN_FALLO]:
            del self._fallos_apuntados[clave]
        if olvidadas:
            registro.info("olvidadas %d conversaciones que llevaban un mes sin salir en la bandeja", olvidadas)


def _numero_de_texto(valor: str | None) -> float | None:
    try:
        return float(valor) if valor is not None else None
    except ValueError:
        return None


def _texto_de_aprobacion(aprobacion: dict, entero: bool = False) -> str:
    """Lo que se lee de una petición de permiso: el comando, o sin comando la descripción. En una línea y recortado, o
    entero, con sus líneas, para leerlo al mantener pulsado el aviso (`_peticion_de_permiso`)."""
    limpiar = texto.entero if entero else texto.corto
    comando = aprobacion.get("command")
    if isinstance(comando, str) and comando.strip():
        return limpiar(f"Pide permiso para ejecutar: {comando}")
    descripcion = aprobacion.get("description")
    return limpiar(descripcion) if isinstance(descripcion, str) else ""


def _peticion_de_permiso(run_id: str, aprobacion: dict) -> avisos.PeticionDePermiso | None:
    """Lo que hace falta para contestar la aprobación desde el aviso (spec 2026-10-04), o `None` si Hermes no da su
    ``request_id``: sin él no se sabría a qué petición se contesta."""
    peticion = aprobacion.get("request_id")
    if not (isinstance(peticion, str) and peticion):
        return None
    choices = aprobacion.get("choices")
    opciones = tuple(opcion for opcion in choices if isinstance(opcion, str)) if isinstance(choices, list) else ()
    return avisos.PeticionDePermiso(run=run_id, peticion=peticion, opciones=opciones,
                                    texto=_texto_de_aprobacion(aprobacion, entero=True))


def _texto_de_error(estado: dict) -> str:
    if estado.get("status") == "interrupted":
        return "Hermes se reinició antes de terminar la respuesta."
    error = estado.get("error")
    if isinstance(error, str) and error.strip():
        return texto.corto(f"Hermes no pudo terminar la respuesta: {error}")
    return "Hermes no pudo terminar la respuesta."
