"""La memoria del vigía, en un SQLite propio (nunca el ``state.db`` de Hermes).

Guarda tres cosas, y ninguna es texto de una conversación:

- los **dispositivos**: token, entorno, clave, ajustes, si la app está delante y, si la app lo trae, su **permiso** para
  el relé (spec 2026-09-28, «Avisos sin comandos»). La clave es la que cifra los avisos de ese iPhone, y el permiso deja
  pedir avisos para él: el fichero se crea 0600 y el directorio es del usuario del vigía y de nadie más;
- hasta dónde se ha leído cada **sesión** (el id de la última fila vista), para no avisar dos veces tras un reinicio ni
  de todo el historial la primera vez; desde la versión 5, por perfil de Hermes (los agentes, contrato §18);
- los **turnos** que la app dejó en marcha al irse, si los manda (ampliación propuesta del contrato: ver el README).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field

from .ajustes import Ajustes

registro = logging.getLogger("vigia.almacen")

# La versión de la base de datos (`PRAGMA user_version`). Cada cambio sube uno, con su paso en `_migrar`, y una base de
# una versión anterior se pone al día al abrirla. La 2 añadió el latido del primer plano (`delante_latido`,
# `delante_caduca`); la 3, el permiso de cada iPhone para el relé (`permiso*`); la 4, la hora de la última respuesta vista
# de cada conversación (`sesiones.ultima_respuesta`), para no avisar otra vez de las copias que deja una compactación; la
# 5, el perfil de Hermes de cada conversación y de cada turno (los agentes, contrato §18): cada perfil tiene su propio
# state.db, así que la clave de una conversación es `(perfil, id)`. Lo de antes es del principal (`default`); la 6, de
# qué iPhone de la pasarela es cada alta, firmado por ella (`dispositivos.iphone` e `iphone_marca`: su nombre y la marca
# de su token, contrato §12.10): al quitar uno desde la app se borran las suyas, y al que entra con el código de
# recuperación no se le avisa de sí mismo (§12.9). Las de antes no lo dicen (NULL) hasta que su iPhone vuelve a darse de
# alta o a decir que está delante. La 7 (2026-10-23, «Enviar más tarde»), la tabla `programados`: los mensajes que el usuario deja
# para una hora y que el vigía lanza a su hora aunque la app esté cerrada (`programados.py`, contrato §19). La 8
# (2026-10-23, avisos 1.6.7), la tabla `actividades`: el token de cada Actividad en Vivo que la app le registra, para
# moverla con la app suspendida (`actividades.py`, contrato §20).
ESQUEMA = 8
#: El perfil del principal, el de todo lo de antes de los agentes.
PRINCIPAL = "default"

# Lo que se da por visto antes de que la app dijera «estoy delante»: el aviso de «delante» llega un momento después de
# que la app ya esté en pantalla. Por arriba no hace falta margen: el «ya no estoy delante» se apunta al llegar, que es
# después de que la app se fuera, y los instantes de Hermes salen del mismo reloj que los del vigía.
MARGEN_AL_PONERSE_DELANTE = 2.0
# Hasta dónde prueba un latido que la app seguía delante: la app lo repite cada 30 s (`EstadoPrimerPlano.renovacion`),
# así que sin otro en 35 s ya se había ido. Antes el tramo visto duraba todo el plazo (`caduca`, 90 s), y si el «ya no
# estoy delante» no llegaba, lo de ese minuto y medio contaba como visto y no se avisaba nunca.
VISTO_TRAS_EL_LATIDO = 35.0
# Turnos que se vigilan a la vez, sumando los de todos los iPhone.
MAX_TURNOS = 20


@dataclass(frozen=True)
class Permiso:
    """El permiso firmado por el relé para avisar a un iPhone (``hhp1.…``), y a qué entrada del relé llevarlo.

    El valor es un secreto a medias: no dice a qué iPhone avisar (lleva el SHA-256 del token), pero con el token deja
    pedir avisos para él hasta que caduque. Por eso no sale en el ``repr`` (un registro con un dispositivo dentro no lo
    lleva) ni en ningún registro."""

    valor: str = field(repr=False)
    caduca: int
    direccion: str
    puerto: int
    huella: str
    # Cuándo lo rechazó el relé (401/403 con `resultado: "permiso"`): ya no se usa, y la app tiene que traer otro.
    rechazado: float | None = None

    def vigente(self, ahora: float) -> bool:
        return self.rechazado is None and ahora < self.caduca


@dataclass(frozen=True)
class Iphone:
    """De qué iPhone de la pasarela es un alta: el nombre de su token y la marca de ese token (contrato §12.10). Solo lo
    sabe la pasarela, que lo firma (`api.AppVigia.iphone_de`): sin una firma que valga, el alta no es de nadie. La marca
    cambia con cada token, aunque el nombre siga: un iPhone que vuelve con el código de recuperación, o con un token
    rotado, es otro dueño."""
    nombre: str
    marca: str


@dataclass(frozen=True)
class Dispositivo:
    token: str
    entorno: str
    clave: bytes
    ajustes: Ajustes
    alta: float
    actualizado: float
    # El último tramo con la app delante: cuándo empezó, su último latido, el plazo que dio la app y, si lo dijo,
    # cuándo se fue.
    delante_desde: float | None = None
    delante_latido: float | None = None
    delante_caduca: float | None = None
    delante_hasta: float | None = None
    conversacion: str | None = None
    permiso: Permiso | None = None
    #: El iPhone de la pasarela que hizo el alta (firmado por ella), si se sabe.
    iphone: Iphone | None = None

    def delante(self, ahora: float) -> bool:
        """Si la app está en pantalla ahora, por lo que ha dicho: entonces no se manda nada, que ya avisa ella (spec).
        Dura lo que diga su plazo desde el último latido, salvo que diga antes que se va."""
        return (self.delante_hasta is None and self.delante_latido is not None and self.delante_caduca is not None
                and ahora < self.delante_latido + self.delante_caduca)

    def fin_de_lo_visto(self) -> float | None:
        """Hasta cuándo se sabe que la app estaba delante: su último latido y 35 s, o antes si dijo que se iba."""
        if self.delante_latido is None:
            return None
        fin = self.delante_latido + VISTO_TRAS_EL_LATIDO
        return min(fin, self.delante_hasta) if self.delante_hasta is not None else fin

    def lo_vio(self, instante: float) -> bool:
        """Si la app estaba en pantalla cuando pasó ``instante``.

        Es lo que evita el aviso doble de una respuesta que llega con la app delante y Daniel bloquea el iPhone justo
        después: cuando el vigía la lee, la app ya no está delante, pero la vio y la avisó ella. El final es abierto: lo
        escrito en el mismo instante en que llegó el «ya no estoy delante» se escribió con la app ya detrás.
        """
        fin = self.fin_de_lo_visto()
        if self.delante_desde is None or fin is None:
            return False
        return self.delante_desde - MARGEN_AL_PONERSE_DELANTE <= instante < fin

    def fin_de_delante(self) -> float | None:
        """Cuándo dejó (o dejará) de contar como delante: cuando lo dijo o cuando caduca su último latido."""
        if self.delante_latido is None or self.delante_caduca is None:
            return None
        return self.delante_hasta if self.delante_hasta is not None else self.delante_latido + self.delante_caduca


@dataclass(frozen=True)
class Actividad:
    """Una Actividad en Vivo que la app registró para que el vigía la mueva con ella suspendida (contrato §20)."""
    actividad: str
    token: str
    perfil: str
    sesion: str
    run_id: str | None
    alta: float
    vuelta: int
    ultimo: str | None


@dataclass(frozen=True)
class EstadoSesion:
    id: str
    # La última fila vista. `None` hasta la primera lectura de sus mensajes: entonces vale `referencia`.
    ultimo_id: int | None
    # Lo escrito hasta este instante se da por visto. Es la línea de base de una sesión que el vigía aún no ha leído.
    referencia: float
    ultima_actividad: float | None
    mensajes: int | None
    visto: float
    # La hora de la última fila `assistant` vista (`deteccion.ultima_respuesta`): tras una compactación, Hermes vuelve a
    # escribir la cola con ids nuevos y sus horas de siempre, y lo que no es posterior a esta hora es una copia.
    ultima_respuesta: float | None = None
    # El perfil de Hermes de la conversación (un agente, contrato §18; `default`, el principal).
    perfil: str = PRINCIPAL


@dataclass(frozen=True)
class Turno:
    run_id: str
    sesion: str
    alta: float
    aprobacion_avisada: str | None
    visto: float
    perfil: str = PRINCIPAL


@dataclass(frozen=True)
class ProgramadoGuardado:
    """Un mensaje que el usuario dejó para una hora (``programados.py``). ``cuerpo`` es el JSON del turno tal como lo armó la
    app (``input``, ``instructions``, ``effort``, ``model``, ``provider``): el vigía no lo interpreta, lo manda."""

    clave: str
    perfil: str
    sesion: str
    hora: float
    cuerpo: dict
    creado: float
    # pendiente → lanzando (reclamado: ya no se cambia ni se borra) → lanzado; o fallido / caducado, que se quedan para
    # que la app lo diga.
    estado: str = "pendiente"
    run_id: str | None = None
    lanzado: float | None = None
    fallos: int = 0
    # No se vuelve a intentar antes de esta hora (tras un fallo pasajero).
    hasta: float = 0.0
    motivo: str | None = None


# La tabla de la versión 7, la misma en una base nueva y en una puesta al día (una prueba compara las dos).
_TABLA_PROGRAMADOS = """
    CREATE TABLE IF NOT EXISTS programados (
        clave TEXT PRIMARY KEY,
        perfil TEXT NOT NULL DEFAULT 'default',
        sesion TEXT NOT NULL,
        hora REAL NOT NULL,
        cuerpo TEXT NOT NULL,
        creado REAL NOT NULL,
        estado TEXT NOT NULL,
        run_id TEXT,
        lanzado REAL,
        fallos INTEGER NOT NULL DEFAULT 0,
        hasta REAL NOT NULL DEFAULT 0,
        motivo TEXT
    );
"""

# La tabla de la versión 8, la misma en una base nueva y en una puesta al día. `token` es el del iPhone, con el que el relé
# comprueba el permiso; `ultimo`, lo último que se le mandó (`actividades.huella`), para no repetirlo.
_TABLA_ACTIVIDADES = """
    CREATE TABLE IF NOT EXISTS actividades (
        actividad TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        perfil TEXT NOT NULL DEFAULT 'default',
        sesion TEXT NOT NULL,
        run_id TEXT,
        alta REAL NOT NULL,
        vuelta INTEGER NOT NULL DEFAULT 0,
        ultimo TEXT
    );
"""

# Una base nueva, ya en la última versión. Lo que añade cada paso de `_migrar` tiene que estar también aquí (lo mira una
# prueba: una base nueva y una puesta al día desde la 1 tienen las mismas columnas).
_CREAR = f"""
    BEGIN;
    CREATE TABLE IF NOT EXISTS dispositivos (
        token TEXT PRIMARY KEY,
        entorno TEXT NOT NULL,
        clave BLOB NOT NULL,
        ajustes TEXT NOT NULL,
        alta REAL NOT NULL,
        actualizado REAL NOT NULL,
        delante_desde REAL,
        delante_latido REAL,
        delante_caduca REAL,
        delante_hasta REAL,
        conversacion TEXT,
        permiso TEXT,
        permiso_caduca INTEGER,
        permiso_direccion TEXT,
        permiso_puerto INTEGER,
        permiso_huella TEXT,
        permiso_rechazado REAL,
        iphone TEXT,
        iphone_marca TEXT
    );
    CREATE TABLE IF NOT EXISTS sesiones (
        perfil TEXT NOT NULL DEFAULT 'default',
        id TEXT NOT NULL,
        ultimo_id INTEGER,
        referencia REAL NOT NULL,
        ultima_actividad REAL,
        mensajes INTEGER,
        visto REAL NOT NULL,
        ultima_respuesta REAL,
        PRIMARY KEY (perfil, id)
    );
    CREATE TABLE IF NOT EXISTS turnos (
        run_id TEXT PRIMARY KEY,
        sesion TEXT NOT NULL,
        alta REAL NOT NULL,
        aprobacion_avisada TEXT,
        visto REAL NOT NULL,
        perfil TEXT NOT NULL DEFAULT 'default'
    );
    CREATE TABLE IF NOT EXISTS estado (clave TEXT PRIMARY KEY, valor TEXT NOT NULL);
    {_TABLA_PROGRAMADOS}
    {_TABLA_ACTIVIDADES}
    PRAGMA user_version = {ESQUEMA};
    COMMIT;
"""


class Almacen:
    """Una conexión compartida con un cerrojo: el bucle y la API escriben poco y de uno en uno, y así no hay que pensar
    en transacciones que se crucen entre hilos."""

    def __init__(self, ruta: str, max_dispositivos: int = 20):
        self.max_dispositivos = max_dispositivos
        self._cerrojo = threading.RLock()
        if ruta != ":memory:" and not os.path.exists(ruta):
            # Creado aquí y no por SQLite, para que nazca 0600 sea cual sea la umask de quien lo arranque.
            os.close(os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        self._con = sqlite3.connect(ruta, check_same_thread=False, isolation_level=None)
        self._con.execute("PRAGMA busy_timeout = 5000")
        if ruta != ":memory:":
            self._con.execute("PRAGMA journal_mode = WAL")
            self._con.execute("PRAGMA synchronous = NORMAL")
        self._migrar()

    def cerrar(self) -> None:
        with self._cerrojo:
            self._con.close()

    def _migrar(self) -> None:
        with self._cerrojo:
            version = self._con.execute("PRAGMA user_version").fetchone()[0]
            if version > ESQUEMA:
                raise RuntimeError(f"la base de datos es de una versión más nueva del vigía ({version} > {ESQUEMA})")
            if version == 0:
                self._con.executescript(_CREAR)
                return
            # Una base de antes, paso a paso y cada paso en su transacción: si uno falla, se queda en la versión
            # anterior, entera, y el vigía no arranca con una a medias.
            if version < 2:
                registro.info("base de datos de la versión %d: se pone al día", version)
                self._con.executescript("""
                    BEGIN;
                    ALTER TABLE dispositivos ADD COLUMN delante_latido REAL;
                    ALTER TABLE dispositivos ADD COLUMN delante_caduca REAL;
                    -- El primer plano de la versión 1 (un plazo, sin latido) no se traduce: se olvida, y el siguiente
                    -- latido de la app, que llega cada 30 s si está delante, lo vuelve a poner.
                    UPDATE dispositivos SET delante_desde = NULL, delante_hasta = NULL;
                    PRAGMA user_version = 2;
                    COMMIT;
                """)
            if version < 3:
                registro.info("base de datos de la versión %d: se pone al día (el permiso de cada iPhone)",
                              max(version, 2))
                self._con.executescript("""
                    BEGIN;
                    ALTER TABLE dispositivos ADD COLUMN permiso TEXT;
                    ALTER TABLE dispositivos ADD COLUMN permiso_caduca INTEGER;
                    ALTER TABLE dispositivos ADD COLUMN permiso_direccion TEXT;
                    ALTER TABLE dispositivos ADD COLUMN permiso_puerto INTEGER;
                    ALTER TABLE dispositivos ADD COLUMN permiso_huella TEXT;
                    ALTER TABLE dispositivos ADD COLUMN permiso_rechazado REAL;
                    PRAGMA user_version = 3;
                    COMMIT;
                """)
            if version < 4:
                registro.info("base de datos de la versión %d: se pone al día (la última respuesta vista de cada "
                              "conversación)", max(version, 3))
                self._con.executescript("""
                    BEGIN;
                    ALTER TABLE sesiones ADD COLUMN ultima_respuesta REAL;
                    PRAGMA user_version = 4;
                    COMMIT;
                """)
            if version < 5:
                registro.info("base de datos de la versión %d: se pone al día (el perfil de cada conversación y de "
                              "cada turno: lo de antes, del principal)", max(version, 4))
                # SQLite no cambia la clave primaria de una tabla: se hace otra con la nueva y se pasa todo.
                self._con.executescript("""
                    BEGIN;
                    CREATE TABLE sesiones_5 (
                        perfil TEXT NOT NULL DEFAULT 'default',
                        id TEXT NOT NULL,
                        ultimo_id INTEGER,
                        referencia REAL NOT NULL,
                        ultima_actividad REAL,
                        mensajes INTEGER,
                        visto REAL NOT NULL,
                        ultima_respuesta REAL,
                        PRIMARY KEY (perfil, id)
                    );
                    INSERT INTO sesiones_5 (perfil, id, ultimo_id, referencia, ultima_actividad, mensajes, visto,
                                            ultima_respuesta)
                        SELECT 'default', id, ultimo_id, referencia, ultima_actividad, mensajes, visto, ultima_respuesta
                        FROM sesiones;
                    DROP TABLE sesiones;
                    ALTER TABLE sesiones_5 RENAME TO sesiones;
                    ALTER TABLE turnos ADD COLUMN perfil TEXT NOT NULL DEFAULT 'default';
                    PRAGMA user_version = 5;
                    COMMIT;
                """)
            if version < 6:
                registro.info("base de datos de la versión %d: se pone al día (de qué iPhone es cada alta)",
                              max(version, 5))
                # `iphones` en `estado` era de qué iPhone era cada alta según una cabecera sin firmar (el aviso del
                # código de recuperación antes de juntarse con los iPhone conectados): no vale nada, y se va.
                self._con.executescript("""
                    BEGIN;
                    ALTER TABLE dispositivos ADD COLUMN iphone TEXT;
                    ALTER TABLE dispositivos ADD COLUMN iphone_marca TEXT;
                    DELETE FROM estado WHERE clave = 'iphones';
                    PRAGMA user_version = 6;
                    COMMIT;
                """)
            if version < 7:
                registro.info("base de datos de la versión %d: se pone al día (los mensajes programados)",
                              max(version, 6))
                self._con.executescript("BEGIN;" + _TABLA_PROGRAMADOS + "PRAGMA user_version = 7; COMMIT;")
            if version < 8:
                registro.info("base de datos de la versión %d: se pone al día (las Actividades en Vivo)",
                              max(version, 7))
                self._con.executescript("BEGIN;" + _TABLA_ACTIVIDADES + "PRAGMA user_version = 8; COMMIT;")

    # -- Dispositivos

    @staticmethod
    def _dispositivo(fila) -> Dispositivo:
        permiso = None
        if fila[11] is not None:
            permiso = Permiso(valor=fila[11], caduca=fila[12], direccion=fila[13], puerto=fila[14], huella=fila[15],
                              rechazado=fila[16])
        return Dispositivo(token=fila[0], entorno=fila[1], clave=bytes(fila[2]),
                           ajustes=Ajustes.desde_json(json.loads(fila[3])), alta=fila[4], actualizado=fila[5],
                           delante_desde=fila[6], delante_latido=fila[7], delante_caduca=fila[8],
                           delante_hasta=fila[9], conversacion=fila[10], permiso=permiso,
                           iphone=Iphone(fila[17], fila[18]) if fila[17] is not None and fila[18] is not None else None)

    _COLUMNAS = ("token, entorno, clave, ajustes, alta, actualizado, delante_desde, delante_latido, delante_caduca, "
                 "delante_hasta, conversacion, permiso, permiso_caduca, permiso_direccion, permiso_puerto, "
                 "permiso_huella, permiso_rechazado, iphone, iphone_marca")

    def guardar_dispositivo(self, token: str, entorno: str, clave: bytes, ajustes: Ajustes, ahora: float,
                            permiso: Permiso | None = None, iphone: Iphone | None = None) -> bool:
        """Da de alta el dispositivo o, si el token ya estaba, lo actualiza (el alta es idempotente por token).

        Devuelve si es nuevo. Por encima de ``max_dispositivos`` se olvida el que lleva más tiempo sin darse de alta:
        la app se da de alta en cada arranque, así que ese es el de una instalación que ya no existe, y su token habría
        muerto igual en cuanto Apple lo dijera.

        ``permiso``, si lo trae el alta, sustituye al que hubiera (y olvida que el relé rechazó el de antes). Sin él,
        el que había se queda: un alta sin permiso es la de una app que no ha podido pedir otro (App Attest falla, o
        es el Simulador), y el de antes puede seguir valiendo (Contrato C).

        ``iphone``, el de la pasarela que la hace (firmado por ella): el alta dice de quién es, siempre, también si no
        se sabe (una pasarela de antes, o una cabecera sin una firma que valga). Es lo que borra sus altas al quitarlo
        desde la app (``borrar_las_ajenas``) y lo que deja fuera del aviso del código de recuperación al que entra.
        """
        nombre, marca = (iphone.nombre, iphone.marca) if iphone is not None else (None, None)
        with self._cerrojo:
            existia = self._con.execute("SELECT 1 FROM dispositivos WHERE token = ?", (token,)).fetchone() is not None
            self._con.execute("BEGIN")
            try:
                if existia:
                    self._con.execute(
                        "UPDATE dispositivos SET entorno = ?, clave = ?, ajustes = ?, actualizado = ?, iphone = ?, "
                        "iphone_marca = ? WHERE token = ?",
                        (entorno, clave, json.dumps(ajustes.a_json()), ahora, nombre, marca, token))
                else:
                    self._con.execute(
                        "INSERT INTO dispositivos (token, entorno, clave, ajustes, alta, actualizado, iphone, "
                        "iphone_marca) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (token, entorno, clave, json.dumps(ajustes.a_json()), ahora, ahora, nombre, marca))
                if permiso is not None:
                    self._con.execute(
                        "UPDATE dispositivos SET permiso = ?, permiso_caduca = ?, permiso_direccion = ?, "
                        "permiso_puerto = ?, permiso_huella = ?, permiso_rechazado = NULL WHERE token = ?",
                        (permiso.valor, int(permiso.caduca), permiso.direccion, int(permiso.puerto), permiso.huella,
                         token))
                sobran = self._con.execute("SELECT COUNT(*) FROM dispositivos").fetchone()[0] - self.max_dispositivos
                if sobran > 0:
                    self._con.execute(
                        "DELETE FROM dispositivos WHERE token IN (SELECT token FROM dispositivos WHERE token != ? "
                        "ORDER BY actualizado ASC LIMIT ?)", (token, sobran))
                self._con.execute("COMMIT")
            except BaseException:
                self._con.execute("ROLLBACK")
                raise
            return not existia

    def dispositivo(self, token: str) -> Dispositivo | None:
        with self._cerrojo:
            fila = self._con.execute(f"SELECT {self._COLUMNAS} FROM dispositivos WHERE token = ?", (token,)).fetchone()
        return self._dispositivo(fila) if fila else None

    def dispositivos(self) -> list[Dispositivo]:
        with self._cerrojo:
            filas = self._con.execute(f"SELECT {self._COLUMNAS} FROM dispositivos ORDER BY alta").fetchall()
        return [self._dispositivo(fila) for fila in filas]

    def cambiar_ajustes(self, token: str, ajustes: Ajustes, ahora: float) -> bool:
        with self._cerrojo:
            cursor = self._con.execute("UPDATE dispositivos SET ajustes = ?, actualizado = ? WHERE token = ?",
                                       (json.dumps(ajustes.a_json()), ahora, token))
        return cursor.rowcount > 0

    def cambiar_primer_plano(self, token: str, activa: bool, conversacion: str | None, caduca: float,
                             ahora: float) -> bool:
        """Apunta si la app está delante, como un tramo: desde, último latido, plazo y, si lo dice, hasta.

        Un «delante» es un latido: renueva el tramo que siga abierto (la app lo repite cada 30 s) o abre uno nuevo; el
        plazo lo pone la app (``caduca``) para que un «ya no estoy delante» perdido no deje al vigía callado para
        siempre. Un «detrás» cierra el tramo ahora, y se guarda: es lo que dice qué respuestas vio la app
        (``Dispositivo.lo_vio``).
        """
        with self._cerrojo:
            fila = self._con.execute(
                "SELECT delante_desde, delante_latido, delante_caduca, delante_hasta FROM dispositivos "
                "WHERE token = ?", (token,)).fetchone()
            if fila is None:
                return False
            desde, latido, plazo, hasta = fila
            abierto = latido is not None and plazo is not None and hasta is None and ahora < latido + plazo
            if activa:
                if not abierto:
                    desde = ahora
                latido, plazo, hasta = ahora, caduca, None
            elif latido is not None and hasta is None:
                hasta = ahora
            self._con.execute(
                "UPDATE dispositivos SET delante_desde = ?, delante_latido = ?, delante_caduca = ?, delante_hasta = ?, "
                "conversacion = ? WHERE token = ?", (desde, latido, plazo, hasta, conversacion if activa else None,
                                                     token))
        return True

    def rechazar_permiso(self, token: str, valor: str, ahora: float) -> bool:
        """El relé ha rechazado este permiso: no se vuelve a usar, y el siguiente primer plano le pide otro a la app.
        Solo si sigue siendo el guardado: si entretanto llegó uno nuevo en un alta, ese no se toca."""
        with self._cerrojo:
            cursor = self._con.execute(
                "UPDATE dispositivos SET permiso_rechazado = ? WHERE token = ? AND permiso = ? "
                "AND permiso_rechazado IS NULL", (ahora, token, valor))
        return cursor.rowcount > 0

    def borrar_dispositivo(self, token: str) -> bool:
        with self._cerrojo:
            cursor = self._con.execute("DELETE FROM dispositivos WHERE token = ?", (token,))
            # Sus actividades se van con él: sin iPhone no hay permiso con el que mandarlas.
            self._con.execute("DELETE FROM actividades WHERE token = ?", (token,))
        return cursor.rowcount > 0

    # -- Actividades en Vivo (contrato §20)

    def guardar_actividad(self, actividad: str, token: str, perfil: str, sesion: str, run_id: str | None,
                          ahora: float, maximo: int = 8) -> bool:
        """Apunta el token de una actividad de un iPhone dado de alta. Idempotente por actividad: el mismo token otra vez
        cambia la conversación o el run, y se vuelve a mandar lo que toque. Con más de ``maximo`` en ese iPhone, se olvida
        la más antigua. ``False`` si el iPhone no está dado de alta."""
        with self._cerrojo:
            if self._con.execute("SELECT 1 FROM dispositivos WHERE token = ?", (token,)).fetchone() is None:
                return False
            self._con.execute(
                "INSERT INTO actividades (actividad, token, perfil, sesion, run_id, alta) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(actividad) DO UPDATE SET token = excluded.token, perfil = excluded.perfil, "
                "sesion = excluded.sesion, run_id = excluded.run_id, ultimo = NULL",
                (actividad, token, perfil, sesion, run_id, ahora))
            self._con.execute(
                "DELETE FROM actividades WHERE token = ? AND actividad NOT IN "
                "(SELECT actividad FROM actividades WHERE token = ? ORDER BY alta DESC LIMIT ?)", (token, token, maximo))
        return True

    def actividades(self, perfil: str, sesion: str, ahora: float, vida: float) -> list[Actividad]:
        """Las actividades de esa conversación. Las de más de ``vida`` se olvidan aquí: iOS ya las ha quitado."""
        with self._cerrojo:
            self._con.execute("DELETE FROM actividades WHERE alta < ?", (ahora - vida,))
            filas = self._con.execute(
                "SELECT actividad, token, perfil, sesion, run_id, alta, vuelta, ultimo FROM actividades "
                "WHERE perfil = ? AND sesion = ? ORDER BY alta", (perfil, sesion)).fetchall()
        return [Actividad(*fila) for fila in filas]

    def anotar_actividad(self, actividad: str, vuelta: int, ultimo: str) -> None:
        with self._cerrojo:
            self._con.execute("UPDATE actividades SET vuelta = ?, ultimo = ? WHERE actividad = ?",
                              (vuelta, ultimo, actividad))

    def borrar_actividad(self, actividad: str, token: str | None = None) -> bool:
        """Olvida una actividad; con ``token``, solo si es de ese iPhone (lo que pide la app desde la API)."""
        with self._cerrojo:
            if token is None:
                cursor = self._con.execute("DELETE FROM actividades WHERE actividad = ?", (actividad,))
            else:
                cursor = self._con.execute("DELETE FROM actividades WHERE actividad = ? AND token = ?",
                                           (actividad, token))
        return cursor.rowcount > 0

    def vincular(self, token: str, iphone: Iphone) -> bool:
        """De qué iPhone es un alta que aún no lo dice (una de antes de la versión 6), por lo que trae su primer plano.
        Una que ya lo dice no cambia de dueño sin un alta."""
        with self._cerrojo:
            cursor = self._con.execute("UPDATE dispositivos SET iphone = ?, iphone_marca = ? "
                                       "WHERE token = ? AND (iphone IS NULL OR iphone_marca IS NULL)",
                                       (iphone.nombre, iphone.marca, token))
        return cursor.rowcount > 0

    def borrar_las_ajenas(self, quedan: list) -> int:
        """Borra las altas que no son de ningún token de ``quedan`` (las marcas de los que siguen en la pasarela): las
        de uno que se acaba de quitar, las de un token de antes de un nombre que sigue y las que no dicen de quién son.
        Devuelve cuántas."""
        with self._cerrojo:
            marcas = ", ".join("?" for _ in quedan)
            condicion = "iphone_marca IS NULL" + (f" OR iphone_marca NOT IN ({marcas})" if quedan else " OR 1")
            cursor = self._con.execute(f"DELETE FROM dispositivos WHERE {condicion}", list(quedan))
        return cursor.rowcount

    def borrar_las_de_la_marca(self, marca: str) -> int:
        """Borra las altas de un token que ya no vale (el de antes de un iPhone que ha vuelto con el código de
        recuperación con su mismo nombre). Devuelve cuántas."""
        with self._cerrojo:
            cursor = self._con.execute("DELETE FROM dispositivos WHERE iphone_marca = ?", (marca,))
        return cursor.rowcount

    # -- Sesiones

    def sesiones(self) -> dict:
        """`{(perfil, id): EstadoSesion}`: la misma sesión en dos perfiles son dos conversaciones."""
        with self._cerrojo:
            filas = self._con.execute(
                "SELECT id, ultimo_id, referencia, ultima_actividad, mensajes, visto, ultima_respuesta, perfil "
                "FROM sesiones").fetchall()
        return {(fila[7], fila[0]): EstadoSesion(*fila) for fila in filas}

    def guardar_sesion(self, estado: EstadoSesion) -> None:
        """Una sola conversación, en cuanto se ha avisado de lo suyo: si la vuelta se rompe después, lo de esta ya
        consta."""
        with self._cerrojo:
            self._con.execute(
                "INSERT INTO sesiones (perfil, id, ultimo_id, referencia, ultima_actividad, mensajes, visto, "
                "ultima_respuesta) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(perfil, id) DO UPDATE SET "
                "ultimo_id = excluded.ultimo_id, referencia = excluded.referencia, "
                "ultima_actividad = excluded.ultima_actividad, mensajes = excluded.mensajes, visto = excluded.visto, "
                "ultima_respuesta = excluded.ultima_respuesta",
                (estado.perfil, estado.id, estado.ultimo_id, estado.referencia, estado.ultima_actividad,
                 estado.mensajes, estado.visto, estado.ultima_respuesta))

    def podar_sesiones(self, antes_de: float) -> int:
        """Olvida las sesiones que hace mucho que no salen en la bandeja (archivadas, borradas, o muy atrás)."""
        with self._cerrojo:
            cursor = self._con.execute("DELETE FROM sesiones WHERE visto < ?", (antes_de,))
        return cursor.rowcount

    # -- Estado suelto

    def leer_estado(self, clave: str) -> str | None:
        with self._cerrojo:
            fila = self._con.execute("SELECT valor FROM estado WHERE clave = ?", (clave,)).fetchone()
        return fila[0] if fila else None

    def guardar_estado(self, clave: str, valor: str) -> None:
        with self._cerrojo:
            self._con.execute("INSERT INTO estado (clave, valor) VALUES (?, ?) "
                              "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor", (clave, valor))

    # -- Turnos que la app dejó en marcha

    def vigilar_turnos(self, turnos: list, ahora: float) -> None:
        """``turnos``: (run_id, sesión) o (run_id, sesión, perfil), del principal si no lo dice. Un turno que ya se
        vigilaba conserva lo que ya se avisó de él.

        Como mucho ``MAX_TURNOS`` en total, los más recientes: cada uno es una consulta a Hermes en cada vuelta, y la
        app tiene uno o dos en marcha; más que eso es algo que no va bien, no más trabajo que vigilar.
        """
        if not turnos:
            return
        with self._cerrojo:
            self._con.executemany(
                "INSERT INTO turnos (run_id, sesion, alta, visto, perfil) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET visto = excluded.visto",
                [(turno[0], turno[1], ahora, ahora, turno[2] if len(turno) > 2 else PRINCIPAL) for turno in turnos])
            self._con.execute("DELETE FROM turnos WHERE run_id IN (SELECT run_id FROM turnos ORDER BY visto DESC, "
                              "alta DESC LIMIT -1 OFFSET ?)", (MAX_TURNOS,))

    def turnos(self) -> list[Turno]:
        with self._cerrojo:
            filas = self._con.execute(
                "SELECT run_id, sesion, alta, aprobacion_avisada, visto, perfil FROM turnos ORDER BY alta").fetchall()
        return [Turno(*fila) for fila in filas]

    def marcar_aprobacion(self, run_id: str, request_id: str) -> None:
        with self._cerrojo:
            self._con.execute("UPDATE turnos SET aprobacion_avisada = ? WHERE run_id = ?", (request_id, run_id))

    def olvidar_turno(self, run_id: str) -> None:
        with self._cerrojo:
            self._con.execute("DELETE FROM turnos WHERE run_id = ?", (run_id,))

    def podar_turnos(self, antes_de: float) -> int:
        with self._cerrojo:
            cursor = self._con.execute("DELETE FROM turnos WHERE alta < ?", (antes_de,))
        return cursor.rowcount


    # -- Mensajes programados (`programados.py`)

    _COLUMNAS_PROGRAMADOS = "clave, perfil, sesion, hora, cuerpo, creado, estado, run_id, lanzado, fallos, hasta, motivo"

    @staticmethod
    def _programado(fila) -> ProgramadoGuardado:
        return ProgramadoGuardado(clave=fila[0], perfil=fila[1], sesion=fila[2], hora=fila[3],
                                  cuerpo=json.loads(fila[4]), creado=fila[5], estado=fila[6], run_id=fila[7],
                                  lanzado=fila[8], fallos=fila[9], hasta=fila[10], motivo=fila[11])

    def programado(self, clave: str) -> ProgramadoGuardado | None:
        with self._cerrojo:
            fila = self._con.execute(f"SELECT {self._COLUMNAS_PROGRAMADOS} FROM programados WHERE clave = ?",
                                     (clave,)).fetchone()
        return self._programado(fila) if fila else None

    def programados(self, perfil: str | None = None, sesion: str | None = None) -> list[ProgramadoGuardado]:
        """Los de una conversación (o todos), por hora."""
        condiciones, valores = [], []
        if perfil is not None:
            condiciones.append("perfil = ?")
            valores.append(perfil)
        if sesion is not None:
            condiciones.append("sesion = ?")
            valores.append(sesion)
        donde = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
        with self._cerrojo:
            filas = self._con.execute(
                f"SELECT {self._COLUMNAS_PROGRAMADOS} FROM programados{donde} ORDER BY hora, creado, clave",
                valores).fetchall()
        return [self._programado(fila) for fila in filas]

    def contar_programados_pendientes(self) -> int:
        with self._cerrojo:
            return self._con.execute("SELECT COUNT(*) FROM programados WHERE estado = 'pendiente'").fetchone()[0]

    def escribir_programado(self, nuevo: ProgramadoGuardado) -> str:
        """Crea el programado o, si su clave ya estaba **y aún no se ha reclamado**, lo sustituye (la hora, la
        conversación y el cuerpo; ``creado`` se queda). Devuelve ``creado``, ``cambiado`` o ``igual``; ``ya_lanzado`` si
        la clave ya estaba reclamada o lanzada: lo que está en camino no se cambia."""
        with self._cerrojo:
            actual = self.programado(nuevo.clave)
            if actual is None:
                self._con.execute(
                    f"INSERT INTO programados ({self._COLUMNAS_PROGRAMADOS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (nuevo.clave, nuevo.perfil, nuevo.sesion, nuevo.hora, json.dumps(nuevo.cuerpo, sort_keys=True),
                     nuevo.creado, "pendiente", None, None, 0, 0.0, None))
                return "creado"
            if actual.estado != "pendiente":
                return ("igual" if (actual.perfil, actual.sesion, actual.hora, actual.cuerpo)
                        == (nuevo.perfil, nuevo.sesion, nuevo.hora, nuevo.cuerpo) else "ya_lanzado")
            if (actual.perfil, actual.sesion, actual.hora, actual.cuerpo) == (nuevo.perfil, nuevo.sesion, nuevo.hora,
                                                                              nuevo.cuerpo):
                return "igual"
            self._con.execute("UPDATE programados SET perfil = ?, sesion = ?, hora = ?, cuerpo = ?, fallos = 0, "
                              "hasta = 0 WHERE clave = ? AND estado = 'pendiente'",
                              (nuevo.perfil, nuevo.sesion, nuevo.hora, json.dumps(nuevo.cuerpo, sort_keys=True),
                               nuevo.clave))
            return "cambiado"

    def cambiar_programado(self, clave: str, hora: float, cuerpo: dict) -> bool:
        """Solo mientras esté pendiente: desde que se reclama, ya no."""
        with self._cerrojo:
            cursor = self._con.execute(
                "UPDATE programados SET hora = ?, cuerpo = ?, fallos = 0, hasta = 0 WHERE clave = ? "
                "AND estado = 'pendiente'", (hora, json.dumps(cuerpo, sort_keys=True), clave))
        return cursor.rowcount > 0

    def borrar_programado(self, clave: str) -> str:
        """``borrado``, ``no_existe`` o ``ya_lanzado`` (reclamado o lanzado: no se borra, es historia). Uno fallido o
        caducado sí: es quitar el aviso de la app."""
        with self._cerrojo:
            cursor = self._con.execute(
                "DELETE FROM programados WHERE clave = ? AND estado IN ('pendiente', 'fallido', 'caducado')", (clave,))
            if cursor.rowcount:
                return "borrado"
            return "ya_lanzado" if self.programado(clave) is not None else "no_existe"

    def borrar_programados_de(self, perfil: str, sesion: str) -> int:
        """Los pendientes de una conversación que se borra: sin esto saldrían a su hora en una sesión archivada."""
        with self._cerrojo:
            cursor = self._con.execute(
                "DELETE FROM programados WHERE perfil = ? AND sesion = ? AND estado IN ('pendiente', 'fallido', "
                "'caducado')", (perfil, sesion))
        return cursor.rowcount

    def programados_por_hacer(self, ahora: float) -> list[ProgramadoGuardado]:
        """Los pendientes o reclamados a medias cuya hora ya ha llegado, por hora."""
        with self._cerrojo:
            filas = self._con.execute(
                f"SELECT {self._COLUMNAS_PROGRAMADOS} FROM programados WHERE estado IN ('pendiente', 'lanzando') "
                "AND hora <= ? ORDER BY hora, creado, clave", (ahora,)).fetchall()
        return [self._programado(fila) for fila in filas]

    def proxima_hora_programada(self) -> float | None:
        with self._cerrojo:
            fila = self._con.execute(
                "SELECT MIN(hora) FROM programados WHERE estado IN ('pendiente', 'lanzando')").fetchone()
        return fila[0]

    def reclamar_programado(self, clave: str) -> bool:
        """Pendiente → lanzando, de una vez y bajo el cerrojo: quien lo consigue es el único que lo lanza, y desde aquí la
        app ya no lo puede cambiar ni borrar (un POST que llegó pero se dio por fallido, seguido de un cambio de texto,
        dejaría el turno con el texto viejo)."""
        with self._cerrojo:
            cursor = self._con.execute("UPDATE programados SET estado = 'lanzando' WHERE clave = ? "
                                       "AND estado = 'pendiente'", (clave,))
        return cursor.rowcount > 0

    def programado_lanzado(self, clave: str, run_id: str | None, ahora: float) -> None:
        with self._cerrojo:
            self._con.execute("UPDATE programados SET estado = 'lanzado', run_id = ?, lanzado = ?, motivo = NULL "
                              "WHERE clave = ? AND estado = 'lanzando'", (run_id, ahora, clave))

    def programado_con_fallo(self, clave: str, fallos: int, hasta: float) -> None:
        with self._cerrojo:
            self._con.execute("UPDATE programados SET fallos = ?, hasta = ? WHERE clave = ?", (fallos, hasta, clave))

    def programado_terminado(self, clave: str, estado: str, motivo: str, ahora: float) -> None:
        """``fallido`` (Hermes lo rechazó) o ``caducado`` (pasó el retraso máximo sin poder lanzarse)."""
        with self._cerrojo:
            self._con.execute("UPDATE programados SET estado = ?, motivo = ?, lanzado = ? WHERE clave = ? "
                              "AND estado IN ('pendiente', 'lanzando')", (estado, motivo, ahora, clave))

    def podar_programados(self, antes_de: float) -> int:
        """Olvida los que ya no son del futuro y llevan mucho: lanzados, fallidos o caducados."""
        with self._cerrojo:
            cursor = self._con.execute(
                "DELETE FROM programados WHERE estado IN ('lanzado', 'fallido', 'caducado') AND COALESCE(lanzado, hora) "
                "< ?", (antes_de,))
        return cursor.rowcount
