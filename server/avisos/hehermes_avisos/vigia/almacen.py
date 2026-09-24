"""La memoria del vigía, en un SQLite propio (nunca el ``state.db`` de Hermes).

Guarda tres cosas, y ninguna es texto de una conversación:

- los **dispositivos**: token, entorno, clave, ajustes y si la app está delante. La clave es la que cifra los avisos de
  ese iPhone, así que el fichero se crea 0600 y el directorio es del usuario del vigía y de nadie más;
- hasta dónde se ha leído cada **sesión** (el id de la última fila vista), para no avisar dos veces tras un reinicio ni
  de todo el historial la primera vez;
- los **turnos** que la app dejó en marcha al irse, si los manda (ampliación propuesta del contrato: ver el README).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass

from .ajustes import Ajustes

registro = logging.getLogger("vigia.almacen")

# La versión de la base de datos (`PRAGMA user_version`). Cada cambio sube uno, con su paso en `_migrar`, y una base de
# una versión anterior se pone al día al abrirla. La 2 añadió el latido del primer plano (`delante_latido`,
# `delante_caduca`).
ESQUEMA = 2

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
class EstadoSesion:
    id: str
    # La última fila vista. `None` hasta la primera lectura de sus mensajes: entonces vale `referencia`.
    ultimo_id: int | None
    # Lo escrito hasta este instante se da por visto. Es la línea de base de una sesión que el vigía aún no ha leído.
    referencia: float
    ultima_actividad: float | None
    mensajes: int | None
    visto: float


@dataclass(frozen=True)
class Turno:
    run_id: str
    sesion: str
    alta: float
    aprobacion_avisada: str | None
    visto: float


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
        conversacion TEXT
    );
    CREATE TABLE IF NOT EXISTS sesiones (
        id TEXT PRIMARY KEY,
        ultimo_id INTEGER,
        referencia REAL NOT NULL,
        ultima_actividad REAL,
        mensajes INTEGER,
        visto REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS turnos (
        run_id TEXT PRIMARY KEY,
        sesion TEXT NOT NULL,
        alta REAL NOT NULL,
        aprobacion_avisada TEXT,
        visto REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS estado (clave TEXT PRIMARY KEY, valor TEXT NOT NULL);
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

    # -- Dispositivos

    @staticmethod
    def _dispositivo(fila) -> Dispositivo:
        return Dispositivo(token=fila[0], entorno=fila[1], clave=bytes(fila[2]),
                           ajustes=Ajustes.desde_json(json.loads(fila[3])), alta=fila[4], actualizado=fila[5],
                           delante_desde=fila[6], delante_latido=fila[7], delante_caduca=fila[8],
                           delante_hasta=fila[9], conversacion=fila[10])

    _COLUMNAS = ("token, entorno, clave, ajustes, alta, actualizado, delante_desde, delante_latido, delante_caduca, "
                 "delante_hasta, conversacion")

    def guardar_dispositivo(self, token: str, entorno: str, clave: bytes, ajustes: Ajustes, ahora: float) -> bool:
        """Da de alta el dispositivo o, si el token ya estaba, lo actualiza (el alta es idempotente por token).

        Devuelve si es nuevo. Por encima de ``max_dispositivos`` se olvida el que lleva más tiempo sin darse de alta:
        la app se da de alta en cada arranque, así que ese es el de una instalación que ya no existe, y su token habría
        muerto igual en cuanto Apple lo dijera.
        """
        with self._cerrojo:
            existia = self._con.execute("SELECT 1 FROM dispositivos WHERE token = ?", (token,)).fetchone() is not None
            self._con.execute("BEGIN")
            try:
                if existia:
                    self._con.execute(
                        "UPDATE dispositivos SET entorno = ?, clave = ?, ajustes = ?, actualizado = ? WHERE token = ?",
                        (entorno, clave, json.dumps(ajustes.a_json()), ahora, token))
                else:
                    self._con.execute(
                        "INSERT INTO dispositivos (token, entorno, clave, ajustes, alta, actualizado) "
                        "VALUES (?, ?, ?, ?, ?, ?)", (token, entorno, clave, json.dumps(ajustes.a_json()), ahora, ahora))
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

    def borrar_dispositivo(self, token: str) -> bool:
        with self._cerrojo:
            cursor = self._con.execute("DELETE FROM dispositivos WHERE token = ?", (token,))
        return cursor.rowcount > 0

    # -- Sesiones

    def sesiones(self) -> dict:
        with self._cerrojo:
            filas = self._con.execute(
                "SELECT id, ultimo_id, referencia, ultima_actividad, mensajes, visto FROM sesiones").fetchall()
        return {fila[0]: EstadoSesion(*fila) for fila in filas}

    def guardar_sesion(self, estado: EstadoSesion) -> None:
        """Una sola conversación, en cuanto se ha avisado de lo suyo: si la vuelta se rompe después, lo de esta ya
        consta."""
        with self._cerrojo:
            self._con.execute(
                "INSERT INTO sesiones (id, ultimo_id, referencia, ultima_actividad, mensajes, visto) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET ultimo_id = excluded.ultimo_id, "
                "referencia = excluded.referencia, ultima_actividad = excluded.ultima_actividad, "
                "mensajes = excluded.mensajes, visto = excluded.visto",
                (estado.id, estado.ultimo_id, estado.referencia, estado.ultima_actividad, estado.mensajes,
                 estado.visto))

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
        """``turnos``: pares (run_id, sesión). Un turno que ya se vigilaba conserva lo que ya se avisó de él.

        Como mucho ``MAX_TURNOS`` en total, los más recientes: cada uno es una consulta a Hermes en cada vuelta, y la
        app tiene uno o dos en marcha; más que eso es algo que no va bien, no más trabajo que vigilar.
        """
        if not turnos:
            return
        with self._cerrojo:
            self._con.executemany(
                "INSERT INTO turnos (run_id, sesion, alta, visto) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET visto = excluded.visto",
                [(run_id, sesion, ahora, ahora) for run_id, sesion in turnos])
            self._con.execute("DELETE FROM turnos WHERE run_id IN (SELECT run_id FROM turnos ORDER BY visto DESC, "
                              "alta DESC LIMIT -1 OFFSET ?)", (MAX_TURNOS,))

    def turnos(self) -> list[Turno]:
        with self._cerrojo:
            filas = self._con.execute(
                "SELECT run_id, sesion, alta, aprobacion_avisada, visto FROM turnos ORDER BY alta").fetchall()
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
