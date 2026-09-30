"""El borrado de verdad de lo que la app borra de Hermes (desde la 0.9.0).

«Eliminar también de Hermes» (la app) es `DELETE /api/sessions/{id}`: Hermes borra las filas de su `state.db`, pero
SQLite no borra nada del disco (`secure_delete` apagado): las páginas quedan libres y lo borrado se puede recuperar del
fichero hasta que se compacte. En el VPS de Daniel, 220 000 filas borradas seguían ahí (2026-09-29) hasta que se hizo a
mano `hermes sessions optimize` (el FTS fusionado y un VACUUM: 836 MB → 140 MB), que no corre con Hermes escribiendo
salvo con `--force`, así que se paró `hermes-gateway`, se compactó y se volvió a arrancar (unos 15 s).

Esto lo hace solo, con cuidado:

1. La pasarela, cuando Hermes contesta 2xx a un `DELETE /api/sessions/…`, apunta `borrado-pendiente` en su carpeta de
   estado: solo desde cuándo, ni el id ni nada de lo que era (`pasarela.Mantenimiento`). Y cada poco, su actividad.
2. `hehermes-borrado.timer` lanza `hehermes-servidor borrado-seguro` cada 15 minutos de 2:00 a 6:00 (hora del
   servidor). Si hay algo pendiente, **y** es un rato tranquilo (ninguna petición con Hermes, ninguna en 10 minutos, y
   el `state.db` de Hermes sin tocar en 10 minutos: ni la app, ni Telegram, ni un subagente), para la unidad de Hermes,
   compacta (`hermes sessions optimize`; si ese Hermes no lo sabe hacer, lo mismo con sqlite: `optimize` de cada índice
   FTS5 y `VACUUM`), la vuelve a arrancar, espera a que su `/health` conteste y quita la marca.
3. Nunca en bucle: un intento por noche (20 horas entre dos), con un tope duro de 15 minutos para compactar y Hermes
   arrancado otra vez pase lo que pase; a los tres fallos seguidos deja de intentarlo, y `comprobar` lo dice. Si no
   puede parar Hermes (no es una unidad de systemd, o sin root la unidad es del sistema), no lo intenta: lo apunta, y
   `comprobar` dice qué hacer a mano.

Lo que pasó queda en `mantenimiento.json` (la última vez, el último intento, el fallo, cuántos seguidos), que la
pasarela enseña a la app en `GET /hehermes/v1/mantenimiento`.
"""

from __future__ import annotations

import datetime
import json
import os
import time

from . import gestor as gestores
from . import piezas as p
from .pasarela import ACTIVIDAD, BORRADO_PENDIENTE, MANTENIMIENTO, pendiente_desde

#: De qué hora a qué hora (del servidor) se puede parar Hermes.
NOCHE = (2, 6)
#: Sin nada con Hermes en estos segundos: ni peticiones por la pasarela, ni escrituras en su state.db.
CALMA = 600
#: Entre dos intentos (uno por noche), y a los cuántos fallos seguidos se deja de intentar.
ENTRE_INTENTOS = 20 * 3600
MAX_FALLOS = 3
#: El tope duro de la compactación, y lo que se espera a que Hermes vuelva a contestar.
PLAZO_COMPACTAR = 900
PLAZO_SALUD = 60

#: Lo que compacta con sqlite si el `hermes` de ese servidor no sabe `sessions optimize`: el `optimize` de cada índice
#: FTS5 (fusiona sus segmentos, que guardan lo borrado) y un VACUUM (reescribe el fichero sin páginas libres). Corre como
#: el usuario de Hermes, para que el -wal y el -shm sigan siendo suyos.
COMPACTAR_CON_SQLITE = (
    "import sqlite3, sys\n"
    "c = sqlite3.connect(sys.argv[1], timeout=30)\n"
    "for (n,) in c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE '%USING fts5%'\"):\n"
    "    c.execute('INSERT INTO \"%s\"(\"%s\") VALUES (\\'optimize\\')' % (n.replace('\"', '\"\"'), n.replace('\"', '\"\"')))\n"
    "c.commit()\n"
    "c.execute('VACUUM')\n"
    "c.close()\n"
)


# MARK: Las decisiones (puras)


def momento_tranquilo(hora_local: int, actividad: dict | None, cambio_db: float | None, ahora: float,
                      noche=NOCHE, calma=CALMA) -> tuple:
    """(sí o no, por qué). De noche, sin peticiones con Hermes, ninguna en `calma` segundos, y su base sin tocar en
    `calma` segundos. Sin la actividad de la pasarela (una de antes, o parada), cuenta solo la base."""
    if not noche[0] <= hora_local < noche[1]:
        return False, "no es de noche (%d:00-%d:00)" % noche
    if isinstance(actividad, dict):
        reenviando, ultima = actividad.get("reenviando"), actividad.get("ultima")
        if isinstance(reenviando, int) and reenviando > 0:
            return False, "hay %d peticiones con Hermes" % reenviando
        if isinstance(ultima, (int, float)) and ahora - ultima < calma:
            return False, "la última petición fue hace %d s" % (ahora - ultima)
    if cambio_db is not None and ahora - cambio_db < calma:
        return False, "Hermes ha escrito en su base hace %d s" % (ahora - cambio_db)
    return True, "tranquilo"


def debe_intentar(estado: dict, ahora: float, entre=ENTRE_INTENTOS, maximo=MAX_FALLOS) -> tuple:
    """(sí o no, por qué): una vez por noche, y no después de `maximo` fallos seguidos."""
    fallos = estado.get("fallos_seguidos") if isinstance(estado.get("fallos_seguidos"), int) else 0
    if fallos >= maximo:
        return False, "%d fallos seguidos: ya no lo intento solo (mira `comprobar`)" % fallos
    ultimo = estado.get("ultimo_intento")
    if isinstance(ultimo, (int, float)) and ahora - ultimo < entre:
        return False, "ya lo intenté hace %d h" % ((ahora - ultimo) // 3600)
    return True, "toca"


# MARK: Lo que hace


def _leer_json(sis, ruta) -> dict:
    try:
        datos = json.loads(sis.leer(ruta) or b"{}")
    except ValueError:
        return {}
    return datos if isinstance(datos, dict) else {}


def _guardar(sis, ambito, estado):
    sis.escribir(ambito.carpeta_estado_pasarela + "/" + MANTENIMIENTO,
                 json.dumps(estado, sort_keys=True).encode("ascii"), modo=0o644)


def _cambio(sis, ruta):
    """El último cambio de un fichero (mtime), o None."""
    try:
        return os.stat(sis.ruta(ruta)).st_mtime
    except OSError:
        return None


def gestor_de_hermes(man):
    """Quién lleva a Hermes, del manifiesto: `gestor_hermes` desde la 0.10.2; antes, solo `unidad_hermes` (del sistema)."""
    datos = man.datos.get("mantenimiento") or {}
    gestor = gestores.desde_dict(datos.get("gestor_hermes"))
    if gestor is None and "gestor_hermes" not in datos and datos.get("unidad_hermes"):
        gestor = gestores.desde_dict({"tipo": "sistema", "nombre": datos["unidad_hermes"]})
    return gestor


def como_parar(man, ambito) -> tuple:
    """(gestor de Hermes, None) si se puede parar y arrancar; (None, por qué) si no. Su unidad, se llame como se llame
    (la de un perfil, `hermes-gateway-trabajo`) y sea del sistema o de usuario; un contenedor no: su `state.db` puede no
    estar en el servidor, y su `hermes` no está fuera."""
    datos = man.datos.get("mantenimiento") or {}
    gestor = gestor_de_hermes(man)
    if gestor is None or gestor.tipo in gestores.CONTENEDORES:
        return None, ("Hermes no corre como una unidad de systemd (%s): no sé pararlo y volver a arrancarlo"
                      % (datos.get("origen") or "?"))
    if not gestores.puede_reiniciar(gestor, ambito):
        return None, "Hermes es %s, y sin root no la puedo parar" % gestor.describir()
    return gestor, None


def _hermes_que_sabe_optimizar(sis, datos, gestor=None, root=True) -> list | None:
    """La orden de `hermes` de ese Hermes (la de su unidad, o la del PATH) si sabe `sessions optimize`; None si no."""
    candidatas = []
    gestor = gestor or gestores.Gestor("sistema", datos["unidad_hermes"])
    r = sis.ejecutar(gestores.systemctl(gestor, root, "show", gestor.nombre, "-p", "ExecStart", "--value"))
    for trozo in r.salida.replace(";", " ").split():
        if trozo.startswith("path=") and "/" in trozo:
            candidatas.append(os.path.dirname(trozo[5:]) + "/hermes")
    candidatas.append(sis.cual("hermes"))
    for hermes in dict.fromkeys(c for c in candidatas if c):
        orden = _como_hermes(datos, root) + [hermes, "sessions", "optimize", "--help"]
        if sis.existe(hermes) and sis.ejecutar(orden).bien:
            return [hermes, "sessions", "optimize"]
    return None


def _como_hermes(datos, root=True) -> list:
    """Lo que va delante de una orden para que corra como el usuario de Hermes y con su casa (la de su perfil, si
    corre con uno). Sin root ya se es ese usuario (`como_parar` solo deja su propia unidad)."""
    entorno = ["env", "HERMES_HOME=%s" % datos["casa"]]
    usuario = datos.get("usuario") or "root"
    return (["runuser", "-u", usuario, "--"] if usuario != "root" and root else []) + entorno


def borrado_seguro(sis, man, ambito, salida=print, ahora=None, hora_local=None, esperar=time.sleep) -> int:
    """`hehermes-servidor borrado-seguro`, lo que lanza `hehermes-borrado.timer`. 0 si no había nada que hacer o se ha
    hecho; 1 si lo ha intentado y ha fallado (lo apunta, y no lo repite hasta la noche siguiente)."""
    ahora = time.time() if ahora is None else ahora
    hora_local = datetime.datetime.fromtimestamp(ahora).hour if hora_local is None else hora_local
    carpeta = ambito.carpeta_estado_pasarela
    desde = pendiente_desde(sis.leer(carpeta + "/" + BORRADO_PENDIENTE))
    if desde is None:
        return 0
    estado = _leer_json(sis, carpeta + "/" + MANTENIMIENTO)
    unidad, no_puede = como_parar(man, ambito)
    if unidad is None:
        if estado.get("no_puede") != no_puede:
            estado["no_puede"] = no_puede
            _guardar(sis, ambito, estado)
        salida("borrado de verdad: pendiente desde %s, pero %s" % (_fecha(desde), no_puede))
        return 0
    si, porque = debe_intentar(estado, ahora)
    if not si:
        salida("borrado de verdad: pendiente; %s" % porque)
        return 0
    datos = man.datos["mantenimiento"]
    base = datos["casa"].rstrip("/") + "/state.db"
    cambio = max([c for c in (_cambio(sis, base), _cambio(sis, base + "-wal")) if c is not None], default=None)
    si, porque = momento_tranquilo(hora_local, _leer_json(sis, carpeta + "/" + ACTIVIDAD), cambio, ahora)
    if not si:
        salida("borrado de verdad: pendiente; espero a un rato tranquilo (%s)" % porque)
        return 0
    estado.update(ultimo_intento=int(ahora), no_puede=None)
    fallo, metodo = _compactar(sis, datos, unidad, salida, esperar, root=ambito.root)
    if fallo is None:
        sis.borrar(carpeta + "/" + BORRADO_PENDIENTE)
        estado.update(ultimo_borrado=int(ahora), fallo=None, fallos_seguidos=0, metodo=metodo)
        salida("borrado de verdad: hecho (%s); Hermes vuelve a estar en marcha" % metodo)
    else:
        seguidos = estado.get("fallos_seguidos") if isinstance(estado.get("fallos_seguidos"), int) else 0
        estado.update(fallo=fallo, fallos_seguidos=seguidos + 1)
        salida("borrado de verdad: ha fallado (%s). Lo vuelvo a intentar la noche que viene" % fallo)
    _guardar(sis, ambito, estado)
    return 0 if fallo is None else 1


def _compactar(sis, datos, gestor, salida, esperar, root=True) -> tuple:
    """Para Hermes, compacta y lo vuelve a arrancar, pase lo que pase. (fallo o None, cómo se hizo)."""
    unidad = gestor.nombre
    if not sis.ejecutar(gestores.systemctl(gestor, root, "stop", unidad)).bien:
        return "no he podido parar %s" % unidad, None
    fallo, metodo = None, None
    try:
        orden = _hermes_que_sabe_optimizar(sis, datos, gestor, root)
        if orden is not None:
            metodo = "hermes sessions optimize"
            r = sis.ejecutar(["timeout", "--kill-after=30", str(PLAZO_COMPACTAR)] + _como_hermes(datos, root) + orden)
        else:
            metodo = "sqlite (optimize de FTS5 y VACUUM)"
            r = sis.ejecutar(["timeout", "--kill-after=30", str(PLAZO_COMPACTAR)] + _como_hermes(datos, root)
                             + ["/usr/bin/python3", "-I", "-c", COMPACTAR_CON_SQLITE,
                                datos["casa"].rstrip("/") + "/state.db"])
        if r.codigo in (124, 137):
            fallo = "compactar ha pasado de %d s y lo he cortado" % PLAZO_COMPACTAR
        elif not r.bien:
            fallo = "compactar ha fallado (%s): %s" % (r.codigo, (r.error or r.salida).strip()[-200:])
    finally:
        arrancado = sis.ejecutar(gestores.systemctl(gestor, root, "start", unidad)).bien
    salud = _esperar_salud(sis, datos.get("puerto") or 8642, esperar) if arrancado else False
    if not arrancado:
        fallo = (fallo + "; " if fallo else "") + "¡no he podido volver a arrancar %s!" % unidad
    elif not salud:
        fallo = (fallo + "; " if fallo else "") + "Hermes no contesta en /health tras arrancarlo"
    return fallo, metodo


def _esperar_salud(sis, puerto, esperar) -> bool:
    limite = PLAZO_SALUD
    while True:
        estado, _ = sis.http_get("http://127.0.0.1:%d/health" % int(puerto))
        if estado == 200:
            return True
        if limite <= 0:
            return False
        esperar(2)
        limite -= 2


def _fecha(segundos) -> str:
    return datetime.datetime.fromtimestamp(segundos).strftime("%Y-%m-%d %H:%M")


# MARK: comprobar


def comprobar(sis, man, ambito, mira) -> None:
    """Lo del borrado de verdad, para `comprobar`: pendiente o no, la última vez, y si no puede o ha dejado de poder."""
    carpeta = ambito.carpeta_estado_pasarela
    desde = pendiente_desde(sis.leer(carpeta + "/" + BORRADO_PENDIENTE))
    estado = _leer_json(sis, carpeta + "/" + MANTENIMIENTO)
    unidad, no_puede = como_parar(man, ambito)
    ultimo = estado.get("ultimo_borrado")
    antes = "; el último, %s" % _fecha(ultimo) if isinstance(ultimo, (int, float)) else ""
    a_mano = ("con Hermes parado: HERMES_HOME=%s hermes sessions optimize"
              % (man.datos.get("mantenimiento") or {}).get("casa", "<su casa>"))
    if desde is None:
        mira(True, "borrado de verdad: nada pendiente%s" % antes, "")
    elif unidad is None:
        mira(False, "", "borrado de verdad: lo borrado desde %s sigue en el disco de Hermes (recuperable), y %s. Hazlo tú, "
                        "%s" % (_fecha(desde), no_puede, a_mano))
    elif isinstance(estado.get("fallos_seguidos"), int) and estado["fallos_seguidos"] >= MAX_FALLOS:
        mira(False, "", "borrado de verdad: pendiente desde %s y ya no lo intento solo tras %d fallos (el último: %s). "
                        "Hazlo tú, %s" % (_fecha(desde), estado["fallos_seguidos"], estado.get("fallo"), a_mano))
    else:
        fallo = " (el último intento falló: %s)" % estado["fallo"] if estado.get("fallo") else ""
        mira(True, "borrado de verdad: pendiente desde %s; se hace de noche (%d:00-%d:00), con Hermes parado unos "
                   "segundos%s%s" % ((_fecha(desde),) + NOCHE + (fallo, antes)), "")


# MARK: Las unidades


def unidades(ambito) -> dict:
    """{ruta: texto} de la unidad y el temporizador del borrado de verdad."""
    return {ambito.unidad_borrado: p.unidad_borrado(ambito), ambito.temporizador_borrado: p.temporizador_borrado()}
