"""La instalación por chat, en segundo plano (desde la 0.11.2).

Por chat, `instalar --por-chat` lo lanza la herramienta de terminal de Hermes, que tiene un plazo: 180 s de serie (el
modelo lo puede subir hasta 600, y por encima la pasa a segundo plano) y, por encima de todo, el de su agente, 420 s, que
se queda sin la salida (`agent/tool_executor.py`, `_DEFAULT_CONCURRENT_TOOL_TIMEOUT_S`). Al pasarse, SIGTERM a todo el
grupo de procesos, SIGKILL un segundo después y lo mismo a lo que se escapó con `setsid`, que busca en el árbol de
procesos (`tools/environments/local.py`, `_kill_process_group_posix`). Con apt y pip en un VPS de una CPU, la instalación
puede pasar de eso: la 0.11.1 ya decía hasta dónde llegó (`hehermes-error:interrumpido`), pero no lo evitaba.

Desde la 0.11.2, `instalar --por-chat` no instala: lanza la instalación en su propia unidad pasajera de systemd
(`hehermes-instalar`, como el canje), que es hija de PID 1, así que no está en el árbol de procesos de Hermes ni en su
cgroup: ni su plazo ni su reinicio la cortan. Y la sigue, enseñando lo que imprime al momento, hasta `PLAZO_DEL_CHAT`:

- si acaba antes, su final, igual que antes: el enlace (`hehermes-canje:`) o el fallo (`hehermes-error:`), con su código
  de salida;
- si no, `hehermes-sigue: <paso> (<segundos> s)`, la última, y sale con 0: no ha fallado nada;
- el mismo comando otra vez (la misma orden, letra a letra) se engancha a la que está en marcha, sin lanzar otra, y la
  sigue otro rato; si ya acabó, da su final: el enlace mientras su canje siga abierto, y un fallo, una vez;
- con otra orden (otra frase: otra llave, otro iPhone) y una instalación en marcha, espera a que acabe y lanza la suya;
- desde la 0.12.0 (2026-10-08), si la instalación dice que va a actualizar a Hermes y reiniciarlo
  (`marcha.PREFIJO_REINICIO`, `actualizar_hermes`), acaba ya, con esa línea la última: el reinicio cortaría su turno, y
  así Hermes contesta antes. Mientras siga en eso, el mismo comando otra vez acaba igual enseguida (`en_reinicio`).

Lo que imprime va a `salida`, en `ambito.run_instalar` (0700, en /run: con root, solo de root; sin root, del usuario), y
el enlace se queda ahí mientras vale su canje: lo borra la limpieza del canje (`al_cerrar_el_canje`). Sin systemd que la
lance (sin `systemd-run` o sin el gestor de usuario, o si no arranca), la instalación va aquí mismo, como hasta la 0.11.1.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import signal
import threading
import time

from . import VERSION, marcha

UNIDAD = "hehermes-instalar"
#: Lo que la sigue cada vez, desde que arranca este proceso: por debajo de los 180 s de serie de la terminal de Hermes,
#: con margen para lo de antes, que también cuenta en su plazo (la descarga, la suma, el `sudo -n`).
PLAZO_DEL_CHAT = 140
#: Cada cuánto mira si hay líneas nuevas y si sigue en marcha.
CADA = 0.5
#: `RuntimeMaxSec`: lo más que puede durar (apt hasta 15 minutos, pip hasta 30). Si algo se cuelga, systemd la para.
TOPE_DE_LA_UNIDAD = 3600
PREFIJO_SIGUE = "hehermes-sigue:"
#: Los antepasados de quien la lanza (su terminal y Hermes). En su unidad la instalación es hija de PID 1, y con varios
#: Hermes en marcha son lo que dice cuál la ha lanzado (`deteccion._el_que_me_lanza`).
ANTEPASADOS = "HEHERMES_LANZADO_POR"
#: Lo de dentro de `ambito.run_instalar`: lo que imprime, de quién es y el paquete del que corre.
SALIDA = "salida"
ESTADO = "estado.json"
PAQUETE = "hehermes-servidor"
#: La marca de la de dentro (oculta en la ayuda): ella instala, no lanza otra.
BANDERA = "--en-segundo-plano"
SENALES = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
_PASO = re.compile(r"^%s (\d+/\d+ [a-z-]+) \(\d+ s\)$" % re.escape(marcha.PREFIJO_PASO))
_FINAL = re.compile(r"^(hehermes-canje:|%s)" % re.escape(marcha.PREFIJO_ERROR))
#: Lo que se le pasa del entorno: rutas y números, nada que pueda romper la orden de systemd-run.
_SEGURO = re.compile(r"[A-Za-z0-9._/@+:-]{1,512}")

# El reloj y la espera: las pruebas los sustituyen.
_reloj = time.monotonic
_dormir = time.sleep


def toca(op) -> bool:
    """Si esta orden va en segundo plano: `instalar --por-chat` que cambia algo (sin `--plan`), y que no es ya la de
    dentro ni la que va aquí mismo porque no se pudo lanzar."""
    return (getattr(op, "orden", None) == "instalar" and bool(getattr(op, "por_chat", False))
            and not getattr(op, "plan", False) and not getattr(op, "en_segundo_plano", False)
            and not getattr(op, "en_primer_plano", False))


def huella_de(argv) -> str:
    """La orden, letra a letra y con la versión: «el mismo comando otra vez» es la misma huella."""
    return hashlib.sha256(json.dumps([VERSION] + [a for a in argv if a != BANDERA]).encode()).hexdigest()


def por_chat(sis, ambito, argv, aqui, salida, en_primer_plano) -> int:
    """Lanza la instalación (o se engancha a la que ya está en marcha) y la sigue hasta `PLAZO_DEL_CHAT`.
    `en_primer_plano`, lo de siempre, para cuando no se puede lanzar."""
    limite = _reloj() + PLAZO_DEL_CHAT
    if not _se_puede(sis, ambito):
        # Sin systemd la detección lo dirá con su código (`sistema`, `contenedor`); sin el gestor de usuario, `linger`.
        return en_primer_plano()
    huella = huella_de(argv)
    for _ in range(3):
        with _cerrojo(sis, ambito):
            que, estado = _decidir(sis, ambito, huella)
            if que == "nueva":
                motivo = _lanzar(sis, ambito, argv, aqui, huella)
                if motivo is not None and _en_marcha(sis, ambito):
                    continue  # la ha lanzado otro justo ahora: se vuelve a mirar de quién es
                if motivo is not None:
                    _olvidar(sis, ambito)
                    salida("No he podido lanzar la instalación en segundo plano (%s): la hago aquí mismo. Si el plazo "
                           "de esta terminal la corta, el mismo comando otra vez sigue donde se quedó." % motivo)
                    return en_primer_plano()
                estado = _leer_estado(sis, ambito)
                salida("La instalación va en segundo plano, en su propia unidad (%s): ni el plazo de esta terminal ni el "
                       "reinicio de Hermes la cortan. La sigo desde aquí." % UNIDAD)
        if que == "final":
            salida("Esta instalación ya ha acabado. Lo que dijo:")
            return _el_final(sis, ambito, salida, _leer_salida(sis, ambito))
        if que == "seguir":
            salida("Esta misma instalación ya está en marcha desde hace %d s: no lanzo otra, la sigo desde aquí. Lo "
                   "que lleva dicho:" % _desde(estado))
        if que in ("nueva", "seguir"):
            return _seguir(sis, ambito, salida, estado, limite)
        if not _esperar_a_otra(sis, ambito, salida, estado, limite):
            return 0
    raise marcha.Ocupado("no consigo lanzar la instalación en segundo plano: otra la lanza y la para a la vez")


def al_cerrar_el_canje(sis, ambito) -> None:
    """La limpieza del canje (`canje-limpiar`): canjeado, caducado o parado, el enlace guardado ya no vale, y se borra con
    todo lo de la instalación que lo dio. Salvo si hay una en marcha: es ella la que ha parado el canje para lanzar el
    suyo, y lo de dentro es suyo."""
    if not sis.existe(ambito.run_instalar):
        return
    try:
        with _cerrojo(sis, ambito, espera=5):
            if not _en_marcha(sis, ambito):
                _olvidar(sis, ambito)
    except (marcha.Ocupado, OSError, ValueError):
        pass


def resultado_de(texto: str) -> str | None:
    """«enlace» o «error», según la última línea final que haya (la de `hehermes-canje:` o la de `hehermes-error:`), o
    None si no hay ninguna: lo pararon sin dejarle decirlo."""
    final = None
    for linea in texto.splitlines():
        hallado = _FINAL.match(linea.strip())
        if hallado:
            final = "enlace" if hallado.group(1) == "hehermes-canje:" else "error"
    return final


def en_reinicio(texto: str) -> bool:
    """Si lo último que ha dicho la instalación es que va a actualizar Hermes y reiniciarlo (`marcha.PREFIJO_REINICIO`,
    desde la 0.12.0): sin nada detrás que diga que ya ha vuelto, un paso, un final o que sigue."""
    dentro = False
    for linea in texto.splitlines():
        linea = linea.strip()
        if linea.startswith(marcha.PREFIJO_REINICIO):
            dentro = True
        elif linea.startswith((marcha.DE_VUELTA, marcha.PREFIJO_PASO, PREFIJO_SIGUE)) or _FINAL.match(linea):
            dentro = False
    return dentro


def antepasados_de(sis) -> list:
    """Los pid de este proceso hacia arriba, sin PID 1: los de la terminal de Hermes y el de Hermes."""
    pid, vistos = getattr(sis, "pid", None), []
    while pid is not None and str(pid) not in vistos and str(pid) not in ("0", "1") and len(vistos) < 64:
        vistos.append(str(pid))
        estado = sis.leer_texto("/proc/%s/status" % pid) or ""
        padre = re.search(r"^PPid:\s*(\d+)\s*$", estado, re.M)
        pid = padre.group(1) if padre else None
    return vistos


# MARK: Decidir y lanzar


def _se_puede(sis, ambito) -> bool:
    if not sis.es_carpeta("/run/systemd/system") or not sis.cual("systemd-run"):
        return False
    return ambito.root or sis.es_carpeta(os.path.dirname(ambito.run_instalar))


def _decidir(sis, ambito, huella):
    """(«seguir», «otra», «final» o «nueva», el estado guardado). Con el cerrojo tomado."""
    estado = _leer_estado(sis, ambito)
    es_esta = estado is not None and estado.get("orden") == huella
    if _en_marcha(sis, ambito):
        return ("seguir" if es_esta else "otra"), estado
    if es_esta:
        que = resultado_de(_leer_salida(sis, ambito))
        if que == "enlace" and _canje_abierto(sis, ambito):
            return "final", estado
        if que != "enlace" and not estado.get("entregado"):
            return "final", estado
    return "nueva", estado


def _lanzar(sis, ambito, argv, aqui, huella) -> str | None:
    """Prepara su carpeta (solo de root, o del usuario) y la lanza. None si ha arrancado; si no, por qué."""
    carpeta = ambito.run_instalar
    try:
        _olvidar(sis, ambito)
        sis.carpeta(carpeta, 0o700)
        _copiar_el_paquete(sis, aqui, carpeta + "/" + PAQUETE)
        # Antes de lanzarla, y vacío: systemd lo abriría con 0644, y lleva el enlace.
        sis.escribir(carpeta + "/" + SALIDA, b"", modo=0o600)
        _guardar_estado(sis, ambito, {"orden": huella, "version": VERSION, "inicio": time.time()})
    except (OSError, ValueError) as error:
        return "no puedo preparar %s: %s" % (carpeta, getattr(error, "strerror", None) or error)
    r = sis.ejecutar(_orden(sis, ambito, argv, carpeta))
    if r.bien:
        return None
    return (r.error or r.salida).strip()[-200:] or "systemd-run ha salido con %d" % r.codigo


def _orden(sis, ambito, argv, carpeta) -> list:
    """Su propia unidad, como la del canje (`porchat._systemd_run`): ni `--scope`, que se quedaría en el cgroup de quien la
    lanza (por chat, el de Hermes), ni atada a la unidad de Hermes, así que reiniciarlo no la toca. Sin jaula: es el
    instalador, como root, como por SSH. Lo que imprime, a su fichero; lo que cuenta de quién la lanza, por su entorno."""
    orden = ["systemd-run"] + ([] if ambito.root else ["--user"]) + ["--unit=" + UNIDAD, "--collect", "--quiet"]
    for propiedad in ("Description=HeHermes: la instalación por chat, en segundo plano",
                      "StandardOutput=file:%s/%s" % (carpeta, SALIDA), "StandardError=inherit",
                      "RuntimeMaxSec=%d" % TOPE_DE_LA_UNIDAD):
        orden += ["-p", propiedad]
    antepasados = antepasados_de(sis)
    if antepasados:
        orden.append("--setenv=%s=%s" % (ANTEPASADOS, " ".join(antepasados)))
    entorno = getattr(sis, "entorno", None) or {}
    # Su HERMES_HOME (el de su perfil) y, con sudo, quién lo lanzó: el PNG de `--qr-png` es suyo (`porchat._qr_png`).
    for nombre in ("HERMES_HOME", "SUDO_UID", "SUDO_GID"):
        if _SEGURO.fullmatch(entorno.get(nombre) or ""):
            orden.append("--setenv=%s=%s" % (nombre, entorno[nombre]))
    return orden + ["/usr/bin/python3", "-I", "-B", "%s/%s/hehermes-servidor" % (carpeta, PAQUETE)] + \
        [a for a in argv if a != BANDERA] + [BANDERA]


def _copiar_el_paquete(sis, origen, destino) -> None:
    """Lo que necesita para correr, en la carpeta de root: la de `mktemp` es del usuario de Hermes, y con `PrivateTmp`
    en su unidad ni siquiera la vería PID 1. Lo mismo que se instala en el prefijo (`plan.ficheros_propios` y el código
    de los avisos), que sale igual del paquete que del repositorio."""
    from .avisos import ficheros_del_codigo
    from .plan import ficheros_propios
    for ruta, datos, modo in ficheros_propios(origen, destino):
        sis.escribir(ruta, datos, modo=modo)
    for ruta, datos in ficheros_del_codigo(origen, destino):
        sis.escribir(ruta, datos, modo=0o644)


# MARK: Seguirla


def _seguir(sis, ambito, salida, estado, limite) -> int:
    """Lo que imprime, desde el principio y al momento, hasta que acabe o hasta `limite`."""
    ruta = ambito.run_instalar + "/" + SALIDA
    leido, resto, paso = 0, b"", {"donde": None}
    with _si_me_cortan():
        try:
            while True:
                # Primero si sigue en marcha, y luego lo que ha escrito: si ya no lo está, lo escrito está entero.
                activa = _en_marcha(sis, ambito)
                datos = sis.leer(ruta) or b""
                nuevo, leido = resto + datos[leido:], max(leido, len(datos))
                *lineas, resto = nuevo.split(b"\n")
                for linea in lineas:
                    texto = linea.decode("utf-8", "replace")
                    salida(texto)
                    hallado = _PASO.match(texto.strip())
                    if hallado:
                        paso["donde"] = hallado.group(1)
                if not activa:
                    if resto:
                        salida(resto.decode("utf-8", "replace"))
                    return _el_final(sis, ambito, salida, datos.decode("utf-8", "replace"), ya_dicho=True)
                if en_reinicio(datos.decode("utf-8", "replace")):
                    # Desde la 0.12.0: va a actualizar Hermes y reiniciarlo, y eso cortaría este turno. Se acaba ya, con
                    # su línea la última, para que Hermes conteste antes; la instalación sigue (`actualizar_hermes`).
                    return 0
                if _reloj() >= limite:
                    return _sigue(salida, estado, paso["donde"], "\nLa instalación sigue en segundo plano")
                _dormir(CADA)
        except _Cortado as cortado:
            return _sigue(salida, estado, paso["donde"], "\nDejo de seguirla (%s), pero la instalación sigue en segundo "
                          "plano" % cortado.senal)


def _esperar_a_otra(sis, ambito, salida, estado, limite) -> bool:
    """Otra instalación en marcha, de otra orden: se espera a que acabe, sin enseñar lo suyo (su enlace sería el de otra
    llave). True si ha acabado; si no, ya ha dicho que sigue."""
    salida("Hay otra instalación en marcha desde hace %d s, de otra frase (otro iPhone u otra llave): espero a que acabe "
           "para lanzar la de esta, sin pisarla." % _desde(estado))
    with _si_me_cortan():
        try:
            while _en_marcha(sis, ambito):
                if _reloj() >= limite:
                    _sigue(salida, estado, _ultimo_paso(_leer_salida(sis, ambito)), "\nLa otra sigue en marcha")
                    return False
                _dormir(CADA)
        except _Cortado as cortado:
            _sigue(salida, estado, _ultimo_paso(_leer_salida(sis, ambito)), "\nDejo de esperar (%s), y la otra sigue en "
                   "marcha" % cortado.senal)
            return False
    return True


def _el_final(sis, ambito, salida, texto, ya_dicho=False) -> int:
    """Lo que dijo al acabar (si no se ha dicho ya, entero) y su código: 0 con el enlace, 1 con un fallo. Queda
    entregado: un fallo no se vuelve a dar (el mismo comando otra vez lo intenta de nuevo), y el enlace sí, mientras su
    canje siga abierto."""
    if not ya_dicho and texto:
        for linea in texto.split("\n")[:-1] if texto.endswith("\n") else texto.split("\n"):
            salida(linea)
    que = resultado_de(texto)
    if que is None:
        salida("\nerror: la instalación en segundo plano se ha parado sin decir cómo ha acabado (la han parado, o se ha "
               "quedado sin memoria). Lo hecho queda apuntado: el mismo comando otra vez sigue donde se quedó.")
        salida("\n" + marcha.PREFIJO_ERROR + "interrumpido")
    estado = _leer_estado(sis, ambito)
    if estado is not None:
        estado["entregado"] = True
        try:
            _guardar_estado(sis, ambito, estado)
        except OSError:
            pass
    return 0 if que == "enlace" else 1


def _sigue(salida, estado, donde, texto) -> int:
    salida("%s: el mismo comando otra vez la vuelve a seguir, sin empezar otra, y cuando acabe da su enlace o su "
           "fallo." % texto)
    salida("%s %s (%d s)" % (PREFIJO_SIGUE, donde or "preparando", _desde(estado)))
    return 0


class _Cortado(Exception):
    def __init__(self, senal):
        super().__init__(senal)
        self.senal = senal


@contextlib.contextmanager
def _si_me_cortan():
    """Mientras la sigue, una señal (el plazo de la terminal de Hermes, su `/stop`) no la para: solo deja de seguirla, y
    lo dice (`hehermes-sigue:`, no `interrumpido`). Las de detrás se ignoran: el SIGKILL llega un segundo después, y lo
    único que queda es decirlo."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    cortado = []

    def manejador(numero, marco):
        for senal in SENALES:
            signal.signal(senal, signal.SIG_IGN)
        cortado.append(numero)
        raise _Cortado(signal.Signals(numero).name)

    antes = {senal: signal.signal(senal, manejador) for senal in SENALES}
    try:
        yield
    finally:
        if not cortado:
            for senal, anterior in antes.items():
                signal.signal(senal, anterior)


# MARK: Lo guardado


def _en_marcha(sis, ambito) -> bool:
    return sis.ejecutar(ambito.systemctl + ["is-active", UNIDAD]).bien


def _canje_abierto(sis, ambito) -> bool:
    from .porchat import UNIDAD as CANJE
    return sis.ejecutar(ambito.systemctl + ["is-active", CANJE]).bien


def _leer_salida(sis, ambito) -> str:
    return (sis.leer(ambito.run_instalar + "/" + SALIDA) or b"").decode("utf-8", "replace")


def _leer_estado(sis, ambito) -> dict | None:
    try:
        estado = json.loads(sis.leer_texto(ambito.run_instalar + "/" + ESTADO) or "null")
    except ValueError:
        return None
    return estado if isinstance(estado, dict) else None


def _guardar_estado(sis, ambito, estado) -> None:
    sis.escribir(ambito.run_instalar + "/" + ESTADO, json.dumps(estado).encode(), modo=0o600)


def _olvidar(sis, ambito) -> None:
    if sis.existe(ambito.run_instalar):
        sis.borrar_arbol(ambito.run_instalar)


def _desde(estado) -> int:
    inicio = (estado or {}).get("inicio")
    if not isinstance(inicio, (int, float)) or isinstance(inicio, bool):
        return 0
    return max(0, int(time.time() - inicio))


def _ultimo_paso(texto) -> str | None:
    donde = None
    for linea in texto.splitlines():
        hallado = _PASO.match(linea.strip())
        if hallado:
            donde = hallado.group(1)
    return donde


@contextlib.contextmanager
def _cerrojo(sis, ambito, espera=30):
    """Decidir y lanzar, de uno en uno: dos frases a la vez (el modelo la relanza mientras la primera sigue) no pueden
    preparar la misma carpeta. Es corto: la instalación toma después el suyo (`cli._cerrojo`), que este no estorba."""
    import fcntl
    ruta = sis.ruta(ambito.run_instalar + ".lock")
    fd = os.open(ruta, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        hasta = _reloj() + espera
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if _reloj() >= hasta:
                    raise marcha.Ocupado("otra frase está lanzando la instalación en segundo plano ahora mismo: "
                                         "vuelve a lanzar el mismo comando en un momento") from None
                _dormir(0.1)
        yield
    finally:
        os.close(fd)
