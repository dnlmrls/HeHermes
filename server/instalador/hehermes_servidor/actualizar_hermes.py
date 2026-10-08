"""Actualizar Hermes antes de instalar (desde la 0.12.0; decisión de Daniel del 2026-10-08).

Un probador pegó la frase con un Hermes 0.19.0, y la 0.11.2 se paró con `hermes-antiguo` pidiéndole que lo actualizara él
(«hermes update» como root, o «/update» en su chat) y volviera a empezar. Desde la 0.12.0 se instala al momento con lo
que tenga (la mínima de respaldo, abajo), y con `--actualizar-hermes` (el permiso; opcional, para quien lo lance a mano:
la frase de la app no lo lleva hasta probarlo con un Hermes de verdad, decisión de Daniel del 2026-10-08), si su Hermes
es anterior a la que la app aprovecha entera (`capacidades.RECOMENDADA`, la 0.21.1), el instalador lo actualiza antes
que nada con su propio actualizador (`hermes update`, como el dueño de su código, que es como lo hace Hermes), lo
reinicia si `hermes update` no lo ha reiniciado ya, espera a que vuelva con la versión nueva (`PLAZO_DE_VUELTA`) y
sigue. A uno que ya la tiene no se le toca nada.

**El reinicio corta el turno de Hermes que lanzó el instalador** (lo que ejecuta su terminal va en su cgroup). Por eso
solo se hace por chat en segundo plano (`fondo`: la instalación es hija de PID 1 y el reinicio no la toca) o por un
terminal; por chat aquí mismo, nunca. Y por chat, antes de tocar nada, se dice con una línea
(`marcha.PREFIJO_REINICIO`): quien la sigue acaba en cuanto la ve, Hermes contesta con ella, y la instalación espera a que
ese turno acabe (que el que la sigue ya no esté, y un margen para su respuesta) antes de lanzar `hermes update`. Cuando
Hermes vuelve, el mismo comando otra vez se engancha a ella y da el enlace (o el error).

**Nada destructivo.** Ni se borra ni se reinstala Hermes: solo su `hermes update`. Si falla sin cambiar su código, Hermes
sigue con la suya y no se reinicia. Si no vuelve, y su código es un checkout de git que el update ha movido y que está
limpio, se devuelve a donde estaba (`git reset --keep`: lo nuevo sigue en su `origin`, y su próximo `hermes update` lo
vuelve a traer), se reinicia y se espera otra vez. Si tampoco vuelve, `hehermes-error:hermes-no-volvio`, sin haber
instalado nada de HeHermes.

**Si no se puede actualizar** (en un contenedor, suelto en tmux, sin root para reiniciarlo, sin su orden `hermes`, por chat
sin segundo plano, o un `hermes update` que falla), se sigue con lo que hay desde la mínima de respaldo
(`capacidades.MINIMA`, la 0.15.0), y se dice por qué; por debajo de ella, `hermes-antiguo`, que también lo dice.
"""

from __future__ import annotations

import re
import time

from . import capacidades
from . import gestor as gestores
from .deteccion import Bloqueo, bloqueo
from .fondo import ANTEPASADOS, PLAZO_DEL_CHAT
from .marcha import DE_VUELTA, PREFIJO_REINICIO, segundos

#: Lo más que puede tardar `hermes update` (git, sus dependencias con uv o pip, sus migraciones): en un VPS de una CPU,
#: varios minutos. Si se pasa, se corta (124) y se mira cómo ha quedado su código.
PLAZO_UPDATE = 20 * 60
#: Lo que se espera a que vuelva tras reiniciarlo, y tras devolver su código a como estaba.
PLAZO_DE_VUELTA = 10 * 60
PLAZO_TRAS_DESHACER = 5 * 60
#: Cada cuánto se le pregunta mientras vuelve: al principio a menudo, y luego cada 30 s.
ESPERAS = (2, 3, 5, 5, 10, 10, 15, 15, 20)
ESPERA_MAXIMA = 30
#: Por chat: lo que se espera a que acabe quien la sigue (su plazo y un margen) y, después, a que Hermes conteste (el
#: modelo escribe su respuesta y la manda al chat; uno que razona puede tardar). Lo que tarda `hermes update` antes de
#: reiniciarlo (git y sus dependencias) es margen de más.
ESPERA_AL_QUE_SIGUE = PLAZO_DEL_CHAT + 30
GRACIA_DEL_TURNO = 45
PATH_DE_SERIE = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#: Lo que se pasa a una orden (rutas, el PATH): nada que pueda romperla.
_SEGURO = re.compile(r"[A-Za-z0-9._/@+:,=-]{1,1024}")
_GIT = re.compile(r"[0-9a-f]{40}")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
#: Lo que no puede salir de la salida de `hermes update` hacia el chat (lo lee el modelo): una URL con usuario y
#: contraseña (un remoto de git con su token) y algo que parezca una clave.
_CREDENCIAL_URL = re.compile(r"(\w+://)[^/@\s]+@")
_CLAVE = re.compile(r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*[=:]\s*)\S+")
#: Las que eran obligatorias hasta la 0.11.2: sin ellas, sin saber su versión, es que es de antes de la recomendada.
_DE_ANTES = {"modelo", "desviar"}

# El reloj y la espera: las pruebas los sustituyen.
_reloj = time.monotonic
_dormir = time.sleep


class Decision:
    """Lo que se va a hacer con Hermes: `toca`, actualizarlo; si no, `motivo` dice por qué no (para el texto, el aviso y la
    app), o nada si no hace falta. `en_el_plan`: con `--plan`, lo que haría."""

    def __init__(self, antes, toca=False, motivo=None, texto=None):
        self.antes, self.toca, self.motivo, self.texto = antes, toca, motivo, texto
        self.en_el_plan = False
        #: Su código, su orden `hermes`, y el dueño (su nombre, su uid y su casa), con quien se lanza.
        self.carpeta = self.orden = self.dueno = self.casa = None
        self.uid = None


class Resultado:
    """Cómo ha ido: `hecho` (actualizado y de vuelta), o `motivo` y `texto` de por qué no (y si se ha devuelto su código a
    como estaba, `deshecho`); o `parada`, el bloqueo de un Hermes que no ha vuelto."""

    def __init__(self, antes):
        self.antes = antes
        self.hecho = False
        self.despues = None
        self.motivo = self.texto = None
        self.deshecho = False
        self.parada = None


# MARK: Decidir


def hace_falta(hermes) -> bool:
    """Si este Hermes es anterior a la recomendada: por su versión, o, si no la dice, porque la sonda no encuentra algo que
    la tiene (lo obligatorio, o el modelo y el desvío). Sin saber nada, no: a uno que ya la tiene no se le toca."""
    if hermes is None:
        return False
    numeros = capacidades.version(hermes.version)
    if numeros is not None:
        return numeros < capacidades.RECOMENDADA
    sondeo = getattr(hermes, "sondeo", None)
    if sondeo is None:
        return False
    obligatorias = {c.clave for c in capacidades.CAPACIDADES if c.obligatoria}
    return bool(sondeo.ausentes & (obligatorias | _DE_ANTES))


def decidir(sis, det, plan, opciones, ambito, en_segundo_plano=False) -> Decision | None:
    """Si se actualiza Hermes, y si no, por qué. None si no hay nada que decir: sin `--actualizar-hermes`, con un Hermes al
    día, o con algo que para la instalación y no es su versión (entonces Hermes no se toca para nada)."""
    hermes = getattr(det, "hermes", None)
    if not getattr(opciones, "actualizar_hermes", False) or not hace_falta(hermes):
        return None
    if any(getattr(b, "codigo", None) != "hermes-antiguo" for b in plan.bloqueos):
        return None
    antes = hermes.version or "?"
    gestor = hermes.gestor
    solo_plan = bool(getattr(opciones, "solo_plan", False))

    def no(motivo, texto):
        return Decision(antes, motivo=motivo, texto=texto)

    if gestor is not None and gestor.tipo in gestores.CONTENEDORES:
        return no("contenedor", "va en %s, y no lo actualizo yo: lo de dentro se pierde al recrearlo. Se actualiza con su "
                                "imagen nueva" % gestor.describir())
    if gestor is None:
        return no("suelto", "no sé reiniciarlo (lo encuentro por %s, que no es una unidad de systemd), y actualizarlo sin "
                            "reiniciarlo no serviría de nada. Actualízalo tú: «/update» en su chat" % hermes.origen)
    if not gestores.puede_reiniciar(gestor, ambito):
        return no("permisos", "sin root no puedo reiniciar %s. Actualízalo tú: «/update» en su chat" % gestor.describir())
    if getattr(opciones, "por_chat", False) and not en_segundo_plano and not solo_plan:
        return no("primer-plano", "no he podido lanzar la instalación en segundo plano, y aquí corro dentro de tu Hermes: "
                                  "su reinicio me cortaría. Actualízalo tú: «/update» en su chat")
    carpeta = _carpeta(sis, hermes)
    orden = _orden_hermes(sis, hermes, carpeta)
    if orden is None:
        return no("sin-orden", "no encuentro su orden «hermes» (%s), así que no sé actualizarlo. Actualízalo tú: "
                               "«/update» en su chat" % ("ni junto a su código, en %s, ni en su PATH" % carpeta if carpeta
                                                        else "ni su código ni en su PATH"))
    dueno, uid, casa = _dueno(sis, carpeta or orden, hermes)
    if dueno is None or not _SEGURO.fullmatch(casa or ""):
        return no("permisos", "no sé de quién es su código (%s), así que no lo actualizo. Actualízalo tú: «/update» en su "
                              "chat" % (carpeta or orden))
    if not ambito.root and dueno != ambito.usuario:
        return no("permisos", "su código es de «%s», y sin root no puedo actualizarlo como él. Actualízalo tú: «/update» "
                              "en su chat" % dueno)
    decision = Decision(antes, toca=not solo_plan)
    decision.en_el_plan = solo_plan
    decision.carpeta, decision.orden, decision.dueno, decision.uid, decision.casa = carpeta, orden, dueno, uid, casa
    decision.texto = ("Tu Hermes es la %s, y la app lo aprovecha entero desde la %s: %s antes de nada, con su propio "
                      "actualizador (%s update, como %s), y %s" % (
                          antes, capacidades.texto_de(capacidades.RECOMENDADA),
                          "lo actualizaría" if solo_plan else "lo actualizo", orden, dueno,
                          "lo reiniciaría" if solo_plan else "lo reinicio"))
    return decision


def _carpeta(sis, hermes) -> str | None:
    """Donde está el código que corre (`capacidades.version_del_codigo`), como ruta del servidor."""
    _, carpeta = capacidades.version_del_codigo(sis, hermes)
    if carpeta and carpeta.startswith("/proc/"):
        destino = sis.enlace(carpeta)
        carpeta = destino if destino and _valida(destino) else None
    return carpeta if carpeta and _valida(carpeta) else None


def _valida(ruta) -> bool:
    return isinstance(ruta, str) and ruta.startswith("/") and ".." not in ruta.split("/") and bool(_SEGURO.fullmatch(ruta))


def _orden_hermes(sis, hermes, carpeta) -> str | None:
    """La orden `hermes` de ese Hermes: la de su venv (junto a su código, como la deja su instalador), la que lo lanza, o
    la de su PATH (el de su proceso o su unidad) y los sitios de siempre."""
    candidatas = [carpeta + "/venv/bin/hermes", carpeta + "/.venv/bin/hermes"] if carpeta else []
    orden = list(getattr(hermes, "orden", None) or [])
    if orden and orden[0].startswith("/"):
        nombre = orden[0].rsplit("/", 1)[-1]
        if nombre.startswith("hermes"):
            candidatas.append(orden[0])
        elif nombre.startswith("python"):
            candidatas.append(orden[0].rsplit("/", 1)[0] + "/hermes")
    casa = (sis.cuenta_de(hermes.usuario) or (None, None))[1]
    ruta = (getattr(hermes, "entorno", None) or {}).get("PATH") or ""
    for carpeta_ in ruta.split(":") + ([casa + "/.local/bin"] if casa else []) + ["/usr/local/bin", "/usr/bin"]:
        if carpeta_.startswith("/"):
            candidatas.append(carpeta_.rstrip("/") + "/hermes")
    return next((c for c in dict.fromkeys(candidatas) if _valida(c) and sis.es_ejecutable(c)), None)


def _dueno(sis, ruta, hermes) -> tuple:
    """(nombre, uid, casa) del dueño del código de Hermes; si no tiene nombre, el usuario con el que corre Hermes."""
    uid = sis.dueno(ruta)
    cuenta = sis.cuenta(uid) if uid is not None else None
    if cuenta is not None:
        return cuenta[0], uid, cuenta[1]
    hallada = sis.cuenta_de(hermes.usuario)
    if hallada is not None:
        return hermes.usuario, hallada[0], hallada[1]
    return None, None, None


# MARK: Actualizar


def actualizar(sis, decision, det, ambito, salida, por_chat=False) -> Resultado:
    """`hermes update`, el reinicio y la espera a que vuelva (arriba). Lo que va diciendo, a `salida`."""
    hermes, root = det.hermes, ambito.root
    gestor = hermes.gestor
    resultado = Resultado(decision.antes)
    salida("\n==> %s." % decision.texto)
    if por_chat:
        # Lo que lee Hermes antes de reiniciarse (y la persona, si pega su respuesta en la app): la última, la línea.
        salida("    Hermes: vas a reiniciarte en cuanto acabe este turno, y es normal. No tienes que hacer nada más: "
               "contesta acabando con la línea de abajo, sin volver a ejecutar el comando. La instalación sigue sola, en "
               "segundo plano; cuando vuelvas, el mismo comando otra vez da el enlace.")
        salida("%s %s (%d s)" % (PREFIJO_REINICIO, decision.antes, segundos()))
        _esperar_al_turno(sis)
    antes = _foto(sis, decision, gestor, root)
    r = _hermes_update(sis, decision, hermes, gestor, root)
    despues = _foto(sis, decision, gestor, root)
    reiniciado = antes["pid"] is not None and despues["pid"] != antes["pid"]
    cambio = bool((antes["git"] and despues["git"] and antes["git"] != despues["git"]) or
                  (despues["codigo"] and despues["codigo"] != antes["codigo"]))
    if r.bien:
        salida("==> hermes update ha acabado%s" % (": su código es ahora la %s" % despues["codigo"]
                                                  if cambio and despues["codigo"] else ""))
    else:
        salida("==> hermes update ha fallado (%s). Lo último que ha dicho:" % (
            "no ha acabado en %d minutos" % (PLAZO_UPDATE // 60) if r.codigo == 124 else "ha salido con %d" % r.codigo))
        for linea in _cola(r):
            salida("    " + linea)
    if not cambio and not reiniciado:
        resultado.motivo = "fallo" if not r.bien else "sin-cambios"
        resultado.texto = ("hermes update ha fallado sin cambiar su código, así que sigue con la %s y no lo he "
                           "reiniciado" % decision.antes if not r.bien else
                           "hermes update no ha traído nada nuevo (¿su código está fijado a una versión?), así que "
                           "sigue con la %s" % decision.antes)
        salida("%s %s." % (DE_VUELTA, resultado.texto))
        return resultado
    if not reiniciado:
        salida("==> Reinicio tu Hermes (%s) para que corra lo nuevo, y espero a que vuelva (hasta %d minutos)"
               % (gestor.describir(), PLAZO_DE_VUELTA // 60))
        rr = sis.ejecutar(gestores.orden_reiniciar(gestor, root), plazo=300)
        if not rr.bien:
            salida("    El reinicio ha fallado (%s): espero igual, por si vuelve" % _corto(rr))
    else:
        salida("==> hermes update lo ha reiniciado: espero a que vuelva (hasta %d minutos)" % (PLAZO_DE_VUELTA // 60))
    objetivo = capacidades.version(despues["codigo"]) if cambio else capacidades.version(decision.antes)
    vuelta = _esperar(sis, hermes, gestor, root, objetivo, antes["pid"], PLAZO_DE_VUELTA)
    if vuelta is not None:
        texto, nueva = vuelta
        version = texto or despues["codigo"] or "?"
        if cambio and nueva:
            resultado.hecho, resultado.despues = True, version
            salida("%s ya es la %s (antes, la %s)." % (DE_VUELTA, version, decision.antes))
        else:
            resultado.motivo = "fallo" if not r.bien else "sin-cambios"
            resultado.texto = ("ha vuelto, pero con la %s: la actualización no ha llegado a cuajar%s" % (
                version, " (hermes update había fallado)" if not r.bien else ""))
            salida("%s %s." % (DE_VUELTA, resultado.texto))
        return resultado
    # No ha vuelto: se intenta dejarlo como estaba.
    minutos = PLAZO_DE_VUELTA // 60
    if cambio and _deshacer(sis, decision, root, antes, despues, salida):
        salida("==> Lo reinicio con su código de antes, y espero otra vez (hasta %d minutos)" % (PLAZO_TRAS_DESHACER // 60))
        pid = _main_pid(sis, gestor, root)
        sis.ejecutar(gestores.orden_reiniciar(gestor, root), plazo=300)
        vuelta = _esperar(sis, hermes, gestor, root, capacidades.version(decision.antes), pid, PLAZO_TRAS_DESHACER)
        if vuelta is not None:
            resultado.motivo, resultado.deshecho = "no-volvio", True
            resultado.texto = ("con la versión nueva no volvía en %d minutos, así que lo he dejado como estaba: sigue "
                               "con la %s" % (minutos, vuelta[0] or decision.antes))
            salida("%s %s." % (DE_VUELTA, resultado.texto))
            return resultado
        minutos += PLAZO_TRAS_DESHACER // 60
        resultado.deshecho = True
    resultado.parada = _no_volvio(decision, gestor, root, minutos, resultado.deshecho)
    return resultado


def _no_volvio(decision, gestor, root, minutos, deshecho) -> Bloqueo:
    diario = "journalctl %s-u %s -n 50" % ("" if gestor.tipo == "sistema" else "--user ", gestor.nombre)
    hecho = bloqueo("hermes-no-volvio", (
        "Tu Hermes no ha vuelto después de actualizarlo (hermes update y su reinicio): en %d minutos no contesta%s. No he "
        "instalado nada de HeHermes. Míralo en el servidor, por SSH (%s), y reinícialo (%s); cuando vuelva a contestar, "
        "vuelve a lanzarme" % (minutos, ", ni con su código devuelto a como estaba (la %s)" % decision.antes if deshecho
                               else "", diario, gestores.como_se_reinicia(gestor, root))))
    hecho.detalle = "version=%s" % decision.antes
    return hecho


def _esperar_al_turno(sis) -> None:
    """Por chat: que acabe el turno de Hermes que la lanzó antes de reiniciarlo. Quien la sigue (el primero de los
    antepasados que le pasó, `fondo.ANTEPASADOS`) acaba en cuanto ve la línea del reinicio; después, un margen para que
    Hermes conteste."""
    primero = (((getattr(sis, "entorno", None) or {}).get(ANTEPASADOS) or "").split() or [""])[0]
    if primero.isdigit():
        hasta = _reloj() + ESPERA_AL_QUE_SIGUE
        while _reloj() < hasta and b"hehermes-servidor" in (sis.leer("/proc/%s/cmdline" % primero) or b""):
            _dormir(1)
    _dormir(GRACIA_DEL_TURNO)


def _como_dueno(decision, root, args, entorno) -> list:
    """`args` como el dueño de su código, con su casa y lo que haga falta de su entorno."""
    orden = ["env"] + ["%s=%s" % (k, v) for k, v in entorno if v and _SEGURO.fullmatch(v)] + list(args)
    if root and decision.dueno != "root":
        return ["runuser", "-u", decision.dueno, "--"] + orden
    return orden


def _hermes_update(sis, decision, hermes, gestor, root):
    """Sin nada en la entrada (si pregunta algo, lee el final) y sin que git pueda preguntar nada (sin terminal se
    quedaría esperando), con el PATH con el que corre Hermes (y donde suelen estar uv y git: `~/.local/bin`), su
    HERMES_HOME si lo lleva, en UTF-8 (lo que imprime lleva emojis; `Sistema` lo lanza todo en C) y con el systemd de su
    usuario a mano (su reinicio de una unidad de usuario lo necesita)."""
    casa = decision.casa
    del_proceso = (getattr(hermes, "entorno", None) or {}).get("PATH") or ""
    partes = [casa + "/.local/bin", casa + "/.cargo/bin"] + (del_proceso.split(":") if _SEGURO.fullmatch(del_proceso)
                                                             else []) + PATH_DE_SERIE.split(":")
    entorno = [("HOME", casa), ("PATH", ":".join(dict.fromkeys(p for p in partes if p.startswith("/")))),
               ("HERMES_HOME", (getattr(hermes, "entorno", None) or {}).get("HERMES_HOME")), ("NO_COLOR", "1"),
               ("GIT_TERMINAL_PROMPT", "0"), ("LC_ALL", "C.UTF-8"), ("LANG", "C.UTF-8")]
    if decision.uid is not None and (gestor.tipo == "usuario" or sis.es_carpeta("/run/user/%d" % decision.uid)):
        entorno.append(("XDG_RUNTIME_DIR", "/run/user/%d" % decision.uid))
    return sis.ejecutar(_como_dueno(decision, root, [decision.orden, "update"], entorno), entrada="", plazo=PLAZO_UPDATE)


def _foto(sis, decision, gestor, root) -> dict:
    """La versión de su código, el commit de su checkout (si es uno) y el proceso de su unidad."""
    git = None
    if decision.carpeta and sis.existe(decision.carpeta + "/.git") and sis.cual("git"):
        r = sis.ejecutar(_git(decision, root, "rev-parse", "HEAD"), plazo=60)
        git = r.salida.strip() if r.bien and _GIT.fullmatch(r.salida.strip()) else None
    codigo = capacidades.version_en_carpeta(sis, decision.carpeta) if decision.carpeta else None
    return {"codigo": codigo, "git": git, "pid": _main_pid(sis, gestor, root)}


def _git(decision, root, *args) -> list:
    return _como_dueno(decision, root, ["git", "-C", decision.carpeta] + list(args), [("HOME", decision.casa)])


def _main_pid(sis, gestor, root) -> str | None:
    r = sis.ejecutar(gestores.systemctl(gestor, root, "show", gestor.nombre, "-p", "MainPID", "--value"), plazo=30)
    pid = r.salida.strip()
    return pid if r.bien and pid.isdigit() and pid != "0" else None


def _esperar(sis, hermes, gestor, root, objetivo, pid_antes, plazo):
    """(lo que dice su /health de su versión, si es la nueva) en cuanto vuelve, o None si en `plazo` no ha vuelto. Con su
    API, vuelve cuando `/health` contesta 200: con la versión nueva (o ya reiniciado, si no la dice), enseguida; con la de
    antes, al acabar el plazo. Sin su API (`--activar-api` la enciende después), cuando su unidad está en marcha con otro
    proceso, el mismo dos veces seguidas."""
    con_api = bool(hermes.habilitada and hermes.clave and hermes.version_de == "su /health")
    hasta = _reloj() + plazo
    visto, viejo = None, None
    for vez in range(10 ** 6):
        pid = _main_pid(sis, gestor, root)
        if con_api:
            estado, cuerpo = sis.http_get("http://127.0.0.1:%d/health" % hermes.puerto)
            if estado == 200:
                texto = capacidades.version_de_health(cuerpo)
                numeros = capacidades.version(texto)
                if objetivo is None or (numeros is not None and numeros >= objetivo) or \
                        (numeros is None and pid is not None and pid != pid_antes):
                    return texto or "", True
                viejo = texto or ""
        elif pid is not None and pid != pid_antes and sis.ejecutar(
                gestores.systemctl(gestor, root, "is-active", gestor.nombre), plazo=30).bien:
            if visto == pid:
                return "", True
            visto = pid
        if _reloj() >= hasta:
            return (viejo, False) if viejo is not None else None
        _dormir(ESPERAS[vez] if vez < len(ESPERAS) else ESPERA_MAXIMA)
    return None


def _deshacer(sis, decision, root, antes, despues, salida) -> bool:
    """Su checkout de git, de vuelta al commit de antes del update, si lo ha movido y no tiene cambios sin guardar:
    `reset --keep` no pierde nada (lo nuevo sigue en su `origin`) y se niega si algo se pisara."""
    if not (antes["git"] and despues["git"] and antes["git"] != despues["git"]):
        salida("    No puedo devolver su código a como estaba: no es un checkout de git que yo sepa mover")
        return False
    r = sis.ejecutar(_git(decision, root, "status", "--porcelain", "--untracked-files=no"), plazo=60)
    if not r.bien or r.salida.strip():
        salida("    No devuelvo su código a como estaba: %s" % ("tiene cambios sin guardar" if r.bien else
                                                              "git status ha fallado (%s)" % _corto(r)))
        return False
    r = sis.ejecutar(_git(decision, root, "reset", "--keep", antes["git"]), plazo=120)
    if not r.bien:
        salida("    No he podido devolver su código a como estaba (git reset --keep: %s)" % _corto(r))
        return False
    salida("==> Su código, de vuelta a como estaba (git reset --keep %s; lo nuevo sigue en su origin)" % antes["git"][:12])
    return True


def _limpio(texto) -> str:
    texto = _ANSI.sub("", texto or "")
    texto = _CREDENCIAL_URL.sub(r"\1…@", texto)
    return _CLAVE.sub(r"\1…", texto)


def _cola(r, lineas=12) -> list:
    """Lo último que ha dicho una orden, sin colores ni nada que parezca una credencial, y sin líneas larguísimas."""
    utiles = [l.rstrip() for l in _limpio((r.salida or "") + "\n" + (r.error or "")).splitlines() if l.strip()]
    return [l[:200] for l in utiles[-lineas:]]


def _corto(r) -> str:
    return (_cola(r, 1) or [str(r.codigo)])[0][:160]


# MARK: Lo que se dice


def anotar(plan, decision, resultado) -> None:
    """Lo que dice el plan de todo esto: que se ha actualizado, o por qué no (en el bloqueo de `hermes-antiguo`, si lo
    hay, con `actualizar=<motivo>` en su detalle para la app; si no, en un aviso, porque se sigue con la que tiene)."""
    if resultado is not None and resultado.hecho:
        plan.avisos.insert(0, "He actualizado tu Hermes antes de nada: de la %s a la %s" % (resultado.antes,
                                                                                             resultado.despues))
        return
    if decision is not None and decision.en_el_plan:
        texto, motivo = "Con --actualizar-hermes: %s" % decision.texto, None
    elif resultado is not None and resultado.texto:
        texto, motivo = "No he actualizado tu Hermes: %s" % resultado.texto, resultado.motivo
    elif decision is not None and decision.motivo:
        texto, motivo = "No actualizo tu Hermes (la %s): %s" % (decision.antes, decision.texto), decision.motivo
    else:
        return
    antiguos = [i for i, b in enumerate(plan.bloqueos) if getattr(b, "codigo", None) == "hermes-antiguo"]
    for i in antiguos:
        viejo = plan.bloqueos[i]
        nuevo = bloqueo("hermes-antiguo", "%s. %s" % (viejo, texto))
        nuevo.detalle = getattr(viejo, "detalle", None)
        if motivo and nuevo.detalle:
            nuevo.detalle += " actualizar=%s" % motivo
        plan.bloqueos[i] = nuevo
    if not antiguos:
        # Se sigue con la que tiene (desde la mínima de respaldo): lo que le falta lo dicen los avisos de `capacidades`.
        plan.avisos.insert(0, texto)


def avisos_para_la_app(marcha, decision, resultado, hermes=None) -> None:
    """Por chat, junto a los demás avisos, antes del enlace: `hermes-actualizado antes=<X> version=<Y>`, o
    `hermes-sin-actualizar version=<X> motivo=<por qué>` (la app funciona, pero sin lo que llegó después). Sin
    `--actualizar-hermes` (la frase de la app no lo lleva) y con un Hermes anterior a la recomendada, el motivo es
    `sin-permiso`: se ha instalado con lo que tiene, y «/update» trae el resto (Daniel, 2026-10-08)."""
    if resultado is not None and resultado.hecho:
        marcha.avisar("hermes-actualizado", antes=resultado.antes, version=resultado.despues)
    elif resultado is not None and resultado.motivo:
        marcha.avisar("hermes-sin-actualizar", version=resultado.antes, motivo=resultado.motivo)
    elif decision is not None and decision.motivo:
        marcha.avisar("hermes-sin-actualizar", version=decision.antes, motivo=decision.motivo)
    elif decision is None and resultado is None and hace_falta(hermes):
        marcha.avisar("hermes-sin-actualizar", version=hermes.version or "?", motivo="sin-permiso")
