"""Quién lleva el proceso de Hermes, y cómo se reinicia (desde la 0.10.2).

Hasta la 0.10.1 el instalador solo sabía reiniciar la unidad `hermes-gateway.service`. Pero `hermes gateway install`
(hermes_cli/gateway.py, `get_service_name`, a 2026-09-30) llama a la unidad de cada perfil `hermes-gateway-<perfil>`
(o `hermes-gateway-<hash de 8>` si su casa no está en `<raíz>/profiles/<perfil>`), y la pone del sistema con root
(`/etc/systemd/system`) o de usuario sin él (`~/.config/systemd/user`). Un probador con un perfil se quedó sin
poder encender la API (2026-09-30): Hermes corría como `hermes-gateway-<perfil>` y el instalador no lo reconocía.

Así que no se adivina por el nombre: se lee de `/proc/<pid>/cgroup` del proceso de Hermes, que dice en qué unidad de
systemd (del sistema o de un usuario) o en qué contenedor corre, y la unidad se confirma (que su nombre o su ExecStart
sean de Hermes: un Hermes lanzado desde cron o desde una sesión de SSH sin logind cae en `cron.service` o
`ssh.service`, y reiniciar esas no reinicia Hermes). Lo que no es ni una unidad ni un contenedor (tmux, screen, nohup)
no se sabe reiniciar sin riesgo, y lo dice `deteccion` (el código `reinicia-hermes`).

Solo lee: las órdenes que cambian algo (reiniciar, parar, arrancar) se devuelven para que las lance quien toque.
"""

from __future__ import annotations

import json
import re

#: Un nombre de unidad de systemd tal como sale en un cgroup (con sus escapes `\x2d`).
_UNIDAD = re.compile(r"^[A-Za-z0-9:_.\\@-]{1,250}\.service$")
_ID_CONTENEDOR = re.compile(r"^[0-9a-f]{64}$")
_USUARIO = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
#: El reinicio de después de acabar: a los 90 s, para no cortarle a Hermes el turno en el que contesta con el enlace.
LUEGO = ["--on-active=90", "--timer-property=AccuracySec=1s", "--collect", "--quiet"]
CONTENEDORES = ("docker", "podman")


class Gestor:
    """Lo que lleva a Hermes: una unidad del sistema, una de usuario (con su dueño) o un contenedor."""

    def __init__(self, tipo: str, nombre: str, usuario: str | None = None, uid: int | None = None):
        self.tipo, self.nombre, self.usuario, self.uid = tipo, nombre, usuario, uid

    def __eq__(self, otro):
        return isinstance(otro, Gestor) and self.a_dict() == otro.a_dict()

    def __repr__(self):
        return "Gestor(%s, %s%s)" % (self.tipo, self.nombre, ", %s" % self.usuario if self.usuario else "")

    def describir(self) -> str:
        if self.tipo == "usuario":
            return "la unidad de usuario %s (de %s)" % (self.nombre, self.usuario)
        if self.tipo in CONTENEDORES:
            return "el contenedor de %s %s" % (self.tipo.capitalize(), self.nombre[:12])
        return "la unidad %s" % self.nombre

    def a_dict(self) -> dict:
        datos = {"tipo": self.tipo, "nombre": self.nombre}
        if self.tipo == "usuario":
            datos.update(usuario=self.usuario, uid=self.uid)
        return datos


def desde_dict(datos) -> Gestor | None:
    """El del manifiesto, o None si no es uno que se pueda usar tal cual (nada de lo que hay ahí se pasa a una orden sin
    mirarlo: el manifiesto es de root, pero una orden mal formada no tiene que llegar a ejecutarse)."""
    if not isinstance(datos, dict):
        return None
    tipo, nombre = datos.get("tipo"), datos.get("nombre")
    if tipo in ("sistema", "usuario") and isinstance(nombre, str) and _UNIDAD.fullmatch(nombre):
        if tipo == "sistema":
            return Gestor("sistema", nombre)
        usuario, uid = datos.get("usuario"), datos.get("uid")
        if isinstance(usuario, str) and _USUARIO.fullmatch(usuario) and isinstance(uid, int) and uid >= 0:
            return Gestor("usuario", nombre, usuario, uid)
        return None
    if tipo in CONTENEDORES and isinstance(nombre, str) and _ID_CONTENEDOR.fullmatch(nombre):
        return Gestor(tipo, nombre)
    return None


# MARK: El cgroup


def de_cgroup(texto: str) -> tuple | None:
    """(tipo, nombre, uid) de lo que dice `/proc/<pid>/cgroup`, o None si el proceso no es de ninguna unidad ni de
    ningún contenedor (una sesión, `session-3.scope`, o un `tmux-spawn-….scope`). Sin nada ejecutado.

    - cgroup v2: `0::/system.slice/hermes-gateway-trabajo.service`, o, de usuario,
      `0::/user.slice/user-1000.slice/user@1000.service/app.slice/hermes-gateway.service`;
    - cgroup v1: la línea de `name=systemd`;
    - Docker y Podman: `…/docker-<id>.scope` y `…/libpod-<id>.scope` (con el driver de systemd) o `/docker/<id>` (con
      el de cgroupfs). Uno sin root (dentro de `user@….service`) no: reiniciarlo es cosa de su usuario."""
    camino = None
    for linea in (texto or "").splitlines():
        jerarquia, _, resto = linea.partition(":")
        controladores, _, ruta = resto.partition(":")
        if jerarquia == "0" and controladores == "" and ruta.strip() not in ("", "/"):
            camino = ruta.strip()
            break
        if "name=systemd" in controladores.split(",") and camino is None:
            camino = ruta.strip()
    if not camino:
        return None
    partes = [parte for parte in camino.split("/") if parte]
    if any(parte in (".", "..") for parte in partes):
        return None
    de_usuario = next((i for i, parte in enumerate(partes) if re.fullmatch(r"user@\d+\.service", parte)), None)
    if de_usuario is None:
        for i, parte in enumerate(partes):
            hallado = re.fullmatch(r"(docker|libpod)-([0-9a-f]{64})\.scope", parte)
            if hallado:
                return ("docker" if hallado.group(1) == "docker" else "podman"), hallado.group(2), None
            if parte in ("docker", "libpod") and i + 1 < len(partes) and _ID_CONTENEDOR.fullmatch(partes[i + 1]):
                return ("docker" if parte == "docker" else "podman"), partes[i + 1], None
        servicios = [parte for parte in partes if parte.endswith(".service")]
        if servicios and _UNIDAD.fullmatch(servicios[-1]):
            return "sistema", servicios[-1], None
        return None
    uid = int(re.fullmatch(r"user@(\d+)\.service", partes[de_usuario]).group(1))
    servicios = [parte for parte in partes[de_usuario + 1:] if parte.endswith(".service")]
    if servicios and _UNIDAD.fullmatch(servicios[0]):
        return "usuario", servicios[0], uid
    return None


def _usuario_de_uid(sis, uid: int) -> str | None:
    for linea in (sis.leer_texto("/etc/passwd") or "").splitlines():
        campos = linea.split(":")
        if len(campos) >= 3 and campos[2] == str(uid) and _USUARIO.fullmatch(campos[0]):
            return campos[0]
    return None


def detectar(sis, pid, root: bool = True, usuario_actual: str | None = None) -> Gestor | None:
    """El que lleva el proceso `pid`, confirmado; None si no hay ninguno que se sepa reiniciar."""
    hallado = de_cgroup(sis.leer_texto("/proc/%s/cgroup" % pid) or "")
    if hallado is None:
        return None
    tipo, nombre, uid = hallado
    if tipo in CONTENEDORES:
        return Gestor(tipo, nombre) if sis.cual(tipo) else None
    if tipo == "usuario":
        usuario = _usuario_de_uid(sis, uid)
        if usuario is None:
            return None
        gestor = Gestor("usuario", nombre, usuario, uid)
    else:
        gestor = Gestor("sistema", nombre)
    # Que sea la de Hermes: por su nombre (las de `hermes gateway install` empiezan todas por «hermes-gateway») o por lo
    # que ejecuta. Si no se puede preguntar (la de usuario de otro, sin root), solo por el nombre.
    if nombre.lower().startswith("hermes"):
        return gestor
    if gestor.tipo == "usuario" and not root and gestor.usuario != usuario_actual:
        return None
    r = sis.ejecutar(systemctl(gestor, root, "show", nombre, "-p", "ExecStart", "--value"))
    if r.bien and re.search(r"(?<![A-Za-z0-9])hermes", r.salida):
        return gestor
    return None


# MARK: Las órdenes


def systemctl(gestor: Gestor, root: bool, *args) -> list:
    """`systemctl` para su unidad: la del sistema tal cual; la de un usuario, con root, como ese usuario y hacia su
    systemd (`runuser` y su XDG_RUNTIME_DIR: lo que hay en todas las versiones, sin `--machine`, que quiere 248), y sin
    root, `--user`."""
    if gestor.tipo == "usuario":
        if root:
            return ["runuser", "-u", gestor.usuario, "--", "env", "XDG_RUNTIME_DIR=/run/user/%d" % gestor.uid,
                    "systemctl", "--user"] + list(args)
        return ["systemctl", "--user"] + list(args)
    return ["systemctl"] + list(args)


def puede_reiniciar(gestor: Gestor | None, ambito=None) -> bool:
    """Con root, cualquiera; sin root, solo una unidad de usuario suya."""
    if gestor is None:
        return False
    if ambito is None or ambito.root:
        return True
    return gestor.tipo == "usuario" and gestor.usuario == ambito.usuario


def orden_reiniciar(gestor: Gestor, root: bool = True) -> list:
    if gestor.tipo in CONTENEDORES:
        return [gestor.tipo, "restart", gestor.nombre]
    return systemctl(gestor, root, "restart", gestor.nombre)


def recarga_con_drenaje(sis, gestor: Gestor | None, root: bool = True) -> bool:
    """Si su unidad sabe reiniciarlo sin cortarle el turno (desde la 0.11.1). La que escribe `hermes gateway install`
    lleva `ExecReload=/bin/kill -USR1 $MAINPID` (hermes_cli/gateway.py, `generate_systemd_unit`), y Hermes con SIGUSR1
    hace su reinicio con drenaje: no acepta turnos nuevos, espera a que acaben los que tiene (hasta
    `agent.restart_after_turn_timeout`, 1800 s de serie), sale con 75 y systemd lo vuelve a arrancar
    (`RestartForceExitStatus=75`; gateway/run.py, `_start_gateway_make_restart_signal_handler`). Lo dice su
    documentación (website/docs/user-guide/messaging/index.md, en `main` a 2026-10-06): «The installed unit also maps
    `systemctl reload hermes-gateway` to `SIGUSR1`… a graceful drain, process exit, and supervisor relaunch», y que un
    `systemctl restart` a pelo lo para cuando dice systemd. Es lo mismo que su `/restart`. Una unidad hecha a mano, sin
    ese `ExecReload` (o con otro), y un contenedor (SIGUSR1 le llegaría a su s6, no a Hermes), no."""
    if gestor is None or gestor.tipo not in ("sistema", "usuario"):
        return False
    r = sis.ejecutar(systemctl(gestor, root, "show", gestor.nombre, "-p", "ExecReload", "--value"), plazo=30)
    return r.bien and re.search(r"(?<![A-Za-z0-9])kill\b.*\s-(SIG)?USR1\b", r.salida) is not None


def orden_recargar(gestor: Gestor, root: bool = True) -> list:
    """`systemctl reload` de su unidad: le manda SIGUSR1 y vuelve enseguida (Hermes se reinicia cuando acabe su
    turno)."""
    return systemctl(gestor, root, "reload", gestor.nombre)


def orden_reiniciar_luego(gestor: Gestor, root: bool = True) -> list:
    """El reinicio a los 90 s, en una unidad pasajera de systemd: sigue aunque el instalador (y el turno de Hermes que lo
    lanzó) ya hayan acabado. Sin root, en el systemd del usuario."""
    return ["systemd-run"] + ([] if root else ["--user"]) + LUEGO + orden_reiniciar(gestor, root)


def como_se_reinicia(gestor: Gestor, root: bool = True) -> str:
    """La orden para decírsela a una persona."""
    return " ".join(orden_reiniciar(gestor, root)).replace(
        "runuser -u %s -- env XDG_RUNTIME_DIR=/run/user/%s " % (gestor.usuario, gestor.uid), "")


# MARK: Un contenedor


def contenedor(sis, gestor: Gestor) -> dict:
    """Lo que hace falta de un contenedor: {"montajes": [(destino, origen)…], "red": «host»…}. Vacío si no se sabe."""
    r = sis.ejecutar([gestor.tipo, "inspect", "--format", "{{json .Mounts}}\t{{.HostConfig.NetworkMode}}",
                      gestor.nombre])
    if not r.bien or "\t" not in r.salida:
        return {}
    montajes, _, red = r.salida.strip().rpartition("\t")
    try:
        lista = json.loads(montajes)
    except ValueError:
        lista = []
    pares = []
    for montaje in lista if isinstance(lista, list) else []:
        if isinstance(montaje, dict) and isinstance(montaje.get("Source"), str) and \
                isinstance(montaje.get("Destination"), str) and montaje["Source"].startswith("/") and \
                montaje["Destination"].startswith("/"):
            pares.append((montaje["Destination"].rstrip("/") or "/", montaje["Source"].rstrip("/") or "/"))
    return {"montajes": pares, "red": red.strip()}


def ruta_en_el_servidor(montajes, ruta: str) -> str | None:
    """Dónde está en el servidor una ruta de dentro del contenedor (la casa de Hermes, `/opt/data`), por el montaje más
    largo que la contenga; None si no está en ninguno (vive solo dentro del contenedor)."""
    ruta = ruta.rstrip("/") or "/"
    mejor = None
    for destino, origen in montajes:
        if ruta == destino or ruta.startswith(destino.rstrip("/") + "/"):
            if mejor is None or len(destino) > len(mejor[0]):
                mejor = (destino, origen)
    if mejor is None:
        return None
    return mejor[1] + ruta[len(mejor[0]):] if mejor[0] != "/" else mejor[1].rstrip("/") + ruta
