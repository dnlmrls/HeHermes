"""Dónde va cada cosa: con root, en el sistema; sin root, en la casa del usuario (el de Hermes).

En modo TLS se puede instalar sin root (spec 2026-09-26, «El alta», «Sin root»): nada de paquetes ni de cortafuegos, y
todo lo que se escribe, en `~/.local` y `~/.config`, que es suyo. (La VPN de antes de la 0.6.0 solo existía con
root, y por eso quitarla también es cosa de root.) Todo lo que se
escribe sigue llamándose `hehermes*`: `borrar_arbol` no borra nada que no lo sea.
"""

from __future__ import annotations

import re

_CASA = re.compile(r"^/[A-Za-z0-9._@+-][A-Za-z0-9._/@+-]*$")
PYTHON = "/usr/bin/python3"


class Ambito:
    def __init__(self, root: bool, casa: str | None = None, usuario: str | None = None, uid: int | None = None):
        self.root, self.casa, self.usuario, self.uid = root, casa, usuario, uid
        if root:
            self.prefijo = "/opt/hehermes-servidor"
            self.orden = "/usr/local/sbin/hehermes-servidor"
            self.dispositivo = "/usr/local/sbin/hehermes-dispositivo"
            self.carpeta_config = "/etc/hehermes"
            self.carpeta_pasarela = "/etc/hehermes-pasarela"
            self.unidades = "/etc/systemd/system"
            self.carpeta_venv = "/opt/hehermes-canje"
            self.venv = self.carpeta_venv + "/venv"
            self.run_canje = "/run/hehermes-canje"
            self.cerrojo = "/run/hehermes-servidor.lock"
            # La instalación por chat en segundo plano (`fondo`, desde la 0.11.2): lo que imprime, con el enlace, solo
            # de root y en memoria.
            self.run_instalar = "/run/hehermes-instalar"
            self.systemctl = ["systemctl"]
        else:
            if not casa or not _CASA.fullmatch(casa) or casa.rstrip("/") == "" or "//" in casa:
                raise ValueError("la casa de %s no es una ruta que sepa poner en una unidad: %r" % (usuario, casa))
            casa = casa.rstrip("/")
            self.casa = casa
            self.prefijo = casa + "/.local/share/hehermes-servidor"
            self.orden = casa + "/.local/bin/hehermes-servidor"
            self.dispositivo = casa + "/.local/bin/hehermes-dispositivo"
            self.carpeta_config = casa + "/.config/hehermes"
            self.carpeta_pasarela = casa + "/.config/hehermes-pasarela"
            self.unidades = casa + "/.config/systemd/user"
            self.carpeta_venv = casa + "/.local/share/hehermes-venv"
            self.venv = self.carpeta_venv
            self.run_canje = "/run/user/%d/hehermes-canje" % uid
            # En /run/user, que es suyo y en memoria: dentro de ~/.config, desinstalar no podría quitar su carpeta.
            self.cerrojo = "/run/user/%d/hehermes-servidor.lock" % uid
            self.run_instalar = "/run/user/%d/hehermes-instalar" % uid
            self.systemctl = ["systemctl", "--user"]
        # Los avisos (el vigía, `avisos`): con root, donde los deja también `server/avisos/despliegue/instalar.sh` en el
        # VPS de Daniel; sin root, en su casa, como la pasarela.
        if root:
            self.carpeta_avisos = "/etc/hehermes-avisos"
            self.carpeta_estado_vigia = "/var/lib/hehermes-vigia"
        else:
            self.carpeta_avisos = casa + "/.config/hehermes-avisos"
            self.carpeta_estado_vigia = casa + "/.local/state/hehermes-vigia"
        self.carpeta_vigia = self.carpeta_avisos + "/vigia"
        self.vigia_ini = self.carpeta_avisos + "/vigia.ini"
        self.secreto_vigia = self.carpeta_vigia + "/secreto-tunel"
        self.credencial_rele = self.carpeta_vigia + "/credencial-rele"
        #: Con root, la copia 0600 de la clave de Hermes del vigía (la pone al día `pasarela-clave`); sin root, el vigía
        #: lee el .env de Hermes, como la pasarela.
        self.clave_hermes_vigia = self.carpeta_vigia + "/clave-hermes"
        self.base_vigia = self.carpeta_estado_vigia + "/vigia.db"
        self.unidad_vigia = self.unidades + "/hehermes-vigia.service"
        self.socket_vigia = self.unidades + "/hehermes-vigia.socket"
        # El lector de ficheros (`GET /avisos/v1/fichero`, desde la 0.8.0): con root, donde lo deja también instalar.sh
        # en el VPS de Daniel; sin root, la copia del paquete que ya va en su casa, y su socket en su /run/user.
        if root:
            self.lector = "/usr/local/libexec/hehermes-leer-media"
            self.socket_lector = "/run/hehermes-leer-media.sock"
        else:
            self.lector = self.prefijo + "/hehermes-leer-media"
            self.socket_lector = "/run/user/%d/hehermes-leer-media.sock" % uid
        self.unidad_lector_socket = self.unidades + "/hehermes-leer-media.socket"
        self.unidad_lector = self.unidades + "/hehermes-leer-media@.service"
        # El ayudante de la copia en iCloud (desde la 0.10.0): como el lector, y su carpeta de trabajo (instantáneas,
        # restauraciones y la copia de antes de restaurar). Con root la hace systemd (StateDirectory).
        if root:
            self.respaldo = "/usr/local/libexec/hehermes-respaldo"
            self.socket_respaldo = "/run/hehermes-respaldo.sock"
            self.carpeta_respaldo = "/var/lib/hehermes-respaldo"
        else:
            self.respaldo = self.prefijo + "/hehermes-respaldo"
            self.socket_respaldo = "/run/user/%d/hehermes-respaldo.sock" % uid
            self.carpeta_respaldo = casa + "/.local/state/hehermes-respaldo"
        self.unidad_respaldo_socket = self.unidades + "/hehermes-respaldo.socket"
        self.unidad_respaldo = self.unidades + "/hehermes-respaldo@.service"
        # El ayudante de la entrada (desde la 0.10.6): lo que la app le manda a Hermes, en `<HERMES_HOME>/entrada`. Como
        # el lector: con root, en /usr/local/libexec; sin root, la copia del paquete que va en su casa, y su socket en su
        # /run/user. La carpeta no va aquí: es de la casa de Hermes (`avisos.crear_entrada`).
        if root:
            self.entrada = "/usr/local/libexec/hehermes-entrada"
            self.socket_entrada = "/run/hehermes-entrada.sock"
        else:
            self.entrada = self.prefijo + "/hehermes-entrada"
            self.socket_entrada = "/run/user/%d/hehermes-entrada.sock" % uid
        self.unidad_entrada_socket = self.unidades + "/hehermes-entrada.socket"
        self.unidad_entrada = self.unidades + "/hehermes-entrada@.service"
        # El ayudante que actualiza el servidor desde la app (desde la 0.10.10): solo con root, porque actualizar es
        # instalar (sin root, la app enseña cómo hacerlo a mano). Como los demás, en /usr/local/libexec, con su socket.
        self.actualizar = "/usr/local/libexec/hehermes-actualizar" if root else None
        self.socket_actualizar = "/run/hehermes-actualizar.sock" if root else None
        self.carpeta_actualizar = "/var/lib/hehermes-actualizar" if root else None
        self.unidad_actualizar_socket = self.unidades + "/hehermes-actualizar.socket"
        self.unidad_actualizar = self.unidades + "/hehermes-actualizar@.service"
        # El ayudante de los agentes (desde la 0.11.0, contrato §18): crea, cambia y borra los perfiles de Hermes que la
        # app enseña como agentes, y cada minuto junta lo que saben de ti los que lo comparten. Como los demás: con root,
        # en /usr/local/libexec con su socket en /run; sin root, el que va en su casa, con su socket en su /run/user. Su
        # carpeta de trabajo (el estado de cada trabajo y lo visto de la memoria), con root la hace systemd.
        if root:
            self.agentes = "/usr/local/libexec/hehermes-agentes"
            self.socket_agentes = "/run/hehermes-agentes.sock"
            self.carpeta_agentes = "/var/lib/hehermes-agentes"
        else:
            self.agentes = self.prefijo + "/hehermes-agentes"
            self.socket_agentes = "/run/user/%d/hehermes-agentes.sock" % uid
            self.carpeta_agentes = casa + "/.local/state/hehermes-agentes"
        self.unidad_agentes_socket = self.unidades + "/hehermes-agentes.socket"
        self.unidad_agentes = self.unidades + "/hehermes-agentes@.service"
        self.unidad_agentes_memoria = self.unidades + "/hehermes-agentes-memoria.service"
        self.temporizador_agentes_memoria = self.unidades + "/hehermes-agentes-memoria.timer"
        self.manifiesto = self.carpeta_config + "/instalacion.json"
        self.pasarela_ini = self.carpeta_pasarela + "/pasarela.ini"
        self.cert = self.carpeta_pasarela + "/cert.pem"
        self.clave = self.carpeta_pasarela + "/clave.pem"
        # El certificado que viene después (su huella se publica a los iPhone para que la anclen también) y el de antes
        # de la última rotación (`hehermes-servidor certificado rotar`), por si hay que volver atrás.
        self.carpeta_siguiente = self.carpeta_pasarela + "/siguiente"
        self.cert_siguiente = self.carpeta_siguiente + "/cert.pem"
        self.clave_siguiente = self.carpeta_siguiente + "/clave.pem"
        self.carpeta_anterior = self.carpeta_pasarela + "/anterior"
        # La carpeta de estado de la pasarela (el borrado pendiente, su actividad y lo que apunta la limpieza de noche,
        # `mantenimiento.py`): con root, la de su StateDirectory; sin root, en ~/.local/state. Y la limpieza.
        self.carpeta_estado_pasarela = ("/var/lib/hehermes-pasarela" if root
                                        else self.casa + "/.local/state/hehermes-pasarela")
        self.unidad_borrado = self.unidades + "/hehermes-borrado.service"
        self.temporizador_borrado = self.unidades + "/hehermes-borrado.timer"
        self.tokens = self.carpeta_pasarela + "/tokens.json"
        self.clave_hermes = self.carpeta_pasarela + "/clave-hermes"
        # Las claves de los agentes (desde la 0.11.0, contrato §18): una por perfil, `<perfil>.clave`, que escribe el
        # ayudante `hehermes-agentes`. La de la pasarela (`[agentes] claves` de pasarela.ini) y la del vigía (la de
        # vigia.ini): con root, `root:hh-pasarela` y `root:hh-vigia`, 2750; sin root, 0700.
        self.claves_agentes_pasarela = self.carpeta_pasarela + "/agentes"
        self.claves_agentes_vigia = self.carpeta_avisos + "/agentes"
        self.unidad = self.unidades + "/hehermes-pasarela.service"
        self.python_venv = self.venv + "/bin/python"

    def __repr__(self):
        return "Ambito(%s)" % ("root" if self.root else self.usuario)


def de_root() -> Ambito:
    return Ambito(True)


def de_usuario(usuario: str, casa: str, uid: int) -> Ambito:
    return Ambito(False, casa, usuario, uid)
