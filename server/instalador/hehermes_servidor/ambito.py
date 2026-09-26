"""Dónde va cada cosa: con root, en el sistema; sin root, en la casa del usuario (el de Hermes).

En modo TLS se puede instalar sin root (spec 2026-09-26, «El alta», «Sin root»): nada de paquetes ni de cortafuegos, y
todo lo que se escribe, en `~/.local` y `~/.config`, que es suyo. El modo VPN solo existe con root. Todo lo que se
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
            self.systemctl = ["systemctl", "--user"]
        self.manifiesto = self.carpeta_config + "/instalacion.json"
        self.pasarela_ini = self.carpeta_pasarela + "/pasarela.ini"
        self.cert = self.carpeta_pasarela + "/cert.pem"
        self.clave = self.carpeta_pasarela + "/clave.pem"
        self.tokens = self.carpeta_pasarela + "/tokens.json"
        self.clave_hermes = self.carpeta_pasarela + "/clave-hermes"
        self.unidad = self.unidades + "/hehermes-pasarela.service"
        self.python_venv = self.venv + "/bin/python"

    def __repr__(self):
        return "Ambito(%s)" % ("root" if self.root else self.usuario)


def de_root() -> Ambito:
    return Ambito(True)


def de_usuario(usuario: str, casa: str, uid: int) -> Ambito:
    return Ambito(False, casa, usuario, uid)
