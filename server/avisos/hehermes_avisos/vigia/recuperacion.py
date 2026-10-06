"""El aviso del código de recuperación (contrato §12.9, spec 2026-10-06, «Avisar»): «Se ha conectado otro iPhone con tu
código de recuperación», a los demás iPhone del servidor, y «Alguien ha intentado…», una vez por racha de intentos que
no valen.

**Cómo llega al vigía.** Lo apunta el instalador, que es quien comprueba el código (`hehermes_servidor.recuperacion`):
deja un fichero por suceso en el **buzón** del vigía, una carpeta dentro de la suya de estado (`buzon/`, junto a
`vigia.db`) que el vigía crea al arrancar, de su usuario y 0700. Así solo escriben en ella root y el usuario del vigía
(sin root, el de Hermes, que ya podía leer la base de datos y avisar con ella): ninguna ruta nueva, y nada que un token
de la pasarela pueda pedir. Sin buzón (un vigía de antes), el instalador no deja nada.

**A quién.** A todos los iPhone dados de alta, menos el que acaba de entrar. De quién es cada alta lo dice solo la
pasarela, firmado (`X-HeHermes-Iphone`, contrato §12.10: el nombre del token y su marca; `api.AppVigia.iphone_de`), y
el suceso trae la marca del token nuevo: no se avisa a las altas de ese token, que solo puede tener el que entra. Lo
normal es que aún no se haya dado de alta cuando sale el aviso (le falta el canje). **El nombre no basta**: lo pone
quien firma la frase, y cualquiera con el código puede entrar con el de otro iPhone del servidor; por eso las altas del
token de antes con ese nombre (`marca_anterior`) sí lo reciben —pueden ser de ese otro iPhone, que es a quien más le
importa— y, avisadas, se borran (ese token ya no vale). Las que no dicen de quién son (de una pasarela de antes, o sin
una firma que valga), también lo reciben. No le apaga ningún interruptor de Ajustes › Notificaciones ni le calla la app
delante: es de seguridad, como el de prueba.

**Antes que un barrido.** Mientras quede un aviso por mandar, el vigía no borra las altas de un iPhone quitado desde la
app (`hay_por_avisar`, el `409` de §12.10): quien entra con el código no puede quitar a los demás antes de que se
enteren.

**Lo que lleva.** El tipo `recuperacion` y, aparte, lo que la app necesita para escribirlo a su manera
(`{"que": "entrada" | "intentos", "iphone": …}`); el título y el texto son los de una app que no conoce el tipo. Cifrado
como todos: Apple y el relé solo ven el texto de reserva.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass

from . import avisos

registro = logging.getLogger("vigia.recuperacion")

#: La carpeta del buzón, junto a la base de datos (`hehermes_servidor.recuperacion.BUZON`, del lado del instalador).
BUZON = "buzon"
#: Un fichero del buzón: lo demás (los `.` del que se está escribiendo, cualquier otra cosa) ni se mira.
PATRON_FICHERO = re.compile(r"recuperacion-[0-9]{1,12}-[0-9a-f]{8}\.json")
#: El nombre de un iPhone en el servidor (el de su token: `NOMBRE_VALIDO` del instalador) y la marca de un token
#: (`hehermes_servidor.dispositivos.marca_del_token`).
PATRON_IPHONE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
PATRON_MARCA = re.compile(r"[0-9a-f]{16}")
#: Lo más que se lee de un fichero, y cuántos se miran en cada vuelta.
TOPE = 4096
MAX_POR_VUELTA = 20
#: Un suceso de hace más de esto no se avisa (el vigía estuvo parado): Ajustes › Tu servidor lo enseña igual. Y es lo
#: que Apple lo guarda si el iPhone no está localizable.
CADUCA = 24 * 3600
TITULO = "Código de recuperación"
TEXTO_ENTRADA = "Se ha conectado otro iPhone con tu código de recuperación: {}. Si no has sido tú, mira Ajustes › Tu " \
                "servidor."
TEXTO_INTENTOS = "Alguien ha intentado conectar un iPhone con un código de recuperación que no vale. Si no has sido tú, " \
                 "mira Ajustes › Tu servidor."


@dataclass(frozen=True)
class Suceso:
    #: El nombre de su fichero: es su identidad (lo que el relé ya aceptó no se vuelve a mandar).
    fichero: str
    #: `entrada` (ha entrado `iphone` con el código) o `intentos` (el primer fallo de una racha).
    que: str
    cuando: int
    iphone: str | None = None
    #: En `entrada`, la marca del token nuevo (a sus altas no se les avisa) y, si ya estaba con ese nombre, la del de
    #: antes (sus altas se avisan y después se borran).
    marca: str | None = None
    anterior: str | None = None


def leer_suceso(fichero: str, datos: bytes) -> Suceso | None:
    """El suceso de un fichero del buzón, o None si no tiene la forma que deja el instalador."""
    try:
        bruto = json.loads(datos)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(bruto, dict) or bruto.get("v") != 1 or bruto.get("tipo") != "recuperacion":
        return None
    que, cuando, iphone = bruto.get("que"), bruto.get("cuando"), bruto.get("iphone")
    marca, anterior = bruto.get("marca"), bruto.get("marca_anterior")
    if not isinstance(cuando, int) or isinstance(cuando, bool) or cuando < 0:
        return None
    if que == "entrada" and isinstance(iphone, str) and PATRON_IPHONE.fullmatch(iphone) \
            and isinstance(marca, str) and PATRON_MARCA.fullmatch(marca) \
            and (anterior is None or (isinstance(anterior, str) and PATRON_MARCA.fullmatch(anterior)
                                      and anterior != marca)):
        return Suceso(fichero, que, cuando, iphone, marca, anterior)
    if que == "intentos" and iphone is None and marca is None and anterior is None:
        return Suceso(fichero, que, cuando)
    return None


def aviso(suceso: Suceso) -> avisos.Aviso:
    """El aviso de un suceso: a todos, menos a las altas del token del que entra (`avisos.decidir_con_motivo`)."""
    if suceso.que == "entrada":
        texto, datos = TEXTO_ENTRADA.format(suceso.iphone), {"que": "entrada", "iphone": suceso.iphone}
    else:
        texto, datos = TEXTO_INTENTOS, {"que": "intentos"}
    return avisos.Aviso(tipo="recuperacion", sesion=None, titulo=TITULO, texto=texto, instante=float(suceso.cuando),
                        clave="recuperacion:" + suceso.fichero, caduca=CADUCA, recuperacion=datos,
                        excepto=suceso.marca)


class Buzon:
    """La carpeta donde el instalador deja los sucesos. Lo que no tiene forma se borra sin avisar; lo que se avisa, o ya
    es viejo para avisarse (`caducado`), al acabar con él (`hecho`)."""

    def __init__(self, carpeta: str, reloj=time.time):
        self.carpeta = carpeta
        self.reloj = reloj

    def preparar(self) -> None:
        """La crea si no está, 0700: es lo que le dice al instalador que este vigía sabe avisar de esto."""
        try:
            os.mkdir(self.carpeta, 0o700)
        except FileExistsError:
            pass
        info = os.lstat(self.carpeta)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(errno.ENOTDIR, "el buzón no es una carpeta", self.carpeta)

    def pendientes(self) -> list:
        """Los sucesos por resolver, del más viejo al más nuevo: también los que ya no se avisan (`caducado`), que aún
        dicen qué altas sobran. Sin carpeta, ninguno."""
        return self._sucesos(borrar=True)[:MAX_POR_VUELTA]

    def caducado(self, suceso: Suceso) -> bool:
        return self.reloj() - suceso.cuando > CADUCA

    def hay_por_avisar(self) -> bool:
        """Si queda algún aviso por mandar: mientras, no se barren las altas de un iPhone quitado (contrato §12.10).
        Lo mira la API, en su hilo: aquí no se borra nada."""
        try:
            return any(not self.caducado(s) for s in self._sucesos(borrar=False))
        except OSError:
            return False

    def _sucesos(self, borrar: bool) -> list:
        try:
            nombres = sorted(n for n in os.listdir(self.carpeta) if PATRON_FICHERO.fullmatch(n))
        except FileNotFoundError:
            return []
        sucesos = []
        for nombre in nombres:
            suceso = self._leer(nombre)
            if suceso is not None:
                sucesos.append(suceso)
            elif borrar:
                registro.warning("un fichero del buzón que no se entiende: se borra sin avisar")
                self._borrar(nombre)
        return sorted(sucesos, key=lambda s: (s.cuando, s.fichero))

    def hecho(self, suceso: Suceso) -> None:
        self._borrar(suceso.fichero)

    def _leer(self, nombre: str) -> Suceso | None:
        try:
            fd = os.open(os.path.join(self.carpeta, nombre),
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            return None
        except OSError:
            # Un enlace, o algo que no se puede abrir: no es del instalador.
            return None
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            datos = f.read(TOPE + 1)
        return leer_suceso(nombre, datos) if len(datos) <= TOPE else None

    def _borrar(self, nombre: str) -> None:
        try:
            os.unlink(os.path.join(self.carpeta, nombre))
        except FileNotFoundError:
            pass
