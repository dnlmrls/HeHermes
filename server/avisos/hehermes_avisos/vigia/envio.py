"""Mandar un aviso a un iPhone: cifrarlo con su clave, pasárselo al relé y hacer caso de lo que conteste.

Lo único que el relé puede pedir al vigía es que **dé de baja un token** (Apple dice que ya no vale: la app se borró, o
el token es de otro entorno). Lo demás son fallos: unos se arreglan esperando (el relé reiniciándose, Apple caída) y se
reintentan desde el bucle; otros no (un aviso que el relé rechaza) y solo se apuntan.

Con qué se le habla al relé (spec 2026-09-28, «Avisos sin comandos», Contrato B):

- **Con la credencial del vigía**, si la tiene (el de Daniel, o uno con código de avisos): como siempre, a su relé.
- **Sin credencial, con el permiso de cada iPhone**: el que firma el relé para ese token y que la app trae en el alta,
  junto con la dirección, el puerto y la huella de la entrada pública. Va por HTTPS anclado a esa huella y solo a una
  dirección pública (`comun.conectar_solo_a_publicas`): la dirección la manda la app, y el vigía no se deja llevar a
  la red de dentro del servidor. Si el relé lo rechaza (401 o 403 con `resultado: "permiso"`), se olvida, y el
  siguiente primer plano le pide otro a la app (`api.AppVigia.primer_plano`).
- **Sin ninguno de los dos**, no se manda: se apunta una vez por iPhone y hora.
"""

from __future__ import annotations

import http.client as http_client
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .. import comun
from ..comun import cola
from . import avisos
from .almacen import Almacen, Dispositivo, Permiso

registro = logging.getLogger("vigia.envio")

ENVIADO = "enviado"
BAJA = "baja"
LIMITADO = "limitado"
RECHAZADO = "rechazado"
REINTENTABLE = "reintentable"
#: El relé no acepta el permiso de este iPhone (firma mal, caducado, revocado o de otro token): se olvida.
PERMISO = "permiso"
#: Sin credencial y sin un permiso vigente: no se ha mandado nada.
SIN_PERMISO = "sin_permiso"

#: Con qué manda los avisos de un iPhone (la respuesta del alta, Contrato C).
CON_CREDENCIAL, CON_PERMISO, CON_NINGUNO = "credencial", "permiso", "ninguno"
#: Un permiso que caduca antes de esto se pide renovar en el primer plano (Contrato C: «menos de 7 días»).
RENOVAR_ANTES = 7 * 24 * 3600.0
#: El «no tengo con qué mandarlo» se apunta como mucho una vez por iPhone en este tiempo.
REPETIR_SIN_PERMISO = 3600.0
#: Clientes de relé distintos que se guardan (uno por dirección, puerto y huella): hay un relé, pero cada alta puede
#: traer otro, y esto no tiene que crecer sin fin.
MAX_CLIENTES = 16


@dataclass(frozen=True)
class Resultado:
    tipo: str
    motivo: str = ""
    # Lo que pide esperar el relé antes de volver a intentarlo (Retry-After), si lo dice.
    esperar: float | None = None


def url_del_rele(direccion: str, puerto: int) -> str:
    """La de la entrada pública de un permiso. Una IPv6 va entre corchetes."""
    return "https://%s:%d/v1/avisos" % ("[%s]" % direccion if ":" in direccion else direccion, int(puerto))


class ClienteRele:
    """``POST /v1/avisos`` con la credencial de este vigía o con el permiso de un iPhone. Todo lo que no sea una
    respuesta del relé es reintentable.

    El relé de la misma máquina, en claro por ``127.0.0.1``; el de otra (la entrada pública del de Daniel), por HTTPS
    con la huella de su certificado anclada. Un certificado con otra huella no recibe nada: ni la credencial, ni el
    permiso, ni el aviso (``comun.ErrorDeHuella``), y cuenta como que el relé no contesta. Con ``solo_publicas`` (el
    relé de un permiso, cuya dirección trae la app), tampoco se conecta a una dirección que no sea de internet."""

    def __init__(self, url: str, credencial: str | None, plazo: float = 8.0, abridor=None, huella: str | None = None,
                 solo_publicas: bool = False, permiso: str | None = None):
        """``huella``: la del relé de otra máquina (``https://…``), que se ancla antes de mandar nada. ``credencial``
        None: el cliente de un permiso, el que se da aquí (``permiso``) o el de cada ``enviar(…, permiso=…)``."""
        self.url = url
        self._credencial = credencial
        self._permiso = permiso
        self.plazo = plazo
        self._abridor = abridor or comun.abridor(huella, solo_publicas=solo_publicas)

    def enviar(self, peticion: dict, permiso: str | None = None) -> Resultado:
        permiso = permiso if permiso is not None else self._permiso
        if permiso is not None:
            autorizacion = f"Permiso {permiso}"
        elif self._credencial is not None:
            autorizacion = f"Bearer {self._credencial}"
        else:
            raise ValueError("un cliente sin credencial solo manda con el permiso del iPhone")
        cuerpo = json.dumps(peticion, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        solicitud = urllib.request.Request(self.url, data=cuerpo, method="POST",
                                           headers={"Content-Type": "application/json", "Authorization": autorizacion})
        try:
            with self._abridor.open(solicitud, timeout=self.plazo) as respuesta:
                estado, datos, cabeceras = respuesta.status, respuesta.read(), respuesta.headers
        except urllib.error.HTTPError as error:
            estado, cabeceras = error.code, error.headers
            try:
                datos = error.read()
            except (OSError, http_client.HTTPException):
                datos = b""
            error.close()
        except (urllib.error.URLError, OSError, http_client.HTTPException) as error:
            # Sin respuesta entera no se sabe si el aviso salió: se reintenta, y si salió, el colapso lo deja en uno.
            razon = getattr(error, "reason", None) or type(error).__name__
            return Resultado(REINTENTABLE, f"el relé no contesta: {razon}")
        return self._traducir(estado, datos, cabeceras)

    @staticmethod
    def _traducir(estado: int, datos: bytes, cabeceras) -> Resultado:
        try:
            respuesta = json.loads(datos.decode("utf-8")) if datos else {}
        except (UnicodeDecodeError, ValueError):
            respuesta = {}
        if not isinstance(respuesta, dict):
            respuesta = {}
        error = respuesta.get("error")
        motivo = str(respuesta.get("motivo") or (error.get("code") if isinstance(error, dict) else None) or estado)
        if 200 <= estado < 300:
            return Resultado(ENVIADO)
        if respuesta.get("baja") is True:
            return Resultado(BAJA, motivo)
        if estado in (401, 403) and respuesta.get("resultado") == "permiso":
            return Resultado(PERMISO, motivo)
        if estado == 429:
            try:
                esperar = float(cabeceras.get("Retry-After") or 0) or None
            except (TypeError, ValueError):
                esperar = None
            return Resultado(LIMITADO, motivo, esperar)
        if estado >= 500:
            return Resultado(REINTENTABLE, motivo)
        return Resultado(RECHAZADO, motivo)


class Mensajero:
    """Lo que comparten el bucle y el aviso de prueba: armar la petición, mandarla con lo que toque (la credencial o el
    permiso del iPhone) y dar de baja lo que haya muerto."""

    def __init__(self, almacen: Almacen, rele: ClienteRele | None, *, plazo: float = 8.0, reloj=time.time,
                 fabrica=None):
        """``rele``: el cliente con la credencial de este vigía, o None si no tiene (los avisos van con el permiso de
        cada iPhone). ``fabrica(direccion, puerto, huella)``: el cliente del relé de un permiso (las pruebas ponen
        uno que llega a 127.0.0.1)."""
        self.almacen = almacen
        self.rele = rele
        self.plazo = plazo
        self.reloj = reloj
        self._fabrica = fabrica or self._cliente_de_permiso
        self._clientes: dict = {}
        self._sin_permiso_apuntado: dict = {}

    @property
    def con_credencial(self) -> bool:
        return self.rele is not None

    def como_envia(self, dispositivo: Dispositivo | None, ahora: float | None = None) -> str:
        """Con qué irían ahora los avisos de este iPhone: lo que contesta el alta (Contrato C)."""
        if self.rele is not None:
            return CON_CREDENCIAL
        ahora = self.reloj() if ahora is None else ahora
        if dispositivo is not None and dispositivo.permiso is not None and dispositivo.permiso.vigente(ahora):
            return CON_PERMISO
        return CON_NINGUNO

    def pide_renovar(self, dispositivo: Dispositivo, ahora: float | None = None) -> bool:
        """Si hay que pedirle a la app otro permiso: sin credencial, y el suyo falta, caduca en menos de 7 días o el
        relé lo ha rechazado."""
        if self.rele is not None:
            return False
        ahora = self.reloj() if ahora is None else ahora
        permiso = dispositivo.permiso
        return permiso is None or permiso.rechazado is not None or permiso.caduca - ahora < RENOVAR_ANTES

    def _cliente_de_permiso(self, direccion: str, puerto: int, huella: str) -> ClienteRele:
        return ClienteRele(url_del_rele(direccion, puerto), None, self.plazo, huella=huella, solo_publicas=True)

    def _cliente(self, permiso: Permiso):
        clave = (permiso.direccion, permiso.puerto, permiso.huella)
        cliente = self._clientes.get(clave)
        if cliente is None:
            if len(self._clientes) >= MAX_CLIENTES:
                self._clientes.clear()
            cliente = self._clientes[clave] = self._fabrica(*clave)
        return cliente

    def enviar(self, aviso: avisos.Aviso, dispositivo: Dispositivo, peticion: dict | None = None) -> Resultado:
        """Manda ``aviso`` a ``dispositivo``. ``peticion``, si se da, es la ya armada de un intento anterior: un
        reintento repite el mismo sobre en vez de cifrar otro, así que si el primero sí llegó, colapsa con él."""
        donde = f"{cola(dispositivo.token)} ({dispositivo.entorno})"
        ahora = self.reloj()
        permiso = None
        if self.rele is None:
            permiso = dispositivo.permiso
            if permiso is None or not permiso.vigente(ahora):
                self._apuntar_sin_permiso(aviso, dispositivo, donde, ahora)
                return Resultado(SIN_PERMISO, "sin credencial ni un permiso vigente de este iPhone")
        peticion = peticion or avisos.peticion_al_rele(aviso, dispositivo)
        if permiso is None:
            resultado = self.rele.enviar(peticion)
        else:
            resultado = self._cliente(permiso).enviar(peticion, permiso=permiso.valor)
        if resultado.tipo == ENVIADO:
            self._sin_permiso_apuntado.pop(dispositivo.token, None)
            registro.info("aviso de %s → %s: enviado%s", aviso.tipo, donde, " (con su permiso)" if permiso else "")
        elif resultado.tipo == BAJA:
            self.almacen.borrar_dispositivo(dispositivo.token)
            registro.warning("aviso de %s → %s: Apple dice que el token ya no vale (%s); dado de baja",
                             aviso.tipo, donde, resultado.motivo)
        elif resultado.tipo == PERMISO and permiso is not None:
            # No se reintenta: con este permiso no va a salir. El siguiente primer plano le pide otro a la app.
            self.almacen.rechazar_permiso(dispositivo.token, permiso.valor, ahora)
            registro.warning("aviso de %s → %s: el relé no acepta su permiso (%s); se olvida y se le pedirá otro "
                             "a la app", aviso.tipo, donde, resultado.motivo)
        else:
            registro.warning("aviso de %s → %s: %s (%s)", aviso.tipo, donde, resultado.tipo, resultado.motivo)
        return resultado

    def _apuntar_sin_permiso(self, aviso: avisos.Aviso, dispositivo: Dispositivo, donde: str, ahora: float) -> None:
        ultimo = self._sin_permiso_apuntado.get(dispositivo.token)
        if ultimo is not None and ahora - ultimo < REPETIR_SIN_PERMISO:
            return
        self._sin_permiso_apuntado[dispositivo.token] = ahora
        porque = ("no tiene permiso" if dispositivo.permiso is None else
                  "el relé rechazó su permiso" if dispositivo.permiso.rechazado is not None else "su permiso caducó")
        registro.warning("aviso de %s → %s: no sale: este vigía no tiene credencial y el iPhone %s (se le pedirá "
                         "otro en su próximo primer plano)", aviso.tipo, donde, porque)
