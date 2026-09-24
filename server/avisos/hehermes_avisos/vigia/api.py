"""Lo que la app le pide al vigía por el túnel, tal y como lo implementó (``ClienteHermes+Avisos.swift``):

- ``POST   /avisos/v1/dispositivos``                    alta, idempotente por token
- ``PUT    /avisos/v1/dispositivos/{token}/ajustes``    los ajustes de Ajustes › Notificaciones
- ``PUT    /avisos/v1/dispositivos/{token}/primer-plano`` si la app está delante (con plazo)
- ``POST   /avisos/v1/prueba``                           manda un aviso de prueba, y espera a lo que diga Apple
- ``DELETE /avisos/v1/dispositivos/{token}``             baja (un 404 también le vale a la app)
- ``GET    /avisos/v1/salud``                            para ver desde Safari que nginx llega al vigía

Todo contesta 204 si va bien, y los errores con el envoltorio del api_server de Hermes, que es el que entiende la app.

**Solo lo que llega por el túnel.** La credencial del iPhone es la de su VPN, como con Hermes. Pero el vigía escucha en
``127.0.0.1``, y cualquier proceso de la máquina podría hablarle: dar de alta veinte tokens falsos, echar al iPhone de
Daniel del tope de dispositivos y, con la app en la App Store, recibir el principio de sus respuestas. Hacen falta dos
cosas, y ninguna basta sola:

- nginx pone en cada petición de ``/avisos/`` una cabecera con un secreto (``X-HeHermes-Vigia``, desde un fichero de
  root en 0600) y el vigía no atiende nada sin ella: 403, sin apuntar la ruta, que lleva el token. Eso cierra la puerta
  a quien le hable directo en ``127.0.0.1:8790``.
- Pero nginx pone el secreto a todo lo que le llega a ``10.77.0.1:80``, también a los procesos de la propia máquina.
  Así que la ``location /avisos/`` solo deja pasar las direcciones de los iPhone del túnel (``deny 10.77.0.1``, sus dos
  redes, ``deny all``: ``despliegue/nginx-avisos.conf``).
"""

from __future__ import annotations

import hmac
import logging
import re
import time

from .. import VERSION, cifrado
from ..comun import ENTORNOS, PATRON_TOKEN, ErrorHTTP, ManejadorJSON, cola
from . import avisos
from .ajustes import MAX_ID_SESION, Ajustes
from .almacen import Almacen
from .envio import BAJA, ENVIADO, LIMITADO, REINTENTABLE, Mensajero

registro = logging.getLogger("vigia.api")

RUTA_DISPOSITIVO = re.compile(r"/avisos/v1/dispositivos/([^/]+)(?:/(ajustes|primer-plano))?/?")
# Lo que la app manda como plazo del primer plano (90 s) y lo que se acepta: un plazo enorme dejaría al vigía callado
# mucho tiempo si el «ya no estoy delante» se pierde, que es justo lo que el plazo existe para evitar.
CADUCA_POR_DEFECTO = 90.0
CADUCA_MAXIMA = 600.0
# Turnos que la app puede dejar vigilando de una vez (ampliación propuesta del contrato).
MAX_TURNOS = 20
PATRON_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")
CABECERA_TUNEL = "X-HeHermes-Vigia"
# Una petición sin la cabecera se apunta en el registro una vez cada diez minutos: un proceso insistiendo no lo inunda.
REPETIR_SIN_TUNEL = 600.0


def token_valido(texto: object) -> str:
    """El token en hexadecimal y en minúsculas, que es como lo manda la app y como lo quiere Apple en su ruta."""
    if not isinstance(texto, str) or not PATRON_TOKEN.fullmatch(texto.lower()):
        raise ErrorHTTP(400, "token_invalido", "El token tiene que ser el de APNs en hexadecimal")
    return texto.lower()


class AppVigia:
    """La lógica de la API, sin HTTP: así se prueba llamándola, y el manejador solo traduce."""

    def __init__(self, almacen: Almacen, mensajero: Mensajero, *, secreto_tunel: str, caducidad_prueba: int = 300,
                 reloj=time.time, al_moverse=None):
        if not secreto_tunel:
            raise ValueError("sin el secreto del túnel, la API del vigía quedaría abierta a cualquier proceso local")
        self.almacen = almacen
        self.mensajero = mensajero
        self.caducidad_prueba = caducidad_prueba
        self.reloj = reloj
        self._secreto = secreto_tunel.encode("utf-8")
        # Lo que hay que hacer cuando una app se va a segundo plano o deja turnos: despertar al bucle (`Vigilante`).
        self.al_moverse = al_moverse or (lambda: None)
        self._ultimo_sin_tunel = -REPETIR_SIN_TUNEL

    def viene_del_tunel(self, valor: str | None) -> bool:
        """Si la petición trae el secreto que pone nginx. Comparado en tiempo constante."""
        if not isinstance(valor, str):
            return False
        return hmac.compare_digest(valor.encode("utf-8", "surrogateescape"), self._secreto)

    def rechazar_fuera_del_tunel(self) -> None:
        ahora = self.reloj()
        if ahora - self._ultimo_sin_tunel >= REPETIR_SIN_TUNEL:
            self._ultimo_sin_tunel = ahora
            registro.warning("petición a la API del vigía sin la cabecera del túnel: 403 (no llegó por nginx)")
        raise ErrorHTTP(403, "fuera_del_tunel", "El vigía solo atiende lo que llega por el túnel")

    def alta(self, cuerpo: dict) -> None:
        token = token_valido(cuerpo.get("token"))
        entorno = cuerpo.get("entorno")
        if entorno not in ENTORNOS:
            raise ErrorHTTP(400, "entorno_invalido", "El entorno tiene que ser «sandbox» o «production»")
        try:
            clave = cifrado.clave_desde_base64(cuerpo.get("clave"))
        except cifrado.ErrorDeCifrado:
            raise ErrorHTTP(400, "clave_invalida", "La clave tiene que ser base64 de 32 bytes") from None
        nuevo = self.almacen.guardar_dispositivo(token, entorno, clave, Ajustes.desde_json(cuerpo.get("ajustes")),
                                                 self.reloj())
        registro.info("%s de %s (%s)", "alta" if nuevo else "alta renovada", cola(token), entorno)
        self.al_moverse()

    def ajustes(self, token: str, cuerpo: dict) -> None:
        if not self.almacen.cambiar_ajustes(token, Ajustes.desde_json(cuerpo), self.reloj()):
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no está dado de alta")
        registro.info("ajustes de %s al día", cola(token))

    def primer_plano(self, token: str, cuerpo: dict) -> None:
        activa = cuerpo.get("activa") is True
        conversacion = cuerpo.get("conversacion")
        if not (isinstance(conversacion, str) and 0 < len(conversacion) <= MAX_ID_SESION):
            conversacion = None
        caduca = cuerpo.get("caduca")
        if not isinstance(caduca, (int, float)) or isinstance(caduca, bool) or caduca <= 0:
            caduca = CADUCA_POR_DEFECTO
        ahora = self.reloj()
        if not self.almacen.cambiar_primer_plano(token, activa, conversacion, min(float(caduca), CADUCA_MAXIMA),
                                                 ahora):
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no está dado de alta")
        turnos = _turnos(cuerpo.get("turnos"))
        self.almacen.vigilar_turnos(turnos, ahora)
        if not activa or turnos:
            self.al_moverse()

    def prueba(self, cuerpo: dict) -> None:
        token = token_valido(cuerpo.get("token"))
        dispositivo = self.almacen.dispositivo(token)
        if dispositivo is None:
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no está dado de alta")
        resultado = self.mensajero.enviar(avisos.aviso_de_prueba(self.reloj(), self.caducidad_prueba), dispositivo)
        if resultado.tipo == ENVIADO:
            return
        if resultado.tipo == BAJA:
            raise ErrorHTTP(410, "token_caducado", "Apple dice que este token ya no vale: se ha dado de baja")
        if resultado.tipo == LIMITADO:
            raise ErrorHTTP(429, "demasiados_avisos", "Demasiados avisos seguidos",
                            {"Retry-After": str(int(resultado.esperar or 5))})
        codigo = "rele_no_disponible" if resultado.tipo == REINTENTABLE else "aviso_rechazado"
        raise ErrorHTTP(502, codigo, f"El aviso no ha salido: {resultado.motivo}")

    def baja(self, token: str) -> None:
        if not self.almacen.borrar_dispositivo(token):
            raise ErrorHTTP(404, "dispositivo_desconocido", "Este dispositivo no estaba dado de alta")
        registro.info("baja de %s", cola(token))


def _turnos(lista: object) -> list:
    """Los turnos de ``{"turnos": [{"run_id": …, "sesion": …}]}``, si vienen. Lo que no tenga forma se ignora: es una
    ampliación opcional y una app que la mande mal no puede quedarse sin su primer plano."""
    if not isinstance(lista, list):
        return []
    turnos = []
    for turno in lista[:MAX_TURNOS]:
        if isinstance(turno, dict):
            run_id, sesion = turno.get("run_id"), turno.get("sesion")
            if (isinstance(run_id, str) and PATRON_ID.fullmatch(run_id) and isinstance(sesion, str)
                    and PATRON_ID.fullmatch(sesion)):
                turnos.append((run_id, sesion))
    return turnos


class ManejadorVigia(ManejadorJSON):
    def nombre_registro(self) -> str:
        return "vigia.api"

    def atender(self) -> None:
        app: AppVigia = self.server.app
        if not app.viene_del_tunel(self.headers.get(CABECERA_TUNEL)):
            app.rechazar_fuera_del_tunel()
        ruta, metodo = self.ruta, self.command
        if ruta == "/avisos/v1/dispositivos":
            self._exigir(metodo, "POST")
            app.alta(self.leer_json())
        elif ruta == "/avisos/v1/prueba":
            self._exigir(metodo, "POST")
            app.prueba(self.leer_json())
        elif ruta == "/avisos/v1/salud":
            self._exigir(metodo, "GET")
            return self.enviar_json(200, {"estado": "ok", "servicio": "vigia", "version": VERSION})
        else:
            encontrada = RUTA_DISPOSITIVO.fullmatch(ruta)
            if not encontrada:
                raise ErrorHTTP(404, "ruta_desconocida", "Ruta desconocida")
            token = token_valido(encontrada.group(1))
            if encontrada.group(2) is None:
                self._exigir(metodo, "DELETE")
                app.baja(token)
            elif encontrada.group(2) == "ajustes":
                self._exigir(metodo, "PUT")
                app.ajustes(token, self.leer_json())
            else:
                self._exigir(metodo, "PUT")
                app.primer_plano(token, self.leer_json())
        self.enviar_json(204)

    @staticmethod
    def _exigir(metodo: str, permitido: str) -> None:
        if metodo != permitido:
            raise ErrorHTTP(405, "metodo_no_permitido", f"Aquí solo vale {permitido}", {"Allow": permitido})
