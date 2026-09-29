"""La entrada pública del relé: por donde le llegan los avisos de los vigías de **otros** servidores (spec
2026-09-28, «El relé para los probadores»).

El relé sigue escuchando solo en ``127.0.0.1:8791`` (su socket de systemd), y el vigía de la misma máquina le sigue
hablando ahí. Delante, en un puerto TCP alto elegido una vez al azar (58000–65500), va esto: **la misma maquinaria que
la pasarela** (``hehermes_servidor.pasarela``), con las credenciales de los vigías en lugar de los tokens de los iPhone:

- solo TLS 1.3, con un certificado ECDSA P-256 propio y autofirmado cuya huella (el SHA-256 de su SPKI) ancla el vigía;
- a lo que no trae una credencial válida, siempre el mismo 404, un segundo después, sin cabecera ``Server``;
- 10 intentos fallidos desde una IP en 10 minutos la bloquean 15; 16 conexiones por IP y 128 en total; 10 s para las
  cabeceras; cuerpos de 16 KiB como mucho (lo que acepta el relé);
- no apunta ni la credencial, ni la ruta con su consulta, ni ningún cuerpo;
- una baja (``hehermes-rele credencial baja``) vale al momento y corta en un segundo las conexiones abiertas con ella.

Desde la 1.3.0, además, la **oficina de permisos** (``permisos.Oficina``, spec 2026-09-28 «Avisos sin comandos»): las
rutas ``/v1/permisos/…``, que no piden credencial (la app se atesta con App Attest y recibe un permiso por dispositivo),
y los avisos con ``Authorization: Permiso hhp1.…`` en lugar de una credencial.

Lo que pasa, lo reenvía tal cual al relé, **con la misma credencial**: el relé la vuelve a comprobar, aplica sus
límites por credencial y por token y apunta el nombre de la credencial en cada aviso. La entrada no tiene la clave .p8
ni la puede leer: corre como ``hh-rele-publico``, que solo está en el grupo de ``credenciales.ini``.

El «código de avisos» (``codigo``) es lo que se le da al dueño del otro servidor: la dirección, el puerto, la huella y
la credencial, en una línea ``hehermes-avisos:1?h=…&p=…&f=…&c=…``. Lleva la credencial, así que es secreto: se pinta
solo en un terminal, o se deja en un fichero 0600.

``python -m hehermes_avisos.rele.publico``:

- ``servir --config RUTA``: lo que arranca ``hehermes-rele-publico.service``.
- ``preparar --config RUTA --carpeta CARPETA [--direccion D]``: la primera vez, elige el puerto y hace el certificado
  (con el venv, que tiene ``cryptography``). Después no toca nada: el puerto y la huella son para siempre. Pone también
  la oficina de permisos si falta (``preparar_permisos``: sus claves y la sección [permisos]).
- ``comprobar --config RUTA``: se asoma sin credencial, como cualquiera, y mira el TLS, la huella y el 404.
"""

from __future__ import annotations

import argparse
import asyncio
import configparser
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse

from hehermes_servidor import pasarela as base

from . import permisos as modulo_permisos
from .credenciales import FORMA, Almacen

#: Lo más grande que acepta el relé (``ManejadorRele.tope_cuerpo``): lo demás, ni se lee.
TOPE = 16 * 1024
PUERTO_MINIMO, PUERTO_MAXIMO = 58000, 65500
ESQUEMA = "hehermes-avisos:1"
_DIRECCION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}")
_HUELLA = re.compile(r"[A-Za-z0-9_-]{43}")


# MARK: El código de avisos


def codigo(direccion: str, puerto: int, huella: str, credencial: str) -> str:
    """``hehermes-avisos:1?h=<dirección>&p=<puerto>&f=<huella>&c=<credencial>``. Todo va validado: lo que no tiene la
    forma de siempre no sale."""
    if not _DIRECCION.fullmatch(direccion or ""):
        raise ValueError("dirección no válida: %r" % direccion)
    if not isinstance(puerto, int) or not 0 < puerto < 65536:
        raise ValueError("puerto no válido: %r" % puerto)
    if not _HUELLA.fullmatch(huella or ""):
        raise ValueError("huella no válida")
    if not FORMA.fullmatch(credencial or ""):
        raise ValueError("credencial no válida")
    return "%s?%s" % (ESQUEMA, urllib.parse.urlencode({"h": direccion, "p": puerto, "f": huella, "c": credencial}))


def leer_codigo(texto: str) -> dict:
    """Lo contrario de ``codigo``: ``{h, p, f, c}``. Lo mismo que hace el instalador (``hehermes_servidor.avisos``)."""
    esquema, _, consulta = (texto or "").strip().partition("?")
    if esquema != ESQUEMA:
        raise ValueError("no es un código de avisos")
    campos = urllib.parse.parse_qs(consulta, keep_blank_values=True, strict_parsing=True)
    if sorted(campos) != ["c", "f", "h", "p"] or any(len(v) != 1 for v in campos.values()):
        raise ValueError("al código le falta o le sobra algo")
    datos = {k: v[0] for k, v in campos.items()}
    if not datos["p"].isdigit():
        raise ValueError("puerto no válido")
    datos["p"] = int(datos["p"])
    codigo(datos["h"], datos["p"], datos["f"], datos["c"])
    return datos


# MARK: La configuración


class ConfigPublico:
    """``rele-publico.ini``, que escribe ``preparar``. Con systemd, la clave del certificado llega como credencial
    (``LoadCredential=clave:…``) y manda sobre la ruta del fichero."""

    def __init__(self):
        self.puerto = None
        self.escucha = ""
        self.certificado = self.clave = self.credenciales = None
        self.rele = ("127.0.0.1", 8791)
        self.direccion = None
        # La oficina de permisos (App Attest): la clave privada con la que firma, su base de datos, la lista de
        # revocados y el App ID. Sin la sección [permisos], no hay oficina (sus rutas dan el 404 de siempre).
        self.permisos_clave = self.permisos_base = self.permisos_revocados = None
        self.permisos_app = None
        #: El certificado que viene después ([siguiente] certificado, que pone `preparar`): su huella se da a quien
        #: trae una credencial o un permiso (`GET /hehermes/v1/huellas`), para rotar sin dejar a nadie fuera.
        self.certificado_siguiente = None
        #: La carpeta de credenciales de systemd de este servicio, si llegó alguna por ahí.
        self.credenciales_systemd = None
        # Lo que la maquinaria de la pasarela espera encontrar y aquí no hay.
        self.tokens = self.clave_hermes = self.secreto_vigia = self.vigia = None
        self.puerto_hermes = None

    @classmethod
    def leer(cls, ruta: str, credenciales_systemd: str | None = None) -> "ConfigPublico":
        ini = configparser.ConfigParser(interpolation=None)
        try:
            with open(ruta, encoding="utf-8") as fichero:
                ini.read_file(fichero)
            c = cls()
            c.puerto = int(ini.get("publico", "puerto"))
            if not 0 < c.puerto < 65536:
                raise ValueError("puerto fuera de rango")
            c.escucha = ini.get("publico", "escucha", fallback="").strip()
            c.certificado = _absoluta(ini.get("publico", "certificado"))
            c.clave = _absoluta(ini.get("publico", "clave"))
            c.credenciales = _absoluta(ini.get("publico", "credenciales"))
            host, _, puerto = ini.get("publico", "rele", fallback="127.0.0.1:8791").strip().rpartition(":")
            if not ipaddress.ip_address(host.strip("[]")).is_loopback:
                raise ValueError("el relé tiene que estar en 127.0.0.1, no en %s" % host)
            c.rele = (host.strip("[]"), int(puerto))
            c.direccion = ini.get("publico", "direccion", fallback="").strip() or None
            siguiente = ini.get("siguiente", "certificado", fallback="").strip()
            c.certificado_siguiente = _absoluta(siguiente) if siguiente else None
            if ini.has_section("permisos"):
                c.permisos_clave = _absoluta(ini.get("permisos", "clave"))
                c.permisos_base = _absoluta(ini.get("permisos", "base_de_datos"))
                c.permisos_revocados = _absoluta(ini.get("permisos", "revocados"))
                c.permisos_app = ini.get("permisos", "app", fallback="").strip() or None
        except (OSError, configparser.Error, ValueError) as error:
            raise ValueError("%s: %s" % (ruta, error)) from None
        c.credenciales_systemd = credenciales_systemd or None
        if credenciales_systemd and os.path.exists(os.path.join(credenciales_systemd, "clave")):
            c.clave = os.path.join(credenciales_systemd, "clave")
        if c.permisos_clave and credenciales_systemd and os.path.exists(os.path.join(credenciales_systemd, "permisos")):
            c.permisos_clave = os.path.join(credenciales_systemd, "permisos")
        return c


def _absoluta(ruta: str) -> str:
    ruta = ruta.strip()
    if not ruta.startswith("/"):
        raise ValueError("ruta no absoluta: %s" % ruta)
    return ruta


# MARK: El servidor


#: Las rutas de la oficina de permisos: las únicas que no llevan credencial.
RUTAS_PERMISOS = ("/v1/permisos/reto", "/v1/permisos/atestacion", "/v1/permisos/asercion")
_FRASES = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           413: "Payload Too Large", 429: "Too Many Requests", 503: "Service Unavailable"}


def respuesta_json(estado: int, cuerpo: dict, cabeceras: dict | None = None) -> bytes:
    datos = json.dumps(cuerpo, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    extra = "".join("%s: %s\r\n" % par for par in (cabeceras or {}).items())
    return (("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n%s"
             "Connection: close\r\n\r\n") % (estado, _FRASES.get(estado, "Error"), len(datos), extra)).encode(
        "latin-1") + datos


class FrenteDelRele(base.Pasarela):
    """La pasarela, con las credenciales de los vigías y un solo destino: el relé, con la misma credencial.

    Con la oficina de permisos (``permisos.Oficina``), además: sus tres rutas sin credencial, y los avisos que traen un
    permiso en lugar de una credencial (``Authorization: Permiso hhp1.…``), que pasan al relé si el permiso está bien
    firmado, en fecha y sin revocar. El relé lo vuelve a mirar todo, y además que sea para el token del aviso."""

    nombre = "entrada pública del relé"

    def __init__(self, config: ConfigPublico, credenciales: Almacen, oficina=None, **opciones):
        super().__init__(config, tokens=credenciales, **opciones)
        self.oficina = oficina

    def _permiso(self, peticion):
        valores = peticion.valores("authorization")
        return modulo_permisos.permiso_de(valores[0]) if len(valores) == 1 else None

    async def atender_aparte(self, peticion, lector, escritor, ip):
        if self.oficina is None:
            return None
        if peticion.ruta in RUTAS_PERMISOS:
            if peticion.metodo != "POST" or peticion.valores("authorization"):
                return await self._rechazar(escritor, ip)
            return await self._oficina(peticion, lector, escritor, ip)
        permiso = self._permiso(peticion)
        if permiso is None or not modulo_permisos.FORMA.fullmatch(permiso):
            # Una credencial (o nada, o un permiso sin su forma): lo de siempre.
            return None
        if peticion.ruta != "/v1/avisos" or peticion.metodo != "POST":
            return await self._rechazar(escritor, ip)
        try:
            self.oficina.comprobar_permiso(permiso)
        except modulo_permisos.ErrorDePermiso as error:
            if error.motivo == "permiso_invalido":
                bloqueada = self.limites.bloqueada(ip)
                self.limites.fallo(ip)
                if not await self.castigo(ip, bloqueada):
                    return False
            return await self._contestar(escritor, ip, peticion, 401, {"resultado": "permiso", "motivo": error.motivo})
        return None

    def autorizar(self, peticion):
        permiso = self._permiso(peticion)
        if permiso is not None:
            if self.oficina is None:
                return None
            try:
                self.oficina.comprobar_permiso(permiso)
            except modulo_permisos.ErrorDePermiso:
                return None
            return ""
        return super().autorizar(peticion)

    async def _contestar(self, escritor, ip, peticion, estado, cuerpo, cabeceras=None) -> bool:
        escritor.write(respuesta_json(estado, cuerpo, cabeceras))
        try:
            await escritor.drain()
        except (OSError, ConnectionError):
            pass
        # La ruta de la oficina es fija y no lleva nada; la de un aviso, tampoco. Nunca el cuerpo.
        self.diario("%s %s %s %d" % (ip, peticion.metodo, peticion.ruta, estado))
        return False

    async def _oficina(self, peticion, lector, escritor, ip) -> bool:
        largos = peticion.valores("content-length")
        if peticion.valores("transfer-encoding") or len(set(largos)) > 1 or (
                largos and not re.fullmatch(r"[0-9]{1,6}", largos[0])):
            return await self._contestar(escritor, ip, peticion, 400,
                                         {"error": {"code": "peticion_invalida", "message": "Cuerpo sin su largo"}})
        largo = int(largos[0]) if largos else 0
        if largo > TOPE:
            return await self._contestar(escritor, ip, peticion, 413, {"error": {
                "code": "cuerpo_demasiado_grande", "message": "El cuerpo es más grande de lo que se acepta"}})
        try:
            datos = await asyncio.wait_for(lector.readexactly(largo), base.PLAZO_TROZO) if largo else b"{}"
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            return False
        try:
            cuerpo = json.loads(datos.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            cuerpo = None
        if peticion.ruta == "/v1/permisos/reto" and cuerpo is None:
            cuerpo = {}
        # Comprobar una atestación son unos milisegundos de CPU (una cadena de certificados): fuera del bucle.
        respuesta = await asyncio.get_running_loop().run_in_executor(None, self.oficina.atender, peticion.ruta,
                                                                     cuerpo, ip)
        if respuesta.fallo:
            self.limites.fallo(ip)
        return await self._contestar(escritor, ip, peticion, respuesta.estado, respuesta.cuerpo, respuesta.cabeceras)

    def tope(self, peticion) -> int:
        return TOPE

    def destino(self, peticion, ip):
        # Aquí ya se sabe que trae una sola cabecera Authorization, y que es una credencial dada de alta: va tal cual,
        # y el relé la vuelve a comprobar (y apunta su nombre, y la limita).
        return self.config.rele, [("Authorization", peticion.valores("authorization")[0])], "rele_no_contesta"


def oficina_de(config: ConfigPublico):
    """La oficina de permisos de esta configuración, o None si no tiene la sección [permisos]."""
    if not config.permisos_clave:
        return None
    # Llega por LoadCredential: systemd la deja en la carpeta de credenciales del servicio, solo suya, con modo 0440, y
    # `leer_secreto` lo acepta ahí (y solo ahí). Fuera de systemd, la del ini: 0600 u 0400, solo para su dueño.
    from ..comun import leer_secreto
    privada = modulo_permisos.cargar_privada(leer_secreto(config.permisos_clave,
                                                          credenciales=config.credenciales_systemd or ""))
    return modulo_permisos.Oficina(privada, modulo_permisos.Claves(config.permisos_base),
                                   modulo_permisos.Revocados(config.permisos_revocados),
                                   app_id=config.permisos_app or modulo_permisos.appattest.APP_ID)


def servir(config: ConfigPublico, tls_minimo=None) -> int:
    import logging
    from ..comun import SALIDA_CONFIGURACION, ErrorDeSecreto, configurar_registro
    configurar_registro("INFO")
    try:
        oficina = oficina_de(config)
        frente = FrenteDelRele(config, Almacen(config.credenciales), oficina=oficina, tls_minimo=tls_minimo)
    except (OSError, ssl.SSLError, ValueError, ErrorDeSecreto) as error:
        # Un secreto que no se lee, o con otros permisos, no se arregla reiniciando: se dice una vez, con el remedio, y
        # la unidad no vuelve a arrancar (RestartPreventExitStatus=78) hasta que alguien lo arregle.
        print("error: no arranco: %s. Arréglalo y: systemctl restart hehermes-rele-publico" % error, flush=True)
        return SALIDA_CONFIGURACION
    logging.getLogger("rele.permisos").info("oficina de permisos: %s", "en marcha (%s)" % config.permisos_app
                                            if oficina else "sin configurar")
    print("%d credenciales en %s; al relé, en %s:%d" % (len(frente.tokens), config.credenciales, *config.rele),
          flush=True)
    try:
        asyncio.run(frente.servir())
    except KeyboardInterrupt:
        pass
    return 0


# MARK: Preparar y comprobar


def huella_del_certificado(ruta: str) -> str:
    with open(ruta, encoding="ascii") as fichero:
        return base.huella_de_der(ssl.PEM_cert_to_DER_cert(fichero.read()))


def _ocupados() -> set:
    """Todos los puertos TCP locales en uso, escuchen o no (lo mismo que mira el instalador para la pasarela)."""
    try:
        salida = subprocess.run(["ss", "-H", "-tan"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    ocupados = set()
    for linea in salida.splitlines():
        campos = linea.split()
        if len(campos) >= 4 and campos[3].rsplit(":", 1)[-1].isdigit():
            ocupados.add(int(campos[3].rsplit(":", 1)[-1]))
    return ocupados


def _direccion_de_la_pasarela(ruta: str = "/etc/hehermes-pasarela/pasarela.ini") -> str | None:
    """La del QR de la pasarela, si la hay: es la de esta máquina que ya ven los iPhone, y la que hay que dar."""
    ini = configparser.ConfigParser(interpolation=None)
    try:
        ini.read(ruta, encoding="utf-8")
        valor = ini.get("qr", "direccion", fallback="").strip()
    except (OSError, configparser.Error):
        return None
    return valor if _DIRECCION.fullmatch(valor) and valor != "PENDIENTE" else None


def _direccion_de_salida() -> str | None:
    try:
        salida = subprocess.run(["ip", "-4", "-j", "route", "get", "1.1.1.1"], capture_output=True, text=True,
                                timeout=10).stdout
        valor = json.loads(salida)[0].get("prefsrc")
    except (OSError, subprocess.SubprocessError, ValueError, IndexError, AttributeError):
        return None
    return valor if isinstance(valor, str) and _DIRECCION.fullmatch(valor) else None


def preparar(ruta_ini: str, carpeta: str, direccion: str | None = None,
             credenciales: str = "/etc/hehermes-avisos/rele/credenciales.ini", rele: str = "127.0.0.1:8791",
             ocupados=None, azar=None, direccion_pasarela=None) -> dict:
    """La primera vez: el puerto, el certificado y ``rele-publico.ini``. Si ya está, no toca nada (el puerto y la
    huella van en los códigos que ya se han dado). Devuelve ``{puerto, huella, direccion, nuevo}``."""
    if os.path.exists(ruta_ini):
        config = ConfigPublico.leer(ruta_ini)
        return {"puerto": config.puerto, "huella": huella_del_certificado(config.certificado),
                "direccion": config.direccion, "nuevo": False}
    direccion = direccion or (direccion_pasarela or _direccion_de_la_pasarela)() or _direccion_de_salida()
    if not direccion or not _DIRECCION.fullmatch(direccion):
        raise ValueError("no sé la dirección pública de esta máquina: dila con --direccion")
    from hehermes_servidor.porchat import elegir_puerto
    puerto = elegir_puerto(_ocupados() if ocupados is None else ocupados, azar=azar)
    if puerto is None:
        raise ValueError("no queda ningún puerto libre entre el %d y el %d" % (PUERTO_MINIMO, PUERTO_MAXIMO))
    from hehermes_servidor.canje import preparar as certificado
    os.makedirs(carpeta, mode=0o755, exist_ok=True)
    huella = certificado(carpeta, 3650)
    os.chmod(os.path.join(carpeta, "cert.pem"), 0o644)
    texto = ("# La entrada pública del relé (hehermes_avisos.rele.publico). La escribe `preparar` la primera vez: el\n"
             "# puerto y el certificado van en los códigos de avisos que ya se han dado, así que no se cambian.\n"
             "[publico]\n"
             "puerto = %d\n"
             "# Vacío: todas las direcciones (IPv4 e IPv6).\n"
             "escucha =\n"
             "certificado = %s\n"
             "clave = %s\n"
             "credenciales = %s\n"
             "rele = %s\n"
             "# La que va en los códigos de avisos.\n"
             "direccion = %s\n") % (puerto, os.path.join(carpeta, "cert.pem"), os.path.join(carpeta, "clave.pem"),
                                    credenciales, rele, direccion)
    fd = os.open(ruta_ini, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fichero:
        fichero.write(texto)
    return {"puerto": puerto, "huella": huella, "direccion": direccion, "nuevo": True}


PERMISOS_PUBLICA = "/etc/hehermes-avisos/rele/permisos.pub.pem"
PERMISOS_BASE = "/var/lib/hehermes-rele-publico/permisos.db"
PERMISOS_REVOCADOS = "/etc/hehermes-avisos/rele/permisos-revocados.txt"


def preparar_permisos(ruta_ini: str, carpeta: str, publica: str = PERMISOS_PUBLICA, base_de_datos: str = PERMISOS_BASE,
                      revocados: str = PERMISOS_REVOCADOS) -> dict:
    """La oficina de permisos, en una entrada que ya está: el par de claves Ed25519 (la privada, en la carpeta del
    certificado, 0600 de root; la pública, para el relé) y la sección [permisos] de ``rele-publico.ini``. Se puede
    repetir: lo que ya está no se toca (otra clave dejaría sin valor todos los permisos dados). Devuelve
    ``{nueva_clave, nueva_seccion}``."""
    privada = os.path.join(carpeta, "permisos.pem")
    nueva_clave = modulo_permisos.crear_claves(privada, publica)
    ini = configparser.ConfigParser(interpolation=None)
    with open(ruta_ini, encoding="utf-8") as fichero:
        ini.read_file(fichero)
    nueva_seccion = not ini.has_section("permisos")
    if nueva_seccion:
        # Se añade al final, sin reescribir lo de antes (el puerto y la dirección de los códigos que ya se han dado).
        with open(ruta_ini, "a", encoding="utf-8") as fichero:
            fichero.write("\n# La oficina de permisos de avisos (App Attest): la clave con la que firma (le llega por\n"
                          "# LoadCredential=permisos), sus claves atestadas y la lista de revocados, que lee también el relé.\n"
                          "[permisos]\n"
                          "clave = %s\n"
                          "base_de_datos = %s\n"
                          "revocados = %s\n"
                          "app = %s\n" % (privada, base_de_datos, revocados, modulo_permisos.appattest.APP_ID))
    return {"nueva_clave": nueva_clave, "nueva_seccion": nueva_seccion}


def preparar_siguiente(ruta_ini: str, carpeta: str) -> dict:
    """El certificado que viene después, en ``<carpeta>/siguiente`` (la clave, 0600 de root y sin usar hasta rotar; el
    certificado, 0644), y la sección [siguiente] del ini. Se puede repetir. Devuelve ``{huella, nuevo}``."""
    from hehermes_servidor.canje import preparar as certificado
    siguiente = os.path.join(carpeta, "siguiente")
    cert = os.path.join(siguiente, "cert.pem")
    nuevo = not (os.path.exists(cert) and os.path.exists(os.path.join(siguiente, "clave.pem")))
    if nuevo:
        os.makedirs(siguiente, mode=0o755, exist_ok=True)
        certificado(siguiente, 3650)
        os.chmod(cert, 0o644)
    ini = configparser.ConfigParser(interpolation=None)
    with open(ruta_ini, encoding="utf-8") as fichero:
        ini.read_file(fichero)
    if not ini.has_section("siguiente"):
        with open(ruta_ini, "a", encoding="utf-8") as fichero:
            fichero.write("\n# El certificado que viene después: su huella se da a los vigías y a las apps con credencial o\n"
                          "# permiso (GET /hehermes/v1/huellas). `rotar` lo pone en lugar del de ahora.\n"
                          "[siguiente]\ncertificado = %s\n" % cert)
    return {"huella": huella_del_certificado(cert), "nuevo": nuevo}


def rotar(ruta_ini: str, carpeta: str) -> dict:
    """El siguiente pasa a ser el de la entrada pública; el de ahora queda en ``<carpeta>/anterior`` (para volver atrás
    a mano) y se hace otro siguiente. Después, ``systemctl restart hehermes-rele-publico``. Devuelve las tres huellas.
    Los vigías y las apps que ya anclaban la huella siguiente siguen sin hacer nada; los demás, no."""
    config = ConfigPublico.leer(ruta_ini)
    siguiente = os.path.join(carpeta, "siguiente")
    if not (os.path.exists(os.path.join(siguiente, "cert.pem")) and os.path.exists(os.path.join(siguiente, "clave.pem"))):
        raise ValueError("no hay certificado siguiente en %s: primero `preparar`, y espera a que los clientes anclen "
                         "su huella" % siguiente)
    anterior = os.path.join(carpeta, "anterior")
    os.makedirs(anterior, mode=0o700, exist_ok=True)
    antes = huella_del_certificado(config.certificado)
    ahora = huella_del_certificado(os.path.join(siguiente, "cert.pem"))
    os.replace(config.clave, os.path.join(anterior, "clave.pem"))
    os.replace(config.certificado, os.path.join(anterior, "cert.pem"))
    os.replace(os.path.join(siguiente, "clave.pem"), config.clave)
    os.replace(os.path.join(siguiente, "cert.pem"), config.certificado)
    os.chmod(config.clave, 0o600)
    os.chmod(config.certificado, 0o644)
    nueva = preparar_siguiente(ruta_ini, carpeta)["huella"]
    return {"antes": antes, "ahora": ahora, "siguiente": nueva}


def sondear(puerto: int, anfitrion: str = "127.0.0.1", tls_maxima=None, plazo: float = 5.0) -> dict | None:
    """Lo que ve cualquiera que se asome sin credencial: la versión de TLS, la huella y lo que contesta a un GET. None
    si no negocia (o si no negocia con ``tls_maxima``)."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    if tls_maxima is not None:
        contexto.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        contexto.maximum_version = tls_maxima
    try:
        with socket.create_connection((anfitrion, puerto), timeout=plazo) as crudo:
            with contexto.wrap_socket(crudo) as tls:
                datos = {"tls": tls.version(), "huella": base.huella_de_der(tls.getpeercert(binary_form=True))}
                tls.sendall(b"GET /v1/salud HTTP/1.1\r\nHost: rele\r\n\r\n")
                respuesta = b""
                while len(respuesta) < 4096:
                    trozo = tls.recv(4096)
                    if not trozo:
                        break
                    respuesta += trozo
                datos["respuesta"] = respuesta
                return datos
    except (OSError, ssl.SSLError, ValueError):
        return None


def comprobar(config: ConfigPublico, salida=print) -> int:
    fallos = 0

    def decir(bien, texto):
        nonlocal fallos
        fallos += 0 if bien else 1
        salida(("bien: " if bien else "mal:  ") + texto)

    esperada = huella_del_certificado(config.certificado)
    sonda = sondear(config.puerto)
    if sonda is None:
        decir(False, "la entrada pública no contesta TLS en 127.0.0.1:%d" % config.puerto)
        return 1
    decir(sonda["tls"] == "TLSv1.3" and sondear(config.puerto, tls_maxima=ssl.TLSVersion.TLSv1_2) is None,
          "solo TLS 1.3 (negocia %s)" % sonda["tls"])
    decir(sonda["huella"] == esperada, "sirve el certificado de los códigos (huella %s)" % esperada)
    decir(sonda["respuesta"] == base.NO_ENCONTRADO, "sin credencial, el 404 de siempre, sin Server ni nada más")
    decir(bool(config.direccion), "la dirección de los códigos: %s" % (config.direccion or "ninguna"))
    if config.certificado_siguiente:
        decir(True, "la huella siguiente, para rotar sin dejar fuera a nadie: %s"
              % huella_del_certificado(config.certificado_siguiente))
    else:
        decir(True, "sin certificado siguiente (rotar el de ahora dejaría fuera a los vigías y a la app; lo pone "
                    "`preparar`)")
    return 1 if fallos else 0


# MARK: La orden


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hehermes_avisos.rele.publico",
                                     description=__doc__.splitlines()[0])
    parser.add_argument("orden", choices=("servir", "preparar", "comprobar", "rotar"))
    parser.add_argument("--config", default="/etc/hehermes-avisos/rele-publico.ini")
    parser.add_argument("--carpeta", default="/etc/hehermes-avisos/rele-publico")
    parser.add_argument("--direccion")
    parser.add_argument("--credenciales", default="/etc/hehermes-avisos/rele/credenciales.ini")
    argumentos = parser.parse_args(argv)
    os.chdir("/")
    try:
        if argumentos.orden == "preparar":
            hecho = preparar(argumentos.config, argumentos.carpeta, argumentos.direccion or None,
                             credenciales=argumentos.credenciales)
            print("entrada pública del relé: %s en el TCP %d (%s:%d), huella %s" % (
                "preparada" if hecho["nuevo"] else "ya estaba", hecho["puerto"], hecho["direccion"], hecho["puerto"],
                hecho["huella"]))
            permisos = preparar_permisos(argumentos.config, argumentos.carpeta)
            print("oficina de permisos: %s" % ("preparada" if permisos["nueva_clave"] or permisos["nueva_seccion"]
                                               else "ya estaba"))
            siguiente = preparar_siguiente(argumentos.config, argumentos.carpeta)
            print("certificado siguiente: %s, huella %s" % ("preparado" if siguiente["nuevo"] else "ya estaba",
                                                            siguiente["huella"]))
            print("PUERTO=%d" % hecho["puerto"])
            return 0
        if argumentos.orden == "rotar":
            hecho = rotar(argumentos.config, argumentos.carpeta)
            print("rotado: antes %s (en %s/anterior), ahora %s, siguiente %s. Reinicia la entrada pública: systemctl "
                  "restart hehermes-rele-publico" % (hecho["antes"], argumentos.carpeta, hecho["ahora"],
                                                    hecho["siguiente"]))
            return 0
        config = ConfigPublico.leer(argumentos.config, os.environ.get("CREDENTIALS_DIRECTORY"))
    except (ValueError, OSError) as error:
        print("error: %s" % error, flush=True)
        from ..comun import SALIDA_CONFIGURACION
        return SALIDA_CONFIGURACION if argumentos.orden == "servir" else 1
    if argumentos.orden == "comprobar":
        return comprobar(config)
    return servir(config)


if __name__ == "__main__":
    sys.exit(main())
