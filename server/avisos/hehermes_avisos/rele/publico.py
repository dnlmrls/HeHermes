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

Lo que pasa, lo reenvía tal cual al relé, **con la misma credencial**: el relé la vuelve a comprobar, aplica sus
límites por credencial y por token y apunta el nombre de la credencial en cada aviso. La entrada no tiene la clave .p8
ni la puede leer: corre como ``hh-rele-publico``, que solo está en el grupo de ``credenciales.ini``.

El «código de avisos» (``codigo``) es lo que se le da al dueño del otro servidor: la dirección, el puerto, la huella y
la credencial, en una línea ``hehermes-avisos:1?h=…&p=…&f=…&c=…``. Lleva la credencial, así que es secreto: se pinta
solo en un terminal, o se deja en un fichero 0600.

``python -m hehermes_avisos.rele.publico``:

- ``servir --config RUTA``: lo que arranca ``hehermes-rele-publico.service``.
- ``preparar --config RUTA --carpeta CARPETA [--direccion D]``: la primera vez, elige el puerto y hace el certificado
  (con el venv, que tiene ``cryptography``). Después no toca nada: el puerto y la huella son para siempre.
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
        except (OSError, configparser.Error, ValueError) as error:
            raise ValueError("%s: %s" % (ruta, error)) from None
        if credenciales_systemd and os.path.exists(os.path.join(credenciales_systemd, "clave")):
            c.clave = os.path.join(credenciales_systemd, "clave")
        return c


def _absoluta(ruta: str) -> str:
    ruta = ruta.strip()
    if not ruta.startswith("/"):
        raise ValueError("ruta no absoluta: %s" % ruta)
    return ruta


# MARK: El servidor


class FrenteDelRele(base.Pasarela):
    """La pasarela, con las credenciales de los vigías y un solo destino: el relé, con la misma credencial."""

    nombre = "entrada pública del relé"

    def __init__(self, config: ConfigPublico, credenciales: Almacen, **opciones):
        super().__init__(config, tokens=credenciales, **opciones)

    def tope(self, peticion) -> int:
        return TOPE

    def destino(self, peticion, ip):
        # Aquí ya se sabe que trae una sola cabecera Authorization, y que es una credencial dada de alta: va tal cual,
        # y el relé la vuelve a comprobar (y apunta su nombre, y la limita).
        return self.config.rele, [("Authorization", peticion.valores("authorization")[0])], "rele_no_contesta"


def servir(config: ConfigPublico, tls_minimo=None) -> int:
    try:
        frente = FrenteDelRele(config, Almacen(config.credenciales), tls_minimo=tls_minimo)
    except (OSError, ssl.SSLError, ValueError) as error:
        print("error: %s" % error, flush=True)
        return 1
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
    return 1 if fallos else 0


# MARK: La orden


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hehermes_avisos.rele.publico",
                                     description=__doc__.splitlines()[0])
    parser.add_argument("orden", choices=("servir", "preparar", "comprobar"))
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
            print("PUERTO=%d" % hecho["puerto"])
            return 0
        config = ConfigPublico.leer(argumentos.config, os.environ.get("CREDENTIALS_DIRECTORY"))
    except (ValueError, OSError) as error:
        print("error: %s" % error, flush=True)
        return 1
    if argumentos.orden == "comprobar":
        return comprobar(config)
    return servir(config)


if __name__ == "__main__":
    sys.exit(main())
