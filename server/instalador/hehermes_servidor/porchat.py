"""El alta por chat, del lado del instalador (spec, sección B): lo que hace `instalar --por-chat` con el Python del
sistema. El canje en sí es `canje.py`, que corre en su venv; aquí solo se decide, se prepara, se lanza y se limpia.

Por chat no hay nadie delante de un terminal: el comando lo ejecuta Hermes, y lo que imprime lo lee el modelo (y su
proveedor). Por eso no pregunta nada, no pinta el QR (la guarda de `qr` lo impide) y lo único que sale al final es la
línea del enlace, que no lleva ningún secreto.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
import time

from . import piezas as p
from .plan import registro_de_dispositivos

#: Decisión 7: por chat, solo en la media hora siguiente a instalar.
VENTANA = 30 * 60
_LLAVE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def llave_valida(texto) -> bool:
    """La clave pública X25519 de la frase: 32 bytes en base64url sin relleno, sin nada que un descodificador
    permisivo se tragara (se vuelve a codificar y tiene que dar lo mismo)."""
    if not isinstance(texto, str) or not _LLAVE.match(texto):
        return False
    try:
        datos = base64.urlsafe_b64decode(texto + "=")
    except (binascii.Error, ValueError):
        return False
    return len(datos) == 32 and base64.urlsafe_b64encode(datos).rstrip(b"=").decode() == texto


def bloqueos(sis, man, op, ahora=None) -> list:
    """Lo que impide un alta por chat (decisión 7). Una web o un correo que lea Hermes pueden llevar escondida la orden
    de dar un alta con la llave de otro: por eso solo vale para el primer iPhone, una vez, y recién instalado."""
    ahora = time.time() if ahora is None else ahora
    salida = []
    por_chat = man.datos.get("por_chat") or {}
    activos = [d for d in registro_de_dispositivos(sis)]
    otros = sorted(d["nombre"] for d in activos if d.get("nombre") != op.iphone)
    if otros:
        salida.append("Por chat solo se conecta el primer iPhone, y aquí ya hay: %s. El siguiente, desde la app o "
                      "por SSH (sudo hehermes-dispositivo alta <nombre> --ikev2)" % ", ".join(otros))
    elif any(d.get("nombre") == op.iphone for d in activos) and por_chat.get("iphone") != op.iphone:
        salida.append("«%s» ya está dado de alta y no se dio de alta por chat: por chat solo se conecta el primer "
                      "iPhone. Por SSH: sudo hehermes-dispositivo qr %s" % (op.iphone, op.iphone))
    if por_chat.get("canjeado"):
        salida.append("El alta por chat de «%s» ya se canjeó: por chat solo se conecta una vez. Otro iPhone, desde la "
                      "app o por SSH" % por_chat.get("iphone", "?"))
    if man.en_disco:
        instalado = man.datos.get("instalado")
        if not isinstance(instalado, (int, float)) or ahora - instalado > VENTANA:
            salida.append("Esta instalación es de hace más de media hora: por chat solo se da de alta en la media "
                          "hora siguiente a instalar, para que nada que lea Hermes le pueda pedir un alta nueva. Por "
                          "SSH: sudo hehermes-dispositivo alta <nombre> --ikev2")
    return salida


# MARK: --activar-api


def activar_api(sis, man, accion, salida) -> None:
    """Añade al final del .env las líneas que faltan, con una copia antes. Una que ya estuviera con otro valor
    (`API_SERVER_ENABLED=false`) se queda donde está: la de detrás es la que cuenta, en python-dotenv y en la shell."""
    from . import manifiesto as m
    ruta, lineas = accion.objeto, list(accion.datos)
    actual = sis.leer_texto(ruta)
    if actual is None:
        raise ValueError("no puedo leer %s" % ruta)
    copia = m.guardar_copia(sis, ruta)
    nuevo = actual + ("" if actual.endswith("\n") or not actual else "\n") + "".join(l + "\n" for l in lineas)
    sis.escribir(ruta, nuevo.encode("utf-8"), modo=sis.modo(ruta) or 0o600, mismo_dueno=True)
    man.datos["activar_api"] = {"env": ruta, "lineas": lineas, "copia": copia}
    man.guardar(sis)
    salida("==> la API de Hermes: %s en %s" % (", ".join(l.split("=", 1)[0] for l in lineas), ruta))


def corregir_exposicion(sis, man, accion, salida) -> None:
    """--corregir-exposicion: `API_SERVER_HOST=127.0.0.1` al final del .env (la de detrás es la que cuenta), con una copia
    antes. Desinstalar no lo quita: volvería a abrir la API a quien llegue al servidor."""
    from . import manifiesto as m
    ruta, linea = accion.objeto, accion.datos[0]
    actual = sis.leer_texto(ruta)
    if actual is None:
        raise ValueError("no puedo leer %s" % ruta)
    copia = m.guardar_copia(sis, ruta)
    nuevo = actual + ("" if actual.endswith("\n") or not actual else "\n") + linea + "\n"
    sis.escribir(ruta, nuevo.encode("utf-8"), modo=sis.modo(ruta) or 0o600, mismo_dueno=True)
    man.datos["exposicion"] = {"env": ruta, "linea": linea, "copia": copia}
    man.guardar(sis)
    salida("==> la API de Hermes: %s en %s (se cierra al reiniciarse Hermes)" % (linea, ruta))


def reiniciar_hermes_luego(sis, salida) -> None:
    """A los 90 s, y lanzado lo último: si Hermes se reiniciara antes de acabar el comando, se cortaría el turno en el
    que tiene que contestar con el enlace."""
    r = sis.ejecutar(["systemd-run", "--on-active=90", "--timer-property=AccuracySec=1s", "--collect", "--quiet",
                      "systemctl", "restart", "hermes-gateway.service"])
    if r.bien:
        salida("Hermes se reinicia dentro de 90 s para encender su API.")
    else:
        salida("No he podido programar el reinicio de Hermes: reinícialo tú (systemctl restart hermes-gateway) para "
               "que encienda su API.")


def quitar_lineas_api(sis, man, quedan, salida) -> None:
    """Desinstalar: fuera las líneas que añadió --activar-api, solo si siguen tal cual; el resto del .env, intacto."""
    datos = man.datos.get("activar_api")
    if not datos:
        return
    ruta = datos["env"]
    texto = sis.leer_texto(ruta)
    if texto is None:
        return
    lineas = texto.splitlines(True)
    for linea in reversed(datos["lineas"]):
        if not any(l.rstrip("\n") == linea for l in lineas):
            quedan.append("%s: las líneas de --activar-api han cambiado, así que no las quito (la API de Hermes sigue "
                          "encendida)" % ruta)
            return
    for linea in datos["lineas"]:
        indice = max(i for i, l in enumerate(lineas) if l.rstrip("\n") == linea)
        del lineas[indice]
    sis.escribir(ruta, "".join(lineas).encode("utf-8"), modo=sis.modo(ruta) or 0o600, mismo_dueno=True)
    salida("==> la API de Hermes: quito lo que añadí en %s (se apaga cuando reinicies Hermes)" % ruta)
    del man.datos["activar_api"]


# MARK: El canje


RUN = "/run/hehermes-canje"
UNIDAD = "hehermes-canje"
CARPETA_VENV = "/opt/hehermes-canje"
VENV = CARPETA_VENV + "/venv"
PYTHON_VENV = VENV + "/bin/python"
REQUISITOS = p.PREFIJO + "/requirements-canje.txt"
#: Daniel (2026-09-26): alto y al azar, para que no sea fácil de encontrar. Los dos extremos entran.
PUERTO_MINIMO, PUERTO_MAXIMO = 58000, 65500
#: El generador del puerto: el criptográfico del sistema. Las pruebas lo sustituyen para fijarlo.
_azar = secrets.randbelow
COMENTARIO_UFW = "hehermes-canje"
LIMPIAR = "/usr/bin/python3 -I -B %s/hehermes-servidor canje-limpiar" % p.PREFIJO


class ParadaDelCanje(Exception):
    """El canje no se ha podido lanzar. Lo que se había preparado ya está borrado."""


def enlace(direccion: str, puerto: int, codigo: str, huella: str) -> str:
    """Lo único que sale por el chat. Ni la PSK ni nada que sirva sin la clave privada del iPhone."""
    return "hehermes-canje:1?h=%s&p=%d&c=%s&f=%s" % (direccion, puerto, codigo, huella)


def leer_psk(texto: str) -> str:
    """El `secret` del fichero de swanctl del iPhone, como lo escribe `hehermes-dispositivo` (entre comillas)."""
    for linea in texto.splitlines():
        hallado = re.match(r'^\s*secret\s*=\s*"([^"]+)"\s*$', linea)
        if hallado:
            return hallado.group(1)
    raise ValueError("no hay ningún secret entre comillas")


def lanzar(sis, man, det, op, salida) -> str:
    """Prepara y lanza el canje del iPhone de `op.iphone`. Devuelve el enlace; no lo imprime (va el último)."""
    import json
    import secrets as azar

    parar(sis)
    limpiar_restos(sis)
    _venv(sis, man, salida)
    try:
        sis.carpeta(RUN, 0o700)
        r = sis.ejecutar([PYTHON_VENV, "-I", "-B", "-m", "hehermes_servidor.canje", "preparar", RUN])
        if not r.bien:
            raise ParadaDelCanje("no he podido crear el certificado del canje: %s" % (r.error or r.salida).strip())
        huella = json.loads(r.salida)["huella"]
        registro = next(d for d in registro_de_dispositivos(sis) if d.get("nombre") == op.iphone)
        servidor = registro.get("servidor") or det.direccion
        texto = sis.leer_texto("%s/conf.d/hehermes-%s.conf" % (det.swanctl, op.iphone))
        try:
            psk = leer_psk(texto or "")
        except ValueError:
            raise ParadaDelCanje("no encuentro la clave de «%s» en su conexión de strongSwan" % op.iphone) from None
        puerto = _puerto_libre(sis)
        codigo = base64.urlsafe_b64encode(azar.token_bytes(16)).rstrip(b"=").decode()
        datos = {"llave": op.llave, "codigo": codigo, "huella": huella, "puerto": puerto, "direccion": "",
                 "carga": {"h": servidor, "rid": servidor, "lid": op.iphone, "k": psk}}
        sis.escribir(RUN + "/canje.json", json.dumps(datos).encode(), modo=0o600)
        del datos, psk
        regla, cortafuegos = None, None
        if det.ufw == "activo":
            regla, cortafuegos = ["allow", "proto", "tcp", "from", "any", "to", "any", "port", str(puerto), "comment",
                                  COMENTARIO_UFW], "ufw"
            r = sis.ejecutar(["ufw"] + regla)
            if not r.bien:
                raise ParadaDelCanje("ufw no ha abierto el TCP %d: %s" % (puerto, (r.error or r.salida).strip()))
        elif det.firewalld == "activo":
            # Solo en la configuración de ahora, nunca en la permanente: no sobrevive ni a un reinicio. Si el puerto
            # ya estaba abierto, es de otro, y ni se abre ni se cierra.
            opcion = "--add-port=%d/tcp" % puerto
            if not sis.ejecutar(["firewall-cmd", opcion.replace("--add-", "--query-", 1)]).bien:
                r = sis.ejecutar(["firewall-cmd", opcion])
                if not r.bien:
                    raise ParadaDelCanje("firewalld no ha abierto el TCP %d: %s" % (puerto,
                                                                                 (r.error or r.salida).strip()))
                regla, cortafuegos = [opcion], "firewalld"
        propio = False
        if det.lugares:
            # nftables o iptables a pelo: en las mismas cadenas que las de siempre, con su propia marca.
            from . import cortafuegos as cf
            try:
                cf.poner(sis, cf.MARCA_CANJE, cf.del_canje(puerto), det.con_iptables)
            except cf.NoSe as error:
                raise ParadaDelCanje("no he podido abrir el TCP %d en tu cortafuegos: %s" % (puerto, error)) from None
            propio = True
        sis.escribir(RUN + "/estado.json", json.dumps({"puerto": puerto, "regla": regla, "cortafuegos": cortafuegos,
                                                       "propio": propio, "con_iptables": det.con_iptables}).encode(),
                     modo=0o600)
        r = sis.ejecutar(_systemd_run())
        if not r.bien or not sis.ejecutar(["systemctl", "is-active", UNIDAD]).bien:
            raise ParadaDelCanje("el canje no ha arrancado (%s). Mira «journalctl -u %s»"
                                 % ((r.error or r.salida).strip() or "se ha parado nada más empezar", UNIDAD))
    except ParadaDelCanje:
        limpiar(sis, {})
        raise
    abierto_en = ([cortafuegos] if regla else []) + (["tu nftables o iptables"] if propio else [])
    salida("==> el canje: abierto 10 minutos en el TCP %d%s" % (
        puerto, " (y en %s, solo mientras dure)" % " y ".join(abierto_en) if abierto_en else ""))
    if det.cortafuegos_a_mano:
        salida("    Tu cortafuegos lo llevas tú: ábrele ahora el TCP %d, solo mientras dure el canje" % puerto)
    salida("    Si tu proveedor tiene un cortafuegos propio, el TCP %d tiene que estar abierto ahí" % puerto)
    el_enlace = enlace(servidor, puerto, codigo, huella)
    if op.qr_png:
        salida(_qr_png(sis, op.qr_png, el_enlace))
    return el_enlace


def _qr_png(sis, ruta, el_enlace) -> str:
    """El PNG se hace en /run (de root) y se deja en `ruta` como lo haría quien lanzó sudo: con la línea de sudoers de
    la salida 2, `--qr-png /etc/…` no puede pisar ni crear nada que su usuario no pudiera. Nunca sobre algo que ya
    exista, ni a través de un enlace."""
    import os
    if not ruta.startswith("/"):
        return "No dejo el QR en %s: dame una ruta absoluta" % ruta
    temporal = RUN + "/qr.png"
    r = sis.ejecutar(["qrencode", "-t", "PNG", "-o", temporal], entrada=el_enlace)
    datos = sis.leer(temporal) if r.bien else None
    if sis.existe(temporal):
        sis.borrar(temporal)
    if datos is None:
        return "No he podido hacer el QR del enlace"
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    try:
        sis.crear_nuevo(ruta, datos, int(uid) if uid and uid.isdigit() else None,
                        int(gid) if gid and gid.isdigit() else None)
    except OSError as error:
        return "No he podido dejar el QR en %s (%s)" % (ruta, error.strerror or error)
    return "==> el QR del enlace, en %s" % ruta


def _systemd_run() -> list:
    """Una unidad temporal, para que el canje sobreviva al comando de Hermes; un usuario de usar y tirar, que no ve más
    que sus credenciales (copiadas por systemd desde /run, en memoria); y la limpieza como root al pararse por lo que
    sea: canjeado, caducado, por los intentos, por `RuntimeMaxSec` o a mano."""
    propiedades = [
        "Description=HeHermes: el canje del alta por chat (10 minutos, un solo uso)",
        "DynamicUser=yes",
        "LoadCredential=canje:%s/canje.json" % RUN,
        "LoadCredential=cert:%s/cert.pem" % RUN,
        "LoadCredential=clave:%s/clave.pem" % RUN,
        # Un puerto alto no pide ninguna capacidad: el canje corre sin ninguna (el vacío deja el conjunto vacío).
        "CapabilityBoundingSet=",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "RestrictNamespaces=yes",
        "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
        "UMask=0077",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        # Diez minutos del canje y un margen: si algo se cuelga, systemd lo para igual.
        "RuntimeMaxSec=660",
        "ExecStopPost=+" + LIMPIAR,
    ]
    orden = ["systemd-run", "--unit=" + UNIDAD, "--collect", "--quiet"]
    for propiedad in propiedades:
        orden += ["-p", propiedad]
    return orden + [PYTHON_VENV, "-I", "-B", "-m", "hehermes_servidor.canje", "servir"]


def elegir_puerto(ocupados, azar=None) -> int | None:
    """Uno libre del rango, empezando por uno al azar y dando la vuelta: si el primero está ocupado, el siguiente libre.
    `None` si no queda ninguno."""
    azar = azar or _azar
    total = PUERTO_MAXIMO - PUERTO_MINIMO + 1
    inicio = azar(total)
    for paso in range(total):
        puerto = PUERTO_MINIMO + (inicio + paso) % total
        if puerto not in ocupados:
            return puerto
    return None


def _puertos_tcp_ocupados(sis) -> set:
    """Todos los puertos TCP locales en uso, escuchen o no: uno de una conexión de salida tampoco se puede atar."""
    ocupados = set()
    for linea in sis.ejecutar(["ss", "-H", "-tan"]).salida.splitlines():
        campos = linea.split()
        if len(campos) >= 4 and campos[3].rsplit(":", 1)[-1].isdigit():
            ocupados.add(int(campos[3].rsplit(":", 1)[-1]))
    return ocupados


def _puerto_libre(sis) -> int:
    puerto = elegir_puerto(_puertos_tcp_ocupados(sis))
    if puerto is None:
        raise ParadaDelCanje("no hay ningún puerto libre para el canje entre el %d y el %d"
                             % (PUERTO_MINIMO, PUERTO_MAXIMO))
    return puerto


def _venv(sis, man, salida):
    """El venv del canje, con `cryptography` fijada por hash y el código del instalador por un `.pth` (con -I no vale
    PYTHONPATH). Si ya está y funciona, no se toca."""
    comprobar = [PYTHON_VENV, "-I", "-B", "-c", "import cryptography, hehermes_servidor.canje"]
    if sis.existe(PYTHON_VENV) and sis.ejecutar(comprobar).bien:
        return
    salida("==> el entorno de Python del canje (%s)" % VENV)
    man.datos["venv_canje"] = VENV
    man.guardar(sis)
    pasos = ([] if sis.existe(PYTHON_VENV) else [["python3", "-I", "-m", "venv", VENV]]) + [
        [PYTHON_VENV, "-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--quiet",
         "--only-binary=:all:", "--require-hashes", "-r", REQUISITOS]]
    for paso in pasos:
        r = sis.ejecutar(paso)
        if not r.bien:
            raise ParadaDelCanje("el entorno del canje ha fallado (%s): %s" % (paso[2 if paso[0] == "python3" else 3],
                                                                             (r.error or r.salida).strip()[-400:]))
    r = sis.ejecutar([PYTHON_VENV, "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"])
    sis.escribir(r.salida.strip() + "/hehermes-servidor.pth", (p.PREFIJO + "\n").encode())
    if not sis.ejecutar(comprobar).bien:
        raise ParadaDelCanje("el entorno del canje no importa cryptography")


def parar(sis) -> None:
    """Un canje anterior se para antes de lanzar otro: `systemctl stop` espera a su limpieza (`ExecStopPost`)."""
    if sis.ejecutar(["systemctl", "is-active", UNIDAD]).bien:
        sis.ejecutar(["systemctl", "stop", UNIDAD])


def limpiar_restos(sis) -> None:
    """Lo que un canje pudo dejar sin su limpieza: tras un reinicio, /run ya está vacío, pero la regla de ufw no. Solo
    con el canje parado."""
    if sis.ejecutar(["systemctl", "is-active", UNIDAD]).bien:
        return
    _barrer(sis)


def volver_a_abrir(sis, propio_de_la_instalacion=None) -> None:
    """Si el cortafuegos del sistema se recarga (y vacía sus cadenas) con un canje abierto, la regla del canje se va
    con él: `hehermes-cortafuegos` la vuelve a poner, mientras el canje siga en marcha."""
    import json
    if not sis.ejecutar(["systemctl", "is-active", UNIDAD]).bien:
        return
    try:
        estado = json.loads(sis.leer_texto(RUN + "/estado.json") or "{}")
    except ValueError:
        return
    if estado.get("propio") and estado.get("puerto"):
        from . import cortafuegos as cf
        cf.poner(sis, cf.MARCA_CANJE, cf.del_canje(int(estado["puerto"])), estado.get("con_iptables", True))


def _barrer(sis):
    import shlex
    from . import cortafuegos as cf
    cf.quitar(sis, cf.MARCA_CANJE)
    if sis.cual("ufw"):
        for linea in sis.ejecutar(["ufw", "show", "added"]).salida.splitlines():
            linea = linea.strip()
            if linea.startswith("ufw ") and COMENTARIO_UFW in linea:
                sis.ejecutar(["ufw", "delete"] + shlex.split(linea)[1:])
    if sis.existe(RUN):
        sis.borrar_arbol(RUN)


def limpiar(sis, entorno) -> None:
    """`ExecStopPost`: la regla de ufw fuera, /run/hehermes-canje fuera, y si el canje salió con 0 por sí mismo (se
    canjeó), apuntado: por chat no se da de alta nada más (decisión 7)."""
    import json
    try:
        estado = json.loads(sis.leer_texto(RUN + "/estado.json") or "{}")
    except ValueError:
        estado = {}
    if estado.get("regla") and estado.get("cortafuegos") == "firewalld":
        sis.ejecutar(["firewall-cmd", estado["regla"][0].replace("--add-", "--remove-", 1)])
    elif estado.get("regla"):
        sis.ejecutar(["ufw", "delete"] + estado["regla"])
    _barrer(sis)
    canjeado = (entorno.get("SERVICE_RESULT") == "success" and entorno.get("EXIT_CODE") == "exited"
                and entorno.get("EXIT_STATUS") == "0")
    if canjeado:
        from .manifiesto import Manifiesto
        man = Manifiesto.leer(sis)
        man.datos.setdefault("por_chat", {})["canjeado"] = time.time()
        man.guardar(sis)
