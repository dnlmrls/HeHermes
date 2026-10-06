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
from .plan import etiquetar, registro_de_dispositivos

# Decisión 7 (Daniel, 2026-10-01): el alta por chat sigue abierta hasta que el iPhone que se dio de alta por chat usa
# la pasarela (un 2xx con su token, que apunta la pasarela en `usos.json`); desde entonces, los demás por SSH o desde la
# app. Hasta la 0.10.3 era «solo en la media hora siguiente a instalar» (`VENTANA`, 30 minutos), y un probador cuya
# única petición dio un 502 (Hermes reiniciándose) se quedó sin salida por chat.
_LLAVE = re.compile(r"^[A-Za-z0-9_-]{43}$")
#: Una línea del diario de la pasarela de una petición con token que Hermes (o ella) contestó con un 2xx:
#: «<ip> <método> <estado> <bytes>» (lo que apunta `Pasarela._ida_y_vuelta`, igual desde la 0.5.0).
_LINEA_2XX = re.compile(r"\S+ [A-Z]+ 2\d\d \d+")


def llave_valida(texto) -> bool:
    """La clave pública X25519 de la frase: 32 bytes en base64url sin relleno, sin nada que un descodificador
    permisivo se tragara (se vuelve a codificar y tiene que dar lo mismo)."""
    if not isinstance(texto, str) or not _LLAVE.fullmatch(texto):
        return False
    try:
        datos = base64.urlsafe_b64decode(texto + "=")
    except (binascii.Error, ValueError):
        return False
    return len(datos) == 32 and base64.urlsafe_b64encode(datos).rstrip(b"=").decode() == texto


def activos_del_servidor(sis, man, ambito=None) -> list:
    """Los iPhone del servidor: los de la pasarela y, si queda la VPN de antes de la 0.6.0, sus altas. «El primer
    iPhone» es el primero del servidor, no el de la pasarela: si no, con una VPN dada por chat, un correo que leyera
    Hermes podría pedir otra alta por la pasarela."""
    from . import ambito as amb
    from .modo_tls import nombres_de_la_pasarela
    ambito = ambito or amb.de_root()
    lista = list(registro_de_dispositivos(sis)) if "vpn" in man.modos and ambito.root else []
    return lista + [{"nombre": n} for n in nombres_de_la_pasarela(sis, ambito)]


def leer_usos(sis, ambito) -> dict | None:
    """El registro de usos de la pasarela (`pasarela.USOS`, desde la 0.10.4), o None si no lo hay o no se entiende."""
    from .pasarela import TOPE_USOS, USOS, leer_usos as leer
    datos = sis.leer(ambito.carpeta_estado_pasarela + "/" + USOS)
    return leer(datos[:TOPE_USOS]) if datos is not None else None


def _diario_sin_2xx(sis, ambito, desde) -> bool | None:
    """Lo que dice el diario de la pasarela desde `desde`: True si llega hasta antes de entonces y no hay ningún 2xx con
    token (nadie la ha usado), False si lo hay, None si no se sabe (sin diario, o uno que no llega tan atrás: el de un
    servidor que lo guarda solo en memoria y se ha reiniciado). journald borra lo más viejo primero, así que una entrada
    de antes de `desde` dice que está todo lo de después."""
    base = ["journalctl"] + ([] if ambito.root else ["--user"]) + ["-u", p.UNIDAD_PASARELA, "--no-pager", "-q"]
    r = sis.ejecutar(base + ["-o", "short-unix", "--until", "@%d" % int(desde), "-n", "1"])
    if not r.bien or not r.salida.strip():
        return None
    r = sis.ejecutar(base + ["-o", "cat", "--since", "@%d" % int(desde)])
    if not r.bien:
        return None
    return not any(_LINEA_2XX.fullmatch(linea.strip()) for linea in r.salida.splitlines())


def uso_del_iphone_por_chat(sis, man, ambito) -> tuple:
    """Si el iPhone que se dio de alta por chat (`por_chat` del manifiesto) ha usado la pasarela desde entonces:
    ("sin-usar", None), ("usado", cuándo o None) o ("no-se", por qué). Sin alta por chat, ("sin-usar", None).

    Lo apunta la pasarela (`usos.json`): un uso de su nombre desde su alta. Si el registro empezó después del alta (una
    pasarela de antes de la 0.10.4, como la del probador de la 0.10.2), lo que falta lo dice su diario. Si tampoco
    llega, no se sabe, y no se sabe es «usado»: no se reabre a ciegas."""
    por_chat = man.datos.get("por_chat") or {}
    nombre = por_chat.get("iphone")
    if not nombre:
        return "sin-usar", None
    # Desde cuándo cuenta un uso: su alta (o, en un manifiesto que no la tenga, la instalación, que es de antes).
    alta = next((int(t) for t in (por_chat.get("alta"), man.datos.get("instalado"))
                 if isinstance(t, (int, float)) and not isinstance(t, bool)), None)
    usos = leer_usos(sis, ambito)
    if usos is not None:
        primeros = [e["primero"] for e in usos["tokens"].values()
                    if e["nombre"] == nombre and (alta is None or e["primero"] >= alta)]
        if primeros:
            return "usado", min(primeros)
        if alta is not None and usos["desde"] <= alta:
            return "sin-usar", None
    if alta is None:
        return "no-se", "no sé cuándo se dio de alta"
    diario = _diario_sin_2xx(sis, ambito, alta)
    if diario is True:
        return "sin-usar", None
    if diario is False:
        return "usado", None
    return "no-se", ("la pasarela no apuntaba entonces quién la usa y su diario no llega hasta el alta")


def bloqueos(sis, man, op, activos=None, ambito=None) -> list:
    """Lo que impide un alta por chat (decisión 7, Daniel, 2026-10-01). Una web o un correo que lea Hermes pueden llevar
    escondida la orden de dar un alta con la llave de otro: por eso el chat se cierra en cuanto el iPhone que se dio de
    alta por chat usa la pasarela (un 2xx con su token), y desde entonces los demás van por SSH o desde la app. Mientras
    no la ha usado (se canjeara o no), la misma frase vuelve a dar un enlace: al mismo iPhone, con otra clave (la de antes
    deja de valer, `reemitir`); y a otro nombre, en su lugar (`a_sustituir`): la app cambia de nombre si se reinstala, y
    la de la 0.10.2 se llamaba «mi-iphone». Un iPhone dado de alta por SSH sigue cerrando el chat, como siempre.
    `activos`, los iPhone del servidor (`activos_del_servidor`)."""
    from . import ambito as amb
    ambito = ambito or amb.de_root()
    salida = []
    por_chat = man.datos.get("por_chat") or {}
    de_chat = por_chat.get("iphone")
    activos = list(activos or [])
    estado, cuando = uso_del_iphone_por_chat(sis, man, ambito)
    alta = "hehermes-dispositivo alta <nombre>"
    if estado != "sin-usar":
        if estado == "usado":
            fecha = "" if cuando is None else " (%s UTC)" % time.strftime("%Y-%m-%d %H:%M", time.gmtime(cuando))
            texto = "«%s» se dio de alta por chat y ya ha usado la pasarela%s" % (de_chat, fecha)
        else:
            texto = "«%s» se dio de alta por chat y no sé si ha llegado a usar la pasarela (%s)" % (de_chat, cuando)
        salida.append("%s: por chat ya no doy de alta nada más, para que nada que lea Hermes le pueda pedir un alta "
                      "nueva. Este iPhone (o uno nuevo), desde la app o por SSH: %s, o hehermes-dispositivo rotar %s"
                      % (texto, alta, de_chat))
        etiquetar(salida, "por-chat")
        return salida
    otros = sorted(d["nombre"] for d in activos if d.get("nombre") not in (op.iphone, de_chat))
    if otros:
        salida.append("Por chat solo se conecta el primer iPhone, y aquí ya hay: %s. El siguiente, desde la app o "
                      "por SSH (%s)" % (", ".join(otros), alta))
        etiquetar(salida, "por-chat")
    elif any(d.get("nombre") == op.iphone for d in activos) and de_chat != op.iphone:
        salida.append("«%s» ya está dado de alta y no se dio de alta por chat: por chat solo se conecta el primer "
                      "iPhone. Por SSH: hehermes-dispositivo rotar %s" % (op.iphone, op.iphone))
        etiquetar(salida, "por-chat")
    return salida


def a_sustituir(man, op, activos) -> str | None:
    """El iPhone que se dio de alta por chat y no ha usado la pasarela, si la frase es de otro nombre: el que sale para
    que entre este (`bloqueos` ya ha mirado que no la ha usado)."""
    de_chat = (man.datos.get("por_chat") or {}).get("iphone")
    if op.por_chat and de_chat and de_chat != op.iphone and any(d.get("nombre") == de_chat for d in activos):
        return de_chat
    return None


def reemitir(sis, man, iphone, ruta_tokens, salida) -> str:
    """Otra alta por chat para un iPhone que ya la tenía y no ha usado la pasarela (repetida antes de canjearse, o ya
    canjeada): del token solo queda su hash, así que va uno nuevo, y el de antes deja de valer en ese momento
    (`tokens.rotar`). Lo canjeado se olvida (el canje nuevo lo vuelve a apuntar al acabar, `limpiar`), y el alta es de
    ahora: un uso cuenta desde ella. Devuelve el token."""
    from . import tokens
    anterior = man.datos.get("por_chat") or {}
    token = tokens.rotar(ruta_tokens, iphone)
    man.datos["por_chat"] = {"iphone": iphone, "alta": time.time()}
    man.guardar(sis)
    if anterior.get("canjeado"):
        salida("==> «%s» ya se había conectado por chat: le doy una clave nueva, y la de antes deja de valer" % iphone)
    return token


# MARK: --activar-api


def _anadir_al_env(sis, ruta, lineas, ambito=None) -> dict:
    """Añade `lineas` al final del .env de Hermes, con una copia antes. Devuelve la copia."""
    from . import manifiesto as m
    actual = sis.leer_texto(ruta)
    if actual is None:
        raise ValueError("no puedo leer %s" % ruta)
    copia = m.guardar_copia(sis, ruta, None if ambito is None or ambito.root else ambito.carpeta_config)
    nuevo = actual + ("" if actual.endswith("\n") or not actual else "\n") + "".join(l + "\n" for l in lineas)
    sis.escribir(ruta, nuevo.encode("utf-8"), modo=sis.modo(ruta) or 0o600, mismo_dueno=True)
    return copia


def activar_api(sis, man, accion, salida, ambito=None) -> None:
    """Añade al final del .env las líneas que faltan, con una copia antes. Una que ya estuviera con otro valor
    (`API_SERVER_ENABLED=false`) se queda donde está: la de detrás es la que cuenta, en python-dotenv y en la shell."""
    ruta, lineas = accion.objeto, list(accion.datos)
    copia = _anadir_al_env(sis, ruta, lineas, ambito)
    man.datos["activar_api"] = {"env": ruta, "lineas": lineas, "copia": copia}
    man.guardar(sis)
    salida("==> la API de Hermes: %s en %s" % (", ".join(l.split("=", 1)[0] for l in lineas), ruta))


#: Lo que queda apuntado de un --activar-api que se paró para que se reiniciara Hermes a mano (`reinicia-hermes`): sin
#: instalación todavía no hay manifiesto, y uno a medias se leería como una instalación. La siguiente pasada lo pasa al
#: manifiesto (`adoptar_api_pendiente`), para que desinstalar quite esas líneas.
API_PENDIENTE = "api-pendiente.json"


def encender_para_reiniciar_a_mano(sis, det, plan, ambito, salida, por_chat=False) -> None:
    """`reinicia-hermes`: Hermes no lo lleva nada que se sepa reiniciar, así que se añaden al .env las líneas de la API
    (con una copia antes), se apunta y se para. Lo único que se toca: el .env (y su copia)."""
    import json
    accion = next((a for a in plan.acciones if a.tipo == "env"), None)
    if accion is None:
        raise ValueError("no sé qué añadir a su .env")
    ruta, lineas = accion.objeto, list(accion.datos)
    copia = _anadir_al_env(sis, ruta, lineas, ambito)
    sis.escribir(ambito.carpeta_config + "/" + API_PENDIENTE,
                 json.dumps({"env": ruta, "lineas": lineas, "copia": copia}).encode("utf-8"), modo=0o600)
    salida("==> la API de Hermes: %s en %s" % (", ".join(l.split("=", 1)[0] for l in lineas), ruta))
    salida("\nHe encendido la API en %s; reinicia Hermes y vuelve a %s." % (
        ruta, "mandarme la misma frase" if por_chat else "lanzar el mismo comando"))


def adoptar_api_pendiente(sis, man, ambito) -> None:
    """Lo que dejó apuntado `encender_para_reiniciar_a_mano`, al manifiesto (si no hay ya un --activar-api suyo)."""
    import json
    ruta = ambito.carpeta_config + "/" + API_PENDIENTE
    texto = sis.leer_texto(ruta)
    if texto is None:
        return
    try:
        datos = json.loads(texto)
    except ValueError:
        datos = None
    if isinstance(datos, dict) and isinstance(datos.get("env"), str) and isinstance(datos.get("lineas"), list) \
            and "activar_api" not in man.datos:
        man.datos["activar_api"] = {"env": datos["env"], "lineas": [str(l) for l in datos["lineas"]],
                                    "copia": datos.get("copia")}
        man.guardar(sis)
    sis.borrar(ruta)


def corregir_exposicion(sis, man, accion, salida, ambito=None) -> None:
    """--corregir-exposicion: `API_SERVER_HOST=127.0.0.1` al final del .env (la de detrás es la que cuenta), con una copia
    antes. Desinstalar no lo quita: volvería a abrir la API a quien llegue al servidor."""
    from . import manifiesto as m
    ruta, linea = accion.objeto, accion.datos[0]
    actual = sis.leer_texto(ruta)
    if actual is None:
        raise ValueError("no puedo leer %s" % ruta)
    copia = m.guardar_copia(sis, ruta, None if ambito is None or ambito.root else ambito.carpeta_config)
    nuevo = actual + ("" if actual.endswith("\n") or not actual else "\n") + linea + "\n"
    sis.escribir(ruta, nuevo.encode("utf-8"), modo=sis.modo(ruta) or 0o600, mismo_dueno=True)
    man.datos["exposicion"] = {"env": ruta, "linea": linea, "copia": copia}
    man.guardar(sis)
    salida("==> la API de Hermes: %s en %s (se cierra al reiniciarse Hermes)" % (linea, ruta))


def reiniciar_hermes(sis, salida, gestor=None, ambito=None) -> bool:
    """Lo último, para que lea lo nuevo de su .env (encender su API, o cerrarla a 127.0.0.1). Lo que se reinicia es lo
    que lleva su proceso (`gestor`): su unidad, se llame como se llame y sea del sistema o de usuario, o su contenedor.

    Desde la 0.11.1, con la unidad de `hermes gateway install` (`gestor.recarga_con_drenaje`), `systemctl reload` ya:
    Hermes deja de aceptar turnos, espera a que acabe el que tiene (por chat, el que contesta con el enlace) y se
    reinicia solo. Si no (una unidad hecha a mano, un contenedor) o la recarga falla, `restart` a los 90 s, en una unidad
    pasajera de systemd que sigue aunque el instalador ya haya acabado: antes cortaría ese turno. Devuelve si ha quedado
    programado (si no, lo ha dicho)."""
    from . import gestor as gestores
    gestor = gestor or gestores.Gestor("sistema", "hermes-gateway.service")
    root = ambito is None or ambito.root
    if gestores.recarga_con_drenaje(sis, gestor, root):
        r = sis.ejecutar(gestores.orden_recargar(gestor, root), plazo=60)
        if r.bien:
            salida("Hermes se reinicia en cuanto acabe lo que está haciendo (systemctl reload: su reinicio con drenaje, "
                   "que no le corta el turno), para leer lo nuevo de su .env.")
            return True
        salida("    La recarga de Hermes (systemctl reload) ha fallado (%s): lo reinicio a los 90 s"
               % ((r.error or r.salida).strip()[-160:] or r.codigo))
    r = sis.ejecutar(gestores.orden_reiniciar_luego(gestor, root), plazo=60)
    if r.bien:
        salida("Hermes se reinicia dentro de 90 s, para leer lo nuevo de su .env.")
        return True
    salida("No he podido programar el reinicio de Hermes: reinícialo tú (/restart en su chat, o %s) para que lea lo "
           "nuevo de su .env." % gestores.como_se_reinicia(gestor, root))
    return False


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
#: Lo que dura el canje desde que arranca (el `DURACION` de `canje.py`, que se ejecuta con el venv y no se importa aquí;
#: `test_canje_limites` los ata). La frase y el enlace prometen diez minutos, y se dan doce: el enlace sale después de
#: arrancar el canje y todavía tiene que llegar al chat en la respuesta de Hermes. No depende de Hermes: el canje es su
#: propia unidad (`_systemd_run`), y el reinicio de Hermes que programa `--activar-api` a los 90 s no lo toca.
DURACION_CANJE = 12 * 60
#: `RuntimeMaxSec`: la duración y un minuto de margen, por si algo se cuelga; systemd lo para igual.
TOPE_DE_LA_UNIDAD = DURACION_CANJE + 60
LIMPIAR = "/usr/bin/python3 -I -B %s/hehermes-servidor canje-limpiar" % p.PREFIJO


#: pip: sus propios reintentos y su plazo por conexión (de serie, 5 y 15 s), y lo más que espera cada intento entero.
PIP_RED = ["--retries", "5", "--timeout", "20"]
PLAZO_PIP = 600
PLAZO_VENV = 300


class ParadaDelCanje(Exception):
    """El canje no se ha podido lanzar (lo que se había preparado ya está borrado), o su entorno de Python no se ha
    podido hacer. `codigo`, el que dice por chat (`marcha`)."""

    def __init__(self, mensaje="", codigo="a-medias"):
        super().__init__(mensaje)
        self.codigo = codigo


def enlace(direccion: str, puerto: int, codigo: str, huella: str) -> str:
    """Lo único que sale por el chat. Ni el token ni nada que sirva sin la clave privada del iPhone."""
    return "hehermes-canje:1?h=%s&p=%d&c=%s&f=%s" % (direccion, puerto, codigo, huella)


def carga_tls(direccion: str, puerto: int, huella: str, token: str) -> dict:
    """Lo que entrega el canje en modo TLS (server/API-CONTRACT.md, §12.2): en este orden, y `p` como número."""
    from .tokens import texto_qr
    texto_qr(direccion, puerto, huella, token)  # la misma validación que el QR
    return {"h": direccion, "p": puerto, "f": huella, "t": token}


def lanzar(sis, man, det, op, salida, carga, ambito=None) -> str:
    """Prepara y lanza el canje del iPhone de `op.iphone`, que entrega `carga` (`carga_tls`: lo único que entrega desde
    la 0.6.0). Devuelve el enlace; no lo imprime (va el último). Sin root (`ambito` de un usuario), el canje es una
    unidad de usuario y no se toca el cortafuegos."""
    import json
    import secrets as azar
    from . import ambito as amb

    ambito = ambito or amb.de_root()
    run = ambito.run_canje
    python = ambito.python_venv
    parar(sis, ambito)
    limpiar_restos(sis, ambito)
    _venv(sis, man, salida, ambito)
    regla, cortafuegos, propio = None, None, False
    try:
        sis.carpeta(run, 0o700)
        r = sis.ejecutar([python, "-I", "-B", "-m", "hehermes_servidor.canje", "preparar", run])
        if not r.bien:
            raise ParadaDelCanje("no he podido crear el certificado del canje: %s" % (r.error or r.salida).strip())
        huella = json.loads(r.salida)["huella"]
        servidor = carga["h"]
        puerto = _puerto_libre(sis)
        codigo = base64.urlsafe_b64encode(azar.token_bytes(16)).rstrip(b"=").decode()
        datos = {"llave": op.llave, "codigo": codigo, "huella": huella, "puerto": puerto, "direccion": "",
                 "carga": carga}
        sis.escribir(run + "/canje.json", json.dumps(datos).encode(), modo=0o600)
        del datos, carga
        if not ambito.root:
            pass  # sin root no se toca el cortafuegos: se dice qué abrir
        elif det.ufw == "activo":
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
        if ambito.root and det.lugares:
            # nftables o iptables a pelo: en las mismas cadenas que las de siempre, con su propia marca.
            from . import cortafuegos as cf
            try:
                cf.poner(sis, cf.MARCA_CANJE, cf.del_canje(puerto), det.con_iptables)
            except cf.NoSe as error:
                raise ParadaDelCanje("no he podido abrir el TCP %d en tu cortafuegos: %s" % (puerto, error)) from None
            propio = True
        sis.escribir(run + "/estado.json", json.dumps({"puerto": puerto, "regla": regla, "cortafuegos": cortafuegos,
                                                       "propio": propio, "con_iptables": det.con_iptables}).encode(),
                     modo=0o600)
        r = sis.ejecutar(_systemd_run() if ambito.root else _systemd_run_usuario(ambito))
        if not r.bien or not sis.ejecutar(ambito.systemctl + ["is-active", UNIDAD]).bien:
            raise ParadaDelCanje("el canje no ha arrancado (%s). Mira «journalctl %s-u %s»"
                                 % ((r.error or r.salida).strip() or "se ha parado nada más empezar",
                                    "" if ambito.root else "--user ", UNIDAD))
    except ParadaDelCanje:
        limpiar(sis, {}, ambito)
        raise
    abierto_en = ([cortafuegos] if regla else []) + (["tu nftables o iptables"] if propio else [])
    salida("==> el canje: abierto 10 minutos en el TCP %d%s" % (
        puerto, " (y en %s, solo mientras dure)" % " y ".join(abierto_en) if abierto_en else ""))
    if not ambito.root:
        salida("    Sin root no toco el cortafuegos: si hay uno, ábrele ahora el TCP %d, solo mientras dure el canje"
               % puerto)
    elif det.cortafuegos_a_mano:
        salida("    Tu cortafuegos lo llevas tú: ábrele ahora el TCP %d, solo mientras dure el canje" % puerto)
    salida("    Si tu proveedor tiene un cortafuegos propio, el TCP %d tiene que estar abierto ahí" % puerto)
    el_enlace = enlace(servidor, puerto, codigo, huella)
    if op.qr_png:
        salida(_qr_png(sis, op.qr_png, el_enlace, run))
    return el_enlace


def _qr_png(sis, ruta, el_enlace, run=RUN) -> str:
    """El PNG se hace en /run (de root) y se deja en `ruta` como lo haría quien lanzó sudo: con la línea de sudoers de
    la salida 2, `--qr-png /etc/…` no puede pisar ni crear nada que su usuario no pudiera. Nunca sobre algo que ya
    exista, ni a través de un enlace."""
    import os
    if not ruta.startswith("/"):
        return "No dejo el QR en %s: dame una ruta absoluta" % ruta
    temporal = run + "/qr.png"
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
    """Una unidad temporal, para que el canje sobreviva al comando de Hermes y al reinicio de Hermes que programa
    `--activar-api` a los 90 s: es su propia unidad, en su propio cgroup (ni `--scope`, que se quedaría en el de Hermes,
    ni `PartOf=` ni `BindsTo=` con la suya), así que reiniciar Hermes no la toca; un usuario de usar y tirar, que no ve más
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
        # Lo que dura el canje y un margen: si algo se cuelga, systemd lo para igual.
        "RuntimeMaxSec=%d" % TOPE_DE_LA_UNIDAD,
        "ExecStopPost=+" + LIMPIAR,
    ]
    orden = ["systemd-run", "--unit=" + UNIDAD, "--collect", "--quiet"]
    for propiedad in propiedades:
        orden += ["-p", propiedad]
    return orden + [PYTHON_VENV, "-I", "-B", "-m", "hehermes_servidor.canje", "servir"]


def _systemd_run_usuario(ambito) -> list:
    """Sin root (modo TLS): una unidad temporal de usuario. Sin `DynamicUser` ni `LoadCredential`, que un gestor de
    usuario no da: el canje lee su carpeta de /run/user/<uid> (0700, en memoria), y la limpieza, también como el
    usuario, la borra al pararse."""
    limpiar_orden = "/usr/bin/python3 -I -B %s/hehermes-servidor canje-limpiar" % ambito.prefijo
    propiedades = [
        "Description=HeHermes: el canje del alta por chat (10 minutos, un solo uso)",
        "NoNewPrivileges=yes",
        "UMask=0077",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
        "RuntimeMaxSec=%d" % TOPE_DE_LA_UNIDAD,
        "ExecStopPost=" + limpiar_orden,
    ]
    orden = ["systemd-run", "--user", "--unit=" + UNIDAD, "--collect", "--quiet"]
    for propiedad in propiedades:
        orden += ["-p", propiedad]
    return orden + [ambito.python_venv, "-I", "-B", "-m", "hehermes_servidor.canje", "servir", "--carpeta",
                    ambito.run_canje]


def elegir_puerto(ocupados, azar=None, evitar=None) -> int | None:
    """Uno libre del rango, empezando por uno al azar y dando la vuelta: si el primero está ocupado, el siguiente libre.
    `None` si no queda ninguno. `evitar`: los efímeros de Linux (`puertos_efimeros`), que se dejan fuera del sorteo
    salvo que lo cubran todo."""
    azar = azar or _azar
    candidatos = range(PUERTO_MINIMO, PUERTO_MAXIMO + 1)
    if evitar:
        fuera = [puerto for puerto in candidatos if puerto not in evitar]
        candidatos = fuera or candidatos
    total = len(candidatos)
    inicio = azar(total)
    for paso in range(total):
        puerto = candidatos[(inicio + paso) % total]
        if puerto not in ocupados:
            return puerto
    return None


#: Los puertos que el núcleo da a las conexiones de salida (del 32768 al 60999, de serie).
RANGO_EFIMERO = "/proc/sys/net/ipv4/ip_local_port_range"


def puertos_efimeros(sis) -> range | None:
    """Los efímeros de este servidor, o None si no se saben. Uno de la pasarela entre ellos lo puede coger una conexión
    de salida antes de que arranque (tras un reinicio), y su unidad se rendiría con EADDRINUSE."""
    try:
        minimo, maximo = (int(x) for x in (sis.leer_texto(RANGO_EFIMERO) or "").split())
    except ValueError:
        return None
    return range(minimo, maximo + 1) if 0 < minimo <= maximo <= 65535 else None


def _puertos_tcp_ocupados(sis) -> set:
    """Todos los puertos TCP locales en uso, escuchen o no: uno de una conexión de salida tampoco se puede atar."""
    ocupados = set()
    for linea in sis.ejecutar(["ss", "-H", "-tan"]).salida.splitlines():
        campos = linea.split()
        if len(campos) >= 4 and campos[3].rsplit(":", 1)[-1].isdigit():
            ocupados.add(int(campos[3].rsplit(":", 1)[-1]))
    return ocupados


def _puerto_libre(sis) -> int:
    puerto = elegir_puerto(_puertos_tcp_ocupados(sis), evitar=puertos_efimeros(sis))
    if puerto is None:
        raise ParadaDelCanje("no hay ningún puerto libre para el canje entre el %d y el %d"
                             % (PUERTO_MINIMO, PUERTO_MAXIMO))
    return puerto


def venv_listo(sis, ambito=None) -> bool:
    from . import ambito as amb
    ambito = ambito or amb.de_root()
    return sis.existe(ambito.python_venv) and sis.ejecutar(
        [ambito.python_venv, "-I", "-B", "-c", "import cryptography, hehermes_servidor.canje"]).bien


def venv_roto(sis, ambito=None) -> bool:
    """El venv está, pero su Python no encuentra ni su pip: lo hizo otro Python. Pasa al subir de versión la
    distribución (Debian 12 → 13, Ubuntu 24.04 → 26.04): su `bin/python` lleva al `python3` nuevo, que busca lo suyo en
    otra carpeta (o a uno que ya no está). Instalar encima con pip no lo arregla: hay que rehacerlo (`--clear`)."""
    from . import ambito as amb
    ambito = ambito or amb.de_root()
    return sis.existe(ambito.python_venv) and not sis.ejecutar([ambito.python_venv, "-I", "-c", "import pip"]).bien


def _venv(sis, man, salida, ambito=None):
    """El venv del canje (y del certificado de la pasarela), con `cryptography` fijada por hash y el código del
    instalador por un `.pth` (con -I no vale PYTHONPATH). Si ya está y funciona, no se toca."""
    from . import ambito as amb
    ambito = ambito or amb.de_root()
    python, venv = ambito.python_venv, ambito.venv
    comprobar = [python, "-I", "-B", "-c", "import cryptography, hehermes_servidor.canje"]
    if venv_listo(sis, ambito):
        return
    salida("==> el entorno de Python de cryptography (%s)" % venv)
    man.datos["venv_canje"] = venv
    man.guardar(sis)
    rehecho = venv_roto(sis, ambito)
    if rehecho:
        salida("    el de antes es de otro Python (¿se ha actualizado el sistema?) y ya no funciona: lo rehago")
        r = sis.ejecutar(["python3", "-I", "-m", "venv", "--clear", venv], plazo=PLAZO_VENV)
        if not r.bien:
            raise ParadaDelCanje("el entorno de Python ha fallado (venv --clear): %s"
                                 % (r.error or r.salida).strip()[-400:], codigo="pip")
    if not sis.existe(python):
        r = sis.ejecutar(["python3", "-I", "-m", "venv", venv], plazo=PLAZO_VENV)
        if not r.bien:
            raise ParadaDelCanje("no he podido crear el entorno de Python (python3 -m venv %s): %s"
                                 % (venv, (r.error or r.salida).strip()[-400:]), codigo="pip")
    # Lo único de esto que va por la red: con sus reintentos y, si aun así falla (PyPI que no contesta un momento), otra
    # vez entera con espera creciente. Con los hashes fijados, repetirlo da siempre lo mismo.
    r = sis.ejecutar_con_reintentos(
        [python, "-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--quiet"] + PIP_RED +
        ["--only-binary=:all:", "--require-hashes", "-r", ambito.prefijo + "/requirements-canje.txt"],
        intentos=3, plazo=PLAZO_PIP, salida=salida, que="pip")
    if not r.bien:
        raise ParadaDelCanje("pip no ha podido instalar cryptography (¿llega este servidor a pypi.org?): %s"
                             % (r.error or r.salida).strip()[-400:], codigo="pip")
    r = sis.ejecutar([python, "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"])
    sis.escribir(r.salida.strip() + "/hehermes-servidor.pth", (ambito.prefijo + "\n").encode())
    if not sis.ejecutar(comprobar).bien:
        raise ParadaDelCanje("el entorno de Python no importa cryptography", codigo="pip")
    if rehecho and man.datos.get("vigia"):
        # El vigía corre con este venv: si sigue en marcha con el de antes (lo que tenía cargado), con el nuevo.
        sis.ejecutar(ambito.systemctl + ["try-restart", p.UNIDAD_VIGIA])


def _systemctl(ambito):
    return ambito.systemctl if ambito is not None else ["systemctl"]


def parar(sis, ambito=None) -> None:
    """Un canje anterior se para antes de lanzar otro: `systemctl stop` espera a su limpieza (`ExecStopPost`)."""
    if sis.ejecutar(_systemctl(ambito) + ["is-active", UNIDAD]).bien:
        sis.ejecutar(_systemctl(ambito) + ["stop", UNIDAD])


def limpiar_restos(sis, ambito=None) -> None:
    """Lo que un canje pudo dejar sin su limpieza: tras un reinicio, /run ya está vacío, pero la regla de ufw no. Solo
    con el canje parado."""
    if sis.ejecutar(_systemctl(ambito) + ["is-active", UNIDAD]).bien:
        return
    _barrer(sis, ambito)


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


def _barrer(sis, ambito=None):
    import shlex
    from . import cortafuegos as cf
    run = ambito.run_canje if ambito is not None else RUN
    if ambito is None or ambito.root:
        cf.quitar(sis, cf.MARCA_CANJE)
        if sis.cual("ufw"):
            for linea in sis.ejecutar(["ufw", "show", "added"]).salida.splitlines():
                linea = linea.strip()
                if linea.startswith("ufw ") and COMENTARIO_UFW in linea:
                    sis.ejecutar(["ufw", "delete"] + shlex.split(linea)[1:])
    if sis.existe(run):
        sis.borrar_arbol(run)


def limpiar(sis, entorno, ambito=None) -> None:
    """`ExecStopPost`: la regla de ufw fuera, /run/hehermes-canje fuera, y si el canje salió con 0 por sí mismo (se
    canjeó), apuntado (para el mensaje de `reemitir`; lo que cierra el chat es que ese iPhone use la pasarela, decisión
    7)."""
    import json
    run = ambito.run_canje if ambito is not None else RUN
    try:
        estado = json.loads(sis.leer_texto(run + "/estado.json") or "{}")
    except ValueError:
        estado = {}
    if estado.get("regla") and estado.get("cortafuegos") == "firewalld":
        sis.ejecutar(["firewall-cmd", estado["regla"][0].replace("--add-", "--remove-", 1)])
    elif estado.get("regla"):
        sis.ejecutar(["ufw", "delete"] + estado["regla"])
    _barrer(sis, ambito)
    canjeado = (entorno.get("SERVICE_RESULT") == "success" and entorno.get("EXIT_CODE") == "exited"
                and entorno.get("EXIT_STATUS") == "0")
    if canjeado:
        from .manifiesto import Manifiesto, RUTA_MANIFIESTO
        man = Manifiesto.leer(sis, ambito.manifiesto if ambito is not None else RUTA_MANIFIESTO)
        man.datos.setdefault("por_chat", {})["canjeado"] = time.time()
        man.guardar(sis)
