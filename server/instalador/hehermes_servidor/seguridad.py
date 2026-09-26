"""La sección «Seguridad» de `comprobar`: lo que tiene que estar cerrado, mirado desde fuera. Solo lee.

Cada línea es (estado, texto), con el estado «bien», «aviso» o «mal». Un «mal» es algo abierto que no debería estarlo
(y `comprobar` sale con 1); un «aviso», algo que no depende del instalador o que no sabe juzgar. Funciona también sin
manifiesto, en un servidor montado a mano como el de Daniel: mira las rutas de siempre.
"""

from __future__ import annotations

import configparser
import re

from . import cortafuegos as cf
from . import firma
from . import piezas as p
from .deteccion import CABECERA_DISPOSITIVO, SWANCTL, TODAS, _candidatos, _escuchan, leer_swanctl
from .entorno import leer_env

BIEN, AVISO, MAL = "bien", "aviso", "mal"
PROPUESTA_IKE = "aes256gcm16-prfsha384-ecp384"
PROPUESTA_ESP = "aes256gcm16-ecp384"
#: Lo que da `hehermes-dispositivo`: 33 bytes al azar, 44 caracteres en base64.
LARGO_PSK = 44


def revisar(sis, man) -> list:
    resultados = []
    ini = _ini(sis)
    env, puerto = _hermes(sis, ini)
    resultados.append(_api_de_hermes(sis, env, puerto))
    resultados += _nginx(sis)
    resultados += _cortafuegos(sis, man)
    resultados.append(_canje(sis))
    resultados += _secretos(sis, ini, env)
    resultados += _ikev2(sis, ini)
    resultados += _avisos(sis, man)
    resultados.append(_firma(sis))
    return resultados


def _ini(sis):
    ini = configparser.ConfigParser()
    try:
        ini.read_string(sis.leer_texto(p.SERVIDOR_INI) or "")
    except configparser.Error:
        pass
    return ini


def _hermes(sis, ini):
    env = ini.get("hermes", "env", fallback=None)
    if not env:
        candidatos = _candidatos(sis)
        env = candidatos[0].env if candidatos else None
    valores = leer_env(sis.leer_texto(env) or "") if env else {}
    try:
        puerto = int(ini.get("hermes", "puerto", fallback=None) or valores.get("API_SERVER_PORT") or 8642)
    except ValueError:
        puerto = 8642
    return env, puerto


def _api_de_hermes(sis, env, puerto):
    host = leer_env(sis.leer_texto(env) or "").get("API_SERVER_HOST") if env else None
    donde = "%s:%d" % (host, puerto) if host in TODAS else None
    for escucha, suyo, _ in _escuchan(sis, "tcp"):
        if suyo == str(puerto) and escucha in TODAS:
            donde = "%s:%d" % (escucha, puerto)
    if donde:
        return (MAL, "la API de Hermes escucha en %s, en todas las interfaces: se llega a ella sin la VPN. "
                     "sudo hehermes-servidor instalar --corregir-exposicion la cierra a 127.0.0.1" % donde)
    return (BIEN, "la API de Hermes solo escucha en 127.0.0.1:%d" % puerto)


def _nginx(sis):
    salida = []
    sitio = next((r for r in (p.SITIO, p.SITIO_CONF_D) if sis.existe(r)), None)
    if sitio is None:
        return [(AVISO, "nginx: no encuentro el sitio del túnel")]
    texto = re.sub(r"#[^\n]*", "", sis.leer_texto(sitio) or "")
    escucha = re.findall(r"^\s*listen\s+([^;\s]+)", texto, re.M)
    if escucha and all(e == p.IP_TUNEL + ":80" for e in escucha):
        salida.append((BIEN, "nginx: el sitio del túnel solo escucha en %s:80" % p.IP_TUNEL))
    else:
        salida.append((MAL, "nginx: el sitio del túnel escucha en %s, y tiene que ser solo %s:80"
                            % (", ".join(escucha) or "el puerto por defecto de todas las direcciones", p.IP_TUNEL)))
    if p.agujero_abierto(texto):
        salida.append((MAL, "nginx: la location / del túnel no niega a %s: cualquier proceso de este servidor usa la "
                            "API de Hermes con su clave (el agujero del túnel)" % p.IP_TUNEL))
    else:
        salida.append((BIEN, "nginx: la clave de Hermes solo se la pone a los iPhone (%s), no al propio servidor"
                             % p.RED_IPHONES))
    otros = []
    for carpeta in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
        for nombre in sis.listar(carpeta):
            ruta = carpeta + "/" + nombre
            real = sis.enlace(ruta) or ruta
            if real in (p.SITIO, p.SITIO_CONF_D) or ruta in (p.SITIO_ENLACE, p.SITIO_CONF_D):
                continue
            if "hehermes-bearer.conf" in re.sub(r"#[^\n]*", "", sis.leer_texto(real) or ""):
                otros.append(ruta)
    if otros:
        salida.append((MAL, "nginx: %s también pone la clave de Hermes" % ", ".join(otros)))
    return salida


def _cortafuegos(sis, man):
    salida = []
    gestor = None
    if sis.cual("firewall-cmd") and sis.ejecutar(["firewall-cmd", "--state"]).bien:
        gestor = "firewalld"
        salida.append((BIEN, "cortafuegos: firewalld, en marcha"))
    elif sis.cual("ufw"):
        if re.search(r"^Status: active", sis.ejecutar(["ufw", "status"]).salida, re.M):
            gestor = "ufw"
            salida.append((BIEN, "cortafuegos: ufw, en marcha"))
        else:
            salida.append((AVISO, "cortafuegos: ufw está apagado (no lo enciendo: podría dejarte fuera del SSH)"))
    propio = man.datos.get("cortafuegos_propio") or {}
    lugares, dudas = cf.analizar(sis, propio.get("iptables", gestor is None))
    faltan = [l.nombre for l in lugares if l.marcadas < len(cf.permanentes())]
    if faltan:
        salida.append((MAL, "cortafuegos: %s cierra el paso y le faltan las reglas de HeHermes (sudo hehermes-servidor "
                            "instalar las pone)" % ", ".join(faltan)))
    elif lugares:
        salida.append((BIEN, "cortafuegos: %s, con las reglas justas de HeHermes" % ", ".join(l.nombre for l in lugares)))
    if dudas:
        salida.append((AVISO, "cortafuegos: %s; no sé si deja pasar lo de HeHermes" % "; ".join(dudas)))
    if gestor is None and not lugares and not dudas and not salida:
        salida.append((AVISO, "cortafuegos: no hay ninguno que cierre el paso; lo que escucha en todas las "
                              "direcciones está abierto a internet (no enciendo ninguno)"))
    return salida


def _canje(sis):
    from . import porchat
    if sis.ejecutar(["systemctl", "is-active", porchat.UNIDAD]).bien:
        return (AVISO, "canje: hay uno abierto ahora mismo; se cierra solo al canjearse o a los 10 minutos")
    abiertos = []
    if sis.cual("ufw"):
        if any(porchat.COMENTARIO_UFW in l for l in sis.ejecutar(["ufw", "show", "added"]).salida.splitlines()):
            abiertos.append("ufw")
    lugares = []
    if sis.cual("nft"):
        lugares += [o for o in cf._ruleset(sis) if (o.get("rule") or {}).get("comment") == cf.MARCA_CANJE]
    if sis.cual("iptables"):
        lugares += [l for l in sis.ejecutar(["iptables", "-S", "INPUT"]).salida.splitlines() if cf.MARCA_CANJE in l]
    if lugares:
        abiertos.append("nftables o iptables")
    if abiertos:
        return (MAL, "canje: su puerto sigue abierto en %s sin ningún canje en marcha. Lo cierra: sudo systemctl "
                     "restart hehermes-cortafuegos" % " y ".join(abiertos))
    return (BIEN, "canje: ninguno abierto, y ningún puerto suyo en el cortafuegos")


def _abierto(sis, ruta):
    """El modo si alguien que no es su dueño lo puede leer (o es un enlace), o None."""
    modo = sis.modo(ruta)
    if modo is None:
        return None
    if sis.enlace(ruta) is not None:
        return "es un enlace"
    return "%04o" % modo if modo & 0o077 else None


def _secretos(sis, ini, env):
    mal, aviso = [], []
    carpeta = ini.get("strongswan", "carpeta", fallback=None)
    carpetas = [carpeta] if carpeta else [c for c in SWANCTL.values() if sis.es_carpeta(c)]
    psk = []
    for c in carpetas:
        psk += [c + "/conf.d/" + n for n in sis.listar(c + "/conf.d") if n.startswith("hehermes") and n.endswith(".conf")]
    solo_root = psk + [p.BEARER, "/etc/hehermes/instalacion.json", "/etc/hehermes-avisos/vigia/clave-hermes"]
    solo_root += ["/etc/hehermes/copias/" + n for n in sis.listar("/etc/hehermes/copias")]
    for ruta in solo_root:
        problema = _abierto(sis, ruta)
        if problema:
            mal.append("%s (%s)" % (ruta, problema))
    for ruta, modo_carpeta in (("/etc/hehermes/copias", True), ("/run/hehermes-canje", True)):
        modo = sis.modo(ruta)
        if modo is not None and modo & 0o077:
            mal.append("%s (%04o)" % (ruta, modo))
    if env:
        modo = sis.modo(env)
        if modo is not None and modo & 0o007:
            mal.append("%s (%04o)" % (env, modo))
        elif modo is not None and modo & 0o070:
            aviso.append("%s se puede leer desde su grupo (%04o): lleva la clave de Hermes" % (env, modo))
    salida = []
    if mal:
        salida.append((MAL, "secretos que se pueden leer sin ser su dueño: %s. Déjalos en 0600" % ", ".join(mal)))
    else:
        salida.append((BIEN, "secretos: la PSK de cada iPhone, la clave de Hermes en nginx, el .env y las copias, "
                             "solo para su dueño"))
    salida += [(AVISO, "secretos: " + a) for a in aviso]
    return salida


def _psk(texto):
    for linea in texto.splitlines():
        hallado = re.match(r"^\s*secret\s*=\s*(.*?)\s*$", linea)
        if hallado:
            bruto = hallado.group(1)
            if bruto[:2] in ("0x", "0X"):
                try:
                    return bytes.fromhex(bruto[2:]).decode("ascii", "replace")
                except ValueError:
                    return ""
            return bruto.strip('"')
    return ""


def _ikev2(sis, ini):
    carpeta = ini.get("strongswan", "carpeta", fallback=None)
    carpetas = [carpeta] if carpeta else [c for c in SWANCTL.values() if sis.es_carpeta(c)]
    mal, a_mano, cuantos = [], [], 0
    for c in carpetas:
        for nombre in sis.listar(c + "/conf.d"):
            if not (nombre.startswith("hehermes") and nombre.endswith(".conf")):
                continue
            texto = sis.leer_texto(c + "/conf.d/" + nombre) or ""
            generado = texto.startswith(CABECERA_DISPOSITIVO)
            for conexion, datos in (leer_swanctl(texto).get("connections") or {}).items():
                if not isinstance(datos, dict):
                    continue
                cuantos += 1
                hijos = [h for h in (datos.get("children") or {}).values() if isinstance(h, dict)]
                if datos.get("proposals") != PROPUESTA_IKE or any(h.get("esp_proposals") != PROPUESTA_ESP
                                                                  for h in hijos):
                    mal.append("%s acepta otras propuestas que las de la app" % conexion)
                if any(h.get("local_ts") != p.IP_TUNEL + "/32" for h in hijos):
                    mal.append("%s no limita el túnel a %s" % (conexion, p.IP_TUNEL))
                psk = _psk(texto)
                if generado and len(psk) < LARGO_PSK:
                    mal.append("la PSK de %s es más corta de lo que da hehermes-dispositivo" % conexion)
                elif not generado:
                    a_mano.append(conexion)
    salida = []
    if mal:
        salida.append((MAL, "IKEv2: " + "; ".join(mal)))
    elif cuantos:
        salida.append((BIEN, "IKEv2: %d conexión%s, solo AES-256-GCM con PRF SHA-384 y ECP-384, y el túnel solo hasta "
                             "%s" % (cuantos, "" if cuantos == 1 else "es", p.IP_TUNEL)))
    if a_mano:
        salida.append((AVISO, "IKEv2: %s no la generó hehermes-dispositivo: no sé si su PSK es de 256 bits al azar"
                              % ", ".join(a_mano)))
    return salida


def _avisos(sis, man):
    if not (man.datos.get("avisos") or sis.existe("/etc/hehermes-avisos")):
        return []
    fuera = [host + ":" + puerto for host, puerto, _ in _escuchan(sis, "tcp")
             if puerto in ("8790", "8791") and host not in ("127.0.0.1", "[::1]", "::1")]
    if fuera:
        return [(MAL, "avisos: el vigía o el relé escuchan fuera de 127.0.0.1 (%s)" % ", ".join(fuera))]
    return [(BIEN, "avisos: el vigía y el relé solo escuchan en 127.0.0.1")]


def _firma(sis):
    if firma.pendiente(sis.leer_texto(p.PREFIJO + "/clave-publica.pem") or ""):
        return (AVISO, "actualizar: la clave de las firmas todavía es el marcador, así que actualizar se niega (lo "
                       "nuevo, con el comando de la app)")
    return (BIEN, "actualizar: solo con un paquete firmado con la clave de Daniel")
