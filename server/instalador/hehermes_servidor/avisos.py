"""Los avisos push en el servidor de cada uno: el vigía y el lector de ficheros.

Desde la 0.8.0 (spec 2026-09-28, «Avisos sin comandos», «El instalador 0.8.0») `instalar` pone **siempre** el vigía y
el lector, sin preguntar y se pueda repetir. Sin código de avisos, el vigía va **sin credencial**: cada aviso sale con
el permiso que la app le da en el alta de cada iPhone (App Attest), hacia la entrada pública del relé que trae con él.
Con un código (lo de abajo, la 0.7.0), como antes.

El vigía (`server/avisos`, `hehermes_avisos.vigia`) vive al lado de Hermes: lo lee como la app, cifra cada aviso con la
clave de cada iPhone y se lo pasa al relé de Daniel, que es el único con la clave de Apple. Aquí el relé es **el de otra
máquina**: se llega a su entrada pública por HTTPS, con la huella de su certificado anclada y una credencial por
servidor. Las tres cosas llegan juntas en el «código de avisos» que da Daniel (`sudo hehermes-rele credencial alta`):

    hehermes-avisos:1?h=<dirección>&p=<puerto>&f=<huella>&c=<credencial>

La credencial es secreta: el código se pide sin eco (`hehermes-servidor avisos`, y se pega), o se da con `--avisos` (y
entonces queda en el historial del shell: mejor pegarlo). Aquí solo se guarda la credencial, en un fichero 0600 del
vigía; la dirección, el puerto y la huella van en `vigia.ini` y en el manifiesto, que no son secretos.

Lo que se instala, con root: el usuario `hh-vigia`, el código (`hehermes_avisos`, junto al del instalador), su
configuración y sus secretos en `/etc/hehermes-avisos/`, su base de datos en `/var/lib/hehermes-vigia` (la crea systemd)
y dos unidades, el socket (el puerto 127.0.0.1:8790 es de systemd) y el servicio. La pasarela le pasa `/avisos/` con su
secreto. Sin root, lo mismo en la casa del usuario de Hermes, con una unidad de usuario.

El lector de ficheros (`GET /avisos/v1/fichero`, `server/avisos/despliegue/hehermes-leer-media`): con root, como en el
VPS de Daniel (el script en /usr/local/libexec, un socket de systemd `root:hh-vigia` 0660 y un lector de root enjaulado
por conexión); sin root, una unidad de usuario del usuario de Hermes, con su socket en su /run/user, que solo atiende a
su propio uid.
"""

from __future__ import annotations

import os
import re
import secrets
import urllib.parse

from . import manifiesto as m
from . import piezas as p
from .plan import Accion, _unidad, buscar_en_origen, fuente_del_lector

ESQUEMA = "hehermes-avisos:1"
_HUELLA = re.compile(r"[A-Za-z0-9_-]{43}")
_CREDENCIAL = re.compile(r"hhr1\.[A-Za-z0-9_-]{43}")
#: Lo que deja `server/avisos/despliegue/instalar.sh` (el vigía y el relé de Daniel, a mano): no se toca.
A_MANO = "/opt/hehermes-avisos"


class CodigoNoValido(ValueError):
    """El código de avisos no tiene su forma. El mensaje no lo repite: lleva la credencial."""


def leer_codigo(texto) -> dict:
    """`{direccion, puerto, huella, credencial}` de un código de avisos, o `CodigoNoValido`. Lo mismo que
    `hehermes_avisos.rele.publico.leer_codigo`, que es quien los hace (las pruebas los cruzan)."""
    esquema, _, consulta = (texto or "").strip().partition("?")
    if esquema != ESQUEMA:
        raise CodigoNoValido("eso no es un código de avisos (empieza por %s?…)" % ESQUEMA)
    try:
        campos = urllib.parse.parse_qs(consulta, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise CodigoNoValido("el código de avisos está cortado o roto") from None
    if sorted(campos) != ["c", "f", "h", "p"] or any(len(v) != 1 for v in campos.values()):
        raise CodigoNoValido("al código de avisos le falta o le sobra algo: cópialo entero, en una línea")
    h, puerto, f, c = campos["h"][0], campos["p"][0], campos["f"][0], campos["c"][0]
    if not p._DIRECCION_VALIDA.fullmatch(h) or not puerto.isdigit() or not 0 < int(puerto) < 65536:
        raise CodigoNoValido("la dirección o el puerto del código de avisos no valen")
    if not _HUELLA.fullmatch(f) or not _CREDENCIAL.fullmatch(c):
        raise CodigoNoValido("la huella o la credencial del código de avisos no tienen su forma: cópialo entero")
    return {"direccion": h, "puerto": int(puerto), "huella": f, "credencial": c}


def pedir_codigo(entrada, terminal: bool) -> str:
    """El código, pegado. En un terminal, sin eco (no queda en la pantalla ni en el historial)."""
    if terminal and entrada is input:
        import getpass
        return getpass.getpass("Pega el código de avisos (no se ve al pegarlo) y pulsa Intro: ")
    return entrada("Código de avisos: ")


# MARK: El plan


def ficheros_del_codigo(origen: str, prefijo: str) -> list:
    """(ruta en el prefijo, contenido) del paquete de los avisos que va con el instalador (`hehermes_avisos/…`), o del
    repositorio si se ejecuta desde él (`server/avisos`)."""
    fuente = buscar_en_origen(origen, "hehermes_avisos", "../avisos/hehermes_avisos")
    if fuente is None:
        return []
    salida = []
    for carpeta, subcarpetas, nombres in os.walk(fuente):
        subcarpetas[:] = sorted(s for s in subcarpetas if s != "__pycache__")
        for nombre in sorted(nombres):
            if nombre.endswith(".py"):
                ruta = os.path.join(carpeta, nombre)
                relativa = os.path.relpath(ruta, fuente).replace(os.sep, "/")
                with open(ruta, "rb") as f:
                    salida.append((prefijo + "/hehermes_avisos/" + relativa, f.read()))
    return salida


#: El vigía sin código de avisos: sin credencial ni relé fijo (lo que va en el manifiesto, `{"modo": "permisos"}`).
SIN_CODIGO = {"direccion": None, "puerto": None, "huella": None, "credencial": None}


def datos_del_vigia(op, man) -> dict:
    """Lo que se quiere: el código de esta pasada, o (sin código) el que ya se dio, para repararlo sin pedirlo otra vez;
    y si nunca se dio ninguno, el vigía sin credencial (`SIN_CODIGO`)."""
    if getattr(op, "avisos", None):
        return dict(op.avisos)
    guardado = man.datos.get("vigia")
    if isinstance(guardado, dict) and {"direccion", "puerto", "huella"} <= set(guardado):
        return {"direccion": guardado["direccion"], "puerto": guardado["puerto"], "huella": guardado["huella"],
                "credencial": None}
    return dict(SIN_CODIGO)


def con_codigo(vigia) -> bool:
    return bool(vigia) and vigia.get("direccion") is not None


def para_el_manifiesto(vigia) -> dict:
    """Lo que no es secreto del vigía: con ello se repara sin pedir nada. La credencial, nunca."""
    if con_codigo(vigia):
        return {"direccion": vigia["direccion"], "puerto": vigia["puerto"], "huella": vigia["huella"]}
    return {"modo": "permisos"}


def _gestionado(sis, man, ruta, deseado, reemplazar) -> str:
    """Un secreto del vigía: nuevo, el mismo, otro (si es suyo, se cambia: un código nuevo trae otra credencial) o
    ajeno. `deseado` None: el que haya (repararlo sin código)."""
    if not sis.existe(ruta):
        return m.NUEVO
    if ruta not in man.ficheros:
        return m.REEMPLAZA if ruta in reemplazar else m.AJENO
    if deseado is None or sis.leer(ruta) == deseado:
        return m.YA_ESTA
    return m.CAMBIA


def planear(sis, det, man, op, origen, acciones, bloqueos, fichero, avisos=None) -> dict | None:
    """Las acciones del vigía y del lector: siempre, con un código (ahora, o uno de antes) o sin él. Devuelve los datos
    del vigía, o None si aquí no se pone (unos avisos puestos a mano, o algo que lo impide y ya está en `bloqueos`)."""
    ambito = det.ambito
    # Los de instalar.sh: los del VPS de Daniel, o los que ponía la VPN de antes de la 0.6.0 (`avisos` en el manifiesto,
    # con instalar.sh por debajo).
    if (sis.existe(A_MANO) or man.datos.get("avisos")) and not man.datos.get("vigia"):
        if getattr(op, "avisos", None):
            bloqueos.append("Aquí ya hay unos avisos puestos a mano (%s, los de server/avisos/despliegue/instalar.sh): "
                            "no los toco. Su vigía se configura en %s" % (A_MANO, ambito.vigia_ini))
        elif avisos is not None:
            avisos.append("Aquí ya hay unos avisos puestos a mano (%s, los de server/avisos/despliegue/instalar.sh): ni "
                          "el vigía ni el lector de ficheros los pongo yo, y lo suyo no lo toco" % A_MANO)
        return None
    vigia = datos_del_vigia(op, man)
    if con_codigo(vigia) and vigia["credencial"] is None and not sis.existe(ambito.credencial_rele):
        bloqueos.append("Al vigía le falta su credencial (%s): vuelve a darle el código de avisos: %s avisos"
                        % (ambito.credencial_rele, "sudo hehermes-servidor" if ambito.root else ambito.orden))
        return None
    det.con_vigia = True
    detalle = ("el relé de %s:%d, con su huella anclada" % (vigia["direccion"], vigia["puerto"]) if con_codigo(vigia)
               else "sin credencial: cada aviso, con el permiso de su iPhone")
    if ambito.root:
        acciones.append(Accion("usuario", p.USUARIO_VIGIA, m.YA_ESTA if sis.ejecutar(["id", "-u", p.USUARIO_VIGIA]).bien
                               else m.NUEVO, "sin casa ni shell, solo para el vigía de avisos"))
    codigo = ficheros_del_codigo(origen, ambito.prefijo)
    if not codigo:
        bloqueos.append("el paquete no trae el código de los avisos (hehermes_avisos)")
        return None
    for ruta, datos in codigo:
        fichero(ruta, datos, 0o644, grupo=ambito.prefijo + "/hehermes_avisos/")
    reemplazar = getattr(op, "reemplazar", frozenset())
    lector = planear_lector(sis, det, origen, acciones, bloqueos, avisos, fichero)
    credencial = (vigia["credencial"] + "\n").encode() if vigia["credencial"] else None
    secreto = sis.leer(ambito.secreto_vigia)
    propias = [
        fichero(ambito.vigia_ini, p.vigia_ini(ambito, det.hermes.puerto, det.hermes.env,
                                              os.path.dirname(det.hermes.home.rstrip("/")) or "/",
                                              vigia["direccion"], vigia["puerto"], vigia["huella"],
                                              lector=ambito.socket_lector if lector else None),
                0o640 if ambito.root else 0o600, detalle=detalle),
        _secreto(sis, man, acciones, ambito.secreto_vigia,
                 (secrets.token_urlsafe(32) + "\n").encode() if secreto is None else None, reemplazar,
                 "el secreto entre la pasarela y el vigía, 0600 (no se imprime)"),
    ]
    if con_codigo(vigia):
        propias.append(_secreto(sis, man, acciones, ambito.credencial_rele, credencial, reemplazar,
                                "la credencial del vigía ante el relé, 0600 (no se imprime)"))
    if ambito.root:
        propias.append(_secreto(sis, man, acciones, ambito.clave_hermes_vigia, (det.hermes.clave + "\n").encode(),
                                reemplazar, "la clave de Hermes del vigía, 0600 (no se imprime)"))
        socket_ = [fichero(ambito.socket_vigia, p.unidad_vigia_socket())]
        _unidad(sis, acciones, p.SOCKET_VIGIA, socket_, "el puerto del vigía, 127.0.0.1:8790", "restart")
    servicio = fichero(ambito.unidad_vigia, p.unidad_vigia(ambito, vigia["direccion"]))
    _unidad(sis, acciones, p.UNIDAD_VIGIA, propias + [servicio], "el vigía de avisos: " + detalle, "restart",
            ambito.systemctl)
    return vigia


def planear_lector(sis, det, origen, acciones, bloqueos, avisos, fichero) -> bool:
    """El lector de ficheros: el script (con root, en /usr/local/libexec; sin root, el que ya va en su casa con el
    instalador), su socket y su plantilla. Devuelve si se pone: sin él, el vigía va igual y la ruta contesta 503."""
    ambito = det.ambito
    casa = det.hermes.home.rstrip("/")
    if not p._RUTA_VALIDA.fullmatch(casa):
        if avisos is not None:
            avisos.append("La carpeta de Hermes (%r) no la sé poner en una unidad de systemd: no pongo el lector de "
                          "ficheros, y las descargas de la app (GET /avisos/v1/fichero) contestan 503" % casa)
        return False
    fuente = fuente_del_lector(origen)
    if fuente is None:
        bloqueos.append("el paquete no trae el lector de ficheros (hehermes-leer-media)")
        return False
    if ambito.root:
        # Suelto (lo escribe `aplicar_tls` con los demás ficheros): cambiarlo no pide reiniciar nada, cada conexión
        # lanza el que haya.
        with open(fuente, "rb") as f:
            fichero(ambito.lector, f.read(), 0o755)
    unidades = [fichero(ambito.unidad_lector_socket, p.unidad_lector_socket(ambito)),
                fichero(ambito.unidad_lector, p.unidad_lector(ambito, casa))]
    _unidad(sis, acciones, p.SOCKET_LECTOR, unidades, "el lector de ficheros de Hermes (GET /avisos/v1/fichero), %s"
            % ("de root, enjaulado, uno por conexión" if ambito.root else "como %s, uno por conexión" % ambito.usuario),
            "restart", ambito.systemctl)
    return True


def _secreto(sis, man, acciones, ruta, deseado, reemplazar, detalle):
    estado = _gestionado(sis, man, ruta, deseado, reemplazar)
    datos = deseado if deseado is not None else sis.leer(ruta)
    acciones.append(Accion("gestionado", ruta, estado, detalle, datos, 0o600))
    return acciones[-1]


def rutas(ambito) -> set:
    """Lo del vigía y del lector que `aplicar_tls` deja para su propio paso (y no con los ficheros sueltos)."""
    return {ambito.vigia_ini, ambito.secreto_vigia, ambito.credencial_rele, ambito.clave_hermes_vigia,
            ambito.unidad_vigia, ambito.socket_vigia, ambito.unidad_lector_socket, ambito.unidad_lector}


# MARK: Aplicar


def aplicar_secretos(sis, man, acciones, ambito, salida, orden) -> None:
    """Las carpetas, la configuración y los secretos del vigía, **antes** de la pasarela: con root, su unidad carga el
    secreto del vigía (`LoadCredential`) y sin él no arrancaría. Con root, de `hh-vigia` y 0600 (la configuración,
    `root:hh-vigia` 0640)."""
    from .aplicar import Transaccion, _escribir
    nuevas = [c for c in (ambito.carpeta_avisos, ambito.carpeta_vigia) if not sis.es_carpeta(c)]
    for carpeta in nuevas:
        man.apuntar_carpetas(sis, carpeta + "/x")
    sis.carpeta(ambito.carpeta_avisos, 0o755 if ambito.root else 0o700)
    sis.carpeta(ambito.carpeta_vigia, 0o750 if ambito.root else 0o700)
    if not ambito.root and not sis.es_carpeta(ambito.carpeta_estado_vigia):
        man.apuntar_carpetas(sis, ambito.carpeta_estado_vigia + "/x")
        sis.carpeta(ambito.carpeta_estado_vigia, 0o700)
    if ambito.root:
        orden(sis, ["chown", "root:" + p.USUARIO_VIGIA, ambito.carpeta_vigia], "chown de la carpeta del vigía")
    man.guardar(sis)
    tx = Transaccion(sis, man)
    try:
        escritos = [a for a in acciones if a.objeto in (ambito.vigia_ini, ambito.secreto_vigia, ambito.credencial_rele,
                                                         ambito.clave_hermes_vigia) and _escribir(sis, man, tx, a)]
        if ambito.root:
            for accion in escritos:
                dueno = ("root:" if accion.objeto == ambito.vigia_ini else p.USUARIO_VIGIA + ":") + p.USUARIO_VIGIA
                orden(sis, ["chown", dueno, accion.objeto], "chown de %s" % accion.objeto)
    except Exception:
        tx.deshacer()
        man.guardar(sis)
        raise
    if escritos:
        salida("==> los avisos: %d ficheros del vigía" % len(escritos))
    man.guardar(sis)


def aplicar_unidades(sis, man, acciones, ambito, salida) -> None:
    """El lector primero (el vigía lo quiere, `Wants=`), luego el puerto del vigía y el vigía."""
    from .aplicar import _con_unidad
    del_lector = [a for a in acciones if a.objeto in (ambito.unidad_lector_socket, ambito.unidad_lector,
                                                        p.SOCKET_LECTOR)]
    if del_lector:
        _con_unidad(sis, man, del_lector, p.SOCKET_LECTOR, salida, systemctl=ambito.systemctl)
    if ambito.root:
        _con_unidad(sis, man, [a for a in acciones if a.objeto in (ambito.socket_vigia, p.SOCKET_VIGIA)],
                    p.SOCKET_VIGIA, salida)
    _con_unidad(sis, man, [a for a in acciones if a.objeto in (ambito.unidad_vigia, p.UNIDAD_VIGIA)],
                p.UNIDAD_VIGIA, salida, systemctl=ambito.systemctl)


# MARK: Comprobar


#: Lo que se espera entre dos `comprobar` del vigía recién arrancado (las pruebas lo bajan a cero).
ESPERA_AL_COMPROBAR = 2.0


def comprobar(sis, man, ambito, mira, hermes_pendiente=False, intentos=3, espera=None) -> None:
    """El vigía en marcha, y su propio `comprobar` (Hermes, su puerto, el lector de ficheros y, con credencial, el
    relé, sin mandar nada). Recién arrancado puede no contestar todavía: si algo sale mal, se repite un par de veces.
    Con la API de Hermes encendiéndose (se reinicia al acabar), su comprobación no dice nada útil: solo si está en
    marcha."""
    import time
    en_marcha = sis.ejecutar(ambito.systemctl + ["is-active", p.UNIDAD_VIGIA]).bien
    mira(en_marcha, "vigía: en marcha", "vigía: parado (%sjournalctl %s-u hehermes-vigia)"
         % ("sudo " if ambito.root else "", "" if ambito.root else "--user "))
    if not con_codigo(man.datos.get("vigia")):
        mira(True, "vigía: sin credencial; los avisos van con el permiso que la app le da al darse de alta", "")
    if ambito.unidad_lector_socket in man.ficheros:
        lector = sis.ejecutar(ambito.systemctl + ["is-active", p.SOCKET_LECTOR]).bien
        mira(lector, "lector de ficheros: su socket está en marcha (%s)" % ambito.socket_lector,
             "lector de ficheros: su socket está parado (%ssystemctl %sstart %s)"
             % ("sudo " if ambito.root else "", "" if ambito.root else "--user ", p.SOCKET_LECTOR))
    if hermes_pendiente:
        return
    orden = [ambito.python_venv, "-I", "-B", "-m", "hehermes_avisos.vigia", "--config", ambito.vigia_ini, "comprobar"]
    for intento in range(intentos):
        r = sis.ejecutar(orden)
        lineas = [linea for linea in r.salida.splitlines() if linea.startswith(("bien: ", "mal:  "))]
        if lineas and all(linea.startswith("bien: ") for linea in lineas):
            break
        if intento + 1 < intentos:
            time.sleep(ESPERA_AL_COMPROBAR if espera is None else espera)
    if not lineas:
        mira(False, "", "vigía: su comprobación no dice nada (%s)" % ((r.error or r.salida).strip()[-200:] or r.codigo))
    for linea in lineas:
        bien, texto = linea.startswith("bien: "), linea[6:].strip()
        mira(bien, "vigía: " + texto, "vigía: " + texto)
