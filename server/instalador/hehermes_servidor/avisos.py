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
su propio uid. Igual los ayudantes de la copia en iCloud (desde la 0.10.0) y de la entrada (desde la 0.10.6: lo que la
app le manda a Hermes, en `<HERMES_HOME>/entrada`, que crea el instalador como `exports/`). Y desde la 0.10.10, solo con
root, el que actualiza el servidor desde la app (`hehermes-actualizar`), con lo que enseña Ajustes › Tu servidor en la
sección `[servidor]` de `vigia.ini`.

Desde la 0.11.0, los agentes (contrato §18): el ayudante `hehermes-agentes`, que crea, cambia y borra los perfiles de
Hermes que la app enseña como agentes, con su socket y su plantilla como los demás, y su temporizador de la memoria que
comparten (`hehermes-agentes-memoria.timer`, cada minuto). Sus claves, una por perfil, en dos carpetas que crea el
instalador: la de la pasarela (`modo_tls`) y la del vigía (`aplicar_secretos`).
"""

from __future__ import annotations

import os
import re
import secrets
import urllib.parse

from . import manifiesto as m
from . import piezas as p
from .plan import Accion, _unidad, bloqueo, buscar_en_origen, codigo_de, etiquetar, fuente_del_lector

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
            etiquetar(bloqueos, "avisos-a-mano")
        elif avisos is not None:
            avisos.append("Aquí ya hay unos avisos puestos a mano (%s, los de server/avisos/despliegue/instalar.sh): ni "
                          "el vigía ni el lector de ficheros los pongo yo, y lo suyo no lo toco" % A_MANO)
        return None
    vigia = datos_del_vigia(op, man)
    if con_codigo(vigia) and vigia["credencial"] is None and not sis.existe(ambito.credencial_rele):
        bloqueos.append("Al vigía le falta su credencial (%s): vuelve a darle el código de avisos: %s avisos"
                        % (ambito.credencial_rele, "sudo hehermes-servidor" if ambito.root else ambito.orden))
        etiquetar(bloqueos, "avisos-credencial")
        return None
    det.con_vigia = True
    detalle = ("el relé de %s:%d, con su huella anclada" % (vigia["direccion"], vigia["puerto"]) if con_codigo(vigia)
               else "sin credencial: cada aviso, con el permiso de su iPhone")
    if ambito.root:
        acciones.append(Accion("usuario", p.USUARIO_VIGIA, m.YA_ESTA if sis.ejecutar(["id", "-u", p.USUARIO_VIGIA]).bien
                               else m.NUEVO, "sin casa ni shell, solo para el vigía de avisos"))
    codigo = ficheros_del_codigo(origen, ambito.prefijo)
    if not codigo:
        bloqueos.append(bloqueo("paquete", "el paquete no trae el código de los avisos (hehermes_avisos)"))
        return None
    for ruta, datos in codigo:
        fichero(ruta, datos, 0o644, grupo=ambito.prefijo + "/hehermes_avisos/")
    reemplazar = getattr(op, "reemplazar", frozenset())
    lector = planear_lector(sis, det, origen, acciones, bloqueos, avisos, fichero)
    respaldo = planear_respaldo(sis, det, origen, acciones, bloqueos, avisos, fichero)
    entrada = planear_entrada(sis, det, origen, acciones, bloqueos, avisos, fichero)
    actualizar = planear_actualizar(sis, det, origen, acciones, bloqueos, fichero)
    agentes = planear_agentes(sis, det, origen, acciones, bloqueos, avisos, fichero)
    credencial = (vigia["credencial"] + "\n").encode() if vigia["credencial"] else None
    secreto = sis.leer(ambito.secreto_vigia)
    propias = [
        fichero(ambito.vigia_ini, p.vigia_ini(ambito, det.hermes.puerto, det.hermes.env,
                                              det.hermes.casa_de_rutas,
                                              vigia["direccion"], vigia["puerto"], vigia["huella"],
                                              lector=ambito.socket_lector if lector else None,
                                              respaldo=ambito.socket_respaldo if respaldo else None,
                                              entrada=ambito.socket_entrada if entrada else None,
                                              actualizar=ambito.socket_actualizar if actualizar else None,
                                              servicios=servicios_del_vigia(ambito, lector, respaldo, entrada,
                                                                            actualizar, agentes),
                                              hermes_unidad=unidad_de_hermes_para_el_vigia(det.hermes, ambito),
                                              agentes=ambito.socket_agentes if agentes else None),
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
    # Su código: el de los avisos y, por la clave de Hermes, el del instalador (`hehermes_servidor.pasarela`).
    _unidad(sis, acciones, p.UNIDAD_VIGIA, propias + [servicio], "el vigía de avisos: " + detalle, "restart",
            ambito.systemctl, codigo=codigo_de(acciones, ambito.prefijo, "hehermes_avisos/", "hehermes_servidor/"),
            quien="el vigía", man=man)
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
        bloqueos.append(bloqueo("paquete", "el paquete no trae el lector de ficheros (hehermes-leer-media)"))
        return False
    if ambito.root:
        # Suelto (lo escribe `aplicar_tls` con los demás ficheros): cambiarlo no pide reiniciar nada, cada conexión
        # lanza el que haya.
        with open(fuente, "rb") as f:
            fichero(ambito.lector, f.read(), 0o755)
    unidades = [fichero(ambito.unidad_lector_socket, p.unidad_lector_socket(ambito)),
                fichero(ambito.unidad_lector, p.unidad_lector(ambito, casa, det.hermes.usuario if ambito.root else None))]
    _unidad(sis, acciones, p.SOCKET_LECTOR, unidades, "el lector de ficheros de Hermes (GET /avisos/v1/fichero), %s"
            % ("de root, enjaulado, uno por conexión" if ambito.root else "como %s, uno por conexión" % ambito.usuario),
            "restart", ambito.systemctl)
    return True


def _unidad_para_el_respaldo(hermes, ambito) -> str:
    """La unidad de Hermes que para y arranca el ayudante al restaurar: la suya (la de su perfil, desde la 0.10.2) si el
    ayudante la puede manejar (con root, una del sistema; sin root, una de usuario suya); si no, la de siempre, que el
    ayudante no encuentra y por eso no restaura (lo dice)."""
    gestor = hermes.gestor
    suya = gestor is not None and re.fullmatch(r"[A-Za-z0-9:_.@-]{1,200}\.service", gestor.nombre) and (
        gestor.tipo == "sistema" if ambito.root else (gestor.tipo == "usuario" and gestor.usuario == ambito.usuario))
    return gestor.nombre if suya else "hermes-gateway.service"


def planear_respaldo(sis, det, origen, acciones, bloqueos, avisos, fichero) -> bool:
    """El ayudante de la copia en iCloud (desde la 0.10.0): el script (con root, en /usr/local/libexec; sin root, el que
    ya va en su casa con el instalador), su socket y su plantilla. Devuelve si se pone: sin él, el vigía va igual y
    /avisos/v1/respaldo contesta 503."""
    ambito = det.ambito
    casa = det.hermes.home.rstrip("/")
    if not p._RUTA_VALIDA.fullmatch(casa):
        if avisos is not None:
            avisos.append("La carpeta de Hermes (%r) no la sé poner en una unidad de systemd: no pongo la copia en "
                          "iCloud, y /avisos/v1/respaldo contesta 503" % casa)
        return False
    from .plan import fuente_del_respaldo
    fuente = fuente_del_respaldo(origen)
    if fuente is None:
        bloqueos.append(bloqueo("paquete", "el paquete no trae el ayudante de la copia en iCloud (hehermes-respaldo)"))
        return False
    if ambito.root:
        with open(fuente, "rb") as f:
            fichero(ambito.respaldo, f.read(), 0o755)
    unidades = [fichero(ambito.unidad_respaldo_socket, p.unidad_respaldo_socket(ambito)),
                fichero(ambito.unidad_respaldo, p.unidad_respaldo(ambito, casa,
                                                                  det.hermes.usuario if ambito.root else None,
                                                                  _unidad_para_el_respaldo(det.hermes, ambito)))]
    _unidad(sis, acciones, p.SOCKET_RESPALDO, unidades, "la copia de Hermes en iCloud (/avisos/v1/respaldo), %s"
            % ("un ayudante de root, enjaulado, por conexión" if ambito.root
               else "como %s, uno por conexión" % ambito.usuario), "restart", ambito.systemctl)
    return True


def planear_entrada(sis, det, origen, acciones, bloqueos, avisos, fichero) -> bool:
    """El ayudante de la entrada (desde la 0.10.6, contrato §16): el script (con root, en /usr/local/libexec; sin root,
    el que ya va en su casa con el instalador), su socket y su plantilla. Devuelve si se pone: sin él, el vigía va igual
    y /avisos/v1/entrada contesta 503. La carpeta `<HERMES_HOME>/entrada` se crea al aplicar (`crear_entrada`)."""
    ambito = det.ambito
    casa = det.hermes.home.rstrip("/")
    if not p._RUTA_VALIDA.fullmatch(casa):
        if avisos is not None:
            avisos.append("La carpeta de Hermes (%r) no la sé poner en una unidad de systemd: no pongo la entrada de "
                          "ficheros, y /avisos/v1/entrada contesta 503" % casa)
        return False
    from .plan import fuente_de_la_entrada
    fuente = fuente_de_la_entrada(origen)
    if fuente is None:
        bloqueos.append(bloqueo("paquete", "el paquete no trae el ayudante de la entrada (hehermes-entrada)"))
        return False
    if ambito.root:
        # Suelto, como el lector: cambiarlo no pide reiniciar nada, cada conexión lanza el que haya.
        with open(fuente, "rb") as f:
            fichero(ambito.entrada, f.read(), 0o755)
    unidades = [fichero(ambito.unidad_entrada_socket, p.unidad_entrada_socket(ambito)),
                fichero(ambito.unidad_entrada, p.unidad_entrada(ambito, casa,
                                                                det.hermes.usuario if ambito.root else None))]
    _unidad(sis, acciones, p.SOCKET_ENTRADA, unidades,
            "lo que la app le manda a Hermes (/avisos/v1/entrada, en %s/%s), %s"
            % (casa, p.CARPETA_ENTRADA, "uno por conexión, como el dueño de Hermes y sin capacidades" if ambito.root
               else "como %s, uno por conexión" % ambito.usuario), "restart", ambito.systemctl)
    return True


def planear_actualizar(sis, det, origen, acciones, bloqueos, fichero) -> bool:
    """El ayudante que actualiza el servidor desde la app (desde la 0.10.10): con root, el script en /usr/local/libexec,
    su socket y su plantilla. Sin root, nada: actualizar es instalar, y la app enseña cómo hacerlo a mano. Devuelve si se
    pone: sin él, el vigía va igual y /avisos/v1/servidor/actualizar contesta 503."""
    ambito = det.ambito
    if not ambito.root:
        return False
    from .plan import fuente_del_actualizar
    fuente = fuente_del_actualizar(origen)
    if fuente is None:
        bloqueos.append(bloqueo("paquete", "el paquete no trae el ayudante que actualiza (hehermes-actualizar)"))
        return False
    # Suelto, como el lector: cambiarlo no pide reiniciar nada, cada conexión lanza el que haya.
    with open(fuente, "rb") as f:
        fichero(ambito.actualizar, f.read(), 0o755)
    unidades = [fichero(ambito.unidad_actualizar_socket, p.unidad_actualizar_socket()),
                fichero(ambito.unidad_actualizar, p.unidad_actualizar(ambito))]
    _unidad(sis, acciones, p.SOCKET_ACTUALIZAR, unidades, "actualizar desde la app (/avisos/v1/servidor/actualizar), "
            "un ayudante de root por conexión, sin capacidades ni red, que lanza la actualización en su propia unidad",
            "restart", ambito.systemctl)
    return True


def planear_agentes(sis, det, origen, acciones, bloqueos, avisos, fichero) -> bool:
    """El ayudante de los agentes (desde la 0.11.0, contrato §18): el script (con root, en /usr/local/libexec; sin root,
    el que ya va en su casa con el instalador), su socket y su plantilla, y el temporizador de la memoria que comparten
    con su servicio. Devuelve si se pone: sin él, el vigía va igual y /avisos/v1/agentes contesta 503. Las carpetas de
    las claves se crean al aplicar (`aplicar_secretos` y `modo_tls`)."""
    ambito = det.ambito
    casa = det.hermes.home.rstrip("/")
    if not p._RUTA_VALIDA.fullmatch(casa):
        if avisos is not None:
            avisos.append("La carpeta de Hermes (%r) no la sé poner en una unidad de systemd: no pongo los agentes, y "
                          "/avisos/v1/agentes contesta 503" % casa)
        return False
    from .plan import fuente_de_agentes
    fuente = fuente_de_agentes(origen)
    if fuente is None:
        bloqueos.append(bloqueo("paquete", "el paquete no trae el ayudante de los agentes (hehermes-agentes)"))
        return False
    if ambito.root:
        # Suelto, como el lector: cambiarlo no pide reiniciar nada, cada conexión (y cada minuto) lanza el que haya.
        with open(fuente, "rb") as f:
            fichero(ambito.agentes, f.read(), 0o755)
    usuario = det.hermes.usuario if ambito.root else None
    # La unidad de Hermes, para encontrar su `hermes` (de su ExecStart) y reiniciarla una vez con el primer agente: la
    # que maneja también el de la copia.
    unidades = [fichero(ambito.unidad_agentes_socket, p.unidad_agentes_socket(ambito)),
                fichero(ambito.unidad_agentes, p.unidad_agentes(ambito, casa, usuario,
                                                                _unidad_para_el_respaldo(det.hermes, ambito)))]
    _unidad(sis, acciones, p.SOCKET_AGENTES, unidades, "los agentes (/avisos/v1/agentes), %s"
            % ("un ayudante de root por conexión, enjaulado, que crea, cambia y borra los perfiles de Hermes"
               if ambito.root else "como %s, uno por conexión" % ambito.usuario), "restart", ambito.systemctl)
    memoria = [fichero(ambito.unidad_agentes_memoria, p.unidad_agentes_memoria(ambito, casa, usuario)),
               fichero(ambito.temporizador_agentes_memoria, p.temporizador_agentes_memoria())]
    _unidad(sis, acciones, p.TEMPORIZADOR_AGENTES_MEMORIA, memoria, "lo que saben de ti los agentes que lo comparten, "
            "cada minuto (sin red)", "restart", ambito.systemctl)
    return True


def servicios_del_vigia(ambito, lector, respaldo, entrada, actualizar, agentes=False) -> list:
    """Las unidades de HeHermes cuyo estado enseña Ajustes › Tu servidor: las que se ponen aquí, de usuario sin root."""
    unidades = [p.UNIDAD_PASARELA, p.UNIDAD_VIGIA] + [u for u, si in ((p.SOCKET_LECTOR, lector),
                                                                     (p.SOCKET_RESPALDO, respaldo),
                                                                     (p.SOCKET_ENTRADA, entrada),
                                                                     (p.SOCKET_ACTUALIZAR, actualizar),
                                                                     (p.SOCKET_AGENTES, agentes),
                                                                     (p.TEMPORIZADOR_AGENTES_MEMORIA, agentes)) if si]
    return unidades if ambito.root else ["usuario:" + u for u in unidades]


def unidad_de_hermes_para_el_vigia(hermes, ambito) -> str | None:
    """La unidad de Hermes cuyo estado enseña Ajustes › Tu servidor, si el vigía la puede mirar: con root (el vigía es
    `hh-vigia`), una del sistema; sin root, una del sistema o una de usuario suya («usuario:»). Una de usuario de otro, un
    contenedor o un Hermes suelto (tmux), ninguna: la pantalla dice solo si contesta. Y solo con un nombre que el vigía
    sepa poner en `systemctl` (sin los escapes `\\x2d` de un cgroup)."""
    gestor = hermes.gestor
    if gestor is None or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.@-]{0,199}\.service", gestor.nombre):
        return None
    if gestor.tipo == "sistema":
        return gestor.nombre
    if gestor.tipo == "usuario" and not ambito.root and gestor.usuario == ambito.usuario:
        return "usuario:" + gestor.nombre
    return None


def _secreto(sis, man, acciones, ruta, deseado, reemplazar, detalle):
    estado = _gestionado(sis, man, ruta, deseado, reemplazar)
    datos = deseado if deseado is not None else sis.leer(ruta)
    acciones.append(Accion("gestionado", ruta, estado, detalle, datos, 0o600))
    return acciones[-1]


def rutas(ambito) -> set:
    """Lo del vigía y del lector que `aplicar_tls` deja para su propio paso (y no con los ficheros sueltos)."""
    return {ambito.vigia_ini, ambito.secreto_vigia, ambito.credencial_rele, ambito.clave_hermes_vigia,
            ambito.unidad_vigia, ambito.socket_vigia, ambito.unidad_lector_socket, ambito.unidad_lector,
            ambito.unidad_respaldo_socket, ambito.unidad_respaldo, ambito.unidad_entrada_socket, ambito.unidad_entrada,
            ambito.unidad_actualizar_socket, ambito.unidad_actualizar, ambito.unidad_agentes_socket,
            ambito.unidad_agentes, ambito.unidad_agentes_memoria, ambito.temporizador_agentes_memoria}


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
    crear_claves_de_agentes(sis, ambito, ambito.claves_agentes_vigia, p.USUARIO_VIGIA, orden)
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


def crear_claves_de_agentes(sis, ambito, carpeta, grupo, orden) -> None:
    """La carpeta de las claves de los agentes de la pasarela o del vigía (contrato §18.1): la escribe el ayudante, de
    root, y la lee la pasarela o el vigía. Con root, `root:<su grupo>` y 2750: con el bit setgid, cada clave nace del
    grupo de la carpeta (el ayudante no tiene CAP_CHOWN para dárselo). Sin root, 0700. No va al manifiesto (quitar la
    VPN de antes se llevaría una carpeta vacía que no lleva ficheros suyos): desinstalar la pasarela se lleva las claves
    y la carpeta por su nombre (`desinstalar._borrar_claves_de_agentes`)."""
    sis.carpeta(carpeta, 0o2750 if ambito.root else 0o700)
    if ambito.root:
        orden(sis, ["chown", "root:" + grupo, carpeta], "chown de %s" % carpeta)
        # Un chown no le quita el setgid a una carpeta, pero así queda dicho y no depende de eso.
        sis.carpeta(carpeta, 0o2750)


def crear_exportaciones(sis, man, hermes, ambito, salida) -> None:
    """`<HERMES_HOME>/exports`: donde Hermes deja lo que quiere mandarle al iPhone (con `MEDIA:`), lo único de su casa que
    el lector lee además de sus caches. Del dueño de la casa de Hermes y solo suya. Va al manifiesto aparte
    (`exportaciones`), con la pasarela: desinstalarla la quita solo si está vacía (lo que Hermes deje ahí es suyo)."""
    ruta = hermes.home.rstrip("/") + "/" + p.EXPORTACIONES
    if sis.es_carpeta(ruta) or not sis.es_carpeta(hermes.home):
        return
    man.datos["exportaciones"] = ruta
    man.guardar(sis)
    sis.carpeta(ruta, 0o700)
    if ambito.root and hermes.usuario and hermes.usuario != "root":
        r = sis.ejecutar(["chown", "%s:" % hermes.usuario, ruta])
        if not r.bien:
            salida("    No he podido darle %s a %s: el lector no podrá leerla" % (ruta, hermes.usuario))
    salida("==> la carpeta de exportaciones de Hermes: %s (lo que deje ahí con MEDIA:, la app lo descarga)" % ruta)


def crear_entrada(sis, man, hermes, ambito, salida) -> None:
    """`<HERMES_HOME>/entrada`: donde el ayudante deja lo que la app le manda a Hermes, lo único de las casas que ve.
    Del dueño de la casa de Hermes y solo suya, como `exports/`. Va al manifiesto aparte (`entrada`), con la pasarela:
    desinstalarla quita lo que el ayudante dejó a medias (`.subidas`) y la carpeta solo si se queda vacía (lo entregado
    ya es de Hermes)."""
    ruta = hermes.home.rstrip("/") + "/" + p.CARPETA_ENTRADA
    if sis.es_carpeta(ruta) or not sis.es_carpeta(hermes.home):
        return
    man.datos["entrada"] = ruta
    man.guardar(sis)
    sis.carpeta(ruta, 0o700)
    if ambito.root and hermes.usuario and hermes.usuario != "root":
        r = sis.ejecutar(["chown", "%s:" % hermes.usuario, ruta])
        if not r.bien:
            salida("    No he podido darle %s a %s: el ayudante de la entrada no podrá escribir en ella"
                   % (ruta, hermes.usuario))
    salida("==> la carpeta de entrada de Hermes: %s (lo que la app le manda, Hermes lo lee de ahí)" % ruta)


def aplicar_unidades(sis, man, acciones, ambito, salida, hermes=None) -> None:
    """El lector y los ayudantes primero (el vigía los quiere, `Wants=`), luego el puerto del vigía y el vigía."""
    from .aplicar import _con_unidad
    del_lector = [a for a in acciones if a.objeto in (ambito.unidad_lector_socket, ambito.unidad_lector,
                                                        p.SOCKET_LECTOR)]
    if hermes is not None and any(a.objeto == ambito.unidad_lector for a in acciones):
        crear_exportaciones(sis, man, hermes, ambito, salida)
    if del_lector:
        _con_unidad(sis, man, del_lector, p.SOCKET_LECTOR, salida, systemctl=ambito.systemctl)
    del_respaldo = [a for a in acciones if a.objeto in (ambito.unidad_respaldo_socket, ambito.unidad_respaldo,
                                                          p.SOCKET_RESPALDO)]
    if del_respaldo:
        _con_unidad(sis, man, del_respaldo, p.SOCKET_RESPALDO, salida, systemctl=ambito.systemctl)
    if hermes is not None and any(a.objeto == ambito.unidad_entrada for a in acciones):
        crear_entrada(sis, man, hermes, ambito, salida)
    de_la_entrada = [a for a in acciones if a.objeto in (ambito.unidad_entrada_socket, ambito.unidad_entrada,
                                                           p.SOCKET_ENTRADA)]
    if de_la_entrada:
        _con_unidad(sis, man, de_la_entrada, p.SOCKET_ENTRADA, salida, systemctl=ambito.systemctl)
    del_actualizar = [a for a in acciones if a.objeto in (ambito.unidad_actualizar_socket, ambito.unidad_actualizar,
                                                            p.SOCKET_ACTUALIZAR)]
    if del_actualizar:
        _con_unidad(sis, man, del_actualizar, p.SOCKET_ACTUALIZAR, salida, systemctl=ambito.systemctl)
    de_los_agentes = [a for a in acciones if a.objeto in (ambito.unidad_agentes_socket, ambito.unidad_agentes,
                                                            p.SOCKET_AGENTES)]
    if de_los_agentes:
        _con_unidad(sis, man, de_los_agentes, p.SOCKET_AGENTES, salida, systemctl=ambito.systemctl)
    de_la_memoria = [a for a in acciones if a.objeto in (ambito.unidad_agentes_memoria,
                                                           ambito.temporizador_agentes_memoria,
                                                           p.TEMPORIZADOR_AGENTES_MEMORIA)]
    if de_la_memoria:
        _con_unidad(sis, man, de_la_memoria, p.TEMPORIZADOR_AGENTES_MEMORIA, salida, systemctl=ambito.systemctl)
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
    if ambito.unidad_respaldo_socket in man.ficheros:
        respaldo = sis.ejecutar(ambito.systemctl + ["is-active", p.SOCKET_RESPALDO]).bien
        mira(respaldo, "copia en iCloud: el socket de su ayudante está en marcha (%s)" % ambito.socket_respaldo,
             "copia en iCloud: el socket de su ayudante está parado (%ssystemctl %sstart %s)"
             % ("sudo " if ambito.root else "", "" if ambito.root else "--user ", p.SOCKET_RESPALDO))
    if ambito.unidad_entrada_socket in man.ficheros:
        entrada = sis.ejecutar(ambito.systemctl + ["is-active", p.SOCKET_ENTRADA]).bien
        mira(entrada, "entrada de ficheros: el socket de su ayudante está en marcha (%s)" % ambito.socket_entrada,
             "entrada de ficheros: el socket de su ayudante está parado (%ssystemctl %sstart %s)"
             % ("sudo " if ambito.root else "", "" if ambito.root else "--user ", p.SOCKET_ENTRADA))
    if ambito.unidad_actualizar_socket in man.ficheros:
        actualizar = sis.ejecutar(ambito.systemctl + ["is-active", p.SOCKET_ACTUALIZAR]).bien
        mira(actualizar, "actualizar desde la app: el socket de su ayudante está en marcha (%s)"
             % ambito.socket_actualizar,
             "actualizar desde la app: el socket de su ayudante está parado (sudo systemctl start %s)"
             % p.SOCKET_ACTUALIZAR)
    if ambito.unidad_agentes_socket in man.ficheros:
        como = ("sudo " if ambito.root else "", "" if ambito.root else "--user ")
        mira(sis.ejecutar(ambito.systemctl + ["is-active", p.SOCKET_AGENTES]).bien,
             "agentes: el socket de su ayudante está en marcha (%s)" % ambito.socket_agentes,
             "agentes: el socket de su ayudante está parado (%ssystemctl %sstart %s)" % (como + (p.SOCKET_AGENTES,)))
        mira(sis.ejecutar(ambito.systemctl + ["is-active", p.TEMPORIZADOR_AGENTES_MEMORIA]).bien,
             "agentes: la memoria que comparten se junta cada minuto (%s)" % p.TEMPORIZADOR_AGENTES_MEMORIA,
             "agentes: la memoria que comparten no se junta: su temporizador está parado (%ssystemctl %sstart %s)"
             % (como + (p.TEMPORIZADOR_AGENTES_MEMORIA,)))
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
        # Lo de los agentes lo mira el vigía (le pregunta a su ayudante), pero se dice como suyo: «agentes: …».
        texto = texto if texto.startswith("agentes: ") else "vigía: " + texto
        mira(bien, texto, texto)
