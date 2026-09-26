"""El modo TLS del instalador (spec 2026-09-26): la pasarela. Desde la 0.6.0 es lo único que se instala. Detectar,
planear, aplicar y comprobar.

Reutiliza lo de siempre (el manifiesto, las transacciones de `aplicar`, el cortafuegos, la API de Hermes), pero no
toca nada de una VPN: ni strongSwan, ni nginx, ni XFRM, ni `/etc/hehermes/servidor.ini`, que es lo que lee el
`hehermes-dispositivo` para quitar las altas de la VPN de antes. Por eso puede convivir con una (la de una versión
anterior del instalador, o una hecha a mano) hasta que se quite.

Con root: un usuario propio (`hh-pasarela`), la unidad de sistema con su sandbox, las credenciales, la copia de la
clave de Hermes vigilada y la regla del cortafuegos. Sin root: todo en la casa del usuario, una unidad de
`systemctl --user`, sin paquetes y sin tocar el cortafuegos (se dice qué abrir).
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time

from . import ambito as amb
from . import manifiesto as m
from . import piezas as p
from .aplicar import Parada, Transaccion, _con_unidad, _escribir, _ficheros, _firewalld, _orden, _paquetes, _propio, _ufw
from .deteccion import Deteccion, _cortafuegos, _direccion, _distro, _escuchan, _hermes, regla_ufw_canonica
from .entorno import leer_env
from .plan import Accion, Plan, _unidad, buscar_en_origen, ficheros_propios

TOKENS_VACIO = b'{\n  "v": 1,\n  "tokens": []\n}\n'
#: En la familia Debian, `venv` sin `ensurepip` viene aparte.
PAQUETE_VENV = "python3-venv"
DIAS_CERTIFICADO = 3650


# MARK: Detectar


def detectar_tls(sis, man, ambito, direccion=None, hermes_home=None, activar_api=False, cortafuegos_a_mano=False,
                 corregir_exposicion=False) -> Deteccion:
    det = Deteccion()
    det.modo, det.ambito = "tls", ambito
    det.puerto_pasarela = None
    det.con_vigia = False
    det.usuario_pasarela = False
    det.gestor_usuario = det.linger = None
    det.dispositivo_ajeno = False
    det.venv_listo = False
    if not _distro(sis, det):
        return det
    _hermes(sis, det, hermes_home, activar_api, corregir_exposicion)
    if not ambito.root and det.hermes is not None and (det.hermes.api_pendiente or det.hermes.exposicion_pendiente):
        det.bloqueos.append("Para encender la API de Hermes o cerrarla a 127.0.0.1 hay que reiniciarlo, y sin root no "
                            "sé. Hazlo tú en %s (API_SERVER_ENABLED=true, API_SERVER_HOST=127.0.0.1 y una "
                            "API_SERVER_KEY) y reinicia Hermes; luego vuelve a lanzarme" % det.hermes.env)
    _direccion(sis, det, direccion)
    det.puerto_pasarela = _puerto(sis, man)
    _python_venv(sis, det, ambito)
    _systemd(sis, det, ambito)
    if ambito.root:
        det.usuario_pasarela = sis.ejecutar(["id", "-u", p.USUARIO_PASARELA]).bien
        det.con_vigia = sis.existe(p.SECRETO_VIGIA)
        _cortafuegos(sis, det, cortafuegos_a_mano, puerto_pasarela=det.puerto_pasarela)
    else:
        det.avisos.append("No corro como root, así que ni miro ni toco el cortafuegos. Si este servidor tiene uno (ufw, "
                          "firewalld, nftables…), o tu proveedor tiene el suyo en su panel, tiene que dejar entrar el "
                          "TCP %d (la pasarela) desde internet" % det.puerto_pasarela)
    _convivir(sis, det, man, ambito)
    return det


def _puerto(sis, man) -> int:
    """El de la instalación, si ya lo hay: fijo desde que se eligió. Si no, uno libre al azar del rango."""
    from .porchat import _puertos_tcp_ocupados, elegir_puerto
    dado = (man.datos.get("pasarela") or {}).get("puerto")
    if isinstance(dado, int) and p.PUERTO_MINIMO <= dado <= p.PUERTO_MAXIMO:
        return dado
    return elegir_puerto(_puertos_tcp_ocupados(sis))


def _python_venv(sis, det, ambito):
    """El venv de `cryptography` (el del canje) hace falta para el certificado. Sin `ensurepip` (en Debian, sin
    python3-venv) no se puede crear: con root se instala el paquete; sin root, se dice."""
    from .porchat import venv_listo
    det.venv_listo = venv_listo(sis, ambito)
    if det.venv_listo:
        return
    if sis.ejecutar(["python3", "-I", "-c", "import ensurepip, venv"]).bien:
        return
    if ambito.root and det.familia == "debian":
        det.falta_venv = True
        return
    det.bloqueos.append("A este Python le falta venv (en Debian y Ubuntu, el paquete %s), y sin él no puedo preparar "
                        "cryptography para el certificado. Que un administrador lo instale (sudo apt install %s) y "
                        "vuelve a lanzarme" % (PAQUETE_VENV, PAQUETE_VENV))


def _systemd(sis, det, ambito):
    """Con root, systemd del sistema (lo mira `_distro`). Sin root, una unidad de usuario: con linger sigue siempre;
    sin él, solo mientras haya una sesión abierta, y sin gestor de usuario no hay forma (y no me invento otra)."""
    if ambito.root:
        return
    r = sis.ejecutar(["loginctl", "show-user", ambito.usuario, "-p", "Linger"])
    det.linger = r.bien and r.salida.strip() == "Linger=yes"
    det.gestor_usuario = sis.ejecutar(["systemctl", "--user", "is-system-running"]).salida.strip() in (
        "running", "degraded", "starting")
    if det.linger:
        return
    if det.gestor_usuario:
        det.avisos.append("Sin linger, la pasarela se para cuando cierres tu última sesión en este servidor. Para que "
                          "siga siempre, que un administrador ejecute: sudo loginctl enable-linger %s" % ambito.usuario)
        return
    det.bloqueos.append("Sin root, la pasarela solo puede arrancar como una unidad de tu systemd de usuario, y aquí no "
                        "hay ninguno en marcha (ni linger ni una sesión). Que un administrador ejecute: sudo loginctl "
                        "enable-linger %s; o que instale como root (sudo). No me invento otro arranque" % ambito.usuario)


def _convivir(sis, det, man, ambito):
    """Una VPN de HeHermes, hecha a mano o de una versión anterior del instalador, no impide la pasarela: van por
    separado, y la pasarela se añade a su lado. Si la VPN es del instalador, las dos quedan en el mismo manifiesto, y
    la VPN se quita sin tocar la pasarela (`desinstalar --modo vpn`). Desde la 0.6.0 la VPN ya no se instala ni se
    repara: solo se dice que sigue ahí y cómo quitarla."""
    if "vpn" in man.modos:
        det.avisos.append("Aquí sigue la VPN IKEv2 que instaló una versión anterior (%s). Desde la 0.6.0 ya no la "
                          "instalo ni la reparo, y no la toco: la pasarela va a su lado, en su puerto. Cuando tus "
                          "iPhone vayan por la pasarela, quítala con: sudo hehermes-servidor desinstalar --modo vpn"
                          % man.ruta)
    elif ambito.root:
        vpn = [r for r in (p.SITIO, p.SITIO_CONF_D, "/etc/swanctl/conf.d/hehermes-poc.conf", "/etc/wireguard/hehermes")
               if sis.existe(r)] + (["hh-ipsec"] if sis.ejecutar(["ip", "link", "show", p.INTERFAZ]).bien else [])
        if vpn:
            det.avisos.append("Aquí hay una VPN de HeHermes (%s). No la toco: la pasarela va aparte, en su puerto, y "
                              "las dos conviven" % ", ".join(vpn))
    if sis.existe(ambito.dispositivo) and ambito.dispositivo not in man.ficheros:
        det.dispositivo_ajeno = True
        det.avisos.append("%s no es mío: no lo toco. Para los iPhone de la pasarela usa el mío: %s %s/hehermes-dispositivo "
                          "alta <nombre>" % (ambito.dispositivo, "sudo" if ambito.root else "", ambito.prefijo))


# MARK: El plan


def calcular_plan_tls(sis, det, man, op, origen) -> Plan:
    acciones, bloqueos, avisos = [], list(det.bloqueos), list(det.avisos)
    det.al_lado = "vpn" in man.modos
    ambito = det.ambito
    if not det.distro.get("arquitectura") or det.hermes is None or det.hermes.clave is None:
        return Plan(det, acciones, bloqueos, avisos, op)

    def fichero(ruta, contenido, modo=0o644, tipo="fichero", grupo=None, detalle=""):
        datos = contenido.encode() if isinstance(contenido, str) else contenido
        estado = m.clasificar(sis, man, ruta, datos, reemplazar=op.reemplazar)
        acciones.append(Accion(tipo, ruta, estado, detalle, datos, modo, grupo))
        return acciones[-1]

    if getattr(det, "falta_venv", False):
        acciones.append(Accion("paquete", PAQUETE_VENV, m.NUEVO, "para el venv de cryptography"))

    # La API de Hermes
    if det.hermes.api_pendiente:
        nombres = ", ".join(linea.split("=", 1)[0] for linea in det.hermes.api_pendiente)
        acciones.append(Accion("env", det.hermes.env, m.NUEVO, "añade %s (con una copia antes); reinicia Hermes 90 s "
                                                               "después de acabar" % nombres, det.hermes.api_pendiente))
    if det.hermes.exposicion_pendiente:
        acciones.append(Accion("exposicion", det.hermes.env, m.NUEVO, "añade %s (con una copia antes), para que la API "
                               "de Hermes solo escuche en 127.0.0.1; reinicia Hermes 90 s después de acabar"
                               % det.hermes.exposicion_pendiente, [det.hermes.exposicion_pendiente]))

    # El usuario de la pasarela
    if ambito.root:
        acciones.append(Accion("usuario", p.USUARIO_PASARELA, m.YA_ESTA if det.usuario_pasarela else m.NUEVO,
                               "sin casa ni shell, solo para la pasarela"))

    # El instalador y sus órdenes
    for ruta, datos, modo in ficheros_propios(origen, ambito.prefijo):
        fichero(ruta, datos, modo, grupo=ambito.prefijo + "/")
    estado = m.clasificar(sis, man, ambito.orden, destino_enlace=ambito.prefijo + "/hehermes-servidor",
                          reemplazar=op.reemplazar)
    acciones.append(Accion("enlace", ambito.orden, estado, "-> " + ambito.prefijo + "/hehermes-servidor",
                           ambito.prefijo + "/hehermes-servidor"))
    fuente = buscar_en_origen(origen, "hehermes-dispositivo", "../vpn/hehermes-dispositivo")
    if fuente is None:
        bloqueos.append("el paquete no trae hehermes-dispositivo")
    elif not det.dispositivo_ajeno:
        with open(fuente, "rb") as f:
            fichero(ambito.dispositivo, f.read(), 0o750 if ambito.root else 0o700)

    # El venv y el certificado
    acciones.append(Accion("venv", ambito.venv, m.YA_ESTA if det.venv_listo else m.NUEVO,
                           "cryptography, fijada por hash, para el certificado y el canje"))
    hay_cert = sis.existe(ambito.cert) and sis.existe(ambito.clave)
    acciones.append(Accion("certificado", ambito.cert, m.YA_ESTA if hay_cert and ambito.cert in man.ficheros else
                           (m.AJENO if hay_cert else m.NUEVO),
                           "ECDSA P-256, autofirmado y sin datos, diez años; la app ancla su huella"))

    # La pasarela
    pasarela = [
        fichero(ambito.pasarela_ini, p.pasarela_ini(ambito, det.puerto_pasarela, det.hermes.puerto, det.hermes.env,
                                                    det.direccion or "PENDIENTE", det.con_vigia),
                0o640 if ambito.root else 0o600, detalle="en el TCP %d" % det.puerto_pasarela),
        fichero(ambito.tokens, TOKENS_VACIO, 0o640 if ambito.root else 0o600, tipo="gestionado",
                detalle="solo el SHA-256 de cada token"),
    ]
    if ambito.root:
        pasarela.append(fichero(ambito.clave_hermes, det.hermes.clave + "\n", 0o600, tipo="gestionado",
                                detalle="la clave de Hermes, 0600 (no se imprime)"))
    pasarela.append(fichero(ambito.unidad, p.unidad_pasarela(ambito, det.con_vigia)))
    _unidad(sis, acciones, p.UNIDAD_PASARELA, pasarela + [a for a in acciones if a.tipo == "certificado"],
            "la pasarela, en el TCP %d" % det.puerto_pasarela, "restart", ambito.systemctl)
    if ambito.root:
        clave = [fichero(p.UNIDAD_PASARELA_CLAVE_SERVICE, p.unidad_pasarela_clave_service()),
                 fichero(p.UNIDAD_PASARELA_CLAVE_PATH, p.unidad_pasarela_clave_path(det.hermes.env))]
        _unidad(sis, acciones, "hehermes-pasarela-clave.path", clave, "si cambia la clave de Hermes, se la copia a la "
                "pasarela", "restart")

    # El cortafuegos, solo con root
    if ambito.root:
        _plan_cortafuegos(sis, det, man, acciones, fichero)

    # El primer iPhone
    if op.iphone is not None:
        from .plan import NOMBRE_VALIDO
        if not NOMBRE_VALIDO.match(op.iphone):
            bloqueos.append("el nombre del iPhone tiene que ser de minúsculas, números y guiones, hasta 31 (no «%s»)"
                            % op.iphone)
        else:
            ya = op.iphone in nombres_de_la_pasarela(sis, ambito)
            if op.por_chat:
                detalle = "ya dado de alta" if ya else "su token, sin QR (se entrega por el canje)"
            elif not op.terminal:
                detalle = "ya dado de alta" if ya else "sin un terminal no pinto su QR: lo dejo para después"
            else:
                detalle = "ya dado de alta" if ya else "su token y su QR, aquí en el terminal"
            acciones.append(Accion("dispositivo", op.iphone, m.YA_ESTA if ya else m.NUEVO, detalle))

    if op.por_chat:
        from . import porchat
        bloqueos.extend(porchat.bloqueos(sis, man, op, op.ahora,
                                         activos=porchat.activos_del_servidor(sis, man, ambito)))
        acciones.append(Accion("canje", "hehermes-canje", m.NUEVO,
                               "10 minutos en un TCP al azar del 58000 al 65500, %sde un solo uso; al acabar, la línea "
                               "del enlace" % ("abierto solo mientras dura y " if ambito.root else "")))

    for a in acciones:
        if a.estado == m.AJENO:
            bloqueos.append("%s no es mío (no está en mi manifiesto): no lo toco. Si quieres que lo sustituya, "
                            "guardando antes una copia: --reemplazar %s" % (a.objeto, a.objeto)
                            if a.tipo != "certificado" else
                            "%s no es mío (no está en mi manifiesto): no lo toco. Si es de una instalación vieja, "
                            "bórralo tú (y su clave.pem) y vuelve a lanzarme" % a.objeto)
        elif a.estado == m.MODIFICADO:
            bloqueos.append("%s es mío, pero alguien lo ha cambiado desde que lo escribí: no lo toco. Si quieres que "
                            "lo sustituya, guardando antes una copia: --reemplazar %s" % (a.objeto, a.objeto))
    return Plan(det, acciones, bloqueos, avisos, op)


def _plan_cortafuegos(sis, det, man, acciones, fichero):
    from . import cortafuegos as cf
    puerto = det.puerto_pasarela
    if det.ufw is not None:
        hay = {regla_ufw_canonica(r) for r in det.reglas_ufw}
        for regla in p.reglas_ufw("tls", puerto):
            if regla_ufw_canonica(regla.texto) in hay:
                estado = m.YA_ESTA if regla.texto in man.reglas else m.AJENO_IGUAL
            else:
                estado = m.NUEVO
            acciones.append(Accion("regla", regla.nombre, estado, regla.texto, regla.args))
    if det.firewalld is not None:
        for regla in p.reglas_firewalld("tls", puerto):
            if regla.opcion in det.reglas_firewalld:
                estado = m.YA_ESTA if regla.texto in man.reglas else m.AJENO_IGUAL
            else:
                estado = m.NUEVO
            acciones.append(Accion("firewalld", regla.nombre, estado, regla.opcion, regla))
    # Con la VPN al lado, en cada cadena van también las suyas: todas llevan la misma marca.
    reglas = cf.permanentes_de(man.datos, modos=set(man.modos) | {"tls"}, puerto=puerto)
    for lugar in det.lugares:
        estado = m.YA_ESTA if lugar.marcadas >= len(reglas) else m.NUEVO
        acciones.append(Accion("propio", lugar.nombre, estado, "%s, %s (con el comentario %s)" % (
            " y ".join(r.nombre for r in reglas), lugar.donde, cf.MARCA), lugar))
    _unidad(sis, acciones, "hehermes-cortafuegos.service",
            [fichero(p.UNIDAD_CORTAFUEGOS, p.unidad_cortafuegos())],
            "al arrancar, vuelve a poner sus reglas y quita las del canje", "reload")


def nombres_de_la_pasarela(sis, ambito) -> list:
    try:
        datos = json.loads(sis.leer(ambito.tokens) or b"{}")
    except ValueError:
        return []
    return [t.get("nombre") for t in datos.get("tokens", []) if isinstance(t, dict)]


# MARK: Aplicar


def aplicar_tls(sis, plan, man, origen, salida=print, terminal=False) -> dict:
    """Aplica el plan en orden, con el manifiesto al día tras cada paso. Devuelve {"token": …} del primer iPhone si se
    ha dado de alta por chat (lo necesita el canje), o {}."""
    if not plan.puede_seguir:
        raise Parada("el plan tiene bloqueos")
    det, acciones, ambito = plan.deteccion, plan.acciones, plan.deteccion.ambito
    systemctl = ambito.systemctl
    if not man.en_disco and "instalado" not in man.datos:
        man.datos["instalado"] = time.time()
    man.anadir_modo("tls")
    man.datos["pasarela"] = {"puerto": det.puerto_pasarela, "root": ambito.root}
    if det.familia != "debian":
        man.datos["familia"] = det.familia
    man.guardar(sis)
    de = lambda *tipos: [a for a in acciones if a.tipo in tipos]  # noqa: E731

    for a in de("env"):
        from .porchat import activar_api
        activar_api(sis, man, a, salida)
    for a in de("exposicion"):
        from .porchat import corregir_exposicion
        corregir_exposicion(sis, man, a, salida)
    _paquetes(sis, man, de("paquete"), salida, det.familia)
    for a in de("usuario"):
        if a.cambia:
            _orden(sis, ["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell",
                         "/usr/sbin/nologin", "--user-group", a.objeto], "crear el usuario %s" % a.objeto)
            man.datos.setdefault("usuarios", [])
            if a.objeto not in man.datos["usuarios"]:
                man.datos["usuarios"].append(a.objeto)
            man.guardar(sis)
            salida("==> el usuario %s" % a.objeto)

    pasarela = {ambito.pasarela_ini, ambito.tokens, ambito.clave_hermes, ambito.unidad}
    unidades = {p.UNIDAD_PASARELA_CLAVE_PATH, p.UNIDAD_PASARELA_CLAVE_SERVICE, p.UNIDAD_CORTAFUEGOS}
    sueltos = [a for a in acciones if a.tipo in ("fichero", "enlace") and a.objeto not in pasarela | unidades]
    _ficheros(sis, man, sueltos, "ficheros", salida)

    # La carpeta de la pasarela: con root, 0750 y del grupo hh-pasarela, que tiene que llegar a pasarela.ini, al
    # certificado y a tokens.json (la clave del certificado y la de Hermes le llegan por credenciales).
    if not sis.es_carpeta(ambito.carpeta_pasarela):
        man.apuntar_carpetas(sis, ambito.carpeta_pasarela + "/x")
    sis.carpeta(ambito.carpeta_pasarela, 0o750 if ambito.root else 0o700)
    if ambito.root:
        _orden(sis, ["chown", "root:" + p.USUARIO_PASARELA, ambito.carpeta_pasarela], "chown de la pasarela")
    man.guardar(sis)

    from .porchat import ParadaDelCanje, _venv
    try:
        _venv(sis, man, salida, ambito)
    except ParadaDelCanje as error:
        raise Parada(str(error))
    for a in de("certificado"):
        if a.cambia:
            salida("==> el certificado de la pasarela")
            r = sis.ejecutar([ambito.python_venv, "-I", "-B", "-m", "hehermes_servidor.canje", "preparar",
                              ambito.carpeta_pasarela, "--dias", str(DIAS_CERTIFICADO)])
            if not r.bien:
                raise Parada("no he podido crear el certificado de la pasarela: %s" % (r.error or r.salida).strip())
            sis.escribir(ambito.cert, sis.leer(ambito.cert) or b"", modo=0o644)
            man.apuntar_gestionado(ambito.cert)
            man.apuntar_gestionado(ambito.clave)
            man.guardar(sis)
            salida("    huella %s" % huella(sis, ambito))

    def permisos(escritos):
        if not ambito.root:
            return
        for accion in escritos:
            if accion.objeto in (ambito.pasarela_ini, ambito.tokens):
                _orden(sis, ["chown", "root:" + p.USUARIO_PASARELA, accion.objeto], "chown de %s" % accion.objeto)

    _con_unidad(sis, man, [a for a in acciones if a.objeto in pasarela or a.objeto == p.UNIDAD_PASARELA],
                p.UNIDAD_PASARELA, salida, systemctl=systemctl, despues=permisos)
    if ambito.root:
        _con_unidad(sis, man, [a for a in acciones if a.objeto in (p.UNIDAD_PASARELA_CLAVE_PATH,
                                                                    p.UNIDAD_PASARELA_CLAVE_SERVICE,
                                                                    "hehermes-pasarela-clave.path")],
                    "hehermes-pasarela-clave.path", salida)
        _ufw(sis, man, de("regla"), salida)
        _firewalld(sis, man, det, de("firewalld"), salida)
        _propio(sis, man, det, de("propio"), salida)
        _con_unidad(sis, man, [a for a in acciones if a.objeto in (p.UNIDAD_CORTAFUEGOS, "hehermes-cortafuegos.service")],
                    "hehermes-cortafuegos.service", salida)

    _esperar_a_la_pasarela(sis, det.puerto_pasarela)
    pendiente = any(a.tipo in ("env", "exposicion") and a.cambia for a in acciones)
    fallos = [texto for bien, texto in comprobar_tls(sis, man, ambito, hermes_pendiente=pendiente) if not bien]
    if fallos:
        raise Parada("la comprobación no pasa:\n  - " + "\n  - ".join(fallos))

    resultado = {}
    for a in de("dispositivo"):
        if not a.cambia:
            continue
        if not plan.opciones.por_chat and not terminal:
            salida("==> el iPhone «%s»: sin un terminal no pinto su QR (lleva su token). Desde el tuyo: %s%s alta %s"
                   % (a.objeto, "sudo " if ambito.root else "", "hehermes-dispositivo", a.objeto))
            continue
        from . import tokens
        salida("==> el iPhone «%s»" % a.objeto)
        token = tokens.alta(sis.ruta(ambito.tokens), a.objeto)
        if a.objeto not in man.dispositivos:
            man.dispositivos.append(a.objeto)
        if plan.opciones.por_chat:
            man.datos["por_chat"] = {"iphone": a.objeto, "alta": time.time()}
            resultado["token"] = token
        man.guardar(sis)
        if not plan.opciones.por_chat:
            from . import qr
            salida(qr.terminal(tokens.texto_qr(det.direccion, det.puerto_pasarela, huella(sis, ambito), token))
                   .rstrip("\n"))
            salida("Escanéalo desde la app HeHermes Mensajes. Lleva el token de «%s»: ni lo compartas ni le hagas "
                   "captura. No se puede volver a pintar: si hace falta otro, hehermes-dispositivo rotar %s."
                   % (a.objeto, a.objeto))
        del token
    return resultado


def _esperar_a_la_pasarela(sis, puerto, plazo=10.0):
    """Recién arrancada, la pasarela tarda un momento en escuchar: comprobar antes daría un falso «no contesta»."""
    limite = time.monotonic() + plazo
    while sis.sondear_pasarela(puerto) is None and time.monotonic() < limite:
        time.sleep(0.2)


def huella(sis, ambito) -> str | None:
    from .pasarela import huella_de_der
    texto = sis.leer_texto(ambito.cert)
    if not texto:
        return None
    try:
        return huella_de_der(ssl.PEM_cert_to_DER_cert(texto))
    except ValueError:
        return None


# MARK: Comprobar


def comprobar_tls(sis, man, ambito, hermes_pendiente=False) -> list:
    """(bien, texto) de cada cosa que tiene que estar en marcha. Solo lee (y se asoma a la pasarela sin token)."""
    from .pasarela import NO_ENCONTRADO, leer_clave_hermes
    resultados = []

    def mira(bien, si, no):
        resultados.append((bool(bien), si if bien else no))

    datos = man.datos.get("pasarela") or {}
    puerto = datos.get("puerto")
    en_marcha = sis.ejecutar(ambito.systemctl + ["is-active", p.UNIDAD_PASARELA]).bien
    mira(en_marcha, "pasarela: en marcha", "pasarela: parada (%sjournalctl %s-u hehermes-pasarela)"
         % ("sudo " if ambito.root else "", "" if ambito.root else "--user "))
    escucha = [h for h, puerto_, _ in _escuchan(sis, "tcp") if puerto_ == str(puerto)]
    mira(escucha, "pasarela: escucha en el TCP %s" % puerto, "pasarela: nadie escucha en el TCP %s" % puerto)
    sonda = sis.sondear_pasarela(puerto) if puerto else None
    esperada = huella(sis, ambito)
    if sonda is None:
        mira(False, "", "pasarela: no contesta TLS en 127.0.0.1:%s" % puerto)
    else:
        mira(sonda.get("huella") == esperada, "pasarela: su certificado es el del QR (huella %s)" % esperada,
             "pasarela: sirve otro certificado que el de %s: los QR dados no lo aceptarán" % ambito.cert)
        mira(sonda.get("respuesta") == NO_ENCONTRADO, "pasarela: sin token, el 404 de siempre",
             "pasarela: sin token contesta otra cosa que el 404 de siempre")
    ini = _ini(sis, ambito)
    env = ini.get("env")
    clave = leer_clave_hermes(sis.leer_texto(env) or "") if env else None
    if hermes_pendiente:
        mira(True, "Hermes: su API se enciende al reiniciarse, 90 s después de acabar", "")
    elif clave:
        estado, _ = sis.http_get("http://127.0.0.1:%s/api/sessions?limit=1" % ini.get("puerto", 8642),
                                 {"Authorization": "Bearer " + clave})
        mira(estado == 200, "Hermes: contesta con su clave", "Hermes: no contesta con su clave (%s)" % estado)
        if ambito.root:
            copia = leer_clave_hermes(sis.leer_texto(ambito.clave_hermes) or "")
            mira(copia == clave, "pasarela: su copia de la clave de Hermes está al día",
                 "pasarela: su copia de la clave de Hermes es vieja (Hermes le dirá 401). La pone al día: sudo "
                 "systemctl start hehermes-pasarela-clave")
    else:
        mira(False, "", "Hermes: no encuentro su clave (%s)" % env)
    if ambito.root:
        _comprobar_cortafuegos(sis, man, puerto, mira)
    else:
        r = sis.ejecutar(["loginctl", "show-user", ambito.usuario, "-p", "Linger"])
        if not (r.bien and r.salida.strip() == "Linger=yes"):
            mira(True, "pasarela: sin linger, se para al cerrar tu última sesión (sudo loginctl enable-linger %s)"
                 % ambito.usuario, "")
    return resultados


def _ini(sis, ambito) -> dict:
    import configparser
    ini = configparser.ConfigParser(interpolation=None)
    try:
        ini.read_string(sis.leer_texto(ambito.pasarela_ini) or "")
        return {"env": ini.get("hermes", "env", fallback=None), "puerto": ini.getint("hermes", "puerto", fallback=8642)}
    except (configparser.Error, ValueError):
        return {}


def _comprobar_cortafuegos(sis, man, puerto, mira):
    from . import cortafuegos as cf
    if man.datos.get("cortafuegos") == "firewalld":
        en_marcha = sis.ejecutar(["firewall-cmd", "--state"]).bien
        faltan = []
        for regla in p.reglas_firewalld("tls", puerto):
            miran = ([["firewall-cmd", regla.con("query")], ["firewall-cmd", "--permanent", regla.con("query")]]
                     if en_marcha else [["firewall-offline-cmd", regla.con("query")]])
            if not all(sis.ejecutar(orden).bien for orden in miran):
                faltan.append(regla.nombre)
        mira(not faltan, "firewalld: la regla de la pasarela está", "firewalld: falta la regla del TCP %s" % puerto)
    elif sis.cual("ufw"):
        added = sis.ejecutar(["ufw", "show", "added"]).salida
        hay = {regla_ufw_canonica(linea.strip()) for linea in added.splitlines()}
        faltan = [r.nombre for r in p.reglas_ufw("tls", puerto) if regla_ufw_canonica(r.texto) not in hay]
        mira(not faltan, "ufw: la regla de la pasarela está", "ufw: falta la regla del TCP %s" % puerto)
    propio = man.datos.get("cortafuegos_propio")
    if propio:
        lugares, dudas = cf.analizar(sis, propio.get("iptables", True))
        reglas = cf.permanentes_de(man.datos)
        faltan = [l.nombre for l in lugares if l.marcadas < len(reglas)]
        mira(not faltan and not dudas, "cortafuegos: la regla de la pasarela está (%s)" % (
            ", ".join(l.nombre for l in lugares) or "ninguna cadena cierra el paso"),
             "cortafuegos: falta la regla en %s" % ", ".join(faltan + dudas))


# MARK: La clave de Hermes, con root


def poner_al_dia_la_clave(sis, salida=print) -> int:
    """`hehermes-servidor pasarela-clave` (lo lanza `hehermes-pasarela-clave.path` cuando cambia el .env): si la clave
    de Hermes ya no es la de la copia de la pasarela, la copia y reinicia la pasarela. No la imprime nunca."""
    from .pasarela import leer_clave_hermes
    ambito = amb.de_root()
    env = _ini(sis, ambito).get("env")
    clave = leer_clave_hermes(sis.leer_texto(env) or "") if env else None
    if not clave:
        salida("error: no encuentro la clave de Hermes (%s)" % env)
        return 1
    if leer_clave_hermes(sis.leer_texto(ambito.clave_hermes) or "") == clave:
        salida("la copia de la clave de Hermes de la pasarela ya está al día")
        return 0
    sis.escribir(ambito.clave_hermes, (clave + "\n").encode(), modo=0o600)
    sis.ejecutar(["systemctl", "try-restart", p.UNIDAD_PASARELA])
    salida("clave de Hermes copiada a la pasarela, y la pasarela reiniciada")
    return 0
