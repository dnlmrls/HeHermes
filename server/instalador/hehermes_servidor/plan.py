"""El plan: lo que haría el instalador, calculado de la detección, las piezas y el manifiesto, sin tocar nada.

`--plan` lo pinta y sale; `instalar` lo pinta, pregunta y lo aplica en este mismo orden.
"""

from __future__ import annotations

import json
import os
import re

from . import VERSION
from . import manifiesto as m
from . import piezas as p
from .deteccion import NORMAL, PAQUETE_SEMANAGE, ROJO

NOMBRE_VALIDO = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
PAQUETES = ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "qrencode", "nginx")
#: En la familia Red Hat, strongSwan es un solo paquete (con swanctl y charon-systemd), y `venv` va con python3.
PAQUETES_RPM = ("strongswan", "qrencode", "nginx")
# Lo que va en /opt/hehermes-servidor: con eso, `comprobar`, `actualizar` y `desinstalar` siguen ahí después de que se
# borre la carpeta temporal del comando.
PROPIOS = ("hehermes-servidor", "hehermes-pasarela", "clave-publica.pem", "requirements-canje.txt")
EJECUTABLES_PROPIOS = ("hehermes-servidor", "hehermes-pasarela")
#: Lo que hace falta además para el canje del alta por chat: su venv (en Debian y Ubuntu, `venv` sin `ensurepip` viene
#: aparte).
PAQUETES_POR_CHAT = ("python3-venv",)


class Opciones:
    def __init__(self, iphone=None, direccion=None, avisos=False, hermes_home=None, reemplazar=(), si=False,
                 solo_plan=False, por_chat=False, llave=None, activar_api=False, qr_png=None, ahora=None,
                 cortafuegos_a_mano=False, corregir_exposicion=False, modo="vpn"):
        #: «vpn» o «tls» (la pasarela).
        self.modo = modo
        #: Si hay alguien delante de un terminal (el QR de la pasarela solo se pinta ahí).
        self.terminal = True
        self.iphone = iphone
        self.direccion = direccion
        self.avisos = avisos
        self.hermes_home = hermes_home
        self.reemplazar = frozenset(reemplazar)
        self.si = si
        self.solo_plan = solo_plan
        # El alta por chat (pieza B): sin preguntar, sin QR y con el canje al final.
        self.por_chat = por_chat
        self.llave = llave
        self.activar_api = activar_api
        self.qr_png = qr_png
        #: La hora con la que se mide la media hora de la decisión 7; las pruebas la fijan.
        self.ahora = ahora
        #: El cortafuegos lo lleva el usuario: no se toca, aunque cierre (y no se sepa dónde abrirlo).
        self.cortafuegos_a_mano = cortafuegos_a_mano
        #: Permiso para cerrar a 127.0.0.1 una API de Hermes que escucha en todas las interfaces.
        self.corregir_exposicion = corregir_exposicion


class Accion:
    """Una cosa que el instalador deja. `tipo`: paquete, fichero, gestionado, enlace, quitar, unidad, recarga, regla,
    avisos o dispositivo. `datos`: el contenido (fichero), el destino (enlace) o los argumentos (regla)."""

    def __init__(self, tipo, objeto, estado, detalle="", datos=None, modo=0o644, grupo=None):
        self.tipo, self.objeto, self.estado, self.detalle = tipo, objeto, estado, detalle
        self.datos, self.modo, self.grupo = datos, modo, grupo

    @property
    def cambia(self) -> bool:
        return self.estado not in (m.YA_ESTA, m.AJENO_IGUAL)

    def __repr__(self):
        return "Accion(%s, %s, %s)" % (self.tipo, self.objeto, self.estado)


class Plan:
    def __init__(self, deteccion, acciones, bloqueos, avisos, opciones):
        self.deteccion, self.acciones, self.bloqueos, self.avisos = deteccion, acciones, bloqueos, avisos
        self.opciones = opciones

    @property
    def cambios(self) -> list:
        return [a for a in self.acciones if a.cambia]

    @property
    def puede_seguir(self) -> bool:
        return not self.bloqueos


def ficheros_propios(origen: str, prefijo: str = p.PREFIJO) -> list:
    """(ruta en /opt, contenido, modo) de lo que se copia del paquete: los lanzadores, el código y la clave pública. Sin
    root, `prefijo` es el de la casa del usuario (`ambito`)."""
    salida = []
    for nombre in PROPIOS:
        ruta = os.path.join(origen, nombre)
        if os.path.exists(ruta):
            with open(ruta, "rb") as f:
                salida.append((prefijo + "/" + nombre, f.read(), 0o755 if nombre in EJECUTABLES_PROPIOS else 0o644))
    # hehermes-dispositivo también: sin él, repetir o reparar desde lo instalado no tendría de dónde sacarlo.
    fuente = buscar_en_origen(origen, "hehermes-dispositivo", "../vpn/hehermes-dispositivo")
    if fuente is not None:
        with open(fuente, "rb") as f:
            salida.append((prefijo + "/hehermes-dispositivo", f.read(), 0o755))
    carpeta = os.path.join(origen, "hehermes_servidor")
    for nombre in sorted(os.listdir(carpeta)):
        if nombre.endswith(".py"):
            with open(os.path.join(carpeta, nombre), "rb") as f:
                salida.append((prefijo + "/hehermes_servidor/" + nombre, f.read(), 0o644))
    return salida


def buscar_en_origen(origen: str, *candidatas: str) -> str | None:
    """Un fichero del paquete, o del repositorio si se ejecuta desde él (`server/vpn`, `server/avisos`)."""
    for candidata in candidatas:
        ruta = os.path.normpath(os.path.join(origen, candidata))
        if os.path.exists(ruta):
            return ruta
    return None


def registro_de_dispositivos(sis) -> list:
    datos = sis.leer(p.REGISTRO + "/dispositivos.json")
    try:
        return [d for d in json.loads(datos or b"{}").get("dispositivos", []) if not d.get("baja")]
    except ValueError:
        return []


def calcular_plan(sis, det, man, op: Opciones, origen: str) -> Plan:
    acciones, bloqueos = [], list(det.bloqueos)
    avisos = list(det.avisos)
    det.al_lado = "tls" in man.modos
    if not det.distro.get("arquitectura") or det.hermes is None or det.hermes.clave is None:
        # Sin un sistema que se pueda instalar o sin un Hermes con su clave, no hay plan que enseñar.
        return Plan(det, acciones, bloqueos, avisos, op)

    def fichero(ruta, contenido, modo=0o644, tipo="fichero", grupo=None, detalle=""):
        datos = contenido.encode() if isinstance(contenido, str) else contenido
        estado = m.clasificar(sis, man, ruta, datos, reemplazar=op.reemplazar)
        acciones.append(Accion(tipo, ruta, estado, detalle, datos, modo, grupo))
        return acciones[-1]

    def enlace(ruta, destino):
        estado = m.clasificar(sis, man, ruta, destino_enlace=destino, reemplazar=op.reemplazar)
        acciones.append(Accion("enlace", ruta, estado, "-> " + destino, destino))

    # Paquetes
    rhel = det.familia == "rhel"
    if rhel:
        paquetes = PAQUETES_RPM
        if det.selinux and not sis.cual("semanage"):
            paquetes += (PAQUETE_SEMANAGE,)
    else:
        paquetes = PAQUETES + (PAQUETES_POR_CHAT if op.por_chat else ())
    for paquete in paquetes:
        instalado = paquete in det.paquetes_instalados
        acciones.append(Accion("paquete", paquete, m.YA_ESTA if instalado else m.NUEVO))
    charon = "strongswan" if rhel else "charon-systemd"
    if charon in det.paquetes_instalados and not det.strongswan["activo"] and charon not in man.paquetes:
        bloqueos.append("strongSwan está instalado pero parado. Si sirve para otras cosas, arráncalo tú "
                        "(strongswan.service) y vuelve a lanzarme")
    elif rhel:
        # dnf no arranca nada de lo que instala (apt sí): el strongSwan que instala él, lo arranca él.
        listo = det.strongswan["activo"]
        acciones.append(Accion("unidad", "strongswan.service", m.YA_ESTA if listo else m.NUEVO,
                               "strongSwan, en marcha" if listo else "habilitar y arrancar strongSwan (dnf no lo "
                                                                    "arranca)", "arrancar"))
    if rhel and "nginx" not in det.paquetes_instalados:
        avisos.append("El nginx de %s trae en su nginx.conf un servidor de bienvenida en el TCP 80 de todas las "
                      "direcciones. No lo toco (nginx.conf no es mío), y el cortafuegos no abre el 80" %
                      det.distro.get("base", "esta distribución"))

    # El instalador mismo, en /opt, y su orden
    for ruta, datos, modo in ficheros_propios(origen):
        fichero(ruta, datos, modo, grupo=p.PREFIJO + "/")
    enlace(p.ORDEN, p.PREFIJO + "/hehermes-servidor")

    # La API de Hermes (--activar-api): se apunta aquí y se aplica antes que nada, para que nginx lleve la clave nueva.
    if det.hermes.api_pendiente:
        nombres = ", ".join(linea.split("=", 1)[0] for linea in det.hermes.api_pendiente)
        acciones.append(Accion("env", det.hermes.env, m.NUEVO, "añade %s (con una copia antes); reinicia Hermes 90 s "
                                                               "después de acabar" % nombres, det.hermes.api_pendiente))

    # --corregir-exposicion: la API de Hermes, solo en 127.0.0.1.
    if det.hermes.exposicion_pendiente:
        acciones.append(Accion("exposicion", det.hermes.env, m.NUEVO, "añade %s (con una copia antes), para que la API "
                               "de Hermes solo escuche en 127.0.0.1; reinicia Hermes 90 s después de acabar"
                               % det.hermes.exposicion_pendiente, [det.hermes.exposicion_pendiente]))

    # Dispositivos
    fichero(p.SERVIDOR_INI, p.servidor_ini(det.direccion or "PENDIENTE", det.hermes.env, det.hermes.puerto,
                                           det.swanctl))
    fuente = buscar_en_origen(origen, "hehermes-dispositivo", "../vpn/hehermes-dispositivo")
    if fuente is None:
        bloqueos.append("el paquete no trae hehermes-dispositivo")
    else:
        with open(fuente, "rb") as f:
            fichero(p.DISPOSITIVO, f.read(), 0o750)

    # La interfaz XFRM
    xfrm = [fichero(p.SCRIPT_XFRM, p.script_xfrm(), 0o755), fichero(p.UNIDAD_XFRM, p.unidad_xfrm())]
    _unidad(sis, acciones, "hehermes-xfrm.service", xfrm, "crea %s (if_id %s, %s)" % (p.INTERFAZ, p.IF_ID, p.IP_TUNEL),
            "reload")

    # nginx
    nginx = [fichero(p.BEARER, p.bearer(det.hermes.clave), 0o600, tipo="gestionado",
                     detalle="la clave de Hermes, 0600 (no se imprime)")]
    if det.nginx["sitios"] == "conf.d":
        nginx.append(fichero(p.SITIO_CONF_D, p.sitio_nginx(det.hermes.puerto), detalle="solo en 10.77.0.1:80"))
    else:
        nginx.append(fichero(p.SITIO, p.sitio_nginx(det.hermes.puerto), detalle="solo en 10.77.0.1:80"))
        enlace(p.SITIO_ENLACE, p.SITIO)
        nginx.append(acciones[-1])
    nginx.append(fichero(p.DROP_IN_NGINX, p.drop_in_nginx(), detalle="nginx después de hh-ipsec"))
    nuestro = "nginx" not in det.paquetes_instalados or "nginx" in man.paquetes
    # El `default` solo existe con sites-enabled (Debian y Ubuntu); el de la familia Red Hat va en nginx.conf.
    if nuestro and det.nginx["sitios"] != "conf.d":
        # Si nginx lo instala él, su sitio `default` escucha en *:80 con la página de bienvenida: se apaga, y
        # desinstalar lo vuelve a poner.
        quitado = p.DEFAULT_NGINX in man.quitados and not sis.existe(p.DEFAULT_NGINX)
        acciones.append(Accion("quitar", p.DEFAULT_NGINX, m.YA_ESTA if quitado else m.NUEVO,
                               "el sitio de bienvenida de nginx, que escucha en todas las direcciones"))
        nginx.append(acciones[-1])
    cambia_nginx = any(a.cambia for a in nginx)
    acciones.append(Accion("recarga", "recargar nginx", m.NUEVO if cambia_nginx else m.YA_ESTA,
                           "nginx -t y reload (nunca restart)"))

    # ufw
    if det.ufw is not None:
        from .deteccion import regla_ufw_canonica
        hay = {regla_ufw_canonica(r) for r in det.reglas_ufw}
        for regla in p.reglas_ufw():
            if regla_ufw_canonica(regla.texto) in hay:
                estado = m.YA_ESTA if regla.texto in man.reglas else m.AJENO_IGUAL
            else:
                estado = m.NUEVO
            acciones.append(Accion("regla", regla.nombre, estado, regla.texto, regla.args))

    # firewalld (la familia Red Hat)
    if det.firewalld is not None:
        for regla in p.reglas_firewalld():
            if regla.opcion in det.reglas_firewalld:
                estado = m.YA_ESTA if regla.texto in man.reglas else m.AJENO_IGUAL
            else:
                estado = m.NUEVO
            acciones.append(Accion("firewalld", regla.nombre, estado, regla.opcion, regla))

    # nftables e iptables a pelo: en cada cadena que cierra, las reglas justas y con la marca (`cortafuegos`)
    from . import cortafuegos as cf
    # Con la pasarela al lado, en cada cadena van también las suyas: todas llevan la misma marca.
    reglas = cf.permanentes_de(man.datos, modos=set(man.modos) | {"vpn"})
    for lugar in det.lugares:
        estado = m.YA_ESTA if lugar.marcadas >= len(reglas) else m.NUEVO
        acciones.append(Accion("propio", lugar.nombre, estado, "%s, %s (con el comentario %s)" % (
            " y ".join(r.nombre for r in reglas), lugar.donde, cf.MARCA), lugar))
    # La unidad que las vuelve a poner tras un reinicio, y que quita la del canje si un reinicio la dejó en ufw.
    _unidad(sis, acciones, "hehermes-cortafuegos.service",
            [fichero(p.UNIDAD_CORTAFUEGOS, p.unidad_cortafuegos())],
            "al arrancar, vuelve a poner sus reglas y quita las del canje", "reload")

    # SELinux: el puerto de Hermes, para nginx
    if det.selinux:
        puerto = str(det.hermes.puerto)
        if det.selinux_puerto == "http_port_t":
            estado = m.YA_ESTA if puerto in man.datos.get("selinux_puertos", []) else m.AJENO_IGUAL
        else:
            estado = m.NUEVO
        acciones.append(Accion("selinux", "tcp/%s" % puerto, estado,
                               "http_port_t, para que nginx llegue a Hermes (semanage port), y restorecon de lo que "
                               "escribo", puerto))

    # La clave de Hermes, vigilada
    clave = [fichero(p.UNIDAD_CLAVE_SERVICE, p.unidad_clave_service()),
             fichero(p.UNIDAD_CLAVE_PATH, p.unidad_clave_path(det.hermes.env))]
    _unidad(sis, acciones, "hehermes-clave.path", clave, "si cambia la clave, la copia a nginx", "restart")

    # Avisos
    if op.avisos and rhel:
        bloqueos.append("Los avisos (--avisos), por ahora, solo en Debian y Ubuntu: su instalador usa apt. Vuelve a "
                        "lanzarme sin --avisos")
    elif op.avisos:
        fuente = buscar_en_origen(origen, "avisos/despliegue/instalar.sh", "../avisos/despliegue/instalar.sh")
        if fuente is None:
            bloqueos.append("el paquete no trae los avisos (avisos/despliegue/instalar.sh)")
        acciones.append(Accion("avisos", "avisos push", m.YA_ESTA if man.datos.get("avisos") else m.NUEVO,
                               "el instalar.sh de server/avisos: vigía y relé local", fuente))

    # El primer iPhone
    if op.iphone is not None:
        if not NOMBRE_VALIDO.match(op.iphone):
            bloqueos.append("el nombre del iPhone tiene que ser de minúsculas, números y guiones, hasta 31 (no «%s»)"
                            % op.iphone)
        else:
            ya = any(d.get("nombre") == op.iphone for d in registro_de_dispositivos(sis))
            if op.por_chat:
                detalle = "ya dado de alta" if ya else "alta IKEv2, sin QR (se entrega por el canje)"
            else:
                detalle = "ya dado de alta" if ya else "alta IKEv2 y su QR"
            acciones.append(Accion("dispositivo", op.iphone, m.YA_ESTA if ya else m.NUEVO, detalle))

    # El canje del alta por chat: cada vez que se lanza, uno nuevo (un enlace nuevo para la llave de esta frase).
    if op.por_chat:
        from . import porchat
        bloqueos.extend(porchat.bloqueos(sis, man, op, op.ahora,
                                         activos=porchat.activos_de_los_dos(sis, man, "vpn")))
        acciones.append(Accion("canje", "hehermes-canje", m.NUEVO,
                               "10 minutos en un TCP al azar del 58000 al 65500, abierto solo "
                               "mientras dura y de un solo uso; al acabar, la línea del enlace"))

    # Lo que no se pisa
    for a in acciones:
        if a.estado == m.AJENO:
            bloqueos.append("%s no es mío (no está en mi manifiesto): no lo toco. Si quieres que lo sustituya, "
                            "guardando antes una copia: --reemplazar %s" % (a.objeto, a.objeto))
        elif a.estado == m.MODIFICADO:
            bloqueos.append("%s es mío, pero alguien lo ha cambiado desde que lo escribí: no lo toco. Si quieres que "
                            "lo sustituya, guardando antes una copia: --reemplazar %s" % (a.objeto, a.objeto))
    return Plan(det, acciones, bloqueos, avisos, op)


def _unidad(sis, acciones, unidad, ficheros, detalle, como_recargar, systemctl=("systemctl",)):
    """Una unidad se habilita y arranca si no lo está; si solo cambian sus ficheros, se recarga: la XFRM con su
    `ExecReload`, que no tumba la interfaz, y la vigilancia de la clave (una `.path`, que no se puede recargar) con
    un restart, que es suya y no sirve a nada más. Sin root, `systemctl --user`."""
    activa = sis.ejecutar(list(systemctl) + ["is-active", unidad]).bien
    habilitada = sis.ejecutar(list(systemctl) + ["is-enabled", unidad]).bien
    if not (activa and habilitada):
        estado, que = m.NUEVO, "habilitar y arrancar: " + detalle
    elif any(f.cambia for f in ficheros):
        estado, que = m.CAMBIA, ("recargar (reload, sin cortar nada)" if como_recargar == "reload"
                                 else "reiniciar (es solo suya)")
    else:
        estado, que = m.YA_ESTA, detalle
    acciones.append(Accion("unidad", unidad, estado, que, como_recargar))


# MARK: Pintar


SECCIONES = (("Hermes", ("env", "exposicion")), ("Paquetes", ("paquete",)),
             ("La pasarela", ("usuario", "venv", "certificado")),
             ("Ficheros", ("fichero", "gestionado", "enlace", "quitar")),
             ("Servicios", ("unidad", "recarga")), ("Cortafuegos (ufw)", ("regla",)),
             ("Cortafuegos (firewalld)", ("firewalld",)), ("Cortafuegos (nftables e iptables)", ("propio",)), ("SELinux", ("selinux",)), ("Avisos push", ("avisos",)),
             ("iPhone", ("dispositivo",)), ("Canje por chat", ("canje",)))
ETIQUETAS = {m.NUEVO: "nuevo", m.YA_ESTA: "ya está", m.CAMBIA: "cambia", m.AJENO: "ajeno", m.MODIFICADO: "cambiado",
             m.AJENO_IGUAL: "ya está*", m.REEMPLAZA: "reemplaza"}


def pintar(plan: Plan, color: bool = False) -> str:
    det = plan.deteccion
    lineas = ["HeHermes servidor %s: el plan (no he cambiado nada)" % VERSION, ""]
    if det.distro.get("arquitectura"):
        lineas.append("  Sistema    %s, %s, núcleo %s, Python %s" % (
            det.distro["nombre"], det.distro["arquitectura"], det.distro.get("nucleo", "?").split("-")[0],
            det.distro.get("python", "?")))
    h = det.hermes
    if h is not None:
        estado_clave = {True: "la clave vale", False: "la clave NO vale", None: "sin probar la clave"}[h.clave_vale]
        lineas.append("  Hermes     %s (de %s, por %s), API en %s:%d, %s" % (h.env, h.usuario, h.origen, h.host,
                                                                            h.puerto, estado_clave))
    if det.direccion:
        lineas.append("  Dirección  %s (la que irá en el QR)" % det.direccion)
    tls = getattr(det, "modo", "vpn") == "tls"
    if tls:
        ambito = det.ambito
        lineas.append("  Modo       TLS: la pasarela, en el TCP %s%s%s" % (
            det.puerto_pasarela, "" if ambito.root else ", sin root (como %s, en su casa)" % ambito.usuario,
            ", al lado de la VPN IKEv2 (no la toco)" if getattr(det, "al_lado", False) else ""))
    else:
        lineas.append("  Modo       VPN IKEv2%s" % (", al lado de la pasarela TLS (no la toco)"
                                                   if getattr(det, "al_lado", False) else ""))
    estados = {"activo": "activo", "inactivo": "apagado (no lo enciendo)", None: "no está"}
    if tls and not det.ambito.root:
        pass  # sin root no se mira el cortafuegos
    elif det.distro.get("arquitectura") and det.firewalld is not None:
        lineas.append("  firewalld  %s" % estados[det.firewalld])
    elif det.distro.get("arquitectura"):
        lineas.append("  ufw        %s" % estados[det.ufw])
    if det.selinux:
        lineas.append("  SELinux    %s" % det.selinux)
    for titulo, tipos in SECCIONES:
        de_aqui = [a for a in plan.acciones if a.tipo in tipos]
        if titulo == "Avisos push" and not de_aqui and h is not None and tls:
            lineas += ["", titulo, "  %-10s %s" % ("sí" if det.con_vigia else "no",
                                                   "el vigía ya está: la pasarela le pasa /avisos/" if det.con_vigia
                                                   else "el relé central todavía no existe")]
            continue
        if titulo == "Avisos push" and not de_aqui and h is not None:
            lineas += ["", titulo, "  %-10s %s" % ("no", "el relé central todavía no existe; --avisos instala el "
                                                          "vigía y un relé local")]
            continue
        if titulo == "iPhone" and not de_aqui and h is not None and plan.opciones.iphone is None:
            lineas += ["", titulo, "  %-10s %s" % ("ninguno", "--iphone <nombre> lo da de alta y pinta su QR")]
            continue
        if titulo == "Cortafuegos (ufw)" and not de_aqui and tls and not det.ambito.root:
            lineas += ["", "Cortafuegos", "  %-10s %s" % ("no lo toco", "sin root: abre tú el TCP %s si hace falta"
                                                          % det.puerto_pasarela)]
            continue
        if not de_aqui:
            continue
        lineas += ["", titulo]
        agrupados = set()
        for a in de_aqui:
            if a.grupo:
                if a.grupo in agrupados:
                    continue
                agrupados.add(a.grupo)
                del_grupo = [x for x in de_aqui if x.grupo == a.grupo]
                estado = _estado_de_grupo(del_grupo)
                lineas.append("  %-10s %s (%d ficheros)" % (ETIQUETAS[estado], a.grupo, len(del_grupo)))
                continue
            texto = a.objeto + ("  " + a.detalle if a.detalle else "")
            lineas.append("  %-10s %s" % (ETIQUETAS[a.estado], texto))
    if any(a.estado == m.AJENO_IGUAL for a in plan.acciones):
        lineas += ["", "  * ya está, pero no es mío: no lo apunto y desinstalar no lo quita."]
    if plan.avisos:
        lineas += ["", "Hay que saber:"] + ["  - " + a for a in plan.avisos]
    if plan.bloqueos:
        lineas += ["", "No puedo seguir:"] + ["  - " + b for b in plan.bloqueos]
        lineas += ["", "No sigo: no he cambiado nada. Arregla lo de arriba y vuelve a lanzarme."]
    elif plan.cambios:
        lineas += ["", "%d cambios." % len(plan.cambios)]
    else:
        lineas += ["", "Todo al día: 0 cambios."]
    texto = "\n".join(lineas) + "\n"
    if not color:
        texto = texto.replace(ROJO, "").replace(NORMAL, "")
    return texto


def _estado_de_grupo(acciones) -> str:
    estados = {a.estado for a in acciones}
    for estado in (m.MODIFICADO, m.AJENO, m.REEMPLAZA, m.CAMBIA):
        if estado in estados:
            return estado
    if estados == {m.NUEVO}:
        return m.NUEVO
    return m.CAMBIA if m.NUEVO in estados else m.YA_ESTA
