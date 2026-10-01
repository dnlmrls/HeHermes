"""El plan: lo que haría el instalador, sin tocar nada. Lo calcula `modo_tls.calcular_plan_tls` con las piezas de aquí.

`--plan` lo pinta y sale; `instalar` lo pinta, pregunta y lo aplica en este mismo orden.
"""

from __future__ import annotations

import json
import os
import re

from . import VERSION
from . import manifiesto as m
from . import piezas as p
from .aplicar import REINICIOS_PENDIENTES
from .deteccion import NORMAL, PREFIJO_DETALLE, PREFIJO_ERROR, ROJO, Bloqueo, bloqueo, etiquetar  # noqa: F401

NOMBRE_VALIDO = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
# Lo que va en /opt/hehermes-servidor: con eso, `comprobar`, `actualizar` y `desinstalar` siguen ahí después de que se
# borre la carpeta temporal del comando.
PROPIOS = ("hehermes-servidor", "hehermes-pasarela", "clave-publica.pem", "requirements-canje.txt")
EJECUTABLES_PROPIOS = ("hehermes-servidor", "hehermes-pasarela")


class Opciones:
    def __init__(self, iphone=None, direccion=None, hermes_home=None, reemplazar=(), si=False, solo_plan=False,
                 por_chat=False, llave=None, activar_api=False, qr_png=None, cortafuegos_a_mano=False,
                 corregir_exposicion=False, avisos=None):
        #: Si hay alguien delante de un terminal (el QR de la pasarela solo se pinta ahí).
        self.terminal = True
        self.iphone = iphone
        self.direccion = direccion
        self.hermes_home = hermes_home
        self.reemplazar = frozenset(reemplazar)
        self.si = si
        self.solo_plan = solo_plan
        # El alta por chat (pieza B): sin preguntar, sin QR y con el canje al final.
        self.por_chat = por_chat
        self.llave = llave
        self.activar_api = activar_api
        self.qr_png = qr_png
        #: El cortafuegos lo lleva el usuario: no se toca, aunque cierre (y no se sepa dónde abrirlo).
        self.cortafuegos_a_mano = cortafuegos_a_mano
        #: Permiso para cerrar a 127.0.0.1 una API de Hermes que escucha en todas las interfaces.
        self.corregir_exposicion = corregir_exposicion
        #: El código de avisos ya leído (`avisos.leer_codigo`): el vigía, con el relé de ese código. Lleva la credencial.
        self.avisos = avisos


class Accion:
    """Una cosa que el instalador deja. `tipo`: paquete, fichero, gestionado, enlace, unidad, regla, firewalld, propio,
    usuario, venv, certificado, env, exposicion, soul, dispositivo o canje. `datos`: el contenido (fichero, el párrafo
    del `SOUL.md`), el destino (enlace), los argumentos (regla) o, de un iPhone por chat, a quién sustituye."""

    #: Solo las de una unidad (`_unidad`): se reinicia por su código, y en marcha sin habilitar, tras habilitarla.
    por_codigo = False
    reiniciar = False

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

    @property
    def codigo_de_error(self) -> str | None:
        """El código del primer bloqueo (el que se arregla primero), o None si no hay."""
        codigos = [getattr(b, "codigo", Bloqueo.codigo) for b in self.bloqueos]
        # `reinicia-hermes` solo si es lo único: con otra cosa que pare, no se ha encendido nada, y lo que hay que
        # arreglar primero es eso otro.
        return next((c for c in codigos if c != "reinicia-hermes"), codigos[0] if codigos else None)

    @property
    def detalle_del_error(self) -> str | None:
        """Lo que concreta el primer bloqueo con ese código, para la app (`PREFIJO_DETALLE`), si lo lleva."""
        codigo = self.codigo_de_error
        return next((getattr(b, "detalle", None) for b in self.bloqueos if getattr(b, "codigo", None) == codigo), None)


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
    # Y el lector de ficheros (desde la 0.8.0): sin root, es el que lanza su unidad; con root, de aquí se copia a
    # /usr/local/libexec (`avisos.planear_lector`).
    fuente = fuente_del_lector(origen)
    if fuente is not None:
        with open(fuente, "rb") as f:
            salida.append((prefijo + "/hehermes-leer-media", f.read(), 0o755))
    # Y el ayudante de la copia en iCloud (desde la 0.10.0), igual.
    fuente = fuente_del_respaldo(origen)
    if fuente is not None:
        with open(fuente, "rb") as f:
            salida.append((prefijo + "/hehermes-respaldo", f.read(), 0o755))
    carpeta = os.path.join(origen, "hehermes_servidor")
    for nombre in sorted(os.listdir(carpeta)):
        if nombre.endswith(".py"):
            with open(os.path.join(carpeta, nombre), "rb") as f:
                salida.append((prefijo + "/hehermes_servidor/" + nombre, f.read(), 0o644))
    return salida


def fuente_del_lector(origen: str) -> str | None:
    """`hehermes-leer-media`: en el paquete, junto al instalador; en el repositorio, en `server/avisos/despliegue`."""
    return buscar_en_origen(origen, "hehermes-leer-media", "../avisos/despliegue/hehermes-leer-media")


def fuente_del_respaldo(origen: str) -> str | None:
    """`hehermes-respaldo`: en el paquete, junto al instalador; en el repositorio, en `server/avisos/despliegue`."""
    return buscar_en_origen(origen, "hehermes-respaldo", "../avisos/despliegue/hehermes-respaldo")


def buscar_en_origen(origen: str, *candidatas: str) -> str | None:
    """Un fichero del paquete, o del repositorio si se ejecuta desde él (`server/vpn`)."""
    for candidata in candidatas:
        ruta = os.path.normpath(os.path.join(origen, candidata))
        if os.path.exists(ruta):
            return ruta
    return None


def registro_de_dispositivos(sis) -> list:
    """Las altas vivas del registro de la VPN de antes (`/etc/hehermes/dispositivos`): las da de baja `desinstalar`, y
    por chat cuentan como el primer iPhone del servidor."""
    datos = sis.leer(p.REGISTRO + "/dispositivos.json")
    try:
        return [d for d in json.loads(datos or b"{}").get("dispositivos", []) if not d.get("baja")]
    except ValueError:
        return []


def codigo_de(acciones, prefijo, *partes) -> list:
    """Las acciones de los ficheros de código que carga un servicio que no se para (la pasarela, el vigía): los de
    `prefijo` + cada parte (una ruta, o una carpeta acabada en «/», con todo lo de dentro). Python los lee al arrancar:
    si cambian, el servicio sigue con los de antes hasta que se reinicia."""
    rutas = tuple(prefijo + "/" + parte for parte in partes)
    return [a for a in acciones if a.tipo == "fichero" and any(
        a.objeto.startswith(r) if r.endswith("/") else a.objeto == r for r in rutas)]


def _unidad(sis, acciones, unidad, ficheros, detalle, como_recargar, systemctl=("systemctl",), codigo=(), quien=None,
            man=None):
    """Una unidad se habilita y arranca si no lo está; si solo cambian sus ficheros, se recarga (`reload`, si la unidad
    lo sabe hacer sin cortar nada) o se reinicia (una `.path`, que no se puede recargar, o la pasarela). Sin root,
    `systemctl --user`.

    `codigo`: las acciones del código que carga (`codigo_de`), para un servicio que no se para. Si cambia, o quedó un
    reinicio pendiente de una pasada que se paró a medias (`REINICIOS_PENDIENTES`), y está en marcha, se reinicia una
    vez: antes de la 0.10.1 solo se reiniciaba si cambiaban su unidad o su configuración, y una actualización dejaba la
    pasarela corriendo con el código de antes. Los que arrancan uno por conexión o por temporizador (el lector, el
    ayudante de la copia, el borrado, el canje) cogen el código nuevo solos."""
    activa = sis.ejecutar(list(systemctl) + ["is-active", unidad]).bien
    habilitada = sis.ejecutar(list(systemctl) + ["is-enabled", unidad]).bien
    configuracion = any(f.cambia for f in ficheros)
    pendiente = man is not None and unidad in (man.datos.get(REINICIOS_PENDIENTES) or [])
    su_codigo = bool(codigo) and (pendiente or any(f.cambia for f in codigo))
    reiniciar = False
    if not (activa and habilitada):
        estado, que = m.NUEVO, "habilitar y arrancar: " + detalle
        if activa and (configuracion or su_codigo):
            # En marcha sin habilitar: `enable --now` no la reinicia, y seguiría con lo de antes.
            reiniciar, que = True, "habilitar y reiniciar: " + detalle
    elif configuracion:
        estado, que = m.CAMBIA, ("recargar (reload, sin cortar nada)" if como_recargar == "reload"
                                 else "reiniciar (es solo suya)")
        if su_codigo:
            que += "; su código también cambia"
        reiniciar = True
    elif su_codigo:
        estado, que, reiniciar = m.CAMBIA, "se reinicia %s: su código cambia" % (quien or unidad), True
    else:
        estado, que = m.YA_ESTA, detalle
    accion = Accion("unidad", unidad, estado, que, como_recargar)
    # Con el código nuevo ya escrito: `aplicar_tls` lo apunta como pendiente antes de escribirlo.
    accion.por_codigo = reiniciar and su_codigo
    # En marcha sin habilitar: tras `enable --now`, un reinicio.
    accion.reiniciar = reiniciar and estado == m.NUEVO
    acciones.append(accion)


# MARK: Pintar


SECCIONES = (("Hermes", ("env", "exposicion", "soul")), ("Paquetes", ("paquete",)),
             ("La pasarela", ("usuario", "venv", "certificado", "certificado_siguiente")),
             ("Ficheros", ("fichero", "gestionado", "enlace")),
             ("Servicios", ("unidad",)), ("Cortafuegos (ufw)", ("regla",)),
             ("Cortafuegos (firewalld)", ("firewalld",)), ("Cortafuegos (nftables e iptables)", ("propio",)),
             ("Avisos push", ()), ("iPhone", ("dispositivo",)), ("Canje por chat", ("canje",)))
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
        lineas.append("  Hermes     %s (de %s, por %s), API en %s:%d, %s%s" % (
            h.env, h.usuario, h.origen, h.host, h.puerto, estado_clave, _version_de_hermes(h)))
    if det.direccion:
        lineas.append("  Dirección  %s (la que irá en el QR)" % det.direccion)
    ambito = det.ambito
    lineas.append("  Modo       TLS: la pasarela, en el TCP %s%s%s" % (
        det.puerto_pasarela, "" if ambito.root else ", sin root (como %s, en su casa)" % ambito.usuario,
        ", al lado de la VPN IKEv2 de antes (no la toco)" if getattr(det, "al_lado", False) else ""))
    estados = {"activo": "activo", "inactivo": "apagado (no lo enciendo)", None: "no está"}
    if not ambito.root:
        pass  # sin root no se mira el cortafuegos
    elif det.distro.get("arquitectura") and det.firewalld is not None:
        lineas.append("  firewalld  %s" % estados[det.firewalld])
    elif det.distro.get("arquitectura"):
        lineas.append("  ufw        %s" % estados[det.ufw])
    for titulo, tipos in SECCIONES:
        de_aqui = [a for a in plan.acciones if a.tipo in tipos]
        if titulo == "Avisos push" and h is not None:
            vigia = getattr(det, "vigia", None)
            lector = any(a.objeto == p.SOCKET_LECTOR for a in plan.acciones)
            if vigia and vigia.get("direccion") is not None:
                texto = "el vigía, con el relé de %s:%d (su huella, anclada)%s; la pasarela le pasa /avisos/" % (
                    vigia["direccion"], vigia["puerto"], ", y el lector de ficheros" if lector else "")
            elif vigia:
                texto = ("el vigía, sin credencial: cada iPhone le da su permiso para el relé al darse de alta (App "
                         "Attest)%s; la pasarela le pasa /avisos/" % (", y el lector de ficheros" if lector else ""))
            elif det.con_vigia:
                texto = "el vigía ya está (puesto a mano): la pasarela le pasa /avisos/"
            else:
                texto = "no pongo el vigía (abajo, por qué)"
            lineas += ["", titulo, "  %-10s %s" % ("sí" if (vigia or det.con_vigia) else "no", texto)]
            continue
        if titulo == "iPhone" and not de_aqui and h is not None and plan.opciones.iphone is None:
            lineas += ["", titulo, "  %-10s %s" % ("ninguno", "--iphone <nombre> lo da de alta y pinta su QR")]
            continue
        if titulo == "Cortafuegos (ufw)" and not de_aqui and not ambito.root:
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
        if all(getattr(b, "codigo", None) == "reinicia-hermes" for b in plan.bloqueos) and \
                not getattr(plan.opciones, "solo_plan", False):
            # Lo único que falta es reiniciar Hermes: se enciende su API (`cli._instalar`), y nada más.
            lineas += ["", "Solo toco su .env: lo demás, cuando Hermes vuelva con la API encendida."]
        else:
            lineas += ["", "No sigo: no he cambiado nada. Arregla lo de arriba y vuelve a lanzarme."]
    elif plan.cambios:
        lineas += ["", "%d cambios." % len(plan.cambios)]
    else:
        lineas += ["", "Todo al día: 0 cambios."]
    texto = "\n".join(lineas) + "\n"
    if not color:
        texto = texto.replace(ROJO, "").replace(NORMAL, "")
    return texto


def _version_de_hermes(h) -> str:
    """«, versión 0.21.3» (la de su /health), «, versión 0.20.6 (la de su código, en …)» con la API apagada, o
    «, versión desconocida» si se le ha preguntado y no la dice. Nada si no se ha llegado a preguntar."""
    if h.version:
        return ", versión %s%s" % (h.version, "" if h.version_de in (None, "su /health") else " (la de %s)"
                                   % h.version_de)
    return ", versión desconocida" if h.sondeo is not None else ""


def _estado_de_grupo(acciones) -> str:
    estados = {a.estado for a in acciones}
    for estado in (m.MODIFICADO, m.AJENO, m.REEMPLAZA, m.CAMBIA):
        if estado in estados:
            return estado
    if estados == {m.NUEVO}:
        return m.NUEVO
    return m.CAMBIA if m.NUEVO in estados else m.YA_ESTA
