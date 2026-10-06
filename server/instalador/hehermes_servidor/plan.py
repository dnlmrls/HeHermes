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
# borre la carpeta temporal del comando. Las dos claves públicas de las firmas (`firma.CLAVES`), desde la 0.10.10.
PROPIOS = ("hehermes-servidor", "hehermes-pasarela", "clave-publica.pem", "clave-rescate.pem",
           "requirements-canje.txt")
EJECUTABLES_PROPIOS = ("hehermes-servidor", "hehermes-pasarela")


class Opciones:
    def __init__(self, iphone=None, direccion=None, hermes_home=None, reemplazar=(), si=False, solo_plan=False,
                 por_chat=False, llave=None, activar_api=False, qr_png=None, cortafuegos_a_mano=False,
                 corregir_exposicion=False, avisos=None, volver_atras=False, recuperacion=None):
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
        #: Instalar esta versión aunque la instalada sea más nueva (`comprobar_version`).
        self.volver_atras = volver_atras
        #: Por chat, la prueba del código de recuperación de la frase (`--recuperacion`, spec 2026-10-06), y si vale y
        #: hace falta (el chat estaba cerrado): `recuperando`, que lo decide `porchat.comprobar_recuperacion`.
        self.recuperacion = recuperacion
        self.recuperando = False


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
    # Y el ayudante de la copia en iCloud (desde la 0.10.0), el de la entrada (desde la 0.10.6), el que actualiza
    # (desde la 0.10.10) y el de los agentes (desde la 0.11.0), igual.
    for nombre, fuente in (("hehermes-respaldo", fuente_del_respaldo(origen)),
                           ("hehermes-entrada", fuente_de_la_entrada(origen)),
                           ("hehermes-actualizar", fuente_del_actualizar(origen)),
                           ("hehermes-agentes", fuente_de_agentes(origen))):
        if fuente is not None:
            with open(fuente, "rb") as f:
                salida.append((prefijo + "/" + nombre, f.read(), 0o755))
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


def fuente_de_la_entrada(origen: str) -> str | None:
    """`hehermes-entrada`: en el paquete, junto al instalador; en el repositorio, en `server/avisos/despliegue`."""
    return buscar_en_origen(origen, "hehermes-entrada", "../avisos/despliegue/hehermes-entrada")


def fuente_del_actualizar(origen: str) -> str | None:
    """`hehermes-actualizar`: en el paquete, junto al instalador; en el repositorio, en `server/avisos/despliegue`."""
    return buscar_en_origen(origen, "hehermes-actualizar", "../avisos/despliegue/hehermes-actualizar")


def fuente_de_agentes(origen: str) -> str | None:
    """`hehermes-agentes`: en el paquete, junto al instalador; en el repositorio, en `server/avisos/despliegue`."""
    return buscar_en_origen(origen, "hehermes-agentes", "../avisos/despliegue/hehermes-agentes")


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


# MARK: Cómo se instaló (desde la 0.11.1)
#
# `actualizar` (el de la app, por `hehermes-actualizar`) lanza el `instalar --si` de la versión nueva a secas. Sin lo
# que se dio al instalar, detrás de un NAT (AWS, Google Cloud, Oracle, Azure, un servidor en casa) se paraba siempre
# con `nat`, y con varios Hermes, con `varios-hermes`. Lo que cambia el resultado se apunta en el manifiesto al instalar
# y se vuelve a usar mientras no se dé otra cosa.

_FORMA_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_VERSION_DEL_CODIGO = re.compile(r'^VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.M)


def opciones_recordadas(man) -> dict:
    """Las que se dieron al instalar y cambian el resultado (`direccion`, `hermes_home` y `cortafuegos_a_mano`), como
    se apuntaron en el manifiesto (`opciones`): solo las que tienen su forma."""
    guardadas = man.datos.get("opciones")
    if not isinstance(guardadas, dict):
        return {}
    salida = {nombre: guardadas[nombre].strip() for nombre in ("direccion", "hermes_home")
              if isinstance(guardadas.get(nombre), str) and guardadas[nombre].strip()}
    if guardadas.get("cortafuegos_a_mano") is True:
        salida["cortafuegos_a_mano"] = True
    return salida


def completar_opciones(opciones, man) -> list:
    """Lo que no se ha dado y se dio al instalar. Devuelve lo que dice el plan («Hay que saber:»): que sigue como se
    instaló, y cómo se cambia."""
    guardadas, usadas = opciones_recordadas(man), []
    if opciones.direccion is None and "direccion" in guardadas:
        opciones.direccion = guardadas["direccion"]
        usadas.append("--direccion " + opciones.direccion)
    if opciones.hermes_home is None and "hermes_home" in guardadas:
        opciones.hermes_home = guardadas["hermes_home"]
        usadas.append("--hermes-home " + opciones.hermes_home)
    if not opciones.cortafuegos_a_mano and guardadas.get("cortafuegos_a_mano"):
        opciones.cortafuegos_a_mano = True
        usadas.append("--cortafuegos-a-mano")
    if not usadas:
        return []
    return ["Sigo como me instalaste: %s (lo que me des ahora manda)" % " ".join(usadas)]


def direccion_de_la_pasarela(sis, ambito) -> str | None:
    """La dirección del QR que dejó la instalación en `pasarela.ini` (`[qr] direccion`), si tiene la forma de una."""
    import configparser
    from .deteccion import DIRECCION_VALIDA
    ini = configparser.ConfigParser(interpolation=None)
    try:
        ini.read_string(sis.leer_texto(ambito.pasarela_ini) or "")
        direccion = ini.get("qr", "direccion", fallback="").strip()
    except configparser.Error:
        return None
    return direccion if direccion != "PENDIENTE" and DIRECCION_VALIDA.fullmatch(direccion) else None


def segun_lo_instalado(sis, man, ambito, opciones, det, detectar) -> tuple:
    """Una instalación de antes de la 0.11.1 no apuntaba sus opciones: lo que se sabe de cómo quedó. Detrás de un NAT
    (o sin saber la dirección pública), la dirección del QR de su `pasarela.ini`; con varios Hermes, el que tiene
    conectado (`mantenimiento.casa`), si sigue entre ellos. Si cambia algo, vuelve a detectar con ello. (detección, lo
    que dice el plan)."""
    if not man.en_disco or "tls" not in man.modos:
        return det, []
    codigos = {getattr(b, "codigo", None) for b in det.bloqueos}
    usadas = []
    if opciones.direccion is None and (getattr(det, "direccion_privada", False) or "direccion" in codigos):
        direccion = direccion_de_la_pasarela(sis, ambito)
        if direccion:
            opciones.direccion = direccion
            usadas.append("la dirección del QR que ya tiene (%s)" % direccion)
    if opciones.hermes_home is None and "varios-hermes" in codigos:
        casa = ((man.datos.get("mantenimiento") or {}).get("casa") or "").rstrip("/")
        if casa and casa in [c.home.rstrip("/") for c in getattr(det, "hermes_encontrados", None) or []]:
            opciones.hermes_home = casa
            usadas.append("el Hermes que ya tiene conectado (%s)" % casa)
    if not usadas:
        return det, []
    return detectar(), ["Sigo como estaba instalado: %s" % " y ".join(usadas)]


def opciones_para_recordar(opciones, det) -> dict:
    """Lo que se apunta: lo dado (o recordado) y, con varios Hermes, el elegido aunque no se dijera (por chat, el que
    lanzó el instalador): con él, `actualizar` no se para en `varios-hermes`."""
    guardar = {}
    if opciones.direccion:
        guardar["direccion"] = opciones.direccion
    casa = opciones.hermes_home
    if not casa and det.hermes is not None and len(getattr(det, "hermes_encontrados", None) or []) > 1:
        casa = det.hermes.home
    if casa:
        guardar["hermes_home"] = casa.rstrip("/") or casa
    if opciones.cortafuegos_a_mano:
        guardar["cortafuegos_a_mano"] = True
    return guardar


def _tupla(version: str) -> tuple:
    return tuple(int(x) for x in version.split("."))


def version_instalada(sis, man, ambito) -> str | None:
    """La de la instalación: la que apunta el manifiesto (desde la 0.11.1, la de la última pasada que empezó a aplicar)
    o, en una de antes, la del código que dejó en su carpeta. None sin instalación, o si no se sabe."""
    if not man.en_disco:
        return None
    apuntada = man.datos.get("version")
    if isinstance(apuntada, str) and _FORMA_VERSION.fullmatch(apuntada):
        return apuntada
    hallada = _VERSION_DEL_CODIGO.search(sis.leer_texto(ambito.prefijo + "/hehermes_servidor/__init__.py") or "")
    return hallada.group(1) if hallada else None


def comprobar_version(sis, man, ambito, plan) -> None:
    """Un instalador más viejo que lo instalado (una frase de antes, del historial del chat, o un comando viejo) no
    vuelve atrás sin avisar: se para, el primero (`version-antigua`, con la línea de detalle para la app), y dice cómo
    seguir. Con `--volver-atras`, sí, y lo dice."""
    instalada = version_instalada(sis, man, ambito)
    if instalada is None or _tupla(instalada) <= _tupla(VERSION):
        return
    if plan.opciones.volver_atras:
        plan.avisos.insert(0, "Vuelvo de la %s a la %s, que es más vieja, porque me lo pides (--volver-atras)"
                           % (instalada, VERSION))
        return
    orden = "sudo hehermes-servidor" if ambito.root else ambito.orden
    hecho = bloqueo("version-antigua", "Aquí ya está instalada la %s, más nueva que esta (%s): no vuelvo atrás, que "
                    "una versión vieja puede tener un fallo ya arreglado (¿un comando o una frase de antes?). Para "
                    "repararla o repetirla, usa la que está instalada: %s instalar. Para dar de alta un iPhone, copia "
                    "otra vez el comando o la frase desde la app al día, que traen la de ahora. Si de verdad quieres "
                    "volver a la %s: --volver-atras" % (instalada, VERSION, orden, VERSION))
    hecho.detalle = "instalada=%s esta=%s" % (instalada, VERSION)
    plan.bloqueos.insert(0, hecho)


def antes_de_aplicar(man, plan, recordar=True) -> None:
    """Lo que va al manifiesto antes de tocar nada (lo guarda el primer paso de `aplicar_tls`): esta versión, lo que va
    a escribir esta pasada (`m.A_MEDIAS`, que se quita al acabar) y, si `recordar`, las opciones que cambian el
    resultado. `avisos` no las recuerda: las suyas no las ha dado nadie."""
    ficheros = {}
    for a in plan.acciones:
        if a.estado in m.ESCRIBEN and a.tipo == "fichero":
            ficheros[a.objeto] = {"tipo": "fichero", "sha256": m.sha256(a.datos)}
        elif a.estado in m.ESCRIBEN and a.tipo == "enlace":
            ficheros[a.objeto] = {"tipo": "enlace", "destino": a.datos}
    man.datos["version"] = VERSION
    man.datos[m.A_MEDIAS] = {"version": VERSION, "ficheros": ficheros}
    _apuntar_opciones(man, plan, recordar)


def _apuntar_opciones(man, plan, recordar) -> None:
    if not recordar:
        return
    guardar = opciones_para_recordar(plan.opciones, plan.deteccion)
    if guardar:
        man.datos["opciones"] = guardar
    else:
        man.datos.pop("opciones", None)


def despues_de_aplicar(sis, man) -> None:
    """La pasada ha acabado: todo lo que escribió está apuntado."""
    if man.datos.pop(m.A_MEDIAS, None) is not None:
        man.guardar(sis)


def sin_cambios(sis, man, plan, recordar=True) -> None:
    """No había nada que cambiar: lo instalado ya es esta versión con estas opciones (las que se acaban de tomar de
    `pasarela.ini`, por ejemplo), y de una pasada que se cortó cuando ya lo había apuntado todo no queda nada a medias.
    Solo se guarda si algo de eso cambia."""
    if not man.en_disco:
        return
    antes = json.dumps(man.datos, sort_keys=True)
    man.datos.pop(m.A_MEDIAS, None)
    man.datos["version"] = VERSION
    _apuntar_opciones(man, plan, recordar)
    if json.dumps(man.datos, sort_keys=True) != antes:
        man.guardar(sis)


# MARK: Pintar


SECCIONES = (("Hermes", ("env", "exposicion", "soul")), ("Paquetes", ("paquete",)),
             ("La pasarela", ("usuario", "venv", "certificado", "certificado_siguiente")),
             ("Ficheros", ("fichero", "gestionado", "enlace")),
             ("Servicios", ("unidad",)), ("Cortafuegos (ufw)", ("regla",)),
             ("Cortafuegos (firewalld)", ("firewalld",)), ("Cortafuegos (nftables e iptables)", ("propio",)),
             ("Avisos push", ()), ("iPhone", ("dispositivo",)), ("Canje por chat", ("canje",)))
ETIQUETAS = {m.NUEVO: "nuevo", m.YA_ESTA: "ya está", m.CAMBIA: "cambia", m.AJENO: "ajeno", m.MODIFICADO: "cambiado",
             m.AJENO_IGUAL: "ya está*", m.REEMPLAZA: "reemplaza", m.ADOPTA: "es mío**"}


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
    if any(a.estado == m.ADOPTA for a in plan.acciones):
        lineas += ["", "  ** es mío: lo dejó escrito una pasada que se cortó a medias, sin apuntarlo. Lo apunto y lo "
                       "dejo al día."]
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
    for estado in (m.MODIFICADO, m.AJENO, m.REEMPLAZA, m.CAMBIA, m.ADOPTA):
        if estado in estados:
            return estado
    if estados == {m.NUEVO}:
        return m.NUEVO
    return m.CAMBIA if m.NUEVO in estados else m.YA_ESTA
