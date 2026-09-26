"""Aplicar el plan, paso a paso y en el orden de la spec, con el manifiesto al día tras cada paso.

Un paso que falla vuelve a como estaba (sus ficheros, su entrada del manifiesto) y para: lo de los pasos de antes se
queda hecho y apuntado, así que basta con repetir el comando. Nada se reinicia si ya servía a otras cosas: nginx se
recarga, strongSwan se carga con `swanctl --load-all` (lo hace `hehermes-dispositivo alta`) y ufw no se enciende.
"""

from __future__ import annotations

import re
import time

from . import manifiesto as m
from . import piezas as p
from .deteccion import regla_ufw_canonica
from .entorno import leer_env


class Parada(Exception):
    """El instalador se para aquí: lo de este paso ya ha vuelto a como estaba."""


class Transaccion:
    """Lo que había antes de cada escritura de un paso, para deshacerlo si el paso falla."""

    def __init__(self, sis, man, etiquetar=False):
        self.sis, self.man = sis, man
        self.antes = []
        #: Con SELinux: cada fichero escrito, con la etiqueta que le toca por su ruta (`restorecon`).
        self.etiquetar = etiquetar

    def apuntar(self, ruta):
        self.antes.append((ruta, self.sis.leer(ruta), self.sis.enlace(ruta), self.sis.modo(ruta),
                           self.man.ficheros.get(ruta), self.man.quitados.get(ruta)))

    def deshacer(self):
        for ruta, datos, destino, modo, entrada, quitado in reversed(self.antes):
            self.sis.borrar(ruta)
            if destino is not None:
                self.sis.enlazar(ruta, destino)
            elif datos is not None:
                self.sis.escribir(ruta, datos, modo=modo or 0o644)
            if entrada is None:
                self.man.olvidar(ruta)
            else:
                self.man.ficheros[ruta] = entrada
            if quitado is None:
                self.man.quitados.pop(ruta, None)
            else:
                self.man.quitados[ruta] = quitado
        self.antes = []


def _escribir(sis, man, tx, accion):
    """Escribe un fichero o un enlace del plan, si hace falta, y lo apunta en el manifiesto."""
    if accion.estado not in m.ESCRIBEN:
        return False
    tx.apuntar(accion.objeto)
    man.apuntar_carpetas(sis, accion.objeto)
    copia = m.guardar_copia(sis, accion.objeto) if accion.estado == m.REEMPLAZA else None
    if accion.tipo == "enlace":
        sis.borrar(accion.objeto)
        sis.enlazar(accion.objeto, accion.datos)
        man.apuntar_enlace(accion.objeto, accion.datos, copia)
    else:
        sis.escribir(accion.objeto, accion.datos, modo=accion.modo)
        if tx.etiquetar:
            # Escrito al lado y renombrado, hereda la etiqueta de su carpeta; restorecon le pone la de su ruta, que es
            # la que nginx y systemd esperan (y la que tendría tras un relabel del sistema).
            sis.ejecutar(["restorecon", accion.objeto])
        if accion.tipo == "gestionado":
            man.apuntar_gestionado(accion.objeto, copia)
        else:
            man.apuntar_fichero(accion.objeto, accion.datos, copia)
    return True


def _orden(sis, args, que, entrada=None):
    r = sis.ejecutar(args, entrada=entrada)
    if not r.bien:
        raise Parada("%s ha fallado: %s" % (que, (r.error or r.salida).strip() or "código %d" % r.codigo))
    return r


NGINX = {p.BEARER, p.SITIO, p.SITIO_ENLACE, p.SITIO_CONF_D, p.DROP_IN_NGINX, p.DEFAULT_NGINX, "recargar nginx"}
XFRM = {p.SCRIPT_XFRM, p.UNIDAD_XFRM, "hehermes-xfrm.service"}
CLAVE = {p.UNIDAD_CLAVE_PATH, p.UNIDAD_CLAVE_SERVICE, "hehermes-clave.path"}
CORTAFUEGOS = {p.UNIDAD_CORTAFUEGOS, "hehermes-cortafuegos.service"}


def aplicar(sis, plan, man, origen, salida=print):
    if not plan.puede_seguir:
        raise Parada("el plan tiene bloqueos")
    acciones = plan.acciones
    if not man.en_disco and "instalado" not in man.datos:
        # Desde cuándo está instalado: por chat solo se da de alta en la media hora siguiente (decisión 7). Solo en una
        # instalación nueva; una de antes sin fecha se queda sin ella, que es lo mismo que vieja.
        man.datos["instalado"] = time.time()
    de = lambda objetos: [a for a in acciones if a.objeto in objetos]  # noqa: E731
    det = plan.deteccion
    etiquetar = bool(det.selinux)
    if det.familia != "debian" and man.datos.get("familia") != det.familia:
        man.datos["familia"] = det.familia

    for a in acciones:
        if a.tipo == "env" and a.cambia:
            from .porchat import activar_api
            activar_api(sis, man, a, salida)
        if a.tipo == "exposicion" and a.cambia:
            from .porchat import corregir_exposicion
            corregir_exposicion(sis, man, a, salida)
    _paquetes(sis, man, [a for a in acciones if a.tipo == "paquete"], salida, det.familia)
    _strongswan(sis, man, [a for a in acciones if a.objeto == "strongswan.service"], salida)
    _selinux(sis, man, [a for a in acciones if a.tipo == "selinux"], salida)
    # Los ficheros sueltos: el instalador en /opt, su orden, servidor.ini y hehermes-dispositivo.
    sueltos = [a for a in acciones if a.tipo in ("fichero", "enlace") and a.objeto not in NGINX | XFRM | CLAVE | CORTAFUEGOS]
    _ficheros(sis, man, sueltos, "ficheros", salida, etiquetar)
    _con_unidad(sis, man, de(XFRM), "hehermes-xfrm.service", salida, etiquetar)
    _nginx(sis, man, de(NGINX), salida, etiquetar)
    _ufw(sis, man, [a for a in acciones if a.tipo == "regla"], salida)
    _firewalld(sis, man, det, [a for a in acciones if a.tipo == "firewalld"], salida)
    _propio(sis, man, det, [a for a in acciones if a.tipo == "propio"], salida)
    _con_unidad(sis, man, de(CORTAFUEGOS), "hehermes-cortafuegos.service", salida, etiquetar)
    _con_unidad(sis, man, de(CLAVE), "hehermes-clave.path", salida, etiquetar)
    for a in acciones:
        if a.tipo == "avisos" and a.cambia:
            salida("==> avisos push (el instalador de server/avisos)")
            r = sis.ejecutar(["bash", a.datos], heredar=True)
            if not r.bien:
                raise Parada("el instalador de los avisos ha fallado (arriba dice por qué)")
            man.datos["avisos"] = True
            man.guardar(sis)
    pendiente = any(a.tipo in ("env", "exposicion") and a.cambia for a in acciones)
    fallos = [texto for bien, texto in comprobar(sis, man, hermes_pendiente=pendiente) if not bien]
    if fallos:
        raise Parada("la comprobación no pasa:\n  - " + "\n  - ".join(fallos))
    for a in acciones:
        if a.tipo == "dispositivo" and a.cambia:
            _alta(sis, man, a.objeto, plan.deteccion.direccion, salida, qr=not plan.opciones.por_chat)
            if plan.opciones.por_chat:
                man.datos["por_chat"] = {"iphone": a.objeto, "alta": time.time()}
                man.guardar(sis)


def _paquetes(sis, man, acciones, salida, familia="debian"):
    faltan = [a.objeto for a in acciones if a.cambia]
    if not faltan:
        return
    salida("==> paquetes: " + " ".join(faltan))
    if familia == "rhel":
        # Sin las dependencias débiles: lo mismo que --no-install-recommends.
        _orden(sis, ["dnf", "install", "-y", "-q", "--setopt=install_weak_deps=False"] + faltan, "dnf install")
    else:
        apt = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"]
        _orden(sis, apt + ["update", "-q"], "apt-get update")
        _orden(sis, apt + ["install", "-y", "-q", "--no-install-recommends"] + faltan, "apt-get install")
    man.paquetes.extend(x for x in faltan if x not in man.paquetes)
    man.guardar(sis)


def _strongswan(sis, man, acciones, salida):
    """En la familia Red Hat, dnf deja strongSwan instalado y parado: lo arranca el instalador, y es suyo (desinstalar
    lo para)."""
    for a in acciones:
        if not a.cambia:
            continue
        _orden(sis, ["systemctl", "enable", "--now", "strongswan"], "arrancar strongSwan")
        if a.objeto not in man.unidades:
            man.unidades.append(a.objeto)
        man.guardar(sis)
        salida("==> strongswan.service: en marcha")


def _selinux(sis, man, acciones, salida):
    """La etiqueta http_port_t al puerto de Hermes, solo si no la tiene ya; apuntada, para quitarla al desinstalar."""
    from .deteccion import puertos_selinux
    for a in acciones:
        if not a.cambia:
            continue
        puerto = a.datos
        # Se vuelve a mirar: si semanage lo acaba de instalar dnf, la detección no pudo.
        exactos = puertos_selinux(_orden(sis, ["semanage", "port", "-l", "-n"], "semanage port -l").salida,
                                  int(puerto))["exacto"]
        if "http_port_t" in exactos:
            continue
        if exactos:
            raise Parada("SELinux le da el puerto %s de Hermes a %s: no le cambio la etiqueta" % (puerto,
                                                                                              ", ".join(exactos)))
        _orden(sis, ["semanage", "port", "-a", "-t", "http_port_t", "-p", "tcp", puerto],
               "semanage port -a (tcp/%s)" % puerto)
        man.datos.setdefault("selinux_puertos", [])
        if puerto not in man.datos["selinux_puertos"]:
            man.datos["selinux_puertos"].append(puerto)
        man.guardar(sis)
        salida("==> SELinux: tcp/%s como http_port_t, para que nginx llegue a Hermes" % puerto)


def _firewalld(sis, man, det, acciones, salida):
    """Como ufw: se añade, no se enciende. En marcha, en la configuración de ahora y en la permanente, sin `--reload`
    (que se llevaría las reglas de ahora de los demás); apagado, con firewall-offline-cmd."""
    from .deteccion import orden_firewalld
    for a in acciones:
        if not a.cambia:
            continue
        regla = a.datos
        if det.firewalld == "activo" and not sis.ejecutar(["firewall-cmd", regla.con("query")]).bien:
            _orden(sis, ["firewall-cmd", regla.opcion], regla.texto)
        _orden(sis, orden_firewalld(det, regla.opcion), regla.texto)
        if regla.texto not in man.reglas:
            man.reglas.append(regla.texto)
        man.datos["cortafuegos"] = "firewalld"
        man.guardar(sis)
        salida("==> firewalld: %s" % a.objeto)


def _propio(sis, man, det, acciones, salida):
    """nftables o iptables a pelo: se apunta antes de poner nada (lo lee `hehermes-cortafuegos` al arrancar) y se
    ponen todas de una vez, quitando antes las que hubiera (`cortafuegos.poner`)."""
    from . import cortafuegos as cf
    if not any(a.cambia for a in acciones):
        return
    man.datos["cortafuegos_propio"] = {"iptables": det.con_iptables}
    man.guardar(sis)
    try:
        lugares = cf.poner(sis, cf.MARCA, cf.permanentes(), det.con_iptables)
    except cf.NoSe as error:
        raise Parada("no he podido poner las reglas en tu cortafuegos, y no he dejado ninguna: %s" % error)
    for lugar in lugares:
        salida("==> %s: UDP 500 y 4500, y TCP 80 por %s (%s)" % (lugar.nombre, p.INTERFAZ, lugar.donde))


def _ficheros(sis, man, acciones, que, salida, etiquetar=False):
    tx = Transaccion(sis, man, etiquetar)
    try:
        escritos = [a.objeto for a in acciones if _escribir(sis, man, tx, a)]
    except Exception:
        tx.deshacer()
        raise
    if escritos:
        salida("==> %s: %d escritos" % (que, len(escritos)))
    man.guardar(sis)
    return escritos


def _con_unidad(sis, man, acciones, unidad, salida, etiquetar=False):
    ficheros = [a for a in acciones if a.tipo == "fichero"]
    accion = next(a for a in acciones if a.tipo == "unidad")
    tx = Transaccion(sis, man, etiquetar)
    try:
        escritos = [a for a in ficheros if _escribir(sis, man, tx, a)]
        if escritos:
            _orden(sis, ["systemctl", "daemon-reload"], "systemctl daemon-reload")
        if accion.estado == m.NUEVO:
            _orden(sis, ["systemctl", "enable", "--now", unidad], "arrancar %s" % unidad)
        elif accion.estado == m.CAMBIA:
            _orden(sis, ["systemctl", accion.datos, unidad], "%s %s" % (accion.datos, unidad))
    except Parada:
        tx.deshacer()
        man.guardar(sis)
        sis.ejecutar(["systemctl", "daemon-reload"])
        raise
    if unidad not in man.unidades:
        man.unidades.append(unidad)
    if accion.cambia:
        salida("==> %s: %s" % (unidad, accion.detalle))
    man.guardar(sis)


def _nginx(sis, man, acciones, salida, etiquetar=False):
    recarga = next(a for a in acciones if a.objeto == "recargar nginx")
    if not recarga.cambia:
        return
    salida("==> nginx: el sitio del túnel")
    tx = Transaccion(sis, man, etiquetar)
    try:
        escritos = [a for a in acciones if a.tipo in ("fichero", "gestionado", "enlace") and _escribir(sis, man, tx, a)]
        for a in acciones:
            if a.tipo == "quitar" and a.cambia and sis.existe(a.objeto):
                tx.apuntar(a.objeto)
                man.quitados[a.objeto] = m.guardar_copia(sis, a.objeto)
                sis.borrar(a.objeto)
        r = sis.ejecutar(["nginx", "-t"])
        if not r.bien:
            raise Parada("«nginx -t» no da por bueno el sitio del túnel, y he vuelto a dejarlo como estaba:\n  "
                         + (r.error or r.salida).strip())
        if any(a.objeto == p.DROP_IN_NGINX for a in escritos):
            _orden(sis, ["systemctl", "daemon-reload"], "systemctl daemon-reload")
        if sis.ejecutar(["systemctl", "is-active", "nginx"]).bien:
            _orden(sis, ["systemctl", "reload", "nginx"], "recargar nginx")
        else:
            # Solo llega aquí un nginx que instaló él (la detección para con uno ajeno parado).
            _orden(sis, ["systemctl", "enable", "--now", "nginx"], "arrancar nginx")
    except Parada:
        tx.deshacer()
        man.guardar(sis)
        raise
    man.guardar(sis)
    salida("    probado y recargado")


def _ufw(sis, man, acciones, salida):
    for a in acciones:
        if not a.cambia:
            continue
        _orden(sis, ["ufw"] + a.datos, "ufw " + " ".join(a.datos))
        texto = "ufw " + " ".join(a.datos)
        if texto not in man.reglas:
            man.reglas.append(texto)
        man.guardar(sis)
        salida("==> ufw: %s" % a.objeto)


def _alta(sis, man, nombre, direccion, salida, qr=True):
    salida("==> el iPhone «%s»" % nombre)
    _orden(sis, [p.DISPOSITIVO, "alta", nombre, "--ikev2", "--servidor", direccion], "el alta de «%s»" % nombre)
    if nombre not in man.dispositivos:
        man.dispositivos.append(nombre)
    man.guardar(sis)
    if not qr:
        # Por chat: la PSK se entrega cifrada por el canje. El QR la llevaría en claro, y lo leería el modelo.
        return
    # El QR lleva la clave del iPhone: `qr` exige sudo y un terminal, y lo pinta directo en él.
    r = sis.ejecutar([p.DISPOSITIVO, "qr", nombre], heredar=True)
    if not r.bien:
        salida("No he podido pintar el QR aquí (hace falta un terminal). Desde el tuyo:  sudo hehermes-dispositivo qr "
               + nombre)


# MARK: Comprobar


def comprobar(sis, man, hermes_pendiente=False) -> list:
    """(bien, texto) de cada cosa que tiene que estar en marcha. Solo lee. Con `hermes_pendiente` (--activar-api en
    esta misma pasada), Hermes todavía no escucha: se reinicia al acabar."""
    resultados = []

    def mira(bien, si, no):
        resultados.append((bool(bien), si if bien else no))

    mira(sis.ejecutar(["nginx", "-t"]).bien, "nginx: la configuración pasa nginx -t", "nginx: nginx -t falla")
    mira(sis.ejecutar(["systemctl", "is-active", "nginx"]).bien, "nginx: en marcha", "nginx: parado")
    mira(sis.ejecutar(["swanctl", "--stats"]).bien, "strongSwan: swanctl habla con charon",
         "strongSwan: swanctl no habla con charon (¿strongswan.service parado?)")
    r = sis.ejecutar(["ip", "-d", "link", "show", p.INTERFAZ])
    mira(r.bien and re.search(r"\bxfrm if_id %s\b" % p.IF_ID, r.salida), "%s: XFRM con if_id %s" % (p.INTERFAZ, p.IF_ID),
         "%s: no está, o no es XFRM con if_id %s" % (p.INTERFAZ, p.IF_ID))
    if man.datos.get("cortafuegos") == "firewalld":
        en_marcha = sis.ejecutar(["firewall-cmd", "--state"]).bien
        faltan = []
        for regla in p.reglas_firewalld():
            miran = ([["firewall-cmd", regla.con("query")], ["firewall-cmd", "--permanent", regla.con("query")]]
                     if en_marcha else [["firewall-offline-cmd", regla.con("query")]])
            if not all(sis.ejecutar(orden).bien for orden in miran):
                faltan.append(regla.nombre)
        mira(not faltan, "firewalld: las reglas de HeHermes están%s" % ("" if en_marcha else " (y firewalld, apagado)"),
             "firewalld: faltan reglas (%s)" % ", ".join(faltan))
    elif sis.cual("ufw"):
        added = sis.ejecutar(["ufw", "show", "added"]).salida
        hay = {regla_ufw_canonica(linea.strip()) for linea in added.splitlines()}
        faltan = [r.nombre for r in p.reglas_ufw() if regla_ufw_canonica(r.texto) not in hay]
        mira(not faltan, "ufw: las reglas de HeHermes están", "ufw: faltan reglas (%s)" % ", ".join(faltan))
    propio = man.datos.get("cortafuegos_propio")
    if propio:
        from . import cortafuegos as cf
        lugares, dudas = cf.analizar(sis, propio.get("iptables", True))
        faltan = [l.nombre for l in lugares if l.marcadas < len(cf.permanentes())]
        mira(not faltan and not dudas,
             "cortafuegos: las reglas de HeHermes están (%s)" % (", ".join(l.nombre for l in lugares) or
                                                                  "ninguna cadena cierra el paso"),
             "cortafuegos: faltan reglas en %s" % ", ".join(faltan + dudas))
    # Hermes, directo y con su clave; el túnel, desde el propio servidor, tiene que decir que no.
    env, puerto = _hermes_del_ini(sis)
    clave = leer_env(sis.leer_texto(env) or "").get("API_SERVER_KEY") if env else None
    if hermes_pendiente:
        mira(True, "Hermes: su API se enciende al reiniciarse, 90 s después de acabar", "")
    elif clave:
        estado, _ = sis.http_get("http://127.0.0.1:%d/api/sessions?limit=1" % puerto, {"Authorization": "Bearer " + clave})
        mira(estado == 200, "Hermes: contesta con su clave", "Hermes: no contesta con su clave (%s)" % estado)
    else:
        mira(False, "", "Hermes: no encuentro su clave (%s)" % env)
    estado, _ = sis.http_get("http://%s/health" % p.IP_TUNEL)
    if estado == 403:
        mira(True, "túnel: nginx escucha en %s y le dice 403 al propio servidor (el agujero, cerrado)" % p.IP_TUNEL, "")
    elif estado is None:
        mira(False, "", "túnel: nadie contesta en %s:80" % p.IP_TUNEL)
    else:
        mira(False, "", "túnel: %s contesta %s al propio servidor: el agujero está abierto" % (p.IP_TUNEL, estado))
    if man.datos.get("avisos"):
        mira(sis.ejecutar(["systemctl", "is-active", "hehermes-vigia.socket"]).bien, "avisos: el vigía escucha",
             "avisos: el vigía no escucha")
    return resultados


def _hermes_del_ini(sis):
    import configparser
    ini = configparser.ConfigParser()
    try:
        ini.read_string(sis.leer_texto(p.SERVIDOR_INI) or "")
        return ini.get("hermes", "env", fallback=None), ini.getint("hermes", "puerto", fallback=8642)
    except (configparser.Error, ValueError):
        return None, 8642
