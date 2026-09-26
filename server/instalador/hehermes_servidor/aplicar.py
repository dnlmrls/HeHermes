"""Aplicar un plan, paso a paso, con el manifiesto al día tras cada paso: las piezas que usa `modo_tls.aplicar_tls`.

Un paso que falla vuelve a como estaba (sus ficheros, su entrada del manifiesto) y para: lo de los pasos de antes se
queda hecho y apuntado, así que basta con repetir el comando. Ningún cortafuegos se enciende: ufw, firewalld,
nftables e iptables reciben las reglas justas y marcadas.
"""

from __future__ import annotations

from . import manifiesto as m


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
            # la que systemd espera (y la que tendría tras un relabel del sistema).
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
    reglas = cf.permanentes_de(man.datos)
    try:
        lugares = cf.poner(sis, cf.MARCA, reglas, det.con_iptables)
    except cf.NoSe as error:
        raise Parada("no he podido poner las reglas en tu cortafuegos, y no he dejado ninguna: %s" % error)
    for lugar in lugares:
        salida("==> %s: %s (%s)" % (lugar.nombre, " y ".join(r.nombre for r in reglas), lugar.donde))


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


def _con_unidad(sis, man, acciones, unidad, salida, etiquetar=False, systemctl=("systemctl",), despues=None):
    """Sus ficheros, `daemon-reload` y la unidad en marcha. `despues` (la pasarela: los permisos de sus ficheros) va
    entre escribir y arrancar. Sin root, `systemctl --user`."""
    systemctl = list(systemctl)
    ficheros = [a for a in acciones if a.tipo in ("fichero", "gestionado")]
    accion = next(a for a in acciones if a.tipo == "unidad")
    tx = Transaccion(sis, man, etiquetar)
    try:
        escritos = [a for a in ficheros if _escribir(sis, man, tx, a)]
        if despues:
            despues(escritos)
        if escritos:
            _orden(sis, systemctl + ["daemon-reload"], "systemctl daemon-reload")
        if accion.estado == m.NUEVO:
            _orden(sis, systemctl + ["enable", "--now", unidad], "arrancar %s" % unidad)
        elif accion.estado == m.CAMBIA:
            _orden(sis, systemctl + [accion.datos, unidad], "%s %s" % (accion.datos, unidad))
    except Parada:
        tx.deshacer()
        man.guardar(sis)
        sis.ejecutar(systemctl + ["daemon-reload"])
        raise
    if unidad not in man.unidades:
        man.unidades.append(unidad)
    if accion.cambia:
        salida("==> %s: %s" % (unidad, accion.detalle))
    man.guardar(sis)


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
