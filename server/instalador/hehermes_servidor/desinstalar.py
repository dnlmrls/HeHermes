"""Desinstalar según el manifiesto: quita lo que el instalador dejó y nadie ha cambiado, devuelve lo que reemplazó o
apagó, y enumera lo que se queda. Los paquetes, solo con `--quitar-paquetes`, y solo los que instaló él."""

from __future__ import annotations

import shlex

from . import manifiesto as m
from . import piezas as p
from .plan import registro_de_dispositivos

# El lector de ficheros primero: su socket es de root y es lo único de los avisos que lee como root.
UNIDADES_AVISOS = ("hehermes-leer-media.socket", "hehermes-vigia.socket", "hehermes-vigia.service",
                   "hehermes-rele.socket", "hehermes-rele.service")
CARPETAS_AVISOS = ("/opt/hehermes-avisos", "/etc/hehermes-avisos", "/etc/nginx/hehermes-avisos", "/var/lib/hehermes-vigia")
# La plantilla del lector (se para con sus instancias, no se deshabilita: no tiene [Install]), su añadido si Hermes
# vive fuera de /root/.hermes (el fichero y luego su carpeta, que solo se borra vacía) y el propio lector.
FICHEROS_AVISOS = ("/etc/systemd/system/hehermes-leer-media@.service",
                   "/etc/systemd/system/hehermes-leer-media@.service.d/hermes-home.conf",
                   "/etc/systemd/system/hehermes-leer-media@.service.d", "/usr/local/libexec/hehermes-leer-media")
NGINX = (p.SITIO_ENLACE, p.SITIO, p.SITIO_CONF_D, p.BEARER, p.DROP_IN_NGINX)


_EXPOSICION = ("%s, en %s: la puso --corregir-exposicion y se queda, porque quitarla volvería a abrir la API de "
               "Hermes a quien llegue al servidor. Si la quieres fuera, quítala tú")


def _iphones(sis):
    return [d["nombre"] for d in registro_de_dispositivos(sis) if d.get("tipo") == "ikev2"]


def resumen(sis, man) -> str:
    if not man.en_disco:
        return ("En este servidor no hay nada mío (no está %s): no hay nada que quitar. Una instalación hecha a mano "
                "no la toco.\n" % m.RUTA_MANIFIESTO)
    lineas = ["Voy a quitar:"]
    iphones = _iphones(sis)
    if iphones:
        lineas.append("  iPhone (corto su sesión y borro su clave): " + ", ".join(iphones))
    quedan = []
    for ruta in sorted(man.ficheros):
        if m.sin_tocar(sis, man, ruta):
            vuelve = " (vuelve el que había)" if "copia" in man.ficheros[ruta] else ""
            lineas.append("  " + ruta + vuelve)
        elif sis.existe(ruta):
            quedan.append(ruta + ": alguien lo ha cambiado")
    for regla in man.reglas:
        lineas.append("  la regla " + regla)
    for puerto in man.datos.get("selinux_puertos", []):
        lineas.append("  la etiqueta http_port_t de SELinux del puerto tcp/%s" % puerto)
    for unidad in man.unidades:
        lineas.append("  la unidad " + unidad)
    for ruta in man.quitados:
        lineas.append("  y vuelvo a poner " + ruta)
    if man.datos.get("avisos"):
        lineas.append("  los avisos: " + ", ".join(UNIDADES_AVISOS + CARPETAS_AVISOS + FICHEROS_AVISOS)
                      + ", y los usuarios hh-vigia "
                      "y hh-rele")
    if man.paquetes:
        lineas.append("Los paquetes que instalé se quedan (%s); --quitar-paquetes los quita." % ", ".join(man.paquetes))
    if man.datos.get("exposicion"):
        lineas.append("Se queda " + _EXPOSICION % (man.datos["exposicion"]["linea"], man.datos["exposicion"]["env"]))
    if quedan:
        lineas += ["Se queda, porque no es como lo dejé:"] + ["  " + q for q in quedan]
    return "\n".join(lineas) + "\n"


def desinstalar(sis, man, quitar_paquetes=False, salida=print) -> list:
    """Devuelve lo que se queda (y por qué)."""
    if not man.en_disco:
        return []
    quedan = []

    def quitar(ruta):
        if not sis.existe(ruta):
            return
        if not m.sin_tocar(sis, man, ruta):
            quedan.append(ruta + ": alguien lo ha cambiado")
            return
        copia = man.ficheros[ruta].get("copia")
        if copia:
            m.restaurar_copia(sis, ruta, copia)
        else:
            sis.borrar(ruta)

    # 1. Los iPhone: sin esto, las sesiones vivas siguen aunque se borre su conexión.
    if sis.existe(p.DISPOSITIVO):
        for nombre in _iphones(sis):
            salida("==> baja de «%s»" % nombre)
            r = sis.ejecutar([p.DISPOSITIVO, "baja", nombre])
            if not r.bien:
                quedan.append("el iPhone %s: su baja ha fallado (%s)" % (nombre, (r.error or r.salida).strip()))
    # 2. El canje, si queda alguno, y su venv.
    from . import porchat
    porchat.parar(sis)
    porchat.limpiar_restos(sis)
    if man.datos.get("venv_canje"):
        sis.borrar_arbol(porchat.CARPETA_VENV)
    # 2b. Los avisos.
    if man.datos.get("avisos"):
        salida("==> los avisos")
        for unidad in UNIDADES_AVISOS:
            sis.ejecutar(["systemctl", "disable", "--now", unidad])
            sis.borrar("/etc/systemd/system/" + unidad)
        sis.ejecutar(["systemctl", "stop", "hehermes-leer-media@*.service"])
        for ruta in FICHEROS_AVISOS:
            sis.borrar(ruta)
        for carpeta in CARPETAS_AVISOS:
            sis.borrar_arbol(carpeta)
        for usuario in ("hh-vigia", "hh-rele"):
            if sis.ejecutar(["id", "-u", usuario]).bien:
                sis.ejecutar(["userdel", usuario])
    # 3. nginx: el sitio fuera y el default de vuelta, probado antes de recargar.
    for ruta in NGINX:
        if ruta in man.ficheros:
            quitar(ruta)
    for ruta, copia in list(man.quitados.items()):
        if not sis.existe(ruta):
            m.restaurar_copia(sis, ruta, copia)
        del man.quitados[ruta]
    if sis.ejecutar(["systemctl", "is-active", "nginx"]).bien:
        r = sis.ejecutar(["nginx", "-t"])
        if r.bien:
            sis.ejecutar(["systemctl", "daemon-reload"])
            sis.ejecutar(["systemctl", "reload", "nginx"])
        else:
            quedan.append("nginx: «nginx -t» falla sin el sitio del túnel, así que no lo he recargado")
    # 4. Las reglas del cortafuegos: las de ufw, y las de firewalld (en la de ahora y en la permanente, o apagado, con
    #    firewall-offline-cmd). Y la etiqueta de SELinux del puerto de Hermes, si la puso él.
    firewalld_en_marcha = None
    for regla in list(man.reglas):
        de_firewalld = p.regla_firewalld_de(regla)
        if de_firewalld is not None:
            if firewalld_en_marcha is None:
                firewalld_en_marcha = sis.ejecutar(["firewall-cmd", "--state"]).bien
            quitar_ = de_firewalld.con("remove")
            ordenes = ([["firewall-cmd", quitar_], ["firewall-cmd", "--permanent", quitar_]] if firewalld_en_marcha
                       else [["firewall-offline-cmd", quitar_]])
            if all([sis.ejecutar(orden).bien for orden in ordenes]):
                man.reglas.remove(regla)
            else:
                quedan.append("la regla %s: firewalld no la ha quitado" % regla)
            continue
        args = shlex.split(regla)[1:]
        r = sis.ejecutar(["ufw", "delete"] + args)
        if r.bien:
            man.reglas.remove(regla)
        else:
            quedan.append("la regla %s: ufw no la ha quitado" % regla)
    for puerto in list(man.datos.get("selinux_puertos", [])):
        r = sis.ejecutar(["semanage", "port", "-d", "-t", "http_port_t", "-p", "tcp", puerto])
        if r.bien:
            man.datos["selinux_puertos"].remove(puerto)
        else:
            quedan.append("la etiqueta de SELinux de tcp/%s: semanage no la ha quitado" % puerto)
    #    Las de nftables e iptables, por su marca; y se dice si el sistema las guardó con las suyas.
    if man.datos.get("cortafuegos_propio"):
        from . import cortafuegos as cf
        cf.quitar(sis, cf.MARCA)
        for ruta in cf.guardadas(sis):
            quedan.append("%s: tu cortafuegos guardado lleva reglas de HeHermes (se guardó con ellas puestas). No lo "
                          "toco: quítalas de ahí o vuelve a guardarlo ahora" % ruta)
    # 5. Las unidades, de la última a la primera: la XFRM, al final, cuando nginx ya no escucha en 10.77.0.1.
    for unidad in reversed(man.unidades):
        sis.ejecutar(["systemctl", "disable", "--now", unidad])
    # 6. Las líneas de --activar-api, y el resto de ficheros.
    from .porchat import quitar_lineas_api
    quitar_lineas_api(sis, man, quedan, salida)
    if man.datos.get("exposicion"):
        quedan.append(_EXPOSICION % (man.datos["exposicion"]["linea"], man.datos["exposicion"]["env"]))
    for ruta in sorted(man.ficheros):
        if ruta not in NGINX:
            quitar(ruta)
    sis.ejecutar(["systemctl", "daemon-reload"])
    # 7. Los paquetes que instaló él.
    if quitar_paquetes and man.paquetes:
        salida("==> paquetes: " + " ".join(man.paquetes))
        if man.datos.get("familia") == "rhel":
            orden, que = ["dnf", "remove", "-y", "-q"] + man.paquetes, "dnf remove"
        else:
            orden = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "purge", "-y", "-q"] + man.paquetes
            que = "apt-get purge"
        r = sis.ejecutar(orden)
        if not r.bien:
            quedan.append("los paquetes: %s ha fallado (%s)" % (que, (r.error or r.salida).strip()))
    # 8. Lo suyo en /etc/hehermes y las carpetas que creó, si se han quedado vacías.
    registro = p.REGISTRO + "/dispositivos.json"
    if not registro_de_dispositivos(sis):
        sis.borrar(registro)
        sis.borrar(p.REGISTRO)
    else:
        quedan.append(registro + ": quedan iPhone dados de alta")
    for nombre in sis.listar(m.CARPETA_COPIAS):
        if not any((e.get("copia") or {}).get("ruta") == m.CARPETA_COPIAS + "/" + nombre for e in man.ficheros.values()):
            sis.borrar(m.CARPETA_COPIAS + "/" + nombre)
    sis.borrar(m.CARPETA_COPIAS)
    sis.borrar(m.RUTA_MANIFIESTO)
    for carpeta in sorted(man.carpetas, key=len, reverse=True):
        sis.borrar(carpeta)
    sis.borrar(m.CARPETA)
    if quedan:
        salida("Se queda:\n  " + "\n  ".join(quedan))
    return quedan
