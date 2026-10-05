"""Desinstalar según el manifiesto: quita lo que el instalador dejó y nadie ha cambiado, devuelve lo que reemplazó o
apagó, y enumera lo que se queda. Los paquetes, solo con `--quitar-paquetes`, y solo los que instaló él.

Con `modo` (`desinstalar --modo vpn` o `--modo tls`), solo lo de ese modo (`modos`): lo del otro y lo común se quedan
tal cual, y el manifiesto sigue, sin ese modo. Desde la 0.6.0 la VPN ya no se instala: `--modo vpn` es como se quita la
de una versión anterior dejando la pasarela, sin dejar restos.
"""

from __future__ import annotations

import os
import shlex
import shutil

from . import manifiesto as m
from . import modos as md
from . import piezas as p
from .plan import registro_de_dispositivos

# El lector de ficheros primero: su socket es de root y es lo único de los avisos que lee como root.
UNIDADES_AVISOS = ("hehermes-leer-media.socket", "hehermes-respaldo.socket", "hehermes-entrada.socket",
                   "hehermes-actualizar.socket", "hehermes-vigia.socket", "hehermes-vigia.service",
                   "hehermes-rele.socket", "hehermes-rele.service")
CARPETAS_AVISOS = ("/opt/hehermes-avisos", "/etc/hehermes-avisos", "/etc/nginx/hehermes-avisos", "/var/lib/hehermes-vigia")
# La plantilla del lector (se para con sus instancias, no se deshabilita: no tiene [Install]), su añadido si Hermes
# vive fuera de /root/.hermes (el fichero y luego su carpeta, que solo se borra vacía) y el propio lector.
FICHEROS_AVISOS = ("/etc/systemd/system/hehermes-leer-media@.service",
                   "/etc/systemd/system/hehermes-leer-media@.service.d/hermes-home.conf",
                   "/etc/systemd/system/hehermes-leer-media@.service.d", "/usr/local/libexec/hehermes-leer-media",
                   "/etc/systemd/system/hehermes-respaldo@.service",
                   "/etc/systemd/system/hehermes-respaldo@.service.d/hermes.conf",
                   "/etc/systemd/system/hehermes-respaldo@.service.d", "/usr/local/libexec/hehermes-respaldo",
                   "/etc/systemd/system/hehermes-entrada@.service",
                   "/etc/systemd/system/hehermes-entrada@.service.d/hermes.conf",
                   "/etc/systemd/system/hehermes-entrada@.service.d", "/usr/local/libexec/hehermes-entrada",
                   "/etc/systemd/system/hehermes-actualizar@.service", "/usr/local/libexec/hehermes-actualizar")
NGINX = (p.SITIO_ENLACE, p.SITIO, p.SITIO_CONF_D, p.BEARER, p.DROP_IN_NGINX)


_EXPOSICION = ("%s, en %s: la puso --corregir-exposicion y se queda, porque quitarla volvería a abrir la API de "
               "Hermes a quien llegue al servidor. Si la quieres fuera, quítala tú")
#: Los avisos los instalaba la VPN de antes (`--avisos`), pero la pasarela también los sirve: quitar solo la VPN no se
#: los lleva.
_AVISOS_SE_QUEDAN = ("los avisos (el vigía y el relé): los instalé con la VPN, pero la pasarela también los sirve, así "
                     "que no los quito. Si cambias la clave de Hermes, pónsela al día al vigía con: sudo "
                     "hehermes-dispositivo clave --solo-vigia. «sudo hehermes-servidor desinstalar», sin --modo, los "
                     "quita con todo lo demás")


#: Lo que el ayudante de la entrada tiene a medias, dentro de `<HERMES_HOME>/entrada` (`hehermes-entrada`).
SUBIDAS = ".subidas"


def _borrar_subidas(sis, carpeta: str) -> None:
    """`.subidas` entera, dentro de la carpeta de entrada: es del ayudante (lo que la app subió a medias y sus
    cerrojos), no de Hermes. Solo si la carpeta de entrada es una carpeta de verdad: un enlace en su sitio llevaría el
    borrado, de root, a otro sitio. Si `.subidas` fuera un enlace, se quita el enlace; `shutil.rmtree`, con descriptores
    en Linux, no sigue los de dentro."""
    entrada = sis.ruta(carpeta)
    if os.path.islink(entrada) or not os.path.isdir(entrada):
        return
    real = os.path.join(entrada, SUBIDAS)
    if os.path.islink(real):
        os.unlink(real)
    elif os.path.isdir(real):
        shutil.rmtree(real, ignore_errors=True)


def _iphones(sis, man=None):
    if man is not None and "vpn" not in man.modos:
        # Los de una VPN que no es mía (la hecha a mano, al lado de la pasarela) no se tocan.
        return []
    return [d["nombre"] for d in registro_de_dispositivos(sis) if d.get("tipo") == "ikev2"]


class _Que:
    """Qué se quita: todo (`modo` None) o solo lo de un modo."""

    def __init__(self, man, modo, ambito):
        self.todo, self.modo, self.ambito = modo is None, modo, ambito
        modos = man.modos
        self.vpn = "vpn" in modos and modo in (None, "vpn")
        self.tls = "tls" in modos and modo in (None, "tls")
        self.puerto = (man.datos.get("pasarela") or {}).get("puerto")

    def de(self, de_que) -> bool:
        """Si se quita algo que es de `de_que` («vpn», «tls» o None si es común)."""
        return self.todo or de_que == self.modo

    def fichero(self, ruta) -> bool:
        return self.de(md.de_fichero(ruta, self.ambito))

    def regla(self, texto) -> bool:
        return self.de(md.de_regla(texto, self.puerto))


def resumen(sis, man, ambito=None, modo=None) -> str:
    from . import ambito as amb
    ambito = ambito or amb.de_root()
    if not man.en_disco:
        return ("En este servidor no hay nada mío (no está %s): no hay nada que quitar. Una instalación hecha a mano "
                "no la toco.\n" % man.ruta)
    que = _Que(man, modo, ambito)
    lineas = ["Voy a quitar:" if que.todo else
              "Voy a quitar %s, y nada más (lo demás se queda como está):" % md.NOMBRES[modo]]
    iphones = _iphones(sis, man) if que.vpn else []
    if iphones:
        lineas.append("  iPhone (corto su sesión y borro su clave): " + ", ".join(iphones))
    if que.tls:
        from .modo_tls import nombres_de_la_pasarela
        de_la_pasarela = nombres_de_la_pasarela(sis, ambito)
        if de_la_pasarela:
            lineas.append("  iPhone de la pasarela (sus tokens dejan de valer): " + ", ".join(de_la_pasarela))
    if man.datos.get("venv_canje") and (que.todo or modo == "tls"):
        lineas.append("  " + ambito.carpeta_venv)
    if man.datos.get("vigia") and que.tls:
        lineas.append("  " + ambito.carpeta_estado_vigia + " (la base de datos del vigía, con las claves de los iPhone)")
    if man.datos.get("entrada") and que.tls:
        lineas.append("  %s/%s (lo que la app dejó a medias) y %s, si se queda vacía (lo entregado es de Hermes)"
                      % (man.datos["entrada"], SUBIDAS, man.datos["entrada"]))
    if que.tls:
        from . import alma
        lineas += alma.resumen(man)
    for usuario in man.datos.get("usuarios", []):
        if que.de(md.de_usuario(usuario)):
            lineas.append("  el usuario " + usuario)
    quedan = []
    for ruta in sorted(man.ficheros):
        if not que.fichero(ruta):
            continue
        if m.sin_tocar(sis, man, ruta):
            vuelve = " (vuelve el que había)" if "copia" in man.ficheros[ruta] else ""
            lineas.append("  " + ruta + vuelve)
        elif sis.existe(ruta):
            quedan.append(ruta + ": alguien lo ha cambiado")
    for regla in man.reglas:
        if que.regla(regla):
            lineas.append("  la regla " + regla)
    if que.vpn:
        for puerto in man.datos.get("selinux_puertos", []):
            lineas.append("  la etiqueta http_port_t de SELinux del puerto tcp/%s" % puerto)
    for unidad in man.unidades:
        if que.de(md.de_unidad(unidad)):
            lineas.append("  la unidad " + unidad)
    if que.vpn:
        for ruta in man.quitados:
            lineas.append("  y vuelvo a poner " + ruta)
    if man.datos.get("avisos") and que.todo:
        lineas.append("  los avisos: " + ", ".join(UNIDADES_AVISOS + CARPETAS_AVISOS + FICHEROS_AVISOS)
                      + ", y los usuarios hh-vigia "
                      "y hh-rele")
    elif man.datos.get("avisos") and que.vpn:
        quedan.append(_AVISOS_SE_QUEDAN)
    paquetes = [x for x in man.paquetes if que.de(md.de_paquete(x))]
    if paquetes:
        lineas.append("Los paquetes que instalé se quedan (%s); --quitar-paquetes los quita." % ", ".join(paquetes))
    if man.datos.get("exposicion") and que.todo:
        lineas.append("Se queda " + _EXPOSICION % (man.datos["exposicion"]["linea"], man.datos["exposicion"]["env"]))
    if quedan:
        lineas += ["Se queda, porque no es como lo dejé:" if que.todo else "Se queda:"] + ["  " + q for q in quedan]
    return "\n".join(lineas) + "\n"


def desinstalar(sis, man, quitar_paquetes=False, salida=print, ambito=None, modo=None) -> list:
    """Devuelve lo que se queda (y por qué). Con `modo`, solo lo de ese modo."""
    from . import ambito as amb
    ambito = ambito or amb.de_root()
    if not man.en_disco:
        return []
    quedan = []
    que = _Que(man, modo, ambito)
    # Los nombres, antes de las bajas: lo que el manifiesto apunta de cada iPhone se va con su modo.
    de_la_vpn = _iphones(sis, man) if que.vpn else []
    if que.tls:
        from .modo_tls import nombres_de_la_pasarela
        de_la_pasarela = nombres_de_la_pasarela(sis, ambito)
    else:
        de_la_pasarela = []

    def quitar(ruta):
        if not sis.existe(ruta):
            if not que.todo:
                man.olvidar(ruta)
            return
        if not m.sin_tocar(sis, man, ruta):
            quedan.append(ruta + ": alguien lo ha cambiado")
            return
        copia = man.ficheros[ruta].get("copia")
        if copia:
            m.restaurar_copia(sis, ruta, copia)
        else:
            sis.borrar(ruta)
        if not que.todo:
            man.olvidar(ruta)

    # 0. La pasarela, lo primero: sin ella, ningún token vale ya.
    if que.tls:
        salida("==> la pasarela")
        for unidad in (p.UNIDAD_PASARELA, "hehermes-pasarela-clave.path", p.UNIDAD_VIGIA, p.SOCKET_VIGIA,
                       p.SOCKET_LECTOR, p.SOCKET_RESPALDO, p.SOCKET_ENTRADA, p.SOCKET_ACTUALIZAR):
            if unidad in man.unidades:
                sis.ejecutar(ambito.systemctl + ["disable", "--now", unidad])
        if p.SOCKET_LECTOR in man.unidades:
            # Los lectores en marcha (uno por conexión): la plantilla no se deshabilita, se paran sus instancias.
            sis.ejecutar(ambito.systemctl + ["stop", "hehermes-leer-media@*.service"])
        if p.SOCKET_RESPALDO in man.unidades and sis.ejecutar(
                ambito.systemctl + ["is-active", "hehermes-respaldo@*.service"]).bien:
            # Una restauración a medias no se corta: la pasarela ya no deja pedir nada nuevo, y se dice.
            quedan.append("la copia en iCloud: su ayudante tiene una operación en marcha (journalctl %s-u "
                          "'hehermes-respaldo@*'): la dejo acabar" % ("" if ambito.root else "--user "))
    # Un fichero a medio colocar no se corta (el socket ya no deja pedir nada nuevo): se deja acabar, y lo que tenga a
    # medias se queda.
    entrada_en_marcha = p.SOCKET_ENTRADA in man.unidades and que.tls and sis.ejecutar(
        ambito.systemctl + ["is-active", "hehermes-entrada@*.service"]).bien
    if entrada_en_marcha:
        quedan.append("la entrada de ficheros: su ayudante está colocando un fichero (journalctl %s-u "
                      "'hehermes-entrada@*'): lo dejo acabar" % ("" if ambito.root else "--user "))
    # 1. Los iPhone: sin esto, las sesiones vivas siguen aunque se borre su conexión.
    if sis.existe(p.DISPOSITIVO) and que.vpn:
        for nombre in de_la_vpn:
            salida("==> baja de «%s»" % nombre)
            r = sis.ejecutar([p.DISPOSITIVO, "baja", nombre])
            if not r.bien:
                quedan.append("el iPhone %s: su baja ha fallado (%s)" % (nombre, (r.error or r.salida).strip()))
    # 2. El canje, si queda alguno, y su venv. El venv es de los dos (la VPN de antes lo usaba para el canje), pero
    #    solo la pasarela lo necesita siempre, para el certificado: se va con ella.
    from . import porchat
    if que.todo:
        porchat.parar(sis, ambito)
        porchat.limpiar_restos(sis, ambito)
    if man.datos.get("venv_canje") and (que.todo or modo == "tls"):
        if not que.todo and sis.ejecutar(ambito.systemctl + ["is-active", porchat.UNIDAD]).bien:
            quedan.append("%s: hay un canje en marcha que lo usa. Se va con «desinstalar», sin --modo"
                          % ambito.carpeta_venv)
        else:
            sis.borrar_arbol(ambito.carpeta_venv)
            if not que.todo:
                del man.datos["venv_canje"]
    # 2b. Los avisos: con todo; quitando solo la VPN, se quedan (la pasarela también los sirve).
    if man.datos.get("avisos") and que.todo:
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
    elif man.datos.get("avisos") and que.vpn:
        quedan.append(_AVISOS_SE_QUEDAN)
    # 3. nginx: el sitio fuera y el default de vuelta, probado antes de recargar. La pasarela no toca nginx: ni se
    #    prueba ni se recarga (en el VPS de Daniel es suyo).
    if que.vpn:
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
        if not que.regla(regla):
            continue
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
    if que.vpn:
        for puerto in list(man.datos.get("selinux_puertos", [])):
            r = sis.ejecutar(["semanage", "port", "-d", "-t", "http_port_t", "-p", "tcp", puerto])
            if r.bien:
                man.datos["selinux_puertos"].remove(puerto)
            else:
                quedan.append("la etiqueta de SELinux de tcp/%s: semanage no la ha quitado" % puerto)
    #    Las de nftables e iptables, por su marca (las de los dos modos la comparten: quitando uno, se vuelven a poner
    #    las del otro); y se dice si el sistema las guardó con las suyas.
    if man.datos.get("cortafuegos_propio"):
        from . import cortafuegos as cf
        if que.todo:
            cf.quitar(sis, cf.MARCA)
        else:
            siguen = cf.permanentes_de(man.datos, modos=[x for x in man.modos if x != modo])
            try:
                cf.poner(sis, cf.MARCA, siguen, man.datos["cortafuegos_propio"].get("iptables", True))
            except cf.NoSe as error:
                quedan.append("tu cortafuegos: no he podido dejar solo las reglas de %s (%s). Lo arregla «sudo "
                              "hehermes-servidor instalar»" % (" y ".join(md.NOMBRES[x] for x in man.modos
                                                                          if x != modo), error))
        for ruta in cf.guardadas(sis):
            quedan.append("%s: tu cortafuegos guardado lleva reglas de HeHermes (se guardó con ellas puestas). No lo "
                          "toco: quítalas de ahí o vuelve a guardarlo ahora" % ruta)
    # 5. Las unidades, de la última a la primera: la XFRM, al final, cuando nginx ya no escucha en 10.77.0.1.
    for unidad in reversed(list(man.unidades)):
        if not que.de(md.de_unidad(unidad)):
            continue
        sis.ejecutar((ambito.systemctl if unidad in (p.UNIDAD_PASARELA, p.UNIDAD_VIGIA, p.SOCKET_LECTOR,
                                                     p.SOCKET_RESPALDO, p.SOCKET_ENTRADA, p.SOCKET_ACTUALIZAR)
                      else ["systemctl"]) + ["disable", "--now", unidad])
        if not que.todo:
            man.unidades.remove(unidad)
    # 6. Las líneas de --activar-api (que son de los dos), y el resto de ficheros.
    if que.todo:
        from .porchat import quitar_lineas_api
        quitar_lineas_api(sis, man, quedan, salida)
        if man.datos.get("exposicion"):
            quedan.append(_EXPOSICION % (man.datos["exposicion"]["linea"], man.datos["exposicion"]["env"]))
    if que.tls:
        # Lo que se le dijo a Hermes en su SOUL.md, para el lector de ficheros (que es de la pasarela).
        from . import alma
        alma.quitar(sis, man, quedan, salida)
    for ruta in sorted(man.ficheros):
        if ruta not in NGINX and que.fichero(ruta):
            quitar(ruta)
    sis.ejecutar(ambito.systemctl + ["daemon-reload"])
    #    La base de datos del vigía (con root, la hizo systemd; sin root, el instalador): lleva la clave de cada iPhone.
    if man.datos.get("vigia") and que.tls:
        sis.borrar_arbol(ambito.carpeta_estado_vigia)
        if ambito.carpeta_estado_vigia in man.carpetas:
            man.carpetas.remove(ambito.carpeta_estado_vigia)
        if not que.todo:
            del man.datos["vigia"]
    #    La carpeta de trabajo de la copia en iCloud: las instantáneas y las restauraciones se van; la copia de antes de
    #    una restauración (lo que había en Hermes, con sus claves) solo si no queda nada en ella, y si queda se dice.
    if que.tls and sis.es_carpeta(ambito.carpeta_respaldo):
        antes = ambito.carpeta_respaldo + "/antes"
        if sis.es_carpeta(antes) and sis.listar(antes):
            import shutil
            # Las instantáneas llevan copias de las bases y de las claves: fuera. (`borrar_arbol` solo borra carpetas
            # que se llamen hehermes*, y estas están dentro de una que sí.)
            for sub in ("instantaneas", "restauraciones"):
                shutil.rmtree(sis.ruta(ambito.carpeta_respaldo + "/" + sub), ignore_errors=True)
            quedan.append("%s: la copia de lo que había en Hermes antes de la última restauración (con sus claves). "
                          "No la borro: si no la quieres, bórrala tú" % antes)
        else:
            sis.borrar_arbol(ambito.carpeta_respaldo)
    #    La del ayudante que actualiza (el estado de la última, sus intentos y lo que dijo el instalador): de HeHermes.
    if que.tls and ambito.carpeta_actualizar and sis.es_carpeta(ambito.carpeta_actualizar):
        sis.borrar_arbol(ambito.carpeta_actualizar)
    #    La carpeta de estado de la pasarela (el borrado pendiente, su actividad): nada que no sea de HeHermes.
    if que.tls and sis.existe(ambito.carpeta_estado_pasarela):
        sis.borrar_arbol(ambito.carpeta_estado_pasarela)
        if ambito.carpeta_estado_pasarela in man.carpetas:
            man.carpetas.remove(ambito.carpeta_estado_pasarela)
    #    La carpeta de exportaciones de Hermes que creó el instalador, solo si está vacía: lo de dentro es de Hermes.
    if man.datos.get("exportaciones") and que.tls:
        sis.borrar(man.datos["exportaciones"])
        if sis.existe(man.datos["exportaciones"]):
            quedan.append("%s: la carpeta de exportaciones de Hermes no está vacía; lo de dentro es suyo, no lo toco"
                          % man.datos["exportaciones"])
        if not que.todo:
            del man.datos["exportaciones"]
    #    La carpeta de entrada de Hermes que creó el instalador: lo que el ayudante dejó a medias (`.subidas`, suyo) se
    #    va, y la carpeta solo si se queda vacía: lo que ya se entregó es de Hermes.
    if man.datos.get("entrada") and que.tls:
        carpeta = man.datos["entrada"]
        if not entrada_en_marcha:
            _borrar_subidas(sis, carpeta)
        sis.borrar(carpeta)
        if sis.existe(carpeta):
            quedan.append("%s: la carpeta de entrada de Hermes no está vacía; lo de dentro es suyo, no lo toco"
                          % carpeta)
        if not que.todo:
            del man.datos["entrada"]
    for usuario in list(man.datos.get("usuarios", [])):
        if not que.de(md.de_usuario(usuario)):
            continue
        if sis.ejecutar(["id", "-u", usuario]).bien:
            r = sis.ejecutar(["userdel", usuario])
            if not r.bien:
                quedan.append("el usuario %s: userdel ha fallado (%s)" % (usuario, (r.error or r.salida).strip()))
                continue
        man.datos["usuarios"].remove(usuario)
    # 7. Los paquetes que instaló él (quitando un modo, los suyos: python3-venv es de los dos).
    paquetes = [x for x in man.paquetes if que.de(md.de_paquete(x))]
    if quitar_paquetes and paquetes:
        salida("==> paquetes: " + " ".join(paquetes))
        if man.datos.get("familia") == "rhel":
            orden, que_orden = ["dnf", "remove", "-y", "-q"] + paquetes, "dnf remove"
        else:
            orden = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "purge", "-y", "-q"] + paquetes
            que_orden = "apt-get purge"
        r = sis.ejecutar(orden)
        if not r.bien:
            quedan.append("los paquetes: %s ha fallado (%s)" % (que_orden, (r.error or r.salida).strip()))
        elif not que.todo:
            man.datos["paquetes"] = [x for x in man.paquetes if x not in paquetes]
    # 8. El registro de la VPN (el de la pasarela es su tokens.json, que ya se ha ido con sus ficheros).
    registro = p.REGISTRO + "/dispositivos.json"
    if que.vpn:
        if not registro_de_dispositivos(sis):
            sis.borrar(registro)
            sis.borrar(p.REGISTRO)
        else:
            quedan.append(registro + ": quedan iPhone dados de alta")
    if que.todo:
        # Lo suyo en /etc/hehermes y las carpetas que creó, si se han quedado vacías.
        for nombre in sis.listar(m.CARPETA_COPIAS):
            if not any((e.get("copia") or {}).get("ruta") == m.CARPETA_COPIAS + "/" + nombre
                       for e in man.ficheros.values()):
                sis.borrar(m.CARPETA_COPIAS + "/" + nombre)
        sis.borrar(m.CARPETA_COPIAS)
        sis.borrar(man.ruta)
        for carpeta in sorted(man.carpetas, key=len, reverse=True):
            sis.borrar(carpeta)
        sis.borrar(man.ruta.rsplit("/", 1)[0])
    else:
        # El manifiesto sigue, sin este modo: lo que queda es del otro y lo común.
        man.quitar_modo(modo)
        if modo == "tls":
            man.datos.pop("pasarela", None)
        idos = set(de_la_vpn) | set(de_la_pasarela)
        from .modo_tls import nombres_de_la_pasarela
        siguen = set(_iphones(sis, man)) | (set(nombres_de_la_pasarela(sis, ambito)) if "tls" in man.modos else set())
        man.datos["dispositivos"] = [d for d in man.dispositivos if d not in idos or d in siguen]
        for carpeta in sorted(man.carpetas, key=len, reverse=True):
            if not any(r.startswith(carpeta + "/") for r in man.ficheros):
                sis.borrar(carpeta)
            if not sis.existe(carpeta):
                man.carpetas.remove(carpeta)
        man.guardar(sis)
    if quedan:
        salida("Se queda:\n  " + "\n  ".join(quedan))
    return quedan
