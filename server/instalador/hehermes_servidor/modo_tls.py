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
from . import gestor as gestores
from . import manifiesto as m
from . import piezas as p
from .aplicar import (Parada, Transaccion, _con_unidad, _escribir, _ficheros, _firewalld, _orden, _paquetes, _propio,
                      _ufw, apuntar_reinicios)
from .deteccion import (Deteccion, bloqueo, etiquetar, _cortafuegos, _direccion, _distro, _escuchan, _hermes,
                        _version_sin_api, regla_ufw_canonica)
from .entorno import leer_env
from .plan import Accion, Plan, _unidad, buscar_en_origen, codigo_de, ficheros_propios

TOKENS_VACIO = b'{\n  "v": 1,\n  "tokens": []\n}\n'
#: En la familia Debian, `venv` sin `ensurepip` viene aparte.
PAQUETE_VENV = "python3-venv"
DIAS_CERTIFICADO = 3650
#: Lo que hace falta libre donde van el instalador y el venv de cryptography (un venv con pip y la rueda ocupan unos
#: 40 MB): con menos, pip se para a medias.
MINIMO_LIBRE = 150 * 1024 * 1024


# MARK: Detectar


def detectar_tls(sis, man, ambito, direccion=None, hermes_home=None, activar_api=False, cortafuegos_a_mano=False,
                 corregir_exposicion=False, por_chat=False, solo_plan=False) -> Deteccion:
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
    _hermes(sis, det, hermes_home, activar_api, corregir_exposicion, ambito=ambito)
    _reinicio_pendiente(sis, det, man, ambito)
    if not ambito.root and det.hermes is not None and (det.hermes.api_pendiente or det.hermes.exposicion_pendiente) \
            and not gestores.puede_reiniciar(det.hermes.gestor, ambito):
        det.bloqueos.append("Para encender la API de Hermes o cerrarla a 127.0.0.1 hay que reiniciarlo, y sin root no "
                            "sé. Hazlo tú en %s (API_SERVER_ENABLED=true, API_SERVER_HOST=127.0.0.1 y una "
                            "API_SERVER_KEY) y reinicia Hermes; luego vuelve a lanzarme" % det.hermes.env)
        etiquetar(det.bloqueos, "api-hermes")
    _direccion(sis, det, direccion)
    det.puerto_pasarela = _puerto(sis, man)
    if det.puerto_pasarela is None:
        det.bloqueos.append(bloqueo("puerto", "no queda ningún puerto TCP libre para la pasarela entre el %d y el %d"
                                    % (p.PUERTO_MINIMO, p.PUERTO_MAXIMO)))
    _espacio(sis, det, ambito)
    _python_venv(sis, det, ambito)
    _systemd(sis, det, ambito, por_chat=por_chat, solo_plan=solo_plan)
    # Un vigía, lo haya puesto este instalador (`avisos`) o instalar.sh (el VPS de Daniel): la pasarela le pasa /avisos/.
    det.con_vigia = sis.existe(ambito.secreto_vigia)
    if det.puerto_pasarela is None:
        pass  # ya es un bloqueo: sin puerto no hay regla que mirar ni que decir
    elif ambito.root:
        det.usuario_pasarela = sis.ejecutar(["id", "-u", p.USUARIO_PASARELA]).bien
        _cortafuegos(sis, det, cortafuegos_a_mano, puerto_pasarela=det.puerto_pasarela)
    else:
        det.avisos.append("No corro como root, así que ni miro ni toco el cortafuegos. Si este servidor tiene uno (ufw, "
                          "firewalld, nftables…), o tu proveedor tiene el suyo en su panel, tiene que dejar entrar el "
                          "TCP %d (la pasarela) desde internet" % det.puerto_pasarela)
    _convivir(sis, det, man, ambito)
    return det


#: En el manifiesto (desde la 0.11.1): a Hermes le falta reiniciarse para leer lo que se le ha puesto en su .env. Se
#: apunta antes de tocarlo y, al programar su reinicio, cuándo («programado»): si algo se para o lo cortan entre medias,
#: la vez siguiente se sabe y se acaba.
REINICIO_DE_HERMES = "reinicio_de_hermes"
#: Lo que puede tardar en reiniciarse uno ya programado: los 90 s del temporizador, o lo que tarde en acabar su turno con
#: la recarga (`agent.restart_after_turn_timeout`, 1800 s de serie), y un margen. Pasado eso, si no contesta es otra
#: cosa, y se dice (`api-hermes`).
TARDA_EN_REINICIARSE = 1800 + 300


def _lineas_mias(sis, man, ambito, env) -> list:
    """Las líneas que encienden la API de Hermes y que puse yo en `env`: las de `--activar-api` en el manifiesto, o las
    de un `reinicia-hermes` que aún no ha pasado a él (`porchat.API_PENDIENTE`)."""
    from .porchat import API_PENDIENTE
    datos = man.datos.get("activar_api")
    if not isinstance(datos, dict):
        try:
            datos = json.loads(sis.leer_texto(ambito.carpeta_config + "/" + API_PENDIENTE) or "null")
        except ValueError:
            datos = None
    if not isinstance(datos, dict) or datos.get("env") != env or not isinstance(datos.get("lineas"), list):
        return []
    return [str(linea) for linea in datos["lineas"]]


def _reinicio_pendiente(sis, det, man, ambito):
    """Hasta la 0.11.0, si algo se paraba entre encender la API en el .env de Hermes y reiniciarlo (el cerrojo de apt, el
    plazo de su terminal, un `/stop`), la vez siguiente su API estaba «encendida» y no contestaba, y se paraba con
    `api-hermes` hasta que alguien lo reiniciara (y la app decía «No se ha cambiado nada»). Ahora, si su API no contesta,
    las líneas que la encienden son mías y siguen en su .env, y su reinicio está pendiente (apuntado y sin programar, o
    programado hace poco; o un `reinicia-hermes` sin hacer): si se sabe reiniciar, se sigue como con `--activar-api` (la
    versión, por su código) y se reinicia al acabar; si no, `reinicia-hermes` otra vez, que la app explica (`/restart`)."""
    hermes = det.hermes
    if hermes is None or not (hermes.habilitada and hermes.clave) or not det.bloqueos:
        return
    ultimo = det.bloqueos[-1]
    # El de «su API no contesta» es lo último que dice `_hermes` (y entonces no ha llegado a saber ni su versión ni si su
    # clave vale).
    if getattr(ultimo, "codigo", None) != "api-hermes" or hermes.version is not None or hermes.clave_vale is not None:
        return
    lineas = _lineas_mias(sis, man, ambito, hermes.env)
    texto = (sis.leer_texto(hermes.env) or "").splitlines()
    if not lineas or not all(linea in texto for linea in lineas):
        return
    from .porchat import API_PENDIENTE
    apuntado = man.datos.get(REINICIO_DE_HERMES)
    programado = apuntado.get("programado") if isinstance(apuntado, dict) else None
    sin_programar = isinstance(apuntado, dict) and not isinstance(programado, (int, float))
    ya_programado = isinstance(programado, (int, float)) and time.time() - programado < TARDA_EN_REINICIARSE
    pendiente = sin_programar or ya_programado or sis.existe(ambito.carpeta_config + "/" + API_PENDIENTE)
    if not pendiente or sis.http_get("http://127.0.0.1:%d/health" % hermes.puerto)[0] is not None:
        return
    nombres = ", ".join(linea.split("=", 1)[0] for linea in lineas)
    if gestores.puede_reiniciar(hermes.gestor, ambito):
        det.bloqueos.pop()
        _version_sin_api(sis, det, hermes)
        if ya_programado and not sin_programar:
            # La frase otra vez antes de que llegue: se sigue, y no se programa otro (dos reinicios seguidos podrían
            # cortar el turno de esta pasada).
            hermes.reinicio_pendiente = "programado"
            det.avisos.append("Hermes tiene programado su reinicio (hace %d s) para leer lo que le puse en %s (%s): su "
                              "API contesta en cuanto se reinicie" % (time.time() - programado, hermes.env, nombres))
            return
        hermes.reinicio_pendiente = True
        det.avisos.append("A Hermes le falta reiniciarse para leer lo que le puse en %s (%s): una pasada anterior se "
                          "paró antes. Lo reinicio al acabar" % (hermes.env, nombres))
        return
    det.bloqueos[-1] = bloqueo("reinicia-hermes", "La API de Hermes ya está encendida en %s (le puse %s), pero Hermes no "
                               "se ha reiniciado, y no sé reiniciarlo (lo encuentro por %s). Reinícialo tú (/restart en "
                               "su chat) y vuelve a lanzar el mismo comando" % (hermes.env, nombres, hermes.origen))


def _puerto(sis, man) -> int:
    """El de la instalación, si ya lo hay: fijo desde que se eligió. Si no, uno libre al azar del rango."""
    from .porchat import _puertos_tcp_ocupados, elegir_puerto, puertos_efimeros
    dado = (man.datos.get("pasarela") or {}).get("puerto")
    if isinstance(dado, int) and p.PUERTO_MINIMO <= dado <= p.PUERTO_MAXIMO:
        return dado
    return elegir_puerto(_puertos_tcp_ocupados(sis), evitar=puertos_efimeros(sis))


def _espacio(sis, det, ambito):
    """Sin sitio para el venv, pip se pararía a medias: se dice antes de tocar nada."""
    for ruta in dict.fromkeys((ambito.prefijo, ambito.venv)):
        libre = sis.libre(ruta)
        if libre is not None and libre < MINIMO_LIBRE:
            det.bloqueos.append(bloqueo("sin-disco", "no hay sitio: donde va %s quedan %d MB libres, y hacen falta %d. "
                                        "Libera espacio (df -h te dice dónde) y vuelve a lanzarme"
                                        % (ruta, libre // (1024 * 1024), MINIMO_LIBRE // (1024 * 1024))))
            return


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
    etiquetar(det.bloqueos, "ensurepip")


def _linger(sis, usuario) -> bool:
    r = sis.ejecutar(["loginctl", "show-user", usuario, "-p", "Linger"])
    return r.bien and r.salida.strip() == "Linger=yes"


def _systemd(sis, det, ambito, por_chat=False, solo_plan=False):
    """Con root, systemd del sistema (lo mira `_distro`). Sin root, una unidad de usuario: con linger sigue siempre;
    sin él, solo mientras haya una sesión abierta, y sin gestor de usuario no hay forma (y no me invento otra).

    Por chat, sin linger, no se da el enlace (auditoría §7): el iPhone quedaría emparejado con una pasarela que se para
    al cerrarse la sesión, y para él sería «no contesta» sin más. Se prueba a encenderlo (hay sistemas cuyo polkit deja
    a cada usuario encender el suyo); si no se puede, se para antes de tocar nada, con `hehermes-error:linger` y el
    remedio exacto."""
    if ambito.root:
        return
    det.linger = _linger(sis, ambito.usuario)
    det.gestor_usuario = sis.ejecutar(["systemctl", "--user", "is-system-running"]).salida.strip() in (
        "running", "degraded", "starting")
    if det.linger:
        return
    remedio = "sudo loginctl enable-linger %s" % ambito.usuario
    if det.gestor_usuario and por_chat:
        if solo_plan:
            det.avisos.append("Sin linger, la pasarela se pararía al cerrarse tu última sesión: al instalar probaré a "
                              "encenderlo (loginctl enable-linger); si no puedo, no daré el enlace")
            return
        if sis.ejecutar(["loginctl", "--no-ask-password", "enable-linger", ambito.usuario]).bien and \
                _linger(sis, ambito.usuario):
            det.linger = True
            det.avisos.append("He encendido linger para %s (loginctl enable-linger): la pasarela seguirá aunque se "
                              "cierren tus sesiones. Desinstalar no lo apaga" % ambito.usuario)
            return
        det.bloqueos.append(bloqueo("linger", "Por chat no doy el enlace: sin linger, la pasarela se para en cuanto se "
                                    "cierra tu última sesión en este servidor, y el iPhone se quedaría sin conexión sin "
                                    "saber por qué; y yo no puedo encenderlo. No he tocado nada. Que un administrador "
                                    "ejecute: %s; y vuelve a pedírselo a tu Hermes" % remedio))
        return
    if det.gestor_usuario:
        det.avisos.append("Sin linger, la pasarela se para cuando cierres tu última sesión en este servidor. Para que "
                          "siga siempre, que un administrador ejecute: %s" % remedio)
        return
    det.bloqueos.append("Sin root, la pasarela solo puede arrancar como una unidad de tu systemd de usuario, y aquí no "
                        "hay ninguno en marcha (ni linger ni una sesión). Que un administrador ejecute: sudo loginctl "
                        "enable-linger %s; o que instale como root (sudo). No me invento otro arranque" % ambito.usuario)
    etiquetar(det.bloqueos, "linger")


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
    if not det.distro.get("arquitectura") or det.hermes is None or det.hermes.clave is None or \
            det.puerto_pasarela is None:
        return Plan(det, acciones, bloqueos, avisos, op)

    def fichero(ruta, contenido, modo=0o644, tipo="fichero", grupo=None, detalle=""):
        datos = contenido.encode() if isinstance(contenido, str) else contenido
        estado = m.clasificar(sis, man, ruta, datos, reemplazar=op.reemplazar)
        acciones.append(Accion(tipo, ruta, estado, detalle, datos, modo, grupo))
        return acciones[-1]

    if getattr(det, "falta_venv", False):
        acciones.append(Accion("paquete", PAQUETE_VENV, m.NUEVO, "para el venv de cryptography"))

    # La API de Hermes. Lo último que se aplica (`aplicar_hermes`), y su reinicio, al acabar.
    reinicio = ""
    if det.hermes.api_pendiente or det.hermes.exposicion_pendiente:
        reinicio = ("reinicia Hermes al acabar, cuando acabe su turno (systemctl reload)"
                    if gestores.recarga_con_drenaje(sis, det.hermes.gestor, ambito.root) else
                    "reinicia Hermes 90 s después de acabar")
    if det.hermes.api_pendiente:
        nombres = ", ".join(linea.split("=", 1)[0] for linea in det.hermes.api_pendiente)
        acciones.append(Accion("env", det.hermes.env, m.NUEVO, "añade %s (con una copia antes); %s" % (nombres, reinicio),
                               det.hermes.api_pendiente))
    if det.hermes.exposicion_pendiente:
        acciones.append(Accion("exposicion", det.hermes.env, m.NUEVO, "añade %s (con una copia antes), para que la API "
                               "de Hermes solo escuche en 127.0.0.1; %s" % (det.hermes.exposicion_pendiente, reinicio),
                               [det.hermes.exposicion_pendiente]))
    if getattr(det.hermes, "reinicio_pendiente", False) is True:
        # Lo dice el aviso de `_reinicio_pendiente`; aquí, que es un cambio (y se aplica aunque no haya otro). Uno ya
        # programado no: llegará solo.
        acciones.append(Accion("reinicio", det.hermes.env, m.NUEVO, "reiniciar Hermes, que lo tenía pendiente"))
    # Cómo mandarle ficheros al iPhone, en su SOUL.md (desde la 0.10.4).
    from . import alma
    alma.planear(sis, det, man, acciones, avisos)

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
        bloqueos.append(bloqueo("paquete", "el paquete no trae hehermes-dispositivo"))
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
    hay_siguiente = sis.existe(ambito.cert_siguiente) and sis.existe(ambito.clave_siguiente)
    acciones.append(Accion("certificado_siguiente", ambito.cert_siguiente,
                           m.YA_ESTA if hay_siguiente and ambito.cert_siguiente in man.ficheros else
                           (m.AJENO if hay_siguiente else m.NUEVO),
                           "el que viene después: la app puede anclar su huella ya, y rotar no obliga a emparejar"))

    # Los avisos (el vigía y el lector de ficheros), siempre desde la 0.8.0: con un código de avisos (ahora o uno de
    # antes), con su credencial; sin él, con el permiso de cada iPhone. Antes que la pasarela, que así ya sabe que le
    # pasa /avisos/ (y con root, lleva su secreto por credencial).
    from . import avisos as vigias
    det.vigia = vigias.planear(sis, det, man, op, origen, acciones, bloqueos, fichero, avisos)

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
    _unidad(sis, acciones, p.UNIDAD_PASARELA, pasarela + [a for a in acciones if a.tipo in ("certificado",
                                                                                        "certificado_siguiente")],
            "la pasarela, en el TCP %d" % det.puerto_pasarela, "restart", ambito.systemctl,
            codigo=codigo_de(acciones, ambito.prefijo, "hehermes-pasarela", "hehermes_servidor/"), quien="la pasarela",
            man=man)
    # El borrado de verdad de lo que la app borra de Hermes, de noche (`mantenimiento.py`).
    borrado = [fichero(ambito.unidad_borrado, p.unidad_borrado(ambito)),
               fichero(ambito.temporizador_borrado, p.temporizador_borrado())]
    _unidad(sis, acciones, "hehermes-borrado.timer", borrado, "de noche, si la app ha borrado algo de Hermes, compacta "
            "su base con Hermes parado unos segundos (para que no se pueda recuperar)", "restart", ambito.systemctl)
    if ambito.root:
        clave = [fichero(p.UNIDAD_PASARELA_CLAVE_SERVICE, p.unidad_pasarela_clave_service()),
                 fichero(p.UNIDAD_PASARELA_CLAVE_PATH, p.unidad_pasarela_clave_path(det.hermes.env))]
        _unidad(sis, acciones, "hehermes-pasarela-clave.path", clave, "si cambia la clave de Hermes, se la copia a la "
                "pasarela", "restart")

    # El cortafuegos, solo con root
    if ambito.root:
        _plan_cortafuegos(sis, det, man, acciones, fichero)

    # El primer iPhone
    from . import porchat
    activos = porchat.activos_del_servidor(sis, man, ambito) if op.por_chat else []
    if op.iphone is not None:
        from .plan import NOMBRE_VALIDO
        if not NOMBRE_VALIDO.fullmatch(op.iphone):
            bloqueos.append("el nombre del iPhone tiene que ser de minúsculas, números y guiones, hasta 31 (no «%s»)"
                            % op.iphone)
            etiquetar(bloqueos, "nombre-iphone")
        else:
            ya = op.iphone in nombres_de_la_pasarela(sis, ambito)
            sustituye = porchat.a_sustituir(man, op, activos)
            if op.por_chat:
                detalle = "ya dado de alta" if ya else "su token, sin QR (se entrega por el canje)"
                if sustituye:
                    detalle += ("; en lugar de «%s», que se dio de alta por chat y no ha usado la pasarela: su token deja "
                                "de valer" % sustituye)
            elif not op.terminal:
                detalle = "ya dado de alta" if ya else "sin un terminal no pinto su QR: lo dejo para después"
            else:
                detalle = "ya dado de alta" if ya else "su token y su QR, aquí en el terminal"
            acciones.append(Accion("dispositivo", op.iphone, m.YA_ESTA if ya else m.NUEVO, detalle,
                                   {"sustituye": sustituye} if sustituye else None))

    if op.por_chat:
        bloqueos.extend(porchat.bloqueos(sis, man, op, activos=activos, ambito=ambito))
        acciones.append(Accion("canje", "hehermes-canje", m.NUEVO,
                               "10 minutos en un TCP al azar del 58000 al 65500, %sde un solo uso; al acabar, la línea "
                               "del enlace" % ("abierto solo mientras dura y " if ambito.root else "")))

    for a in acciones:
        if a.estado == m.AJENO:
            bloqueos.append("%s no es mío (no está en mi manifiesto): no lo toco. Si quieres que lo sustituya, "
                            "guardando antes una copia: --reemplazar %s" % (a.objeto, a.objeto)
                            if a.tipo not in ("certificado", "certificado_siguiente") else
                            "%s no es mío (no está en mi manifiesto): no lo toco. Si es de una instalación vieja, "
                            "bórralo tú (y su clave.pem) y vuelve a lanzarme" % a.objeto)
            etiquetar(bloqueos, "ficheros-ajenos")
        elif a.estado == m.MODIFICADO:
            bloqueos.append("%s es mío, pero alguien lo ha cambiado desde que lo escribí: no lo toco. Si quieres que "
                            "lo sustituya, guardando antes una copia: --reemplazar %s" % (a.objeto, a.objeto))
            etiquetar(bloqueos, "ficheros-ajenos")
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


def pasos_de(plan) -> list:
    """Los pasos de esta pasada, en su orden (`marcha.Marcha`): los de `aplicar_tls`, el canje por chat y, lo último, lo
    de Hermes (`aplicar_hermes`)."""
    det, acciones = plan.deteccion, plan.acciones

    def cambia(*tipos):
        return any(a.tipo in tipos and a.cambia for a in acciones)

    claves = (["paquetes"] if cambia("paquete") else []) + ["ficheros", "venv", "certificados", "servicios"]
    if det.ambito.root:
        claves.append("cortafuegos")
    claves.append("comprobar")
    if cambia("dispositivo"):
        claves.append("iphone")
    if plan.opciones.por_chat:
        claves.append("canje")
    if cambia("env", "exposicion", "soul", "reinicio"):
        claves.append("hermes")
    return claves


def aplicar_tls(sis, plan, man, origen, salida=print, terminal=False, marcha=None, con_hermes=True) -> dict:
    """Aplica el plan en orden, con el manifiesto al día tras cada paso. Devuelve {"token": …} del primer iPhone si se
    ha dado de alta por chat (lo necesita el canje), o {}.

    Desde la 0.11.1, primero lo que puede fallar (los paquetes, el venv y pip, los certificados, las unidades, el
    cortafuegos y la comprobación) y lo de Hermes lo último (`aplicar_hermes`): hasta la 0.11.0 su .env iba lo primero, y
    un fallo a mitad (el cerrojo de dpkg de un VPS recién creado) dejaba su API encendida en el .env sin reiniciarlo.
    Con `con_hermes=False`, lo de Hermes no va aquí: por chat va detrás del canje (`cli._instalar`). `marcha` dice cada
    paso y junta los avisos para la app (`marcha.Marcha`)."""
    from .marcha import Marcha
    marcha = marcha or Marcha()
    if not plan.puede_seguir:
        raise Parada("el plan tiene bloqueos")
    det, acciones, ambito = plan.deteccion, plan.acciones, plan.deteccion.ambito
    systemctl = ambito.systemctl
    if not man.en_disco and "instalado" not in man.datos:
        man.datos["instalado"] = time.time()
    man.anadir_modo("tls")
    man.datos["pasarela"] = {"puerto": det.puerto_pasarela, "root": ambito.root}
    # Lo que la limpieza de noche necesita saber de Hermes para pararlo, compactarlo y volver a arrancarlo.
    # Desde la 0.10.2, quién lo lleva (`gestor_hermes`: su unidad, del sistema o de usuario, o su contenedor), que es lo
    # que para y arranca la limpieza de noche. `unidad_hermes` sigue siendo la del sistema, como la leía la 0.10.1.
    gestor = det.hermes.gestor
    man.datos["mantenimiento"] = {
        "unidad_hermes": gestor.nombre if gestor is not None and gestor.tipo == "sistema" else None,
        "gestor_hermes": gestor.a_dict() if gestor is not None else None,
        "origen": det.hermes.origen, "casa": det.hermes.home.rstrip("/"), "usuario": det.hermes.usuario,
        "puerto": det.hermes.puerto}
    from .porchat import adoptar_api_pendiente
    adoptar_api_pendiente(sis, man, ambito)
    vigia = getattr(det, "vigia", None)
    from . import avisos as vigias
    if vigia:
        # Lo que no es secreto del código de avisos: con ello se repara sin pedirlo otra vez. La credencial, no. Sin
        # código, solo que el vigía va sin credencial.
        man.datos["vigia"] = vigias.para_el_manifiesto(vigia)
    if det.familia != "debian":
        man.datos["familia"] = det.familia
    hermes_pendiente = any(a.tipo in ("env", "exposicion", "reinicio") and a.cambia for a in acciones) or \
        bool(getattr(det.hermes, "reinicio_pendiente", False))
    if not hermes_pendiente:
        # Hermes contesta con lo de su .env: un reinicio apuntado por una pasada anterior ya se ha hecho.
        man.datos.pop(REINICIO_DE_HERMES, None)
    man.guardar(sis)
    de = lambda *tipos: [a for a in acciones if a.tipo in tipos]  # noqa: E731

    if any(a.cambia for a in de("paquete")):
        marcha.empezar("paquetes")
        _paquetes(sis, man, de("paquete"), salida, det.familia)
    marcha.empezar("ficheros")
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
    unidades = {p.UNIDAD_PASARELA_CLAVE_PATH, p.UNIDAD_PASARELA_CLAVE_SERVICE, p.UNIDAD_CORTAFUEGOS,
                ambito.unidad_borrado, ambito.temporizador_borrado}
    sueltos = [a for a in acciones if a.tipo in ("fichero", "enlace")
               and a.objeto not in pasarela | unidades | vigias.rutas(ambito)]
    # El código de la pasarela y del vigía va aquí: antes de escribirlo, se apunta que hay que reiniciarlos.
    apuntar_reinicios(sis, man, acciones)
    _ficheros(sis, man, sueltos, "ficheros", salida)

    # La carpeta de la pasarela: con root, 0750 y del grupo hh-pasarela, que tiene que llegar a pasarela.ini, al
    # certificado y a tokens.json (la clave del certificado y la de Hermes le llegan por credenciales).
    if not sis.es_carpeta(ambito.carpeta_pasarela):
        man.apuntar_carpetas(sis, ambito.carpeta_pasarela + "/x")
    sis.carpeta(ambito.carpeta_pasarela, 0o750 if ambito.root else 0o700)
    if ambito.root:
        _orden(sis, ["chown", "root:" + p.USUARIO_PASARELA, ambito.carpeta_pasarela], "chown de la pasarela")
    # Y la de las claves de los agentes (desde la 0.11.0, `[agentes] claves` de pasarela.ini): la escribe su ayudante.
    vigias.crear_claves_de_agentes(sis, ambito, ambito.claves_agentes_pasarela, p.USUARIO_PASARELA, _orden)
    man.guardar(sis)

    from .porchat import ParadaDelCanje, _venv
    marcha.empezar("venv")
    try:
        _venv(sis, man, salida, ambito)
    except ParadaDelCanje as error:
        raise Parada(str(error), codigo=error.codigo)
    marcha.empezar("certificados")
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
    for a in de("certificado_siguiente"):
        if a.cambia:
            _certificado_siguiente(sis, man, ambito, salida)

    marcha.empezar("servicios")

    def permisos(escritos):
        if not ambito.root:
            return
        for accion in escritos:
            if accion.objeto in (ambito.pasarela_ini, ambito.tokens):
                _orden(sis, ["chown", "root:" + p.USUARIO_PASARELA, accion.objeto], "chown de %s" % accion.objeto)
        # La copia de la clave de Hermes es de la pasarela, que la lee sola cuando cambia (desde la 0.9.0; antes le
        # llegaba por LoadCredential y cada rotación la reiniciaba). Siempre, también al actualizar sin cambiarla.
        if sis.existe(ambito.clave_hermes):
            _orden(sis, ["chown", "%s:%s" % (p.USUARIO_PASARELA, p.USUARIO_PASARELA), ambito.clave_hermes],
                   "chown de %s" % ambito.clave_hermes)

    if vigia:
        vigias.aplicar_secretos(sis, man, acciones, ambito, salida, _orden)
    if not ambito.root and not sis.es_carpeta(ambito.carpeta_estado_pasarela):
        # Con root la hace systemd (StateDirectory); sin root, aquí, antes de arrancar la pasarela, que escribe en ella.
        man.apuntar_carpetas(sis, ambito.carpeta_estado_pasarela + "/x")
        sis.carpeta(ambito.carpeta_estado_pasarela, 0o700)
        man.guardar(sis)
    _con_unidad(sis, man, [a for a in acciones if a.objeto in pasarela or a.objeto == p.UNIDAD_PASARELA],
                p.UNIDAD_PASARELA, salida, systemctl=systemctl, despues=permisos)
    if vigia:
        vigias.aplicar_unidades(sis, man, acciones, ambito, salida, hermes=det.hermes)
    _con_unidad(sis, man, [a for a in acciones if a.objeto in (ambito.unidad_borrado, ambito.temporizador_borrado,
                                                                "hehermes-borrado.timer")],
                "hehermes-borrado.timer", salida, systemctl=systemctl)
    if ambito.root:
        _con_unidad(sis, man, [a for a in acciones if a.objeto in (p.UNIDAD_PASARELA_CLAVE_PATH,
                                                                    p.UNIDAD_PASARELA_CLAVE_SERVICE,
                                                                    "hehermes-pasarela-clave.path")],
                    "hehermes-pasarela-clave.path", salida)
        marcha.empezar("cortafuegos")
        _ufw(sis, man, de("regla"), salida)
        _firewalld(sis, man, det, de("firewalld"), salida)
        _propio(sis, man, det, de("propio"), salida)
        _con_unidad(sis, man, [a for a in acciones if a.objeto in (p.UNIDAD_CORTAFUEGOS, "hehermes-cortafuegos.service")],
                    "hehermes-cortafuegos.service", salida)

    marcha.empezar("comprobar")
    _esperar_a_la_pasarela(sis, det.puerto_pasarela)
    comprobado = comprobar_tls(sis, man, ambito, hermes_pendiente=hermes_pendiente, con_vigia=False)
    fallos = [texto for bien, texto in comprobado if not bien]
    if fallos:
        raise Parada("la comprobación no pasa:\n  - " + "\n  - ".join(fallos))
    for _, texto in comprobado:
        if texto.startswith("alcance"):
            # Lo que se sabe (y lo que no) de si la app llegará por la dirección del QR: también por chat, antes del
            # enlace, para que Hermes se lo cuente a quien lo pidió.
            salida("==> " + texto)
    if vigia and _clave_nueva_sin_root(plan):
        # Sin root, el vigía lee la clave de Hermes de su .env al arrancar, y la nueva va lo último (`aplicar_hermes`):
        # hasta entonces no puede arrancar, y no hay nada que comprobar.
        salida("==> los avisos\n    El vigía arranca con la clave nueva de Hermes, que va lo último (lo reinicio "
               "entonces); \"%s comprobar\" lo mira cuando quieras." % ambito.orden)
    elif vigia:
        # Lo del vigía y el lector se dice, pero no para: la pasarela ya funciona, y el relé es de otra máquina (su
        # cortafuegos, su credencial) y no se arregla repitiendo esto. `comprobar` lo vuelve a mirar cuando se quiera.
        resultados = []
        vigias.comprobar(sis, man, ambito, lambda bien, si, no: resultados.append((bool(bien), si if bien else no)),
                         hermes_pendiente=hermes_pendiente)
        salida("==> los avisos")
        for bien, texto in resultados:
            salida("    %-4s %s" % ("bien" if bien else "MAL", texto))
        if not all(bien for bien, _ in resultados):
            salida("    El vigía no está bien del todo (arriba). La pasarela sí: la app ya puede conectar, y los avisos "
                   "llegarán cuando se arregle lo de arriba (\"%s comprobar\" lo vuelve a mirar)."
                   % ("sudo hehermes-servidor" if ambito.root else ambito.orden))
            marcha.avisar("avisos-push")

    resultado = {}
    if any(a.cambia for a in de("dispositivo")):
        marcha.empezar("iphone")
    for a in de("dispositivo"):
        if not a.cambia:
            continue
        if not plan.opciones.por_chat and not terminal:
            salida("==> el iPhone «%s»: sin un terminal no pinto su QR (lleva su token). Desde el tuyo: %s%s alta %s"
                   % (a.objeto, "sudo " if ambito.root else "", "hehermes-dispositivo", a.objeto))
            continue
        from . import tokens
        sustituye = (a.datos or {}).get("sustituye") if isinstance(a.datos, dict) else None
        if plan.opciones.por_chat and sustituye:
            # El que se dio de alta por chat y no llegó a usar la pasarela: sale para que entre este (decisión 7).
            tokens.baja(sis.ruta(ambito.tokens), sustituye)
            if sustituye in man.dispositivos:
                man.dispositivos.remove(sustituye)
            man.guardar(sis)
            salida("==> «%s» deja de valer: se dio de alta por chat y no llegó a usar la pasarela" % sustituye)
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
            salida("Escanéalo desde la app HeHermes. Lleva el token de «%s»: ni lo compartas ni le hagas "
                   "captura. No se puede volver a pintar: si hace falta otro, hehermes-dispositivo rotar %s."
                   % (a.objeto, a.objeto))
        del token
    if con_hermes:
        aplicar_hermes(sis, plan, man, salida, marcha)
    return resultado


def _clave_nueva_sin_root(plan) -> bool:
    """Sin root y con una API_SERVER_KEY nueva para Hermes: el vigía, que la lee de su .env, tiene que esperar a ella."""
    return not plan.deteccion.ambito.root and any(
        str(linea).startswith("API_SERVER_KEY=") for a in plan.acciones if a.tipo == "env" and a.cambia
        for linea in a.datos or ())


def aplicar_hermes(sis, plan, man, salida=print, marcha=None) -> bool:
    """Lo último de todo (desde la 0.11.1): lo que se escribe en Hermes, su .env (`--activar-api`,
    `--corregir-exposicion`) y su SOUL.md. Antes de tocar su .env se apunta que le falta reiniciarse
    (`REINICIO_DE_HERMES`): si algo se para o lo cortan antes de programar su reinicio, la vez siguiente se sabe
    (`_reinicio_pendiente`). Devuelve si hay que reiniciarlo: lo programa `cli._instalar`, lo último que hace, pase lo
    que pase. Sin root y con una clave nueva, el vigía (que la lee del .env al arrancar) se reinicia aquí."""
    from . import alma
    from .marcha import Marcha
    from .porchat import activar_api, corregir_exposicion
    marcha = marcha or Marcha()
    ambito = plan.deteccion.ambito
    de = lambda *tipos: [a for a in plan.acciones if a.tipo in tipos and a.cambia]  # noqa: E731
    if not de("env", "exposicion", "soul", "reinicio"):
        return False
    marcha.empezar("hermes")
    reiniciar = bool(de("env", "exposicion", "reinicio"))
    if reiniciar:
        man.datos[REINICIO_DE_HERMES] = {"desde": time.time()}
        man.guardar(sis)
    for a in de("env"):
        activar_api(sis, man, a, salida, ambito)
        marcha.en_hermes.append("su API encendida en %s" % a.objeto)
    for a in de("exposicion"):
        corregir_exposicion(sis, man, a, salida, ambito)
        marcha.en_hermes.append("%s en %s" % (a.datos[0], a.objeto))
    for a in de("soul"):
        alma.anadir(sis, man, a, salida, ambito)
        marcha.en_hermes.append("cómo mandarte ficheros en %s" % a.objeto)
    if _clave_nueva_sin_root(plan) and p.UNIDAD_VIGIA in man.unidades:
        sis.ejecutar(ambito.systemctl + ["reset-failed", p.UNIDAD_VIGIA], plazo=60)
        r = sis.ejecutar(ambito.systemctl + ["restart", p.UNIDAD_VIGIA], plazo=180)
        salida("==> el vigía, reiniciado para leer la clave nueva de Hermes%s" % (
            "" if r.bien else " (no ha podido: %s; systemctl --user restart %s)"
            % ((r.error or r.salida).strip()[-160:] or r.codigo, p.UNIDAD_VIGIA)))
    return reiniciar


def _certificado_siguiente(sis, man, ambito, salida) -> str:
    """El par que viene después, en `siguiente/` (la carpeta, como la de la pasarela; la clave, 0600 y sin usar hasta
    rotar; el certificado, 0644, que la pasarela lee para publicar su huella). Devuelve su huella."""
    if not sis.es_carpeta(ambito.carpeta_siguiente):
        man.apuntar_carpetas(sis, ambito.cert_siguiente)
    sis.carpeta(ambito.carpeta_siguiente, 0o750 if ambito.root else 0o700)
    if ambito.root:
        _orden(sis, ["chown", "root:" + p.USUARIO_PASARELA, ambito.carpeta_siguiente], "chown de la siguiente")
    r = sis.ejecutar([ambito.python_venv, "-I", "-B", "-m", "hehermes_servidor.canje", "preparar",
                      ambito.carpeta_siguiente, "--dias", str(DIAS_CERTIFICADO)])
    if not r.bien:
        raise Parada("no he podido crear el certificado siguiente de la pasarela: %s" % (r.error or r.salida).strip())
    sis.escribir(ambito.cert_siguiente, sis.leer(ambito.cert_siguiente) or b"", modo=0o644)
    man.apuntar_gestionado(ambito.cert_siguiente)
    man.apuntar_gestionado(ambito.clave_siguiente)
    man.guardar(sis)
    siguiente = huella_de(sis, ambito.cert_siguiente)
    salida("==> el certificado siguiente de la pasarela: huella %s" % siguiente)
    return siguiente


def huella_de(sis, ruta) -> str | None:
    from .pasarela import huella_de_der
    texto = sis.leer_texto(ruta)
    if not texto:
        return None
    try:
        return huella_de_der(ssl.PEM_cert_to_DER_cert(texto))
    except ValueError:
        return None


def rotar_certificado(sis, man, ambito, salida) -> int:
    """`hehermes-servidor certificado rotar`: el siguiente pasa a ser el de la pasarela, el de ahora queda en
    `anterior/` (para volver atrás a mano), se hace otro siguiente y se reinicia la pasarela. Los iPhone que ya anclaban
    la huella siguiente (la app que la pide a `GET /hehermes/v1/huellas`) siguen sin hacer nada; los demás necesitan un
    QR nuevo (`hehermes-dispositivo rotar <nombre>`)."""
    if "tls" not in man.modos:
        salida("error: aquí no está la pasarela")
        return 1
    if not (sis.existe(ambito.cert_siguiente) and sis.existe(ambito.clave_siguiente)):
        salida("error: no hay certificado siguiente (%s). Lo pone «instalar» (desde la 0.9.0): lánzalo antes, y "
               "espera a que tus iPhone hayan pedido su huella, antes de rotar" % ambito.cert_siguiente)
        return 1
    antes, despues = huella(sis, ambito), huella_de(sis, ambito.cert_siguiente)
    if not sis.es_carpeta(ambito.carpeta_anterior):
        man.apuntar_carpetas(sis, ambito.carpeta_anterior + "/cert.pem")
    sis.carpeta(ambito.carpeta_anterior, 0o700)
    # Primero la copia del de ahora; luego el siguiente en su sitio (la clave antes que el certificado: la pasarela no
    # lee ninguno de los dos hasta reiniciarse); y el siguiente ya no está.
    for de, a, modo in ((ambito.clave, ambito.carpeta_anterior + "/clave.pem", 0o600),
                        (ambito.cert, ambito.carpeta_anterior + "/cert.pem", 0o644),
                        (ambito.clave_siguiente, ambito.clave, 0o600),
                        (ambito.cert_siguiente, ambito.cert, 0o644)):
        datos = sis.leer(de)
        if datos is None:
            salida("error: no puedo leer %s; no he terminado de rotar (lo de antes está en %s)"
                   % (de, ambito.carpeta_anterior))
            return 1
        sis.escribir(a, datos, modo=modo)
    for ruta in (ambito.carpeta_anterior + "/clave.pem", ambito.carpeta_anterior + "/cert.pem"):
        man.apuntar_gestionado(ruta)
    sis.borrar(ambito.clave_siguiente)
    sis.borrar(ambito.cert_siguiente)
    man.guardar(sis)
    try:
        nueva = _certificado_siguiente(sis, man, ambito, salida)
    except Parada as error:
        salida("error: %s. La pasarela ya lleva el certificado nuevo; vuelve a lanzar esto para el siguiente." % error)
        nueva = None
    r = sis.ejecutar(ambito.systemctl + ["try-restart", p.UNIDAD_PASARELA])
    salida("==> la pasarela, reiniciada con el certificado nuevo%s" % ("" if r.bien else " (NO: reiníciala tú)"))
    salida("    antes     %s (queda en %s)" % (antes, ambito.carpeta_anterior))
    salida("    ahora     %s" % despues)
    salida("    siguiente %s" % (nueva or "ninguno"))
    salida("Los iPhone que ya anclaban la huella de ahora siguen conectando. Los que no (una app que no la ha pedido "
           "todavía), no: necesitan un QR nuevo (%shehermes-dispositivo rotar <nombre>)." % ("sudo " if ambito.root
                                                                                            else ""))
    return 0 if r.bien and nueva else 1


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


def comprobar_tls(sis, man, ambito, hermes_pendiente=False, con_vigia=True) -> list:
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
    if sonda is not None:
        _alcance(sis, ambito, puerto, esperada, mira)
    siguiente = huella_de(sis, ambito.cert_siguiente)
    mira(True, "pasarela: la huella siguiente, para rotar sin volver a emparejar: %s" % siguiente
         if siguiente else "pasarela: sin certificado siguiente (rotar el de ahora obligaría a volver a emparejar; "
         "lo pone «instalar»)", "")
    ini = _ini(sis, ambito)
    env = ini.get("env")
    clave = leer_clave_hermes(sis.leer_texto(env) or "") if env else None
    if hermes_pendiente:
        mira(True, "Hermes: lo nuevo de su .env vale cuando se reinicie, al acabar", "")
    elif clave:
        estado, _ = sis.http_get("http://127.0.0.1:%s/api/sessions?limit=1" % ini.get("puerto", 8642),
                                 {"Authorization": "Bearer " + clave})
        mira(estado == 200, "Hermes: contesta con su clave", "Hermes: no contesta con su clave (%s)" % estado)
        if estado in (200, 404):
            _capacidades_de_hermes(sis, man, ini.get("puerto", 8642), mira, sin_bandeja=estado == 404)
        if ambito.root:
            copia = leer_clave_hermes(sis.leer_texto(ambito.clave_hermes) or "")
            mira(copia == clave, "pasarela: su copia de la clave de Hermes está al día",
                 "pasarela: su copia de la clave de Hermes es vieja (Hermes le dirá 401). La pone al día: sudo "
                 "systemctl start hehermes-pasarela-clave")
    else:
        mira(False, "", "Hermes: no encuentro su clave (%s)" % env)
    if con_vigia and man.datos.get("vigia"):
        from . import avisos
        avisos.comprobar(sis, man, ambito, mira, hermes_pendiente=hermes_pendiente)
    from . import mantenimiento
    mantenimiento.comprobar(sis, man, ambito, mira)
    if ambito.root:
        _comprobar_cortafuegos(sis, man, puerto, mira)
    else:
        r = sis.ejecutar(["loginctl", "show-user", ambito.usuario, "-p", "Linger"])
        if not (r.bien and r.salida.strip() == "Linger=yes"):
            mira(True, "pasarela: sin linger, se para al cerrar tu última sesión (sudo loginctl enable-linger %s)"
                 % ambito.usuario, "")
    return resultados


def _capacidades_de_hermes(sis, man, puerto, mira, sin_bandeja=False):
    """Su versión y lo que la app necesita de su api_server, como al instalar (`capacidades`): lo que falta y es
    obligatorio es un MAL; lo demás, un aviso."""
    from . import capacidades
    from . import gestor as gestores
    estado, cuerpo = sis.http_get("http://127.0.0.1:%s/health" % puerto)
    version = capacidades.version_de_health(cuerpo) if estado == 200 else None
    sondeo = capacidades.sondear(sis, int(puerto), version)
    if sin_bandeja:
        sondeo.presentes.discard("bandeja")
        sondeo.sin_saber.discard("bandeja")
        sondeo.ausentes.add("bandeja")
    datos = man.datos.get("mantenimiento") or {}
    bloqueos, avisos = capacidades.veredicto(sondeo, usuario=datos.get("usuario"),
                                             gestor=gestores.desde_dict(datos.get("gestor_hermes")))
    for texto, _ in bloqueos:
        mira(False, "", texto)
    for texto in avisos:
        mira(True, "Hermes (aviso): " + texto, "")
    if bloqueos:
        return
    if sondeo.calibrada:
        mira(True, "Hermes: versión %s, con todo lo que usa la app" % (version or "desconocida"), "")
    else:
        mira(True, "Hermes: versión %s (la app necesita la %s o más nueva)"
             % (version or "desconocida", capacidades.texto_de(capacidades.MINIMA)), "")


def _direcciones_locales(sis) -> set:
    """Las IP de las interfaces de este servidor (`ip -j addr`)."""
    try:
        enlaces = json.loads(sis.ejecutar(["ip", "-j", "addr"]).salida or "[]")
    except ValueError:
        return set()
    return {a.get("local") for e in enlaces if isinstance(e, dict) for a in e.get("addr_info", []) if a.get("local")}


def _alcance(sis, ambito, puerto, esperada, mira):
    """La pasarela por la dirección del QR, como la vería la app: TLS, el certificado del QR y el 404 de siempre
    (auditoría §7: hasta la 0.8.0 solo se miraba 127.0.0.1). Distingue lo que se puede distinguir desde dentro: la
    dirección lleva a otra máquina (mal), es de este servidor y no contesta (mal), es de este servidor y contesta
    (bien: si la app aun así no llega, es el cortafuegos del proveedor, que desde aquí no se ve), o no es de este
    servidor (un NAT): contesta si el router reenvía el puerto y deja probarlo desde dentro; si no, no se sabe, y se
    dice qué abrir. La regla de ufw la mira `_comprobar_cortafuegos`."""
    import configparser
    import ipaddress
    from .pasarela import NO_ENCONTRADO
    ini = configparser.ConfigParser(interpolation=None)
    try:
        ini.read_string(sis.leer_texto(ambito.pasarela_ini) or "")
        direccion = ini.get("qr", "direccion", fallback="").strip()
    except configparser.Error:
        return
    if not direccion or direccion == "PENDIENTE" or not puerto:
        return
    try:
        ips = [str(ipaddress.ip_address(direccion))]
    except ValueError:
        ips = sis.resolver(direccion)
    donde = "%s:%s" % (direccion, puerto)
    if not ips:
        mira(False, "", "alcance: %s no se resuelve a ninguna IP: la app no llegará" % direccion)
        return
    ip, locales = ips[0], _direcciones_locales(sis)
    sonda = sis.sondear_pasarela(puerto, anfitrion=ip)
    if sonda is not None and sonda.get("huella") != esperada:
        mira(False, "", "alcance: en %s contesta otro certificado: esa dirección no lleva a esta pasarela (¿otra "
                        "máquina, un proxy o un reenvío a otro sitio?). Los QR de este servidor no conectarán" % donde)
    elif sonda is not None and sonda.get("respuesta") != NO_ENCONTRADO:
        mira(False, "", "alcance: en %s contesta algo que no es el 404 de la pasarela" % donde)
    elif sonda is not None:
        mira(True, ("alcance: %s contesta, con el certificado del QR. Es una dirección de este servidor: si la app aun "
                    "así no conecta, es el cortafuegos de tu proveedor (en su panel), que desde aquí no se ve: ábrele "
                    "el TCP %s" % (donde, puerto)) if ip in locales else
             ("alcance: %s contesta a través de tu NAT, que lleva el TCP %s a este servidor" % (donde, puerto)), "")
    elif ip in locales:
        mira(False, "", "alcance: la pasarela no contesta en %s, que es una dirección de este servidor (¿escucha en "
                        "otra? ss -ltnp | grep %s)" % (donde, puerto))
    else:
        mira(True, "alcance (aviso): no llego a %s desde dentro. Esa dirección no es de este servidor: está detrás de "
                   "un NAT. Tu router o tu proveedor tienen que llevar el TCP %s a este servidor; muchos no dejan "
                   "probarlo desde dentro, así que esto no lo confirma: pruébalo desde la app" % (donde, puerto), "")


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
    de Hermes ya no es la de la copia de la pasarela, la copia. La pasarela la vuelve a leer sola, sin reiniciarse: los
    SSE abiertos siguen. No la imprime nunca."""
    from .pasarela import leer_clave_hermes
    ambito = amb.de_root()
    env = _ini(sis, ambito).get("env")
    clave = leer_clave_hermes(sis.leer_texto(env) or "") if env else None
    if not clave:
        salida("error: no encuentro la clave de Hermes (%s)" % env)
        return 1
    codigo = 0
    if leer_clave_hermes(sis.leer_texto(ambito.clave_hermes) or "") == clave:
        salida("la copia de la clave de Hermes de la pasarela ya está al día")
    else:
        # Del mismo dueño que la de antes (hh-pasarela) ya al renombrarla: la pasarela no ve nunca una que no puede leer.
        sis.escribir(ambito.clave_hermes, (clave + "\n").encode(), modo=0o600, mismo_dueno=True)
        r = sis.ejecutar(["chown", "%s:%s" % (p.USUARIO_PASARELA, p.USUARIO_PASARELA), ambito.clave_hermes])
        if not r.bien:
            salida("error: no he podido darle la copia de la clave a %s" % p.USUARIO_PASARELA)
            codigo = 1
        salida("clave de Hermes copiada a la pasarela, que la lee sola (sin reiniciarla)")
    # La del vigía, si lo puso este instalador (la de un vigía puesto a mano la lleva `hehermes-dispositivo clave`).
    man = m.Manifiesto.leer(sis, ambito.manifiesto)
    if man.datos.get("vigia") and ambito.clave_hermes_vigia in man.ficheros:
        if leer_clave_hermes(sis.leer_texto(ambito.clave_hermes_vigia) or "") == clave:
            salida("la copia de la clave de Hermes del vigía ya está al día")
        else:
            sis.escribir(ambito.clave_hermes_vigia, (clave + "\n").encode(), modo=0o600)
            r = sis.ejecutar(["chown", p.USUARIO_VIGIA + ":" + p.USUARIO_VIGIA, ambito.clave_hermes_vigia])
            if not r.bien:
                salida("error: no he podido dar la copia del vigía a %s" % p.USUARIO_VIGIA)
                codigo = 1
            sis.ejecutar(["systemctl", "try-restart", p.UNIDAD_VIGIA])
            salida("clave de Hermes copiada al vigía, y el vigía reiniciado")
    return codigo
