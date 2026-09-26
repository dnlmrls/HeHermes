"""`instalar --por-chat`: la decisión 7, `--activar-api` y el canje que se lanza al acabar, sobre el servidor falso.

Sin `cryptography`: esto es el instalador, con el Python del sistema. El canje de verdad está en `test_canje_*.py`.
"""

import apoyo

import base64
import json
import re
import time
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import cli
from hehermes_servidor import porchat
from hehermes_servidor.deteccion import detectar
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.plan import Opciones, calcular_plan



def con_modo_vpn(argv):
    """Estas pruebas son del modo VPN, que desde la pasarela (0.5.0) ya no es el de por defecto."""
    argv = list(argv)
    if argv[:1] == ["instalar"] and "--modo" not in argv:
        argv.append("--modo")
        argv.append("vpn")
    return argv


ORIGEN = str(apoyo.RAIZ)
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()
MEDIA_HORA = 30 * 60


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv, terminal=False):
        self.texto = []
        codigo = cli.main(con_modo_vpn(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=terminal, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def por_chat(self, *extra, iphone="mi-iphone", llave=LLAVE):
        return self.orden("instalar", "--por-chat", "--iphone", iphone, "--llave", llave, *extra)

    def plan(self, ahora=None, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        opciones.setdefault("por_chat", True)
        opciones.setdefault("llave", LLAVE)
        man = Manifiesto.leer(self.sis)
        det = detectar(self.sis, man, activar_api=opciones.get("activar_api", False))
        return calcular_plan(self.sis, det, man, Opciones(ahora=ahora, **opciones), ORIGEN)

    def instalado_hace(self, segundos, **datos):
        man = Manifiesto.leer(self.sis)
        man.datos["instalado"] = time.time() - segundos
        man.datos.update(datos)
        man.guardar(self.sis)


class LaLlave(Base):
    def test_valida(self):
        self.assertTrue(porchat.llave_valida(LLAVE))
        for mala in (None, "", LLAVE[:-1], LLAVE + "A", LLAVE.replace(LLAVE[3], "/", 1), LLAVE[:-1] + "=",
                     "a" * 43 + " "):
            with self.subTest(mala=mala):
                self.assertFalse(porchat.llave_valida(mala))


class Uso(Base):
    def test_sin_llave_o_sin_iphone_es_un_error_de_uso(self):
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone"), 2)
        self.assertIn("--llave", self.salida)
        self.assertEqual(self.orden("instalar", "--por-chat", "--llave", LLAVE), 2)
        self.assertIn("--iphone", self.salida)
        self.assertEqual(self.sis.ordenes, [])

    def test_una_llave_mala_es_un_error_de_uso(self):
        self.assertEqual(self.por_chat(llave="no-es-una-llave"), 2)
        self.assertIn("la llave", self.salida)

    def test_la_llave_sin_por_chat_no_vale(self):
        self.assertEqual(self.orden("instalar", "--llave", LLAVE), 2)

    def test_el_plan_por_chat_no_cambia_nada(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE), 0)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("canje", self.salida)


class SoloElPrimero(Base):
    """Decisión 7: una inyección en algo que lea Hermes no puede pedirle un alta nueva con la llave de otro."""

    def test_limpio_pasa(self):
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_con_otro_iphone_ya_dado_de_alta_se_para(self):
        self.falso._hehermes_dispositivo(["alta", "el-de-antes", "--ikev2"], None)
        plan = self.plan()
        self.assertFalse(plan.puede_seguir)
        self.assertIn("solo se conecta el primer iPhone", "\n".join(plan.bloqueos))
        self.assertIn("el-de-antes", "\n".join(plan.bloqueos))

    def test_el_mismo_iphone_dado_de_alta_por_ssh_se_para(self):
        self.falso._hehermes_dispositivo(["alta", "mi-iphone", "--ikev2"], None)
        self.assertIn("no se dio de alta por chat", "\n".join(self.plan().bloqueos))

    def test_ya_canjeado_se_para(self):
        self.instalado_hace(60, por_chat={"iphone": "mi-iphone", "canjeado": time.time()})
        self.falso._hehermes_dispositivo(["alta", "mi-iphone", "--ikev2"], None)
        self.assertIn("ya se canjeó", "\n".join(self.plan().bloqueos))

    def test_repetirlo_sin_canjear_pasa(self):
        self.instalado_hace(60, por_chat={"iphone": "mi-iphone"})
        self.falso._hehermes_dispositivo(["alta", "mi-iphone", "--ikev2"], None)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)


class LaMediaHora(Base):
    def test_a_los_veintinueve_minutos_pasa_y_a_los_treinta_y_uno_no(self):
        self.instalado_hace(0)
        ahora = Manifiesto.leer(self.sis).datos["instalado"]
        self.assertTrue(self.plan(ahora=ahora + MEDIA_HORA - 60).puede_seguir)
        plan = self.plan(ahora=ahora + MEDIA_HORA + 60)
        self.assertFalse(plan.puede_seguir)
        self.assertIn("media hora", "\n".join(plan.bloqueos))

    def test_una_instalacion_sin_fecha_es_vieja(self):
        man = Manifiesto.leer(self.sis)
        man.guardar(self.sis)
        self.assertIn("media hora", "\n".join(self.plan().bloqueos))

    def test_instalar_apunta_cuando_y_repetir_no_lo_mueve(self):
        antes = time.time()
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "otro"), 0, self.salida)
        instalado = Manifiesto.leer(self.sis).datos["instalado"]
        self.assertGreaterEqual(instalado, antes)
        self.assertEqual(self.orden("instalar", "--si", "--avisos"), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["instalado"], instalado)

    def test_una_instalacion_de_antes_sin_fecha_no_la_gana_al_repetir(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        man = Manifiesto.leer(self.sis)
        del man.datos["instalado"]
        man.guardar(self.sis)
        self.assertEqual(self.orden("instalar", "--si", "--avisos"), 0, self.salida)
        self.assertNotIn("instalado", Manifiesto.leer(self.sis).datos)

    def test_sin_por_chat_no_hay_limite(self):
        self.instalado_hace(10 * MEDIA_HORA)
        plan = self.plan(por_chat=False, llave=None)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)


class ActivarApi(Base):
    """Decisión 6: quien solo usa Telegram suele tener la API apagada. Se enciende tocando solo lo que falta."""

    def montar(self, **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)
        self.env = "/root/.hermes/.env"
        self.antes = self.sis.leer_texto(self.env)

    def instalar(self, *extra):
        codigo = self.orden("instalar", "--si", "--activar-api", "--iphone", "mi-iphone", *extra)
        self.assertEqual(codigo, 0, self.salida)

    def reinicios(self):
        return [o for o in self.sis.ordenes if o[:1] == ["systemd-run"] and "--on-active=90" in o]

    def test_apagada_con_clave_anade_solo_lo_que_falta(self):
        self.montar(habilitada=False)
        self.instalar()
        despues = self.sis.leer_texto(self.env)
        self.assertTrue(despues.startswith(self.antes), "lo de antes no se toca")
        self.assertEqual(despues[len(self.antes):], "API_SERVER_ENABLED=true\nAPI_SERVER_HOST=127.0.0.1\n")
        self.assertEqual(self.sis.modo(self.env), 0o600)
        # La copia, antes de tocarlo.
        copia = Manifiesto.leer(self.sis).datos["activar_api"]["copia"]
        self.assertEqual(self.sis.leer_texto(copia["ruta"]), self.antes)
        # nginx lleva la clave que ya había, y el reinicio va a los 90 s, una sola vez.
        self.assertIn(sf.CLAVE, self.sis.leer_texto("/etc/nginx/hehermes-bearer.conf"))
        self.assertEqual(len(self.reinicios()), 1)
        self.assertEqual(self.reinicios()[0][-3:], ["systemctl", "restart", "hermes-gateway.service"])

    def test_sin_nada_pone_las_tres_y_la_clave_nueva_no_sale(self):
        self.montar(habilitada=None, clave=None)
        self.instalar()
        nuevas = self.sis.leer_texto(self.env)[len(self.antes):].splitlines()
        self.assertEqual([l.split("=")[0] for l in nuevas], ["API_SERVER_ENABLED", "API_SERVER_HOST", "API_SERVER_KEY"])
        clave = nuevas[2].split("=", 1)[1]
        self.assertGreaterEqual(len(clave), 40)
        self.assertEqual(self.sis.leer_texto("/etc/nginx/hehermes-bearer.conf"),
                         'proxy_set_header Authorization "Bearer %s";\n' % clave)
        self.assertNotIn(clave, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if any(clave in a for a in o)], "la clave en una orden")
        self.assertIn("API_SERVER_KEY", self.salida, "dice qué añade, sin el valor")

    def test_false_explicito_se_enciende_detras(self):
        self.montar(habilitada=False, host="127.0.0.1")
        self.instalar()
        self.assertEqual(self.sis.leer_texto(self.env)[len(self.antes):], "API_SERVER_ENABLED=true\n")

    def test_encendida_no_toca_nada(self):
        self.montar()
        self.instalar()
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)
        self.assertEqual(self.reinicios(), [])
        self.assertNotIn("activar_api", Manifiesto.leer(self.sis).datos)

    def test_sin_activar_api_se_sigue_parando(self):
        self.montar(habilitada=False)
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 1)
        self.assertIn("--activar-api", self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)

    def test_un_hermes_suelto_no_se_sabe_reiniciar(self):
        self.montar(habilitada=False, como="proceso")
        self.assertEqual(self.orden("instalar", "--si", "--activar-api", "--iphone", "mi-iphone"), 1)
        self.assertIn("no sé reiniciarlo", self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)

    def test_el_plan_dice_lo_que_hara_sin_hacerlo(self):
        self.montar(habilitada=False)
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--activar-api"), 0, self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("API_SERVER_ENABLED", self.salida)
        self.assertIn("90 s", self.salida)

    def test_desinstalar_quita_las_lineas_y_deja_el_resto(self):
        self.montar(habilitada=False)
        self.instalar()
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)

    def test_desinstalar_no_toca_lineas_cambiadas(self):
        self.montar(habilitada=False)
        self.instalar()
        tocado = self.sis.leer_texto(self.env).replace("API_SERVER_HOST=127.0.0.1", "API_SERVER_HOST=localhost")
        self.sis.poner(self.env, tocado, modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), tocado)
        self.assertIn(".env", self.salida)


class ElCanje(Base):
    """Lo que deja `instalar --por-chat` al acabar: el alta, el canje lanzado y la línea del enlace."""

    ENLACE = r"^hehermes-canje:1\?h=%s&p=(\d+)&c=([A-Za-z0-9_-]{22})&f=%s$" % (re.escape(sf.IP_PUBLICA), sf.HUELLA)

    def lanzar(self, *extra):
        codigo = self.por_chat(*extra)
        self.assertEqual(codigo, 0, self.salida)
        import re
        ultima = self.texto[-1]
        hallado = re.match(self.ENLACE, ultima)
        self.assertTrue(hallado, "la última línea tiene que ser el enlace, y es: %r" % ultima)
        return hallado

    def canje_json(self):
        return json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))

    def lanzamiento(self):
        return next(o for o in self.falso.lanzados if "--unit=hehermes-canje" in o)

    def test_de_punta_a_punta_sin_la_psk_fuera(self):
        hallado = self.lanzar()
        self.assertTrue(58000 <= int(hallado.group(1)) <= 65500, hallado.group(1))
        # La PSK solo está en el fichero que se le pasa al canje, 0600 dentro de una carpeta 0700.
        self.assertNotIn(sf.PSK, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if any(sf.PSK in a for a in o)], "la PSK en una orden")
        datos = self.canje_json()
        self.assertEqual(datos["carga"], {"h": sf.IP_PUBLICA, "rid": sf.IP_PUBLICA, "lid": "mi-iphone", "k": sf.PSK})
        self.assertEqual(datos["llave"], LLAVE)
        self.assertEqual(datos["codigo"], hallado.group(2))
        self.assertEqual(datos["huella"], sf.HUELLA)
        self.assertEqual(datos["puerto"], int(hallado.group(1)))
        self.assertEqual(self.sis.modo(porchat.RUN + "/canje.json"), 0o600)
        self.assertEqual(self.sis.modo(porchat.RUN), 0o700)
        # Por chat no se pinta el QR: la guarda de `qr` no lo dejaría, y lo leería el modelo.
        self.assertFalse([o for o in self.sis.ordenes if o[:2] == ["/usr/local/sbin/hehermes-dispositivo", "qr"]])
        self.assertEqual(Manifiesto.leer(self.sis).datos["por_chat"]["iphone"], "mi-iphone")

    def test_la_unidad_es_de_usar_y_tirar_y_se_limpia_como_root(self):
        self.lanzar()
        orden = self.lanzamiento()
        for propiedad in ("DynamicUser=yes", "LoadCredential=canje:/run/hehermes-canje/canje.json",
                          "LoadCredential=cert:/run/hehermes-canje/cert.pem",
                          "LoadCredential=clave:/run/hehermes-canje/clave.pem",
                          "CapabilityBoundingSet=", "NoNewPrivileges=yes", "ProtectSystem=strict",
                          "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
                          "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictNamespaces=yes",
                          "RestrictSUIDSGID=yes", "LockPersonality=yes", "SystemCallArchitectures=native",
                          "UMask=0077", "RuntimeMaxSec=660",
                          "ExecStopPost=+/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor canje-limpiar"):
            with self.subTest(propiedad=propiedad):
                self.assertIn(propiedad, orden)
        self.assertEqual(orden[-6:], [sf.VENV_CANJE + "/bin/python", "-I", "-B", "-m", "hehermes_servidor.canje",
                                      "servir"])
        self.assertIn("--collect", orden)
        # Un puerto alto no pide ninguna capacidad: el canje corre sin ninguna.
        self.assertFalse([a for a in orden if "CAP_" in a or a.startswith("AmbientCapabilities")], orden)

    def test_el_venv_se_hace_una_vez_con_las_dependencias_fijadas(self):
        self.lanzar()
        self.assertEqual(len(self.falso.pip), 1)
        pip = self.falso.pip[0]
        for opcion in ("--require-hashes", "--only-binary=:all:", "/opt/hehermes-servidor/requirements-canje.txt"):
            self.assertIn(opcion, pip)
        self.assertEqual(self.sis.leer_texto(sf.VENV_CANJE + "/lib/python3.11/site-packages/hehermes-servidor.pth"),
                         "/opt/hehermes-servidor\n")
        self.assertIn("python3-venv", Manifiesto.leer(self.sis).paquetes)
        self.falso.activos.discard("hehermes-canje")
        self.lanzar()
        self.assertEqual(len(self.falso.pip), 1, "el venv ya estaba")

    def test_el_puerto_sale_al_azar_y_se_salta_los_ocupados(self):
        # Al azar: el primero que se prueba es el 61234; está escuchando otro y el siguiente lo usa una conexión.
        self.falso.tcp += [("0.0.0.0:61234", "otro")]
        self.falso.tcp_conexiones += ["198.51.100.23:61235"]
        with mock.patch.object(porchat, "_azar", lambda n: 61234 - porchat.PUERTO_MINIMO):
            self.assertEqual(self.lanzar().group(1), "61236")
        self.assertEqual(self.canje_json()["puerto"], 61236)
        self.assertIn(["ss", "-H", "-tan"], self.sis.ordenes, "también las conexiones, no solo lo que escucha")

    def test_sin_puerto_libre_se_para(self):
        with mock.patch.object(porchat, "elegir_puerto", lambda ocupados: None):
            self.assertEqual(self.por_chat(), 1)
        self.assertIn("no hay ningún puerto libre", self.salida)
        self.assertFalse(self.falso.lanzados and "--unit=hehermes-canje" in self.falso.lanzados[-1])
        self.assertFalse(self.sis.existe(porchat.RUN))

    def test_con_ufw_activo_abre_el_puerto_solo_para_el_canje(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        puerto = self.lanzar().group(1)
        regla = "ufw allow proto tcp from any to any port %s comment hehermes-canje" % puerto
        self.assertIn(regla, self.falso.reglas_ufw)
        self.assertNotIn(regla,
                         Manifiesto.leer(self.sis).reglas, "no es una regla de la instalación: se va con el canje")

    def test_con_ufw_apagado_no_hay_regla(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "inactivo"
        self.lanzar()
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])

    def test_repetirlo_da_otro_enlace_para_el_mismo_iphone(self):
        primero = self.lanzar()
        altas = len(self.falso.altas)
        segundo = self.lanzar()
        self.assertNotEqual(primero.group(2), segundo.group(2))
        self.assertEqual(len(self.falso.altas), altas, "sin alta nueva")
        self.assertIn(["systemctl", "stop", "hehermes-canje"], self.sis.ordenes)
        self.assertEqual(self.canje_json()["carga"]["k"], sf.PSK, "la misma PSK, que nunca salió del servidor")

    def test_con_qr_png_deja_el_enlace_y_nada_mas(self):
        self.sis.carpeta("/tmp", 0o1777)
        hallado = self.lanzar("--qr-png", "/tmp/hehermes-canje.png")
        self.assertEqual(self.sis.leer("/tmp/hehermes-canje.png"), b"\x89PNG falso de " + hallado.group(0).encode())
        self.assertFalse(self.sis.existe(porchat.RUN + "/qr.png"), "el de /run, fuera")

    def test_con_qr_png_no_pisa_nada_ni_sigue_enlaces(self):
        self.sis.poner("/etc/importante", "no me pises\n")
        self.lanzar("--qr-png", "/etc/importante")
        self.assertEqual(self.sis.leer_texto("/etc/importante"), "no me pises\n")
        self.assertIn("No he podido dejar el QR en /etc/importante", self.salida)
        self.sis.carpeta("/tmp")
        self.sis.enlazar("/tmp/trampa.png", "/etc/nuevo")
        self.falso.activos.discard("hehermes-canje")
        self.lanzar("--qr-png", "/tmp/trampa.png")
        self.assertFalse(self.sis.existe("/etc/nuevo"))

    def test_con_sudo_el_png_se_crea_como_su_usuario(self):
        self.sis.carpeta("/tmp", 0o1777)
        llamadas = []
        with mock.patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch("os.geteuid", lambda: 0), mock.patch("os.getgroups", lambda: [0]), \
                mock.patch("os.setgroups", lambda g: llamadas.append(("grupos", g))), \
                mock.patch("os.setegid", lambda g: llamadas.append(("egid", g))), \
                mock.patch("os.seteuid", lambda u: llamadas.append(("euid", u))):
            self.lanzar("--qr-png", "/tmp/hehermes-canje.png")
        self.assertEqual(llamadas, [("grupos", [1000]), ("egid", 1000), ("euid", 1000), ("euid", 0), ("egid", 0),
                                    ("grupos", [0])])
        self.assertTrue(self.sis.existe("/tmp/hehermes-canje.png"))

    def test_con_activar_api_hermes_se_reinicia_despues_del_canje(self):
        self.sis, self.falso = sf.servidor(habilitada=False)
        self.addCleanup(self.sis.limpiar)
        self.lanzar("--activar-api")
        indices = [i for i, o in enumerate(self.falso.lanzados)]
        canje_ = next(i for i in indices if "--unit=hehermes-canje" in self.falso.lanzados[i])
        reinicio = next(i for i in indices if "--on-active=90" in self.falso.lanzados[i])
        self.assertLess(canje_, reinicio)

    def test_si_la_unidad_no_arranca_se_para_y_limpia(self):
        original = self.falso._systemd_run
        self.falso._systemd_run = lambda args, entrada: (original(args, entrada), self.falso.activos.discard(
            "hehermes-canje"))[0]
        self.assertEqual(self.por_chat(), 1)
        self.assertIn("el canje no ha arrancado", self.salida)
        self.assertFalse(self.sis.existe(porchat.RUN))
        self.assertFalse(self.texto[-1].startswith("hehermes-canje:"))


class SinSecretos(Base):
    """Daniel: nada de secretos en la salida (que por chat lee el modelo), en una orden (que ve `ps` y puede acabar en
    el diario) ni en lo que se deja escrito fuera de su sitio. Lo único que lleva una clave es el QR, y solo a un
    terminal (`hehermes-dispositivo qr`)."""

    def test_ni_la_psk_ni_la_clave_de_hermes_salen_de_su_sitio(self):
        self.sis, self.falso = sf.servidor(habilitada=None, clave=None)
        self.addCleanup(self.sis.limpiar)
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.por_chat("--activar-api"), 0, self.salida)
        clave = [l for l in self.sis.leer_texto("/root/.hermes/.env").splitlines()
                 if l.startswith("API_SERVER_KEY=")][0].split("=", 1)[1]
        salidas = self.salida
        self.orden("comprobar")
        salidas += self.salida
        for secreto in (sf.PSK, clave):
            with self.subTest(secreto=secreto[:6]):
                self.assertNotIn(secreto, salidas)
                self.assertFalse([o for o in self.sis.ordenes if any(secreto in a for a in o)], "en una orden")
                for ruta, datos in self.sis.foto().items():
                    if datos[0] != "fichero" or secreto.encode() not in datos[2]:
                        continue
                    # Donde sí tiene que estar: su sitio, 0600, y las copias de /etc/hehermes y /run, también 0600.
                    self.assertEqual(datos[1], "0o600", ruta)
                    self.assertTrue(ruta.startswith(("/etc/swanctl/conf.d/hehermes-", "/run/hehermes-canje/",
                                                     "/root/.hermes/", "/etc/nginx/hehermes-bearer.conf",
                                                     "/etc/hehermes/")), ruta)


class Limpiar(Base):
    """`canje-limpiar`, lo que corre como root en `ExecStopPost` al cerrarse el canje, por lo que sea."""

    def setUp(self):
        super().setUp()
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.falso.activos.discard("hehermes-canje")

    def limpiar(self, **entorno):
        return porchat.limpiar(self.sis, entorno)

    def test_lo_borra_todo(self):
        self.limpiar(SERVICE_RESULT="timeout", EXIT_CODE="killed", EXIT_STATUS="TERM")
        self.assertFalse(self.sis.existe(porchat.RUN))
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])
        self.assertNotIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])

    def test_canjeado_se_apunta_y_el_siguiente_por_chat_se_para(self):
        self.limpiar(SERVICE_RESULT="success", EXIT_CODE="exited", EXIT_STATUS="0")
        self.assertIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])
        self.assertEqual(self.por_chat(), 1)
        self.assertIn("ya se canjeó", self.salida)

    def test_caducado_no_cuenta_como_canjeado(self):
        self.limpiar(SERVICE_RESULT="exit-code", EXIT_CODE="exited", EXIT_STATUS="3")
        self.assertNotIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])

    def test_como_orden(self):
        codigo = self.orden("canje-limpiar")
        self.assertEqual(codigo, 0, self.salida)
        self.assertFalse(self.sis.existe(porchat.RUN))

    def test_una_regla_que_quedo_de_antes_de_reiniciar_se_quita_al_repetir(self):
        # Tras un reinicio /run está vacío, pero la regla de ufw sigue.
        self.sis.borrar_arbol(porchat.RUN)
        self.assertTrue([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len([r for r in self.falso.reglas_ufw if "hehermes-canje" in r]), 1)

    def test_desinstalar_no_deja_nada_del_canje(self):
        self.sis.borrar_arbol(porchat.RUN)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe("/opt/hehermes-canje"))
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])


class ElegirPuerto(unittest.TestCase):
    """Daniel (2026-09-26): alto y al azar, para que no sea fácil de encontrar; y de un generador criptográfico."""

    def test_el_rango_es_de_58000_a_65500_con_los_dos_extremos(self):
        self.assertEqual((porchat.PUERTO_MINIMO, porchat.PUERTO_MAXIMO), (58000, 65500))
        total = 65500 - 58000 + 1
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: 0), 58000)
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: n - 1), 65500)
        pedidos = []
        porchat.elegir_puerto(set(), azar=lambda n: pedidos.append(n) or 0)
        self.assertEqual(pedidos, [total], "el azar se pide sobre el rango entero, ni uno más ni uno menos")

    def test_se_salta_los_ocupados_y_da_la_vuelta(self):
        self.assertEqual(porchat.elegir_puerto({65500}, azar=lambda n: n - 1), 58000)
        self.assertEqual(porchat.elegir_puerto({58000, 58001}, azar=lambda n: 0), 58002)

    def test_sin_ninguno_libre_no_hay_puerto(self):
        self.assertIsNone(porchat.elegir_puerto(set(range(58000, 65501)), azar=lambda n: 7))
        self.assertEqual(porchat.elegir_puerto(set(range(58000, 65500)), azar=lambda n: 7), 65500)

    def test_el_azar_es_el_criptografico(self):
        import secrets
        self.assertIs(porchat._azar, secrets.randbelow)

    def test_de_verdad_cae_siempre_dentro(self):
        vistos = {porchat.elegir_puerto(set()) for _ in range(300)}
        self.assertTrue(all(58000 <= p <= 65500 for p in vistos))
        self.assertGreater(len(vistos), 250, "al azar, casi nunca repite")


class LaPsk(unittest.TestCase):
    def test_la_lee_como_la_escribe_hehermes_dispositivo(self):
        import importlib.machinery
        import importlib.util
        ruta = str(apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo")
        cargador = importlib.machinery.SourceFileLoader("hehermes_dispositivo", ruta)
        modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader("hehermes_dispositivo", cargador))
        cargador.exec_module(modulo)
        psk = modulo.nueva_psk()
        texto = modulo.conf_swanctl({"nombre": "mi-iphone", "ip": "10.77.1.3", "servidor": "203.0.113.7",
                                     "conexion": "hh-mi-iphone", "alta": "2026-09-24T00:00:00Z"}, psk)
        self.assertEqual(porchat.leer_psk(texto), psk)

    def test_sin_secret_no_hay_psk(self):
        with self.assertRaises(ValueError):
            porchat.leer_psk("connections {}\n")


if __name__ == "__main__":
    unittest.main()
