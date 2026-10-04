"""Hermes con perfiles, con su unidad (del sistema o de usuario), en un contenedor o suelto (desde la 0.10.2).

El fallo de un probador (2026-09-30, Ubuntu 24.04, root, instalador 0.10.1 por chat): su Hermes corría con un perfil
(aquí, «trabajo»: `/root/.hermes/profiles/trabajo`) como `hermes-gateway-trabajo.service`, que es como llama
`hermes gateway install` a la unidad de un perfil (hermes_cli/gateway.py, `get_service_name`), y el instalador solo
sabía reiniciar `hermes-gateway.service`: «hehermes-error:api-apagada». Ahora lo que se reinicia es lo que lleva su proceso, leído de
`/proc/<pid>/cgroup` (`gestor.py`), y todo lo de Hermes (su .env, su clave, su `exports`, su `state.db`) es lo de su
perfil.
"""

import apoyo  # noqa: F401

import base64
import json
import re
import time
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli, porchat
from hehermes_servidor import gestor as gs
from hehermes_servidor import mantenimiento as mt
from hehermes_servidor.deteccion import casa_del_proceso
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import detectar_tls

ORIGEN = str(apoyo.RAIZ)
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()
ENLACE = re.compile(r"^hehermes-canje:1\?h=")
TRABAJO = "/root/.hermes/profiles/trabajo"
ID = "0123456789abcdef" * 4


class ElCgroup(unittest.TestCase):
    """`de_cgroup`: de qué unidad o de qué contenedor es un proceso, sin ejecutar nada."""

    def test_una_unidad_del_sistema_se_llame_como_se_llame(self):
        for nombre in ("hermes-gateway-trabajo.service", "hermes-gateway-3f2a9c1b.service", "hermes@trabajo.service",
                       "mi-agente.service", "hermes-gateway.service"):
            with self.subTest(nombre=nombre):
                self.assertEqual(gs.de_cgroup("0::/system.slice/%s\n" % nombre), ("sistema", nombre, None))
        # Con un subgrupo debajo (Delegate=), la unidad sigue siendo la de arriba.
        self.assertEqual(gs.de_cgroup("0::/system.slice/hermes-gateway-trabajo.service/trabajo\n"),
                         ("sistema", "hermes-gateway-trabajo.service", None))

    def test_una_de_usuario_con_su_uid(self):
        self.assertEqual(gs.de_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                                      "hermes-gateway.service\n"), ("usuario", "hermes-gateway.service", 1000))
        self.assertEqual(gs.de_cgroup("0::/user.slice/user-0.slice/user@0.service/hermes-gateway-trabajo.service\n"),
                         ("usuario", "hermes-gateway-trabajo.service", 0))

    def test_cgroup_v1_por_su_jerarquia_de_systemd(self):
        texto = ("12:pids:/system.slice/hermes-gateway-trabajo.service\n3:cpu,cpuacct:/\n"
                 "1:name=systemd:/system.slice/hermes-gateway-trabajo.service\n")
        self.assertEqual(gs.de_cgroup(texto), ("sistema", "hermes-gateway-trabajo.service", None))

    def test_un_contenedor(self):
        self.assertEqual(gs.de_cgroup("0::/system.slice/docker-%s.scope\n" % ID), ("docker", ID, None))
        self.assertEqual(gs.de_cgroup("0::/docker/%s\n" % ID), ("docker", ID, None))
        self.assertEqual(gs.de_cgroup("0::/machine.slice/libpod-%s.scope/container\n" % ID), ("podman", ID, None))

    def test_lo_que_no_se_sabe_reiniciar(self):
        for texto in ("0::/user.slice/user-0.slice/session-3.scope\n",
                      "0::/user.slice/user-1000.slice/user@1000.service/tmux-spawn-1b2c.scope\n",
                      "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n",
                      # Un Docker sin root: reiniciarlo es cosa de su usuario.
                      "0::/user.slice/user-1000.slice/user@1000.service/app.slice/docker-%s.scope\n" % ID,
                      "0::/\n", "", "basura", "0::/system.slice/../../etc.service\n",
                      "0::/system.slice/con espacio.service\n", "0::/init.scope\n"):
            with self.subTest(texto=texto):
                self.assertIsNone(gs.de_cgroup(texto))


class LaUnidad(unittest.TestCase):
    """`detectar`: la unidad del cgroup se confirma, para no reiniciar `cron.service` o `ssh.service`."""

    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def cgroup(self, texto, pid=7000):
        self.sis.poner("/proc/%d/cgroup" % pid, texto)
        return pid

    def test_la_de_un_perfil_por_su_nombre(self):
        pid = self.cgroup("0::/system.slice/hermes-gateway-trabajo.service\n")
        self.assertEqual(gs.detectar(self.sis, pid), gs.Gestor("sistema", "hermes-gateway-trabajo.service"))

    def test_otra_solo_si_ejecuta_hermes(self):
        pid = self.cgroup("0::/system.slice/mi-agente.service\n")
        self.falso.unidades_hermes["mi-agente.service"] = {
            "User": "", "Environment": "",
            "ExecStart": "{ path=/root/.hermes/hermes-agent/venv/bin/python ; argv[]=/root/.hermes/hermes-agent/venv/"
                         "bin/python -m hermes_cli.main gateway run ; }"}
        self.assertEqual(gs.detectar(self.sis, pid), gs.Gestor("sistema", "mi-agente.service"))
        for otra in ("cron.service", "ssh.service", "supervisor.service"):
            with self.subTest(otra=otra):
                self.falso.unidades_hermes[otra] = {"User": "", "Environment": "", "ExecStart": "/usr/sbin/" + otra}
                self.assertIsNone(gs.detectar(self.sis, self.cgroup("0::/system.slice/%s\n" % otra)))
        # Una que ni se sabe qué ejecuta: no.
        self.assertIsNone(gs.detectar(self.sis, self.cgroup("0::/system.slice/desconocida.service\n")))

    def test_la_de_usuario_con_su_dueño_por_su_uid(self):
        pid = self.cgroup("0::/user.slice/user-0.slice/user@0.service/app.slice/hermes-gateway-trabajo.service\n")
        gestor = gs.detectar(self.sis, pid)
        self.assertEqual(gestor, gs.Gestor("usuario", "hermes-gateway-trabajo.service", "root", 0))
        self.assertEqual(gs.orden_reiniciar(gestor), ["runuser", "-u", "root", "--", "env", "XDG_RUNTIME_DIR=/run/user/0",
                                                      "systemctl", "--user", "restart", "hermes-gateway-trabajo.service"])
        self.assertEqual(gs.orden_reiniciar(gestor, root=False), ["systemctl", "--user", "restart",
                                                                  "hermes-gateway-trabajo.service"])
        # Un uid que no es de nadie: no.
        self.assertIsNone(gs.detectar(self.sis, self.cgroup("0::/user.slice/user-4242.slice/user@4242.service/"
                                                            "hermes-gateway.service\n")))

    def test_un_contenedor_solo_si_esta_su_orden(self):
        pid = self.cgroup("0::/system.slice/docker-%s.scope\n" % ID)
        self.assertIsNone(gs.detectar(self.sis, pid))
        self.falso.programa("/usr/bin/docker")
        self.assertEqual(gs.detectar(self.sis, pid), gs.Gestor("docker", ID))

    def test_el_del_manifiesto_se_mira_antes_de_usarlo(self):
        for bueno in (gs.Gestor("sistema", "hermes-gateway-trabajo.service"), gs.Gestor("docker", ID),
                      gs.Gestor("usuario", "hermes-gateway.service", "ana", 1000)):
            self.assertEqual(gs.desde_dict(json.loads(json.dumps(bueno.a_dict()))), bueno)
        for malo in (None, "x", {"tipo": "sistema", "nombre": "a b.service"}, {"tipo": "sistema", "nombre": "x"},
                     {"tipo": "usuario", "nombre": "h.service", "usuario": "-rf", "uid": 1},
                     {"tipo": "usuario", "nombre": "h.service", "usuario": "ana", "uid": "1"},
                     {"tipo": "docker", "nombre": "; rm -rf /"}, {"tipo": "otro", "nombre": "h.service"}):
            with self.subTest(malo=malo):
                self.assertIsNone(gs.desde_dict(malo))

    def test_montajes_de_un_contenedor(self):
        montajes = [("/opt", "/srv/opt"), ("/opt/data", "/root/.hermes"), ("/", "/var/lib/docker/raiz")]
        self.assertEqual(gs.ruta_en_el_servidor(montajes, "/opt/data"), "/root/.hermes")
        self.assertEqual(gs.ruta_en_el_servidor(montajes, "/opt/data/profiles/trabajo"), "/root/.hermes/profiles/trabajo")
        self.assertEqual(gs.ruta_en_el_servidor(montajes, "/opt/otra"), "/srv/opt/otra")
        self.assertEqual(gs.ruta_en_el_servidor(montajes[1:2], "/opt/database"), None, "un prefijo no es un montaje")
        self.assertIsNone(gs.ruta_en_el_servidor([], "/opt/data"))


class LaCasaDelProceso(unittest.TestCase):
    """Su HERMES_HOME, como lo decide Hermes al arrancar (hermes_cli/main.py, `_apply_profile_override`)."""

    def setUp(self):
        self.sis, _ = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def casa(self, orden, entorno=None):
        return casa_del_proceso(self.sis, "root", orden.split(), entorno or {})

    def test_el_perfil_de_su_orden_manda(self):
        self.assertEqual(self.casa("python -m hermes_cli.main --profile trabajo gateway run"), TRABAJO)
        self.assertEqual(self.casa("hermes -p trabajo gateway run"), TRABAJO)
        self.assertEqual(self.casa("hermes --profile=Trabajo gateway run"), TRABAJO)
        self.assertEqual(self.casa("hermes -p default gateway run"), "/root/.hermes")
        self.assertEqual(self.casa("hermes gateway run -- -p trabajo"), "/root/.hermes")
        # Con un HERMES_HOME de otra raíz, el perfil es de esa raíz.
        self.assertEqual(self.casa("hermes -p trabajo gateway run", {"HERMES_HOME": "/srv/hermes"}),
                         "/srv/hermes/profiles/trabajo")
        self.assertEqual(self.casa("hermes -p otro gateway run", {"HERMES_HOME": TRABAJO}),
                         "/root/.hermes/profiles/otro")

    def test_un_hermes_home_de_perfil_o_propio(self):
        self.assertEqual(self.casa("hermes gateway run", {"HERMES_HOME": TRABAJO + "/"}), TRABAJO)
        self.assertEqual(self.casa("hermes gateway run", {"HERMES_HOME": "/srv/hermes"}), "/srv/hermes")
        self.assertEqual(self.casa("hermes gateway run"), "/root/.hermes")

    def test_el_perfil_activo_solo_sin_supervisor(self):
        self.sis.poner("/root/.hermes/active_profile", "trabajo\n")
        self.sis.carpeta(TRABAJO)
        self.assertEqual(self.casa("hermes gateway run"), TRABAJO, "en tmux, `hermes profile use trabajo` manda")
        for marca in ("HERMES_SUPERVISED_CHILD", "INVOCATION_ID", "HERMES_S6_SUPERVISED_CHILD"):
            with self.subTest(marca=marca):
                self.assertEqual(self.casa("hermes gateway run", {marca: "1"}), "/root/.hermes")
        self.assertEqual(self.casa("hermes gateway run", {"HERMES_GATEWAY_EXTERNAL_SUPERVISOR": "yes"}),
                         "/root/.hermes")
        # Un perfil activo que ya no existe, o que no es un nombre, no.
        self.sis.poner("/root/.hermes/active_profile", "borrado\n")
        self.assertEqual(self.casa("hermes gateway run"), "/root/.hermes")
        self.sis.poner("/root/.hermes/active_profile", "../../etc\n")
        self.assertEqual(self.casa("hermes gateway run"), "/root/.hermes")


class Base(unittest.TestCase):
    euid = 0
    cuenta = None

    def montar(self, **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv, terminal=False):
        self.texto = []
        with mock.patch.object(porchat, "_azar", lambda n: 3234):
            codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n",
                              salida=self.texto.append, terminal=terminal, euid=self.euid, cuenta=self.cuenta,
                              relanzar=lambda orden: 0, usuario="hermes")
        self.salida = "\n".join(self.texto)
        return codigo

    def por_chat(self, *extra):
        return self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE, *extra)

    def reinicios(self):
        return [o for o in self.sis.ordenes if o[:1] == ["systemd-run"] and "--on-active=90" in o]

    def lineas_nuevas(self, env, antes):
        despues = self.sis.leer_texto(env)
        self.assertTrue(despues.startswith(antes), "lo de antes no se toca")
        return despues[len(antes):].splitlines()

    def encender(self, env, puerto=8642):
        """Lo que hace Hermes al reiniciarse: lee su .env y enciende la API con esa clave."""
        clave = [l for l in self.sis.leer_texto(env).splitlines() if l.startswith("API_SERVER_KEY")][-1]
        self.falso.hermes[puerto] = clave.split("=", 1)[1].strip('"')
        self.falso.tcp.append(("127.0.0.1:%d" % puerto, "python3"))


class ElDelProbador(Base):
    """Root, el perfil «trabajo» y su unidad del sistema, `hermes-gateway-trabajo.service` (la de `sudo hermes -p trabajo gateway
    install`), con la API apagada: por chat, una sola frase y el enlace, como con `hermes-gateway`."""

    def setUp(self):
        self.montar(como="unidad-perfil", perfil="trabajo", habilitada=False)
        self.env = TRABAJO + "/.env"
        self.antes = self.sis.leer_texto(self.env)
        self.assertFalse(self.sis.existe("/root/.hermes/.env"), "solo el perfil tiene .env")

    def test_por_chat_enciende_la_api_de_su_perfil_da_el_enlace_y_reinicia_su_unidad(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.texto[-1]), self.texto[-1])
        self.assertNotIn("hehermes-error", self.salida)
        self.assertEqual([l.split("=")[0] for l in self.lineas_nuevas(self.env, self.antes)],
                         ["API_SERVER_ENABLED", "API_SERVER_HOST"])
        copia = Manifiesto.leer(self.sis).datos["activar_api"]["copia"]
        self.assertEqual(self.sis.leer_texto(copia["ruta"]), self.antes)
        self.assertEqual(self.reinicios(), [["systemd-run", "--on-active=90", "--timer-property=AccuracySec=1s",
                                             "--collect", "--quiet", "systemctl", "restart",
                                             "hermes-gateway-trabajo.service"]])
        self.assertIn("la unidad hermes-gateway-trabajo.service", self.salida)

    def test_todo_lo_de_hermes_es_lo_de_su_perfil(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        man = Manifiesto.leer(self.sis).datos
        self.assertEqual(man["mantenimiento"]["casa"], TRABAJO, "su state.db")
        self.assertEqual(man["mantenimiento"]["unidad_hermes"], "hermes-gateway-trabajo.service")
        self.assertEqual(man["mantenimiento"]["gestor_hermes"], {"tipo": "sistema",
                                                                 "nombre": "hermes-gateway-trabajo.service"})
        # La clave que vigila la pasarela, su .env; el lector, su casa, y sus exportaciones, en ella.
        self.assertIn("env = %s\n" % self.env, self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"))
        self.assertIn("PathChanged=%s\n" % self.env,
                      self.sis.leer_texto("/etc/systemd/system/hehermes-pasarela-clave.path"))
        self.assertEqual(man["exportaciones"], TRABAJO + "/exports")
        self.assertTrue(self.sis.es_carpeta(TRABAJO + "/exports"))
        self.assertIn(TRABAJO, self.sis.leer_texto("/etc/systemd/system/hehermes-leer-media@.service"))
        # El vigía lee «~/» desde la casa de root, no desde la carpeta de los perfiles.
        self.assertIn("casa = /root\n", self.sis.leer_texto("/etc/hehermes-avisos/vigia.ini"))
        respaldo = self.sis.leer_texto("/etc/systemd/system/hehermes-respaldo@.service")
        self.assertIn("--hermes-home=%s " % TRABAJO, respaldo)
        self.assertIn("--unidad-hermes=hermes-gateway-trabajo.service ", respaldo)
        # Lo que la app le manda (desde la 0.10.6), en la entrada de su perfil.
        entrada = self.sis.leer_texto("/etc/systemd/system/hehermes-entrada@.service")
        self.assertIn("--hermes-home=%s " % TRABAJO, entrada)
        self.assertIn("BindPaths=-%s/entrada\n" % TRABAJO, entrada)
        self.assertEqual(man["entrada"], TRABAJO + "/entrada")
        self.assertTrue(self.sis.es_carpeta(TRABAJO + "/entrada"))

    def test_de_noche_para_y_arranca_su_unidad(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.encender(self.env)
        self.falso.programa("/usr/local/bin/hermes")
        self.sis.poner(TRABAJO + "/state.db", b"SQLite format 3\0")
        man = Manifiesto.leer(self.sis)
        self.assertEqual(mt.como_parar(man, amb.de_root()), (gs.Gestor("sistema", "hermes-gateway-trabajo.service"),
                                                             None))
        texto = []
        fallo, _ = mt._compactar(self.sis, man.datos["mantenimiento"], mt.como_parar(man, amb.de_root())[0],
                                 texto.append, lambda s: None)
        self.assertIsNone(fallo, texto)
        self.assertIn(["systemctl", "stop", "hermes-gateway-trabajo.service"], self.sis.ordenes)
        self.assertIn(["systemctl", "start", "hermes-gateway-trabajo.service"], self.sis.ordenes)
        self.assertIn("HERMES_HOME=%s" % TRABAJO, self.falso.entornos)


class HermesGatewayDeSiempre(Base):
    """Lo de siempre no cambia: la unidad `hermes-gateway` se reinicia con la misma orden que la 0.10.1."""

    def test_la_misma_orden(self):
        self.montar(habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(self.reinicios(), [["systemd-run", "--on-active=90", "--timer-property=AccuracySec=1s",
                                             "--collect", "--quiet", "systemctl", "restart",
                                             "hermes-gateway.service"]])
        man = Manifiesto.leer(self.sis).datos["mantenimiento"]
        self.assertEqual((man["unidad_hermes"], man["casa"]), ("hermes-gateway.service", "/root/.hermes"))
        self.assertIn("casa = /root\n", self.sis.leer_texto("/etc/hehermes-avisos/vigia.ini"))
        self.assertIn("--unidad-hermes=hermes-gateway.service ",
                      self.sis.leer_texto("/etc/systemd/system/hehermes-respaldo@.service"))

    def test_un_manifiesto_de_la_0_10_1_sigue_valiendo(self):
        self.montar()
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        man = Manifiesto.leer(self.sis)
        del man.datos["mantenimiento"]["gestor_hermes"]
        self.assertEqual(mt.como_parar(man, amb.de_root()), (gs.Gestor("sistema", "hermes-gateway.service"), None))


class UnidadDeUsuario(Base):
    """`hermes gateway install` sin --system: una unidad de usuario (`systemctl --user`)."""

    def test_con_root_se_reinicia_en_el_systemd_de_su_usuario(self):
        self.montar(como="unidad-usuario", perfil="trabajo", habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(self.reinicios()[0][5:], ["runuser", "-u", "root", "--", "env", "XDG_RUNTIME_DIR=/run/user/0",
                                                   "systemctl", "--user", "restart", "hermes-gateway-trabajo.service"])
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["gestor_hermes"],
                         {"tipo": "usuario", "nombre": "hermes-gateway-trabajo.service", "usuario": "root", "uid": 0})
        # El ayudante de la copia (de root) no sabe de unidades de usuario: la de siempre, que no encuentra.
        self.assertIn("--unidad-hermes=hermes-gateway.service ",
                      self.sis.leer_texto("/etc/systemd/system/hehermes-respaldo@.service"))

    def test_de_noche_como_su_usuario(self):
        self.montar(como="unidad-usuario", perfil="trabajo")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.falso.programa("/usr/local/bin/hermes")
        man = Manifiesto.leer(self.sis)
        gestor, _ = mt.como_parar(man, amb.de_root())
        fallo, _ = mt._compactar(self.sis, man.datos["mantenimiento"], gestor, [].append, lambda s: None)
        self.assertIsNone(fallo)
        self.assertIn(["runuser", "-u", "root", "--", "env", "XDG_RUNTIME_DIR=/run/user/0", "systemctl", "--user",
                       "stop", "hermes-gateway-trabajo.service"], self.sis.ordenes)
        self.assertIn("hermes-gateway-trabajo", self.falso.activos_usuario, "arrancado otra vez")


class SinRootConSuUnidad(Base):
    """Sin root y con Hermes como unidad de usuario suya: también se enciende y se reinicia solo."""

    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def test_por_chat(self):
        self.montar(usuario="hermes", como="unidad-usuario", habilitada=False)
        self.sis.carpeta("/run/user/1000", 0o700)
        env = "/home/hermes/.hermes/.env"
        antes = self.sis.leer_texto(env)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.texto[-1]), self.texto[-1])
        self.assertEqual([l.split("=")[0] for l in self.lineas_nuevas(env, antes)],
                         ["API_SERVER_ENABLED", "API_SERVER_HOST"])
        # La copia, en su casa (no puede escribir en /etc).
        copia = Manifiesto.leer(self.sis, amb.de_usuario(*self.cuenta).manifiesto).datos["activar_api"]["copia"]
        self.assertTrue(copia["ruta"].startswith("/home/hermes/.config/hehermes/copias/"), copia)
        self.assertEqual(self.reinicios(), [["systemd-run", "--user", "--on-active=90",
                                             "--timer-property=AccuracySec=1s", "--collect", "--quiet", "systemctl",
                                             "--user", "restart", "hermes-gateway-3f2a9c1b.service"]])

    def test_una_del_sistema_sin_root_sigue_sin_poder(self):
        self.montar(usuario="hermes", habilitada=False)
        self.sis.carpeta("/run/user/1000", 0o700)
        antes = self.sis.leer_texto("/home/hermes/.hermes/.env")
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:api-hermes")
        self.assertEqual(self.sis.leer_texto("/home/hermes/.hermes/.env"), antes)


class ReiniciaHermes(Base):
    """Un Hermes que no lleva ni systemd ni un contenedor (tmux, nohup): se enciende su API y se para con
    `reinicia-hermes`; con Hermes reiniciado, la misma frase sigue."""

    def setUp(self):
        self.montar(como="proceso", habilitada=False, clave=None)
        self.env = "/root/.hermes/.env"
        self.antes = self.sis.leer_texto(self.env)

    def test_primera_vez_enciende_y_se_para(self):
        foto = self.sis.foto()
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:reinicia-hermes")
        self.assertIn("He encendido la API en %s; reinicia Hermes y vuelve a mandarme la misma frase." % self.env,
                      self.salida)
        nuevas = self.lineas_nuevas(self.env, self.antes)
        self.assertEqual([l.split("=")[0] for l in nuevas], ["API_SERVER_ENABLED", "API_SERVER_HOST", "API_SERVER_KEY"])
        self.assertNotIn(nuevas[2].split("=", 1)[1], self.salida, "la clave nueva no sale")
        self.assertEqual(self.reinicios(), [], "nada que reiniciar")
        # Solo el .env, su copia y el apunte: ni la pasarela ni un manifiesto (que se leería como una instalación).
        cambiados = sorted(r for r, d in self.sis.foto().items() if foto.get(r) != d)
        self.assertEqual([r for r in cambiados if not r.startswith("/etc/hehermes")], [self.env])
        self.assertEqual(sorted(cambiados), ["/etc/hehermes", "/etc/hehermes/api-pendiente.json", "/etc/hehermes/copias",
                                             "/etc/hehermes/copias/root%.hermes%.env", self.env])
        self.assertEqual(self.sis.modo("/etc/hehermes/api-pendiente.json"), 0o600)

    def test_con_hermes_reiniciado_la_misma_frase_da_el_enlace_y_desinstalar_quita_las_lineas(self):
        self.assertEqual(self.por_chat(), 1)
        self.encender(self.env)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.texto[-1]), self.texto[-1])
        self.assertEqual(self.reinicios(), [])
        self.assertIn("activar_api", Manifiesto.leer(self.sis).datos)
        self.assertFalse(self.sis.existe("/etc/hehermes/api-pendiente.json"))
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)

    def test_sin_reiniciarlo_dice_que_no_contesta(self):
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:api-hermes")

    def test_por_un_terminal_lo_mismo_sin_la_linea_de_la_app(self):
        self.assertEqual(self.orden("instalar", "--si", "--activar-api", "--iphone", "mi-iphone"), 1)
        self.assertIn("reinicia Hermes y vuelve a lanzar el mismo comando", self.salida)
        self.assertNotIn("hehermes-error", self.salida)

    def test_el_plan_no_toca_nada(self):
        foto = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--activar-api"), 1)
        self.assertEqual(self.sis.foto(), foto)
        self.assertIn("no sé reiniciarlo", self.salida)

    def test_con_otra_cosa_que_pare_no_enciende_nada_y_dice_esa(self):
        self.falso.direccion_salida = "10.0.0.5"
        self.falso.enlaces_ip = {"eth0": {"ifname": "eth0", "addr": ["10.0.0.5/24"]}}
        foto = self.sis.foto()
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:nat")
        self.assertEqual(self.sis.foto(), foto)


class VariosPerfiles(Base):
    """Con varios Hermes en marcha, el que ha lanzado el instalador; sin saberlo, se enumeran."""

    def setUp(self):
        self.montar()
        self.falso.con_hermes(como="unidad-perfil", perfil="trabajo", puerto=8643)

    def test_sin_saber_cual_se_enumeran(self):
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:varios-hermes")
        self.assertIn(TRABAJO, self.salida)

    def test_el_que_me_lanza_por_su_arbol_de_procesos(self):
        self.sis.pid = 9002
        self.sis.poner("/proc/9002/status", "Name:\tbash\nPPid:\t9001\n")
        self.sis.poner("/proc/9001/status", "Name:\tpython3\nPPid:\t%d\n" % self.falso.pid_hermes)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["casa"], TRABAJO)

    def test_o_por_el_hermes_home_que_hereda(self):
        self.sis.entorno = {"HERMES_HOME": TRABAJO}
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["casa"], TRABAJO)

    def test_mirar_su_registro_no_es_otro_hermes(self):
        self.falso.activos.discard("hermes-gateway-trabajo")
        self.falso.procesos = [(4100, "root", "tail -f /root/.hermes/profiles/trabajo/logs/gateway.log"),
                               (4101, "root", "less /root/.hermes/logs/gateway.log")]
        # Desde una shell de ese perfil (su HERMES_HOME): sin mirar qué ejecuta, sería otro Hermes, el de «trabajo».
        self.sis.poner("/proc/4100/environ", "HERMES_HOME=%s\0" % TRABAJO)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["casa"], "/root/.hermes")

    def test_la_unidad_de_siempre_parada_no_cuenta(self):
        self.falso.activos.discard("hermes-gateway")
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["casa"], TRABAJO)


class EnUnContenedor(Base):
    """El Hermes de Docker: su casa es la del montaje de /opt/data, y se reinicia con `docker restart`."""

    def test_con_la_red_del_servidor(self):
        self.montar(como="docker", perfil="trabajo", habilitada=False)
        env = TRABAJO + "/.env"
        antes = self.sis.leer_texto(env)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.lineas_nuevas(env, antes)), 2)
        self.assertEqual(self.reinicios()[0][-3:], ["docker", "restart", self.falso.contenedor])
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["casa"], TRABAJO)
        # De noche no se para: su hermes no está fuera.
        self.assertIsNone(mt.como_parar(Manifiesto.leer(self.sis), amb.de_root())[0])

    def test_con_su_propia_red_no_se_puede(self):
        self.montar(como="docker", habilitada=False)
        self.falso.red_docker = "bridge"
        antes = self.sis.foto()
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:api-apagada")
        self.assertIn("con su propia red (bridge)", self.salida)
        self.assertEqual(self.sis.foto(), antes)



class ElCanjeYElReinicioDeHermes(Base):
    """El fallo de otro probador (2026-09-30, instalador 0.10.2 por chat, root, Hermes con un perfil y su unidad del
    sistema, `--activar-api`): llegó el enlace con el aviso de que Hermes se reiniciaba a los 90 s, la app lo canjeó y
    no se quedó conectada, y la misma frase otra vez acababa en «ya se canjeó». Aquí, lo del servidor: el canje es su
    propia unidad y el reinicio de Hermes no lo toca (con Hermes de sistema o de usuario, con root y sin él), y la misma
    frase otra vez da otra clave al mismo iPhone."""

    def lanzamiento(self):
        return next(o for o in self.falso.lanzados if "--unit=hehermes-canje" in o)

    def disparar_el_reinicio(self):
        """Lo que hace el temporizador a los 90 s: la orden de detrás de las opciones de `systemd-run`."""
        (orden,) = self.reinicios()
        self.assertNotIn("hehermes-canje", " ".join(orden))
        self.assertTrue(self.sis.ejecutar(orden[orden.index("--quiet") + 1:]).bien)

    def comprobar_que_es_su_propia_unidad(self):
        orden = self.lanzamiento()  # lo de detrás de `systemd-run`
        self.assertNotIn("--scope", orden, "con --scope se quedaría en el cgroup de Hermes, que es quien lo lanza")
        self.assertFalse([a for a in orden if a.split("=", 1)[0] in ("PartOf", "BindsTo", "Requisite", "Requires",
                                                                    "Slice") or "hermes-gateway" in a], orden)

    def test_con_su_unidad_del_sistema_el_reinicio_no_toca_el_canje(self):
        self.montar(como="unidad-perfil", perfil="trabajo", habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.comprobar_que_es_su_propia_unidad()
        self.assertIn("hehermes-canje", self.falso.activos)
        self.disparar_el_reinicio()
        self.assertIn("hermes-gateway-trabajo", self.falso.reinicios)
        self.assertIn("hehermes-canje", self.falso.activos, "el reinicio de Hermes se ha llevado el canje")

    def test_con_su_unidad_de_usuario_el_reinicio_no_toca_el_canje(self):
        self.montar(como="unidad-usuario", perfil="trabajo", habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.comprobar_que_es_su_propia_unidad()
        self.disparar_el_reinicio()
        self.assertIn("usuario:hermes-gateway-trabajo", self.falso.reinicios)
        self.assertIn("hehermes-canje", self.falso.activos)

    def test_la_prueba_ve_un_canje_atado_a_hermes(self):
        """Sin esto, las dos de arriba no probarían nada: un canje con --scope (o atado a Hermes) sí muere."""
        self.montar(como="unidad-perfil", perfil="trabajo", habilitada=False)
        original = porchat._systemd_run
        with mock.patch.object(porchat, "_systemd_run", lambda: original()[:1] + ["--scope"] + original()[1:]):
            self.assertEqual(self.por_chat(), 0, self.salida)
        self.disparar_el_reinicio()
        self.assertNotIn("hehermes-canje", self.falso.activos)

    def test_la_misma_frase_otra_vez_tras_canjearlo_da_otra_clave(self):
        self.montar(como="unidad-perfil", perfil="trabajo", habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        primero = self.texto[-1]
        token = json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))["carga"]["t"]
        # La app lo canjea (el canje sale con 0) y Hermes se reinicia con la API encendida.
        self.falso.activos.discard("hehermes-canje")
        porchat.limpiar(self.sis, {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"})
        self.disparar_el_reinicio()
        self.encender(TRABAJO + "/.env")
        self.assertIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.texto[-1]), self.texto[-1])
        self.assertNotEqual(self.texto[-1], primero)
        self.assertNotIn("hehermes-error", self.salida)
        self.assertIn("ya se había conectado por chat: le doy una clave nueva", self.salida)
        from hehermes_servidor import pasarela as pa
        tokens = pa.Tokens(self.sis.ruta("/etc/hehermes-pasarela/tokens.json"))
        self.assertIsNone(tokens.quien(token), "la clave de antes sigue valiendo")
        nuevo = json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))["carga"]["t"]
        self.assertEqual(tokens.quien(nuevo), "mi-iphone")


class ElCanjeSinRoot(Base):
    """Sin root, el canje es una unidad de usuario, igual que Hermes: tampoco la toca su reinicio."""

    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def test_el_reinicio_de_su_hermes_no_toca_el_canje(self):
        self.montar(usuario="hermes", como="unidad-usuario", habilitada=False)
        self.sis.carpeta("/run/user/1000", 0o700)
        self.assertEqual(self.por_chat(), 0, self.salida)
        orden = next(o for o in self.falso.lanzados if "--unit=hehermes-canje" in o)
        self.assertEqual(orden[0], "--user")
        self.assertNotIn("--scope", orden)
        self.assertIn("hehermes-canje", self.falso.activos_usuario)
        (reinicio,) = self.reinicios()
        self.assertTrue(self.sis.ejecutar(reinicio[reinicio.index("--quiet") + 1:]).bien)
        self.assertIn("usuario:hermes-gateway-3f2a9c1b", self.falso.reinicios)
        self.assertIn("hehermes-canje", self.falso.activos_usuario)


if __name__ == "__main__":
    unittest.main()
