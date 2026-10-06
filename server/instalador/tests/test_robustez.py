"""Robustez al aplicar (desde la 0.11.1): la salida al momento, lo de Hermes lo último, apt y pip con aguante, un código
para cada fallo y los avisos para la app (`hehermes_servidor/marcha.py`).

Sobre el servidor falso, como las demás. Las señales son de verdad: se mandan a este mismo proceso desde una orden falsa,
como las mandaría el plazo de la terminal de Hermes (SIGTERM a todo el grupo) o un SSH que se cierra (SIGHUP). Antes de
mandarla, la orden falsa mira que el instalador la atienda: si no, la señal tumbaría la tirada entera.
"""

import apoyo

import fcntl
import os
import re
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import alma, cli, marcha, modo_tls, porchat
from hehermes_servidor import ambito as amb
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.sistema import Resultado, _ejecutar_de_verdad

ORIGEN = str(apoyo.RAIZ)
LLAVE = "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkc"
ENV = "/root/.hermes/.env"
SOUL = "/root/.hermes/SOUL.md"
PASO = re.compile(r"^hehermes-paso: (\d+)/(\d+) ([a-z]+) \((\d+) s\)$")
ENLACE = re.compile(r"^hehermes-canje:1\?h=[^&]+&p=(\d+)&")
PIP = VENV_PIP = sf.VENV_CANJE + "/bin/python -I -m pip install"
#: Lo que da `systemctl show -p ExecReload --value` con la unidad que escribe `hermes gateway install`
#: (hermes_cli/gateway.py, `generate_systemd_unit`: `ExecReload=/bin/kill -USR1 $MAINPID`).
EXEC_RELOAD = ("{ path=/bin/kill ; argv[]=/bin/kill -USR1 $MAINPID ; ignore_errors=no ; start_time=[n/a] ; "
               "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")


class Base(unittest.TestCase):
    euid = 0
    cuenta = None

    def setUp(self):
        self.montar()
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        azar.start()
        self.addCleanup(azar.stop)

    def montar(self, **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv, terminal=False):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=terminal, euid=self.euid, cuenta=self.cuenta, relanzar=lambda orden: 0,
                          usuario="hermes")
        self.salida = "\n".join(self.texto)
        self.lineas = [linea for linea in self.salida.splitlines() if linea.strip()]
        return codigo

    def por_chat(self, *extra):
        return self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE, *extra)

    def ultima(self):
        return self.lineas[-1].strip()

    def indice(self, condicion, desde=0):
        return next(i for i, o in enumerate(self.sis.ordenes) if i >= desde and condicion(o))

    def reinicios(self, desde=0):
        return [o for o in self.sis.ordenes[desde:] if o[:1] == ["systemd-run"] and "--on-active=90" in o]

    def senal_desde(self, prefijo, senal, despues=None):
        """Una orden falsa que, al ejecutarse, le manda `senal` a este proceso (y si sigue vivo, contesta lo de
        `despues`, o bien)."""
        def responder(args, entrada):
            if signal.getsignal(senal) in (signal.SIG_DFL, signal.SIG_IGN, signal.default_int_handler):
                raise AssertionError("el instalador no atiende %s: mandarla tumbaría la tirada" % senal.name)
            os.kill(os.getpid(), senal)
            return despues(args, entrada) if despues else Resultado(0)
        self.sis.responder[prefijo] = responder


class LaSalidaAlMomento(Base):
    def test_el_lanzador_vacia_cada_linea(self):
        """Con `python3 -IB` y la salida a una tubería (la de la terminal de Hermes), Python guarda lo impreso hasta el
        final, y si Hermes lo corta por plazo se pierde todo: el lanzador la pone con búfer de línea."""
        programa = ("import runpy, sys\n"
                    "runpy.run_path(%r, run_name='hehermes_prueba')\n"
                    "sys.stderr.write(repr(sys.stdout.line_buffering))\n" % str(apoyo.RAIZ / "hehermes-servidor"))
        r = subprocess.run([sys.executable, "-I", "-B", "-c", programa], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=60)
        self.assertEqual(r.stderr.strip(), "True", r.stderr)

    def test_un_python_viejo_lo_dice_con_su_codigo(self):
        """El 3.6 de RHEL 8: sin la guarda, un SyntaxError al importar, sin código para la app."""
        programado = ("import runpy, sys\n"
                      "sys.version_info = (3, 6, 8, 'final', 0)\n"
                      "sys.argv = ['hehermes-servidor', 'instalar', '--por-chat']\n"
                      "runpy.run_path(%r, run_name='__main__')\n" % str(apoyo.RAIZ / "hehermes-servidor"))
        r = subprocess.run([sys.executable, "-I", "-B", "-c", programado], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Python 3.9 o más nuevo", r.stdout)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "hehermes-error:sistema")
        self.assertNotIn("Traceback", r.stderr)

    def test_cada_paso_dice_cual_y_cuando(self):
        self.montar(habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        pasos = [PASO.match(linea) for linea in self.lineas if linea.startswith(marcha.PREFIJO_PASO)]
        self.assertTrue(pasos and all(pasos), [l for l in self.lineas if l.startswith("hehermes-paso")])
        numeros = [int(p.group(1)) for p in pasos]
        self.assertEqual(numeros, list(range(1, len(pasos) + 1)))
        self.assertEqual({int(p.group(2)) for p in pasos}, {len(pasos)})
        claves = [p.group(3) for p in pasos]
        for clave in ("ficheros", "venv", "certificados", "servicios", "comprobar", "canje", "hermes"):
            self.assertIn(clave, claves)
        self.assertEqual(claves[-2:], ["canje", "hermes"], "lo de Hermes, lo último")
        segundos = [int(p.group(4)) for p in pasos]
        self.assertEqual(segundos, sorted(segundos))
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())

    def test_por_ssh_tambien_salen_los_pasos(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertTrue([l for l in self.lineas if PASO.match(l)])
        self.assertFalse([l for l in self.lineas if l.startswith(marcha.PREFIJO_AVISO)], "los avisos son para la app")


class HermesLoUltimo(Base):
    """Lo que puede fallar (paquetes, venv, pip, unidades, cortafuegos, canje) va antes; lo de Hermes (su .env y su
    SOUL.md), lo último, y su reinicio pendiente no se pierde aunque algo se pare o lo corten."""

    def test_si_apt_falla_hermes_queda_como_estaba_y_repetir_lo_acaba(self):
        """El cerrojo de dpkg de un VPS recién creado: hasta la 0.11.0 dejaba la API encendida en el .env sin reiniciar
        Hermes, y la frase siguiente se paraba en `api-hermes`."""
        self.montar(habilitada=False)
        self.falso.ensurepip = False
        env, soul = self.sis.leer_texto(ENV), self.sis.leer_texto(SOUL)
        self.falso.apt_falla = {"install": "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by "
                                           "process 1234 (unattended-upgr)"}
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:apt")
        self.assertIn("hehermes-detalle:paso=paquetes", self.lineas)
        self.assertEqual(self.sis.leer_texto(ENV), env)
        self.assertEqual(self.sis.leer_texto(SOUL), soul)
        self.assertEqual(self.reinicios(), [])
        self.assertIn("Hermes, sin tocar", self.salida)
        self.falso.apt_falla = {}
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertNotIn("api-hermes", self.salida)

    def test_el_env_y_el_soul_van_despues_del_canje(self):
        self.montar(habilitada=False)
        cuando = {}
        for modulo, nombre in ((porchat, "activar_api"), (alma, "anadir")):
            original = getattr(modulo, nombre)

            def apuntar(*args, _original=original, _nombre=nombre, **kwargs):
                cuando[_nombre] = len(self.sis.ordenes)
                return _original(*args, **kwargs)
            parche = mock.patch.object(modulo, nombre, apuntar)
            parche.start()
            self.addCleanup(parche.stop)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(set(cuando), {"activar_api", "anadir"})
        primero = min(cuando.values())
        for nombre, condicion in (
                ("pip", lambda o: o[0].endswith("/bin/python") and o[1:5] == ["-I", "-m", "pip", "install"]),
                ("la pasarela", lambda o: o[:3] == ["systemctl", "enable", "--now"] and "hehermes-pasarela" in o[3]),
                ("el canje", lambda o: o[:1] == ["systemd-run"] and "--unit=hehermes-canje" in o)):
            with self.subTest(antes=nombre):
                self.assertLess(self.indice(condicion), primero)
        self.assertGreater(self.indice(lambda o: o[:1] == ["systemd-run"] and "--on-active=90" in o), primero,
                           "el reinicio, después de tocar el .env")

    def test_un_corte_entre_el_env_y_su_reinicio_lo_acaba_la_vez_siguiente(self):
        self.montar(habilitada=False)
        antes = self.sis.leer_texto(ENV)
        with mock.patch.object(porchat, "reiniciar_hermes", side_effect=marcha.Interrupcion("SIGTERM")):
            self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:interrumpido")
        self.assertNotEqual(self.sis.leer_texto(ENV), antes, "el .env ya tenía lo suyo")
        desde = len(self.sis.ordenes)
        # Hermes no se ha reiniciado: su API sigue sin contestar.
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertNotIn("hehermes-error", self.salida)
        self.assertEqual(len(self.reinicios(desde)), 1, "y ahora sí se reinicia, una vez")

    def test_si_falla_tras_tocar_hermes_su_reinicio_se_programa_igual(self):
        self.montar(habilitada=False)
        with mock.patch.object(alma, "anadir", side_effect=OSError(28, "No space left on device")):
            self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(len(self.reinicios()), 1, "su .env ya dice que encienda la API: tiene que reiniciarse")
        self.assertEqual(self.ultima(), "hehermes-error:python")
        self.assertIn("A Hermes ya le he dejado su API encendida en %s" % ENV, self.salida)
        self.assertIn("Hermes se reinicia", self.salida)

    def test_la_frase_otra_vez_con_su_reinicio_ya_programado_no_programa_otro(self):
        """Dentro de los 90 s (o con la recarga esperando a que acabe el turno): dos reinicios seguidos podrían cortar
        el turno de la segunda pasada."""
        self.montar(habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.reinicios()), 1)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.reinicios(desde), [])
        self.assertIn("Hermes tiene programado su reinicio", self.salida)

    def test_programado_hace_mucho_y_sin_contestar_es_otra_cosa(self):
        """Si se reinició (o debía) hace más de lo que tarda y su API sigue sin contestar, no es lo pendiente: se dice
        (`api-hermes`), en vez de reiniciarlo una y otra vez y dar un enlace que no llega a ninguna parte."""
        self.montar(habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        man = Manifiesto.leer(self.sis)
        man.datos[modo_tls.REINICIO_DE_HERMES]["programado"] = time.time() - modo_tls.TARDA_EN_REINICIARSE - 60
        man.guardar(self.sis)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:api-hermes")
        self.assertEqual(self.reinicios(desde), [])

    def test_un_reinicio_ya_programado_no_se_repite_si_lo_de_antes_falla(self):
        self.montar(habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.reinicios()), 1)
        desde = len(self.sis.ordenes)
        self.sis.responder["useradd"] = apoyo.mal("useradd: se ha roto")
        self.sis.borrar("/etc/hehermes-pasarela/pasarela.ini")
        self.falso.usuarios_sistema.discard("hh-pasarela")
        self.sis.responder["id -u hh-pasarela"] = apoyo.mal("no existe")
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.reinicios(desde), [], "ya estaba programado")

    def test_sin_poder_reiniciarlo_la_vez_siguiente_sigue_siendo_reinicia_hermes(self):
        """Un Hermes suelto (tmux, nohup): la API se enciende en el .env y se pide `/restart`. Si se vuelve a pegar la
        frase sin reiniciarlo, hasta la 0.11.0 salía `api-hermes`, que la app no explica."""
        self.montar(habilitada=False, como="proceso")
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:reinicia-hermes")
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:reinicia-hermes")
        self.assertIn("/restart", self.salida)

    def test_una_api_que_no_contesta_sin_nada_pendiente_sigue_siendo_api_hermes(self):
        self.falso.hermes.clear()
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:api-hermes")

    def test_con_la_unidad_de_hermes_se_recarga_con_drenaje(self):
        """`systemctl reload` de su unidad es SIGUSR1: Hermes no acepta turnos nuevos, espera a que acabe el que tiene
        (el que contesta con el enlace) y se reinicia (gateway/run.py, `_start_gateway_make_restart_signal_handler`).
        Sin cortar el turno, sin esperar 90 s a ciegas."""
        self.montar(habilitada=False)
        self.falso.unidades_hermes["hermes-gateway.service"]["ExecReload"] = EXEC_RELOAD
        self.assertEqual(self.por_chat(), 0, self.salida)
        recarga = self.indice(lambda o: o == ["systemctl", "reload", "hermes-gateway.service"])
        self.assertGreater(recarga, self.indice(lambda o: o[:1] == ["systemd-run"] and "--unit=hehermes-canje" in o))
        self.assertEqual(self.reinicios(), [])
        self.assertIn("hehermes-aviso:hermes-se-reinicia", self.lineas)

    def test_si_la_recarga_falla_se_reinicia_a_los_90_s(self):
        self.montar(habilitada=False)
        self.falso.unidades_hermes["hermes-gateway.service"]["ExecReload"] = EXEC_RELOAD
        self.sis.responder["systemctl reload hermes-gateway.service"] = apoyo.mal("Job failed")
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.reinicios()), 1)


class SinRootConClaveNueva(Base):
    """Sin root, el vigía lee la clave de Hermes de su .env al arrancar. Con la clave nueva escrita lo último, el vigía
    se reinicia después, para leerla."""

    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def test_el_vigia_se_reinicia_tras_el_env(self):
        self.montar(usuario="hermes", como="unidad-usuario", habilitada=None, clave=None)
        self.sis.carpeta("/run/user/1000", 0o700)
        cuando = {}
        original = porchat.activar_api

        def apuntar(*args, **kwargs):
            cuando["env"] = len(self.sis.ordenes)
            return original(*args, **kwargs)
        with mock.patch.object(porchat, "activar_api", apuntar):
            self.assertEqual(self.por_chat(), 0, self.salida)
        reinicio = self.indice(lambda o: o[:2] == ["systemctl", "--user"] and o[2:3] == ["restart"]
                               and "hehermes-vigia" in o[-1])
        self.assertGreater(reinicio, cuando["env"])


class UnCodigoParaCadaFallo(Base):
    def test_una_parada_a_medias(self):
        self.sis.responder["useradd"] = apoyo.mal("useradd: se ha roto")
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.lineas[-2:], ["hehermes-detalle:paso=ficheros", "hehermes-error:a-medias"])
        self.assertIn("useradd: se ha roto", self.salida)
        self.assertIn("el mismo comando", self.salida)

    def test_pip_que_no_llega(self):
        self.sis.responder[PIP] = apoyo.mal("ERROR: Could not find a version that satisfies the requirement")
        with mock.patch("time.sleep"):
            self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:pip")
        self.assertEqual(len([o for o in self.sis.ordenes if " ".join(o).startswith(PIP)]), 3, "tres intentos")

    def test_lo_inesperado_a_mitad(self):
        with mock.patch.object(modo_tls, "_certificado_siguiente", side_effect=RuntimeError("se ha roto por dentro")):
            self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:python")
        self.assertIn("RuntimeError: se ha roto por dentro", self.salida)
        self.assertNotIn("Traceback", self.salida)
        self.assertIn("Hermes, sin tocar", self.salida)

    def test_lo_inesperado_antes_de_tocar_nada(self):
        antes = self.sis.foto()
        with mock.patch.object(modo_tls, "calcular_plan_tls", side_effect=KeyError("no estaba")):
            self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:python")
        self.assertIn("No he cambiado nada", self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_otro_instalador_en_marcha(self):
        ruta = self.sis.ruta("/run/hehermes-servidor.lock")
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, "w") as cerrojo:
            fcntl.flock(cerrojo, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:ocupado")
        self.assertIn("ya hay otro hehermes-servidor en marcha", self.salida)

    def test_por_ssh_no_hay_codigos(self):
        self.sis.responder["useradd"] = apoyo.mal("useradd: se ha roto")
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 1)
        self.assertNotIn("hehermes-error", self.salida)
        self.assertIn("useradd: se ha roto", self.salida)

    def test_sigterm_a_mitad(self):
        """El plazo de la terminal de Hermes (o `/stop`): SIGTERM a todo el grupo y, un segundo después, SIGKILL."""
        manejador = signal.getsignal(signal.SIGTERM)
        antes = self.sis.leer_texto(ENV)
        self.senal_desde(PIP, signal.SIGTERM)
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:interrumpido")
        self.assertIn("hehermes-detalle:paso=venv", self.lineas)
        self.assertIn("SIGTERM", self.salida)
        self.assertEqual(self.sis.leer_texto(ENV), antes)
        self.assertEqual(signal.getsignal(signal.SIGTERM), manejador, "deja la señal como estaba")

    def test_sighup_a_mitad_deshace_su_paso(self):
        """Un SSH que se cierra (iOS suspende la app del terminal): el paso de la pasarela vuelve a como estaba."""
        manejador = signal.getsignal(signal.SIGHUP)
        self.senal_desde("systemctl enable --now hehermes-pasarela.service", signal.SIGHUP)
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:interrumpido")
        self.assertFalse(self.sis.existe("/etc/hehermes-pasarela/pasarela.ini"))
        self.assertNotIn("/etc/hehermes-pasarela/pasarela.ini", Manifiesto.leer(self.sis).ficheros)
        self.assertEqual(signal.getsignal(signal.SIGHUP), manejador)

    def test_ctrl_c_por_ssh(self):
        self.senal_desde(PIP, signal.SIGINT)
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 1)
        self.assertIn("SIGINT", self.salida)
        self.assertNotIn("hehermes-error", self.salida)
        self.assertNotIn("Traceback", self.salida)


class AptYPipConAguante(Base):
    def test_apt_espera_al_cerrojo_y_a_cloud_init_sin_reiniciar_servicios(self):
        self.falso.ensurepip = False
        self.falso.programa("/usr/bin/cloud-init")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        cloud = self.indice(lambda o: o[:3] == ["cloud-init", "status", "--wait"])
        apt = [o for o in self.sis.ordenes if "apt-get" in o]
        self.assertEqual(len(apt), 2, apt)
        self.assertLess(cloud, self.sis.ordenes.index(apt[0]))
        for orden in apt:
            with self.subTest(orden=orden):
                for opcion in ("DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_SUSPEND=1", "NEEDRESTART_MODE=l",
                               "DPkg::Lock::Timeout=120", "Acquire::Retries=3"):
                    self.assertIn(opcion, orden)
        self.assertIn("python3-venv", self.falso.paquetes)

    def test_un_update_que_falla_no_impide_instalar(self):
        self.falso.ensurepip = False
        self.falso.apt_falla = {"update": "E: The repository 'https://ejemplo.invalid stable Release' does not have a "
                                          "Release file."}
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertIn("python3-venv", self.falso.paquetes)
        self.assertIn("does not have a Release file", self.salida)

    def test_si_tampoco_instala_dice_las_dos_cosas(self):
        self.falso.ensurepip = False
        self.falso.apt_falla = {"update": "E: un repositorio roto", "install": "E: Unable to locate package"}
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:apt")
        self.assertIn("un repositorio roto", self.salida)
        self.assertIn("Unable to locate package", self.salida)

    def test_pip_reintenta_con_espera_creciente(self):
        intentos = []

        def pip(args, entrada):
            intentos.append(args)
            if len(intentos) == 1:
                return Resultado(1, "", "ERROR: HTTPSConnectionPool(host='pypi.org'): Read timed out.")
            return self.falso(args, entrada)
        self.sis.responder[PIP] = pip
        with mock.patch("time.sleep") as dormir:
            self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual(len(intentos), 2)
        for opcion in ("--retries", "--timeout"):
            self.assertIn(opcion, intentos[0])
        self.assertTrue(dormir.called)

    def test_apt_y_pip_con_su_plazo(self):
        self.falso.ensurepip = False
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        plazos = {" ".join(args): plazo for args, plazo in self.sis.plazos}
        apt = [plazo for orden, plazo in plazos.items() if "apt-get" in orden]
        pip = [plazo for orden, plazo in plazos.items() if orden.startswith(PIP)]
        self.assertTrue(apt and all(plazo >= 600 for plazo in apt), plazos)
        self.assertTrue(pip and all(plazo >= 300 for plazo in pip), plazos)

    def test_una_orden_que_se_cuelga_se_corta(self):
        empieza = time.monotonic()
        r = _ejecutar_de_verdad(["sleep", "30"], plazo=0.5)
        self.assertEqual(r.codigo, 124)
        self.assertLess(time.monotonic() - empieza, 10)
        self.assertIn("0.5", r.error)


class AvisosParaLaApp(Base):
    def test_por_chat_van_antes_del_enlace(self):
        self.montar(habilitada=False)
        self.assertEqual(self.por_chat(), 0, self.salida)
        canje = ENLACE.match(self.ultima()).group(1)
        avisos = [l for l in self.lineas if l.startswith(marcha.PREFIJO_AVISO)]
        self.assertIn("hehermes-aviso:cortafuegos-proveedor tcp=61234 canje=%s" % canje, avisos)
        self.assertIn("hehermes-aviso:hermes-se-reinicia", avisos)
        indices = [self.lineas.index(a) for a in avisos]
        self.assertEqual(max(indices), len(self.lineas) - 2, "juntos, justo antes del enlace")

    def test_sin_poder_programar_el_reinicio_lo_avisa(self):
        self.montar(habilitada=False)
        self.sis.responder["systemd-run --on-active=90"] = apoyo.mal("Failed to start transient timer unit")
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertIn("hehermes-aviso:reinicia-hermes", self.lineas)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())

    def test_si_el_vigia_no_esta_bien_lo_avisa(self):
        self.falso.vigia_comprueba = ["mal:  el relé no contesta"]
        with mock.patch("hehermes_servidor.avisos.ESPERA_AL_COMPROBAR", 0):
            self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertIn("hehermes-aviso:avisos-push", self.lineas)


if __name__ == "__main__":
    unittest.main()
