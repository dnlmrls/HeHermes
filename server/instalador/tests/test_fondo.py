"""La instalación por chat en segundo plano (desde la 0.11.2, `hehermes_servidor/fondo.py`), sobre el servidor falso.

La unidad `hehermes-instalar` es de mentira: al lanzarla, la prueba hace lo que haría systemd (`correr_la_de_dentro`):
el instalador con la orden de la unidad, como root (o como el usuario, con `--user`), con lo que imprime a su fichero. O
la deja en marcha a medias (`dejarla_a_medias`), para lo que pasa cuando no acaba a tiempo, y la acaba después
(`acabarla`). El reloj de quien la sigue también es de mentira: avanza con cada espera, y a sus horas pasan cosas
(`Reloj.a_los`).
"""

import apoyo

import base64
import json
import os
import re
import signal
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import cli, fondo, porchat
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.sistema import Resultado

ORIGEN = str(apoyo.RAIZ)
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()
OTRA_LLAVE = base64.urlsafe_b64encode(bytes(range(100, 132))).rstrip(b"=").decode()
ENLACE = re.compile(r"^hehermes-canje:1\?h=[^&]+&p=(\d+)&")
SIGUE = re.compile(r"^hehermes-sigue: (?:(\d+)/(\d+) ([a-z-]+)|preparando) \((\d+) s\)$")
CARPETA = "/run/hehermes-instalar"
TRABAJO = "/root/.hermes/profiles/trabajo"
#: Lo que dice la de mentira antes de quedarse a medias.
A_MEDIAS = "hehermes-paso: 1/9 paquetes (0 s)\nhehermes-paso: 2/9 ficheros (61 s)\n"


class Reloj:
    """El de quien la sigue: no duerme, avanza; y a sus horas pasa lo que se le diga."""

    def __init__(self):
        self.ahora = 1000.0
        self.citas = []

    def __call__(self):
        return self.ahora

    def dormir(self, segundos):
        self.ahora += segundos
        for cita in [c for c in self.citas if c[0] <= self.ahora]:
            self.citas.remove(cita)
            cita[1]()

    def a_los(self, segundos, que):
        self.citas.append((self.ahora + segundos, que))


class Base(unittest.TestCase):
    euid = 0
    cuenta = None

    def setUp(self):
        self.sis, self.falso = self.servidor()
        self.addCleanup(self.sis.limpiar)
        # Con systemd-run (el servidor falso no lo trae: sin él, las pruebas de antes van en primer plano).
        self.falso.programa("/usr/bin/systemd-run")
        self.falso.al_instalar_en_segundo_plano = self.correr_la_de_dentro
        self.reloj = Reloj()
        for nombre, valor in (("_reloj", self.reloj), ("_dormir", self.reloj.dormir)):
            parche = mock.patch.object(fondo, nombre, valor)
            parche.start()
            self.addCleanup(parche.stop)
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        azar.start()
        self.addCleanup(azar.stop)
        self.unidad = None
        self.codigos_de_dentro = []

    def servidor(self):
        return sf.servidor()

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=False, euid=self.euid, cuenta=self.cuenta, relanzar=lambda orden: 0,
                          usuario="hermes")
        self.salida = "\n".join(self.texto)
        self.lineas = [linea for linea in self.salida.splitlines() if linea.strip()]
        return codigo

    def por_chat(self, llave=LLAVE, iphone="mi-iphone"):
        return self.orden("instalar", "--por-chat", "--activar-api", "--iphone", iphone, "--llave", llave)

    def ultima(self):
        return self.lineas[-1].strip()

    def lanzadas(self):
        return [o for o in self.sis.ordenes if o[:1] == ["systemd-run"] and "--unit=hehermes-instalar" in o]

    def activas(self, orden):
        return self.falso.activos_usuario if "--user" in orden else self.falso.activos

    def fichero_de(self, orden):
        return next(a.split("file:", 1)[1] for a in orden if a.startswith("StandardOutput=file:"))

    def correr_la_de_dentro(self, orden):
        """Lo que hace systemd con la unidad: el instalador con su orden, como root (o el usuario, con `--user`), con su
        entorno (hija de PID 1: ni el pid ni el entorno de quien la lanzó) y lo que imprime a su fichero. Al acabar,
        deja de estar en marcha."""
        python = orden.index("/usr/bin/python3")
        lanzador = orden[python + 3]
        entorno = dict(a[len("--setenv="):].split("=", 1) for a in orden if a.startswith("--setenv="))
        antes = (self.sis.entorno, self.sis.pid)
        self.sis.entorno, self.sis.pid = entorno, None
        try:
            with open(self.sis.ruta(self.fichero_de(orden)), "a", encoding="utf-8") as f:
                def escribir(texto=""):
                    f.write(texto + "\n")
                    f.flush()
                self.codigos_de_dentro.append(cli.main(
                    orden[python + 4:], "uso", self.sis.ruta(os.path.dirname(lanzador)), sis=self.sis,
                    entrada=lambda _: "n", salida=escribir, terminal=False, euid=self.euid, cuenta=self.cuenta,
                    relanzar=lambda o: 0, usuario="hermes"))
        finally:
            self.sis.entorno, self.sis.pid = antes
        self.activas(orden).discard("hehermes-instalar")

    def dejarla_a_medias(self, orden):
        """Arranca, dice sus primeros pasos y se queda en marcha: lo que tarda de verdad no cabe en el plazo."""
        self.unidad = orden
        with open(self.sis.ruta(self.fichero_de(orden)), "a", encoding="utf-8") as f:
            f.write(A_MEDIAS)

    def acabarla(self):
        """La que se quedó a medias, ahora entera."""
        self.correr_la_de_dentro(self.unidad)


class LaPrimeraVez(Base):
    def test_la_lanza_en_su_unidad_la_sigue_y_da_el_enlace(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.codigos_de_dentro, [0])
        self.assertIn("La instalación va en segundo plano", self.salida)
        # Lo que dice la de dentro, tal cual: sus pasos y sus avisos, antes del enlace.
        self.assertTrue([l for l in self.lineas if l.startswith("hehermes-paso:")])
        self.assertIn("hehermes-aviso:cortafuegos-proveedor tcp=", self.salida)
        self.assertIn("hehermes-canje", self.falso.activos)
        self.assertNotIn("hehermes-instalar", self.falso.activos)

    def test_es_su_propia_unidad_y_no_la_de_hermes(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        [orden] = self.lanzadas()
        self.assertEqual(orden[:2], ["systemd-run", "--unit=hehermes-instalar"])
        self.assertNotIn("--scope", orden)
        self.assertNotIn("hehermes-instalar", self.falso.atados_a_hermes)
        for propiedad in ("--collect", "StandardOutput=file:%s/salida" % CARPETA, "StandardError=inherit",
                          "RuntimeMaxSec=%d" % fondo.TOPE_DE_LA_UNIDAD):
            self.assertIn(propiedad, orden)
        python = orden.index("/usr/bin/python3")
        self.assertEqual(orden[python:], ["/usr/bin/python3", "-I", "-B", CARPETA + "/hehermes-servidor/hehermes-servidor",
                                          "instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave",
                                          LLAVE, "--en-segundo-plano"])
        # Corre del paquete copiado a su carpeta, no del de mktemp, que es del usuario de Hermes.
        self.assertTrue(self.sis.existe(CARPETA + "/hehermes-servidor/hehermes_servidor/fondo.py"))
        self.assertTrue(self.sis.existe(CARPETA + "/hehermes-servidor/hehermes-dispositivo"))

    def test_lo_guardado_solo_lo_lee_root(self):
        """Lo que imprime lleva el enlace, que se guarda mientras vale el canje: en una carpeta 0700 de root, y cada
        fichero 0600."""
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(self.sis.modo(CARPETA), 0o700)
        for nombre in ("salida", "estado.json"):
            with self.subTest(nombre):
                self.assertEqual(self.sis.modo(CARPETA + "/" + nombre), 0o600)
        self.assertIn(self.ultima(), self.sis.leer_texto(CARPETA + "/salida"))

    def test_la_de_dentro_instala_y_no_lanza_otra(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.lanzadas()), 1)
        self.assertEqual(json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))["llave"], LLAVE)

    def test_si_no_arranca_va_aqui_mismo_y_no_deja_nada(self):
        self.sis.responder["systemd-run --unit=hehermes-instalar"] = lambda args, entrada: Resultado(
            1, "", "Failed to start transient service unit: Access denied\n")
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertIn("No he podido lanzar la instalación en segundo plano (Failed to start transient service unit: "
                      "Access denied): la hago aquí mismo", self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertFalse(self.sis.existe(CARPETA))

    def test_sin_systemd_run_va_aqui_mismo_como_hasta_la_0111(self):
        os.unlink(self.sis.ruta("/usr/bin/systemd-run"))
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.lanzadas(), [])
        self.assertFalse(self.sis.existe(CARPETA))
        self.assertNotIn("segundo plano", self.salida)

    def test_con_plan_no_lanza_nada(self):
        self.assertEqual(self.orden("instalar", "--plan", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE), 0)
        self.assertEqual(self.lanzadas(), [])

    def test_si_la_matan_sin_decir_nada_es_interrumpido(self):
        def muere(orden):
            self.dejarla_a_medias(orden)
            self.activas(orden).discard("hehermes-instalar")
        self.falso.al_instalar_en_segundo_plano = muere
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:interrumpido")
        self.assertIn("sin decir cómo ha acabado", self.salida)


class Sigue(Base):
    def setUp(self):
        super().setUp()
        self.falso.al_instalar_en_segundo_plano = self.dejarla_a_medias

    def test_si_no_acaba_a_tiempo_dice_que_sigue_y_la_deja_en_marcha(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        sigue = SIGUE.match(self.ultima())
        self.assertTrue(sigue, self.ultima())
        self.assertEqual(sigue.group(1, 2, 3), ("2", "9", "ficheros"))
        self.assertIn("hehermes-paso: 2/9 ficheros (61 s)", self.lineas)
        self.assertNotIn("hehermes-error:", self.salida)
        self.assertIn("hehermes-instalar", self.falso.activos)
        self.assertFalse([o for o in self.sis.ordenes if o[:2] == ["systemctl", "stop"] and "hehermes-instalar" in o])
        self.assertEqual(self.reloj.ahora - 1000, fondo.PLAZO_DEL_CHAT, "lo que cabe en el plazo de Hermes, y no más")
        self.assertLess(fondo.PLAZO_DEL_CHAT, 180)

    def test_el_mismo_comando_otra_vez_se_engancha_y_no_lanza_otra(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.reloj.a_los(30, self.acabarla)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.lanzadas()), 1, "engancharse no lanza otra")
        self.assertIn("ya está en marcha", self.salida)
        self.assertIn("hehermes-paso: 2/9 ficheros (61 s)", self.lineas, "lo dicho, desde el principio")
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.codigos_de_dentro, [0])

    def test_si_acaba_mientras_nadie_la_sigue_la_frase_otra_vez_da_su_enlace(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.acabarla()
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertIn("ya ha acabado", self.salida)
        enlace = self.ultima()
        self.assertTrue(ENLACE.match(enlace), enlace)
        self.assertEqual(len(self.lanzadas()), 1)
        # Otra vez, con el canje abierto: el mismo enlace, sin lanzar nada (otra instalación le quitaría la clave).
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(self.ultima(), enlace)
        self.assertEqual(len(self.lanzadas()), 1)
        # Canjeado o caducado, ya no vale: la frase otra vez es otra instalación, con otro enlace.
        self.falso.activos.discard("hehermes-canje")
        self.falso.al_instalar_en_segundo_plano = self.correr_la_de_dentro
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.lanzadas()), 2)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertNotEqual(self.ultima(), enlace)

    def test_un_fallo_que_nadie_ha_visto_se_da_una_vez(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.falso.ensurepip = False
        self.falso.apt_falla = {"install": "E: Could not get lock /var/lib/dpkg/lock-frontend"}
        self.acabarla()
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:apt")
        self.assertIn("hehermes-detalle:paso=paquetes", self.lineas)
        self.assertEqual(len(self.lanzadas()), 1)
        # Ya dado: la frase otra vez lo vuelve a intentar, y sigue donde se quedó.
        self.falso.apt_falla = {}
        self.falso.al_instalar_en_segundo_plano = self.correr_la_de_dentro
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len(self.lanzadas()), 2)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())

    def test_si_cortan_al_que_la_sigue_dice_que_sigue_y_no_la_para(self):
        """El plazo de la terminal de Hermes (o su /stop) manda SIGTERM a quien la sigue: la instalación sigue, y lo
        último que dice es que sigue, no `interrumpido`."""
        def cortar():
            if signal.getsignal(signal.SIGTERM) in (signal.SIG_DFL, signal.SIG_IGN, signal.default_int_handler):
                raise AssertionError("nadie atiende SIGTERM: mandarla tumbaría la tirada")
            os.kill(os.getpid(), signal.SIGTERM)
        self.reloj.a_los(20, cortar)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(SIGUE.match(self.ultima()), self.ultima())
        self.assertIn("Dejo de seguirla (SIGTERM)", self.salida)
        self.assertNotIn("interrumpido", self.salida)
        self.assertIn("hehermes-instalar", self.falso.activos)
        self.assertEqual(self.reloj.ahora - 1000, 20)

    def test_con_otra_frase_en_marcha_espera_a_que_acabe_y_lanza_la_suya(self):
        self.assertEqual(self.por_chat(llave=LLAVE), 0, self.salida)
        # Otra frase (otra llave) con la primera en marcha: espera, sin lanzar la suya ni enseñar lo de la otra.
        self.assertEqual(self.por_chat(llave=OTRA_LLAVE), 0, self.salida)
        self.assertTrue(SIGUE.match(self.ultima()), self.ultima())
        self.assertIn("otra instalación en marcha", self.salida)
        self.assertFalse([l for l in self.lineas if l.startswith("hehermes-paso:")])
        self.assertEqual(len(self.lanzadas()), 1)
        # La primera acaba mientras espera la segunda: lanza la suya, y el enlace es el de su llave.
        self.reloj.a_los(10, self.acabarla)
        self.falso.al_instalar_en_segundo_plano = self.correr_la_de_dentro
        self.assertEqual(self.por_chat(llave=OTRA_LLAVE), 0, self.salida)
        self.assertEqual(len(self.lanzadas()), 2)
        self.assertIn(OTRA_LLAVE, self.lanzadas()[-1])
        self.assertEqual(len([l for l in self.lineas if ENLACE.match(l.strip())]), 1, "solo el suyo")
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))["llave"], OTRA_LLAVE)


class ElCanjeSeCierra(Base):
    def test_su_limpieza_borra_el_enlace_guardado_salvo_con_una_instalacion_en_marcha(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(self.sis.existe(CARPETA))
        # La de ahora ha parado el canje para lanzar el suyo: lo de dentro es suyo.
        self.falso.activos.add("hehermes-instalar")
        self.assertEqual(self.orden("canje-limpiar"), 0, self.salida)
        self.assertTrue(self.sis.existe(CARPETA))
        self.falso.activos.discard("hehermes-instalar")
        self.assertEqual(self.orden("canje-limpiar"), 0, self.salida)
        self.assertFalse(self.sis.existe(CARPETA))


class ConVariosHermes(Base):
    def setUp(self):
        super().setUp()
        self.falso.con_hermes(como="unidad-perfil", perfil="trabajo", puerto=8643)

    def test_la_de_dentro_conecta_el_hermes_que_la_lanzo(self):
        """En su unidad la instalación es hija de PID 1: el Hermes que la lanzó lo dicen los antepasados de quien la
        lanzó, que van en su entorno."""
        self.sis.pid = 9002
        self.sis.poner("/proc/9002/status", "Name:\tpython3\nPPid:\t9001\n")
        self.sis.poner("/proc/9001/status", "Name:\tbash\nPPid:\t%d\n" % self.falso.pid_hermes)
        self.assertEqual(self.por_chat(), 0, self.salida)
        [orden] = self.lanzadas()
        self.assertIn("--setenv=%s=9002 9001 %d" % (fondo.ANTEPASADOS, self.falso.pid_hermes), orden)
        self.assertEqual(Manifiesto.leer(self.sis).datos["mantenimiento"]["casa"], TRABAJO)


class SinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)
    RUN = "/run/user/1000/hehermes-instalar"

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_es_una_unidad_de_usuario_con_lo_suyo_en_su_run(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        [orden] = self.lanzadas()
        self.assertEqual(orden[:3], ["systemd-run", "--user", "--unit=hehermes-instalar"])
        self.assertIn("StandardOutput=file:%s/salida" % self.RUN, orden)
        self.assertEqual(self.sis.modo(self.RUN), 0o700)
        self.assertEqual(self.sis.modo(self.RUN + "/salida"), 0o600)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertIn("hehermes-pasarela", self.falso.activos_usuario)
        self.assertFalse(self.sis.existe(CARPETA))

    def test_sin_su_gestor_va_aqui_mismo(self):
        os.rmdir(self.sis.ruta("/run/user/1000"))
        self.por_chat()
        self.assertEqual(self.lanzadas(), [])
        self.assertTrue(self.ultima().startswith("hehermes-"), self.ultima())


if __name__ == "__main__":
    unittest.main()
