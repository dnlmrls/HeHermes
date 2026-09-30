"""El borrado de verdad de lo que la app borra de Hermes (`mantenimiento.py`): la marca de la pasarela, cuándo es un
rato tranquilo, parar Hermes, compactar, arrancarlo y comprobar que contesta, y todo lo que puede fallar sin entrar
nunca en bucle."""

import apoyo  # noqa: F401

import json
import os
import tempfile
import time
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import cli, porchat
from hehermes_servidor import mantenimiento as mt
from hehermes_servidor import pasarela as pa

ORIGEN = str(apoyo.RAIZ)
LLENA = 1790000000  # un instante cualquiera, en segundos


class LaDecision(unittest.TestCase):
    def test_un_rato_tranquilo(self):
        ahora = LLENA
        tranquila = {"reenviando": 0, "ultima": ahora - 3600}
        self.assertEqual(mt.momento_tranquilo(3, tranquila, ahora - 3600, ahora), (True, "tranquilo"))
        for hora in (1, 6, 12, 23):
            with self.subTest(hora=hora):
                self.assertFalse(mt.momento_tranquilo(hora, tranquila, ahora - 3600, ahora)[0])
        self.assertTrue(mt.momento_tranquilo(2, tranquila, ahora - 3600, ahora)[0])
        self.assertTrue(mt.momento_tranquilo(5, tranquila, ahora - 3600, ahora)[0])
        # Una petición con Hermes (un SSE, un turno), una reciente o Hermes escribiendo: no.
        self.assertIn("peticiones con Hermes", mt.momento_tranquilo(3, {"reenviando": 1, "ultima": ahora - 3600},
                                                                     ahora - 3600, ahora)[1])
        self.assertIn("última petición", mt.momento_tranquilo(3, {"reenviando": 0, "ultima": ahora - 60},
                                                              ahora - 3600, ahora)[1])
        self.assertIn("ha escrito en su base", mt.momento_tranquilo(3, tranquila, ahora - 60, ahora)[1])
        # Sin lo de la pasarela (una de antes, o parada), cuenta solo la base.
        self.assertTrue(mt.momento_tranquilo(3, None, ahora - 3600, ahora)[0])
        self.assertTrue(mt.momento_tranquilo(3, {"reenviando": "x", "ultima": None}, None, ahora)[0])

    def test_una_vez_por_noche_y_no_despues_de_tres_fallos(self):
        ahora = LLENA
        self.assertTrue(mt.debe_intentar({}, ahora)[0])
        self.assertFalse(mt.debe_intentar({"ultimo_intento": ahora - 3600}, ahora)[0])
        self.assertTrue(mt.debe_intentar({"ultimo_intento": ahora - mt.ENTRE_INTENTOS - 1}, ahora)[0])
        self.assertFalse(mt.debe_intentar({"fallos_seguidos": mt.MAX_FALLOS}, ahora)[0])
        self.assertTrue(mt.debe_intentar({"fallos_seguidos": mt.MAX_FALLOS - 1}, ahora)[0])
        self.assertEqual((mt.NOCHE, mt.CALMA, mt.MAX_FALLOS, mt.PLAZO_COMPACTAR), ((2, 6), 600, 3, 900))


class LaMarca(unittest.TestCase):
    """Lo que apunta la pasarela: solo desde cuándo hay algo borrado por limpiar, y su actividad."""

    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(self.carpeta.cleanup)
        self.t = [LLENA]
        self.m = pa.Mantenimiento(self.carpeta.name, reloj=lambda: self.t[0])

    def leer(self, nombre):
        with open(os.path.join(self.carpeta.name, nombre), "rb") as f:
            return f.read()

    def test_la_primera_fecha_y_nada_mas(self):
        self.assertEqual(self.m.estado()["borrado_pendiente"], False)
        self.m.apuntar_borrado()
        self.t[0] += 100
        self.m.apuntar_borrado()
        self.assertEqual(self.leer(pa.BORRADO_PENDIENTE), b"%d\n" % LLENA)
        self.assertEqual(self.m.estado()["pendiente_desde"], LLENA)
        self.assertEqual(os.listdir(self.carpeta.name), [pa.BORRADO_PENDIENTE], "ni temporales")

    def test_la_actividad(self):
        self.m.apuntar_actividad(2, LLENA - 5)
        self.assertEqual(json.loads(self.leer(pa.ACTIVIDAD)), {"reenviando": 2, "ultima": LLENA - 5, "escrita": LLENA})

    def test_lo_que_se_ensena_es_solo_lo_suyo(self):
        with open(os.path.join(self.carpeta.name, pa.MANTENIMIENTO), "w") as f:
            json.dump({"ultimo_borrado": 5, "fallo": "x", "secreto": "no", "fallos_seguidos": [1]}, f)
        estado = self.m.estado()
        self.assertNotIn("secreto", estado)
        self.assertEqual((estado["ultimo_borrado"], estado["fallo"], estado["fallos_seguidos"]), (5, "x", None))

    def test_no_sigue_enlaces(self):
        otro = os.path.join(self.carpeta.name, "otro")
        with open(otro, "w") as f:
            f.write("%d\n" % LLENA)
        os.symlink(otro, os.path.join(self.carpeta.name, pa.BORRADO_PENDIENTE))
        self.assertFalse(self.m.estado()["borrado_pendiente"], "un enlace no se lee")

    def test_lo_que_no_es_una_fecha_no_es_pendiente(self):
        for datos in (b"", b"ayer\n", b"-5\n", b"1" * 20, b"\xff"):
            with self.subTest(datos=datos):
                self.assertIsNone(pa.pendiente_desde(datos))
        self.assertEqual(pa.pendiente_desde(b" 42\n"), 42)

    def test_la_ruta_de_un_borrado_para_siempre(self):
        for ruta in ("/api/sessions/api_1790_ab", "/api/sessions/x?force=1"):
            self.assertTrue(pa.BORRAR_SESION.fullmatch(ruta), ruta)
        for ruta in ("/api/sessions", "/api/sessions/", "/api/sessions/x/messages", "/api/jobs/x", "/api/sessions/x\n"):
            self.assertFalse(pa.BORRAR_SESION.fullmatch(ruta), ruta)


class Base(unittest.TestCase):
    euid = 0
    cuenta = None

    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.falso.programa("/usr/local/bin/hermes")
        # La base de Hermes, sin tocar desde hace una hora.
        self.base = "/root/.hermes/state.db"
        self.sis.poner(self.base, b"SQLite format 3\0")
        viejo = time.time() - 3600
        os.utime(self.sis.ruta(self.base), (viejo, viejo))
        self.carpeta = "/var/lib/hehermes-pasarela"
        self.sis.carpeta(self.carpeta, 0o755)

    def orden(self, *argv, terminal=False):
        self.texto = []
        with mock.patch.object(porchat, "_azar", lambda n: 3234):
            codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "s",
                              salida=self.texto.append, terminal=terminal, euid=self.euid, cuenta=self.cuenta,
                              relanzar=lambda orden: 0, usuario="hermes")
        self.salida = "\n".join(self.texto)
        return codigo

    def pendiente(self, desde=LLENA - 7200):
        self.sis.poner(self.carpeta + "/" + pa.BORRADO_PENDIENTE, "%d\n" % desde)

    def limpiar(self, hora=3, ahora=None):
        from hehermes_servidor import ambito as amb
        from hehermes_servidor.manifiesto import Manifiesto
        self.texto = []
        ambito = amb.de_root() if self.euid == 0 else amb.de_usuario(*self.cuenta)
        man = Manifiesto.leer(self.sis, ambito.manifiesto)
        codigo = mt.borrado_seguro(self.sis, man, ambito, salida=self.texto.append, ahora=ahora or time.time(),
                                   hora_local=hora, esperar=lambda s: None)
        self.salida = "\n".join(self.texto)
        return codigo

    def estado(self):
        return json.loads(self.sis.leer(self.carpeta + "/" + pa.MANTENIMIENTO) or b"{}")

    def paradas(self):
        return [o for o in self.sis.ordenes if o[:2] == ["systemctl", "stop"] and "hermes-gateway" in o[2]]


class LaLimpieza(Base):
    def test_se_instala_su_temporizador_y_la_pasarela_sabe_donde_apuntar(self):
        self.assertIn("hehermes-borrado.timer", self.falso.activos)
        unidad = self.sis.leer_texto("/etc/systemd/system/hehermes-borrado.service")
        self.assertIn("ExecStart=/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor borrado-seguro\n",
                      unidad)
        self.assertIn("TimeoutStartSec=20min\n", unidad)
        self.assertIn("OnCalendar=*-*-* 02..05:00/15:00\n",
                      self.sis.leer_texto("/etc/systemd/system/hehermes-borrado.timer"))
        self.assertIn("[mantenimiento]\n", self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"))
        self.assertIn("StateDirectory=hehermes-pasarela\n",
                      self.sis.leer_texto("/etc/systemd/system/hehermes-pasarela.service"))
        man = json.loads(self.sis.leer("/etc/hehermes/instalacion.json"))
        self.assertEqual(man["mantenimiento"]["unidad_hermes"], "hermes-gateway.service")
        self.assertEqual(man["mantenimiento"]["casa"], "/root/.hermes")

    def test_sin_nada_pendiente_no_hace_nada(self):
        antes = len(self.sis.ordenes)
        self.assertEqual(self.limpiar(), 0)
        self.assertEqual(self.sis.ordenes[antes:], [])
        self.assertEqual(self.salida, "")

    def test_de_dia_o_con_hermes_ocupado_espera(self):
        self.pendiente()
        self.assertEqual(self.limpiar(hora=14), 0)
        self.assertIn("no es de noche", self.salida)
        self.sis.poner(self.carpeta + "/" + pa.ACTIVIDAD, json.dumps({"reenviando": 1, "ultima": time.time()}))
        self.assertEqual(self.limpiar(), 0)
        self.assertIn("peticiones con Hermes", self.salida)
        self.sis.borrar(self.carpeta + "/" + pa.ACTIVIDAD)
        os.utime(self.sis.ruta(self.base), None)  # Hermes acaba de escribir
        self.assertEqual(self.limpiar(), 0)
        self.assertIn("ha escrito en su base", self.salida)
        self.assertEqual(self.paradas(), [])
        self.assertTrue(self.sis.existe(self.carpeta + "/" + pa.BORRADO_PENDIENTE))
        self.assertEqual(self.estado(), {}, "esperar no es un intento")

    def test_de_noche_y_tranquilo_para_compacta_arranca_y_quita_la_marca(self):
        self.pendiente()
        self.assertEqual(self.limpiar(), 0, self.salida)
        self.assertEqual(self.falso.compactados, ["hermes sessions optimize"])
        self.assertIn("HERMES_HOME=/root/.hermes", self.falso.entornos)
        self.assertEqual(self.falso.topes, [str(mt.PLAZO_COMPACTAR)])
        self.assertEqual(len(self.paradas()), 1)
        self.assertIn("hermes-gateway", self.falso.activos, "arrancado otra vez")
        self.assertFalse(self.sis.existe(self.carpeta + "/" + pa.BORRADO_PENDIENTE))
        estado = self.estado()
        self.assertEqual((estado["fallos_seguidos"], estado["fallo"], estado["metodo"]),
                         (0, None, "hermes sessions optimize"))
        self.assertIsInstance(estado["ultimo_borrado"], int)
        self.assertEqual(self.sis.modo(self.carpeta + "/" + pa.MANTENIMIENTO), 0o644, "la pasarela lo lee")
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("borrado de verdad: nada pendiente; el último,", self.salida)

    def test_si_ese_hermes_no_sabe_optimizar_lo_hace_sqlite(self):
        self.falso.sabe_optimizar = False
        self.pendiente()
        self.assertEqual(self.limpiar(), 0, self.salida)
        self.assertEqual(self.falso.compactados, ["sqlite /root/.hermes/state.db"])
        self.assertEqual(self.estado()["metodo"], "sqlite (optimize de FTS5 y VACUUM)")
        self.assertFalse(self.sis.existe(self.carpeta + "/" + pa.BORRADO_PENDIENTE))

    def test_como_el_usuario_de_hermes_si_no_es_root(self):
        from hehermes_servidor.manifiesto import Manifiesto
        man = Manifiesto.leer(self.sis)
        man.datos["mantenimiento"].update(usuario="hermes", casa="/home/hermes/.hermes")
        man.guardar(self.sis)
        self.sis.poner("/home/hermes/.hermes/state.db", b"x")
        viejo = time.time() - 3600
        os.utime(self.sis.ruta("/home/hermes/.hermes/state.db"), (viejo, viejo))
        self.pendiente()
        self.assertEqual(self.limpiar(), 0, self.salida)
        self.assertIn("hermes", self.falso.como)

    def test_si_falla_arranca_hermes_igual_lo_apunta_y_no_lo_repite_esa_noche(self):
        self.falso.optimiza_bien = False
        self.pendiente()
        ahora = time.time()
        self.assertEqual(self.limpiar(ahora=ahora), 1)
        self.assertIn("hermes-gateway", self.falso.activos, "arrancado pase lo que pase")
        self.assertTrue(self.sis.existe(self.carpeta + "/" + pa.BORRADO_PENDIENTE))
        self.assertEqual(self.estado()["fallos_seguidos"], 1)
        self.assertIn("database is locked", self.estado()["fallo"])
        paradas = len(self.paradas())
        # La misma noche, un cuarto de hora después: nada.
        self.assertEqual(self.limpiar(ahora=ahora + 900), 0)
        self.assertIn("ya lo intenté", self.salida)
        self.assertEqual(len(self.paradas()), paradas)
        # Tres noches seguidas fallando, y a la cuarta ya no lo intenta; comprobar lo dice.
        self.assertEqual(self.limpiar(ahora=ahora + 86400), 1)
        self.assertEqual(self.limpiar(ahora=ahora + 2 * 86400), 1)
        self.assertEqual(self.limpiar(ahora=ahora + 3 * 86400), 0)
        self.assertIn("ya no lo intento solo", self.salida)
        self.assertEqual(len(self.paradas()), paradas + 2)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   borrado de verdad: pendiente desde", self.salida)
        self.assertIn("hermes sessions optimize", self.salida)

    def test_si_se_pasa_del_tope_lo_corta(self):
        self.falso.se_pasa = True
        self.pendiente()
        self.assertEqual(self.limpiar(), 1)
        self.assertIn("ha pasado de 900 s", self.estado()["fallo"])
        self.assertIn("hermes-gateway", self.falso.activos)

    def test_si_hermes_no_vuelve_a_contestar_lo_dice(self):
        self.pendiente()
        puerto = 8642
        with mock.patch.object(self.sis, "http_get", return_value=(None, b"")):
            self.assertEqual(self.limpiar(), 1)
        self.assertIn("no contesta en /health", self.estado()["fallo"])
        self.assertTrue(self.sis.existe(self.carpeta + "/" + pa.BORRADO_PENDIENTE), "no se da por hecho")
        self.assertEqual(puerto, 8642)

    def test_si_no_puede_parar_hermes_no_lo_intenta_y_comprobar_lo_dice(self):
        from hehermes_servidor.manifiesto import Manifiesto
        man = Manifiesto.leer(self.sis)
        man.datos["mantenimiento"].update(unidad_hermes=None, gestor_hermes=None, origen="el proceso 4242")
        man.guardar(self.sis)
        self.pendiente()
        self.assertEqual(self.limpiar(), 0)
        self.assertEqual(self.paradas(), [])
        self.assertIn("no sé pararlo", self.estado()["no_puede"])
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   borrado de verdad: lo borrado desde", self.salida)
        self.assertIn("HERMES_HOME=/root/.hermes hermes sessions optimize", self.salida)

    def test_la_orden_de_la_unidad(self):
        self.assertEqual(self.orden("borrado-seguro"), 0, self.salida)


class SinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def setUp(self):
        self.sis, self.falso = sf.servidor(usuario="hermes")
        self.addCleanup(self.sis.limpiar)
        self.sis.carpeta("/run/user/1000", 0o700)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.carpeta = "/home/hermes/.local/state/hehermes-pasarela"

    def test_la_carpeta_es_suya_y_no_puede_parar_un_hermes_del_sistema(self):
        self.assertEqual(self.sis.modo(self.carpeta), 0o700)
        self.assertIn("hehermes-borrado.timer", self.falso.activos_usuario)
        self.assertIn("carpeta = %s\n" % self.carpeta,
                      self.sis.leer_texto("/home/hermes/.config/hehermes-pasarela/pasarela.ini"))
        self.pendiente()
        self.assertEqual(self.limpiar(), 0)
        self.assertIn("sin root no la puedo parar", self.salida)
        self.assertEqual(self.paradas(), [])
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("sin root no la puedo parar", self.salida)
        # Y desinstalar se la lleva.
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe(self.carpeta))


if __name__ == "__main__":
    unittest.main()
