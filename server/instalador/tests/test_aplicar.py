"""Aplicar el plan de la pasarela, paso a paso, sobre el servidor falso: repetir (0 cambios), reparar, recargar lo que
cambia y deshacer lo que falla. Lo de punta a punta, con sus órdenes, en `test_modo_tls`."""

import apoyo

import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import manifiesto as m
from hehermes_servidor import piezas as p
from hehermes_servidor import porchat
from hehermes_servidor.aplicar import Parada
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import aplicar_tls, calcular_plan_tls, comprobar_tls, detectar_tls
from hehermes_servidor.plan import Opciones

ORIGEN = str(apoyo.RAIZ)
INI = "/etc/hehermes-pasarela/pasarela.ini"
UNIDAD = "/etc/systemd/system/hehermes-pasarela.service"


class Base(unittest.TestCase):
    def setUp(self):
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        azar.start()
        self.addCleanup(azar.stop)

    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)
        self.salida = []

    def plan(self, origen=ORIGEN, **opciones):
        op = Opciones(**opciones)
        self.man = Manifiesto.leer(self.sis)
        det = detectar_tls(self.sis, self.man, amb.de_root(), direccion=op.direccion, hermes_home=op.hermes_home)
        return calcular_plan_tls(self.sis, det, self.man, op, origen)

    def instalar(self, **opciones):
        plan = self.plan(**opciones)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        aplicar_tls(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        return plan

    def ordenes_que_cambian(self, desde=0):
        leen = ("is-active", "is-enabled", "show", "is-system-running")
        return [o for o in self.sis.ordenes[desde:]
                if not (o[0] == "systemctl" and o[1] in leen) and o[:1] not in (["dpkg"], ["dpkg-query"], ["ps"],
                                                                                  ["ss"], ["ip"], ["id"])
                and o[:2] not in (["ufw", "status"], ["ufw", "show"])
                and not (o[0].endswith("/bin/python") and o[1:4] == ["-I", "-B", "-c"])
                and o[:3] != ["python3", "-I", "-c"]]


class Instalar(Base):
    def test_una_instalacion_limpia(self):
        self.montar(sf.servidor())
        self.instalar()
        man = Manifiesto.leer(self.sis)
        for ruta in (INI, UNIDAD, p.UNIDAD_PASARELA_CLAVE_PATH, p.UNIDAD_PASARELA_CLAVE_SERVICE, p.UNIDAD_CORTAFUEGOS,
                     p.DISPOSITIVO, p.ORDEN, p.PREFIJO + "/hehermes_servidor/modo_tls.py"):
            with self.subTest(ruta=ruta):
                self.assertTrue(m.sin_tocar(self.sis, man, ruta))
        self.assertEqual(man.ficheros["/etc/hehermes-pasarela/clave-hermes"]["tipo"], "gestionado")
        self.assertEqual(self.sis.modo(p.DISPOSITIVO), 0o750)
        self.assertEqual(self.sis.enlace(p.ORDEN), p.PREFIJO + "/hehermes-servidor")
        self.assertEqual(man.unidades, ["hehermes-pasarela.service", "hehermes-pasarela-clave.path",
                                        "hehermes-cortafuegos.service"])
        self.assertEqual((man.modos, man.paquetes, man.reglas), (["tls"], [], []))
        self.assertEqual(self.falso.reinicios, [])
        self.assertNotIn(sf.CLAVE, "\n".join(self.salida))

    def test_repetir_da_cero_cambios_y_no_ejecuta_nada_que_cambie(self):
        """Con 0 cambios, `instalar` ni aplica (`cli._instalar`): el plan de repetir no puede cambiar nada."""
        self.montar(sf.servidor())
        self.instalar()
        desde = len(self.sis.ordenes)
        foto = self.sis.foto()
        plan = self.plan()
        self.assertEqual(plan.cambios, [])
        self.assertEqual(self.ordenes_que_cambian(desde), [])
        self.assertEqual(self.sis.foto(), foto)

    def test_repetir_repara_lo_que_falta(self):
        self.montar(sf.servidor())
        self.instalar()
        self.sis.borrar(INI)
        self.sis.borrar(p.UNIDAD_PASARELA_CLAVE_PATH)
        self.falso._parar("hehermes-pasarela")
        plan = self.plan()
        self.assertEqual(sorted(a.objeto for a in plan.cambios),
                         sorted([INI, p.UNIDAD_PASARELA_CLAVE_PATH, "hehermes-pasarela.service",
                                 "hehermes-pasarela-clave.path"]))
        aplicar_tls(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        self.assertTrue(self.sis.existe(INI))
        self.assertIn("hehermes-pasarela", self.falso.activos)
        self.assertEqual(self.plan().cambios, [])

    def test_lo_instalado_en_opt_basta_para_repetir_y_reparar(self):
        # `sudo hehermes-servidor instalar` después, sin la carpeta temporal: su origen es /opt/hehermes-servidor.
        self.montar(sf.servidor())
        self.instalar()
        origen = self.sis.ruta(p.PREFIJO)
        plan = self.plan(origen=origen)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        self.assertEqual(plan.cambios, [])
        self.sis.borrar(p.DISPOSITIVO)
        self.assertEqual([a.objeto for a in self.plan(origen=origen).cambios], [p.DISPOSITIVO])

    def test_una_version_nueva_de_la_unidad_reinicia_la_pasarela(self):
        self.montar(sf.servidor())
        self.instalar()
        # Como si la versión de antes hubiera dejado otra unidad (sin tocar a mano: el manifiesto lo sabe).
        vieja = self.sis.leer_texto(UNIDAD) + "# versión anterior\n"
        self.sis.poner(UNIDAD, vieja)
        man = Manifiesto.leer(self.sis)
        man.apuntar_fichero(UNIDAD, vieja.encode())
        man.guardar(self.sis)
        desde = len(self.sis.ordenes)
        plan = self.plan()
        self.assertEqual([(a.objeto, a.estado) for a in plan.cambios],
                         [(UNIDAD, m.CAMBIA), ("hehermes-pasarela.service", m.CAMBIA)])
        aplicar_tls(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        self.assertIn(["systemctl", "restart", "hehermes-pasarela.service"], self.sis.ordenes[desde:])

    def test_reemplazar_guarda_una_copia(self):
        sis, falso = sf.servidor()
        sis.poner(p.UNIDAD_PASARELA_CLAVE_PATH, "[Unit]\nDescription=otra\n")
        self.montar((sis, falso))
        self.instalar(reemplazar={p.UNIDAD_PASARELA_CLAVE_PATH})
        copia = Manifiesto.leer(sis).ficheros[p.UNIDAD_PASARELA_CLAVE_PATH]["copia"]
        self.assertEqual(sis.leer(copia["ruta"]), b"[Unit]\nDescription=otra\n")
        self.assertEqual(sis.leer(p.UNIDAD_PASARELA_CLAVE_PATH),
                         p.unidad_pasarela_clave_path("/root/.hermes/.env").encode())


class Deshacer(Base):
    def test_si_la_pasarela_no_arranca_sus_ficheros_vuelven(self):
        self.montar(sf.servidor())
        self.sis.responder["systemctl enable --now hehermes-pasarela.service"] = apoyo.mal("no arranca")
        with self.assertRaises(Parada) as parada:
            self.instalar()
        self.assertIn("no arranca", str(parada.exception))
        for ruta in (INI, UNIDAD, "/etc/hehermes-pasarela/tokens.json"):
            with self.subTest(ruta=ruta):
                self.assertFalse(self.sis.existe(ruta))
                self.assertNotIn(ruta, Manifiesto.leer(self.sis).ficheros)
        # Lo de antes se queda hecho y apuntado: repetir sigue desde ahí.
        self.assertTrue(m.sin_tocar(self.sis, Manifiesto.leer(self.sis), p.DISPOSITIVO))

    def test_si_falla_useradd_no_sigue(self):
        self.montar(sf.servidor())
        self.sis.responder["useradd"] = apoyo.mal("useradd: sin sitio")
        with self.assertRaises(Parada) as parada:
            self.instalar()
        self.assertIn("sin sitio", str(parada.exception))
        self.assertFalse(self.sis.existe(INI))


class Comprobar(Base):
    def test_todo_bien_tras_instalar(self):
        self.montar(sf.servidor())
        self.instalar()
        resultados = comprobar_tls(self.sis, Manifiesto.leer(self.sis), amb.de_root())
        self.assertTrue(all(bien for bien, _ in resultados), resultados)
        self.assertTrue(any("el 404 de siempre" in texto for _, texto in resultados))

    def test_la_pasarela_parada_es_un_fallo(self):
        self.montar(sf.servidor())
        self.instalar()
        self.falso._parar("hehermes-pasarela")
        resultados = comprobar_tls(self.sis, Manifiesto.leer(self.sis), amb.de_root())
        self.assertTrue(any(not bien and "parada" in texto for bien, texto in resultados), resultados)


if __name__ == "__main__":
    unittest.main()
