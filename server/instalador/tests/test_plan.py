"""El plan de la pasarela: cada fichero, servicio y regla, marcado «ya está», «nuevo» o «cambia», calculado sin tocar
nada. Desde la 0.6.0 es el único plan: nada de la VPN, ni siquiera en un servidor que tenga la de antes."""

import apoyo

import unittest
from unittest import mock

import servidor_falso as sf
import vpn_antigua
from hehermes_servidor import ambito as amb
from hehermes_servidor import manifiesto as m
from hehermes_servidor import piezas as p
from hehermes_servidor import porchat
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
from hehermes_servidor.plan import Opciones, pintar

ORIGEN = str(apoyo.RAIZ)
INI = "/etc/hehermes-pasarela/pasarela.ini"


class Base(unittest.TestCase):
    def setUp(self):
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        azar.start()
        self.addCleanup(azar.stop)

    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)

    def plan(self, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        op = Opciones(**opciones)
        man = Manifiesto.leer(self.sis)
        det = detectar_tls(self.sis, man, amb.de_root(), direccion=op.direccion, hermes_home=op.hermes_home)
        return calcular_plan_tls(self.sis, det, man, op, ORIGEN)

    def estado(self, plan, objeto):
        return next(a.estado for a in plan.acciones if a.objeto == objeto)


class Limpio(Base):
    def test_todo_es_nuevo_y_nada_es_de_la_vpn(self):
        self.montar(sf.servidor())
        antes = self.sis.foto()
        plan = self.plan()
        self.assertEqual(self.sis.foto(), antes)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        self.assertEqual([a for a in plan.acciones if a.tipo == "paquete"], [])
        for objeto in (INI, "/etc/hehermes-pasarela/tokens.json", "/etc/hehermes-pasarela/clave-hermes",
                       "/etc/systemd/system/hehermes-pasarela.service", p.UNIDAD_PASARELA_CLAVE_PATH,
                       p.UNIDAD_PASARELA_CLAVE_SERVICE, p.UNIDAD_CORTAFUEGOS, p.DISPOSITIVO, p.ORDEN,
                       p.USUARIO_PASARELA, "hehermes-pasarela.service", "hehermes-pasarela-clave.path",
                       "hehermes-cortafuegos.service", "/etc/hehermes-pasarela/cert.pem", "mi-iphone"):
            with self.subTest(objeto=objeto):
                self.assertEqual(self.estado(plan, objeto), m.NUEVO)
        objetos = {a.objeto for a in plan.acciones}
        self.assertFalse(objetos & set(vpn_antigua.FICHEROS + vpn_antigua.UNIDADES[:1] + ("hehermes-clave.path",)))
        # Sin ufw no hay reglas que poner.
        self.assertFalse([a for a in plan.acciones if a.tipo == "regla"])
        texto = pintar(plan)
        for de_la_vpn in ("IKEv2", "strongSwan", "nginx", "UDP 500", "hh-ipsec"):
            self.assertNotIn(de_la_vpn, texto)

    def test_la_clave_de_hermes_va_aparte_y_no_se_imprime(self):
        self.montar(sf.servidor(puerto=9100))
        plan = self.plan()
        ini = next(a for a in plan.acciones if a.objeto == INI)
        self.assertIn(b"[hermes]\npuerto = 9100\n", ini.datos)
        clave = next(a for a in plan.acciones if a.objeto == "/etc/hehermes-pasarela/clave-hermes")
        self.assertEqual((clave.modo, clave.tipo), (0o600, "gestionado"))
        self.assertNotIn(sf.CLAVE, pintar(plan), "la clave de Hermes no se imprime nunca")

    def test_ufw_apagado_pone_la_regla_sin_encenderlo(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("ufw")
        falso.ufw = "inactivo"
        self.montar((sis, falso))
        plan = self.plan()
        reglas = [a for a in plan.acciones if a.tipo == "regla"]
        self.assertEqual([(a.objeto, a.estado) for a in reglas], [("TCP 61234 (la pasarela)", m.NUEVO)])
        self.assertIn("no lo enciendo", pintar(plan))

    def test_una_regla_que_ya_estaba_a_mano_no_se_repite_ni_es_mia(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("ufw")
        falso.ufw = "activo"
        falso.reglas_ufw = ["ufw allow 61234/tcp"]
        self.montar((sis, falso))
        reglas = [a for a in self.plan().acciones if a.tipo == "regla"]
        self.assertEqual([a.estado for a in reglas], [m.AJENO_IGUAL])

    def test_sin_iphone_no_hay_alta(self):
        self.montar(sf.servidor())
        plan = self.plan(iphone=None)
        self.assertFalse([a for a in plan.acciones if a.tipo == "dispositivo"])
        self.assertIn("--iphone", pintar(plan))

    def test_un_nombre_de_iphone_que_no_vale(self):
        self.montar(sf.servidor())
        for malo in ("Mi iPhone", "-x", "a" * 40, "x;rm"):
            with self.subTest(nombre=malo):
                plan = self.plan(iphone=malo)
                self.assertFalse(plan.puede_seguir)
                self.assertTrue(any("nombre del iPhone" in b for b in plan.bloqueos))

    def test_los_avisos_no_se_instalan_pero_se_sirven_si_estan(self):
        self.montar(sf.servidor())
        self.assertIn("el relé central todavía no existe", pintar(self.plan()))
        self.sis.poner(p.SECRETO_VIGIA, "s" * 43 + "\n", modo=0o600)
        self.assertIn("el vigía ya está: la pasarela le pasa /avisos/", pintar(self.plan()))


class NoPisar(Base):
    def test_un_fichero_ajeno_para_y_dice_cual(self):
        sis, falso = sf.servidor()
        sis.poner(p.UNIDAD_PASARELA_CLAVE_PATH, "[Unit]\nDescription=otra\n")
        self.montar((sis, falso))
        plan = self.plan()
        self.assertFalse(plan.puede_seguir)
        self.assertTrue(any(p.UNIDAD_PASARELA_CLAVE_PATH in b and "--reemplazar" in b for b in plan.bloqueos),
                        plan.bloqueos)
        plan = self.plan(reemplazar={p.UNIDAD_PASARELA_CLAVE_PATH})
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        self.assertEqual(self.estado(plan, p.UNIDAD_PASARELA_CLAVE_PATH), m.REEMPLAZA)

    def test_uno_mio_cambiado_a_mano_para(self):
        sis, falso = sf.servidor()
        man = Manifiesto()
        man.apuntar_fichero(p.UNIDAD_PASARELA_CLAVE_SERVICE, p.unidad_pasarela_clave_service().encode())
        man.guardar(sis)
        sis.poner(p.UNIDAD_PASARELA_CLAVE_SERVICE, p.unidad_pasarela_clave_service() + "# de Daniel\n")
        self.montar((sis, falso))
        plan = self.plan()
        self.assertEqual(self.estado(plan, p.UNIDAD_PASARELA_CLAVE_SERVICE), m.MODIFICADO)
        self.assertTrue(any(p.UNIDAD_PASARELA_CLAVE_SERVICE in b and "cambiado" in b for b in plan.bloqueos))

    def test_con_la_vpn_de_antes_no_se_planea_nada_suyo(self):
        """Ni se repara ni se toca: lo suyo, cambiado o borrado, no sale en el plan."""
        self.montar(vpn_antigua.servidor())
        vpn_antigua.montar(self.sis, self.falso)
        self.sis.borrar(p.UNIDAD_XFRM)
        self.sis.poner(p.DROP_IN_NGINX, "[Unit]\n# cambiado\n")
        plan = self.plan()
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        objetos = {a.objeto for a in plan.acciones}
        self.assertFalse(objetos & set(vpn_antigua.FICHEROS), objetos & set(vpn_antigua.FICHEROS))
        self.assertFalse(objetos & {"hehermes-xfrm.service", "hehermes-clave.path", "strongswan.service"})
        self.assertIn("desinstalar --modo vpn", pintar(plan))


if __name__ == "__main__":
    unittest.main()
