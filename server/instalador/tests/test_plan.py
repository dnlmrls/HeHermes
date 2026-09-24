"""El plan: cada paquete, fichero, servicio y regla, marcado «ya está», «nuevo» o «cambia», calculado sin tocar nada."""

import apoyo

import unittest

import servidor_falso as sf
from hehermes_servidor import manifiesto as m
from hehermes_servidor import piezas as p
from hehermes_servidor.deteccion import detectar
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.plan import Opciones, calcular_plan, pintar

ORIGEN = str(apoyo.RAIZ)


class Base(unittest.TestCase):
    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)

    def plan(self, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        op = Opciones(**opciones)
        man = Manifiesto.leer(self.sis)
        det = detectar(self.sis, man, direccion=op.direccion, hermes_home=op.hermes_home)
        return calcular_plan(self.sis, det, man, op, ORIGEN)

    def estado(self, plan, objeto):
        return next(a.estado for a in plan.acciones if a.objeto == objeto)


class Limpio(Base):
    def test_todo_es_nuevo(self):
        self.montar(sf.servidor())
        antes = self.sis.foto()
        plan = self.plan()
        self.assertEqual(self.sis.foto(), antes)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        paquetes = [a.objeto for a in plan.acciones if a.tipo == "paquete"]
        self.assertEqual(paquetes, ["charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins",
                                    "qrencode", "nginx"])
        for objeto in (p.SERVIDOR_INI, p.DISPOSITIVO, p.UNIDAD_XFRM, p.SCRIPT_XFRM, p.SITIO, p.SITIO_ENLACE,
                       p.DROP_IN_NGINX, p.BEARER, p.UNIDAD_CLAVE_PATH, p.UNIDAD_CLAVE_SERVICE, p.ORDEN,
                       "hehermes-xfrm.service", "hehermes-clave.path", "mi-iphone"):
            with self.subTest(objeto=objeto):
                self.assertEqual(self.estado(plan, objeto), m.NUEVO)
        # Sin ufw no hay reglas que poner, y el sitio default se apaga porque nginx lo instala él.
        self.assertFalse([a for a in plan.acciones if a.tipo == "regla"])
        self.assertEqual(self.estado(plan, p.DEFAULT_NGINX), m.NUEVO)
        self.assertGreater(len(plan.cambios), 20)

    def test_el_sitio_lleva_el_puerto_de_hermes_y_la_clave_va_aparte(self):
        self.montar(sf.servidor(puerto=9100))
        plan = self.plan()
        sitio = next(a for a in plan.acciones if a.objeto == p.SITIO)
        self.assertIn(b"proxy_pass http://127.0.0.1:9100;", sitio.datos)
        bearer = next(a for a in plan.acciones if a.objeto == p.BEARER)
        self.assertEqual(bearer.modo, 0o600)
        self.assertEqual(bearer.tipo, "gestionado")
        texto = pintar(plan)
        self.assertNotIn(sf.CLAVE, texto, "la clave de Hermes no se imprime nunca")

    def test_ufw_apagado_pone_las_reglas_sin_encenderlo(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("ufw")
        falso.ufw = "inactivo"
        self.montar((sis, falso))
        plan = self.plan()
        reglas = [a for a in plan.acciones if a.tipo == "regla"]
        self.assertEqual([a.estado for a in reglas], [m.NUEVO, m.NUEVO])
        self.assertIn("no lo enciendo", pintar(plan))

    def test_una_regla_que_ya_estaba_a_mano_no_se_repite_ni_es_mia(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("ufw")
        falso.ufw = "activo"
        falso.reglas_ufw = ["ufw allow 500,4500/udp"]
        self.montar((sis, falso))
        reglas = [a for a in self.plan().acciones if a.tipo == "regla"]
        self.assertEqual([a.estado for a in reglas], [m.AJENO_IGUAL, m.NUEVO])

    def test_nginx_de_otro_no_pierde_su_default(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        self.montar((sis, falso))
        plan = self.plan()
        self.assertFalse([a for a in plan.acciones if a.objeto == p.DEFAULT_NGINX])
        self.assertEqual(self.estado(plan, "nginx"), m.YA_ESTA, "el paquete ya estaba")

    def test_nginx_con_conf_d(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        sis.poner("/etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
        self.montar((sis, falso))
        plan = self.plan()
        objetos = [a.objeto for a in plan.acciones]
        self.assertIn(p.SITIO_CONF_D, objetos)
        self.assertNotIn(p.SITIO, objetos)
        self.assertNotIn(p.SITIO_ENLACE, objetos)

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

    def test_los_avisos_solo_si_se_piden(self):
        self.montar(sf.servidor())
        self.assertFalse([a for a in self.plan().acciones if a.tipo == "avisos"])
        self.assertIn("relé central", pintar(self.plan()))
        self.assertEqual([a.estado for a in self.plan(avisos=True).acciones if a.tipo == "avisos"], [m.NUEVO])


class NoPisar(Base):
    def test_un_fichero_ajeno_para_y_dice_cual(self):
        sis, falso = sf.servidor()
        sis.poner(p.DROP_IN_NGINX, "[Unit]\nAfter=otra.service\n")
        self.montar((sis, falso))
        plan = self.plan()
        self.assertFalse(plan.puede_seguir)
        self.assertTrue(any(p.DROP_IN_NGINX in b and "--reemplazar" in b for b in plan.bloqueos), plan.bloqueos)
        plan = self.plan(reemplazar={p.DROP_IN_NGINX})
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        self.assertEqual(self.estado(plan, p.DROP_IN_NGINX), m.REEMPLAZA)

    def test_uno_mio_cambiado_a_mano_para(self):
        sis, falso = sf.servidor()
        man = Manifiesto()
        man.apuntar_fichero(p.UNIDAD_XFRM, p.unidad_xfrm().encode())
        man.guardar(sis)
        sis.poner(p.UNIDAD_XFRM, p.unidad_xfrm() + "# de Daniel\n")
        self.montar((sis, falso))
        plan = self.plan()
        self.assertEqual(self.estado(plan, p.UNIDAD_XFRM), m.MODIFICADO)
        self.assertTrue(any(p.UNIDAD_XFRM in b and "cambiado" in b for b in plan.bloqueos))

    def test_strongswan_de_otro_parado(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("charon-systemd")
        falso.activos.discard("strongswan")
        self.montar((sis, falso))
        self.assertTrue(any("strongSwan está instalado pero parado" in b for b in self.plan().bloqueos))


class ElDeDaniel(Base):
    def test_se_pinta_entero_y_no_sigue(self):
        self.montar(sf.servidor_de_daniel())
        antes = self.sis.foto()
        plan = self.plan()
        self.assertEqual(self.sis.foto(), antes)
        self.assertFalse(plan.puede_seguir)
        self.assertEqual(self.estado(plan, p.SITIO), m.AJENO)
        # El script desplegado es de antes de servidor.ini: no es el del paquete, y no es mío.
        self.assertEqual(self.estado(plan, p.DISPOSITIVO), m.AJENO)
        self.assertEqual(self.estado(plan, "charon-systemd"), m.YA_ESTA)
        reglas = [a for a in plan.acciones if a.tipo == "regla"]
        self.assertEqual([a.estado for a in reglas], [m.AJENO_IGUAL, m.AJENO_IGUAL])
        texto = pintar(plan)
        for trozo in ("instalación hecha a mano", "hh-iphone-poc", "agujero", "sigue abierto", "No sigo"):
            self.assertIn(trozo, texto)
        self.assertNotIn(sf.CLAVE, texto)


if __name__ == "__main__":
    unittest.main()
