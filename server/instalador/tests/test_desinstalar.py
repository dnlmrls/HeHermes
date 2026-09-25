"""Desinstalar: el servidor vuelve a como estaba, según el manifiesto, y lo que alguien cambió se queda y se dice."""

import apoyo

import unittest

import servidor_falso as sf
from hehermes_servidor import piezas as p
from hehermes_servidor.aplicar import aplicar
from hehermes_servidor.desinstalar import desinstalar, resumen
from hehermes_servidor.deteccion import detectar
from hehermes_servidor.manifiesto import RUTA_MANIFIESTO, Manifiesto
from hehermes_servidor.plan import Opciones, calcular_plan

ORIGEN = str(apoyo.RAIZ)


class Base(unittest.TestCase):
    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)
        self.salida = []

    def instalar(self, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        op = Opciones(**opciones)
        man = Manifiesto.leer(self.sis)
        plan = calcular_plan(self.sis, detectar(self.sis, man), man, op, ORIGEN)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        aplicar(self.sis, plan, man, ORIGEN, salida=self.salida.append)

    def desinstalar(self, **opciones):
        return desinstalar(self.sis, Manifiesto.leer(self.sis), salida=self.salida.append, **opciones)


class Desinstalar(Base):
    def servidor_con_todo(self):
        """Un servidor con los paquetes, nginx con su default y ufw activo: lo que había antes no es del instalador."""
        sis, falso = sf.servidor()
        for paquete in ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "qrencode", "nginx",
                        "ufw"):
            falso.instalar_paquete(paquete)
        falso.ufw = "activo"
        falso.reglas_ufw = ["ufw allow 22/tcp"]
        return sis, falso

    def test_el_servidor_queda_como_estaba(self):
        self.montar(self.servidor_con_todo())
        antes = self.sis.foto()
        activos, reglas = set(self.falso.activos), list(self.falso.reglas_ufw)
        self.instalar()
        self.assertNotEqual(self.sis.foto(), antes)
        quedan = self.desinstalar()
        self.assertEqual(quedan, [])
        despues = self.sis.foto()
        self.assertEqual(sorted(set(despues) ^ set(antes)), [], "ni un fichero ni una carpeta de más o de menos")
        self.assertEqual(despues, antes)
        self.assertEqual(self.falso.reglas_ufw, reglas)
        self.assertEqual(self.falso.activos, activos)
        self.assertNotIn("hh-ipsec", self.falso.enlaces_ip)
        self.assertIn(["systemctl", "reload", "nginx"], self.sis.ordenes[-12:])
        self.assertEqual(self.falso.reinicios, [])

    def test_corta_las_sesiones_de_cada_iphone(self):
        self.montar(self.servidor_con_todo())
        self.instalar()
        self.falso._hehermes_dispositivo(["alta", "otro", "--ikev2"], None)
        self.desinstalar()
        bajas = [o[2] for o in self.sis.ordenes if o[:2] == [p.DISPOSITIVO, "baja"]]
        self.assertEqual(sorted(bajas), ["mi-iphone", "otro"])
        # Antes de quitar el propio script.
        indice = max(i for i, o in enumerate(self.sis.ordenes) if o[:2] == [p.DISPOSITIVO, "baja"])
        self.assertTrue(all(o[:2] != ["systemctl", "disable"] for o in self.sis.ordenes[:indice]))

    def test_lo_cambiado_a_mano_se_queda_y_se_dice(self):
        self.montar(self.servidor_con_todo())
        self.instalar()
        self.sis.poner(p.DROP_IN_NGINX, p.drop_in_nginx() + "# de Daniel\n")
        quedan = self.desinstalar()
        self.assertTrue(self.sis.existe(p.DROP_IN_NGINX))
        self.assertEqual([q for q in quedan if p.DROP_IN_NGINX in q], [p.DROP_IN_NGINX + ": alguien lo ha cambiado"])
        self.assertFalse(self.sis.existe(p.SITIO))
        self.assertFalse(self.sis.existe(RUTA_MANIFIESTO))

    def test_lo_reemplazado_vuelve(self):
        sis, falso = self.servidor_con_todo()
        self.montar((sis, falso))
        sis.poner(p.DROP_IN_NGINX, "[Unit]\nAfter=otra.service\n")
        antes = sis.foto()
        self.instalar(reemplazar={p.DROP_IN_NGINX})
        self.desinstalar()
        self.assertEqual(sis.leer(p.DROP_IN_NGINX), b"[Unit]\nAfter=otra.service\n")
        self.assertEqual(sis.foto(), antes)

    def test_el_default_de_nginx_vuelve(self):
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        self.instalar()
        self.assertFalse(sis.existe(p.DEFAULT_NGINX))
        self.desinstalar()
        self.assertEqual(sis.enlace(p.DEFAULT_NGINX), "/etc/nginx/sites-available/default")

    def test_los_paquetes_solo_con_la_opcion_y_solo_los_suyos(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        self.montar((sis, falso))
        self.instalar()
        self.desinstalar()
        self.assertFalse([o for o in sis.ordenes if "purge" in o or "remove" in o])
        self.montar(sf.servidor())
        self.falso.instalar_paquete("nginx")
        self.instalar()
        self.desinstalar(quitar_paquetes=True)
        purga = [o for o in self.sis.ordenes if "purge" in o]
        self.assertEqual(len(purga), 1)
        self.assertEqual(sorted(purga[0][purga[0].index("-q") + 1:]),
                         sorted(["charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins",
                                 "qrencode"]))
        self.assertNotIn("nginx", purga[0])

    def test_sin_manifiesto_no_hay_nada_que_quitar(self):
        self.montar(sf.servidor_de_daniel())
        antes = self.sis.foto()
        self.assertIn("no hay nada mío", resumen(self.sis, Manifiesto.leer(self.sis)))
        self.assertEqual(self.desinstalar(), [])
        self.assertEqual(self.sis.foto(), antes)
        self.assertEqual([o for o in self.sis.ordenes if o[:2] != ["systemctl", "is-active"]], [])

    def test_con_los_avisos_quita_tambien_el_lector_de_ficheros(self):
        self.montar(self.servidor_con_todo())
        self.instalar(avisos=True)
        lector = "/usr/local/libexec/hehermes-leer-media"
        unidades = ["/etc/systemd/system/hehermes-leer-media.socket", "/etc/systemd/system/hehermes-leer-media@.service",
                    "/etc/systemd/system/hehermes-leer-media@.service.d/hermes-home.conf",
                    "/etc/systemd/system/hehermes-leer-media@.service.d"]
        # Como si Hermes viviera fuera de /root/.hermes: el añadido que deja instalar.sh.
        self.sis.poner(unidades[2], "[Service]\n")
        self.assertTrue(all(self.sis.existe(r) for r in [lector] + unidades))
        texto = resumen(self.sis, Manifiesto.leer(self.sis))
        self.assertIn("hehermes-leer-media.socket", texto)
        self.assertIn(lector, texto)
        self.desinstalar()
        self.assertEqual([r for r in [lector] + unidades if self.sis.existe(r)], [])
        self.assertNotIn("hehermes-leer-media.socket", self.falso.activos)
        # El socket del lector, el primero: nada de root de los avisos se queda escuchando mientras se quita lo demás.
        paradas = [o[-1] for o in self.sis.ordenes if o[:3] == ["systemctl", "disable", "--now"]]
        self.assertEqual(paradas[0], "hehermes-leer-media.socket")
        self.assertIn(["systemctl", "stop", "hehermes-leer-media@*.service"], self.sis.ordenes)

    def test_el_resumen_dice_lo_que_quita(self):
        self.montar(self.servidor_con_todo())
        self.instalar()
        texto = resumen(self.sis, Manifiesto.leer(self.sis))
        for trozo in (p.SITIO, p.UNIDAD_XFRM, "mi-iphone", "ufw allow proto udp", "hehermes-xfrm.service"):
            self.assertIn(trozo, texto)
        self.assertNotIn(sf.CLAVE, texto)


if __name__ == "__main__":
    unittest.main()
