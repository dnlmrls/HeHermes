"""Desinstalar la VPN IKEv2 que dejaba el instalador hasta la 0.5.1: el servidor vuelve a como estaba, según el
manifiesto, y lo que alguien cambió se queda y se dice.

La VPN ya no se instala (`vpn_antigua` la monta como la dejaba); lo de la pasarela, en `test_modo_tls`, y quitar la VPN
dejando la pasarela, en `test_dos_modos`.
"""

import apoyo  # noqa: F401

import unittest

import servidor_falso as sf
import vpn_antigua
from hehermes_servidor import piezas as p
from hehermes_servidor.desinstalar import desinstalar, resumen
from hehermes_servidor.manifiesto import RUTA_MANIFIESTO, Manifiesto


class Base(unittest.TestCase):
    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)
        self.salida = []

    def vpn(self, **opciones):
        vpn_antigua.montar(self.sis, self.falso, **opciones)

    def desinstalar(self, **opciones):
        return desinstalar(self.sis, Manifiesto.leer(self.sis), salida=self.salida.append, **opciones)


class Desinstalar(Base):
    def test_el_servidor_queda_como_estaba(self):
        self.montar(vpn_antigua.servidor())
        antes = self.sis.foto()
        activos, reglas = set(self.falso.activos), list(self.falso.reglas_ufw)
        self.vpn()
        self.assertNotEqual(self.sis.foto(), antes)
        self.assertIn("hh-ipsec", self.falso.enlaces_ip)
        quedan = self.desinstalar()
        self.assertEqual(quedan, [])
        despues = self.sis.foto()
        self.assertEqual(sorted(set(despues) ^ set(antes)), [], "ni un fichero ni una carpeta de más o de menos")
        self.assertEqual(despues, antes)
        self.assertEqual(self.falso.reglas_ufw, reglas)
        self.assertEqual(self.falso.activos, activos)
        self.assertNotIn("hh-ipsec", self.falso.enlaces_ip)
        self.assertIn(["systemctl", "reload", "nginx"], self.sis.ordenes)
        self.assertEqual(self.falso.reinicios, [])

    def test_corta_las_sesiones_de_cada_iphone(self):
        self.montar(vpn_antigua.servidor())
        self.vpn(iphones=("mi-iphone", "otro"))
        self.desinstalar()
        bajas = [o[2] for o in self.sis.ordenes if o[:2] == [p.DISPOSITIVO, "baja"]]
        self.assertEqual(sorted(bajas), ["mi-iphone", "otro"])
        # Antes de quitar el propio script.
        indice = max(i for i, o in enumerate(self.sis.ordenes) if o[:2] == [p.DISPOSITIVO, "baja"])
        self.assertTrue(all(o[:2] != ["systemctl", "disable"] for o in self.sis.ordenes[:indice]))
        self.assertFalse(self.sis.existe(p.REGISTRO))
        self.assertFalse(self.sis.existe(self.falso.swanctl + "/conf.d/hehermes-otro.conf"))

    def test_lo_cambiado_a_mano_se_queda_y_se_dice(self):
        self.montar(vpn_antigua.servidor())
        self.vpn()
        self.sis.poner(p.DROP_IN_NGINX, "[Unit]\n# de Daniel\n")
        quedan = self.desinstalar()
        self.assertTrue(self.sis.existe(p.DROP_IN_NGINX))
        self.assertEqual([q for q in quedan if p.DROP_IN_NGINX in q], [p.DROP_IN_NGINX + ": alguien lo ha cambiado"])
        self.assertFalse(self.sis.existe(p.SITIO))
        self.assertFalse(self.sis.existe(RUTA_MANIFIESTO))

    def test_lo_reemplazado_vuelve(self):
        self.montar(vpn_antigua.servidor())
        self.sis.poner(p.DROP_IN_NGINX, "[Unit]\nAfter=otra.service\n")
        antes = self.sis.foto()
        self.vpn(reemplazar={p.DROP_IN_NGINX})
        self.desinstalar()
        self.assertEqual(self.sis.leer(p.DROP_IN_NGINX), b"[Unit]\nAfter=otra.service\n")
        self.assertEqual(self.sis.foto(), antes)

    def test_el_default_de_nginx_vuelve(self):
        self.montar(sf.servidor())
        self.vpn()
        self.assertFalse(self.sis.existe(p.DEFAULT_NGINX))
        self.desinstalar()
        self.assertEqual(self.sis.enlace(p.DEFAULT_NGINX), "/etc/nginx/sites-available/default")

    def test_los_paquetes_solo_con_la_opcion_y_solo_los_suyos(self):
        self.montar(sf.servidor())
        self.falso.instalar_paquete("nginx")
        self.vpn()
        self.desinstalar()
        self.assertFalse([o for o in self.sis.ordenes if "purge" in o or "remove" in o])
        self.montar(sf.servidor())
        self.falso.instalar_paquete("nginx")
        self.vpn()
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
        self.montar(vpn_antigua.servidor())
        self.vpn(avisos=True)
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
        self.montar(vpn_antigua.servidor())
        self.vpn()
        texto = resumen(self.sis, Manifiesto.leer(self.sis))
        for trozo in (p.SITIO, p.UNIDAD_XFRM, "mi-iphone", "ufw allow proto udp", "hehermes-xfrm.service"):
            self.assertIn(trozo, texto)
        self.assertNotIn(sf.CLAVE, texto)


class FamiliaRedHat(Base):
    def test_desinstalar_lo_deja_como_estaba(self):
        """firewalld (en la de ahora y en la permanente), la etiqueta de SELinux del puerto de Hermes y strongSwan,
        que la VPN arrancaba ella."""
        self.montar(sf.servidor(("rocky", "9.4")))
        for paquete in ("epel-release",) + vpn_antigua.PAQUETES_RPM:
            self.falso.instalar_paquete(paquete)
        antes = self.sis.foto()
        fw_ahora, fw_permanente = set(self.falso.fw_ahora), set(self.falso.fw_permanente)
        self.vpn()
        self.assertIn("8642", self.falso.etiquetas)
        self.assertIn("strongswan", self.falso.activos)
        self.assertTrue(self.sis.existe(p.SITIO_CONF_D))
        self.assertEqual(self.desinstalar(), [])
        self.assertEqual(self.sis.foto(), antes)
        self.assertEqual((self.falso.fw_ahora, self.falso.fw_permanente), (fw_ahora, fw_permanente))
        self.assertEqual(self.falso.etiquetas, {})
        self.assertNotIn("strongswan", self.falso.activos)

    def test_los_paquetes_que_puso_con_dnf(self):
        self.montar(sf.servidor(("rocky", "9.4")))
        self.falso.instalar_paquete("epel-release")
        self.vpn()
        self.assertEqual(self.desinstalar(quitar_paquetes=True), [])
        self.assertIn(["dnf", "remove", "-y", "-q", "strongswan", "qrencode", "nginx", "policycoreutils-python-utils"],
                      self.sis.ordenes)


if __name__ == "__main__":
    unittest.main()
