"""La detección: lo mira todo antes de preguntar, y sin cambiar nada.

Cada caso de la spec («Qué detecta») sobre un servidor falso. Al final de cada prueba se mira que ninguna orden de las
que ha visto cambie algo. Desde la 0.6.0 solo se detecta lo que necesita la pasarela: de nginx, strongSwan o las
redes del túnel ya no se mira nada, porque la VPN ya no se instala.
"""

import apoyo  # noqa: F401

import unittest

import servidor_falso as sf
import vpn_antigua
from hehermes_servidor import ambito as amb
from hehermes_servidor import deteccion as d
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import detectar_tls

# Lo que puede ejecutar la detección: solo órdenes que leen.
QUE_LEEN = (["dpkg", "--print-architecture"], ["uname", "-m"], ["systemctl", "is-active"],
            ["systemctl", "is-enabled"], ["systemctl", "show"], ["ps"], ["ss"], ["ip", "-4", "-j", "route", "get"],
            ["ip", "link", "show"], ["ufw", "status"], ["ufw", "show", "added"], ["nft", "-j", "list", "ruleset"],
            ["iptables", "-S", "INPUT"], ["iptables", "-V"], ["python3", "-I", "-c"], ["id", "-u"],
            ["firewall-cmd", "--state"], ["firewall-cmd", "--query-port=61234/tcp"])


def detectar(sis, man=None, **opciones):
    return detectar_tls(sis, man or Manifiesto.leer(sis), amb.de_root(), **opciones)


class Base(unittest.TestCase):
    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)
        return self.falso

    def detectar(self, **opciones):
        antes = self.sis.foto()
        det = detectar(self.sis, **opciones)
        self.assertEqual(self.sis.foto(), antes, "la detección no escribe nada")
        for orden in self.sis.ordenes:
            self.assertTrue(any(orden[:len(p)] == p for p in QUE_LEEN) or orden[0].endswith("/venv/bin/python"),
                            "orden que no solo lee: %s" % orden)
        return det

    def bloqueo(self, det, texto):
        self.assertTrue(any(texto in b for b in det.bloqueos), "no hay bloqueo con «%s»: %s" % (texto, det.bloqueos))

    def aviso(self, det, texto):
        self.assertTrue(any(texto in a for a in det.avisos), "no hay aviso con «%s»: %s" % (texto, det.avisos))


class Limpios(Base):
    def test_debian_12_limpio(self):
        self.montar(sf.servidor(("debian", "12")))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertEqual((det.distro["id"], det.distro["version"], det.distro["arquitectura"]), ("debian", "12", "amd64"))
        h = det.hermes
        self.assertEqual((h.usuario, h.env, h.host, h.puerto, h.clave_vale), ("root", "/root/.hermes/.env",
                                                                              "127.0.0.1", 8642, True))
        self.assertEqual(det.direccion, sf.IP_PUBLICA)
        self.assertIsNone(det.ufw)
        self.aviso(det, "cortafuegos propio")
        # La clave va con Bearer a Hermes, y nunca a otro sitio.
        self.assertIn(("http://127.0.0.1:8642/api/sessions?limit=1", {"Authorization": "Bearer " + sf.CLAVE}),
                      self.sis.peticiones_http)
        self.assertNotIn(sf.CLAVE, repr(det.bloqueos) + repr(det.avisos))
        # Nada de la VPN: ni paquetes, ni nginx, ni strongSwan, ni redes.
        for orden in (["dpkg-query"], ["nginx"], ["swanctl"], ["ip", "-j", "addr"], ["ip", "-d", "-j", "link"]):
            self.assertFalse([o for o in self.sis.ordenes if o[:len(orden)] == orden], orden)

    def test_ubuntu_24_04_arm64(self):
        sis, falso = sf.servidor(("ubuntu", "24.04"))
        falso.arquitectura = "arm64"
        self.montar((sis, falso))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertEqual(det.distro["arquitectura"], "arm64")

    def test_todas_las_de_la_decision_4(self):
        for distro in (("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04"),
                       ("ubuntu", "26.04")):
            with self.subTest(distro=distro):
                sis, falso = sf.servidor(distro)
                self.addCleanup(sis.limpiar)
                self.assertEqual(detectar(sis, Manifiesto()).bloqueos, [])


class NoSoportados(Base):
    def test_otra_distribucion_se_para_al_empezar(self):
        for distro in (("debian", "11"), ("ubuntu", "23.10"), ("fedora", "40"), ("ubuntu", "20.04")):
            with self.subTest(distro=distro):
                sis, falso = sf.servidor(distro)
                self.addCleanup(sis.limpiar)
                det = detectar(sis, Manifiesto())
                self.assertEqual(len(det.bloqueos), 1)
                self.assertIn("no es una de las que sé instalar", det.bloqueos[0])
                self.assertEqual(sis.ordenes, [], "ni siquiera mira lo demás")

    def test_otra_arquitectura_o_python_viejo(self):
        sis, falso = sf.servidor()
        falso.arquitectura = "armhf"
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "armhf")
        sis2, _ = sf.servidor()
        self.addCleanup(sis2.limpiar)
        sis2.version_python = (3, 8, 10)
        self.assertTrue(any("Python 3.9" in b for b in detectar(sis2, Manifiesto()).bloqueos))

    def test_un_nucleo_viejo_o_sin_apt_ya_no_para(self):
        """Eran de la VPN (las interfaces XFRM, los paquetes de strongSwan): la pasarela no los necesita."""
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        sis.nucleo = "4.14.0-1-amd64"
        sis.borrar("/usr/bin/apt-get")
        self.assertEqual(self.detectar().bloqueos, [])

    def test_sin_systemd(self):
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        sis.borrar("/run/systemd/system")
        self.bloqueo(self.detectar(), "no arranca con systemd")


class Hermes(Base):
    def test_sin_hermes(self):
        sis = apoyo.SistemaFalso()
        sf.ServidorFalso(sis)
        self.montar((sis, None))
        self.bloqueo(self.detectar(), "No encuentro Hermes")

    def test_hermes_de_otro_usuario_por_su_proceso_y_con_su_hermes_home(self):
        sis = apoyo.SistemaFalso()
        falso = sf.ServidorFalso(sis)
        sis.http_falso = falso.http
        falso.con_hermes(usuario="ana", como="proceso", hermes_home="/srv/hermes-ana", puerto=9000)
        self.montar((sis, falso))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertEqual((det.hermes.usuario, det.hermes.env, det.hermes.puerto), ("ana", "/srv/hermes-ana/.env", 9000))

    def test_hermes_de_otro_usuario_por_su_unidad(self):
        sis = apoyo.SistemaFalso()
        falso = sf.ServidorFalso(sis)
        sis.http_falso = falso.http
        falso.con_hermes(usuario="ana")
        self.montar((sis, falso))
        det = self.detectar()
        self.assertEqual((det.hermes.usuario, det.hermes.env), ("ana", "/home/ana/.hermes/.env"))

    def test_la_api_apagada(self):
        self.montar(sf.servidor(habilitada=False))
        self.bloqueo(self.detectar(), "API_SERVER_ENABLED")

    def test_sin_clave(self):
        self.montar(sf.servidor(clave=None))
        self.bloqueo(self.detectar(), "API_SERVER_KEY")

    def test_una_clave_que_no_puede_ir_en_una_cabecera(self):
        self.montar(sf.servidor(clave="con un espacio"))
        self.bloqueo(self.detectar(), "no pueden ir en una cabecera HTTP")

    def test_una_clave_que_no_vale(self):
        sis, falso = sf.servidor()
        falso.hermes[8642] = "otra-clave"
        self.montar((sis, falso))
        det = self.detectar()
        self.bloqueo(det, "no la acepta")
        self.assertFalse(det.hermes.clave_vale)
        self.assertNotIn("otra-clave", repr(det.bloqueos))

    def test_hermes_que_no_contesta(self):
        sis, falso = sf.servidor()
        falso.hermes.clear()
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "no contesta")

    def test_hermes_en_todas_las_interfaces_avisa_en_rojo_y_no_lo_toca(self):
        self.montar(sf.servidor(host="0.0.0.0"))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.aviso(det, "0.0.0.0")
        self.assertTrue(any(a.startswith(d.ROJO) for a in det.avisos))

    def test_hermes_en_otra_direccion_no_se_alcanza(self):
        self.montar(sf.servidor(host="10.0.0.5"))
        self.bloqueo(self.detectar(), "la pasarela no lo alcanzaría")

    def test_varios_hermes_se_enumeran_y_se_elige(self):
        sis, falso = sf.servidor()
        falso.con_hermes(usuario="ana", como="proceso", puerto=9000)
        self.montar((sis, falso))
        det = self.detectar()
        self.bloqueo(det, "varios Hermes")
        self.bloqueo(det, "/root/.hermes")
        self.bloqueo(det, "/home/ana/.hermes")
        det = self.detectar(hermes_home="/home/ana/.hermes")
        self.assertEqual(det.bloqueos, [])
        self.assertEqual(det.hermes.puerto, 9000)


class Direccion(Base):
    def test_privada_pide_direccion(self):
        sis, falso = sf.servidor()
        falso.direccion_salida = "192.168.1.20"
        self.montar((sis, falso))
        det = self.detectar()
        self.bloqueo(det, "--direccion")
        self.assertTrue(det.direccion_privada)
        det = self.detectar(direccion="198.51.100.9")
        self.assertEqual((det.bloqueos, det.direccion), ([], "198.51.100.9"))

    def test_una_direccion_que_no_vale(self):
        self.montar(sf.servidor())
        self.bloqueo(self.detectar(direccion="a b"), "--direccion")


class LoQueYaHay(Base):
    def test_nginx_strongswan_o_el_80_ocupado_no_importan(self):
        """Eran de la VPN: la pasarela va en su TCP alto y no los usa."""
        sis, falso = sf.servidor()
        for paquete in ("apache2", "strongswan-swanctl", "charon-systemd"):
            falso.instalar_paquete(paquete)
        falso.activos.add("strongswan-starter")
        falso.udp.append(("0.0.0.0:500", "racoon"))
        falso.enlaces_ip["br-1234"] = {"ifname": "br-1234", "addr": ["10.77.3.1/24"]}
        self.montar((sis, falso))
        self.assertEqual(self.detectar().bloqueos, [])

    def test_la_vpn_de_antes_se_dice_y_no_para(self):
        sis, falso = vpn_antigua.servidor()
        self.montar((sis, falso))
        vpn_antigua.montar(sis, falso)
        del sis.ordenes[:]
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.aviso(det, "Aquí sigue la VPN IKEv2 que instaló una versión anterior")
        self.aviso(det, "sudo hehermes-servidor desinstalar --modo vpn")

    def test_una_vpn_hecha_a_mano_se_dice_y_no_para(self):
        self.montar(sf.servidor_de_daniel())
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.aviso(det, "Aquí hay una VPN de HeHermes")
        self.assertEqual(det.direccion, "203.0.113.7")
        self.assertEqual(det.ufw, "activo")
        self.assertTrue(det.hermes.clave_vale)


class Cortafuegos(Base):
    def test_ufw_apagado_avisa_y_no_bloquea(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("ufw")
        falso.ufw = "inactivo"
        self.montar((sis, falso))
        det = self.detectar()
        self.assertEqual((det.bloqueos, det.ufw), ([], "inactivo"))
        self.aviso(det, "no lo enciendo")

    def test_las_reglas_de_ufw_se_leen_en_las_dos_formas(self):
        canon = d.regla_ufw_canonica
        self.assertEqual(canon("ufw allow 61234/tcp"), canon("ufw allow proto tcp from any to any port 61234 "
                                                             "comment 'hehermes'"))
        self.assertEqual(canon("ufw allow 500,4500/udp"), canon("ufw allow proto udp from any to any port 4500,500 "
                                                                 "comment 'hehermes'"))
        self.assertEqual(canon("ufw allow in on hh-ipsec to 10.77.0.1 port 80 proto tcp"),
                         canon("ufw allow in on hh-ipsec proto tcp from any to 10.77.0.1 port 80 comment hehermes"))
        self.assertNotEqual(canon("ufw allow 80/tcp"), canon("ufw allow in on hh-ipsec to 10.77.0.1 port 80 proto tcp"))
        self.assertNotEqual(canon("ufw deny 61234/tcp"), canon("ufw allow 61234/tcp"))
        self.assertIsNone(canon("ufw allow OpenSSH"))

    def test_sin_ninguno_avisa_de_que_no_hay(self):
        # nftables, iptables y firewalld en Debian, en test_cortafuegos.
        self.montar(sf.servidor())
        det = self.detectar()
        self.aviso(det, "No hay ningún cortafuegos")
        self.aviso(det, "en su panel, abre ahí el TCP")


if __name__ == "__main__":
    unittest.main()
