"""La detección: lo mira todo antes de preguntar, y sin cambiar nada.

Cada caso de la spec («Qué detecta», «Un servidor que ya tiene nginx o strongSwan») sobre un servidor falso. Al final
de cada prueba se mira que ninguna orden de las que ha visto cambie algo.
"""

import apoyo  # noqa: F401

import unittest

import servidor_falso as sf
from hehermes_servidor import deteccion as d
from hehermes_servidor.manifiesto import Manifiesto

# Lo que puede ejecutar la detección: solo órdenes que leen.
QUE_LEEN = (["dpkg", "--print-architecture"], ["dpkg-query"], ["systemctl", "is-active"], ["systemctl", "is-enabled"],
            ["systemctl", "show"], ["ps"], ["ss"], ["ip", "-4", "-j", "route", "get"], ["ip", "-j"], ["ip", "-d", "-j"],
            ["nginx", "-t"], ["swanctl", "--stats"], ["swanctl", "--list-conns"], ["ufw", "status"],
            ["ufw", "show", "added"], ["nft", "-j", "list", "ruleset"], ["iptables", "-S", "INPUT"],
            ["iptables", "-V"])


class Base(unittest.TestCase):
    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)
        return self.falso

    def detectar(self, **opciones):
        antes = self.sis.foto()
        det = d.detectar(self.sis, Manifiesto.leer(self.sis), **opciones)
        self.assertEqual(self.sis.foto(), antes, "la detección no escribe nada")
        for orden in self.sis.ordenes:
            self.assertTrue(any(orden[:len(p)] == p for p in QUE_LEEN), "orden que no solo lee: %s" % orden)
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
        self.assertEqual(det.paquetes_instalados, set())
        self.assertFalse(det.nginx["instalado"])
        self.assertIsNone(det.ufw)
        self.aviso(det, "cortafuegos propio")
        # La clave va con Bearer a Hermes, y nunca a otro sitio.
        self.assertIn(("http://127.0.0.1:8642/api/sessions?limit=1", {"Authorization": "Bearer " + sf.CLAVE}),
                      self.sis.peticiones_http)
        self.assertNotIn(sf.CLAVE, repr(det.bloqueos) + repr(det.avisos))

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
                self.assertEqual(d.detectar(sis, Manifiesto()).bloqueos, [])


class NoSoportados(Base):
    def test_otra_distribucion_se_para_al_empezar(self):
        for distro in (("debian", "11"), ("ubuntu", "23.10"), ("fedora", "40"), ("ubuntu", "20.04")):
            with self.subTest(distro=distro):
                sis, falso = sf.servidor(distro)
                self.addCleanup(sis.limpiar)
                det = d.detectar(sis, Manifiesto())
                self.assertEqual(len(det.bloqueos), 1)
                self.assertIn("no es una de las que sé instalar", det.bloqueos[0])
                self.assertEqual(sis.ordenes, [], "ni siquiera mira lo demás")

    def test_otra_arquitectura_python_viejo_o_nucleo_viejo(self):
        sis, falso = sf.servidor()
        falso.arquitectura = "armhf"
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "armhf")
        sis2, _ = sf.servidor()
        self.addCleanup(sis2.limpiar)
        sis2.version_python = (3, 8, 10)
        self.assertTrue(any("Python 3.9" in b for b in d.detectar(sis2, Manifiesto()).bloqueos))
        sis3, _ = sf.servidor()
        self.addCleanup(sis3.limpiar)
        sis3.nucleo = "4.14.0-1-amd64"
        self.assertTrue(any("núcleo" in b for b in d.detectar(sis3, Manifiesto()).bloqueos))

    def test_sin_systemd_o_sin_apt(self):
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        sis.borrar("/usr/bin/apt-get")
        self.bloqueo(self.detectar(), "apt")


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
        self.bloqueo(self.detectar(), "10.0.0.5")

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
    def test_nginx_con_otros_sitios_convive(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        sis.poner("/etc/nginx/sites-available/tienda", "server { listen 80; }\n")
        self.montar((sis, falso))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertTrue(det.nginx["instalado"] and det.nginx["activo"])
        self.assertEqual(det.nginx["sitios"], "sites-enabled")

    def test_nginx_que_ya_no_pasaba_la_prueba(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        falso.nginx_t = lambda: False
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "nginx -t")

    def test_nginx_parado(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        falso.activos.discard("nginx")
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "nginx está instalado pero parado")

    def test_nginx_sin_sites_enabled_usa_conf_d(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        sis.poner("/etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
        self.montar((sis, falso))
        self.assertEqual(self.detectar().nginx["sitios"], "conf.d")

    def test_apache_en_el_80(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("apache2")
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "apache2")

    def test_otro_programa_en_el_udp_500(self):
        sis, falso = sf.servidor()
        falso.udp.append(("0.0.0.0:500", "racoon"))
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "racoon")

    def test_strongswan_con_starter(self):
        sis, falso = sf.servidor()
        falso.activos.add("strongswan-starter")
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "ipsec.conf")

    def test_strongswan_con_otra_conexion_convive(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("strongswan-swanctl")
        falso.instalar_paquete("charon-systemd")
        sis.poner("/etc/swanctl/conf.d/oficina.conf", (
            "connections {\n    oficina {\n        remote_addrs = 198.51.100.1\n        local { auth = psk }\n"
            "        remote {\n            auth = psk\n            id = oficina.example\n        }\n"
            "        children { oficina { if_id_in = 0x10\n if_id_out = 0x10 } }\n    }\n}\n"
            "pools {\n    oficina { addrs = 10.9.0.0/24 }\n}\n"))
        self.montar((sis, falso))
        self.assertEqual(self.detectar().bloqueos, [])

    def test_strongswan_que_chocaria(self):
        casos = {
            "hh-": "connections {\n    hh-otra {\n        remote { auth = psk\n id = x }\n    }\n}\n",
            "pool": "pools {\n    suyo {\n        addrs = 10.77.1.0/25\n    }\n}\n",
            "if_id": "connections {\n    x {\n        remote { auth = pubkey }\n        children { x { if_id_in = 0x77 } }\n"
                     "    }\n}\n",
            "%any": "connections {\n    abierta {\n        remote {\n            auth = psk\n        }\n    }\n}\n",
        }
        for texto, conf in casos.items():
            with self.subTest(caso=texto):
                sis, falso = sf.servidor()
                self.addCleanup(sis.limpiar)
                falso.instalar_paquete("strongswan-swanctl")
                sis.poner("/etc/swanctl/conf.d/suyo.conf", conf)
                det = d.detectar(sis, Manifiesto())
                self.assertTrue(any(texto in b for b in det.bloqueos), det.bloqueos)

    def test_swanctl_conf_sin_conf_d(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("strongswan-swanctl")
        sis.poner("/etc/swanctl/swanctl.conf", "connections {}\n")
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "conf.d/*.conf")

    def test_docker_en_10_77(self):
        sis, falso = sf.servidor()
        falso.enlaces_ip["br-1234"] = {"ifname": "br-1234", "addr": ["10.77.3.1/24"]}
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "br-1234")

    def test_otra_interfaz_con_el_if_id(self):
        sis, falso = sf.servidor()
        falso.enlaces_ip["xfrm9"] = {"ifname": "xfrm9", "linkinfo": {"info_kind": "xfrm", "info_data": {"if_id": 119}}}
        self.montar((sis, falso))
        self.bloqueo(self.detectar(), "xfrm9")


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
        self.assertEqual(canon("ufw allow 500,4500/udp"), canon("ufw allow proto udp from any to any port 4500,500 "
                                                                 "comment 'hehermes'"))
        self.assertEqual(canon("ufw allow in on hh-ipsec to 10.77.0.1 port 80 proto tcp"),
                         canon("ufw allow in on hh-ipsec proto tcp from any to 10.77.0.1 port 80 comment hehermes"))
        self.assertNotEqual(canon("ufw allow 80/tcp"), canon("ufw allow in on hh-ipsec to 10.77.0.1 port 80 proto tcp"))
        self.assertNotEqual(canon("ufw deny 500,4500/udp"), canon("ufw allow 500,4500/udp"))
        self.assertIsNone(canon("ufw allow OpenSSH"))

    def test_sin_ninguno_avisa_de_que_no_hay(self):
        # nftables, iptables y firewalld en Debian, en test_cortafuegos.
        self.montar(sf.servidor())
        self.aviso(self.detectar(), "No hay ningún cortafuegos")


class ElDeDaniel(Base):
    def test_una_instalacion_a_mano_no_se_toca(self):
        self.montar(sf.servidor_de_daniel())
        det = self.detectar()
        self.bloqueo(det, "instalación hecha a mano")
        texto = "\n".join(det.bloqueos)
        for senal in ("hh-iphone-poc", "wg0", "hh-ipsec", "/usr/local/sbin/hehermes-dispositivo",
                      "/etc/nginx/sites-available/hehermes-tunel"):
            self.assertIn(senal, texto)
        self.aviso(det, "agujero")
        self.assertEqual(det.direccion, "203.0.113.7")
        self.assertEqual(det.ufw, "activo")
        self.assertTrue(det.hermes.clave_vale)


if __name__ == "__main__":
    unittest.main()
