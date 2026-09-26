"""Lo que el instalador escribe, y lo que reconoce de la VPN de antes para quitarla.

Desde la 0.6.0 solo escribe la pasarela (sus piezas, en `test_ambito`). De la VPN quedan sus rutas, sus reglas y el
agujero del túnel, que «Seguridad» sigue mirando mientras esté: lo que la escribía (el sitio de nginx, la interfaz
XFRM, `servidor.ini`…) ya no existe.
"""

import apoyo

import importlib.machinery
import importlib.util
import unittest

from hehermes_servidor import deteccion as d
from hehermes_servidor import piezas as p


def cargar_dispositivo():
    ruta = apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo"
    cargador = importlib.machinery.SourceFileLoader("hehermes_dispositivo_piezas", str(ruta))
    modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader(cargador.name, cargador))
    cargador.exec_module(modulo)
    return modulo


class ElAgujeroDelTunel(unittest.TestCase):
    def test_el_agujero(self):
        # El sitio a mano del VPS de Daniel: sin allow ni deny en `location /`.
        daniel = (apoyo.REPO / "server" / "vpn" / "hehermes-tunel.nginx").read_text()
        self.assertTrue(p.agujero_abierto(daniel))
        # El que escribía el instalador: el servidor, negado delante de todo.
        self.assertFalse(p.agujero_abierto("server { listen 10.77.0.1:80; location / { deny 10.77.0.1; "
                                           "allow 10.77.1.0/24; deny all; proxy_pass http://127.0.0.1:8642; } }"))
        # Una regla que deja pasar al propio servidor también es agujero; una que lo niega, no.
        self.assertTrue(p.agujero_abierto("server { location / { allow all; proxy_pass x; } }"))
        self.assertTrue(p.agujero_abierto("server { location / { allow 10.77.0.0/16; deny all; } }"))
        self.assertFalse(p.agujero_abierto("server { location / { allow 10.77.1.0/24; deny all; } }"))
        self.assertFalse(p.agujero_abierto("server { location / { deny all; } }"))
        # Sin location / no se sabe qué deja pasar: se da por abierto.
        self.assertTrue(p.agujero_abierto("server { listen 10.77.0.1:80; include otra.conf; }"))
        # Comentada, no cuenta.
        self.assertTrue(p.agujero_abierto("server { location / { # deny all;\n proxy_pass x; } }"))
        # Las de una location anidada no cuentan para `/`.
        self.assertTrue(p.agujero_abierto("server { location / { location /x { deny all; } proxy_pass x; } }"))


class LoDeLaVpn(unittest.TestCase):
    def test_coincide_con_hehermes_dispositivo(self):
        dispositivo = cargar_dispositivo()
        self.assertEqual(p.IP_TUNEL, str(dispositivo.IP_SERVIDOR))
        self.assertEqual(p.BEARER, dispositivo.BEARER_NGINX)
        self.assertEqual(p.SERVIDOR_INI, dispositivo.SERVIDOR_INI)
        self.assertTrue(dispositivo.CABECERA_SWANCTL.startswith(d.CABECERA_DISPOSITIVO))

    def test_lo_que_la_escribia_ya_no_esta(self):
        for que in ("sitio_nginx", "bearer", "drop_in_nginx", "unidad_xfrm", "script_xfrm", "unidad_clave_path",
                    "unidad_clave_service", "servidor_ini", "reglas_de_acceso"):
            with self.subTest(que=que):
                self.assertFalse(hasattr(p, que))

    def test_las_reglas_de_ufw_de_la_vpn_se_siguen_reconociendo(self):
        self.assertEqual([r.args for r in p.reglas_ufw("vpn")], [
            ["allow", "proto", "udp", "from", "any", "to", "any", "port", "500,4500", "comment", "hehermes"],
            ["allow", "in", "on", "hh-ipsec", "proto", "tcp", "from", "any", "to", "10.77.0.1", "port", "80",
             "comment", "hehermes"],
        ])
        self.assertEqual([r.opcion for r in p.reglas_firewalld("vpn")][:2], ["--add-port=500/udp",
                                                                            "--add-port=4500/udp"])


class LoDeLaPasarela(unittest.TestCase):
    def test_las_reglas_de_ufw_y_firewalld(self):
        self.assertEqual([r.args for r in p.reglas_ufw("tls", 61234)],
                         [["allow", "proto", "tcp", "from", "any", "to", "any", "port", "61234", "comment", "hehermes"]])
        self.assertEqual([r.opcion for r in p.reglas_firewalld("tls", 61234)], ["--add-port=61234/tcp"])
        for malo in (None, 80, 70000, True):
            with self.subTest(puerto=malo), self.assertRaises(ValueError):
                p.reglas_ufw("tls", malo)


if __name__ == "__main__":
    unittest.main()
