"""Lo que el instalador escribe: el sitio de nginx con el túnel cerrado de fábrica, la interfaz XFRM, las unidades, las
reglas de ufw y `servidor.ini`.

La regla que cierra el túnel es la otra pieza con mutaciones: `reglas_de_acceso` y dónde la pone `sitio_nginx`.
"""

import apoyo

import configparser
import importlib.machinery
import importlib.util
import ipaddress
import re
import unittest

from hehermes_servidor import piezas as p


def decide(reglas, origen):
    """Como nginx: gana la primera regla que abarca la dirección; sin ninguna, entra."""
    ip = ipaddress.ip_address(origen)
    for accion, red in reglas:
        if red == "all" or (ip.version == ipaddress.ip_network(red, strict=False).version
                            and ip in ipaddress.ip_network(red, strict=False)):
            return accion
    return "allow"


def bloque(texto, cabecera):
    """El cuerpo del bloque `cabecera { … }`, contando llaves."""
    inicio = re.search(re.escape(cabecera) + r"\s*\{", texto)
    assert inicio, cabecera
    nivel, i = 1, inicio.end()
    while nivel:
        nivel += {"{": 1, "}": -1}.get(texto[i], 0)
        i += 1
    return texto[inicio.end():i - 1]


def sin_comentarios(texto):
    return re.sub(r"#[^\n]*", "", texto)


def cargar_dispositivo():
    ruta = apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo"
    cargador = importlib.machinery.SourceFileLoader("hehermes_dispositivo_piezas", str(ruta))
    modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader(cargador.name, cargador))
    cargador.exec_module(modulo)
    return modulo


class ReglaDelTunel(unittest.TestCase):
    def test_solo_entran_los_iphone(self):
        reglas = p.reglas_de_acceso()
        for origen, esperado in (("10.77.1.7", "allow"), ("10.77.1.254", "allow"),
                                 ("10.77.0.1", "deny"),      # los procesos del propio servidor
                                 ("10.77.0.2", "deny"),      # WireGuard: no hay en una instalación nueva
                                 ("127.0.0.1", "deny"), ("10.77.2.1", "deny"), ("203.0.113.7", "deny"),
                                 ("::1", "deny"), ("fe80::1", "deny")):
            with self.subTest(origen=origen):
                self.assertEqual(decide(reglas, origen), esperado)

    def test_el_servidor_se_niega_primero_aunque_se_abra_la_red(self):
        # El `deny 10.77.0.1` va delante de todo: si un día se deja entrar a más red (WireGuard, 10.77.0.0/16), los
        # procesos del servidor, que llegan desde 10.77.0.1, siguen fuera. Sin él, esto entraría.
        for permitidas in (("10.77.0.0/16",), ("10.77.0.0/24", "10.77.1.0/24")):
            with self.subTest(permitidas=permitidas):
                reglas = p.reglas_de_acceso(permitidas)
                self.assertEqual(reglas[0], ("deny", "10.77.0.1"))
                self.assertEqual(reglas[-1], ("deny", "all"))
                self.assertEqual(decide(reglas, "10.77.0.1"), "deny")
                self.assertEqual(decide(reglas, "10.77.0.9"), "allow")
                self.assertEqual(decide(reglas, "127.0.0.1"), "deny")

    def test_no_se_puede_abrir_fuera_del_tunel(self):
        for red in ("0.0.0.0/0", "10.0.0.0/8", "127.0.0.1", "all", "10.78.0.0/24", "::/0"):
            with self.subTest(red=red), self.assertRaises(ValueError):
                p.reglas_de_acceso((red,))


class SitioDeNginx(unittest.TestCase):
    def setUp(self):
        self.texto = p.sitio_nginx(8642)
        self.limpio = sin_comentarios(self.texto)

    def test_la_location_de_hermes_lleva_la_regla_y_solo_ahi(self):
        location = bloque(self.limpio, "location /")
        reglas = re.findall(r"^\s*(allow|deny)\s+([^;]+);", location, re.M)
        self.assertEqual(reglas, p.reglas_de_acceso())
        # Delante del proxy_pass: que se lea como lo que es.
        self.assertLess(location.index("deny 10.77.0.1;"), location.index("proxy_pass"))
        fuera = self.limpio.replace(location, "")
        self.assertNotRegex(fuera, r"\b(allow|deny)\b", "en el server {} cerraría también /avisos/, que lleva las suyas")

    def test_escucha_solo_en_el_tunel_y_lleva_la_clave(self):
        self.assertEqual(re.findall(r"^\s*listen\s+([^;]+);", self.limpio, re.M), ["10.77.0.1:80"])
        location = bloque(self.limpio, "location /")
        self.assertIn("proxy_pass http://127.0.0.1:8642;", location)
        self.assertIn("include /etc/nginx/hehermes-bearer.conf;", location)
        self.assertEqual(self.limpio.count("hehermes-bearer.conf"), 1)
        self.assertIn("proxy_buffering off;", location, "el SSE de los runs, token a token")

    def test_los_avisos_se_incluyen_en_el_server(self):
        server = bloque(self.limpio, "server")
        location = bloque(self.limpio, "location /")
        self.assertIn("include /etc/nginx/hehermes-avisos/sitio/*.conf;", server.replace(location, ""))

    def test_el_puerto_de_hermes_se_comprueba(self):
        self.assertIn("127.0.0.1:9000;", p.sitio_nginx(9000))
        for malo in (0, 70000, "8642; evil"):
            with self.subTest(puerto=malo), self.assertRaises(ValueError):
                p.sitio_nginx(malo)

    def test_el_agujero(self):
        self.assertFalse(p.agujero_abierto(self.texto))
        # El sitio a mano del VPS de Daniel: sin allow ni deny en `location /`.
        daniel = (apoyo.REPO / "server" / "vpn" / "hehermes-tunel.nginx").read_text()
        self.assertTrue(p.agujero_abierto(daniel))
        # Una regla que deja pasar al propio servidor también es agujero; una que lo niega, no.
        self.assertTrue(p.agujero_abierto("server { location / { allow all; proxy_pass x; } }"))
        self.assertTrue(p.agujero_abierto("server { location / { allow 10.77.0.0/16; deny all; } }"))
        self.assertFalse(p.agujero_abierto("server { location / { allow 10.77.1.0/24; deny all; } }"))
        self.assertFalse(p.agujero_abierto("server { location / { deny all; } }"))
        # Sin location / no se sabe qué deja pasar: se da por abierto.
        self.assertTrue(p.agujero_abierto("server { listen 10.77.0.1:80; include otra.conf; }"))
        # Comentada, no cuenta.
        self.assertTrue(p.agujero_abierto("server { location / { # deny all;\n proxy_pass x; } }"))


class LoDemas(unittest.TestCase):
    def test_coincide_con_hehermes_dispositivo(self):
        d = cargar_dispositivo()
        self.assertEqual(p.IF_ID, d.IF_ID_XFRM)
        self.assertEqual(p.INTERFAZ, d.INTERFAZ_XFRM)
        self.assertEqual(p.IP_TUNEL, str(d.IP_SERVIDOR))
        self.assertEqual(p.RED_IPHONES, str(d.RED_IKEV2))
        self.assertEqual(p.BEARER, d.BEARER_NGINX)

    def test_la_interfaz_xfrm(self):
        unidad = p.unidad_xfrm()
        self.assertRegex(unidad, r"(?m)^Type=oneshot$")
        self.assertRegex(unidad, r"(?m)^RemainAfterExit=yes$")
        self.assertRegex(unidad, r"(?m)^Before=.*\bstrongswan\.service\b")
        self.assertRegex(unidad, r"(?m)^Before=.*\bnginx\.service\b")
        # Un cambio se aplica con reload, que no tumba la interfaz ni corta los túneles.
        self.assertIn("ExecReload=%s subir" % p.SCRIPT_XFRM, unidad)
        self.assertIn("ExecStart=%s subir" % p.SCRIPT_XFRM, unidad)
        self.assertNotIn("networkd", sin_comentarios(unidad), "no enciende la red de otro")
        script = p.script_xfrm()
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertIn("ip link add hh-ipsec type xfrm if_id 0x77", script)
        self.assertIn("ip addr replace 10.77.0.1/32 dev hh-ipsec", script)
        self.assertIn("ip route replace 10.77.1.0/24 dev hh-ipsec", script)
        self.assertIn("xfrm if_id 0x77", script, "si ya existe, que sea la nuestra")
        drop_in = p.drop_in_nginx()
        self.assertRegex(drop_in, r"(?m)^After=hehermes-xfrm\.service$")
        self.assertRegex(drop_in, r"(?m)^Wants=hehermes-xfrm\.service$")

    def test_la_vigilancia_de_la_clave(self):
        ruta = p.unidad_clave_path("/home/ana/.hermes/.env")
        self.assertIn("PathChanged=/home/ana/.hermes/.env", ruta)
        self.assertIn("Unit=hehermes-clave.service", ruta)
        self.assertIn("ExecStart=/usr/local/sbin/hehermes-dispositivo clave", p.unidad_clave_service())
        with self.assertRaises(ValueError):
            p.unidad_clave_path("/home/ana/.hermes/.env\nExecStart=/bin/mal")

    def test_servidor_ini(self):
        ini = configparser.ConfigParser()
        ini.read_string(p.servidor_ini("203.0.113.7", "/home/ana/.hermes/.env", 8642))
        self.assertEqual(ini["servidor"]["direccion"], "203.0.113.7")
        self.assertEqual(ini["hermes"]["env"], "/home/ana/.hermes/.env")
        self.assertEqual(ini["hermes"]["puerto"], "8642")
        self.assertEqual(ini["dispositivos"]["registro"], "/etc/hehermes/dispositivos")
        for malo in ("a b", "x\n[otra]", ""):
            with self.subTest(direccion=malo), self.assertRaises(ValueError):
                p.servidor_ini(malo, "/x/.env", 8642)

    def test_las_reglas_de_ufw(self):
        reglas = p.reglas_ufw()
        self.assertEqual([r.args for r in reglas], [
            ["allow", "proto", "udp", "from", "any", "to", "any", "port", "500,4500", "comment", "hehermes"],
            ["allow", "in", "on", "hh-ipsec", "proto", "tcp", "from", "any", "to", "10.77.0.1", "port", "80",
             "comment", "hehermes"],
        ])


if __name__ == "__main__":
    unittest.main()
