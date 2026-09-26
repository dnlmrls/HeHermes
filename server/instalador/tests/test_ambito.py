"""El ámbito (root o un usuario) y las piezas de la pasarela: rutas, unidades, `pasarela.ini` y las reglas del
cortafuegos. Funciones puras, sin nada que ejecutar."""

import apoyo  # noqa: F401

import configparser
import unittest

from hehermes_servidor import ambito
from hehermes_servidor import cortafuegos as cf
from hehermes_servidor import pasarela as pa
from hehermes_servidor import piezas as p


class LasRutas(unittest.TestCase):
    def test_las_de_root(self):
        a = ambito.de_root()
        self.assertTrue(a.root)
        self.assertEqual((a.prefijo, a.orden, a.dispositivo), ("/opt/hehermes-servidor", "/usr/local/sbin/hehermes-servidor",
                                                              "/usr/local/sbin/hehermes-dispositivo"))
        self.assertEqual((a.manifiesto, a.carpeta_pasarela, a.pasarela_ini),
                         ("/etc/hehermes/instalacion.json", "/etc/hehermes-pasarela",
                          "/etc/hehermes-pasarela/pasarela.ini"))
        self.assertEqual(a.unidad, "/etc/systemd/system/hehermes-pasarela.service")
        self.assertEqual((a.carpeta_venv, a.venv), ("/opt/hehermes-canje", "/opt/hehermes-canje/venv"))
        self.assertEqual(a.run_canje, "/run/hehermes-canje")
        self.assertEqual(a.systemctl, ["systemctl"])

    def test_las_de_un_usuario_todas_en_su_casa(self):
        a = ambito.de_usuario("hermes", "/home/hermes", 1000)
        self.assertFalse(a.root)
        self.assertEqual((a.prefijo, a.orden, a.dispositivo),
                         ("/home/hermes/.local/share/hehermes-servidor", "/home/hermes/.local/bin/hehermes-servidor",
                          "/home/hermes/.local/bin/hehermes-dispositivo"))
        self.assertEqual((a.manifiesto, a.carpeta_pasarela, a.pasarela_ini),
                         ("/home/hermes/.config/hehermes/instalacion.json", "/home/hermes/.config/hehermes-pasarela",
                          "/home/hermes/.config/hehermes-pasarela/pasarela.ini"))
        self.assertEqual(a.unidad, "/home/hermes/.config/systemd/user/hehermes-pasarela.service")
        self.assertEqual((a.carpeta_venv, a.venv), ("/home/hermes/.local/share/hehermes-venv",
                                                    "/home/hermes/.local/share/hehermes-venv"))
        self.assertEqual(a.run_canje, "/run/user/1000/hehermes-canje")
        self.assertEqual(a.systemctl, ["systemctl", "--user"])
        for ruta in (a.prefijo, a.orden, a.dispositivo, a.manifiesto, a.pasarela_ini, a.unidad, a.venv):
            self.assertTrue(ruta.startswith("/home/hermes/"), ruta)

    def test_una_casa_que_no_se_puede_poner_en_una_unidad(self):
        for casa in ("home/hermes", "/home/her mes", "/home/hermes\n", "/"):
            with self.subTest(casa=casa):
                with self.assertRaises(ValueError):
                    ambito.de_usuario("hermes", casa, 1000)


class LaUnidad(unittest.TestCase):
    def test_la_de_root_con_su_usuario_y_su_sandbox(self):
        texto = p.unidad_pasarela(ambito.de_root(), con_vigia=False)
        for linea in ("User=hh-pasarela", "Group=hh-pasarela", "NoNewPrivileges=yes", "ProtectSystem=strict",
                      "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "CapabilityBoundingSet=",
                      "AmbientCapabilities=", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
                      "SystemCallFilter=@system-service", "RestrictNamespaces=yes", "RestrictSUIDSGID=yes",
                      "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "UMask=0077",
                      "ExecStart=/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-pasarela --config "
                      "/etc/hehermes-pasarela/pasarela.ini",
                      "LoadCredential=clave:/etc/hehermes-pasarela/clave.pem",
                      "LoadCredential=hermes:/etc/hehermes-pasarela/clave-hermes", "WantedBy=multi-user.target"):
            self.assertIn(linea + "\n", texto)
        self.assertNotIn("vigia", texto)
        self.assertTrue(texto.startswith(p.CABECERA))

    def test_con_el_vigia_su_secreto_como_credencial(self):
        texto = p.unidad_pasarela(ambito.de_root(), con_vigia=True)
        self.assertIn("LoadCredential=vigia:/etc/hehermes-avisos/vigia/secreto-tunel\n", texto)

    def test_la_de_usuario_sin_usuario_ni_credenciales(self):
        texto = p.unidad_pasarela(ambito.de_usuario("hermes", "/home/hermes", 1000), con_vigia=False)
        self.assertNotIn("User=", texto)
        self.assertNotIn("LoadCredential", texto)
        self.assertNotIn("ProtectSystem", texto)
        self.assertIn("NoNewPrivileges=yes\n", texto)
        self.assertIn("ExecStart=/usr/bin/python3 -I -B /home/hermes/.local/share/hehermes-servidor/hehermes-pasarela "
                      "--config /home/hermes/.config/hehermes-pasarela/pasarela.ini\n", texto)
        self.assertIn("WantedBy=default.target\n", texto)

    def test_la_vigilancia_de_la_clave_de_hermes(self):
        self.assertIn("PathChanged=/root/.hermes/.env\n", p.unidad_pasarela_clave_path("/root/.hermes/.env"))
        self.assertIn("ExecStart=/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor pasarela-clave\n",
                      p.unidad_pasarela_clave_service())


class ElIni(unittest.TestCase):
    def test_lo_lee_la_pasarela(self):
        import os
        import tempfile
        a = ambito.de_root()
        texto = p.pasarela_ini(a, puerto=61234, puerto_hermes=8642, env="/root/.hermes/.env", direccion="203.0.113.7",
                               vigia=True)
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = os.path.join(carpeta, "pasarela.ini")
            with open(ruta, "w") as f:
                f.write(texto)
            c = pa.Configuracion.leer(ruta)
        self.assertEqual((c.puerto, c.puerto_hermes, c.clave_hermes), (61234, 8642, "/etc/hehermes-pasarela/clave-hermes"))
        self.assertEqual((c.certificado, c.clave, c.tokens), ("/etc/hehermes-pasarela/cert.pem",
                                                             "/etc/hehermes-pasarela/clave.pem",
                                                             "/etc/hehermes-pasarela/tokens.json"))
        self.assertEqual(c.vigia, ("127.0.0.1", 8790))
        ini = configparser.ConfigParser(interpolation=None)
        ini.read_string(texto)
        self.assertEqual(ini.get("qr", "direccion"), "203.0.113.7")
        self.assertEqual(ini.get("instalador", "codigo"), "/opt/hehermes-servidor")
        self.assertEqual(ini.get("hermes", "env"), "/root/.hermes/.env")

    def test_sin_root_la_clave_es_el_env_de_hermes(self):
        a = ambito.de_usuario("hermes", "/home/hermes", 1000)
        texto = p.pasarela_ini(a, puerto=61234, puerto_hermes=8642, env="/home/hermes/.hermes/.env",
                               direccion="203.0.113.7", vigia=False)
        ini = configparser.ConfigParser(interpolation=None)
        ini.read_string(texto)
        self.assertEqual(ini.get("hermes", "clave"), "/home/hermes/.hermes/.env")
        self.assertFalse(ini.has_section("avisos"))

    def test_lo_que_no_vale(self):
        a = ambito.de_root()
        for cambio in ({"puerto": 80}, {"puerto": 65501}, {"direccion": "a b"}, {"env": "relativo/.env"}):
            datos = dict(puerto=61234, puerto_hermes=8642, env="/root/.hermes/.env", direccion="203.0.113.7",
                         vigia=False)
            datos.update(cambio)
            with self.subTest(cambio=cambio):
                with self.assertRaises(ValueError):
                    p.pasarela_ini(a, **datos)


class ElCortafuegos(unittest.TestCase):
    def test_en_tls_solo_el_puerto_de_la_pasarela(self):
        reglas = cf.permanentes("tls", 61234)
        self.assertEqual([(r.proto, r.puertos, r.entra, r.destino) for r in reglas], [("tcp", "61234", None, None)])
        self.assertEqual([r.texto for r in p.reglas_ufw("tls", 61234)],
                         ["ufw allow proto tcp from any to any port 61234 comment hehermes"])
        self.assertEqual([r.opcion for r in p.reglas_firewalld("tls", 61234)], ["--add-port=61234/tcp"])

    def test_en_vpn_lo_de_siempre(self):
        self.assertEqual([r.puertos for r in cf.permanentes()], ["500,4500", "80"])
        self.assertEqual(len(p.reglas_ufw()), 2)
        self.assertEqual(len(p.reglas_firewalld()), 3)

    def test_las_del_manifiesto(self):
        self.assertEqual([r.puertos for r in cf.permanentes_de({"modo": "tls", "pasarela": {"puerto": 61234}})],
                         ["61234"])
        self.assertEqual([r.puertos for r in cf.permanentes_de({})], ["500,4500", "80"])


if __name__ == "__main__":
    unittest.main()
