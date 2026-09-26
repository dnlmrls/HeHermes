"""`hehermes-dispositivo rotar <nombre>`: una PSK nueva para un iPhone cuyo QR ha podido verse.

El script es de root y toca `/etc`: se carga como módulo con sus carpetas en una temporal y swanctl de mentira.
"""

import apoyo

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

RUTA = apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo"


def cargar():
    cargador = importlib.machinery.SourceFileLoader("hehermes_dispositivo_rotar", str(RUTA))
    modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader("hehermes_dispositivo_rotar", cargador))
    cargador.exec_module(modulo)
    return modulo


class Rotar(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.mkdtemp(prefix="hh-rotar-")
        self.addCleanup(shutil.rmtree, self.carpeta)
        self.m = cargar()
        self.m.DIR_HH = os.path.join(self.carpeta, "registro")
        self.m.REGISTRO = os.path.join(self.m.DIR_HH, "dispositivos.json")
        self.m.DIR_SWANCTL = os.path.join(self.carpeta, "conf.d")
        os.makedirs(self.m.DIR_HH)
        os.makedirs(self.m.DIR_SWANCTL)
        self.d = {"nombre": "mi-iphone", "tipo": "ikev2", "ip": "10.77.1.3", "servidor": "203.0.113.7",
                  "conexion": "hh-mi-iphone", "alta": "2026-09-24T00:00:00+00:00"}
        self.m.guardar_registro({"dispositivos": [self.d]})
        self.psk_vieja = self.m.nueva_psk()
        self.m.escribir_privado(self.m.ruta_swanctl("mi-iphone"), self.m.conf_swanctl(self.d, self.psk_vieja))
        self.ordenes = []
        self.carga_bien = True
        mock.patch.object(self.m, "correr", self.correr).start()
        self.addCleanup(mock.patch.stopall)

    def correr(self, *args, entrada=None):
        self.ordenes.append(list(args))
        if args[:2] == ("swanctl", "--load-all"):
            return subprocess.CompletedProcess(args, 0 if self.carga_bien else 1, "", "" if self.carga_bien else "roto")
        if args[:2] == ("swanctl", "--list-conns"):
            return subprocess.CompletedProcess(args, 0, "hh-mi-iphone: IKEv2\n" if self.carga_bien else "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def rotar(self, nombre="mi-iphone"):
        salida, errores = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(salida), contextlib.redirect_stderr(errores):
            try:
                self.m.cmd_rotar([nombre])
                codigo = 0
            except SystemExit as salir:
                codigo = salir.code
        return codigo, salida.getvalue() + errores.getvalue()

    def psk(self):
        return self.m.leer_psk(self.m.ruta_swanctl("mi-iphone"))

    def test_una_psk_nueva_en_la_misma_conexion_y_corta_la_sesion(self):
        antes = self.m.leer(self.m.ruta_swanctl("mi-iphone"))
        codigo, texto = self.rotar()
        self.assertEqual(codigo, 0, texto)
        nueva = self.psk()
        self.assertNotEqual(nueva, self.psk_vieja)
        self.assertEqual(len(nueva), 44)
        despues = self.m.leer(self.m.ruta_swanctl("mi-iphone"))
        self.assertEqual(despues.replace(nueva, "X"), antes.replace(self.psk_vieja, "X"), "solo cambia la clave")
        self.assertEqual(os.stat(self.m.ruta_swanctl("mi-iphone")).st_mode & 0o777, 0o600)
        self.assertIn(["swanctl", "--terminate", "--ike", "hh-mi-iphone", "--force"], self.ordenes)
        self.assertLess(self.ordenes.index(["swanctl", "--load-all", "--noprompt"]),
                        self.ordenes.index(["swanctl", "--terminate", "--ike", "hh-mi-iphone", "--force"]))
        self.assertIn("sudo hehermes-dispositivo qr mi-iphone", texto)
        self.assertNotIn(nueva, texto)
        self.assertNotIn(self.psk_vieja, texto)
        self.assertIn("rotada", self.m.leer_registro()["dispositivos"][0])

    def test_si_swanctl_no_la_carga_se_queda_la_de_antes(self):
        self.carga_bien = False
        codigo, texto = self.rotar()
        self.assertEqual(codigo, 1)
        self.assertEqual(self.psk(), self.psk_vieja)
        self.assertIn("sigue la de antes", texto)
        self.assertNotIn(["swanctl", "--terminate", "--ike", "hh-mi-iphone", "--force"], self.ordenes)

    def test_ni_uno_que_no_existe_ni_uno_escrito_a_mano(self):
        self.assertEqual(self.rotar("otro")[0], 1)
        with open(self.m.ruta_swanctl("mi-iphone"), "w") as f:
            f.write("# escrito a mano\nsecrets { x { secret = \"a\" } }\n")
        codigo, texto = self.rotar()
        self.assertEqual(codigo, 1)
        self.assertIn("no lo escribió este script", texto)

    def test_uno_de_wireguard_no(self):
        self.m.guardar_registro({"dispositivos": [dict(self.d, tipo="wireguard")]})
        codigo, texto = self.rotar()
        self.assertEqual(codigo, 1)
        self.assertIn("WireGuard", texto)

    def test_esta_en_la_ayuda(self):
        self.assertIn("rotar", self.m.COMANDOS)
        self.assertIn("hehermes-dispositivo rotar <nombre>", self.m.__doc__)


if __name__ == "__main__":
    unittest.main()
