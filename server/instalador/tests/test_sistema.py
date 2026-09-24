"""El `Sistema`: todo lo que el instalador lee, escribe o ejecuta pasa por él, con una raíz que en las pruebas es una
carpeta temporal y unas órdenes que en las pruebas son falsas."""

import apoyo

import os
import stat
import unittest

from hehermes_servidor.sistema import Resultado, sha256


class Sistema(unittest.TestCase):
    def setUp(self):
        self.sis = apoyo.SistemaFalso()
        self.addCleanup(self.sis.limpiar)

    def test_las_rutas_caen_dentro_de_la_raiz(self):
        self.assertEqual(self.sis.ruta("/etc/hehermes/x"), os.path.join(self.sis.raiz, "etc/hehermes/x"))
        with self.assertRaises(ValueError):
            self.sis.ruta("etc/relativa")
        with self.assertRaises(ValueError):
            self.sis.ruta("/etc/../../fuera")

    def test_escribir_es_atomico_y_con_el_modo_pedido(self):
        self.sis.escribir("/etc/hehermes/secreto", b"hola\n", modo=0o600)
        real = self.sis.ruta("/etc/hehermes/secreto")
        self.assertEqual(stat.S_IMODE(os.stat(real).st_mode), 0o600)
        self.assertEqual(self.sis.leer("/etc/hehermes/secreto"), b"hola\n")
        self.assertEqual(os.listdir(os.path.dirname(real)), ["secreto"], "sin temporales")
        self.sis.escribir("/etc/hehermes/secreto", b"adios\n", modo=0o644)
        self.assertEqual(stat.S_IMODE(os.stat(real).st_mode), 0o644)

    def test_leer_no_sigue_enlaces(self):
        self.sis.escribir("/etc/destino", b"x")
        self.sis.enlazar("/etc/enlace", "/etc/destino")
        self.assertIsNone(self.sis.leer("/etc/enlace"))
        self.assertEqual(self.sis.enlace("/etc/enlace"), "/etc/destino")
        self.assertTrue(self.sis.existe("/etc/enlace"))
        self.assertIsNone(self.sis.enlace("/etc/destino"))
        self.assertIsNone(self.sis.leer("/etc/no-existe"))

    def test_escribir_sustituye_un_enlace_sin_tocar_su_destino(self):
        self.sis.escribir("/etc/destino", b"de otro")
        self.sis.enlazar("/etc/enlace", "/etc/destino")
        self.sis.escribir("/etc/enlace", b"mio")
        self.assertEqual(self.sis.leer("/etc/destino"), b"de otro")
        self.assertEqual(self.sis.leer("/etc/enlace"), b"mio")

    def test_borrar_lo_que_no_hay_no_falla(self):
        self.sis.borrar("/etc/nada")
        self.sis.escribir("/etc/algo", b"x")
        self.sis.borrar("/etc/algo")
        self.assertFalse(self.sis.existe("/etc/algo"))

    def test_las_ordenes_se_apuntan_y_contestan_lo_que_se_diga(self):
        self.sis.responder["systemctl is-active"] = lambda args, entrada: Resultado(3, "inactive\n", "")
        r = self.sis.ejecutar(["systemctl", "is-active", "nginx"])
        self.assertEqual((r.codigo, r.salida, r.bien), (3, "inactive\n", False))
        self.assertTrue(self.sis.ejecutar(["true"]).bien, "lo que no tiene respuesta sale bien y sin salida")
        self.assertEqual(self.sis.ordenes, [["systemctl", "is-active", "nginx"], ["true"]])

    def test_sha256(self):
        self.assertEqual(sha256(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


if __name__ == "__main__":
    unittest.main()
