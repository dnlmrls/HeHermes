"""Los tokens de la pasarela (`tokens.py`): lo que escriben el instalador y `hehermes-dispositivo`, y lo que lee la
pasarela. Del token solo se guarda su hash: el QR no se puede volver a pintar."""

import apoyo  # noqa: F401

import json
import os
import stat
import tempfile
import unittest

from hehermes_servidor import pasarela as pa
from hehermes_servidor import tokens

HUELLA = "vrXpqZOgQjS050NyWV-byRxAgZ8aayoC6hrPdwP2dGY"


class ConCarpeta(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.carpeta.name, "tokens.json")

    def tearDown(self):
        self.carpeta.cleanup()


class ElFichero(ConCarpeta):
    def test_el_alta_da_un_token_que_la_pasarela_acepta_y_no_lo_guarda(self):
        token = tokens.alta(self.ruta, "mi-iphone")
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        with open(self.ruta) as f:
            texto = f.read()
        self.assertNotIn(token, texto)
        self.assertEqual(pa.Tokens(self.ruta).quien(token), "mi-iphone")
        datos = json.loads(texto)
        self.assertEqual(datos["v"], 1)
        self.assertEqual(datos["tokens"][0]["sha256"], pa.hash_token(token))

    def test_nuevo_sale_0600(self):
        tokens.alta(self.ruta, "mi-iphone")
        self.assertEqual(stat.S_IMODE(os.stat(self.ruta).st_mode), 0o600)

    def test_al_reescribir_conserva_el_modo(self):
        tokens.guardar(self.ruta, {"v": 1, "tokens": []}, modo=0o640)
        tokens.alta(self.ruta, "mi-iphone")
        self.assertEqual(stat.S_IMODE(os.stat(self.ruta).st_mode), 0o640)

    def test_dos_con_el_mismo_nombre_no(self):
        tokens.alta(self.ruta, "mi-iphone")
        with self.assertRaises(ValueError):
            tokens.alta(self.ruta, "mi-iphone")

    def test_un_nombre_que_no_vale(self):
        for malo in ("", "Mi-iPhone", "-a", "a" * 32, "a b", "a/b"):
            with self.subTest(malo=malo):
                with self.assertRaises(ValueError):
                    tokens.alta(self.ruta, malo)

    def test_la_baja_lo_invalida(self):
        uno = tokens.alta(self.ruta, "mi-iphone")
        otro = tokens.alta(self.ruta, "otro")
        self.assertTrue(tokens.baja(self.ruta, "mi-iphone"))
        leidos = pa.Tokens(self.ruta)
        self.assertIsNone(leidos.quien(uno))
        self.assertEqual(leidos.quien(otro), "otro")
        self.assertFalse(tokens.baja(self.ruta, "mi-iphone"))

    def test_rotar_da_otro_y_el_de_antes_deja_de_valer(self):
        viejo = tokens.alta(self.ruta, "mi-iphone")
        nuevo = tokens.rotar(self.ruta, "mi-iphone")
        self.assertNotEqual(viejo, nuevo)
        leidos = pa.Tokens(self.ruta)
        self.assertIsNone(leidos.quien(viejo))
        self.assertEqual(leidos.quien(nuevo), "mi-iphone")
        self.assertIn("rotado", tokens.lista(self.ruta)[0])
        with self.assertRaises(ValueError):
            tokens.rotar(self.ruta, "no-esta")

    def test_la_lista_no_lleva_los_hashes(self):
        tokens.alta(self.ruta, "mi-iphone", ahora="2026-09-26T10:00:00+00:00")
        self.assertEqual(tokens.lista(self.ruta), [{"nombre": "mi-iphone", "alta": "2026-09-26T10:00:00+00:00"}])

    def test_un_fichero_roto_no_se_pisa(self):
        with open(self.ruta, "w") as f:
            f.write("{roto")
        with self.assertRaises(ValueError):
            tokens.alta(self.ruta, "mi-iphone")
        with open(self.ruta) as f:
            self.assertEqual(f.read(), "{roto")

    def test_no_escribe_a_traves_de_un_enlace(self):
        destino = os.path.join(self.carpeta.name, "otro-sitio")
        with open(destino, "w") as f:
            f.write("de otro")
        os.symlink(destino, self.ruta)
        with self.assertRaises(ValueError):
            tokens.alta(self.ruta, "mi-iphone")
        with open(destino) as f:
            self.assertEqual(f.read(), "de otro")


class ElTextoDelQR(unittest.TestCase):
    TOKEN = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"

    def test_es_el_del_contrato(self):
        self.assertEqual(tokens.texto_qr("203.0.113.7", 61234, HUELLA, self.TOKEN),
                         "hehermes-tls:1?h=203.0.113.7&p=61234&f=%s&t=%s" % (HUELLA, self.TOKEN))

    def test_lo_que_no_vale_no_se_escribe(self):
        for args in (("203.0.113.7 ", 61234, HUELLA, self.TOKEN), ("-a", 61234, HUELLA, self.TOKEN),
                     ("a&t=b", 61234, HUELLA, self.TOKEN), ("203.0.113.7", 0, HUELLA, self.TOKEN),
                     ("203.0.113.7", 70000, HUELLA, self.TOKEN), ("203.0.113.7", 61234, HUELLA[:-1], self.TOKEN),
                     ("203.0.113.7", 61234, HUELLA, self.TOKEN + "A"), ("203.0.113.7", "61234", HUELLA, self.TOKEN)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    tokens.texto_qr(*args)


if __name__ == "__main__":
    unittest.main()
