"""Lo quitado desde la app (contrato §12.10), del lado de quien escribe `tokens.json`: el instalador y
`hehermes-dispositivo`. La pasarela no puede escribirlo: lo apunta en su carpeta de estado (`quitados.json`) y los
demás lo sacan de `tokens.json` antes de tocarlo, para que el nombre quede libre y nada quitado vuelva a valer."""

import apoyo  # noqa: F401

import json
import os
import tempfile
import time
import unittest

import test_porchat
from hehermes_servidor import dispositivos as dis
from hehermes_servidor import modo_tls
from hehermes_servidor import pasarela as pa
from hehermes_servidor import recuperacion as rec
from hehermes_servidor import tokens
from test_recuperacion import ESTADO_PASARELA, TOKENS, VECTOR, clave_de, prueba


def quitar(carpeta, token, nombre):
    os.makedirs(carpeta, exist_ok=True)
    dis.Quitados(carpeta).quitar(pa.hash_token(token), nombre, time.time())


class ElFichero(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.carpeta.name, "tokens.json")
        self.estado = os.path.join(self.carpeta.name, "estado")
        self.uno = tokens.alta(self.ruta, "mi-iphone")
        self.otro = tokens.alta(self.ruta, "otro")

    def tearDown(self):
        self.carpeta.cleanup()

    def test_purgar_saca_solo_lo_quitado_y_deja_libre_el_nombre(self):
        quitar(self.estado, self.otro, "otro")
        antes = os.stat(self.ruta).st_mtime_ns
        self.assertEqual(tokens.purgar(self.ruta, set()), [])
        self.assertEqual(os.stat(self.ruta).st_mtime_ns, antes, "sin nada que sacar no se escribe")
        self.assertEqual(tokens.purgar(self.ruta, dis.hashes_quitados(self.estado)), ["otro"])
        self.assertEqual([t["nombre"] for t in tokens.lista(self.ruta)], ["mi-iphone"])
        nuevo = tokens.alta(self.ruta, "otro")
        tablero = pa.Tokens(self.ruta)
        tablero.poner_quitados(dis.hashes_quitados(self.estado))
        self.assertEqual((tablero.quien(nuevo), tablero.quien(self.otro), tablero.quien(self.uno)),
                         ("otro", None, "mi-iphone"))

    def test_la_lista_no_ensena_lo_quitado(self):
        quitar(self.estado, self.otro, "otro")
        self.assertEqual([t["nombre"] for t in tokens.lista(self.ruta, dis.hashes_quitados(self.estado))],
                         ["mi-iphone"])
        self.assertEqual(len(tokens.lista(self.ruta)), 2)

    def test_un_registro_roto_no_es_uno_vacio(self):
        os.makedirs(self.estado)
        with open(os.path.join(self.estado, dis.QUITADOS), "w") as f:
            f.write('{"v": 1, "tokens": {"no-es-un-hash": {}}}')
        self.assertIsNone(dis.hashes_quitados(self.estado))
        self.assertEqual(dis.hashes_quitados(os.path.join(self.carpeta.name, "no-esta")), set())


class VuelveConElCodigo(test_porchat.Base):
    """Un iPhone quitado desde la app vuelve con el código de recuperación: con su mismo nombre, un alta nueva (el
    nombre está libre), y su token de antes sigue sin valer."""

    def setUp(self):
        super().setUp()
        self.por_chat_de(3600)
        self.falso.usar("mi-iphone")
        carpeta = self.sis.ruta(ESTADO_PASARELA)
        os.makedirs(carpeta, exist_ok=True)
        rec.Registro(carpeta).cambiar(lambda e: rec.con_clave(e, clave_de(VECTOR["canonico"]), "mi-iphone",
                                                              time.time() - 600))
        self.viejo = tokens.rotar(self.sis.ruta(TOKENS), "mi-iphone")
        quitar(carpeta, self.viejo, "mi-iphone")

    def tablero(self):
        tablero = pa.Tokens(self.sis.ruta(TOKENS))
        tablero.poner_quitados(dis.hashes_quitados(self.sis.ruta(ESTADO_PASARELA)))
        return tablero

    def test_el_instalador_no_lo_cuenta(self):
        from hehermes_servidor import ambito
        self.assertEqual(modo_tls.nombres_de_la_pasarela(self.sis, ambito.de_root()), [])

    def test_vuelve_con_un_alta_nueva_y_lo_de_antes_sigue_sin_valer(self):
        codigo = self.por_chat("--recuperacion", prueba(VECTOR["canonico"], "mi-iphone"), iphone="mi-iphone")
        self.assertEqual(codigo, 0, self.salida)
        nuevo = self.carga()["t"]
        self.assertEqual(self.tablero().quien(nuevo), "mi-iphone")
        self.assertIsNone(self.tablero().quien(self.viejo))
        with open(self.sis.ruta(TOKENS)) as f:
            self.assertEqual([t["nombre"] for t in json.load(f)["tokens"]], ["mi-iphone"])


if __name__ == "__main__":
    unittest.main()
