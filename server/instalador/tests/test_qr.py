"""El QR propio (`qr.py`), contra `segno` cuando está en el venv de las pruebas (no se instala en el servidor).

Sin root no hay paquetes, así que el QR del alta no puede depender de `qrencode`: lo pinta el instalador. Un QR con un
fallo sutil no lo lee nadie, y aquí no hay un lector: por eso se compara módulo a módulo con otra implementación, con
la misma versión, el mismo nivel y la misma máscara.
"""

import apoyo  # noqa: F401

import unittest

from hehermes_servidor import qr

try:
    import segno
    import segno.encoder

    def _relleno_de_la_norma(buff, version, length):
        """segno 1.6.6 añade ocho ceros cuando el flujo ya acaba en un byte (`8 - length % 8`); la norma, ninguno.
        Los dos QR se leen igual (lo de detrás del terminador no cuenta), pero para comparar módulo a módulo hace
        falta el mismo relleno."""
        buff.extend([0] * (-length % 8))

    segno.encoder.write_padding_bits = _relleno_de_la_norma
except ImportError:  # pragma: no cover
    segno = None

URL = "hehermes-tls:1?h=203.0.113.7&p=61234&f=vrXpqZOgQjS050NyWV-byRxAgZ8aayoC6hrPdwP2dGY&t=QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
TEXTOS = ["a", "hola", URL, URL.replace("203.0.113.7", "servidor-con-un-nombre-muy-largo." * 4 + "example.org"),
          "x" * 300, "ñ" * 200, "0123456789" * 90]


def de_segno(texto, nivel, mascara=None, version=None):
    hecho = segno.make_qr(texto.encode("utf-8"), error=nivel.lower(), mask=mascara, version=version, mode="byte",
                          boost_error=False, eci=False)
    return hecho, [[bool(m) for m in fila] for fila in hecho.matrix_iter(scale=1, border=0)]


@unittest.skipUnless(segno, "segno no está en este venv (pip install segno, solo para las pruebas)")
class ComoSegno(unittest.TestCase):
    def test_la_misma_matriz_con_cada_mascara_y_nivel(self):
        for texto in TEXTOS:
            for nivel in ("L", "M"):
                for mascara in range(8):
                    with self.subTest(texto=texto[:20], largo=len(texto), nivel=nivel, mascara=mascara):
                        hecho, esperada = de_segno(texto, nivel, mascara)
                        mia = qr.matriz(texto, nivel=nivel, mascara=mascara)
                        self.assertEqual(len(mia), len(esperada), "otra versión")
                        self.assertEqual(mia, esperada)

    def test_elige_la_misma_version(self):
        for largo in (1, 14, 15, 26, 27, 42, 43, 62, 63, 84, 85, 106, 107, 122, 123, 152, 153, 180, 181, 213, 214, 251,
                      252, 287, 288, 331, 332, 362, 363, 412, 413, 450, 451, 504, 505, 560, 561, 624, 625, 666, 667):
            with self.subTest(largo=largo):
                texto = "k" * largo
                hecho, _ = de_segno(texto, "M")
                self.assertEqual(qr.version_para(len(texto.encode()), "M"), hecho.version)

    def test_las_versiones_altas_tambien(self):
        for version in (21, 27, 33, 40):
            texto = "z" * (qr.capacidad(version, "L") - 3)
            with self.subTest(version=version):
                _, esperada = de_segno(texto, "L", 5, version)
                self.assertEqual(qr.matriz(texto, nivel="L", mascara=5, version=version), esperada)


class SinSegno(unittest.TestCase):
    def test_la_mascara_elegida_es_una_de_las_ocho(self):
        elegida = qr.matriz(URL)
        self.assertIn(elegida, [qr.matriz(URL, mascara=m) for m in range(8)])

    def test_los_tres_localizadores_estan_en_su_sitio(self):
        m = qr.matriz(URL)
        n = len(m)
        for x, y in ((0, 0), (n - 7, 0), (0, n - 7)):
            self.assertTrue(all(m[y][x + i] and m[y + 6][x + i] and m[y + i][x] and m[y + i][x + 6]
                                for i in range(7)))
            self.assertTrue(all(m[y + 2 + i][x + 2 + j] for i in range(3) for j in range(3)))

    def test_demasiado_largo(self):
        with self.assertRaises(ValueError):
            qr.matriz("x" * 3000)

    def test_en_el_terminal_negro_sobre_blanco_con_su_margen(self):
        texto = qr.terminal(URL)
        lineas = texto.rstrip("\n").split("\n")
        n = len(qr.matriz(URL)) + 2 * qr.MARGEN
        self.assertEqual(len(lineas), (n + 1) // 2)
        for linea in lineas:
            self.assertTrue(linea.startswith("\033[30;47m") and linea.endswith("\033[0m"))
            self.assertEqual(len(linea) - len("\033[30;47m") - len("\033[0m"), n)
        self.assertEqual(set(texto) - set("\033[0;3456789m\n"), set(" ▀▄█"))


if __name__ == "__main__":
    unittest.main()
