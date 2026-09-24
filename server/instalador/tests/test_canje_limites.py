"""La máquina del canje, sin red: los dos pasos, que no se canjee dos veces y cada uno de sus límites.

El reloj es de mentira: ni una espera de verdad. Hace falta `cryptography` (el venv).
"""

import apoyo  # noqa: F401

import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hehermes_servidor import canje

HUELLA = bytes(range(32))
CODIGO = canje.b64url(bytes(range(16)))
CARGA = {"h": "203.0.113.7", "rid": "203.0.113.7", "lid": "mi-iphone", "k": "psk-de-prueba-que-no-es-de-nadie-1234"}
IP = "198.51.100.20"


class Reloj:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def pasa(self, segundos):
        self.t += segundos


class Base(unittest.TestCase):
    def setUp(self):
        self.privada = X25519PrivateKey.generate()
        self.llave = self.privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.reloj = Reloj()
        self.canje = canje.Canje(self.llave, CODIGO, HUELLA, json.dumps(CARGA).encode(), reloj=self.reloj)

    def pedir(self, ruta, cuerpo, ip=IP, pausa=1.0):
        self.reloj.pasa(pausa)
        datos = cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo).encode()
        return self.canje.atender(ruta, ip, datos)

    def abrir(self, proposito, sobre):
        privada = self.privada.private_bytes(Encoding.Raw, canje_formato_privado(), canje_sin_cifrar())
        return canje.abrir_con(privada, proposito, HUELLA, CODIGO, sobre)

    def reto(self, **kw):
        estado, respuesta = self.pedir("/canje/v1/reto", {"c": CODIGO}, **kw)
        self.assertEqual(estado, 200, respuesta)
        return self.abrir("reto", respuesta)

    def canjear(self, reto, **kw):
        return self.pedir("/canje/v1/canjear", {"c": CODIGO, "reto": base64.b64encode(reto).decode()}, **kw)

    def fallo(self, ip=IP):
        return self.pedir("/canje/v1/reto", {"c": "B" + CODIGO[1:]}, ip=ip)


def canje_formato_privado():
    from cryptography.hazmat.primitives.serialization import PrivateFormat
    return PrivateFormat.Raw


def canje_sin_cifrar():
    from cryptography.hazmat.primitives.serialization import NoEncryption
    return NoEncryption()


class DosPasos(Base):
    def test_de_punta_a_punta(self):
        reto = self.reto()
        self.assertEqual(len(reto), 32)
        self.assertFalse(self.canje.cerrado, "pedir el reto no gasta el código")
        estado, respuesta = self.canjear(reto)
        self.assertEqual(estado, 200)
        self.assertEqual(json.loads(self.abrir("psk", respuesta)), CARGA)
        self.assertTrue(self.canje.cerrado)
        self.assertEqual(self.canje.motivo, "canjeado")

    def test_no_se_canjea_dos_veces(self):
        reto = self.reto()
        self.assertEqual(self.canjear(reto)[0], 200)
        estado, respuesta = self.canjear(reto)
        self.assertEqual((estado, respuesta), (409, {"error": "canjeado"}))
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO})[0], 409)

    def test_la_psk_no_sale_nunca_sin_el_reto(self):
        for cuerpo in ({"c": CODIGO}, {"c": CODIGO, "reto": ""}, {"c": CODIGO, "reto": base64.b64encode(bytes(32)).decode()}):
            with self.subTest(cuerpo=cuerpo):
                estado, respuesta = self.pedir("/canje/v1/canjear", cuerpo, ip="192.0.2.%d" % len(str(cuerpo)))
                self.assertNotEqual(estado, 200)
                self.assertNotIn("t", respuesta)
        self.assertFalse(self.canje.cerrado)

    def test_un_reto_sin_pedir_es_un_fallo(self):
        self.canjear(bytes(32))
        self.assertEqual(self.canje.fallos, 1)

    def test_el_reto_viejo_no_vale_tras_pedir_otro(self):
        viejo = self.reto()
        nuevo = self.reto()
        self.assertNotEqual(viejo, nuevo)
        self.assertEqual(self.canjear(viejo)[0], 403)
        self.assertEqual(self.canjear(nuevo)[0], 200)

    def test_el_reto_va_cifrado_para_la_llave(self):
        estado, respuesta = self.pedir("/canje/v1/reto", {"c": CODIGO})
        otra = X25519PrivateKey.generate().private_bytes(Encoding.Raw, canje_formato_privado(), canje_sin_cifrar())
        with self.assertRaises(canje.ErrorDeCanje):
            canje.abrir_con(otra, "reto", HUELLA, CODIGO, respuesta)

    def test_otra_ruta_es_404_y_no_cuenta(self):
        self.assertEqual(self.pedir("/", b"")[0], 404)
        self.assertEqual(self.pedir("/canje/v1/otra", {"c": CODIGO})[0], 404)
        self.assertEqual(self.canje.fallos, 0)

    def test_json_roto_es_un_fallo(self):
        self.assertEqual(self.pedir("/canje/v1/reto", b"{no")[0], 403)
        self.assertEqual(self.pedir("/canje/v1/reto", [1, 2], ip="192.0.2.9")[0], 403)
        self.assertEqual(self.canje.fallos, 2)


class Caducidad(Base):
    def test_a_los_diez_minutos_se_cierra(self):
        self.reloj.pasa(canje.DURACION - 1.0)  # con la pausa de `pedir`, justo en el límite: aún vale
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO})[0], 200)
        self.assertFalse(self.canje.vencido())
        estado, respuesta = self.pedir("/canje/v1/reto", {"c": CODIGO}, pausa=0.001)
        self.assertEqual((estado, respuesta), (410, {"error": "caducado"}))
        self.assertTrue(self.canje.cerrado)
        self.assertEqual(self.canje.motivo, "caducado")

    def test_caducado_no_canjea_ni_con_el_reto_bueno(self):
        reto = self.reto()
        self.reloj.pasa(canje.DURACION)
        self.assertEqual(self.canjear(reto)[0], 410)

    def test_vencido_se_ve_sin_peticiones(self):
        self.reloj.pasa(canje.DURACION + 0.5)
        self.assertTrue(self.canje.vencido())


class Intentos(Base):
    def test_cinco_fallos_lo_cierran_y_cuatro_no(self):
        for i in range(canje.MAX_FALLOS - 1):
            self.assertEqual(self.fallo(ip="192.0.2.%d" % i)[0], 403)
        self.assertFalse(self.canje.cerrado)
        estado, respuesta = self.fallo(ip="192.0.2.99")
        self.assertEqual((estado, respuesta), (429, {"error": "demasiados_intentos"}))
        self.assertTrue(self.canje.cerrado)
        self.assertEqual(self.canje.motivo, "demasiados_intentos")
        # Cerrado, ni el código bueno sirve.
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO}, ip="192.0.2.200")[0], 429)

    def test_tres_de_una_ip_lo_cierran_y_dos_no(self):
        for _ in range(canje.MAX_FALLOS_POR_IP - 1):
            self.assertEqual(self.fallo()[0], 403)
        self.assertFalse(self.canje.cerrado)
        self.assertEqual(self.fallo()[0], 429)
        self.assertTrue(self.canje.cerrado)

    def test_cada_fallo_dice_cuantos_quedan(self):
        self.assertEqual(self.fallo(ip="192.0.2.1")[1], {"error": "no_vale", "quedan": canje.MAX_FALLOS - 1})

    def test_un_reto_malo_cuenta(self):
        self.reto()
        for i in range(canje.MAX_FALLOS):
            self.canjear(bytes([i]) * 32, ip="192.0.2.%d" % i)
        self.assertTrue(self.canje.cerrado)


class Pausa(Base):
    def test_una_por_segundo_y_por_ip(self):
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO})[0], 200)
        estado, respuesta = self.pedir("/canje/v1/reto", {"c": CODIGO}, pausa=0.5)
        self.assertEqual((estado, respuesta), (429, {"error": "despacio"}))
        self.assertEqual(self.canje.fallos, 0, "ir deprisa no es un fallo")
        self.assertFalse(self.canje.cerrado)
        # Otra IP no espera, y la misma, pasado el segundo, tampoco.
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO}, ip="192.0.2.5", pausa=0.0)[0], 200)
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO}, pausa=1.0)[0], 200)

    def test_la_pausa_cuenta_desde_la_ultima_aunque_se_rechazara(self):
        self.pedir("/canje/v1/reto", {"c": CODIGO})
        self.pedir("/canje/v1/reto", {"c": CODIGO}, pausa=0.6)
        self.assertEqual(self.pedir("/canje/v1/reto", {"c": CODIGO}, pausa=0.6)[0], 429)


if __name__ == "__main__":
    unittest.main()
