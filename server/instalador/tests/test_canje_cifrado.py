"""El sobre del canje, contra el vector que comparte con la app (`HeHermesMensajesTests/Fixtures/canje-vpn.json`).

El vector lo abre la app con CryptoKit (`CanjeDelChatTests`): si uno de los dos lados cambia la construcción, falla uno
de los dos. Hace falta `cryptography` (el venv de los avisos o el del canje): sin él, este fichero no importa.
"""

import apoyo

import base64
import hashlib
import json
import re
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hehermes_servidor import canje

_RUTA_VECTOR = apoyo.APP / "HeHermesMensajesTests" / "Fixtures" / "canje-vpn.json"
VECTOR = json.loads(_RUTA_VECTOR.read_text()) if _RUTA_VECTOR.exists() else None
SIN_VECTOR = "el vector es de la app, que no está aquí (el espejo público solo lleva el instalador)"


def b(texto):
    return base64.b64decode(texto)


@unittest.skipUnless(VECTOR, SIN_VECTOR)
class Vector(unittest.TestCase):
    def setUp(self):
        self.v = VECTOR
        self.huella = canje.de_b64url(self.v["huella"], 32)

    def sellar(self, caso):
        return canje.sellar_para(b(self.v["publica_del_iphone"]), caso["proposito"], self.huella, self.v["codigo"],
                                 b(caso["claro"]), efimera=b(caso["efimera_privada"]), nonce=b(caso["nonce"]))

    def test_la_publica_es_la_de_la_privada(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        privada = X25519PrivateKey.from_private_bytes(b(self.v["privada_del_iphone"]))
        self.assertEqual(privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                         b(self.v["publica_del_iphone"]))
        self.assertEqual(canje.b64url(b(self.v["publica_del_iphone"])), self.v["llave_de_la_frase"])

    def test_cada_sobre_sale_byte_a_byte_como_en_el_vector(self):
        for caso in self.v["sobres"]:
            with self.subTest(proposito=caso["proposito"]):
                self.assertEqual(self.sellar(caso), caso["sobre"])

    def test_la_privada_del_iphone_abre_cada_sobre(self):
        for caso in self.v["sobres"]:
            with self.subTest(proposito=caso["proposito"]):
                claro = canje.abrir_con(b(self.v["privada_del_iphone"]), caso["proposito"], self.huella,
                                        self.v["codigo"], caso["sobre"])
                self.assertEqual(claro, b(caso["claro"]))

    def test_la_carga_es_la_del_qr(self):
        carga = json.loads(b(self.v["sobres"][1]["claro"]))
        self.assertEqual(sorted(carga), ["h", "k", "lid", "rid"])

    def test_la_huella_es_la_del_spki_del_certificado(self):
        cert = x509.load_der_x509_certificate(b(self.v["certificado"]))
        spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(canje.huella_spki(spki), self.v["huella"])
        self.assertEqual(self.v["huella"], base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).rstrip(b"=").decode())

    def test_el_codigo_es_de_128_bits_en_22_caracteres(self):
        self.assertEqual(len(canje.de_b64url(self.v["codigo"], 16)), 16)
        nuevo = canje.codigo_nuevo()
        self.assertRegex(nuevo, r"^[A-Za-z0-9_-]{22}$")
        self.assertNotEqual(nuevo, canje.codigo_nuevo())


@unittest.skipUnless(VECTOR, SIN_VECTOR)
class LoQueNoSeAbre(unittest.TestCase):
    """El HKDF lleva la huella, el código y el propósito: un sobre de otro servidor, de otro canje o del otro paso no
    se abre, aunque sea para la misma llave."""

    def setUp(self):
        self.v = VECTOR
        self.huella = canje.de_b64url(self.v["huella"], 32)
        self.privada = b(self.v["privada_del_iphone"])
        self.caso = self.v["sobres"][1]

    def no_se_abre(self, privada=None, proposito=None, huella=None, codigo=None, sobre=None):
        with self.assertRaises(canje.ErrorDeCanje):
            canje.abrir_con(privada or self.privada, proposito or self.caso["proposito"], huella or self.huella,
                            codigo or self.v["codigo"], sobre or self.caso["sobre"])

    def test_con_otra_huella(self):
        self.no_se_abre(huella=bytes(32))

    def test_con_otro_codigo(self):
        self.no_se_abre(codigo="B" + self.v["codigo"][1:])

    def test_con_el_proposito_del_otro_paso(self):
        self.no_se_abre(proposito="reto")

    def test_con_otra_llave(self):
        self.no_se_abre(privada=bytes([7]) * 32)

    def test_tocado_por_el_camino(self):
        sobre = dict(self.caso["sobre"])
        t = bytearray(b(sobre["t"]))
        t[0] ^= 1
        sobre["t"] = base64.b64encode(bytes(t)).decode()
        self.no_se_abre(sobre=sobre)

    def test_de_otra_version(self):
        self.no_se_abre(sobre=dict(self.caso["sobre"], v=2))

    def test_una_llave_mal_escrita_no_se_acepta(self):
        for mala in ("", "corta", self.v["llave_de_la_frase"] + "A", self.v["llave_de_la_frase"][:-1] + "=",
                     self.v["llave_de_la_frase"].replace(self.v["llave_de_la_frase"][0], "+", 1)):
            with self.subTest(mala=mala), self.assertRaises(canje.ErrorDeCanje):
                canje.de_b64url(mala, 32)

    def test_cada_sobre_lleva_una_efimera_y_un_nonce_nuevos(self):
        uno = canje.sellar_para(b(self.v["publica_del_iphone"]), "psk", self.huella, self.v["codigo"], b"x")
        otro = canje.sellar_para(b(self.v["publica_del_iphone"]), "psk", self.huella, self.v["codigo"], b"x")
        self.assertNotEqual(uno["e"], otro["e"])
        self.assertNotEqual(uno["n"], otro["n"])


class Dependencias(unittest.TestCase):
    def test_las_del_canje_son_las_de_los_avisos(self):
        """Las mismas versiones y hashes: una sola lista que revisar, y un venv del canje que no trae nada nuevo."""
        avisos = (apoyo.REPO / "server" / "avisos" / "requirements.txt").read_text()
        canje_ = (apoyo.RAIZ / "requirements-canje.txt").read_text()

        def bloques(texto):
            return {m.group(1): m.group(0).strip() for m in
                    re.finditer(r"^([a-z0-9_-]+)==[^\n]*\\\n(?:\s+--hash=sha256:[0-9a-f]{64}(?: \\)?\n?)+", texto, re.M)}

        de_avisos, del_canje = bloques(avisos), bloques(canje_)
        self.assertEqual(sorted(del_canje), ["cffi", "cryptography", "pycparser"])
        for paquete, bloque in del_canje.items():
            self.assertEqual(bloque, de_avisos[paquete], paquete)


if __name__ == "__main__":
    unittest.main()
