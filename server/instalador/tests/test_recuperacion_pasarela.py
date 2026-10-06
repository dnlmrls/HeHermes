"""`/hehermes/v1/recuperacion` en la pasarela de verdad (spec 2026-10-06): la app pone ahí la clave pública de su código
de recuperación con el token de su iPhone, y lo mira. Lo contesta la pasarela misma: nunca llega a Hermes.

Como `test_pasarela_red`: hace falta poder escuchar en 127.0.0.1 (en el sandbox de Claude Code, fuera de él).
"""

import apoyo  # noqa: F401

import json
import os
import time
import unittest

from hehermes_servidor import recuperacion as rec
from test_pasarela_red import NO_404, OTRO, TOKEN, ConPasarela
from test_recuperacion import OTRO_CODIGO, VECTOR, clave_de

RUTA = "/hehermes/v1/recuperacion"


class LaRecuperacion(ConPasarela):
    def registro(self):
        return rec.Registro(self.c("estado"))

    def pedir(self, metodo="GET", token=TOKEN, cuerpo=None, crudo=None):
        datos = crudo if crudo is not None else (b"" if cuerpo is None else json.dumps(cuerpo).encode())
        return self.leer_respuesta(self.peticion(metodo=metodo, ruta=RUTA, token=token, cuerpo=datos))

    def poner(self, clave, token=TOKEN):
        return self.pedir("PUT", token=token, cuerpo={"clave": clave})

    def test_sin_token_el_404_de_siempre(self):
        for metodo in ("GET", "PUT"):
            with self.subTest(metodo=metodo):
                cuerpo = json.dumps({"clave": VECTOR["clave"]}).encode() if metodo == "PUT" else b""
                tls = self.peticion(metodo=metodo, ruta=RUTA, token=None, cuerpo=cuerpo)
                self.assertEqual(self.todo(tls), NO_404)
        self.assertEqual(self.registro().leer(), rec.vacio())

    def test_sin_codigo_dice_quien_pregunta_y_nada_mas(self):
        estado, cabeceras, cuerpo, _ = self.pedir()
        self.assertEqual(estado, 200)
        self.assertEqual(cabeceras["cache-control"], "no-store")
        datos = json.loads(cuerpo)
        self.assertIsNone(datos["clave"])
        self.assertEqual(datos["yo"], "mi-iphone")
        self.assertEqual(self.hermes.peticiones, [])

    def test_el_primero_lo_pone_y_otro_ya_no_lo_cambia(self):
        estado, _, cuerpo, _ = self.poner(VECTOR["clave"])
        self.assertEqual(estado, 200, cuerpo)
        self.assertEqual(json.loads(cuerpo)["clave"], VECTOR["clave"])
        guardado = self.registro().leer()
        self.assertEqual((guardado["clave"], guardado["por"]), (VECTOR["clave"], "mi-iphone"))
        self.assertEqual(os.stat(self.registro().ruta).st_mode & 0o777, 0o600)
        # Ni otro token ni el mismo: con un código puesto, solo lo cambia el de la recuperación en curso.
        for token in (OTRO, TOKEN):
            with self.subTest(token=token):
                estado, _, cuerpo, _ = self.poner(clave_de(OTRO_CODIGO), token=token)
                self.assertEqual(estado, 409)
                self.assertEqual(json.loads(cuerpo)["error"]["code"], "ya_hay_codigo")
        self.assertEqual(self.registro().leer()["clave"], VECTOR["clave"])
        self.assertEqual(self.hermes.peticiones, [])

    def test_el_de_la_recuperacion_en_curso_lo_cambia_por_otro(self):
        self.poner(VECTOR["clave"])
        self.registro().cambiar(lambda e: rec.con_exito(e, "otro", time.time()))
        self.assertEqual(self.poner(clave_de(OTRO_CODIGO), token=TOKEN)[0], 409)
        estado, _, cuerpo, _ = self.poner(clave_de(OTRO_CODIGO), token=OTRO)
        self.assertEqual(estado, 200, cuerpo)
        guardado = self.registro().leer()
        self.assertEqual((guardado["clave"], guardado["por"], guardado["en_curso"]),
                         (clave_de(OTRO_CODIGO), "otro", None))
        # La última recuperación se queda: es lo que avisan los demás iPhone.
        self.assertEqual(guardado["ultima"]["iphone"], "otro")
        # Y ya no lo puede volver a cambiar.
        self.assertEqual(self.poner(VECTOR["clave"], token=OTRO)[0], 409)

    def test_lo_que_no_es_una_clave(self):
        for crudo in (b"{", b"[]", json.dumps({"clave": "corta"}).encode(), json.dumps({"clave": None}).encode(),
                      json.dumps({"clave": VECTOR["clave"] + "="}).encode()):
            with self.subTest(crudo=crudo):
                self.assertEqual(self.pedir("PUT", crudo=crudo)[0], 400)
        self.assertEqual(self.pedir("PUT", crudo=b"x" * 2048)[0], 413)
        self.assertEqual(self.registro().leer(), rec.vacio())

    def test_un_registro_que_no_se_entiende_no_se_pisa(self):
        with open(self.registro().ruta, "w") as f:
            f.write("{roto")
        estado, _, cuerpo, _ = self.pedir()
        self.assertEqual((estado, json.loads(cuerpo)), (200, {"ilegible": True, "yo": "mi-iphone"}))
        self.assertEqual(self.poner(VECTOR["clave"])[0], 409)
        with open(self.registro().ruta) as f:
            self.assertEqual(f.read(), "{roto")

    def test_es_un_uso_de_la_pasarela(self):
        self.pedir()
        with open(self.c("estado/usos.json")) as f:
            usos = json.load(f)
        self.assertEqual([e["nombre"] for e in usos["tokens"].values()], ["mi-iphone"])


if __name__ == "__main__":
    unittest.main()
