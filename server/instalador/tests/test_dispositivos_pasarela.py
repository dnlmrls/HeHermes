"""`/hehermes/v1/dispositivos` en la pasarela de verdad (contrato §12.10): la lista de los iPhone conectados y quitar
uno desde la app, solo con el token de un iPhone dado de alta. Lo contesta la pasarela misma: nunca llega a Hermes.

Como `test_pasarela_red`: hace falta poder escuchar en 127.0.0.1 (en el sandbox de Claude Code, fuera de él).
"""

import apoyo  # noqa: F401

import asyncio
import json
import os
import socket
import time
import unittest

from hehermes_servidor import dispositivos as dis
from hehermes_servidor import pasarela as pa
from test_pasarela_red import NO_404, OTRO, SECRETO_VIGIA, TLS_MINIMO, TOKEN, ConPasarela, Falso

RUTA = "/hehermes/v1/dispositivos"
#: Los mismos vectores que `server/avisos/tests/test_iphones_quitados.py`: el vigía comprueba estas firmas. La marca es
#: la del token `TOKEN` de estas pruebas.
SECRETO_DE_LOS_AVISOS = "secreto-del-tunel-de-las-pruebas"
MARCA = "fe630d8b4886c568"
IPHONE_FIRMADO = "iphone-1a2b fe630d8b4886c568 SeEdDWbslm9RdOXzsI0H4Lx19riABcljhJCR8TyZU1w"
FIRMA_DEL_BARRIDO = "0kuqdgxlfxtnCS8_6Q0QGT6BdJhcYxxSZ2u0PzeQNr0"


def marca(token):
    return dis.marca_del_token(pa.hash_token(token))


class LosVectores(unittest.TestCase):
    def test_las_firmas_son_las_que_comprueba_el_vigia(self):
        self.assertEqual(marca(TOKEN), MARCA)
        self.assertEqual(dis.cabecera_del_iphone(SECRETO_DE_LOS_AVISOS, "iphone-1a2b", MARCA), IPHONE_FIRMADO)
        self.assertEqual(dis.firma_del_barrido(SECRETO_DE_LOS_AVISOS, b'{"quedan":["fe630d8b4886c568"]}'),
                         FIRMA_DEL_BARRIDO)

    def test_la_marca_no_es_ni_el_token_ni_su_hash_y_cambia_con_cada_uno(self):
        self.assertRegex(MARCA, dis.MARCA)
        self.assertNotIn(MARCA, (TOKEN, pa.hash_token(TOKEN)))
        self.assertNotIn(MARCA, pa.hash_token(TOKEN))
        self.assertNotEqual(marca(TOKEN), marca(OTRO))


class LosIPhoneConectados(ConPasarela):
    def pedir(self, metodo="GET", ruta=RUTA, token=TOKEN, cuerpo=b"", extra=""):
        return self.leer_respuesta(self.peticion(metodo=metodo, ruta=ruta, token=token, cuerpo=cuerpo, extra=extra))

    def quitar(self, nombre, token=TOKEN, consulta=""):
        return self.pedir("DELETE", "%s/%s%s" % (RUTA, nombre, consulta), token=token)

    def quitados(self):
        return dis.Quitados(self.c("estado")).leer()

    def barridos(self):
        return [p for p in self.vigia.peticiones if p["ruta"] == dis.RUTA_DEL_VIGIA]

    # Quién puede

    def test_sin_un_token_de_alta_el_404_de_siempre_y_nada_cambia(self):
        for token in (None, "x" * 43, "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9"):
            for metodo, ruta in (("GET", RUTA), ("DELETE", RUTA + "/otro"), ("DELETE", RUTA + "/mi-iphone")):
                with self.subTest(token=token, metodo=metodo, ruta=ruta):
                    self.assertEqual(self.todo(self.peticion(metodo, ruta, token=token)), NO_404)
        self.assertFalse(os.path.exists(self.c("estado/" + dis.QUITADOS)))
        self.assertEqual(self.pedir(token=OTRO)[0], 200)
        self.assertEqual((self.hermes.peticiones, self.barridos()), ([], []))

    # La lista

    def test_la_lista_sin_tokens_ni_hashes(self):
        estado, cabeceras, cuerpo, crudo = self.pedir()
        self.assertEqual(estado, 200)
        self.assertEqual(cabeceras["cache-control"], "no-store")
        datos = json.loads(cuerpo)
        self.assertEqual(set(datos), {"iphones", "recuperacion"})
        self.assertEqual([(i["nombre"], i["este"]) for i in datos["iphones"]], [("mi-iphone", True), ("otro", False)])
        for iphone in datos["iphones"]:
            self.assertEqual(set(iphone), {"nombre", "alta", "uso", "este"})
        for secreto in (TOKEN, OTRO, pa.hash_token(TOKEN), pa.hash_token(OTRO)):
            self.assertNotIn(secreto.encode(), crudo)
        self.assertIs(datos["recuperacion"], False)
        self.assertEqual(self.hermes.peticiones, [])

    def test_este_es_el_del_token_que_pregunta(self):
        datos = json.loads(self.pedir(token=OTRO)[2])
        self.assertEqual([i["nombre"] for i in datos["iphones"] if i["este"]], ["otro"])

    def test_el_alta_y_el_ultimo_uso(self):
        self.escribir_tokens([("mi-iphone", TOKEN), ("otro", OTRO)])
        with open(self.c("tokens.json")) as f:
            datos = json.load(f)
        datos["tokens"][1]["alta"] = "2026-10-01T10:00:00+00:00"
        datos["tokens"][1]["rotado"] = "2026-10-03T10:00:00+00:00"
        with open(self.c("tokens.json"), "w") as f:
            json.dump(datos, f)
        antes = int(time.time())
        iphones = {i["nombre"]: i for i in json.loads(self.pedir()[2])["iphones"]}
        self.assertGreaterEqual(iphones["mi-iphone"]["uso"], antes)
        self.assertIsNone(iphones["otro"]["uso"])
        import datetime
        rotado = datetime.datetime(2026, 10, 3, 10, tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(iphones["otro"]["alta"], int(rotado), "el de su token de ahora: el que se rotó")
        self.assertIsNone(iphones["mi-iphone"]["alta"])

    def test_con_codigo_de_recuperacion_lo_dice(self):
        from hehermes_servidor import recuperacion as rec
        rec.Registro(self.c("estado")).cambiar(lambda e: rec.con_clave(e, "A" * 43, "mi-iphone", time.time()))
        self.assertIs(json.loads(self.pedir()[2])["recuperacion"], True)

    # Quitar

    def test_quitar_otro_vale_al_momento(self):
        estado, _, cuerpo, _ = self.quitar("otro")
        self.assertEqual(estado, 200, cuerpo)
        self.assertEqual(json.loads(cuerpo), {"quitado": "otro", "este": False, "avisos": "borradas"})
        self.assertEqual(self.todo(self.peticion(token=OTRO)), NO_404)
        self.assertEqual(self.pedir()[0], 200)
        quitados = self.quitados()
        self.assertEqual(list(quitados["tokens"]), [pa.hash_token(OTRO)])
        self.assertEqual(os.stat(self.c("estado/" + dis.QUITADOS)).st_mode & 0o777, 0o600)
        self.assertEqual([i["nombre"] for i in json.loads(self.pedir()[2])["iphones"]], ["mi-iphone"])
        # Y sigue sin valer después de reiniciar la pasarela, aunque siga en tokens.json.
        otra = pa.Pasarela(pa.Configuracion.leer(self.c("pasarela.ini")), diario=lambda _: None,
                           tls_minimo=TLS_MINIMO)
        self.assertIsNone(otra.tokens.quien(OTRO))
        self.assertEqual(otra.tokens.quien(TOKEN), "mi-iphone")
        self.assertEqual(self.hermes.peticiones, [])

    def test_sus_altas_de_avisos_se_borran_en_el_vigia_con_la_firma(self):
        self.quitar("otro")
        [barrido] = self.barridos()
        self.assertEqual(barrido["metodo"], "POST")
        self.assertEqual(json.loads(barrido["cuerpo"]), {"quedan": [marca(TOKEN)]})
        cabeceras = {k.lower(): v for k, v in barrido["lista"]}
        self.assertEqual(cabeceras["x-hehermes-vigia"], SECRETO_VIGIA)
        self.assertEqual(cabeceras["x-hehermes-firma"], dis.firma_del_barrido(SECRETO_VIGIA, barrido["cuerpo"]))
        self.assertFalse(self.quitados()["barrer"])

    def test_quitar_corta_lo_que_tenia_abierto(self):
        tls = self.peticion(ruta="/v1/runs/r1/events", token=OTRO)
        tls.settimeout(5)
        recibido = b""
        while b'"n": 0' not in recibido:
            recibido += tls.recv(65536)
        inicio = time.monotonic()
        self.assertEqual(self.quitar("otro")[0], 200)
        self.hermes.sse_siguiente.set()
        resto = self.todo(tls)
        self.assertLess(time.monotonic() - inicio, 2)
        self.assertNotIn(b'"n": 1', resto)

    def test_quitarse_a_si_mismo_contesta_y_cierra(self):
        tls = self.peticion("DELETE", RUTA + "/mi-iphone")
        estado, cabeceras, cuerpo, _ = self.leer_respuesta(tls)
        self.assertEqual((estado, json.loads(cuerpo)), (200, {"quitado": "mi-iphone", "este": True,
                                                              "avisos": "borradas"}))
        self.assertEqual(cabeceras["connection"], "close")
        self.assertEqual(self.todo(tls), b"")
        self.assertEqual(self.todo(self.peticion()), NO_404)
        self.assertEqual(self.pedir(token=OTRO)[0], 200)

    def test_el_ultimo_solo_confirmandolo(self):
        self.quitar("otro")
        estado, _, cuerpo, _ = self.quitar("mi-iphone")
        self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (409, "es_el_ultimo"))
        self.assertEqual(self.pedir()[0], 200)
        estado, _, cuerpo, _ = self.quitar("mi-iphone", consulta="?ultimo=si")
        self.assertEqual((estado, json.loads(cuerpo)["este"]), (200, True))
        self.assertEqual(self.todo(self.peticion()), NO_404)
        self.assertEqual(json.loads(self.barridos()[-1]["cuerpo"]), {"quedan": []})

    def test_lo_que_no_esta(self):
        for nombre in ("nadie", "Mi-iphone", "mi-iphone/x", "..", "%2e%2e", "a" * 40):
            with self.subTest(nombre=nombre):
                estado, cabeceras, cuerpo, _ = self.quitar(nombre)
                self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (404, "dispositivo_desconocido"))
                self.assertEqual(cabeceras["content-type"], "application/json")
        self.quitar("otro")
        self.assertEqual(self.quitar("otro")[0], 404)
        self.assertEqual(self.pedir()[0], 200)

    def test_otros_metodos_y_cuerpos(self):
        self.assertEqual(self.pedir("POST", cuerpo=b"{}")[0], 405)
        self.assertEqual(self.pedir("PUT", RUTA + "/otro", cuerpo=b"{}")[0], 405)
        self.assertEqual(self.pedir("DELETE", RUTA + "/otro", cuerpo=b"{}")[0], 400)
        self.assertEqual(self.pedir("DELETE", RUTA)[0], 405)
        self.assertEqual(self.pedir(token=OTRO)[0], 200)

    def test_las_peticiones_al_vigia_llevan_su_iphone_firmado(self):
        self.leer_respuesta(self.peticion(ruta="/avisos/v1/salud", extra="X-HeHermes-Iphone: otro falsa\r\n"
                                                                         "X-HeHermes-Firma: falsa\r\n"))
        vista = self.vigia.peticiones[-1]
        self.assertEqual([v for k, v in vista["lista"] if k.lower() == "x-hehermes-iphone"],
                         [dis.cabecera_del_iphone(SECRETO_VIGIA, "mi-iphone", marca(TOKEN))])
        self.assertFalse([k for k, _ in vista["lista"] if k.lower() == "x-hehermes-firma"])

    def test_un_registro_que_no_se_entiende_no_deja_pasar_a_nadie(self):
        with open(self.c("estado/" + dis.QUITADOS), "w") as f:
            f.write("{roto")
        otra = pa.Pasarela(pa.Configuracion.leer(self.c("pasarela.ini")), diario=lambda _: None,
                           tls_minimo=TLS_MINIMO)
        self.assertIsNone(otra.tokens.quien(TOKEN))
        self.assertIsNone(otra.tokens.quien(OTRO))

    def test_si_no_se_puede_apuntar_no_se_quita(self):
        os.chmod(self.c("estado"), 0o500)
        try:
            estado, _, cuerpo, _ = self.quitar("otro")
        finally:
            os.chmod(self.c("estado"), 0o700)
        self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (503, "dispositivos_no_disponible"))
        self.assertEqual(self.pedir(token=OTRO)[0], 200)

    def test_si_el_vigia_no_contesta_se_vuelve_a_pedir(self):
        self.vigia.shutdown()
        self.vigia.server_close()
        estado, _, cuerpo, _ = self.quitar("otro")
        self.assertEqual((estado, json.loads(cuerpo)["avisos"]), (200, "pendiente"))
        self.assertTrue(self.quitados()["barrer"])
        self.assertIsNone(self.p.tokens.quien(OTRO))
        # Vuelve el vigía: el siguiente intento borra (con los que siguen ahora) y ya no queda pendiente.
        self.vigia = Falso()
        import threading
        threading.Thread(target=self.vigia.serve_forever, args=(0.05,), daemon=True).start()
        self.p.config.vigia = ("127.0.0.1", self.vigia.puerto)
        hecho = asyncio.run_coroutine_threadsafe(self.p.borrar_en_el_vigia(), self.bucle).result(10)
        self.assertEqual(hecho, "borradas")
        self.assertEqual(json.loads(self.barridos()[-1]["cuerpo"]), {"quedan": [marca(TOKEN)]})
        self.assertFalse(self.quitados()["barrer"])

    def test_si_el_vigia_tiene_un_aviso_por_mandar_se_vuelve_a_pedir(self):
        """El `409` del vigía mientras le queda por mandar el aviso del código de recuperación: como si no contestara."""
        self.vigia.estado_fijo = 409
        estado, _, cuerpo, _ = self.quitar("otro")
        self.assertEqual((estado, json.loads(cuerpo)["avisos"]), (200, "pendiente"))
        self.assertTrue(self.quitados()["barrer"])
        self.vigia.estado_fijo = None
        hecho = asyncio.run_coroutine_threadsafe(self.p.borrar_en_el_vigia(), self.bucle).result(10)
        self.assertEqual(hecho, "borradas")
        self.assertFalse(self.quitados()["barrer"])

    def test_el_mismo_nombre_con_otro_token_es_otro_dueno(self):
        """Rotado (o vuelto con el código), el nombre sigue, pero las altas del token de antes ya no son de nadie que
        siga: el barrido manda la marca del de ahora, y la del de antes no está."""
        from hehermes_servidor import tokens
        nuevo = tokens.rotar(self.c("tokens.json"), "otro")
        self.assertEqual(self.quitar("mi-iphone")[0], 200)
        [barrido] = self.barridos()
        self.assertEqual(json.loads(barrido["cuerpo"]), {"quedan": [marca(nuevo)]})
        self.assertNotIn(marca(OTRO), json.loads(barrido["cuerpo"])["quedan"])


class SinAvisos(ConPasarela):
    con_vigia = False

    def test_sin_vigia_no_hay_altas_que_borrar(self):
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion("DELETE", RUTA + "/otro"))
        self.assertEqual((estado, json.loads(cuerpo)["avisos"]), (200, "sin_avisos"))
        self.assertFalse(dis.Quitados(self.c("estado")).leer()["barrer"])


class SinCarpetaDeEstado(unittest.TestCase):
    def test_sin_carpeta_no_hay_lista_ni_quitar(self):
        class Config:
            tokens = "/no/existe/tokens.json"
            mantenimiento = None

        p = pa.Pasarela.__new__(pa.Pasarela)
        p.tokens = pa.Tokens(Config.tokens)
        p._preparar_dispositivos(None)
        self.assertIsNone(p.quitados)

    def test_la_entrada_del_rele_no_tiene_la_ruta(self):
        """El relé reutiliza la pasarela con las credenciales de los vigías: ni las lista ni las quita."""
        p = pa.Pasarela.__new__(pa.Pasarela)
        p.tokens = object()
        p._preparar_dispositivos("/tmp")
        self.assertIsNone(p.quitados)
        peticion = pa.Peticion("GET", RUTA, "HTTP/1.1", [])
        self.assertFalse(p._de_los_dispositivos(peticion))


if __name__ == "__main__":
    unittest.main()
