"""La pasarela de verdad: TLS en 127.0.0.1, un Hermes y un vigía de mentira detrás, y un cliente que hace de iPhone.

Hace falta poder escuchar en 127.0.0.1 (en el sandbox de Claude Code, fuera de él). En el Mac va con TLS 1.2 (el Python
de Xcode trae LibreSSL 2.8, que no sabe 1.3): la prueba que exige 1.3 se salta aquí y corre donde haya OpenSSL 3.
"""

import apoyo

import asyncio
import http.server
import io
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
import warnings
from unittest import mock

from hehermes_servidor import pasarela as pa

CERT = str(apoyo.DATOS / "pasarela-NO-ES-DE-DANIEL.cert.pem")
CLAVE = str(apoyo.DATOS / "pasarela-NO-ES-DE-DANIEL.clave.pem")
CLAVE_HERMES = "clave-del-api-server-de-las-pruebas"
SECRETO_VIGIA = "secreto-del-vigia-de-las-pruebas-0123456789"
TOKEN = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"
OTRO = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8"
TLS_MINIMO = None if ssl.HAS_TLSv1_3 else ssl.TLSVersion.TLSv1_2
NO_404 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


class Falso(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.peticiones = []
        self.sse_siguiente = threading.Event()
        self.sse_fin = threading.Event()
        super().__init__(("127.0.0.1", 0), Manejador)

    @property
    def puerto(self):
        return self.server_address[1]

    def handle_error(self, peticion, origen):
        # Una conexión que la pasarela corta (una baja con el SSE abierto) no es un fallo del Hermes de mentira.
        pass


class Manejador(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _todo(self):
        largo = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(largo) if largo else b""
        self.server.peticiones.append({"metodo": self.command, "ruta": self.path, "cabeceras": dict(self.headers),
                                       "lista": list(self.headers.items()), "cuerpo": cuerpo})
        if self.path.startswith("/v1/runs/r1/events"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for n in range(3):
                trozo = ("event: delta\ndata: {\"n\": %d}\n\n" % n).encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(trozo), trozo))
                self.wfile.flush()
                if n < 2:
                    self.server.sse_siguiente.wait(10)
                    self.server.sse_siguiente.clear()
            self.server.sse_fin.wait(10)
            self.wfile.write(b"0\r\n\r\n")
            return
        respuesta = json.dumps({"ruta": self.path, "largo": len(cuerpo)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(respuesta)))
        self.end_headers()
        self.wfile.write(respuesta)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _todo


class ConPasarela(unittest.TestCase):
    retraso = 0.05
    con_vigia = True
    plazo_cabeceras = 0.5

    def setUp(self):
        # Las conexiones que deja abiertas cada prueba las cierra el recolector: no son un fallo de la pasarela.
        warnings.simplefilter("ignore", ResourceWarning)
        self.carpeta = tempfile.TemporaryDirectory()
        c = lambda n: os.path.join(self.carpeta.name, n)  # noqa: E731
        self.c = c
        self.hermes = Falso()
        self.vigia = Falso()
        for servidor in (self.hermes, self.vigia):
            threading.Thread(target=servidor.serve_forever, args=(0.05,), daemon=True).start()
        with open(c("clave-hermes"), "w") as f:
            f.write(CLAVE_HERMES + "\n")
        with open(c("secreto"), "w") as f:
            f.write(SECRETO_VIGIA + "\n")
        self.escribir_tokens([("mi-iphone", TOKEN), ("otro", OTRO)])
        ini = ("[pasarela]\npuerto = 1\nescucha = 127.0.0.1\ncertificado = %s\nclave = %s\ntokens = %s\n"
               "[hermes]\npuerto = %d\nclave = %s\n" % (CERT, CLAVE, c("tokens.json"), self.hermes.puerto,
                                                        c("clave-hermes")))
        if self.con_vigia:
            ini += "[avisos]\nvigia = 127.0.0.1:%d\nsecreto = %s\n" % (self.vigia.puerto, c("secreto"))
        with open(c("pasarela.ini"), "w") as f:
            f.write(ini)
        self.diario = []
        config = pa.Configuracion.leer(c("pasarela.ini"))
        config.puerto = 0
        self.p = pa.Pasarela(config, limites=pa.Limites(contar_locales=True), diario=self.diario.append, tls_minimo=TLS_MINIMO, retraso_404=self.retraso,
                             plazo_cabeceras=self.plazo_cabeceras, revision=0.1)
        listo = threading.Event()
        self.bucle = asyncio.new_event_loop()

        def correr():
            asyncio.set_event_loop(self.bucle)
            self.bucle.run_until_complete(self.p.servir(listo=lambda puerto: (setattr(self, "puerto", puerto),
                                                                            listo.set())))

        self.hilo = threading.Thread(target=correr, daemon=True)
        self.hilo.start()
        self.assertTrue(listo.wait(5), "la pasarela no ha arrancado")

    def tearDown(self):
        self.bucle.call_soon_threadsafe(self.p.parar)
        self.hilo.join(5)
        self.hermes.sse_siguiente.set()
        self.hermes.sse_fin.set()
        for servidor in (self.hermes, self.vigia):
            servidor.shutdown()
            servidor.server_close()
        self.carpeta.cleanup()

    def escribir_tokens(self, entradas):
        datos = {"v": 1, "tokens": [{"nombre": n, "sha256": pa.hash_token(t)} for n, t in entradas]}
        ruta = self.c("tokens.json")
        with open(ruta + ".n", "w") as f:
            json.dump(datos, f)
        os.replace(ruta + ".n", ruta)

    # El iPhone

    def conectar(self, maxima=None):
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        if maxima:
            contexto.maximum_version = maxima
        crudo = socket.create_connection(("127.0.0.1", self.puerto), timeout=5)
        return contexto.wrap_socket(crudo)

    def peticion(self, metodo="GET", ruta="/health", token=TOKEN, cuerpo=b"", extra="", tls=None):
        tls = tls or self.conectar()
        cabeceras = "Host: servidor\r\n"
        if token:
            cabeceras += "Authorization: Bearer %s\r\n" % token
        if cuerpo or metodo in ("POST", "PUT", "PATCH"):
            cabeceras += "Content-Length: %d\r\n" % len(cuerpo)
        tls.sendall(("%s %s HTTP/1.1\r\n%s%s\r\n" % (metodo, ruta, cabeceras, extra)).encode() + cuerpo)
        return tls

    def leer_respuesta(self, tls):
        """(estado, cabeceras en minúsculas, cuerpo, bytes crudos) de una respuesta con Content-Length."""
        f = tls.makefile("rb")
        crudo = f.readline()
        estado = int(crudo.split()[1])
        cabeceras = {}
        while True:
            linea = f.readline()
            crudo += linea
            if linea in (b"\r\n", b""):
                break
            nombre, _, valor = linea.decode().partition(":")
            cabeceras[nombre.strip().lower()] = valor.strip()
        cuerpo = f.read(int(cabeceras.get("content-length", 0)))
        return estado, cabeceras, cuerpo, crudo + cuerpo

    def todo(self, tls):
        partes = []
        tls.settimeout(5)
        while True:
            try:
                trozo = tls.recv(65536)
            except (ssl.SSLError, OSError):
                break
            if not trozo:
                break
            partes.append(trozo)
        return b"".join(partes)


class LoQueSePasaAHermes(ConPasarela):
    def test_con_token_llega_a_hermes_con_su_clave_y_sin_el_token(self):
        estado, cabeceras, cuerpo, _ = self.leer_respuesta(self.peticion(ruta="/api/sessions?limit=1"))
        self.assertEqual(estado, 200)
        self.assertEqual(json.loads(cuerpo)["ruta"], "/api/sessions?limit=1")
        vista = self.hermes.peticiones[-1]
        self.assertEqual(vista["cabeceras"]["Authorization"], "Bearer " + CLAVE_HERMES)
        self.assertEqual([v for k, v in vista["lista"] if k.lower() == "authorization"], ["Bearer " + CLAVE_HERMES])
        self.assertNotIn(TOKEN, json.dumps(vista["lista"]))
        self.assertEqual(vista["cabeceras"]["X-Forwarded-For"], "127.0.0.1")

    def test_ninguna_respuesta_lleva_server(self):
        _, cabeceras, _, _ = self.leer_respuesta(self.peticion())
        self.assertNotIn("server", cabeceras)
        _, cabeceras, _, _ = self.leer_respuesta(self.peticion(ruta="/avisos/v1/salud"))
        self.assertNotIn("server", cabeceras)

    def test_el_cuerpo_de_un_post_llega_entero(self):
        cuerpo = os.urandom(300 * 1024)
        estado, _, respuesta, _ = self.leer_respuesta(self.peticion("POST", "/v1/runs", cuerpo=cuerpo))
        self.assertEqual(estado, 200)
        self.assertEqual(self.hermes.peticiones[-1]["cuerpo"], cuerpo)

    def test_dos_peticiones_por_la_misma_conexion(self):
        tls = self.peticion(ruta="/uno")
        self.assertEqual(json.loads(self.leer_respuesta(tls)[2])["ruta"], "/uno")
        self.peticion(ruta="/dos", tls=tls)
        self.assertEqual(json.loads(self.leer_respuesta(tls)[2])["ruta"], "/dos")

    def test_el_sse_llega_evento_a_evento(self):
        """Sin búfer: el primer evento llega antes de que Hermes mande el segundo."""
        tls = self.peticion(ruta="/v1/runs/r1/events")
        tls.settimeout(5)
        recibido = b""
        for n in range(3):
            while b'"n": %d' % n not in recibido:
                recibido += tls.recv(65536)
            if n < 2:
                self.hermes.sse_siguiente.set()
        self.hermes.sse_fin.set()
        recibido += self.todo(tls)
        cabeza = recibido.split(b"\r\n\r\n", 1)[0].lower()
        self.assertIn(b"transfer-encoding: chunked", cabeza)
        self.assertIn(b"connection: close", cabeza)
        self.assertTrue(recibido.endswith(b"0\r\n\r\n"))

    def test_un_cuerpo_de_mas_es_un_413(self):
        tls = self.conectar()
        tls.sendall(("POST /v1/runs HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n"
                     % (TOKEN, pa.MAX_CUERPO + 1)).encode())
        estado, cabeceras, cuerpo, _ = self.leer_respuesta(tls)
        self.assertEqual(estado, 413)
        self.assertEqual(json.loads(cuerpo)["error"]["code"], "cuerpo_demasiado_grande")
        self.assertEqual(cabeceras["connection"], "close")
        self.assertEqual(self.hermes.peticiones, [])

    def test_en_avisos_el_tope_es_de_64_kib(self):
        tls = self.conectar()
        tls.sendall(("POST /avisos/v1/dispositivos HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n"
                     % (TOKEN, pa.MAX_CUERPO_AVISOS + 1)).encode())
        self.assertEqual(self.leer_respuesta(tls)[0], 413)

    def test_transfer_encoding_es_un_400(self):
        tls = self.peticion("POST", "/v1/runs", extra="Transfer-Encoding: chunked\r\n")
        estado, _, cuerpo, _ = self.leer_respuesta(tls)
        self.assertEqual(estado, 400)
        self.assertEqual(json.loads(cuerpo)["error"]["code"], "peticion_invalida")

    def test_hermes_parado_es_un_502(self):
        self.hermes.shutdown()
        self.hermes.server_close()
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion())
        self.assertEqual(estado, 502)
        self.assertEqual(json.loads(cuerpo)["error"]["code"], "hermes_no_contesta")

    def test_la_clave_nueva_de_hermes_se_coge_sin_reiniciar(self):
        with open(self.c("clave-hermes.n"), "w") as f:
            f.write("otra-clave-mas-larga\n")
        os.replace(self.c("clave-hermes.n"), self.c("clave-hermes"))
        self.leer_respuesta(self.peticion())
        self.assertEqual(self.hermes.peticiones[-1]["cabeceras"]["Authorization"], "Bearer otra-clave-mas-larga")


class LoQueSePasaAlVigia(ConPasarela):
    def test_avisos_va_al_vigia_con_su_secreto_y_sin_authorization(self):
        tls = self.peticion("PUT", "/avisos/v1/dispositivos/abc/ajustes", cuerpo=b'{"a": 1}',
                            extra="X-HeHermes-Vigia: me-lo-invento\r\n")
        estado, _, _, _ = self.leer_respuesta(tls)
        self.assertEqual(estado, 200)
        self.assertEqual(self.hermes.peticiones, [])
        vista = self.vigia.peticiones[-1]
        self.assertEqual(vista["ruta"], "/avisos/v1/dispositivos/abc/ajustes")
        self.assertEqual([v for k, v in vista["lista"] if k.lower() == "x-hehermes-vigia"], [SECRETO_VIGIA])
        self.assertFalse([k for k, _ in vista["lista"] if k.lower() == "authorization"])
        self.assertEqual(vista["cuerpo"], b'{"a": 1}')

    def test_avisos_sin_la_barra_de_detras_va_a_hermes(self):
        self.leer_respuesta(self.peticion(ruta="/avisosx"))
        self.assertEqual(self.vigia.peticiones, [])
        self.assertEqual(len(self.hermes.peticiones), 1)


class SinVigia(ConPasarela):
    con_vigia = False

    def test_avisos_sin_vigia_es_un_503(self):
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion(ruta="/avisos/v1/salud"))
        self.assertEqual(estado, 503)
        self.assertEqual(json.loads(cuerpo)["error"]["code"], "avisos_no_instalados")


class ElCuatrocientosCuatro(ConPasarela):
    def rechazo(self, texto):
        tls = self.conectar()
        tls.sendall(texto)
        return self.todo(tls)

    def test_sin_token_con_uno_malo_o_con_una_peticion_rota_los_mismos_bytes(self):
        casos = {
            "sin token": b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n",
            "token malo": ("GET /health HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n" % ("A" * 43)).encode(),
            "otro esquema": ("GET /health HTTP/1.1\r\nAuthorization: Basic %s\r\n\r\n" % TOKEN).encode(),
            "la clave de Hermes": ("GET /health HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n" % CLAVE_HERMES).encode(),
            "ruta rara": b"GET * HTTP/1.1\r\n\r\n",
            "línea rota": b"HOLA\r\n\r\n",
            "otro protocolo": b"SSH-2.0-OpenSSH_9.6\r\n\r\n",
            "cabeceras de más": b"GET / HTTP/1.1\r\n" + b"X-A: b\r\n" * (pa.MAX_LINEAS_CABECERA + 1) + b"\r\n",
            "cabecera doblada": ("GET / HTTP/1.1\r\nAuthorization: Bearer %s\r\n  sigue\r\n\r\n" % TOKEN).encode(),
            "dos tokens": ("GET / HTTP/1.1\r\nAuthorization: Bearer %s\r\nAuthorization: Bearer %s\r\n\r\n"
                           % (TOKEN, TOKEN)).encode(),
            "token que no es ascii": ("GET / HTTP/1.1\r\nAuthorization: Bearer %s\r\n\r\n" % ("ñ" * 43)).encode(),
        }
        for nombre, texto in casos.items():
            with self.subTest(nombre):
                # Son más de diez: sin olvidar los fallos, los últimos se encontrarían la IP bloqueada.
                self.p.limites._fallos.clear()
                self.assertEqual(self.rechazo(texto), NO_404)
        self.assertEqual(self.hermes.peticiones, [])
        self.assertEqual(self.vigia.peticiones, [])

    def test_una_cabeza_enorme_tambien(self):
        self.assertEqual(self.rechazo(b"GET /" + b"a" * (pa.MAX_CABECERAS + 10) + b" HTTP/1.1\r\n\r\n"), NO_404)

    def test_diez_fallos_bloquean_la_ip_antes_del_apreton(self):
        for _ in range(pa.MAX_FALLOS):
            self.rechazo(b"GET / HTTP/1.1\r\n\r\n")
        with self.assertRaises((ssl.SSLError, OSError)):
            self.leer_respuesta(self.peticion())

    def test_las_cabeceras_a_medias_se_cierran_y_cuentan(self):
        tls = self.conectar()
        tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
        inicio = time.monotonic()
        self.assertEqual(self.todo(tls), b"")
        self.assertLess(time.monotonic() - inicio, 3)
        self.assertEqual(len(self.p.limites._fallos.get("127.0.0.1", ())), 1)

    def test_una_conexion_que_se_cierra_sin_decir_nada_no_cuenta(self):
        self.conectar().close()
        time.sleep(0.2)
        self.assertEqual(len(self.p.limites._fallos.get("127.0.0.1", ())), 0)


class ConElRetrasoDeVerdad(ConPasarela):
    retraso = pa.RETRASO_404

    def test_el_404_llega_un_segundo_despues(self):
        tls = self.conectar()
        inicio = time.monotonic()
        tls.sendall(b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(self.todo(tls), NO_404)
        self.assertGreaterEqual(time.monotonic() - inicio, pa.RETRASO_404 - 0.05)


class LaBaja(ConPasarela):
    def test_una_baja_vale_al_momento_para_lo_nuevo(self):
        self.assertEqual(self.leer_respuesta(self.peticion())[0], 200)
        self.escribir_tokens([("otro", OTRO)])
        tls = self.peticion()
        self.assertEqual(self.todo(tls), NO_404)
        self.assertEqual(self.leer_respuesta(self.peticion(token=OTRO))[0], 200)

    def test_una_baja_corta_el_sse_abierto(self):
        tls = self.peticion(ruta="/v1/runs/r1/events")
        tls.settimeout(5)
        recibido = b""
        while b'"n": 0' not in recibido:
            recibido += tls.recv(65536)
        inicio = time.monotonic()
        self.escribir_tokens([("otro", OTRO)])
        resto = self.todo(tls)
        self.assertLess(time.monotonic() - inicio, 2)
        self.assertNotIn(b'"n": 1', resto)

    def test_la_de_otro_no_corta_la_mia(self):
        tls = self.peticion(ruta="/v1/runs/r1/events")
        tls.settimeout(5)
        recibido = b""
        while b'"n": 0' not in recibido:
            recibido += tls.recv(65536)
        self.escribir_tokens([("mi-iphone", TOKEN)])
        time.sleep(0.4)
        self.hermes.sse_siguiente.set()
        while b'"n": 1' not in recibido:
            recibido += tls.recv(65536)


class LosTopesDeConexiones(ConPasarela):
    # Que las abiertas no caduquen por no mandar cabeceras mientras dura la prueba (eso contaría como fallos).
    plazo_cabeceras = 10
    def test_la_decimoseptima_de_una_ip_ni_llega_al_tls(self):
        abiertas = [self.conectar() for _ in range(pa.CONEXIONES_POR_IP)]
        with self.assertRaises((ssl.SSLError, OSError)):
            self.conectar()
        abiertas[0].close()
        time.sleep(0.2)
        self.conectar().close()
        for tls in abiertas[1:]:
            tls.close()


class ElRegistro(ConPasarela):
    """Ni el token, ni la ruta, ni la consulta, ni ningún cuerpo: solo la IP, el método, el estado y los bytes."""

    def test_no_apunta_nada_de_lo_que_lleva_la_peticion(self):
        cuerpo = b'{"secreto-del-cuerpo": "cuerpo-que-no-se-apunta"}'
        self.leer_respuesta(self.peticion("POST", "/v1/runs?consulta=que-no-se-apunta", cuerpo=cuerpo))
        self.leer_respuesta(self.peticion(ruta="/avisos/v1/dispositivos/token-de-avisos-que-no-se-apunta/ajustes"))
        self.todo(self.peticion(token=OTRO[:-1] + "Z", ruta="/ruta-rechazada-que-no-se-apunta"))
        self.leer_respuesta(self.peticion("POST", "/v1/runs", cuerpo=b"x" * 10,
                                          extra="Transfer-Encoding: chunked\r\n"))
        time.sleep(0.2)
        texto = "\n".join(self.diario)
        self.assertTrue(self.diario)
        for secreto in (TOKEN, OTRO, OTRO[:-1] + "Z", CLAVE_HERMES, SECRETO_VIGIA, "consulta", "que-no-se-apunta",
                        "cuerpo", "/v1/runs", "/avisos", "mi-iphone"):
            self.assertNotIn(secreto, texto)
        self.assertIn("POST", texto)
        self.assertIn("200", texto)


class UnFalloPorDentro(ConPasarela):
    def test_de_una_excepcion_solo_se_apunta_el_tipo(self):
        """El mensaje de una excepción puede llevar trozos de la petición: al registro va solo su tipo."""
        async def roto(*args):
            raise ValueError("algo con %s y /ruta/que-no-se-apunta" % TOKEN)

        with mock.patch.object(self.p, "_reenviar", roto):
            self.todo(self.peticion())
            time.sleep(0.2)
        texto = "\n".join(self.diario)
        self.assertIn("ValueError", texto)
        self.assertNotIn(TOKEN, texto)
        self.assertNotIn("que-no-se-apunta", texto)


class ElContexto(unittest.TestCase):
    def test_en_el_servidor_solo_tls_13_con_alpn_http11(self):
        """Con un contexto de mentira, para que se vea también en el Mac, que no sabe TLS 1.3."""
        config = pa.Configuracion()
        config.certificado, config.clave = CERT, CLAVE
        hecho = {}

        class Contexto:
            options = 0

            def __init__(self, protocolo):
                hecho["protocolo"] = protocolo

            def __setattr__(self, nombre, valor):
                hecho[nombre] = valor

            def load_cert_chain(self, cert, clave):
                hecho["cadena"] = (cert, clave)

            def set_alpn_protocols(self, protocolos):
                hecho["alpn"] = protocolos

        with mock.patch.object(pa.ssl, "SSLContext", Contexto):
            pa.contexto_tls(config)
        self.assertEqual(hecho["protocolo"], ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(hecho["minimum_version"], ssl.TLSVersion.TLSv1_3)
        self.assertEqual(hecho["cadena"], (CERT, CLAVE))
        self.assertEqual(hecho["alpn"], ["http/1.1"])

    @unittest.skipUnless(ssl.HAS_TLSv1_3, "este Python no sabe TLS 1.3 (LibreSSL de Xcode): corre en el servidor")
    def test_un_cliente_de_tls_12_no_pasa(self):
        # Una pasarela con su contexto de siempre, sin bajar a 1.2.
        caso = ConPasarela("run")
        caso.setUp()
        try:
            self.assertEqual(caso.p.contexto.minimum_version, ssl.TLSVersion.TLSv1_3)
            with self.assertRaises((ssl.SSLError, OSError)):
                caso.conectar(maxima=ssl.TLSVersion.TLSv1_2)
            self.assertEqual(caso.conectar().version(), "TLSv1.3")
        finally:
            caso.tearDown()


if __name__ == "__main__":
    unittest.main()
