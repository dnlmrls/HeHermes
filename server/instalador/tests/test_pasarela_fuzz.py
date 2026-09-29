"""El fuzz del analizador HTTP de la pasarela (auditoría del 2026-09-29, §14.9), solo con la biblioteca estándar.

Dos niveles, con semilla fija (se repite igual; `HEHERMES_FUZZ_SEMILLA` cambia la semilla y `HEHERMES_FUZZ_VECES` el
número de casos, para una tirada larga a mano):

- `leer_cabeza` y `cabeza_hacia_arriba`, puras: miles de peticiones mutadas (bytes de control, saltos sueltos, líneas
  repetidas o cortadas, cabeceras dobladas…). Lo que se acepta tiene que salir hacia Hermes como **una** petición limpia:
  ni un `\\r` ni un `\\n` sueltos, una sola línea vacía al final, sin los secretos ni lo que no pasa de un salto al
  siguiente, y con el largo que ha medido la pasarela.
- Por la red, contra la pasarela de verdad con un Hermes que apunta los bytes crudos que le llegan: sin token, siempre el
  404 idéntico (o nada) y Hermes sin ver ni un byte; con token, lo que le llega a Hermes es una sola petición bien
  formada. Y los casos de siempre del contrabando: dos `Authorization`, `Host` raros, `Content-Length` con
  `Transfer-Encoding`, dos largos distintos, cuerpos a medias, peticiones encadenadas y el slowloris.

Lo que encontró: `_RUTA` y `_NOMBRE` se miraban con `match` y `$`, que casa también delante de un «\\n» final; con un
token, «GET /x\\n HTTP/1.1» o una cabecera «X\\n: y» llegaban a Hermes con un salto suelto dentro. Ahora, `fullmatch`.
"""

import apoyo  # noqa: F401

import asyncio
import os
import random
import socket
import ssl
import tempfile
import threading
import time
import unittest
import warnings

from hehermes_servidor import pasarela as pa

CERT = str(apoyo.DATOS / "pasarela-NO-ES-DE-DANIEL.cert.pem")
CLAVE = str(apoyo.DATOS / "pasarela-NO-ES-DE-DANIEL.clave.pem")
TOKEN = "T" * 43
CLAVE_HERMES = "clave-de-hermes-de-prueba"
TLS_MINIMO = ssl.TLSVersion.TLSv1_2 if ssl.OPENSSL_VERSION.startswith("LibreSSL") else None
SEMILLA = int(os.environ.get("HEHERMES_FUZZ_SEMILLA", "20260929"))
VECES = int(os.environ.get("HEHERMES_FUZZ_VECES", "4000"))

BASE = ("GET /api/sessions?limit=5 HTTP/1.1\r\nHost: 203.0.113.9:62186\r\nAuthorization: Bearer %s\r\n"
        "Accept: application/json\r\nContent-Length: 0\r\n\r\n" % TOKEN).encode()
#: Lo que se mete en las mutaciones: lo que rompe analizadores (y lo de siempre).
TROZOS = [b"\r", b"\n", b"\r\n", b"\x00", b"\t", b" ", b":", b"\x7f", b"\xff", b"\x0b", b"\x0c", b"/", b"%0d%0a",
          b"Authorization: Bearer " + TOKEN.encode() + b"\r\n", b"Transfer-Encoding: chunked\r\n",
          b"Content-Length: 5\r\n", b"Content-Length: -1\r\n", b"Host: evil\r\n", b" HTTP/1.1", b"GET ",
          b"X-HeHermes-Vigia: robado\r\n", b"\r\n\r\n", b"a" * 50]


def mutar(azar: random.Random, datos: bytes) -> bytes:
    datos = bytearray(datos)
    for _ in range(azar.randint(1, 4)):
        que = azar.random()
        sitio = azar.randint(0, max(0, len(datos) - 1))
        if que < 0.45:
            datos[sitio:sitio] = azar.choice(TROZOS)
        elif que < 0.65 and datos:
            del datos[sitio:sitio + azar.randint(1, 6)]
        elif que < 0.8 and datos:
            datos[sitio] = azar.randrange(256)
        else:
            lineas = bytes(datos).split(b"\r\n")
            if len(lineas) > 2:
                i = azar.randrange(1, len(lineas) - 1)
                lineas.insert(i, lineas[i])
            datos = bytearray(b"\r\n".join(lineas))
    return bytes(datos)


def cabeza_de(datos: bytes):
    """Lo que `_cabeza` le pasaría a `leer_cabeza`: hasta la primera línea vacía, o None si no hay."""
    fin = datos.find(b"\r\n\r\n")
    return None if fin < 0 else datos[:fin]


class ComprobarArriba:
    """Lo que tiene que cumplir cualquier petición que sale hacia Hermes."""

    def comprobar_arriba(self, crudo: bytes, largo: int):
        self.assertTrue(crudo.endswith(b"\r\n\r\n"), crudo[-40:])
        cuerpo = crudo[:-4]
        self.assertNotIn(b"\r\n\r\n", cuerpo, "una sola cabeza")
        lineas = cuerpo.split(b"\r\n")
        for linea in lineas:
            self.assertNotIn(b"\n", linea, "un salto suelto hacia Hermes: %r" % linea[:80])
            self.assertNotIn(b"\r", linea)
            self.assertFalse(any(b < 0x20 and b != 0x09 or b == 0x7F for b in linea), linea[:80])
        metodo, ruta, version = lineas[0].split(b" ")
        self.assertEqual(version, b"HTTP/1.1")
        self.assertTrue(ruta.startswith(b"/"))
        nombres = [linea.split(b":", 1)[0].lower() for linea in lineas[1:]]
        for secreto in (b"x-hehermes-vigia", b"transfer-encoding", b"te", b"upgrade", b"proxy-authorization"):
            self.assertNotIn(secreto, nombres)
        self.assertEqual(nombres.count(b"authorization"), 1)
        self.assertEqual(nombres.count(b"host"), 1)
        self.assertEqual(nombres.count(b"connection"), 1)
        largos = [linea.split(b":", 1)[1].strip() for linea in lineas[1:] if linea.lower().startswith(b"content-length:")]
        self.assertLessEqual(len(largos), 1)
        if largos:
            self.assertEqual(int(largos[0]), largo)


class ElAnalizador(unittest.TestCase, ComprobarArriba):
    def test_lo_que_se_acepta_sale_limpio(self):
        azar = random.Random(SEMILLA)
        aceptadas = 0
        for _ in range(VECES):
            datos = mutar(azar, BASE)
            cabeza = cabeza_de(datos)
            if cabeza is None:
                continue
            try:
                peticion = pa.leer_cabeza(cabeza)
            except pa._Rechazo:
                continue
            aceptadas += 1
            with self.subTest(datos=datos[:120]):
                self.assertIn(peticion.metodo, pa._METODOS)
                self.assertIn(peticion.version, ("HTTP/1.1", "HTTP/1.0"))
                self.assertIsNotNone(pa._RUTA.fullmatch(peticion.ruta))
                for nombre, valor in peticion.cabeceras:
                    self.assertIsNotNone(pa._NOMBRE.fullmatch(nombre), repr(nombre))
                    self.assertFalse(any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in valor), repr(valor))
                peticion.largo = 0
                self.comprobar_arriba(pa.cabeza_hacia_arriba(peticion, ("127.0.0.1", 8642), "198.51.100.7",
                                                             [("Authorization", "Bearer " + CLAVE_HERMES)]), 0)
        self.assertGreater(aceptadas, VECES // 20, "el fuzz tiene que ejercitar también lo que se acepta")

    def test_los_saltos_sueltos_no_pasan(self):
        """Lo que encontró el fuzz: `$` casa delante de un «\\n» final."""
        for cabeza in (b"GET /x\n HTTP/1.1", b"GET /x HTTP/1.1\r\nX-Algo\n: y", b"GET /x\r HTTP/1.1",
                       b"GET /x HTTP/1.1\r\nX-Algo: y\n", b"GET /x HTTP/1.1\r\nX-Algo: y\rX-Otra: z",
                       b"GET /x HTTP/1.1\n", b"GET\t/x HTTP/1.1", b"GET /x HTTP/1.1 ", b"get /x HTTP/1.1",
                       b"GET /x HTTP/2", b"GET x HTTP/1.1", b"GET /x HTTP/1.1\r\n: vacio", b"GET /x HTTP/1.1\r\nX Y: z"):
            with self.subTest(cabeza=cabeza):
                with self.assertRaises(pa._Rechazo):
                    pa.leer_cabeza(cabeza)

    def test_los_validadores_de_forma_no_se_dejan_un_salto(self):
        self.assertIsNone(pa.Tokens.__dict__["quien"](type("T", (), {"_entradas": []})(), TOKEN + "\n"))
        self.assertIsNone(pa.leer_secreto_vigia("A" * 40 + "\n" + "B"))
        self.assertIsNone(pa.leer_clave_hermes("clave\nmala"))


class HermesCrudo:
    """Un «Hermes» que apunta los bytes tal cual le llegan en cada conexión y contesta un 200 pequeño."""

    def __init__(self):
        self.escucha = socket.create_server(("127.0.0.1", 0))
        self.puerto = self.escucha.getsockname()[1]
        self.recibidas = []
        self._candado = threading.Lock()
        threading.Thread(target=self._aceptar, daemon=True).start()

    def _aceptar(self):
        while True:
            try:
                conexion, _ = self.escucha.accept()
            except OSError:
                return
            threading.Thread(target=self._una, args=(conexion,), daemon=True).start()

    def _una(self, conexion):
        with conexion:
            conexion.settimeout(2)
            datos = b""
            try:
                while b"\r\n\r\n" not in datos:
                    trozo = conexion.recv(65536)
                    if not trozo:
                        break
                    datos += trozo
                cabeza, _, resto = datos.partition(b"\r\n\r\n")
                largo = 0
                for linea in cabeza.split(b"\r\n")[1:]:
                    if linea.lower().startswith(b"content-length:"):
                        largo = int(linea.split(b":", 1)[1])
                while len(resto) < largo:
                    trozo = conexion.recv(65536)
                    if not trozo:
                        break
                    resto += trozo
                # Lo que llegue después (no debería llegar nada: `Connection: close`) también se apunta.
                conexion.settimeout(0.2)
                try:
                    while True:
                        trozo = conexion.recv(65536)
                        if not trozo:
                            break
                        resto += trozo
                except OSError:
                    pass
                with self._candado:
                    self.recibidas.append((cabeza + b"\r\n\r\n", resto, largo))
                conexion.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except OSError:
                with self._candado:
                    self.recibidas.append((datos, b"", -1))

    def cerrar(self):
        self.escucha.close()


class PorLaRed(unittest.TestCase, ComprobarArriba):
    VECES_RED = int(os.environ.get("HEHERMES_FUZZ_VECES_RED", "160"))

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.carpeta = tempfile.TemporaryDirectory()
        c = self.c = lambda n: os.path.join(self.carpeta.name, n)  # noqa: E731
        self.hermes = HermesCrudo()
        with open(c("clave-hermes"), "w") as f:
            f.write(CLAVE_HERMES + "\n")
        with open(c("tokens.json"), "w") as f:
            f.write('{"v": 1, "tokens": [{"nombre": "mi-iphone", "sha256": "%s"}]}' % pa.hash_token(TOKEN))
        with open(c("pasarela.ini"), "w") as f:
            f.write("[pasarela]\npuerto = 1\nescucha = 127.0.0.1\ncertificado = %s\nclave = %s\ntokens = %s\n"
                    "[hermes]\npuerto = %d\nclave = %s\n" % (CERT, CLAVE, c("tokens.json"), self.hermes.puerto,
                                                             c("clave-hermes")))
        config = pa.Configuracion.leer(c("pasarela.ini"))
        config.puerto = 0
        # Sin contar los fallos de 127.0.0.1: si no, a los diez la IP se bloquearía y el resto se cerraría sin 404.
        self.p = pa.Pasarela(config, limites=pa.Limites(), diario=lambda texto: None, tls_minimo=TLS_MINIMO,
                             retraso_404=0.0, plazo_cabeceras=0.25, plazo_parada=0.2, revision=0.1)
        listo = threading.Event()
        self.bucle = asyncio.new_event_loop()

        def correr():
            asyncio.set_event_loop(self.bucle)
            self.bucle.run_until_complete(self.p.servir(listo=lambda puerto: (setattr(self, "puerto", puerto),
                                                                            listo.set())))

        self.hilo = threading.Thread(target=correr, daemon=True)
        self.hilo.start()
        self.assertTrue(listo.wait(5))

    def tearDown(self):
        self.bucle.call_soon_threadsafe(self.p.parar)
        self.hilo.join(5)
        self.hermes.cerrar()
        self.carpeta.cleanup()

    def mandar(self, datos: bytes, cerrar_escritura=True, plazo=3.0) -> bytes:
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", self.puerto), timeout=plazo) as crudo:
            with contexto.wrap_socket(crudo) as tls:
                tls.sendall(datos)
                recibido = b""
                tls.settimeout(plazo)
                try:
                    while True:
                        trozo = tls.recv(65536)
                        if not trozo:
                            break
                        recibido += trozo
                except (OSError, ssl.SSLError):
                    pass
                return recibido

    def esperar_a_hermes(self, cuantas, plazo=3.0):
        limite = time.monotonic() + plazo
        while len(self.hermes.recibidas) < cuantas and time.monotonic() < limite:
            time.sleep(0.02)
        time.sleep(0.05)
        return list(self.hermes.recibidas)

    def test_sin_token_nada_llega_a_hermes(self):
        azar = random.Random(SEMILLA + 1)
        base = BASE.replace(b"Authorization: Bearer " + TOKEN.encode() + b"\r\n", b"")
        for _ in range(self.VECES_RED // 2):
            datos = mutar(azar, base)
            if b"Bearer " + TOKEN.encode() in datos:
                continue
            with self.subTest(datos=datos[:120]):
                self.assertIn(self.mandar(datos, plazo=1.5), (pa.NO_ENCONTRADO, b""))
        self.assertEqual(self.hermes.recibidas, [])

    def test_con_token_a_hermes_solo_llega_una_peticion_limpia(self):
        azar = random.Random(SEMILLA + 2)
        antes = 0
        for _ in range(self.VECES_RED // 2):
            datos = mutar(azar, BASE)
            respuesta = self.mandar(datos, plazo=1.5)
            recibidas = self.esperar_a_hermes(antes + 1, plazo=0.05 if not respuesta.startswith(b"HTTP/1.1 200")
                                              else 3)
            with self.subTest(datos=datos[:120]):
                self.assertLessEqual(len(recibidas) - antes, 1, "una petición, como mucho una a Hermes")
                for cabeza, resto, largo in recibidas[antes:]:
                    self.comprobar_arriba(cabeza, largo)
                    self.assertIn(b"authorization: bearer " + CLAVE_HERMES.encode(), cabeza.lower())
                    self.assertNotIn(TOKEN.encode(), cabeza)
                    self.assertEqual(len(resto), largo, "ni un byte de más detrás del cuerpo")
            antes = len(recibidas)

    def test_los_casos_de_contrabando(self):
        token = b"Authorization: Bearer " + TOKEN.encode() + b"\r\n"
        casos = {
            "dos authorization": (b"GET / HTTP/1.1\r\n" + token + token + b"\r\n", pa.NO_ENCONTRADO),
            "CL y TE": (b"POST / HTTP/1.1\r\n" + token + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"0\r\n\r\n", b"HTTP/1.1 400"),
            "TE solo": (b"POST / HTTP/1.1\r\n" + token + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                        b"HTTP/1.1 400"),
            "dos CL distintos": (b"POST / HTTP/1.1\r\n" + token + b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nab",
                                 b"HTTP/1.1 400"),
            "CL con signo": (b"POST / HTTP/1.1\r\n" + token + b"Content-Length: +1\r\n\r\na", b"HTTP/1.1 400"),
            "CL en lista": (b"POST / HTTP/1.1\r\n" + token + b"Content-Length: 1, 1\r\n\r\na", b"HTTP/1.1 400"),
            "CL enorme": (b"POST / HTTP/1.1\r\n" + token + b"Content-Length: 99999999999\r\n\r\n", b"HTTP/1.1 413"),
            "ruta con salto": (b"GET /x\n HTTP/1.1\r\n" + token + b"\r\n", pa.NO_ENCONTRADO),
            "cabecera con salto": (b"GET /x HTTP/1.1\r\n" + token + b"X-Algo\n: y\r\n\r\n", pa.NO_ENCONTRADO),
            "cabecera doblada": (b"GET /x HTTP/1.1\r\n" + token + b"X-Algo: y\r\n z\r\n\r\n", pa.NO_ENCONTRADO),
        }
        for nombre, (datos, esperado) in casos.items():
            with self.subTest(nombre):
                self.assertTrue(self.mandar(datos).startswith(esperado))
        self.assertEqual(self.esperar_a_hermes(1, plazo=0.3), [], "nada de esto llega a Hermes")

    def test_host_raros_no_llegan_a_hermes(self):
        token = b"Authorization: Bearer " + TOKEN.encode() + b"\r\n"
        for host in (b"Host: evil.example\r\n", b"Host: a\r\nHost: b\r\n", b"", b"Host: 127.0.0.1:8642\r\n"):
            with self.subTest(host=host):
                self.assertTrue(self.mandar(b"GET /h HTTP/1.1\r\n" + host + token + b"\r\n").startswith(
                    b"HTTP/1.1 200"))
        recibidas = self.esperar_a_hermes(4)
        self.assertEqual(len(recibidas), 4)
        for cabeza, _, _ in recibidas:
            self.assertIn(b"\r\nHost: 127.0.0.1:%d\r\n" % self.hermes.puerto, cabeza)
            self.assertNotIn(b"evil", cabeza)

    def test_un_cuerpo_con_otra_peticion_dentro_es_solo_cuerpo(self):
        dentro = b"GET /secreto HTTP/1.1\r\n\r\n"
        datos = (b"POST /v1/runs HTTP/1.1\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\nContent-Length: %d\r\n"
                 b"\r\n" % len(dentro)) + dentro
        self.assertTrue(self.mandar(datos).startswith(b"HTTP/1.1 200"))
        recibidas = self.esperar_a_hermes(1)
        self.assertEqual(len(recibidas), 1)
        self.assertEqual(recibidas[0][1], dentro)

    def test_encadenada_sin_token_detras_de_una_buena(self):
        """Dos peticiones en el mismo paquete: la de detrás, sin token, recibe su 404 y no llega a Hermes."""
        datos = (b"GET /uno HTTP/1.1\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\n\r\n"
                 b"GET /dos HTTP/1.1\r\n\r\n")
        respuesta = self.mandar(datos)
        self.assertTrue(respuesta.startswith(b"HTTP/1.1 200"))
        recibidas = self.esperar_a_hermes(2, plazo=0.5)
        self.assertEqual([c.split(b" ")[1] for c, _, _ in recibidas], [b"/uno"])

    def test_un_cuerpo_a_medias_no_se_completa(self):
        datos = b"POST /v1/runs HTTP/1.1\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\nContent-Length: 10\r\n\r\nabc"
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", self.puerto), timeout=3) as crudo:
            with contexto.wrap_socket(crudo) as tls:
                tls.sendall(datos)
                time.sleep(0.2)
        recibidas = self.esperar_a_hermes(1)
        # Hermes ve el largo de verdad y menos bytes: una petición cortada, que descarta; nunca otra cosa.
        for cabeza, resto, largo in recibidas:
            self.assertEqual(largo, 10)
            self.assertLess(len(resto), 10)

    def test_slowloris_goteando_se_corta_en_su_plazo(self):
        """Un byte cada poco no alarga el plazo: las cabeceras enteras, en `plazo_cabeceras`."""
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", self.puerto), timeout=5) as crudo:
            with contexto.wrap_socket(crudo) as tls:
                inicio = time.monotonic()
                cortada = None
                for byte in b"GET / HTTP/1.1\r\nX-Algo: " + b"a" * 100:
                    try:
                        tls.sendall(bytes([byte]))
                        tls.settimeout(0.05)
                        try:
                            if tls.recv(10) == b"":
                                cortada = time.monotonic() - inicio
                                break
                        except socket.timeout:
                            pass
                    except (OSError, ssl.SSLError):
                        cortada = time.monotonic() - inicio
                        break
                    if time.monotonic() - inicio > 3:
                        break
                self.assertIsNotNone(cortada, "sigue abierta a los 3 s, goteando")
                self.assertLess(cortada, 1.0)
        self.assertEqual(self.hermes.recibidas, [])


if __name__ == "__main__":
    unittest.main()
