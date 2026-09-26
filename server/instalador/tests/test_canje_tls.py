"""El canje de verdad, por TLS en 127.0.0.1: `preparar`, `servir` y un cliente de Python que hace de iPhone.

El cliente hace lo mismo que la app: ancla la huella del SPKI antes de mandar nada, pide el reto, lo abre con su
privada, canjea y abre `{h, p, f, t}`, el acceso a la pasarela. Hace falta `cryptography` (el venv).
"""

import apoyo

import base64
import contextlib
import http.client
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from hehermes_servidor import canje

# El Python de Xcode no sabe TLS 1.3 (LibreSSL 2.8): en el Mac, el canje se prueba con 1.2, y lo de exigir 1.3 donde
# lo haya (en el servidor, siempre).
TLS_MINIMO = ssl.TLSVersion.TLSv1_3 if ssl.HAS_TLSv1_3 else ssl.TLSVersion.TLSv1_2
#: Lo que entrega desde la 0.6.0: el acceso a la pasarela (el token es de prueba, no es de nadie).
CARGA = {"h": "203.0.113.7", "p": 61234, "f": "0GUKsxTavhZWbjkIBTXZmhJX0PMoBKdRcxK1ljakLyc",
         "t": "dG9rZW4tZGUtcHJ1ZWJhLXF1ZS1uby1lcy1kZS1uYWQ"}
#: Lo que entregaba con la VPN: ya no sale del canje.
CARGA_DE_LA_VPN = {"h": "203.0.113.7", "rid": "203.0.113.7", "lid": "mi-iphone",
                   "k": "psk-de-prueba-que-no-es-de-nadie-1234"}


class HuellaDistinta(Exception):
    pass


class Iphone:
    """El papel de la app, en Python."""

    def __init__(self, puerto, huella, codigo, privada, tls_max=None):
        self.puerto, self.huella, self.codigo, self.privada = puerto, huella, codigo, privada
        self.tls_max = tls_max
        self.pausa = canje.PAUSA_POR_IP + 0.05

    def pedir(self, ruta, cuerpo):
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # La confianza no viene de una autoridad: viene de la huella del enlace, que se mira a mano antes de mandar nada.
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        if self.tls_max:
            contexto.maximum_version = self.tls_max
        conexion = http.client.HTTPSConnection("127.0.0.1", self.puerto, context=contexto, timeout=5)
        try:
            conexion.connect()
            cert = x509.load_der_x509_certificate(conexion.sock.getpeercert(binary_form=True))
            spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            if canje.huella_spki(spki) != self.huella:
                raise HuellaDistinta()
            conexion.request("POST", ruta, body=json.dumps(cuerpo), headers={"Content-Type": "application/json"})
            respuesta = conexion.getresponse()
            return respuesta.status, json.loads(respuesta.read())
        finally:
            conexion.close()

    def canjear(self):
        privada = self.privada.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        huella = canje.de_b64url(self.huella, 32)
        estado, sobre = self.pedir(canje.RUTA_RETO, {"c": self.codigo})
        if estado != 200:
            return estado, sobre
        reto = canje.abrir_con(privada, "reto", huella, self.codigo, sobre)
        time.sleep(self.pausa)
        estado, sobre = self.pedir(canje.RUTA_CANJEAR, {"c": self.codigo, "reto": base64.b64encode(reto).decode()})
        if estado != 200:
            return estado, sobre
        return estado, json.loads(canje.abrir_con(privada, "psk", huella, self.codigo, sobre))


class Base(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.mkdtemp(prefix="hh-canje-")
        self.addCleanup(shutil.rmtree, self.carpeta, True)
        self.huella = canje.preparar(self.carpeta)
        self.privada = X25519PrivateKey.generate()
        self.llave = self.privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.codigo = canje.codigo_nuevo()

    def arrancar(self, reloj=None):
        self.canje = canje.Canje(self.llave, self.codigo, canje.de_b64url(self.huella, 32),
                                 json.dumps(CARGA).encode(), reloj=reloj)
        listo = threading.Event()
        self.resultado = {}

        def al_escuchar(puerto):
            self.resultado["puerto"] = puerto
            listo.set()

        def correr():
            self.resultado["salida"] = canje.servir(self.canje, os.path.join(self.carpeta, "cert.pem"),
                                                    os.path.join(self.carpeta, "clave.pem"), 0, "127.0.0.1",
                                                    listo=al_escuchar, tic=0.05, plazo_saludo=1.0,
                                                    tls_minimo=TLS_MINIMO, diario=lambda texto: None)

        self.hilo = threading.Thread(target=correr, daemon=True)
        self.hilo.start()
        self.assertTrue(listo.wait(5))
        return self.resultado["puerto"]

    def iphone(self, puerto, **kw):
        return Iphone(puerto, kw.pop("huella", self.huella), self.codigo, self.privada, **kw)

    def acabado(self):
        self.hilo.join(5)
        self.assertFalse(self.hilo.is_alive(), "el canje sigue abierto")
        return self.resultado["salida"]


class Preparar(Base):
    def test_un_certificado_p256_sin_datos_de_nadie_y_la_huella_de_su_spki(self):
        with open(os.path.join(self.carpeta, "cert.pem"), "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        self.assertEqual(cert.public_key().curve.name, "secp256r1")
        # Ni «hehermes» en el nombre: a quien escanee el puerto, el certificado no le dice qué es.
        self.assertRegex(cert.subject.rfc4514_string(), r"^CN=[0-9a-f]{16}$")
        self.assertEqual(cert.issuer, cert.subject)
        self.assertNotIn(b"hehermes", cert.public_bytes(Encoding.DER).lower())
        spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(canje.huella_spki(spki), self.huella)
        for nombre in ("cert.pem", "clave.pem"):
            self.assertEqual(os.stat(os.path.join(self.carpeta, nombre)).st_mode & 0o777, 0o600, nombre)

    def test_cada_canje_su_certificado(self):
        otra = tempfile.mkdtemp(prefix="hh-canje-")
        self.addCleanup(shutil.rmtree, otra, True)
        self.assertNotEqual(canje.preparar(otra), self.huella)


class DePuntaAPunta(Base):
    def test_canjea_y_se_cierra(self):
        puerto = self.arrancar()
        estado, carga = self.iphone(puerto).canjear()
        self.assertEqual((estado, carga), (200, CARGA))
        self.assertEqual(self.acabado(), 0)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", puerto), timeout=1).close()

    def test_el_diario_no_lleva_ni_la_psk_ni_el_codigo(self):
        diario = []
        self.canje = canje.Canje(self.llave, self.codigo, canje.de_b64url(self.huella, 32),
                                 json.dumps(CARGA).encode())
        listo = threading.Event()
        puerto = {}
        hilo = threading.Thread(target=lambda: canje.servir(
            self.canje, os.path.join(self.carpeta, "cert.pem"), os.path.join(self.carpeta, "clave.pem"), 0,
            "127.0.0.1", listo=lambda p: (puerto.setdefault("p", p), listo.set()), tic=0.05, plazo_saludo=1.0,
            tls_minimo=TLS_MINIMO, diario=diario.append), daemon=True)
        hilo.start()
        self.assertTrue(listo.wait(5))
        self.assertEqual(self.iphone(puerto["p"]).canjear()[0], 200)
        hilo.join(5)
        texto = "\n".join(diario)
        self.assertEqual(len(diario), 2, diario)
        for secreto in (CARGA["t"], self.codigo, canje.b64url(self.llave)):
            self.assertNotIn(secreto, texto)

    def test_otra_huella_y_el_iphone_no_manda_nada(self):
        puerto = self.arrancar()
        with self.assertRaises(HuellaDistinta):
            self.iphone(puerto, huella=canje.b64url(bytes(32))).canjear()
        self.assertEqual(self.canje.fallos, 0, "no llegó a mandar el código")
        self.assertFalse(self.canje.cerrado)
        self.canje.cerrar("caducado")
        self.acabado()

    @unittest.skipUnless(ssl.HAS_TLSv1_3, "este Python no sabe TLS 1.3 (el de Xcode va con LibreSSL 2.8)")
    def test_sin_tls_13_no_hay_conexion(self):
        puerto = self.arrancar()
        with self.assertRaises(ssl.SSLError):
            self.iphone(puerto, tls_max=ssl.TLSVersion.TLSv1_2).canjear()
        self.assertEqual(self.iphone(puerto).canjear()[0], 200, "el canje sigue sirviendo después")
        self.acabado()

    def test_quien_no_tiene_la_privada_no_pasa_del_reto(self):
        puerto = self.arrancar()
        intruso = Iphone(puerto, self.huella, self.codigo, X25519PrivateKey.generate())
        with self.assertRaises(canje.ErrorDeCanje):
            intruso.canjear()
        self.assertFalse(self.canje.cerrado)
        time.sleep(canje.PAUSA_POR_IP + 0.05)  # los dos salen de 127.0.0.1: la misma IP
        self.assertEqual(self.iphone(puerto).canjear()[0], 200)
        self.acabado()

    def test_quien_conecta_y_no_saluda_no_lo_bloquea(self):
        puerto = self.arrancar()
        mudo = socket.create_connection(("127.0.0.1", puerto))
        self.addCleanup(mudo.close)
        self.assertEqual(self.iphone(puerto).canjear()[0], 200)
        self.acabado()

    def test_a_los_diez_minutos_sale_sin_que_nadie_llame(self):
        reloj = [0.0]
        puerto = self.arrancar(reloj=lambda: reloj[0])
        reloj[0] = canje.DURACION + 1
        self.assertEqual(self.acabado(), canje.SALIDAS["caducado"])
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", puerto), timeout=1).close()

    def test_los_intentos_lo_cierran_con_su_salida(self):
        puerto = self.arrancar()
        malo = Iphone(puerto, self.huella, "B" * 22, self.privada)
        for _ in range(canje.MAX_FALLOS_POR_IP):
            estado, _ = malo.pedir(canje.RUTA_RETO, {"c": "B" * 22})
            time.sleep(canje.PAUSA_POR_IP + 0.05)
        self.assertEqual(estado, 429)
        self.assertEqual(self.acabado(), canje.SALIDAS["demasiados_intentos"])


class AUnEscaner(Base):
    """Daniel: que no le diga nada útil a un escáner. Un 404 igual para todo lo que no es del protocolo, sin cuerpo y
    sin cabecera Server, y quien conecta demasiadas veces ya ni pasa del apretón."""

    def crudo(self, puerto, peticion):
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", puerto), timeout=5) as tcp:
            with contexto.wrap_socket(tcp) as tls:
                tls.sendall(peticion)
                datos = b""
                while True:
                    trozo = tls.recv(4096)
                    if not trozo:
                        return datos
                    datos += trozo

    def test_todo_lo_que_no_es_del_protocolo_da_el_mismo_404_mudo(self):
        puerto = self.arrancar()
        respuestas = {self.crudo(puerto, peticion) for peticion in (
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /canje/v1/reto HTTP/1.1\r\nHost: x\r\n\r\n",
            b"POST /admin HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
            b"OPTIONS * HTTP/1.1\r\n\r\n",
            b"basura\r\n\r\n",
            b"POST /canje/v1/reto HTTP/1.1\r\nContent-Length: 999999\r\n\r\n")}
        self.assertEqual(respuestas, {b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"})
        self.assertEqual(self.canje.fallos, 0, "un escáner no gasta los intentos del iPhone")
        self.assertEqual(self.iphone(puerto).canjear()[0], 200)
        self.acabado()

    def test_las_respuestas_del_protocolo_tampoco_dicen_que_servidor_es(self):
        puerto = self.arrancar()
        respuesta = self.crudo(puerto, b"POST /canje/v1/reto HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
        cabeceras = respuesta.split(b"\r\n\r\n", 1)[0].lower()
        self.assertTrue(cabeceras.startswith(b"http/1.1 403"), respuesta)
        self.assertNotIn(b"server:", cabeceras)
        self.canje.cerrar("caducado")
        self.acabado()

    def test_demasiadas_conexiones_de_una_ip_ni_llegan_al_tls(self):
        puerto = self.arrancar()
        for _ in range(canje.MAX_CONEXIONES_POR_IP):
            self.crudo(puerto, b"GET / HTTP/1.1\r\n\r\n")
        with self.assertRaises((ssl.SSLError, OSError)):
            self.crudo(puerto, b"GET / HTTP/1.1\r\n\r\n")
        self.canje.cerrar("caducado")
        self.acabado()


class ComoProceso(Base):
    """`python -m hehermes_servidor.canje servir`, con las credenciales en `$CREDENTIALS_DIRECTORY`, como lo lanza
    systemd."""

    @unittest.skipUnless(ssl.HAS_TLSv1_3, "servir exige TLS 1.3, y el Python de Xcode no lo sabe (LibreSSL 2.8)")
    def test_servir_desde_las_credenciales(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            puerto = s.getsockname()[1]
        credenciales = tempfile.mkdtemp(prefix="hh-cred-")
        self.addCleanup(shutil.rmtree, credenciales, True)
        shutil.copy(os.path.join(self.carpeta, "cert.pem"), os.path.join(credenciales, "cert"))
        shutil.copy(os.path.join(self.carpeta, "clave.pem"), os.path.join(credenciales, "clave"))
        with open(os.path.join(credenciales, "canje"), "w") as f:
            json.dump({"llave": canje.b64url(self.llave), "codigo": self.codigo, "huella": self.huella,
                       "carga": CARGA, "puerto": puerto, "direccion": "127.0.0.1"}, f)
        proceso = subprocess.Popen([sys.executable, "-B", "-m", "hehermes_servidor.canje", "servir"],
                                   cwd=str(apoyo.RAIZ), env=dict(os.environ, CREDENTIALS_DIRECTORY=credenciales),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: proceso.poll() is None and proceso.kill())
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", puerto), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        time.sleep(canje.PAUSA_POR_IP)  # el sondeo de arriba no cuenta como petición, pero por si acaso
        estado, carga = self.iphone(puerto).canjear()
        self.assertEqual((estado, carga), (200, CARGA))
        salida, _ = proceso.communicate(timeout=10)
        self.assertEqual(proceso.returncode, 0, salida)
        self.assertIn("canjeado", salida)
        for secreto in (CARGA["t"], self.codigo):
            self.assertNotIn(secreto, salida, "el diario no lleva ni el token ni el código")

    def test_main_lee_las_credenciales(self):
        """Lo mismo por dentro, en un hilo, para el Mac: `main servir` con TLS 1.3 no arrancaría aquí."""
        import functools
        import unittest.mock
        credenciales = tempfile.mkdtemp(prefix="hh-cred-")
        self.addCleanup(shutil.rmtree, credenciales, True)
        shutil.copy(os.path.join(self.carpeta, "cert.pem"), os.path.join(credenciales, "cert"))
        shutil.copy(os.path.join(self.carpeta, "clave.pem"), os.path.join(credenciales, "clave"))
        with open(os.path.join(credenciales, "canje"), "w") as f:
            json.dump({"llave": canje.b64url(self.llave), "codigo": self.codigo, "huella": self.huella,
                       "carga": CARGA, "puerto": 0, "direccion": "127.0.0.1"}, f)
        listo, resultado = threading.Event(), {}
        de_verdad = canje.servir
        servir = functools.partial(de_verdad, tls_minimo=TLS_MINIMO, diario=lambda texto: None, tic=0.05,
                                   listo=lambda puerto: (resultado.update(puerto=puerto), listo.set()))
        with unittest.mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": credenciales}), \
                unittest.mock.patch.object(canje, "servir", servir):
            hilo = threading.Thread(target=lambda: resultado.update(salida=canje.main(["servir"])), daemon=True)
            hilo.start()
            self.assertTrue(listo.wait(5))
            self.assertEqual(self.iphone(resultado["puerto"]).canjear(), (200, CARGA))
            hilo.join(5)
        self.assertEqual(resultado["salida"], 0)

    def test_main_no_entrega_nada_que_no_sea_el_acceso_a_la_pasarela(self):
        """Ni la PSK de una VPN, que ya no existe, ni {h, p, f, t} en otro orden o con algo más: ni arranca."""
        import unittest.mock
        credenciales = tempfile.mkdtemp(prefix="hh-cred-")
        self.addCleanup(shutil.rmtree, credenciales, True)
        arrancados = []
        for carga in (CARGA_DE_LA_VPN, dict(CARGA, k="x"), {k: CARGA[k] for k in ("t", "f", "p", "h")}, None):
            with self.subTest(carga=carga):
                with open(os.path.join(credenciales, "canje"), "w") as f:
                    json.dump({"llave": canje.b64url(self.llave), "codigo": self.codigo, "huella": self.huella,
                               "carga": carga, "puerto": 0, "direccion": "127.0.0.1"}, f)
                salida = io.StringIO()
                with unittest.mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": credenciales}), \
                        unittest.mock.patch.object(canje, "servir", lambda *a, **k: arrancados.append(a) or 0), \
                        contextlib.redirect_stdout(salida):
                    self.assertEqual(canje.main(["servir"]), 2)
                self.assertIn("solo entrega {h, p, f, t}", salida.getvalue())
        self.assertEqual(arrancados, [])

    def test_preparar_imprime_la_huella(self):
        otra = tempfile.mkdtemp(prefix="hh-canje-")
        self.addCleanup(shutil.rmtree, otra, True)
        r = subprocess.run([sys.executable, "-B", "-m", "hehermes_servidor.canje", "preparar", otra],
                           cwd=str(apoyo.RAIZ), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(json.loads(r.stdout)["huella"], r"^[A-Za-z0-9_-]{43}$")


if __name__ == "__main__":
    unittest.main()
