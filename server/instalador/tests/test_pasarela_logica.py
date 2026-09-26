"""La pasarela sin red: los tokens, los límites, la clave de Hermes, la configuración y la huella del certificado.

Lo que decide si una petición pasa está aquí, en funciones que se prueban sin abrir un solo puerto. Lo de la red, en
`test_pasarela_red.py`.
"""

import apoyo

import base64
import hashlib
import json
import os
import ssl
import tempfile
import unittest
from unittest import mock

from hehermes_servidor import pasarela as pa

CERT = apoyo.DATOS / "pasarela-NO-ES-DE-DANIEL.cert.pem"
#: La huella del certificado de prueba, sacada con `cryptography` al hacerlo (SHA-256 de su SPKI, en base64url).
HUELLA_CERT = "0GUKsxTavhZWbjkIBTXZmhJX0PMoBKdRcxK1ljakLyc"


def token(n=0):
    return base64.urlsafe_b64encode(bytes([n]) * 32).rstrip(b"=").decode()


class Reloj:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class ConFichero(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.carpeta.name, "tokens.json")

    def tearDown(self):
        self.carpeta.cleanup()

    def escribir(self, entradas):
        datos = {"v": 1, "tokens": [{"nombre": n, "sha256": pa.hash_token(t)} for n, t in entradas]}
        temporal = self.ruta + ".nuevo"
        with open(temporal, "w") as f:
            json.dump(datos, f)
        os.replace(temporal, self.ruta)


class ElToken(ConFichero):
    def test_el_hash_es_el_sha256_del_texto_en_hexadecimal(self):
        self.assertEqual(pa.hash_token(token(1)), hashlib.sha256(token(1).encode("ascii")).hexdigest())

    def test_uno_dado_de_alta_vale_y_dice_de_quien_es(self):
        self.escribir([("mi-iphone", token(1)), ("otro", token(2))])
        tokens = pa.Tokens(self.ruta)
        self.assertEqual(tokens.quien(token(1)), "mi-iphone")
        self.assertEqual(tokens.quien(token(2)), "otro")

    def test_lo_que_no_es_un_token_dado_no_vale(self):
        self.escribir([("mi-iphone", token(1))])
        tokens = pa.Tokens(self.ruta)
        uno = token(1)
        for malo in (token(3), uno[:-1], uno + "A", uno[:-1] + "=", " " + uno[1:], uno.upper() if uno != uno.upper()
                     else token(4), "", None, 12, uno.encode()):
            with self.subTest(malo=malo):
                self.assertIsNone(tokens.quien(malo))

    def test_uno_que_no_es_ascii_no_rompe_nada(self):
        """Sin mirar antes su forma, el hash de un texto que no es ASCII lanzaría una excepción, y la conexión se
        cerraría sin el 404 de siempre: se notaría que ahí hay algo."""
        self.escribir([("mi-iphone", token(1))])
        tokens = pa.Tokens(self.ruta)
        for raro in ("ñ" * 43, token(1)[:-1] + "é", "\udcff" * 43):
            with self.subTest(raro=raro):
                self.assertIsNone(tokens.quien(raro))

    def test_el_hash_guardado_no_vale_como_token(self):
        self.escribir([("mi-iphone", token(1))])
        self.assertIsNone(pa.Tokens(self.ruta).quien(pa.hash_token(token(1))))

    def test_se_compara_en_tiempo_constante_con_todas_las_entradas(self):
        """Sin salir en la primera que coincide: el tiempo no dice cuál es ni cuántas hay antes. Y con
        `hmac.compare_digest`, que no se para en el primer byte distinto."""
        self.escribir([("a", token(1)), ("b", token(2)), ("c", token(3))])
        tokens = pa.Tokens(self.ruta)
        llamadas = []
        real = pa.hmac.compare_digest

        def espia(x, y):
            llamadas.append((x, y))
            return real(x, y)

        with mock.patch.object(pa.hmac, "compare_digest", espia):
            self.assertEqual(tokens.quien(token(1)), "a")
        self.assertEqual(len(llamadas), 3)
        with mock.patch.object(pa.hmac, "compare_digest", espia):
            self.assertIsNone(tokens.quien(token(9)))
        self.assertEqual(len(llamadas), 6)

    def test_una_baja_vale_en_cuanto_cambia_el_fichero(self):
        self.escribir([("mi-iphone", token(1)), ("otro", token(2))])
        tokens = pa.Tokens(self.ruta)
        antes = pa.hash_token(token(1))
        self.assertTrue(tokens.sigue(antes))
        self.escribir([("otro", token(2))])
        self.assertTrue(tokens.recargar_si_cambia())
        self.assertIsNone(tokens.quien(token(1)))
        self.assertFalse(tokens.sigue(antes))
        self.assertEqual(tokens.quien(token(2)), "otro")
        self.assertFalse(tokens.recargar_si_cambia())

    def test_sin_fichero_o_con_uno_roto_no_vale_nada(self):
        self.assertIsNone(pa.Tokens(self.ruta).quien(token(1)))
        with open(self.ruta, "w") as f:
            f.write("{no es json")
        self.assertIsNone(pa.Tokens(self.ruta).quien(token(1)))

    def test_un_fichero_roto_despues_de_uno_bueno_deja_de_valer_todo(self):
        """Un tokens.json que no se entiende no deja pasar a nadie: cerrado, no con lo de antes."""
        self.escribir([("mi-iphone", token(1))])
        tokens = pa.Tokens(self.ruta)
        with open(self.ruta, "w") as f:
            f.write("{roto")
        tokens.recargar_si_cambia()
        self.assertIsNone(tokens.quien(token(1)))

    def test_un_token_nuevo_es_de_32_bytes_al_azar_en_base64url(self):
        vistos = {pa.token_nuevo() for _ in range(50)}
        self.assertEqual(len(vistos), 50)
        for t in vistos:
            self.assertRegex(t, r"^[A-Za-z0-9_-]{43}$")
            self.assertEqual(len(base64.urlsafe_b64decode(t + "=")), 32)


class LosLimites(unittest.TestCase):
    def setUp(self):
        self.reloj = Reloj()
        self.l = pa.Limites(reloj=self.reloj, contar_locales=True)

    def test_diez_fallos_en_diez_minutos_bloquean_quince(self):
        for _ in range(pa.MAX_FALLOS - 1):
            self.l.fallo("198.51.100.1")
        self.assertFalse(self.l.bloqueada("198.51.100.1"))
        self.assertTrue(self.l.admitir("198.51.100.1"))
        self.l.soltar("198.51.100.1")
        self.l.fallo("198.51.100.1")
        self.assertTrue(self.l.bloqueada("198.51.100.1"))
        self.assertFalse(self.l.admitir("198.51.100.1"))
        self.assertTrue(self.l.admitir("198.51.100.2"))
        self.reloj.t += pa.BLOQUEO - 1
        self.assertTrue(self.l.bloqueada("198.51.100.1"))
        self.reloj.t += 2
        self.assertFalse(self.l.bloqueada("198.51.100.1"))
        self.assertTrue(self.l.admitir("198.51.100.1"))

    def test_los_de_este_servidor_no_cuentan(self):
        """`comprobar` se asoma sin token desde 127.0.0.1: si contara, diez comprobaciones la bloquearían."""
        limites = pa.Limites(reloj=self.reloj)
        for ip in ("127.0.0.1", "::1"):
            for _ in range(pa.MAX_FALLOS * 2):
                limites.fallo(ip)
            self.assertFalse(limites.bloqueada(ip))
            self.assertTrue(limites.admitir(ip))

    def test_los_fallos_viejos_caducan(self):
        for _ in range(pa.MAX_FALLOS - 1):
            self.l.fallo("198.51.100.1")
        self.reloj.t += pa.VENTANA_FALLOS + 1
        self.l.fallo("198.51.100.1")
        self.assertFalse(self.l.bloqueada("198.51.100.1"))

    def test_los_numeros_son_los_del_contrato(self):
        self.assertEqual((pa.MAX_FALLOS, pa.VENTANA_FALLOS, pa.BLOQUEO), (10, 600, 900))
        self.assertEqual((pa.CONEXIONES_POR_IP, pa.CONEXIONES_EN_TOTAL), (16, 128))
        self.assertEqual((pa.PLAZO_CABECERAS, pa.PLAZO_PARADA, pa.RETRASO_404), (10, 75, 1.0))
        self.assertEqual((pa.MAX_CUERPO, pa.MAX_CUERPO_AVISOS), (25 * 1024 * 1024, 64 * 1024))
        self.assertEqual((pa.MAX_CABECERAS, pa.MAX_LINEAS_CABECERA), (16 * 1024, 100))

    def test_dieciseis_conexiones_por_ip(self):
        for _ in range(pa.CONEXIONES_POR_IP):
            self.assertTrue(self.l.admitir("198.51.100.1"))
        self.assertFalse(self.l.admitir("198.51.100.1"))
        self.l.soltar("198.51.100.1")
        self.assertTrue(self.l.admitir("198.51.100.1"))

    def test_ciento_veintiocho_en_total(self):
        for i in range(pa.CONEXIONES_EN_TOTAL):
            self.assertTrue(self.l.admitir("10.0.%d.%d" % (i // 200, i % 200)))
        self.assertFalse(self.l.admitir("198.51.100.200"))
        self.l.soltar("10.0.0.0")
        self.assertTrue(self.l.admitir("198.51.100.200"))

    def test_soltar_no_baja_de_cero(self):
        self.l.soltar("198.51.100.1")
        self.assertEqual(self.l.abiertas, 0)
        self.assertTrue(self.l.admitir("198.51.100.1"))
        self.assertEqual(self.l.abiertas, 1)

    def test_la_memoria_no_crece_sin_fin(self):
        for i in range(pa.MAX_IPS + 500):
            self.l.fallo("10.%d.%d.%d" % (i // 65536, (i // 256) % 256, i % 256))
        self.assertLessEqual(len(self.l._fallos), pa.MAX_IPS)

    def test_con_la_memoria_llena_los_bloqueos_siguen(self):
        for _ in range(pa.MAX_FALLOS):
            self.l.fallo("198.51.100.1")
        for i in range(pa.MAX_IPS + 10):
            self.l.fallo("10.%d.%d.%d" % (i // 65536, (i // 256) % 256, i % 256))
        self.assertTrue(self.l.bloqueada("198.51.100.1"))


class LaClaveDeHermes(unittest.TestCase):
    def test_de_un_env(self):
        self.assertEqual(pa.leer_clave_hermes('# .env\nAPI_SERVER_ENABLED=true\nexport API_SERVER_KEY="k1-2"\n'),
                         "k1-2")

    def test_de_un_fichero_con_la_clave_sola(self):
        self.assertEqual(pa.leer_clave_hermes("k1-2\n"), "k1-2")

    def test_nada_o_algo_raro(self):
        for texto in ("", "\n", "API_SERVER_ENABLED=true\n", "dos palabras\n", 'a"b\n', "k\r\n\x00"):
            with self.subTest(texto=texto):
                self.assertIsNone(pa.leer_clave_hermes(texto))


class LaHuella(unittest.TestCase):
    def test_la_del_spki_sin_cryptography(self):
        der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
        self.assertEqual(pa.huella_de_der(der), HUELLA_CERT)

    def test_un_der_roto(self):
        for roto in (b"", b"\x30", b"\x30\x05\x02\x01", b"\x04\x00", b"\x30\x84\xff\xff\xff\xff"):
            with self.subTest(roto=roto):
                with self.assertRaises(ValueError):
                    pa.huella_de_der(roto)


class LaConfiguracion(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.c = lambda n: os.path.join(self.carpeta.name, n)  # noqa: E731

    def tearDown(self):
        self.carpeta.cleanup()

    def ini(self, texto):
        with open(self.c("pasarela.ini"), "w") as f:
            f.write(texto)
        return self.c("pasarela.ini")

    def test_lee_lo_que_escribe_el_instalador(self):
        ruta = self.ini("[pasarela]\npuerto = 61234\ncertificado = /c/cert.pem\nclave = /c/clave.pem\n"
                        "tokens = /c/tokens.json\n[hermes]\npuerto = 8642\nclave = /root/.hermes/.env\n"
                        "[avisos]\nvigia = 127.0.0.1:8790\nsecreto = /s\n")
        c = pa.Configuracion.leer(ruta, credenciales=None)
        self.assertEqual((c.puerto, c.certificado, c.clave, c.tokens), (61234, "/c/cert.pem", "/c/clave.pem",
                                                                         "/c/tokens.json"))
        self.assertEqual((c.puerto_hermes, c.clave_hermes), (8642, "/root/.hermes/.env"))
        self.assertEqual((c.vigia, c.secreto_vigia), (("127.0.0.1", 8790), "/s"))
        self.assertEqual(c.escucha, "")

    def test_las_credenciales_de_systemd_mandan(self):
        os.makedirs(self.c("cred"))
        for nombre in ("clave", "hermes", "vigia"):
            with open(self.c("cred/" + nombre), "w") as f:
                f.write("x")
        ruta = self.ini("[pasarela]\npuerto = 61234\ncertificado = /c/cert.pem\nclave = /c/clave.pem\n"
                        "tokens = /c/tokens.json\n[hermes]\npuerto = 8642\nclave = /c/clave-hermes\n"
                        "[avisos]\nvigia = 127.0.0.1:8790\nsecreto = /s\n")
        c = pa.Configuracion.leer(ruta, credenciales=self.c("cred"))
        self.assertEqual((c.clave, c.clave_hermes, c.secreto_vigia),
                         (self.c("cred/clave"), self.c("cred/hermes"), self.c("cred/vigia")))

    def test_sin_avisos(self):
        ruta = self.ini("[pasarela]\npuerto = 61234\ncertificado = /a\nclave = /b\ntokens = /t\n"
                        "[hermes]\npuerto = 8642\nclave = /e\n")
        c = pa.Configuracion.leer(ruta, credenciales=None)
        self.assertIsNone(c.vigia)

    def test_lo_que_no_vale(self):
        for texto in ("[pasarela]\npuerto = 0\ncertificado = /a\nclave = /b\ntokens = /t\n[hermes]\npuerto = 1\nclave = /e\n",
                      "[pasarela]\npuerto = 61234\ncertificado = a\nclave = /b\ntokens = /t\n[hermes]\npuerto = 1\nclave = /e\n",
                      "[pasarela]\npuerto = 61234\n",
                      "[pasarela]\npuerto = 61234\ncertificado = /a\nclave = /b\ntokens = /t\n[hermes]\npuerto = 1\n"
                      "clave = /e\n[avisos]\nvigia = 10.0.0.1:8790\nsecreto = /s\n"):
            with self.subTest(texto=texto):
                with self.assertRaises(ValueError):
                    pa.Configuracion.leer(self.ini(texto), credenciales=None)


class ElSecreto(unittest.TestCase):
    """La clave de Hermes y el secreto del vigía se vuelven a leer si su fichero cambia: sin root, el .env de Hermes."""

    def test_se_relee_al_cambiar(self):
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = os.path.join(carpeta, "env")
            with open(ruta, "w") as f:
                f.write("API_SERVER_KEY=uno\n")
            s = pa.Secreto(ruta, pa.leer_clave_hermes)
            self.assertEqual(s.valor(), "uno")
            with open(ruta + ".n", "w") as f:
                f.write("API_SERVER_KEY=dos-mas-larga\n")
            os.replace(ruta + ".n", ruta)
            self.assertEqual(s.valor(), "dos-mas-larga")
            os.unlink(ruta)
            self.assertIsNone(s.valor())


if __name__ == "__main__":
    unittest.main()
