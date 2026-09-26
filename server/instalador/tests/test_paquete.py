"""El paquete por versión con su SHA-256, el comando que da la app, y la firma Ed25519 de las actualizaciones."""

import apoyo

import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock

import servidor_falso as sf
from hehermes_servidor import VERSION
from hehermes_servidor import ambito
from hehermes_servidor import firma
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
from hehermes_servidor.plan import Opciones
from hehermes_servidor.sistema import Resultado, Sistema

PRIVADA = apoyo.DATOS / "clave-de-prueba-NO-ES-DE-DANIEL.pem"
PUBLICA = apoyo.DATOS / "clave-de-prueba-NO-ES-DE-DANIEL.pub.pem"


def cargar_empaquetar():
    ruta = apoyo.RAIZ / "empaquetar"
    cargador = importlib.machinery.SourceFileLoader("empaquetar", str(ruta))
    modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader("empaquetar", cargador))
    cargador.exec_module(modulo)
    return modulo


class Paquete(unittest.TestCase):
    def setUp(self):
        self.e = cargar_empaquetar()
        self.carpeta = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.carpeta)

    def construir(self, sub="a"):
        return self.e.construir(VERSION, os.path.join(self.carpeta, sub))

    def test_es_reproducible_y_la_suma_es_la_del_fichero(self):
        ruta, suma = self.construir("a")
        otra, suma2 = self.construir("b")
        self.assertEqual(suma, suma2, "dos veces, la misma suma: la app la lleva escrita")
        with open(ruta, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), suma)
        self.assertEqual(os.path.basename(ruta), "hehermes-servidor-%s.tar.gz" % VERSION)
        with open(ruta + ".sha256") as f:
            self.assertEqual(f.read(), "%s  hehermes-servidor-%s.tar.gz\n" % (suma, VERSION))

    def test_lleva_lo_que_tiene_que_llevar_y_nada_mas(self):
        ruta, _ = self.construir()
        prefijo = "hehermes-servidor-%s/" % VERSION
        with tarfile.open(ruta) as tar:
            miembros = {m.name: m for m in tar.getmembers()}
        for nombre, m in miembros.items():
            with self.subTest(nombre=nombre):
                self.assertTrue(nombre.startswith(prefijo) or nombre == prefijo.rstrip("/"))
                self.assertNotIn("..", nombre.split("/"))
                self.assertFalse(nombre.startswith("/"))
                self.assertTrue(m.isfile() or m.isdir(), "ni enlaces ni dispositivos")
                self.assertNotIn("__pycache__", nombre)
                self.assertNotIn("/tests/", nombre)
                self.assertFalse(nombre.endswith(".pyc"))
                self.assertEqual((m.uid, m.gid, m.uname, m.gname), (0, 0, "root", "root"))
        for nombre, modo in (("hehermes-servidor", 0o755), ("hehermes-pasarela", 0o755),
                             ("hehermes_servidor/pasarela.py", 0o644), ("hehermes_servidor/qr.py", 0o644),
                             ("hehermes_servidor/cli.py", 0o644), ("hehermes_servidor/desinstalar.py", 0o644),
                             ("hehermes_servidor/modos.py", 0o644),
                             ("hehermes_servidor/plan.py", 0o644), ("clave-publica.pem", 0o644),
                             ("hehermes-dispositivo", 0o755), ("README.md", 0o644),
                             ("requirements-canje.txt", 0o644), ("hehermes_servidor/canje.py", 0o644),
                             ("hehermes_servidor/porchat.py", 0o644)):
            with self.subTest(fichero=nombre):
                self.assertIn(prefijo + nombre, miembros)
                self.assertEqual(miembros[prefijo + nombre].mode, modo)
        # Los avisos solo los instalaba --avisos, que iba con la VPN: ya no van.
        self.assertFalse([n for n in miembros if n.startswith(prefijo + "avisos")])
        ficheros = sorted(n[len(prefijo):] for n, m in miembros.items() if m.isfile())
        modulos = sorted("hehermes_servidor/" + p.name for p in (apoyo.RAIZ / "hehermes_servidor").glob("*.py"))
        self.assertEqual(ficheros, sorted(["README.md", "clave-publica.pem", "hehermes-dispositivo", "hehermes-pasarela",
                                           "hehermes-servidor", "requirements-canje.txt"] + modulos))
        # El dispositivo es el de server/vpn, byte a byte.
        with tarfile.open(ruta) as tar:
            dentro = tar.extractfile(prefijo + "hehermes-dispositivo").read()
        self.assertEqual(dentro, (apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo").read_bytes())

    def test_desempaquetado_se_encuentra_todo_sin_el_repositorio(self):
        ruta, _ = self.construir()
        fuera = os.path.join(self.carpeta, "fuera")
        with tarfile.open(ruta) as tar:
            tar.extractall(fuera)
        origen = os.path.join(fuera, "hehermes-servidor-%s" % VERSION)
        sis, falso = sf.servidor()
        self.addCleanup(sis.limpiar)
        man = Manifiesto()
        plan = calcular_plan_tls(sis, detectar_tls(sis, man, ambito.de_root()), man, Opciones(iphone="mi-iphone"),
                                 origen)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        dispositivo = next(a for a in plan.acciones if a.objeto == "/usr/local/sbin/hehermes-dispositivo")
        with open(os.path.join(origen, "hehermes-dispositivo"), "rb") as f:
            self.assertEqual(dispositivo.datos, f.read())

    def test_el_comando_de_la_app(self):
        comando = self.e.comando("https://ejemplo.org/hehermes", "0.1.0", "ab" * 32, "mi-iphone")
        self.assertEqual(comando, (
            'd=$(mktemp -d) && cd "$d" && curl -fsSLO https://ejemplo.org/hehermes/v0.1.0/hehermes-servidor-0.1.0.tar.gz'
            ' && echo "%s  hehermes-servidor-0.1.0.tar.gz" | sha256sum -c - && tar -xzf hehermes-servidor-0.1.0.tar.gz'
            ' && sudo ./hehermes-servidor-0.1.0/hehermes-servidor instalar --iphone mi-iphone') % ("ab" * 32))

    @unittest.skipUnless(apoyo.SPEC.exists(), "la spec no está aquí (el espejo público solo lleva el instalador)")
    def test_la_frase_por_chat_es_la_de_la_spec(self):
        frase = self.e.frase("https://ejemplo.org/hehermes", "0.2.0", "ab" * 32, "mi-iphone", "LLAVE")
        self.assertEqual(frase, frase_de_la_spec().replace("{url-base}", "https://ejemplo.org/hehermes")
                         .replace("{versión}", "0.2.0").replace("{sha256}", "ab" * 32).replace("{nombre}", "mi-iphone")
                         .replace("{llave}", "LLAVE"))
        self.assertIn(" instalar --por-chat --activar-api --iphone mi-iphone --llave LLAVE`", frase)

    def test_la_url_por_defecto_es_la_de_las_releases_de_github(self):
        # Decisión 1, por ahora: una Release `v<versión>` del repositorio público, con el paquete como asset.
        self.assertEqual(self.e.URL_BASE, "https://github.com/dnlmrls/HeHermes/releases/download")
        # La misma que usa el instalador para el comando del administrador (`permisos`).
        from hehermes_servidor import URL_BASE
        self.assertEqual(URL_BASE, self.e.URL_BASE)
        self.assertEqual(self.e.url_del_paquete(self.e.URL_BASE, "0.3.0"),
                         "https://github.com/dnlmrls/HeHermes/releases/download/v0.3.0/hehermes-servidor-0.3.0.tar.gz")
        self.assertIn(" curl -fsSLO https://github.com/dnlmrls/HeHermes/releases/download/v0.3.0/"
                      "hehermes-servidor-0.3.0.tar.gz && ", self.e.comando(self.e.URL_BASE, "0.3.0", "ab" * 32, "x"))
        with unittest.mock.patch.dict(os.environ, {"HEHERMES_URL_BASE": "https://otro.example/x/"}):
            self.assertEqual(self.e.url_base(None), "https://otro.example/x")
        self.assertEqual(self.e.url_base("https://a.example/hh"), "https://a.example/hh")
        for mala in ("http://a.example/hh", "https://a.example/hh?x=1", "ftp://x", "https://a b"):
            with self.subTest(url=mala), self.assertRaises(ValueError):
                self.e.url_base(mala)


def frase_de_la_spec() -> str:
    """El texto exacto de «La frase» de la spec: sus tres párrafos, cada uno en una línea."""
    spec = apoyo.SPEC.read_text()
    lineas = spec[spec.index("> Hermes, quiero conectar"):].splitlines()
    parrafos, actual = [], []
    for linea in lineas:
        if not linea.startswith(">"):
            break
        texto = linea[1:].strip()
        if texto:
            actual.append(texto)
        elif actual:
            parrafos.append(" ".join(actual))
            actual = []
    parrafos.append(" ".join(actual))
    return "\n\n".join(parrafos)


@unittest.skipUnless(apoyo.APP.is_dir(), "la app no está aquí (el espejo público solo lleva el instalador)")
class LaApp(unittest.TestCase):
    """La app es el ancla de confianza: lleva la versión y la suma del paquete, y con ellas escribe la frase."""

    BIENVENIDA = apoyo.APP / "HeHermesMensajes" / "Presentacion" / "Bienvenida.swift"
    FIXTURE = apoyo.APP / "HeHermesMensajesTests" / "Fixtures" / "frase-por-chat.json"

    def setUp(self):
        self.e = cargar_empaquetar()
        self.carpeta = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.carpeta)
        self.swift = self.BIENVENIDA.read_text()

    def constante(self, nombre):
        import re
        hallado = re.search(r'static let %s = "([^"]*)"' % nombre, self.swift)
        self.assertTrue(hallado, "falta %s en Bienvenida.swift" % nombre)
        return hallado.group(1)

    def test_la_version_y_la_suma_son_las_del_paquete_de_hoy(self):
        _, suma = self.e.construir(VERSION, self.carpeta)
        self.assertEqual(self.constante("versionDelInstalador"), VERSION)
        self.assertEqual(self.constante("sha256DelPaquete"), suma,
                         "el paquete ha cambiado: server/instalador/empaquetar da la suma nueva, y va en Bienvenida.swift")
        self.assertEqual(self.constante("urlBaseDelPaquete"), self.e.URL_BASE)

    def test_la_frase_de_la_app_es_la_del_instalador(self):
        """`CanjeDelChatTests` compara la frase de la app con este fichero; aquí, el fichero con `empaquetar`."""
        import json
        _, suma = self.e.construir(VERSION, self.carpeta)
        datos = json.loads(self.FIXTURE.read_text())
        self.assertEqual(datos["frase"], self.e.frase(self.e.URL_BASE, VERSION, suma, "mi-iphone", "{llave}"))

    def test_el_comando_por_ssh_de_la_app_es_el_del_instalador(self):
        """«Conecta tu servidor» enseña el instalador, no el alta de `hehermes-dispositivo`, que sin él no existe.
        `BienvenidaTests` compara el de la app con este fichero; aquí, el fichero con `empaquetar`."""
        import json
        _, suma = self.e.construir(VERSION, self.carpeta)
        datos = json.loads(self.FIXTURE.read_text())
        self.assertEqual(datos["comando"], self.e.comando(self.e.URL_BASE, VERSION, suma, "mi-iphone"))
        self.assertNotIn("hehermes-dispositivo", datos["comando"])


class Firma(unittest.TestCase):
    def test_la_clave_publica_del_paquete_es_un_marcador(self):
        texto = (apoyo.RAIZ / "clave-publica.pem").read_text()
        self.assertTrue(firma.pendiente(texto))
        self.assertIn(firma.MARCADOR, texto)
        self.assertNotIn("BEGIN PUBLIC KEY", texto, "la de Daniel no está en el repositorio")
        self.assertFalse(firma.pendiente(PUBLICA.read_text()))

    def test_la_de_prueba_esta_marcada(self):
        for ruta in (PRIVADA, PUBLICA):
            self.assertIn("NO-ES-DE-DANIEL", ruta.name)
            self.assertIn("CLAVE DE PRUEBA, NO ES DE DANIEL", ruta.read_text())

    def test_verificar_llama_a_openssl_y_respeta_lo_que_dice(self):
        ordenes = []

        def openssl(args, entrada=None, heredar=False):
            ordenes.append(args)
            return respuesta

        sis = Sistema(ejecutor=openssl)
        respuesta = Resultado(0, "Signature Verified Successfully\n")
        self.assertTrue(firma.verificar(sis, "/tmp/p.tar.gz", "/tmp/p.tar.gz.sig", "/opt/k.pem"))
        self.assertEqual(ordenes[-1], ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", "/opt/k.pem", "-rawin",
                                       "-in", "/tmp/p.tar.gz", "-sigfile", "/tmp/p.tar.gz.sig"])
        for respuesta in (Resultado(1, "Signature Verification Failure\n"), Resultado(0, ""),
                          Resultado(1, "Signature Verified Successfully\n")):
            with self.subTest(respuesta=respuesta):
                self.assertFalse(firma.verificar(sis, "/tmp/p", "/tmp/s", "/opt/k.pem"))

    def test_la_clave_de_prueba_es_ed25519_y_firma_como_openssl_rawin(self):
        try:
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest("sin cryptography (va en el venv de server/avisos)")
        # Los PEM llevan delante el aviso de que son de prueba; openssl lo salta, cryptography no.
        privada = serialization.load_pem_private_key(b"-----BEGIN" + PRIVADA.read_bytes().split(b"-----BEGIN", 1)[1],
                                                     None)
        publica = serialization.load_pem_public_key(b"-----BEGIN" + PUBLICA.read_bytes().split(b"-----BEGIN", 1)[1])
        mensaje = b"hehermes-servidor-0.1.0.tar.gz de prueba"
        sello = privada.sign(mensaje)
        self.assertEqual(len(sello), 64, "Ed25519 puro: 64 bytes, lo que da `openssl pkeyutl -sign -rawin`")
        publica.verify(sello, mensaje)

    def test_con_openssl_3_de_verdad(self):
        # En el Mac hay LibreSSL, que no sabe Ed25519: esta prueba solo corre donde haya OpenSSL 3 (el servidor).
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.startswith("OpenSSL 3"):
            self.skipTest("hace falta OpenSSL 3 (aquí: %s)" % (r.stdout.strip() or "ninguno"))
        with tempfile.TemporaryDirectory() as carpeta:
            paquete = os.path.join(carpeta, "p.tar.gz")
            with open(paquete, "wb") as f:
                f.write(b"un paquete")
            sello = paquete + ".sig"
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(PRIVADA), "-rawin", "-in", paquete,
                            "-out", sello], check=True)
            self.assertTrue(firma.verificar(Sistema(), paquete, sello, str(PUBLICA)))
            with open(paquete, "ab") as f:
                f.write(b" cambiado")
            self.assertFalse(firma.verificar(Sistema(), paquete, sello, str(PUBLICA)))


if __name__ == "__main__":
    unittest.main()
