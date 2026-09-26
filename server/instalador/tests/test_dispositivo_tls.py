"""`hehermes-dispositivo` con la pasarela TLS: alta, baja, rotar, lista y qr.

El script se carga como módulo, con su `pasarela.ini` en una carpeta temporal que apunta a una copia del código del
instalador (el de `[instalador] codigo`) y al certificado de prueba.
"""

import apoyo

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from hehermes_servidor import pasarela as pa

RUTA = apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo"
CERT = apoyo.DATOS / "pasarela-NO-ES-DE-DANIEL.cert.pem"
HUELLA_CERT = "0GUKsxTavhZWbjkIBTXZmhJX0PMoBKdRcxK1ljakLyc"


def cargar():
    cargador = importlib.machinery.SourceFileLoader("hehermes_dispositivo_tls", str(RUTA))
    modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader("hehermes_dispositivo_tls", cargador))
    cargador.exec_module(modulo)
    return modulo


class Terminal(io.StringIO):
    def isatty(self):
        return True


class ConPasarela(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.mkdtemp(prefix="hh-disp-tls-")
        self.addCleanup(shutil.rmtree, self.carpeta)
        c = lambda n: os.path.join(self.carpeta, n)  # noqa: E731
        self.c = c
        shutil.copytree(apoyo.RAIZ / "hehermes_servidor", c("codigo/hehermes_servidor"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(CERT, c("cert.pem"))
        self.tokens = c("tokens.json")
        with open(c("pasarela.ini"), "w") as f:
            f.write("[pasarela]\npuerto = 61234\ncertificado = %s\nclave = /x\ntokens = %s\n[hermes]\npuerto = 8642\n"
                    "clave = /x\n[qr]\ndireccion = 203.0.113.7\n[instalador]\ncodigo = %s\n"
                    % (c("cert.pem"), self.tokens, c("codigo")))
        self.m = cargar()
        self.m.REGISTRO = c("no-hay-vpn/dispositivos.json")
        mock.patch.object(self.m, "ruta_pasarela_ini", lambda: c("pasarela.ini")).start()
        # Se carga ya, con el usuario de la prueba: las que hacen de root no podrían fiarse de sus ficheros.
        self.m.pasarela()
        self.qr = []
        self.addCleanup(mock.patch.stopall)

    def orden(self, nombre, *args, terminal=True):
        salida = Terminal() if terminal else io.StringIO()
        errores = io.StringIO()
        p = self.m.pasarela()
        with contextlib.ExitStack() as pila:
            if p is not None:
                real = p["modulo_qr"].terminal
                pila.enter_context(mock.patch.object(p["modulo_qr"], "terminal",
                                                     lambda texto: self.qr.append(texto) or real(texto)))
            with contextlib.redirect_stdout(salida), contextlib.redirect_stderr(errores):
                try:
                    self.m.COMANDOS[nombre](list(args))
                    codigo = 0
                except SystemExit as salir:
                    codigo = salir.code
        return codigo, salida.getvalue() + errores.getvalue()

    def token_del_qr(self, texto):
        prefijo = "hehermes-tls:1?h=203.0.113.7&p=61234&f=%s&t=" % HUELLA_CERT
        self.assertTrue(texto.startswith(prefijo), texto)
        return texto[len(prefijo):]


class ElAlta(ConPasarela):
    def test_en_un_terminal_da_el_token_y_pinta_su_qr(self):
        codigo, texto = self.orden("alta", "mi-iphone")
        self.assertEqual(codigo, 0, texto)
        token = self.token_del_qr(self.qr[-1])
        self.assertEqual(pa.Tokens(self.tokens).quien(token), "mi-iphone")
        self.assertIn("▀", texto)
        self.assertNotIn(token, texto)
        self.assertIn("ni lo compartas", texto)

    def test_con_tls_explicito_tambien(self):
        codigo, texto = self.orden("alta", "mi-iphone", "--tls")
        self.assertEqual(codigo, 0, texto)

    def test_fuera_de_un_terminal_no_hace_nada(self):
        codigo, texto = self.orden("alta", "mi-iphone", terminal=False)
        self.assertEqual(codigo, 1)
        self.assertIn("terminal", texto)
        self.assertFalse(os.path.exists(self.tokens))
        self.assertEqual(self.qr, [])

    def test_como_root_sin_sudo_tampoco(self):
        with mock.patch.object(self.m.os, "geteuid", lambda: 0), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_USER", None)
            codigo, texto = self.orden("alta", "mi-iphone")
        self.assertEqual(codigo, 1)
        self.assertIn("con sudo", texto)
        self.assertFalse(os.path.exists(self.tokens))

    def test_con_sudo_si(self):
        with mock.patch.object(self.m.os, "geteuid", lambda: 0), mock.patch.dict(os.environ, {"SUDO_USER": "daniel"}):
            codigo, texto = self.orden("alta", "mi-iphone")
        self.assertEqual(codigo, 0, texto)

    def test_dos_veces_el_mismo_no(self):
        self.orden("alta", "mi-iphone")
        codigo, texto = self.orden("alta", "mi-iphone")
        self.assertEqual(codigo, 1)
        self.assertIn("rotar", texto)

    def test_con_opciones_de_la_vpn_no(self):
        codigo, texto = self.orden("alta", "mi-iphone", "--tls", "--ikev2")
        self.assertEqual(codigo, 1)

    def test_no_importa_codigo_que_otro_puede_cambiar(self):
        os.chmod(self.c("codigo/hehermes_servidor"), 0o777)
        self.addCleanup(os.chmod, self.c("codigo/hehermes_servidor"), 0o755)
        self.m._pasarela = None
        salida = io.StringIO()
        with contextlib.redirect_stderr(salida), self.assertRaises(SystemExit):
            self.m.pasarela()
        self.assertIn("no me fío", salida.getvalue())


class LaBajaYRotar(ConPasarela):
    def setUp(self):
        super().setUp()
        self.orden("alta", "mi-iphone")
        self.viejo = self.token_del_qr(self.qr[-1])

    def test_la_baja_lo_invalida_al_momento(self):
        codigo, texto = self.orden("baja", "mi-iphone", terminal=False)
        self.assertEqual(codigo, 0, texto)
        self.assertIsNone(pa.Tokens(self.tokens).quien(self.viejo))
        self.assertIn("ya no vale", texto)
        codigo, texto = self.orden("baja", "mi-iphone", terminal=False)
        self.assertEqual(codigo, 1)

    def test_rotar_da_otro_y_pinta_su_qr(self):
        codigo, texto = self.orden("rotar", "mi-iphone")
        self.assertEqual(codigo, 0, texto)
        nuevo = self.token_del_qr(self.qr[-1])
        self.assertNotEqual(nuevo, self.viejo)
        tokens = pa.Tokens(self.tokens)
        self.assertIsNone(tokens.quien(self.viejo))
        self.assertEqual(tokens.quien(nuevo), "mi-iphone")

    def test_rotar_fuera_de_un_terminal_no_toca_nada(self):
        antes = open(self.tokens).read()
        codigo, _ = self.orden("rotar", "mi-iphone", terminal=False)
        self.assertEqual(codigo, 1)
        self.assertEqual(open(self.tokens).read(), antes)

    def test_la_lista_dice_el_modo(self):
        codigo, texto = self.orden("lista", terminal=False)
        self.assertEqual(codigo, 0, texto)
        self.assertRegex(texto, r"mi-iphone\s+tls\s")
        self.assertIn("puerto 61234", texto)
        self.assertNotIn(json.load(open(self.tokens))["tokens"][0]["sha256"], texto)

    def test_el_qr_no_se_puede_volver_a_pintar(self):
        codigo, texto = self.orden("qr", "mi-iphone")
        self.assertEqual(codigo, 1)
        self.assertIn("rotar mi-iphone", texto)
        self.assertEqual(len(self.qr), 1)


class ConLosDos(ConPasarela):
    """La pasarela y la VPN IKEv2 del instalador (su servidor.ini) en el mismo servidor, como root con sudo."""

    def setUp(self):
        super().setUp()
        self.ini_vpn = self.c("servidor.ini")
        with open(self.ini_vpn, "w") as f:
            f.write("[servidor]\ndireccion = 203.0.113.7\n")
        self.m.SERVIDOR_INI = self.ini_vpn
        self.m.aplicar_servidor_ini(self.ini_vpn)
        self.ikev2 = []
        mock.patch.object(self.m, "alta_ikev2", lambda nombre, servidor: self.ikev2.append((nombre, servidor))).start()
        mock.patch.object(self.m.os, "geteuid", lambda: 0).start()
        mock.patch.dict(os.environ, {"SUDO_USER": "daniel"}).start()

    def test_sin_decir_cual_no_adivina(self):
        codigo, texto = self.orden("alta", "otro")
        self.assertEqual(codigo, 1)
        self.assertIn("aquí están la pasarela TLS y la VPN IKEv2: di cuál", texto)
        self.assertIn("alta otro --tls", texto)
        self.assertIn("alta otro --ikev2", texto)
        self.assertFalse(os.path.exists(self.tokens))
        self.assertEqual(self.ikev2, [])

    def test_con_tls_la_pasarela(self):
        codigo, texto = self.orden("alta", "otro", "--tls")
        self.assertEqual(codigo, 0, texto)
        self.assertEqual(pa.Tokens(self.tokens).quien(self.token_del_qr(self.qr[-1])), "otro")
        self.assertEqual(self.ikev2, [])

    def test_con_ikev2_la_vpn(self):
        codigo, texto = self.orden("alta", "otro", "--ikev2")
        self.assertEqual(codigo, 0, texto)
        self.assertEqual(self.ikev2, [("otro", "203.0.113.7")])
        self.assertFalse(os.path.exists(self.tokens))

    def test_solo_la_vpn_elige_la_vpn(self):
        self.m._pasarela = None
        mock.patch.object(self.m, "ruta_pasarela_ini", lambda: self.c("no-hay.ini")).start()
        codigo, texto = self.orden("alta", "otro")
        self.assertEqual(codigo, 0, texto)
        self.assertEqual(self.ikev2, [("otro", "203.0.113.7")])

    def test_solo_la_pasarela_elige_la_pasarela(self):
        os.unlink(self.ini_vpn)
        codigo, texto = self.orden("alta", "otro")
        self.assertEqual(codigo, 0, texto)
        self.assertEqual(pa.Tokens(self.tokens).quien(self.token_del_qr(self.qr[-1])), "otro")
        self.assertEqual(self.ikev2, [])

    def test_la_lista_dice_el_modo_de_cada_uno(self):
        self.orden("alta", "de-la-pasarela", "--tls")
        os.makedirs(os.path.dirname(self.m.REGISTRO))
        with open(self.m.REGISTRO, "w") as f:
            json.dump({"dispositivos": [{"nombre": "mi-iphone", "tipo": "ikev2", "ip": "10.77.1.3", "conexion":
                                         "hh-mi-iphone", "alta": "2026-09-24T10:00:00+00:00"}]}, f)
        mock.patch.object(self.m, "sas_ikev2", lambda: {"hh-mi-iphone": "ESTABLISHED"}).start()
        mock.patch.object(self.m.subprocess, "run", lambda *a, **k: mock.Mock(returncode=1)).start()
        codigo, texto = self.orden("lista", terminal=False)
        self.assertEqual(codigo, 0, texto)
        self.assertRegex(texto, r"de-la-pasarela\s+tls\s")
        self.assertRegex(texto, r"mi-iphone\s+ikev2\s+10\.77\.1\.3")
        self.assertNotIn("Sin dispositivos", texto)

    def test_baja_con_ikev2_es_de_la_vpn(self):
        self.orden("alta", "mi-iphone", "--tls")
        self.assertEqual(self.m.modo_de(["--ikev2"], "mi-iphone"), "vpn")
        self.assertEqual(self.m.modo_de(["--vpn"], "mi-iphone"), "vpn")
        self.assertEqual(self.m.modo_de([], "mi-iphone"), "tls")


class SinPasarela(unittest.TestCase):
    def test_sin_root_ni_pasarela_pide_root(self):
        m = cargar()
        with tempfile.TemporaryDirectory() as carpeta:
            with mock.patch.object(m, "ruta_pasarela_ini", lambda: os.path.join(carpeta, "no.ini")), \
                    mock.patch.object(m.sys, "argv", ["hehermes-dispositivo", "lista"]), \
                    mock.patch.object(m.os, "geteuid", lambda: 1000):
                errores = io.StringIO()
                with contextlib.redirect_stderr(errores), self.assertRaises(SystemExit):
                    m.main()
        self.assertIn("como root", errores.getvalue())


if __name__ == "__main__":
    unittest.main()
