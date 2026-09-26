"""`hehermes-dispositivo` con lo que queda de la VPN de antes de la 0.6.0: ni altas nuevas ni claves nuevas, pero las
de antes se ven en `lista` y se dan de baja como siempre (IKEv2 y WireGuard).

El script es de root y toca `/etc`: se carga como módulo con sus carpetas en una temporal, como root con sudo, y
swanctl de mentira.
"""

import apoyo

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

RUTA = apoyo.REPO / "server" / "vpn" / "hehermes-dispositivo"
POC = (apoyo.DATOS / "hehermes-poc-a-mano.conf").read_text()
PSK = "UFNLLWRlLWxhcy1wcnVlYmFzLXF1ZS1ubyBlcy1kZS1u"
CLAVE_WG = "A" * 42 + "E="


def cargar():
    cargador = importlib.machinery.SourceFileLoader("hehermes_dispositivo_vpn", str(RUTA))
    modulo = importlib.util.module_from_spec(importlib.util.spec_from_loader("hehermes_dispositivo_vpn", cargador))
    cargador.exec_module(modulo)
    return modulo


class Terminal(io.StringIO):
    def isatty(self):
        return True


class VpnDeAntes(unittest.TestCase):
    """Un servidor con la VPN del instalador de antes: `mi-iphone` por IKEv2 (su conexión, escrita por el script), el
    `hh-iphone-poc` escrito a mano, y `iphone-viejo` por WireGuard, con su .conf aún en el servidor."""

    def setUp(self):
        self.carpeta = tempfile.mkdtemp(prefix="hh-disp-vpn-")
        self.addCleanup(shutil.rmtree, self.carpeta)
        c = self.c = lambda ruta: os.path.join(self.carpeta, ruta)  # noqa: E731
        os.makedirs(c("registro"))
        os.makedirs(c("conf.d"))
        m = self.m = cargar()
        m.DIR = c("wireguard")
        os.makedirs(m.DIR)
        m.DIR_HH = c("registro")
        m.REGISTRO = c("registro/dispositivos.json")
        m.DIR_SWANCTL = c("conf.d")
        m.CLAVE_SERVIDOR = c("wireguard/servidor.key")
        m.WG_CONF = c("wireguard/wg0.conf")
        with open(m.CLAVE_SERVIDOR, "w") as f:
            f.write("clave-privada-del-servidor-de-las-pruebas\n")
        self.ikev2 = {"nombre": "mi-iphone", "tipo": "ikev2", "ip": "10.77.1.3", "servidor": "203.0.113.7",
                      "conexion": "hh-mi-iphone", "alta": "2026-09-24T00:00:00+00:00"}
        self.wg = {"nombre": "iphone-viejo", "ip": "10.77.0.2", "clavePublica": CLAVE_WG,
                   "alta": "2026-09-18T10:00:00+00:00", "origen": "servidor"}
        m.guardar_registro({"dispositivos": [self.ikev2, self.wg]})
        with open(m.ruta_swanctl("mi-iphone"), "w") as f:
            f.write(m.CABECERA_SWANCTL + "connections {\n    hh-mi-iphone {\n        version = 2\n    }\n}\n"
                    "secrets {\n    ike-hehermes-mi-iphone {\n        id = mi-iphone\n        secret = \"%s\"\n"
                    "    }\n}\n" % PSK)
        with open(c("conf.d/hehermes-poc.conf"), "w") as f:
            f.write(POC)
        with open(m.ruta_conf("iphone-viejo"), "w") as f:
            f.write("[Interface]\nPrivateKey = de-las-pruebas\n")
        self.ordenes = []
        self.sas = {"hh-mi-iphone": "ESTABLISHED", "hh-iphone-poc": "ESTABLISHED"}
        mock.patch.object(m, "correr", self.correr).start()
        # Sin wg0 levantada: `aplicar` no llama a `wg syncconf`.
        mock.patch.object(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "")).start()
        mock.patch.object(m.shutil, "which", lambda nombre: "/usr/sbin/" + nombre).start()
        mock.patch.object(m.os, "geteuid", lambda: 0).start()
        mock.patch.object(m, "ruta_pasarela_ini", lambda: c("no-hay-pasarela.ini")).start()
        mock.patch.dict(os.environ, {"SUDO_USER": "daniel"}).start()
        self.addCleanup(mock.patch.stopall)

    def correr(self, *args, entrada=None):
        self.ordenes.append(list(args))
        if args[:2] == ("swanctl", "--list-sas"):
            return subprocess.CompletedProcess(args, 0, "".join("%s: #1, %s, IKEv2\n" % s for s in self.sas.items()), "")
        if args[:3] == ("swanctl", "--terminate", "--ike"):
            if self.sas.pop(args[3], None) is None:
                return subprocess.CompletedProcess(args, 1, "", "no matching SAs to terminate found")
        return subprocess.CompletedProcess(args, 0, "", "")

    def orden(self, nombre, *args):
        salida, errores = Terminal(), io.StringIO()
        with contextlib.redirect_stdout(salida), contextlib.redirect_stderr(errores):
            try:
                self.m.COMANDOS[nombre](list(args))
                codigo = 0
            except SystemExit as salir:
                codigo = salir.code
        return codigo, salida.getvalue() + errores.getvalue()

    def registro(self):
        with open(self.m.REGISTRO) as f:
            return {d["nombre"]: d for d in json.load(f)["dispositivos"]}

    def sin_nada_nuevo(self):
        self.assertEqual(sorted(os.listdir(self.c("conf.d"))), ["hehermes-mi-iphone.conf", "hehermes-poc.conf"])
        self.assertEqual(sorted(self.registro()), ["iphone-viejo", "mi-iphone"])
        self.assertFalse([o for o in self.ordenes if o[:2] == ["swanctl", "--load-all"]])

    # Las bajas, como siempre

    def test_la_baja_de_un_alta_ikev2_quita_su_conexion_recarga_y_corta_la_sesion(self):
        codigo, texto = self.orden("baja", "mi-iphone")
        self.assertEqual(codigo, 0, texto)
        self.assertFalse(os.path.exists(self.m.ruta_swanctl("mi-iphone")))
        carga = self.ordenes.index(["swanctl", "--load-all", "--noprompt"])
        corte = self.ordenes.index(["swanctl", "--terminate", "--ike", "hh-mi-iphone", "--force"])
        self.assertLess(carga, corte, "primero se descarga, luego se corta: si no, podría volver a entrar")
        self.assertNotIn("hh-mi-iphone", self.sas)
        self.assertTrue(self.registro()["mi-iphone"]["baja"])
        self.assertIn("Ya no puede conectarse", texto)
        self.assertNotIn(PSK, texto)

    def test_la_baja_con_ikev2_explicito_tambien(self):
        codigo, texto = self.orden("baja", "mi-iphone", "--ikev2")
        self.assertEqual(codigo, 0, texto)
        self.assertFalse(os.path.exists(self.m.ruta_swanctl("mi-iphone")))

    def test_la_baja_no_toca_hh_iphone_poc(self):
        with open(self.c("conf.d/hehermes-poc.conf"), "rb") as f:
            antes = f.read()
        self.orden("baja", "mi-iphone")
        with open(self.c("conf.d/hehermes-poc.conf"), "rb") as f:
            self.assertEqual(f.read(), antes)
        self.assertEqual(self.sas, {"hh-iphone-poc": "ESTABLISHED"}, "su sesión sigue arriba")
        self.assertFalse([o for o in self.ordenes if "hh-iphone-poc" in o])

    def test_la_baja_de_un_wireguard_regenera_wg0_sin_el(self):
        codigo, texto = self.orden("baja", "iphone-viejo")
        self.assertEqual(codigo, 0, texto)
        with open(self.m.WG_CONF) as f:
            self.assertNotIn(CLAVE_WG, f.read())
        self.assertFalse(os.path.exists(self.m.ruta_conf("iphone-viejo")), "su clave privada, fuera del servidor")
        self.assertTrue(self.registro()["iphone-viejo"]["baja"])
        self.assertFalse([o for o in self.ordenes if o[:2] == ["swanctl", "--terminate"]])
        self.assertTrue(os.path.exists(self.m.ruta_swanctl("mi-iphone")), "la otra, sin tocar")

    def test_la_lista_ensena_las_viejas_con_su_tipo(self):
        codigo, texto = self.orden("lista")
        self.assertEqual(codigo, 0, texto)
        self.assertRegex(texto, r"mi-iphone\s+ikev2\s+10\.77\.1\.3 .*SA viva")
        self.assertRegex(texto, r"iphone-viejo\s+wireguard\s+10\.77\.0\.2 .*\(\.conf con clave privada aún en el VPS\)")
        self.assertNotIn(PSK, texto)

    def test_limpiar_borra_el_conf_de_un_wireguard(self):
        codigo, texto = self.orden("limpiar", "iphone-viejo")
        self.assertEqual(codigo, 0, texto)
        self.assertFalse(os.path.exists(self.m.ruta_conf("iphone-viejo")))

    # Nada nuevo

    def test_un_alta_ikev2_ya_no(self):
        for argumentos in (("otro", "--ikev2"), ("otro", "--ikev2", "--servidor", "203.0.113.7")):
            with self.subTest(argumentos=argumentos):
                codigo, texto = self.orden("alta", *argumentos)
                self.assertEqual(codigo, 1)
                self.assertIn("--ikev2 ya no existe", texto)
                self.assertIn("la app solo usa la conexión directa", texto)
        self.sin_nada_nuevo()

    def test_un_alta_de_wireguard_ya_no(self):
        for argumentos in (("otro", "--pubkey", CLAVE_WG), ("otro", "--servidor", "203.0.113.7")):
            with self.subTest(argumentos=argumentos):
                codigo, texto = self.orden("alta", *argumentos)
                self.assertEqual(codigo, 1)
                self.assertIn("WireGuard ya no da altas nuevas", texto)
        self.assertFalse(os.path.exists(self.m.WG_CONF))
        self.sin_nada_nuevo()

    def test_un_alta_a_secas_sin_pasarela_no_va_a_la_vpn(self):
        """Antes, con servidor.ini, `alta <nombre>` era de la VPN. Ahora es siempre de la pasarela."""
        ini = self.c("servidor.ini")
        with open(ini, "w") as f:
            f.write("[servidor]\ndireccion = 203.0.113.7\n")
        self.m.SERVIDOR_INI = ini
        codigo, texto = self.orden("alta", "otro")
        self.assertEqual(codigo, 1)
        self.assertIn("la pasarela TLS no está instalada", texto)
        self.sin_nada_nuevo()

    def test_rotar_una_de_la_vpn_ya_no(self):
        for argumentos in (("mi-iphone",), ("mi-iphone", "--ikev2"), ("iphone-viejo",)):
            with self.subTest(argumentos=argumentos):
                codigo, texto = self.orden("rotar", *argumentos)
                self.assertEqual(codigo, 1)
                self.assertIn("ya no da altas nuevas ni cambia claves", texto)
        with open(self.m.ruta_swanctl("mi-iphone")) as f:
            self.assertIn(PSK, f.read(), "la misma PSK")
        self.sin_nada_nuevo()

    def test_el_qr_de_una_de_la_vpn_ya_no(self):
        codigo, texto = self.orden("qr", "mi-iphone")
        self.assertEqual(codigo, 1)
        self.assertIn("es de la VPN de antes (ikev2)", texto)
        self.assertNotIn(PSK, texto)
        self.assertFalse([o for o in self.ordenes if o[:1] == ["qrencode"]])

    def test_iniciar_ya_no_existe(self):
        self.assertNotIn("iniciar", self.m.COMANDOS)
        for que in ("alta_ikev2", "rotar_ikev2", "conf_swanctl", "nueva_psk", "texto_qr_ikev2", "cmd_iniciar"):
            self.assertFalse(hasattr(self.m, que), que)

    def test_esta_en_la_ayuda(self):
        ayuda = self.m.__doc__
        for linea in ("hehermes-dispositivo alta <nombre> [--tls]", "hehermes-dispositivo baja <nombre> [--tls|--ikev2]",
                      "hehermes-dispositivo rotar <nombre>", "hehermes-dispositivo lista"):
            self.assertIn(linea, ayuda)
        self.assertNotIn("--ikev2 [--servidor", ayuda)
        self.assertNotIn("iniciar", ayuda)


class SinCrearNadaDeLaVpn(unittest.TestCase):
    def test_como_root_no_crea_la_carpeta_del_registro(self):
        """Antes, como root y sin pasarela, `main` creaba /etc/wireguard/hehermes: era de la VPN."""
        m = cargar()
        with tempfile.TemporaryDirectory() as carpeta:
            m.DIR_HH = os.path.join(carpeta, "hehermes")
            m.REGISTRO = os.path.join(m.DIR_HH, "dispositivos.json")
            with mock.patch.object(m, "ruta_pasarela_ini", lambda: os.path.join(carpeta, "no.ini")), \
                    mock.patch.object(m, "aplicar_servidor_ini", lambda: None), \
                    mock.patch.object(m.sys, "argv", ["hehermes-dispositivo", "lista"]), \
                    mock.patch.object(m.os, "geteuid", lambda: 0), \
                    mock.patch.object(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1)), \
                    contextlib.redirect_stdout(io.StringIO()) as salida:
                m.main()
            self.assertFalse(os.path.exists(m.DIR_HH))
            self.assertIn("Sin dispositivos.", salida.getvalue())


if __name__ == "__main__":
    unittest.main()
