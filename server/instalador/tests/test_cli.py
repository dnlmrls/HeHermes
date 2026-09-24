"""Las órdenes: `instalar [--plan]`, `comprobar`, `actualizar` y `desinstalar`, como las lanza una persona."""

import apoyo

import os
import shutil
import tempfile
import unittest

import servidor_falso as sf
from hehermes_servidor import cli
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import RUTA_MANIFIESTO
from hehermes_servidor.sistema import Resultado

ORIGEN = str(apoyo.RAIZ)
PUBLICA = apoyo.DATOS / "clave-de-prueba-NO-ES-DE-DANIEL.pub.pem"


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv, respuestas=(), terminal=True, euid=0):
        self.texto = []
        pendientes = list(respuestas)
        self.preguntas = []

        def entrada(pregunta):
            self.preguntas.append(pregunta)
            return pendientes.pop(0)

        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=entrada, salida=self.texto.append,
                          terminal=terminal, euid=euid)
        self.salida = "\n".join(self.texto)
        return codigo


class Instalar(Base):
    def test_sin_root_se_niega(self):
        self.assertEqual(self.orden("instalar", "--plan", euid=1000), 1)
        self.assertIn("root", self.salida)
        self.assertEqual(self.sis.ordenes, [])

    def test_plan_ensena_y_no_cambia_nada(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--iphone", "mi-iphone"), 0)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("el plan (no he cambiado nada)", self.salida)
        self.assertIn("nuevo", self.salida)
        self.assertEqual(self.preguntas, [], "--plan no pregunta")
        self.assertFalse([o for o in self.sis.ordenes if o[:2] in (["systemctl", "enable"], ["systemctl", "reload"])
                          or "install" in o or o[:1] == ["ufw"] and o[1:2] == ["allow"]])
        self.assertNotIn(sf.CLAVE, self.salida)

    def test_plan_con_bloqueos_sale_con_error(self):
        self.falso.hermes.clear()
        self.assertEqual(self.orden("instalar", "--plan"), 1)
        self.assertIn("No puedo seguir", self.salida)

    def test_pregunta_y_con_un_no_no_cambia_nada(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone", respuestas=["n"]), 1)
        self.assertEqual(self.preguntas, ["¿Sigo? [s/N] "])
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("No he cambiado nada", self.salida)

    def test_con_un_si_instala_y_la_segunda_vez_no_hay_nada(self):
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone", respuestas=["s"]), 0)
        self.assertTrue(self.sis.existe(RUTA_MANIFIESTO))
        self.assertIn("Hecho", self.salida)
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        self.assertEqual(self.preguntas, [], "sin cambios no pregunta")
        self.assertIn("sudo hehermes-dispositivo qr mi-iphone", self.salida)

    def test_sin_terminal_hace_falta_si(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", terminal=False), 1)
        self.assertIn("--si", self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0)
        self.assertTrue(self.sis.existe(RUTA_MANIFIESTO))

    def test_una_parada_lo_dice_y_sale_con_error(self):
        self.falso.nginx_t = lambda: not self.sis.existe(p.SITIO)
        self.assertEqual(self.orden("instalar", "--si"), 1)
        self.assertIn("nginx -t", self.salida)
        self.assertIn("vuelve a lanzar", self.salida)

    def test_la_direccion_privada_se_pregunta_en_un_terminal(self):
        self.falso.direccion_salida = "192.168.1.20"
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone", respuestas=["198.51.100.99", "s"]), 0)
        self.assertIn("dirección pública", self.preguntas[0])
        self.assertIn([p.DISPOSITIVO, "alta", "mi-iphone", "--ikev2", "--servidor", "198.51.100.99"], self.sis.ordenes)

    def test_adoptar_todavia_no_existe(self):
        self.assertEqual(self.orden("instalar", "--adoptar"), 2)
        self.assertIn("todavía no existe", self.salida)

    def test_opciones_que_no_valen(self):
        self.assertEqual(self.orden("instalar", "--nada"), 2)
        self.assertEqual(self.orden("nada"), 2)


class LasDemas(Base):
    def test_comprobar(self):
        self.assertEqual(self.orden("comprobar"), 1, "sin instalar, no pasa")
        self.orden("instalar", "--si")
        self.assertEqual(self.orden("comprobar"), 0)
        self.assertIn("403", self.salida)

    def test_desinstalar_pregunta_y_quita(self):
        self.orden("instalar", "--si", "--iphone", "mi-iphone")
        self.assertEqual(self.orden("desinstalar", respuestas=["n"]), 1)
        self.assertTrue(self.sis.existe(RUTA_MANIFIESTO))
        self.assertIn("Voy a quitar", self.salida)
        self.assertEqual(self.orden("desinstalar", respuestas=["s"]), 0)
        self.assertFalse(self.sis.existe(RUTA_MANIFIESTO))
        self.assertFalse(self.sis.existe(p.SITIO))

    def test_desinstalar_sin_nada_mio(self):
        self.assertEqual(self.orden("desinstalar", "--si"), 0)
        self.assertIn("no hay nada mío", self.salida)

    def test_actualizar_se_niega_con_la_clave_de_marcador(self):
        self.orden("instalar", "--si")
        self.assertEqual(self.orden("actualizar", "--paquete", "/tmp/x.tar.gz", "--firma", "/tmp/x.sig"), 1)
        self.assertIn("PENDIENTE-DE-DANIEL", self.salida)

    def test_actualizar_con_firma_buena_instala_la_nueva(self):
        self.orden("instalar", "--si")
        # Como si el paquete trajera ya la clave de Daniel (aquí, la de prueba).
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        import importlib.machinery
        import importlib.util
        cargador = importlib.machinery.SourceFileLoader("empaquetar_cli", str(apoyo.RAIZ / "empaquetar"))
        e = importlib.util.module_from_spec(importlib.util.spec_from_loader("empaquetar_cli", cargador))
        cargador.exec_module(e)
        carpeta = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, carpeta)
        paquete, _ = e.construir("0.1.0", carpeta)
        vistas = []

        def openssl(args, entrada):
            vistas.append(args)
            ok = args[args.index("-inkey") + 1] == self.sis.ruta(p.PREFIJO + "/clave-publica.pem")
            return Resultado(0 if ok else 1, "Signature Verified Successfully\n" if ok else "")

        self.sis.responder["openssl"] = openssl
        self.sis.responder["python3 -I"] = apoyo.bien("Todo al día: 0 cambios.\n")
        self.assertEqual(self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig"), 0, self.salida)
        self.assertEqual(len(vistas), 1)
        nueva = [o for o in self.sis.ordenes if o[:2] == ["python3", "-I"]]
        self.assertEqual(len(nueva), 1)
        self.assertTrue(nueva[0][2].endswith("/hehermes-servidor-0.1.0/hehermes-servidor"))
        self.assertEqual(nueva[0][3:], ["instalar", "--si"])
        self.assertFalse(os.path.exists(os.path.dirname(os.path.dirname(nueva[0][2]))), "la carpeta temporal, fuera")

    def test_actualizar_con_firma_mala_no_toca_nada(self):
        self.orden("instalar", "--si")
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        self.sis.responder["openssl"] = apoyo.mal(salida="Signature Verification Failure\n")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("actualizar", "--paquete", "/tmp/x.tar.gz", "--firma", "/tmp/x.sig"), 1)
        self.assertIn("firma", self.salida)
        self.assertEqual([o[0] for o in self.sis.ordenes[desde:]], ["openssl"])


if __name__ == "__main__":
    unittest.main()
