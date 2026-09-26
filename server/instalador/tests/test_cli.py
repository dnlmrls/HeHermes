"""Las órdenes: `instalar [--plan]`, `comprobar`, `actualizar` y `desinstalar`, como las lanza una persona."""

import apoyo

import os
import shutil
import tempfile
import unittest
from unittest import mock

import servidor_falso as sf
import vpn_antigua
from hehermes_servidor import cli, porchat
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import RUTA_MANIFIESTO
from hehermes_servidor.sistema import Resultado

ORIGEN = str(apoyo.RAIZ)
PUBLICA = apoyo.DATOS / "clave-de-prueba-NO-ES-DE-DANIEL.pub.pem"
PASARELA_INI = "/etc/hehermes-pasarela/pasarela.ini"


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        azar.start()
        self.addCleanup(azar.stop)

    def orden(self, *argv, respuestas=(), terminal=True, euid=0, **extra):
        self.texto = []
        pendientes = list(respuestas)
        self.preguntas = []

        def entrada(pregunta):
            self.preguntas.append(pregunta)
            return pendientes.pop(0)

        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=entrada, salida=self.texto.append,
                          terminal=terminal, euid=euid, **extra)
        self.salida = "\n".join(self.texto)
        return codigo

    def empaquetar(self, version):
        import importlib.machinery
        import importlib.util
        cargador = importlib.machinery.SourceFileLoader("empaquetar_cli", str(apoyo.RAIZ / "empaquetar"))
        e = importlib.util.module_from_spec(importlib.util.spec_from_loader("empaquetar_cli", cargador))
        cargador.exec_module(e)
        carpeta = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, carpeta)
        paquete, _ = e.construir(version, carpeta)
        with open(paquete + ".sig", "wb") as f:
            f.write(b"firma")
        return paquete

    def actualizar_a_la_9(self):
        """Con la clave de prueba en lugar del marcador, un paquete 9.0.0 firmado y la versión nueva de mentira."""
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        paquete = self.empaquetar("9.0.0")
        vistas = []

        def openssl(args, entrada):
            vistas.append(args)
            ok = args[args.index("-inkey") + 1] == self.sis.ruta(p.PREFIJO + "/clave-publica.pem")
            return Resultado(0 if ok else 1, "Signature Verified Successfully\n" if ok else "")

        self.sis.responder["openssl"] = openssl
        self.sis.responder["python3 -I"] = apoyo.bien("Todo al día: 0 cambios.\n")
        codigo = self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig")
        return codigo, vistas, [o for o in self.sis.ordenes
                                if o[:2] == ["python3", "-I"] and "/hehermes-servidor-9.0.0/" in o[2]]


class Instalar(Base):
    def test_sin_root_ni_casa_que_sirva_se_niega(self):
        """Sin root se instala en la casa del usuario; si no se sabe cuál es, se para sin tocar nada."""
        self.assertEqual(self.orden("instalar", "--plan", euid=1000, usuario="hermes", cuenta=("hermes", "/", 1000)), 1)
        self.assertIn("la de «hermes» no sé usarla", self.salida)
        self.assertIn("me faltan permisos de administrador", self.salida)
        self.assertNotIn("hehermes-error", self.salida)
        self.assertEqual([o for o in self.sis.ordenes if o[:1] != ["sudo"]], [])

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
        self.assertIn("sudo hehermes-dispositivo rotar mi-iphone", self.salida)

    def test_sin_terminal_hace_falta_si(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", terminal=False), 1)
        self.assertIn("--si", self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0)
        self.assertTrue(self.sis.existe(RUTA_MANIFIESTO))

    def test_una_parada_lo_dice_y_sale_con_error(self):
        self.sis.responder["useradd"] = apoyo.mal("useradd: se ha roto")
        self.assertEqual(self.orden("instalar", "--si"), 1)
        self.assertIn("useradd: se ha roto", self.salida)
        self.assertIn("vuelve a lanzar", self.salida)

    def test_la_direccion_privada_se_pregunta_en_un_terminal(self):
        self.falso.direccion_salida = "192.168.1.20"
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone", respuestas=["198.51.100.99", "s"]), 0)
        self.assertIn("dirección pública", self.preguntas[0])
        self.assertIn("direccion = 198.51.100.99\n", self.sis.leer_texto(PASARELA_INI))

    def test_adoptar_todavia_no_existe(self):
        self.assertEqual(self.orden("instalar", "--adoptar"), 2)
        self.assertIn("todavía no existe", self.salida)

    def test_opciones_que_no_valen(self):
        self.assertEqual(self.orden("instalar", "--nada"), 2)
        self.assertEqual(self.orden("nada"), 2)
        self.assertEqual(self.orden("instalar", "--avisos"), 2, "solo iba con la VPN")


class LaVpnYaNoSeInstala(Base):
    def test_modo_vpn_se_para_antes_que_nada_y_dice_como_quitar_una_de_antes(self):
        antes = self.sis.foto()
        for argv in (("instalar", "--modo", "vpn"), ("instalar", "--plan", "--modo", "vpn", "--iphone", "mi-iphone"),
                     ("instalar", "--modo", "vpn", "--si")):
            with self.subTest(argv=argv):
                self.assertEqual(self.orden(*argv), 2)
                self.assertEqual(self.texto, [cli.SIN_VPN])
                self.assertIn("--modo vpn ya no existe", self.salida)
                self.assertIn("sudo hehermes-servidor desinstalar --modo vpn", self.salida)
        self.assertEqual(self.sis.ordenes, [], "ni detecta ni pregunta a sudo")
        self.assertEqual(self.sis.foto(), antes)

    def test_sin_root_tampoco_pregunta_a_sudo(self):
        self.assertEqual(self.orden("instalar", "--modo", "vpn", euid=1000), 2)
        self.assertEqual(self.sis.ordenes, [])

    def test_sin_modo_en_un_servidor_limpio_es_la_pasarela(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertTrue(self.sis.existe(PASARELA_INI))
        self.assertFalse(self.sis.existe(p.SERVIDOR_INI))
        self.assertFalse([o for o in self.sis.ordenes if o[:1] in (["swanctl"], ["nginx"])])


class LasDemas(Base):
    def test_comprobar(self):
        self.assertEqual(self.orden("comprobar"), 1, "sin instalar, no pasa")
        self.assertIn("MAL   pasarela: no está instalada", self.salida)
        self.orden("instalar", "--si", terminal=False)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("bien  pasarela: en marcha", self.salida)

    def test_desinstalar_pregunta_y_quita(self):
        self.orden("instalar", "--si", "--iphone", "mi-iphone")
        self.assertEqual(self.orden("desinstalar", respuestas=["n"]), 1)
        self.assertTrue(self.sis.existe(RUTA_MANIFIESTO))
        self.assertIn("Voy a quitar", self.salida)
        self.assertEqual(self.orden("desinstalar", respuestas=["s"]), 0)
        self.assertFalse(self.sis.existe(RUTA_MANIFIESTO))
        self.assertFalse(self.sis.existe(PASARELA_INI))

    def test_desinstalar_sin_nada_mio(self):
        self.assertEqual(self.orden("desinstalar", "--si"), 0)
        self.assertIn("no hay nada mío", self.salida)

    def test_actualizar_se_niega_con_la_clave_de_marcador(self):
        self.orden("instalar", "--si", terminal=False)
        self.assertEqual(self.orden("actualizar", "--paquete", "/tmp/x.tar.gz", "--firma", "/tmp/x.sig"), 1)
        self.assertIn("PENDIENTE-DE-DANIEL", self.salida)

    def test_una_version_mas_vieja_no_se_instala_aunque_este_firmada(self):
        self.orden("instalar", "--si", terminal=False)
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        self.sis.responder["openssl"] = apoyo.bien("Signature Verified Successfully\n")
        paquete = self.empaquetar("0.1.0")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig"), 1)
        self.assertIn("más vieja", self.salida)
        self.assertFalse([o for o in self.sis.ordenes[desde:] if o[:1] == ["python3"]])

    def test_se_comprueba_y_se_abre_una_copia_de_root_no_el_fichero_de_otro(self):
        """Entre la firma y el tar, quien pudiera escribir en la carpeta del paquete podría cambiarlo."""
        self.orden("instalar", "--si", terminal=False)
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        paquete = self.empaquetar("9.0.0")
        vistas = []

        def openssl(args, entrada):
            copia = args[args.index("-in") + 1]
            vistas.append((copia, oct(os.stat(os.path.dirname(copia)).st_mode & 0o777)))
            # Justo después de comprobarla, alguien cambia el original: no tiene que importar.
            with open(paquete, "wb") as f:
                f.write(b"otro paquete")
            return Resultado(0, "Signature Verified Successfully\n")

        self.sis.responder["openssl"] = openssl
        self.sis.responder["python3 -I"] = apoyo.bien("Todo al día: 0 cambios.\n")
        self.assertEqual(self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig"), 0, self.salida)
        self.assertNotEqual(vistas[0][0], paquete)
        self.assertEqual(vistas[0][1], "0o700")
        self.assertTrue([o for o in self.sis.ordenes if o[:2] == ["python3", "-I"] and "hehermes-servidor-9.0.0" in o[2]])

    def test_actualizar_con_firma_buena_instala_la_nueva(self):
        self.orden("instalar", "--si", terminal=False)
        codigo, vistas, nueva = self.actualizar_a_la_9()
        self.assertEqual(codigo, 0, self.salida)
        self.assertEqual(len(vistas), 1)
        self.assertEqual(len(nueva), 1)
        self.assertTrue(nueva[0][2].endswith("/hehermes-servidor-9.0.0/hehermes-servidor"))
        # La pasarela, sin --modo: el modo es el que diga la versión nueva.
        self.assertEqual(nueva[0][3:], ["instalar", "--si"])
        self.assertFalse(os.path.exists(os.path.dirname(os.path.dirname(nueva[0][2]))), "la carpeta temporal, fuera")
        self.assertNotIn("VPN", self.salida)

    def test_actualizar_con_firma_mala_no_toca_nada(self):
        self.orden("instalar", "--si", terminal=False)
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        self.sis.responder["openssl"] = apoyo.mal(salida="Signature Verification Failure\n")
        paquete = self.empaquetar("9.0.0")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig"), 1)
        self.assertIn("firma", self.salida)
        self.assertEqual([o[0] for o in self.sis.ordenes[desde:]], ["openssl"])


class ConLaVpnDeAntes(Base):
    """`actualizar`, `comprobar` y `desinstalar` en un servidor con la VPN que dejaba la 0.5.1."""

    def test_actualizar_sobre_la_vpn_sola_no_instala_nada(self):
        """La versión nueva pondría la pasarela, que abre un puerto a internet: eso no se hace por la puerta de atrás
        de una actualización. Se dice qué hay y qué hacer."""
        vpn_antigua.montar(self.sis, self.falso)
        antes = self.sis.foto()
        desde = len(self.sis.ordenes)
        codigo, vistas, nueva = self.actualizar_a_la_9()
        self.assertEqual(codigo, 1)
        self.assertIn("aquí no está la pasarela, así que no hay nada que actualizar: lo que hay es la VPN IKEv2 de una "
                      "versión anterior", self.salida)
        self.assertIn("sudo hehermes-servidor desinstalar --modo vpn", self.salida)
        self.assertIn("sudo hehermes-servidor instalar", self.salida)
        self.assertEqual((vistas, nueva), ([], []), "ni comprueba la firma ni lanza nada")
        self.assertEqual(self.sis.ordenes[desde:], [])
        self.assertEqual({r: v for r, v in self.sis.foto().items() if r != p.PREFIJO + "/clave-publica.pem"},
                         {r: v for r, v in antes.items() if r != p.PREFIJO + "/clave-publica.pem"})

    def test_actualizar_sin_nada_instalado_tampoco(self):
        codigo, vistas, nueva = self.actualizar_a_la_9()
        self.assertEqual(codigo, 1)
        self.assertIn("aquí no está la pasarela, así que no hay nada que actualizar. La conexión directa", self.salida)
        self.assertEqual(nueva, [])

    def test_actualizar_con_la_vpn_y_la_pasarela_solo_actualiza_la_pasarela(self):
        vpn_antigua.montar(self.sis, self.falso)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        codigo, _, nueva = self.actualizar_a_la_9()
        self.assertEqual(codigo, 0, self.salida)
        self.assertEqual([o[3:] for o in nueva], [["instalar", "--si"]], "una sola pasada, y sin --modo vpn")
        self.assertIn("Ojo: " + cli.VPN_DE_ANTES, self.salida)

    def test_comprobar_dice_que_la_vpn_ya_no_se_comprueba(self):
        vpn_antigua.montar(self.sis, self.falso)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   pasarela: no está instalada", self.salida)
        self.assertIn("aviso " + cli.VPN_DE_ANTES, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if o[:1] == ["swanctl"] or o[:2] == ["nginx", "-t"]])

    def test_desinstalar_modo_vpn_la_quita_toda(self):
        # Los paquetes, de antes: sin --quitar-paquetes se quedan, y lo que se compara es lo del instalador.
        for paquete in vpn_antigua.PAQUETES:
            self.falso.instalar_paquete(paquete)
        antes = self.sis.foto()
        vpn_antigua.montar(self.sis, self.falso, iphones=("mi-iphone", "otro"))
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", respuestas=["s"]), 0, self.salida)
        self.assertIn("La VPN IKEv2 es lo único que instalé aquí: lo quito todo.", self.salida)
        self.assertEqual(sorted(o[2] for o in self.sis.ordenes if o[:2] == [p.DISPOSITIVO, "baja"]),
                         ["mi-iphone", "otro"])
        self.assertIn("El servidor está como antes de instalar.", self.salida)
        self.assertEqual(self.sis.foto(), antes)


if __name__ == "__main__":
    unittest.main()
