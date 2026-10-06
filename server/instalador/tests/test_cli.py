"""Las órdenes: `instalar [--plan]`, `comprobar`, `actualizar` y `desinstalar`, como las lanza una persona."""

import apoyo

import os
import shutil
import tempfile
import unittest
from unittest import mock

import servidor_falso as sf
import vpn_antigua
from hehermes_servidor import cli, plan, porchat
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import RUTA_MANIFIESTO, Manifiesto
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
        # Desde la 0.7.0, --avisos lleva un código de avisos: uno que no lo es para antes de nada.
        self.assertEqual(self.orden("instalar", "--avisos", "hehermes-avisos:1?h=x"), 2)


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
        apoyo.claves_de_marcador(self.sis, p.PREFIJO)
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

    def firmado_de_verdad(self, quien, claves):
        """Las dos claves del paquete instalado (`claves`: lo que va en clave-publica.pem y clave-rescate.pem), un
        paquete 9.0.0 firmado por `quien` y openssl comprobando de verdad (con `cryptography`)."""
        self.orden("instalar", "--si", terminal=False)
        for nombre, texto in zip(("clave-publica.pem", "clave-rescate.pem"), claves):
            self.sis.poner(p.PREFIJO + "/" + nombre, texto)
        paquete = self.empaquetar("9.0.0")
        if quien is not None:
            apoyo.firmar(quien, paquete)
        self.sis.responder["openssl"] = apoyo.openssl_que_verifica
        self.sis.responder["python3 -I"] = apoyo.bien("Todo al día: 0 cambios.\n")
        desde = len(self.sis.ordenes)
        codigo = self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig")
        return codigo, [o for o in self.sis.ordenes[desde:] if o[:2] == ["python3", "-I"]]

    def test_vale_la_principal_y_la_de_rescate(self):
        principal, publica_principal = apoyo.ed25519()
        rescate, publica_rescate = apoyo.ed25519()
        for quien in (principal, rescate):
            with self.subTest(principal=quien is principal):
                codigo, nueva = self.firmado_de_verdad(quien, (publica_principal, publica_rescate))
                self.assertEqual(codigo, 0, self.salida)
                self.assertEqual(len(nueva), 1)

    def test_una_clave_que_no_es_ninguna_de_las_dos_no_vale(self):
        _, publica_principal = apoyo.ed25519()
        _, publica_rescate = apoyo.ed25519()
        otra, _ = apoyo.ed25519()
        codigo, nueva = self.firmado_de_verdad(otra, (publica_principal, publica_rescate))
        self.assertEqual(codigo, 1)
        self.assertIn("la firma de", self.salida)
        self.assertEqual(nueva, [], "ni desempaqueta ni lanza nada")

    def test_con_la_principal_de_marcador_vale_la_de_rescate_y_no_otra(self):
        rescate, publica_rescate = apoyo.ed25519()
        otra, _ = apoyo.ed25519()
        marcador = (apoyo.RAIZ / "clave-publica.pem").read_bytes()
        if not marcador.startswith(b"# PENDIENTE-DE-DANIEL"):
            marcador = b"# PENDIENTE-DE-DANIEL\n"
        codigo, nueva = self.firmado_de_verdad(rescate, (marcador, publica_rescate))
        self.assertEqual((codigo, len(nueva)), (0, 1), self.salida)
        codigo, nueva = self.firmado_de_verdad(otra, (marcador, publica_rescate))
        self.assertEqual((codigo, nueva), (1, []))

    def test_con_las_dos_de_marcador_se_niega_sin_mirar_la_firma(self):
        principal, _ = apoyo.ed25519()
        codigo, nueva = self.firmado_de_verdad(principal, (b"# PENDIENTE-DE-DANIEL\n", b"# PENDIENTE-DE-DANIEL\n"))
        self.assertEqual((codigo, nueva), (1, []))
        self.assertIn("PENDIENTE-DE-DANIEL", self.salida)
        self.assertFalse([o for o in self.sis.ordenes if o[:1] == ["openssl"] and "-verify" in o])

    def test_la_version_nueva_puede_tomar_el_cerrojo(self):
        """`instalar --si` de la versión nueva toma el cerrojo de siempre (`/run/hehermes-servidor.lock`): si
        `actualizar` lo tuviera mientras, se pararía en «ya hay otro hehermes-servidor en marcha» y no actualizaría
        nunca."""
        import fcntl
        self.orden("instalar", "--si", terminal=False)
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        self.sis.responder["openssl"] = apoyo.bien("Signature Verified Successfully\n")
        paquete = self.empaquetar("9.0.0")

        def instalar_de_la_nueva(args, entrada):
            ruta = self.sis.ruta(cli._cerrojo.RUTA)
            os.makedirs(os.path.dirname(ruta), exist_ok=True)
            with open(ruta, "w") as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return Resultado(1, "error: ya hay otro hehermes-servidor en marcha\n")
            return Resultado(0, "Todo al día: 0 cambios.\n")

        self.sis.responder["python3 -I"] = instalar_de_la_nueva
        self.assertEqual(self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig"), 0, self.salida)

    def test_actualizar_con_firma_mala_no_toca_nada(self):
        self.orden("instalar", "--si", terminal=False)
        apoyo.claves_de_marcador(self.sis, p.PREFIJO)
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", PUBLICA.read_bytes())
        self.sis.responder["openssl"] = apoyo.mal(salida="Signature Verification Failure\n")
        paquete = self.empaquetar("9.0.0")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig"), 1)
        self.assertIn("firma", self.salida)
        self.assertEqual([o[0] for o in self.sis.ordenes[desde:]], ["openssl"], "mala es mala: no se mira más")

    def sin_openssl(self, quien, con_cryptography=True):
        """Un servidor sin la orden openssl: un paquete 9.0.0 firmado por `quien`, y el venv del canje comprobando con
        el `cryptography` de verdad (el script de `firma`, con el Python de las pruebas), o sin él."""
        import subprocess
        import sys
        principal, publica = apoyo.ed25519()
        self.orden("instalar", "--si", terminal=False)
        self.sis.poner(p.PREFIJO + "/clave-publica.pem", publica)
        paquete = self.empaquetar("9.0.0")
        apoyo.firmar(principal if quien == "principal" else apoyo.ed25519()[0], paquete)
        self.sis.responder["openssl"] = apoyo.mal("no existe openssl", codigo=127)

        def comprobar(args, entrada):
            r = subprocess.run([sys.executable] + args, capture_output=True, text=True, check=False)
            return Resultado(r.returncode, r.stdout, r.stderr)

        self.falso.firma_con_cryptography = comprobar if con_cryptography else None
        self.sis.responder["python3 -I"] = apoyo.bien("Todo al día: 0 cambios.\n")
        desde = len(self.sis.ordenes)
        codigo = self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig")
        return codigo, [o for o in self.sis.ordenes[desde:] if o[:2] == ["python3", "-I"]]

    def test_sin_openssl_la_comprueba_con_cryptography(self):
        codigo, nueva = self.sin_openssl("principal")
        self.assertEqual((codigo, len(nueva)), (0, 1), self.salida)
        codigo, nueva = self.sin_openssl("otra")
        self.assertEqual((codigo, nueva), (1, []))
        self.assertIn("la firma de", self.salida)
        self.assertIn("no es buena", self.salida)

    def test_sin_openssl_ni_cryptography_lo_dice_y_no_instala(self):
        """No es que la firma sea mala: no hay con qué mirarla, y se dice qué falta."""
        codigo, nueva = self.sin_openssl("principal", con_cryptography=False)
        self.assertEqual((codigo, nueva), (1, []))
        self.assertIn("no puedo comprobar la firma", self.salida)
        self.assertIn("sudo apt install openssl", self.salida)
        self.assertNotIn("no es buena", self.salida)


class ComoSeInstalo(Base):
    """«Actualizar» (el de la app) lanza el `instalar --si` de la versión nueva a secas: lo que cambia el resultado y se
    dio al instalar (`--direccion`, `--hermes-home`, `--cortafuegos-a-mano`) va en el manifiesto y se vuelve a usar,
    salvo que se dé otra cosa. Sin eso, detrás de un NAT (AWS, Google Cloud, Oracle, Azure, uno en casa) se paraba
    siempre con `nat`."""

    NAT = "192.168.1.20"

    def opciones(self):
        return Manifiesto.leer(self.sis).datos.get("opciones")

    def direccion(self):
        return next(l.split("=", 1)[1].strip() for l in self.sis.leer_texto(PASARELA_INI).splitlines()
                    if l.startswith("direccion"))

    def actualizar_de_verdad(self):
        """`actualizar` con un paquete 9.0.0 firmado, y su `instalar --si` corriendo de verdad aquí mismo (con el código
        de este repositorio): lo que le llega es lo que lanza `actualizar`, ni una opción más."""
        self.sis.responder["openssl"] = apoyo.bien("Signature Verified Successfully\n")
        paquete = self.empaquetar("9.0.0")
        lanzadas = []

        def instalar_de_la_nueva(args, entrada):
            lanzadas.append(args[3:])
            texto = []
            codigo = cli.main(args[3:], "uso", ORIGEN, sis=self.sis, entrada=lambda _: "", salida=texto.append,
                              terminal=False, euid=0)
            lanzadas.append("\n".join(texto))
            return Resultado(codigo, "\n".join(texto))

        self.sis.responder["python3 -I"] = instalar_de_la_nueva
        codigo = self.orden("actualizar", "--paquete", paquete, "--firma", paquete + ".sig")
        return codigo, lanzadas

    def test_actualizar_detras_de_un_nat_vuelve_a_usar_la_direccion(self):
        self.falso.direccion_salida = self.NAT
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone", respuestas=["198.51.100.99", "s"]), 0,
                         self.salida)
        self.assertEqual(self.opciones(), {"direccion": "198.51.100.99"}, "la respuesta a la pregunta, apuntada")
        codigo, lanzadas = self.actualizar_de_verdad()
        self.assertEqual(codigo, 0, lanzadas)
        self.assertEqual(lanzadas[0], ["instalar", "--si"])
        self.assertNotIn("hehermes-error", lanzadas[1])
        self.assertNotIn("detrás de un NAT", lanzadas[1])
        self.assertIn("Sigo como me instalaste: --direccion 198.51.100.99", lanzadas[1])
        self.assertEqual(self.direccion(), "198.51.100.99")

    def test_sin_terminal_tambien_y_la_que_se_da_manda(self):
        self.falso.direccion_salida = self.NAT
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "198.51.100.99", terminal=False), 0, self.salida)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.direccion(), "198.51.100.99")
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 0, self.salida)
        self.assertEqual(self.direccion(), "203.0.113.50")
        self.assertNotIn("Sigo como me instalaste", self.salida, "con la dada, no se dice")
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.direccion(), "203.0.113.50", "y desde ahí, la nueva")

    def test_la_detectada_no_se_apunta(self):
        """Sin dársela, la dirección pública detectada no se fija: si el servidor cambia de IP, se vuelve a detectar."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIsNone(self.opciones())
        self.falso.direccion_salida = "203.0.113.50"
        self.falso.enlaces_ip["eth0"]["addr"] = ["203.0.113.50/24"]
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.direccion(), "203.0.113.50")

    def test_el_cortafuegos_a_mano_se_recuerda(self):
        self.falso.con_iptables("DROP", ["-j MI-CORTAFUEGOS"])
        self.assertEqual(self.orden("instalar", "--si", "--cortafuegos-a-mano", terminal=False), 0, self.salida)
        self.assertEqual(self.opciones(), {"cortafuegos_a_mano": True})
        codigo, lanzadas = self.actualizar_de_verdad()
        self.assertEqual(codigo, 0, lanzadas)
        self.assertIn("Sigo como me instalaste: --cortafuegos-a-mano", lanzadas[1])
        self.assertEqual(self.falso.iptables["reglas"], [["-j", "MI-CORTAFUEGOS"]], "sigue sin tocarlo")

    def test_con_varios_hermes_el_que_se_dijo(self):
        self.falso.con_hermes(usuario="segundo", como="proceso", puerto=9000)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 1)
        self.assertIn("varios Hermes", self.salida)
        self.assertEqual(self.orden("instalar", "--si", "--hermes-home", "/home/segundo/.hermes", terminal=False), 0,
                         self.salida)
        self.assertEqual(self.opciones(), {"hermes_home": "/home/segundo/.hermes"})
        codigo, lanzadas = self.actualizar_de_verdad()
        self.assertEqual(codigo, 0, lanzadas)
        self.assertIn("Sigo como me instalaste: --hermes-home /home/segundo/.hermes", lanzadas[1])
        self.assertIn("[hermes]\npuerto = 9000\n", self.sis.leer_texto(PASARELA_INI))

    def test_por_chat_con_varios_hermes_se_apunta_el_que_lo_lanzo(self):
        """Por chat no se dice cuál: es el que lanza el instalador. Lo que lanza `actualizar` no es ninguno."""
        self.falso.con_hermes(usuario="segundo", como="proceso", puerto=9000)
        self.sis.entorno = {"HERMES_HOME": "/home/segundo/.hermes"}
        llave = "A" * 43
        self.assertEqual(self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "iphone-1a2b", "--llave",
                                    llave, terminal=False), 0, self.salida)
        self.assertEqual(self.opciones(), {"hermes_home": "/home/segundo/.hermes"})
        self.sis.entorno = {}
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)

    def test_una_instalacion_de_antes_toma_la_direccion_de_su_pasarela(self):
        """La 0.11.0 no apuntaba nada: detrás de un NAT, la dirección del QR que dejó en pasarela.ini."""
        self.falso.direccion_salida = self.NAT
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "198.51.100.99", terminal=False), 0, self.salida)
        self.de_antes_de_recordar()
        codigo, lanzadas = self.actualizar_de_verdad()
        self.assertEqual(codigo, 0, lanzadas)
        self.assertIn("Sigo como estaba instalado: la dirección del QR que ya tiene (198.51.100.99)", lanzadas[1])
        self.assertEqual(self.opciones(), {"direccion": "198.51.100.99"}, "y ya se queda apuntada")

    def test_una_instalacion_de_antes_con_varios_hermes_sigue_con_el_suyo(self):
        self.falso.con_hermes(usuario="segundo", como="proceso", puerto=9000)
        self.assertEqual(self.orden("instalar", "--si", "--hermes-home", "/home/segundo/.hermes", terminal=False), 0,
                         self.salida)
        self.de_antes_de_recordar()
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn("el Hermes que ya tiene conectado (/home/segundo/.hermes)", self.salida)

    def de_antes_de_recordar(self):
        man = Manifiesto.leer(self.sis)
        for clave in ("opciones", "version"):
            man.datos.pop(clave, None)
        man.guardar(self.sis)


class LaVersion(Base):
    """La versión instalada va en el manifiesto: un instalador más viejo (una frase de antes del historial del chat, un
    comando viejo) no vuelve atrás sin avisar."""

    LLAVE = "A" * 43

    def mas_vieja(self, *argv, version="0.10.0", **extra):
        with mock.patch.object(plan, "VERSION", version):
            return self.orden(*argv, **extra)

    def test_se_apunta_al_instalar(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["version"], plan.VERSION)

    def test_uno_mas_viejo_se_para_sin_tocar_nada(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone", terminal=False), 0, self.salida)
        antes = self.sis.foto()
        self.assertEqual(self.mas_vieja("instalar", "--si", terminal=False), 1)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("Aquí ya está instalada la %s, más nueva que esta (0.10.0)" % plan.VERSION, self.salida)
        self.assertIn("sudo hehermes-servidor instalar", self.salida)
        self.assertIn("--volver-atras", self.salida)
        self.assertNotIn("hehermes-error", self.salida, "por SSH lo lee una persona")

    def test_por_chat_acaba_con_su_codigo(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        antes = self.sis.foto()
        self.assertEqual(self.mas_vieja("instalar", "--por-chat", "--activar-api", "--iphone", "iphone-1a2b",
                                        "--llave", self.LLAVE, terminal=False), 1)
        self.assertEqual(self.texto[-1].strip().splitlines()[-2:],
                         ["hehermes-detalle:instalada=%s esta=0.10.0" % plan.VERSION, "hehermes-error:version-antigua"])
        self.assertEqual(self.sis.foto(), antes)

    def test_es_lo_primero_que_se_dice(self):
        """Con otro bloqueo a la vez, el código es este: con el instalador de ahora, lo demás puede ser otra cosa."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.falso.direccion_salida = "192.168.1.20"
        self.assertEqual(self.mas_vieja("instalar", "--por-chat", "--activar-api", "--iphone", "iphone-1a2b",
                                        "--direccion", "x y", "--llave", self.LLAVE, terminal=False), 1)
        self.assertEqual(self.texto[-1].strip().splitlines()[-1], "hehermes-error:version-antigua")

    def test_con_volver_atras_si_y_lo_dice(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.mas_vieja("instalar", "--si", "--volver-atras", terminal=False), 0, self.salida)
        self.assertIn("Vuelvo de la %s a la 0.10.0" % plan.VERSION, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["version"], "0.10.0")

    def test_la_misma_o_una_mas_nueva_sigue(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.mas_vieja("instalar", "--si", version="99.0.0", terminal=False), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["version"], "99.0.0")
        self.assertEqual(self.mas_vieja("instalar", "--si", version="0.11.99", terminal=False), 1)
        self.assertIn("versión vieja", self.salida)

    def test_se_compara_por_numeros(self):
        """La 0.9.0 es más vieja que la 0.11.0, aunque como texto «0.9» vaya después de «0.11»."""
        self.assertEqual(self.mas_vieja("instalar", "--si", version="0.11.0", terminal=False), 0, self.salida)
        self.assertEqual(self.mas_vieja("instalar", "--si", version="0.9.0", terminal=False), 1)
        self.assertIn("Aquí ya está instalada la 0.11.0, más nueva que esta (0.9.0)", self.salida)
        self.assertEqual(self.mas_vieja("instalar", "--si", version="0.11.10", terminal=False), 0, self.salida)
        self.assertEqual(self.mas_vieja("instalar", "--si", version="0.11.9", terminal=False), 1)

    def test_una_instalacion_de_antes_la_saca_de_su_codigo(self):
        """La 0.11.0 no la apuntaba: la de su `hehermes_servidor/__init__.py`, en /opt/hehermes-servidor."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        man = Manifiesto.leer(self.sis)
        del man.datos["version"]
        man.guardar(self.sis)
        self.assertEqual(self.mas_vieja("instalar", "--plan", terminal=False), 1)
        self.assertIn("Aquí ya está instalada la %s" % plan.VERSION, self.salida)

    def test_sin_instalacion_no_hay_version_que_mirar(self):
        self.assertEqual(self.mas_vieja("instalar", "--si", terminal=False), 0, self.salida)


class UnCorteAMedias(Base):
    """Un corte a mitad de un paso (el SIGHUP del SSH, Ctrl-C, el plazo de Hermes) deja lo de ese paso escrito y sin
    apuntar: la vez siguiente, con el mismo comando o con otro (la versión nueva desde la app), no se para en
    `ficheros-ajenos` y acaba el trabajo."""

    def cortar_en(self, prefijo, unidad=p.UNIDAD_PASARELA):
        """La primera orden que empieza por `prefijo` para `unidad` no llega a ejecutarse: el proceso muere ahí (un
        KeyboardInterrupt, que nadie atrapa, como un kill)."""
        cortado = []

        def cortar(args, entrada):
            if not cortado and unidad in args:
                cortado.append(args)
                raise KeyboardInterrupt
            return self.falso(args, entrada)

        self.sis.responder[prefijo] = cortar
        return cortado

    def cortado(self, *argv):
        try:
            self.orden(*argv, terminal=False)
        except KeyboardInterrupt:
            pass

    def test_al_arrancar_la_pasarela_la_primera_vez(self):
        cortado = self.cortar_en("systemctl enable")
        self.cortado("instalar", "--si")
        self.assertTrue(cortado)
        man = Manifiesto.leer(self.sis)
        self.assertTrue(self.sis.existe(PASARELA_INI))
        self.assertNotIn(PASARELA_INI, man.ficheros, "escrito y sin apuntar")
        self.assertIn("a_medias", man.datos)
        # Con otro comando (otra dirección, como una versión nueva con otro pasarela.ini): no es ajeno, es suyo.
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 0,
                         self.salida)
        self.assertNotIn("ficheros-ajenos", self.salida)
        self.assertIn("es mío**", self.salida)
        man = Manifiesto.leer(self.sis)
        self.assertIn(PASARELA_INI, man.ficheros)
        self.assertNotIn("a_medias", man.datos, "acabada la pasada, ya no queda nada a medias")
        self.assertTrue(self.falso.pasarela_en_marcha())
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 0)
        self.assertIn("Todo al día: 0 cambios.", self.salida)

    def test_el_mismo_comando_acaba_el_trabajo(self):
        self.cortar_en("systemctl enable")
        self.cortado("instalar", "--si")
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        self.assertNotIn("ya está*", self.salida, "todo lo suyo, apuntado")

    def test_al_actualizar_lo_reescrito_no_cuenta_como_cambiado(self):
        """El corte al reiniciar la pasarela con su pasarela.ini nuevo: el manifiesto aún tiene el hash del de antes."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.cortar_en("systemctl restart")
        self.cortado("instalar", "--si", "--direccion", "203.0.113.50")
        self.assertIn("203.0.113.50", self.sis.leer_texto(PASARELA_INI))
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 0,
                         self.salida)
        self.assertNotIn("alguien lo ha cambiado", self.salida)
        self.assertIn("es mío**   /etc/hehermes-pasarela/pasarela.ini", self.salida)
        self.assertIn("==> hehermes-pasarela.service: reiniciar", self.salida, "y se reinicia con él, que no llegó")
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 0)
        self.assertIn("Todo al día: 0 cambios.", self.salida)

    def test_los_secretos_del_vigia_tambien(self):
        """Escritos y cortado antes de apuntarlos (al darles su dueño): se quedan los que había, apuntados."""
        secreto = "/etc/hehermes-avisos/vigia/secreto-tunel"
        cortado = self.cortar_en("chown", unidad=secreto)
        self.cortado("instalar", "--si")
        self.assertTrue(cortado)
        antes = self.sis.leer(secreto)
        self.assertNotIn(secreto, Manifiesto.leer(self.sis).ficheros)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertNotIn("ficheros-ajenos", self.salida)
        self.assertEqual(self.sis.leer(secreto), antes, "el mismo secreto: la pasarela y el vigía ya lo comparten")
        self.assertIn(secreto, Manifiesto.leer(self.sis).ficheros)

    def test_lo_que_alguien_cambia_despues_sigue_parando(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.cortar_en("systemctl restart")
        self.cortado("instalar", "--si", "--direccion", "203.0.113.50")
        self.sis.poner(PASARELA_INI, self.sis.leer_texto(PASARELA_INI) + "# de Daniel\n")
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 1)
        self.assertIn("alguien lo ha cambiado", self.salida)


class ElVenvTrasSubirElSistema(Base):
    """Tras subir de versión la distribución (Debian 12 → 13, Ubuntu 24.04 → 26.04), el Python del venv del canje y del
    vigía es otro y ya no encuentra lo suyo: `instalar` (y por él `actualizar`) lo rehace con `--clear`, y el vigía, que
    corre con él, vuelve a arrancar con el nuevo."""

    def roto(self):
        self.falso.venvs_listos.discard(sf.VENV_CANJE)
        self.falso.venvs_rotos.add(sf.VENV_CANJE)

    def test_se_rehace_y_el_vigia_vuelve_a_arrancar(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.roto()
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        ordenes = self.sis.ordenes[desde:]
        clear = ["python3", "-I", "-m", "venv", "--clear", sf.VENV_CANJE]
        self.assertIn(clear, ordenes)
        pip = [o for o in ordenes if o[1:5] == ["-I", "-m", "pip", "install"]]
        self.assertEqual(len(pip), 1)
        self.assertLess(ordenes.index(clear), ordenes.index(pip[0]))
        self.assertIn(["systemctl", "try-restart", p.UNIDAD_VIGIA], ordenes[ordenes.index(pip[0]):])
        self.assertIn("lo rehago", self.salida)
        self.assertTrue(porchat.venv_listo(self.sis))
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)

    def test_uno_al_que_solo_le_falta_cryptography_no_se_rehace(self):
        """Un pip que se cortó (sin red): el venv vale, y se sigue donde se quedó."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.falso.venvs_listos.discard(sf.VENV_CANJE)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertFalse([o for o in self.sis.ordenes[desde:] if o[:4] == ["python3", "-I", "-m", "venv"]])
        self.assertFalse([o for o in self.sis.ordenes[desde:] if o[1:2] == ["try-restart"]])


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
