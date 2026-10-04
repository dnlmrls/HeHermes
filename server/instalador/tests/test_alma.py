"""El `SOUL.md` de Hermes (`alma`, desde la 0.10.4): `instalar` le añade, una vez y con una copia antes, cómo mandar
ficheros al iPhone (déjalos en `<su casa>/exports` y márcalos con una línea `MEDIA:<ruta>`); desinstalar quita
exactamente eso. El que usa Hermes es el de su HERMES_HOME (con un perfil, el del perfil)."""

import apoyo

import json
import re
import unittest

import servidor_falso as sf
from hehermes_servidor import alma
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli
from hehermes_servidor import manifiesto as m
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
from hehermes_servidor.plan import Opciones, pintar

ORIGEN = str(apoyo.RAIZ)
SOUL = "/root/.hermes/SOUL.md"
COPIA = m.CARPETA_COPIAS + "/root%.hermes%SOUL.md"


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def montar(self, **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "s", salida=self.texto.append,
                          terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def plan(self):
        man = Manifiesto.leer(self.sis)
        det = detectar_tls(self.sis, man, amb.de_root())
        return calcular_plan_tls(self.sis, det, man, Opciones(), ORIGEN)

    def del_soul(self, plan):
        return [a for a in plan.acciones if a.tipo == "soul"]


class ElParrafo(Base):
    def test_el_plan_lo_dice_y_no_toca_nada(self):
        antes = self.sis.foto()
        (accion,) = self.del_soul(self.plan())
        self.assertEqual((accion.objeto, accion.estado), (SOUL, m.NUEVO))
        self.assertIn("añado a SOUL.md cómo mandar ficheros al iPhone", accion.detalle)
        self.assertEqual(self.orden("instalar", "--plan"), 0)
        self.assertRegex(self.salida, r"Hermes\n(  .*\n)*  nuevo      /root/\.hermes/SOUL\.md  añado a SOUL\.md cómo "
                                      r"mandar ficheros al iPhone")
        self.assertEqual(self.sis.foto(), antes)

    def test_instalar_lo_anade_al_final_con_una_copia_antes(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        texto = self.sis.leer_texto(SOUL)
        self.assertEqual(texto, sf.SOUL_DE_SERIE + "\n\n" + alma.parrafo("/root/.hermes/exports"))
        self.assertIn("MEDIA:/root/.hermes/exports/informe.pdf", texto)
        self.assertEqual(self.sis.modo(SOUL), 0o600, "el modo de antes")
        self.assertEqual(self.sis.leer_texto(COPIA), sf.SOUL_DE_SERIE)
        self.assertEqual(self.sis.modo(COPIA), 0o600)
        datos = Manifiesto.leer(self.sis).datos["soul"]
        self.assertEqual((datos["ruta"], datos["anadido"]), (SOUL, "\n\n" + alma.parrafo("/root/.hermes/exports")))
        self.assertIn("==> el SOUL.md de Hermes: le añado cómo mandarte ficheros al iPhone", self.salida)

    def test_una_vez_y_nunca_dos(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        antes = self.sis.leer(SOUL)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        self.assertIn("ya está    /root/.hermes/SOUL.md  ya le dice a Hermes cómo mandar ficheros", self.salida)
        self.assertEqual(self.sis.leer(SOUL), antes)
        self.assertEqual(self.sis.leer_texto(SOUL).count(alma.TITULO), 1)

    def test_si_alguien_lo_pone_entre_el_plan_y_aplicarlo_no_se_repite(self):
        (accion,) = self.del_soul(self.plan())
        ya = sf.SOUL_DE_SERIE + "\n\n" + alma.parrafo("/root/.hermes/exports")
        self.sis.poner(SOUL, ya, modo=0o600)
        man = Manifiesto.leer(self.sis)
        alma.anadir(self.sis, man, accion, lambda _: None, amb.de_root())
        self.assertEqual(self.sis.leer_texto(SOUL), ya)
        self.assertNotIn("soul", man.datos)
        self.assertFalse(self.sis.existe(COPIA))

    def test_el_que_ya_lo_dice_no_se_toca(self):
        """Como el de Daniel, puesto a mano: ya habla de MEDIA: y de exports."""
        self.sis.poner(SOUL, sf.SOUL_DE_DANIEL, modo=0o600)
        (accion,) = self.del_soul(self.plan())
        self.assertEqual(accion.estado, m.AJENO_IGUAL)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(SOUL), sf.SOUL_DE_DANIEL)
        self.assertNotIn("soul", Manifiesto.leer(self.sis).datos)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(SOUL), sf.SOUL_DE_DANIEL)

    def test_con_el_titulo_pero_sin_apuntar_no_es_mio(self):
        self.sis.poner(SOUL, sf.SOUL_DE_SERIE + "\n\n" + alma.parrafo("/root/.hermes/exports"), modo=0o600)
        (accion,) = self.del_soul(self.plan())
        self.assertEqual(accion.estado, m.AJENO_IGUAL)

    def test_lo_que_no_se_toca_se_avisa(self):
        casos = {"no está": lambda: self.sis.borrar(SOUL),
                 "vacío": lambda: self.sis.poner(SOUL, "\n  \n", modo=0o600),
                 "enlace": lambda: (self.sis.poner("/srv/alma.md", "Soy otro\n"), self.sis.borrar(SOUL),
                                    self.sis.enlazar(SOUL, "/srv/alma.md")),
                 "distribución": lambda: self.sis.poner("/root/.hermes/distribution.yaml", "name: otra\n")}
        avisos = {"no está": "No encuentro el SOUL.md de Hermes", "vacío": "está vacío", "enlace": "es un enlace",
                  "distribución": "es de una distribución de perfiles"}
        for caso, preparar in casos.items():
            with self.subTest(caso=caso):
                self.setUp()
                preparar()
                antes = {r: v for r, v in self.sis.foto().items() if r.startswith("/root/.hermes")}
                plan = self.plan()
                self.assertEqual(self.del_soul(plan), [])
                (aviso,) = [a for a in plan.avisos if "SOUL.md" in a]
                self.assertIn(avisos[caso], aviso)
                self.assertIn("dile que los deje en /root/.hermes/exports y que los mande con una línea MEDIA:<ruta>",
                              aviso)
                self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
                # Lo único nuevo, las carpetas que crea el instalador: exports/ y (desde la 0.10.6) entrada/.
                despues = {r: v for r, v in self.sis.foto().items()
                           if r.startswith("/root/.hermes") and not r.startswith(("/root/.hermes/exports",
                                                                                  "/root/.hermes/entrada"))}
                self.assertEqual(despues, antes, "su casa, como estaba")

    def test_con_un_perfil_es_el_de_su_perfil(self):
        self.montar(como="unidad-perfil", perfil="trabajo")
        self.sis.poner(SOUL, "El de la raíz\n", modo=0o600)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        perfil = "/root/.hermes/profiles/trabajo/SOUL.md"
        self.assertIn("en /root/.hermes/profiles/trabajo/exports y", self.sis.leer_texto(perfil))
        self.assertEqual(self.sis.leer_texto(SOUL), "El de la raíz\n")

    def test_en_un_contenedor_la_carpeta_como_la_ve_hermes(self):
        self.montar(como="docker")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        texto = self.sis.leer_texto(SOUL)
        self.assertIn("en /opt/data/exports y", texto)
        self.assertIn("MEDIA:/opt/data/exports/informe.pdf", texto)


class Desinstalar(Base):
    def test_lo_deja_byte_a_byte_y_sin_la_copia(self):
        antes = self.sis.leer(SOUL)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("lo que añadí a /root/.hermes/SOUL.md (cómo mandar ficheros al iPhone)", self.salida)
        self.assertEqual(self.sis.leer(SOUL), antes)
        self.assertEqual(self.sis.modo(SOUL), 0o600)
        self.assertFalse(self.sis.existe(m.CARPETA_COPIAS))

    def test_lo_que_se_escribio_despues_se_queda(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.sis.poner(SOUL, self.sis.leer_texto(SOUL) + "\nY sé breve.\n", modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(SOUL), sf.SOUL_DE_SERIE + "\nY sé breve.\n")

    def test_si_lo_han_cambiado_no_lo_quita(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        cambiado = self.sis.leer_texto(SOUL).replace("La app HeHermes", "Mi app")
        self.sis.poner(SOUL, cambiado, modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("/root/.hermes/SOUL.md: lo que le añadí para mandar ficheros al iPhone ha cambiado, así que no "
                      "lo quito", self.salida)
        self.assertEqual(self.sis.leer_texto(SOUL), cambiado)

    def test_sin_root_tambien(self):
        self.montar(usuario="hermes")
        self.sis.carpeta("/run/user/1000", 0o700)
        antes = {r: v for r, v in self.sis.foto().items() if r.startswith("/home/hermes")}

        def como_hermes(*argv):
            self.texto = []
            codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "s",
                              salida=self.texto.append, terminal=False, euid=1000, relanzar=lambda orden: 0,
                              usuario="hermes", cuenta=("hermes", "/home/hermes", 1000))
            self.assertEqual(codigo, 0, "\n".join(self.texto))

        como_hermes("instalar", "--si")
        self.assertIn(alma.TITULO, self.sis.leer_texto("/home/hermes/.hermes/SOUL.md"))
        self.assertEqual(self.sis.leer_texto("/home/hermes/.config/hehermes/copias/home%hermes%.hermes%SOUL.md"),
                         sf.SOUL_DE_SERIE)
        como_hermes("desinstalar", "--si")
        self.assertEqual({r: v for r, v in self.sis.foto().items() if r.startswith("/home/hermes")}, antes,
                         "su casa, como estaba: ni el párrafo, ni la copia, ni sus carpetas")


class ElEscanerDeHermes(unittest.TestCase):
    """Hermes pasa su SOUL.md por su escáner de inyecciones (`tools/threat_patterns.py`) y, en una versión anterior a
    la 0.21.4 o en un perfil de una distribución, bloquea el fichero entero si algo casa: el párrafo no puede casar con
    ninguno. Los patrones de ámbito «all» y «context» del `main` de Hermes del 2026-09-30, copiados tal cual."""

    RELLENO = r"(?:\w+\s+){0,8}"
    PATRONES = (
        r"ignore\s+%s(previous|all|above|prior)\s+%sinstructions" % (RELLENO, RELLENO),
        r"system\s+prompt\s+override",
        r"disregard\s+%s(your|all|any)\s+%s(instructions|rules|guidelines)" % (RELLENO, RELLENO),
        r"<!--[^>]{0,512}(?:ignore|override|system|secret|hidden)[^>]{0,512}-->",
        r"<\s*div\s+style\s*=\s*[\"'][^>]{0,2048}display\s*:\s*none",
        r"do\s+not\s+%stell\s+%sthe\s+user" % (RELLENO, RELLENO),
        r"you\s+are\s+%snow\s+(?:a|an|the)\s+" % RELLENO,
        r"pretend\s+%s(you\s+are|to\s+be)\s+" % RELLENO,
        r"output\s+%s(system|initial)\s+prompt" % RELLENO,
        r"\bname\s+yourself\s+\w+",
        r"register\s+(as\s+)?a?\s*node",
        r"(heartbeat|beacon|check[\s\-]?in)\s+(to|with)\s+",
        r"pull\s+(down\s+)?(?:new\s+)?task(?:ing|s)?\b",
        r"connect\s+to\s+the\s+network\b",
        r"you\s+must\s+(?:\w+\s+){0,3}(register|connect|report|beacon)\b",
        r"curl\s+[^\n]{0,2048}\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S?\b",
        r"cat\s+[^\n]{0,2048}(\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)",
        r"(send|post|upload|transmit)\s+[^\n]{0,2048}\s+(to|at)\s+https?://",
        r"\$HOME/\.hermes/\.env|\~/\.hermes/\.env",
    )
    INVISIBLES = "​‌‍⁠⁢⁣⁤﻿‪‫‬‭‮⁦⁧⁨⁩"

    def test_el_parrafo_no_casa_con_ninguno(self):
        import unicodedata
        for carpeta in ("/root/.hermes/exports", "/opt/data/exports", "/home/ana/.hermes/profiles/trabajo/exports"):
            texto = unicodedata.normalize("NFKC", "\n\n" + alma.parrafo(carpeta))
            for patron in self.PATRONES:
                with self.subTest(carpeta=carpeta, patron=patron):
                    self.assertIsNone(re.search(patron, texto, re.IGNORECASE))
            self.assertFalse(set(texto) & set(self.INVISIBLES))


if __name__ == "__main__":
    unittest.main()
