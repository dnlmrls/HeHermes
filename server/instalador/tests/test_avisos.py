"""Los avisos en el servidor de un probador (spec 2026-09-28): `instalar --avisos` y `avisos`, contra el servidor falso.

Desde la 0.8.0 («Avisos sin comandos»), `instalar` pone siempre el vigía y el lector de ficheros: sin código, el vigía
va sin credencial (cada aviso, con el permiso de su iPhone); con él, como en la 0.7.0.

El código de avisos lleva la credencial del vigía ante el relé de Daniel: se pide sin eco, no sale nunca por la salida,
no va al manifiesto y solo queda en su fichero 0600. El vigía de verdad (su `comprobar`, el HTTPS anclado) lo prueban
las pruebas de los avisos (`server/avisos/tests/test_rele_publico.py`).
"""

import apoyo

import base64
import json
import re
import sys
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import avisos, cli, porchat
from hehermes_servidor import piezas as p

ORIGEN = str(apoyo.RAIZ)
HUELLA = "huella-de-pruebas-del-rele-NO-ES-DE-VERDAD-"
CREDENCIAL = "hhr1.credencial-de-pruebas-NO-ES-DE-VERDAD------"
OTRA = "hhr1.otra-credencial-de-pruebas-NO-ES-DE-VERDAD-"
RELE = "198.51.100.7"
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()
LECTOR = apoyo.REPO / "server" / "avisos" / "despliegue" / "hehermes-leer-media"
RESPALDO = apoyo.REPO / "server" / "avisos" / "despliegue" / "hehermes-respaldo"
ENTRADA = apoyo.REPO / "server" / "avisos" / "despliegue" / "hehermes-entrada"
ACTUALIZAR = apoyo.REPO / "server" / "avisos" / "despliegue" / "hehermes-actualizar"
AGENTES = apoyo.REPO / "server" / "avisos" / "despliegue" / "hehermes-agentes"


def codigo(credencial=CREDENCIAL, direccion=RELE, puerto=61999, huella=HUELLA):
    return "hehermes-avisos:1?h=%s&p=%d&f=%s&c=%s" % (direccion, puerto, huella, credencial)


class ElCodigo(unittest.TestCase):
    def test_se_lee(self):
        self.assertEqual(avisos.leer_codigo(codigo()), {"direccion": RELE, "puerto": 61999, "huella": HUELLA,
                                                         "credencial": CREDENCIAL})
        self.assertEqual(avisos.leer_codigo("  " + codigo() + "\n")["puerto"], 61999, "pegado con espacios o un salto")

    def test_es_el_que_hace_el_rele(self):
        """El relé los hace (`hehermes_avisos.rele.publico.codigo`) y el instalador los lee: los mismos."""
        sys.path.insert(0, str(apoyo.REPO / "server" / "avisos"))
        self.addCleanup(sys.path.remove, str(apoyo.REPO / "server" / "avisos"))
        from hehermes_avisos.rele import credenciales, publico
        secreto = credenciales.nueva()
        for direccion in (RELE, "2001:db8::7", "rele.example.org"):
            with self.subTest(direccion=direccion):
                leido = avisos.leer_codigo(publico.codigo(direccion, 61999, HUELLA, secreto))
                self.assertEqual(leido, {"direccion": direccion, "puerto": 61999, "huella": HUELLA,
                                         "credencial": secreto})
        self.assertEqual(p.url_del_rele("2001:db8::7", 61999), "https://[2001:db8::7]:61999/v1/avisos")

    def test_lo_que_no_es_no_pasa_y_no_se_repite(self):
        for malo in ("", "hehermes-tls:1?h=x", codigo().replace("hhr1.", "hhr2."), codigo(huella="corta"),
                     codigo(direccion="a b"), codigo() + "&c=" + OTRA, codigo().replace("&p=61999", ""),
                     codigo(puerto=70000)):
            with self.subTest(malo=malo[:30]):
                with self.assertRaises(avisos.CodigoNoValido) as error:
                    avisos.leer_codigo(malo)
                self.assertNotIn(CREDENCIAL, str(error.exception))


class LaConfiguracionDelVigia(unittest.TestCase):
    def test_la_lee_el_vigia_de_verdad(self):
        """Lo que escribe el instalador lo entiende `ConfigVigia` (con sus reglas: https, con huella)."""
        import os
        import tempfile
        sys.path.insert(0, str(apoyo.REPO / "server" / "avisos"))
        self.addCleanup(sys.path.remove, str(apoyo.REPO / "server" / "avisos"))
        from hehermes_avisos.vigia.configuracion import ConfigVigia
        from hehermes_servidor import ambito
        for a in (ambito.de_root(), ambito.de_usuario("hermes", "/home/hermes", 1000)):
            with self.subTest(root=a.root), tempfile.TemporaryDirectory() as carpeta:
                ruta = os.path.join(carpeta, "vigia.ini")
                with open(ruta, "w") as f:
                    f.write(p.vigia_ini(a, 8642, "/home/hermes/.hermes/.env", "/home/hermes", "2001:db8::7", 61999,
                                        HUELLA))
                config = ConfigVigia.leer(ruta)
                self.assertEqual((config.rele_url, config.rele_huella, config.rele_credencial),
                                 ("https://[2001:db8::7]:61999/v1/avisos", HUELLA, a.credencial_rele))
                self.assertEqual((config.escucha, config.secreto_tunel, config.base_de_datos, config.ficheros_lector),
                                 (("127.0.0.1", 8790), a.secreto_vigia, a.base_vigia, ""))
                self.assertEqual(config.hermes_clave, a.clave_hermes_vigia if a.root else "/home/hermes/.hermes/.env")
                self.assertTrue(config.con_credencial)
                # Sin código (0.8.0): sin credencial, y con el lector.
                with open(ruta, "w") as f:
                    f.write(p.vigia_ini(a, 8642, "/home/hermes/.hermes/.env", "/home/hermes", lector=a.socket_lector))
                config = ConfigVigia.leer(ruta)
                self.assertFalse(config.con_credencial)
                self.assertEqual((config.rele_url, config.rele_huella, config.ficheros_lector),
                                 ("", None, "/run/hehermes-leer-media.sock" if a.root
                                  else "/run/user/1000/hehermes-leer-media.sock"))

    def test_la_entrada_la_lee_el_vigia_de_verdad(self):
        """El socket del ayudante de la entrada que escribe el instalador, y sin él, vacío (el vigía contesta 503)."""
        import os
        import tempfile
        sys.path.insert(0, str(apoyo.REPO / "server" / "avisos"))
        self.addCleanup(sys.path.remove, str(apoyo.REPO / "server" / "avisos"))
        from hehermes_avisos.vigia.configuracion import ConfigVigia
        from hehermes_servidor import ambito
        for a in (ambito.de_root(), ambito.de_usuario("hermes", "/home/hermes", 1000)):
            with self.subTest(root=a.root), tempfile.TemporaryDirectory() as carpeta:
                ruta = os.path.join(carpeta, "vigia.ini")
                for entrada, esperado in ((a.socket_entrada, a.socket_entrada), (None, "")):
                    with open(ruta, "w") as f:
                        f.write(p.vigia_ini(a, 8642, "/home/hermes/.hermes/.env", "/home/hermes", entrada=entrada))
                    config = ConfigVigia.leer(ruta)
                    self.assertEqual(config.entrada_ayudante, esperado)
                    self.assertEqual((config.entrada_tope, config.entrada_dias), (2 * 1024 ** 3, 30), "los de serie")

    def test_la_jaula_del_lector_es_la_del_vps_de_daniel(self):
        """La unidad del lector de root que escribe el instalador lleva la misma jaula que la de instalar.sh."""
        from hehermes_servidor import ambito

        def directivas(texto):
            return {l for l in texto.splitlines() if re.match(r"^[A-Z][A-Za-z]+=", l)
                    and not l.startswith(("ExecStart=", "InaccessiblePaths=", "Documentation="))}

        suya = (apoyo.REPO / "server" / "avisos" / "despliegue" / "hehermes-leer-media@.service").read_text()
        nuestra = p.unidad_lector(ambito.de_root(), "/root/.hermes")
        self.assertEqual(directivas(nuestra), directivas(suya))
        for tapada in re.findall(r"-/[^ \n]+", " ".join(l for l in suya.splitlines()
                                                        if l.startswith("InaccessiblePaths="))):
            self.assertIn(tapada, nuestra)
        self.assertIn("-/etc/hehermes-pasarela", nuestra, "y lo del instalador, también")


class Base(unittest.TestCase):
    euid = 0
    cuenta = None

    def setUp(self):
        self.sis, self.falso = self.servidor()
        self.addCleanup(self.sis.limpiar)
        for parche in (mock.patch.object(porchat, "_azar", lambda n: 3234),
                       mock.patch.object(avisos, "ESPERA_AL_COMPROBAR", 0)):
            parche.start()
            self.addCleanup(parche.stop)
        self.pedidos = []

    def servidor(self):
        return sf.servidor()

    def orden(self, *argv, terminal=True, pegado=None):
        self.texto = []

        def entrada(pregunta):
            self.pedidos.append(pregunta)
            return pegado if pegado is not None and "código" in pregunta.lower() else "s"

        codigo_ = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=entrada, salida=self.texto.append,
                           terminal=terminal, euid=self.euid, relanzar=lambda orden: 0, usuario="hermes",
                           cuenta=self.cuenta)
        self.salida = "\n".join(self.texto)
        self.assertNotIn(CREDENCIAL, self.salida, "la credencial no sale nunca")
        self.assertNotIn(OTRA, self.salida)
        return codigo_

    def manifiesto(self):
        return json.loads(self.sis.leer(self.ambito().manifiesto))

    def ambito(self):
        from hehermes_servidor import ambito
        return ambito.de_root() if self.euid == 0 else ambito.de_usuario(*self.cuenta)


class ConRoot(Base):
    def test_instalar_con_avisos_deja_el_vigia_hablando_con_el_rele(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        a = self.ambito()
        # Su código, junto al del instalador, y el venv (el del canje, con cryptography) lo encuentra por el .pth.
        self.assertTrue(self.sis.existe("/opt/hehermes-servidor/hehermes_avisos/vigia/__main__.py"))
        self.assertTrue(self.sis.existe("/opt/hehermes-servidor/hehermes_avisos/rele/publico.py"))
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("url = https://%s:61999/v1/avisos\nhuella = %s\n" % (RELE, HUELLA), ini)
        self.assertIn("clave = /etc/hehermes-avisos/vigia/clave-hermes\n", ini)
        self.assertIn("lector = /run/hehermes-leer-media.sock\n", ini)
        self.assertNotIn(CREDENCIAL, ini)
        self.assertEqual(self.sis.leer_texto(a.credencial_rele), CREDENCIAL + "\n")
        self.assertEqual(self.sis.leer_texto(a.clave_hermes_vigia), sf.CLAVE + "\n")
        for ruta in (a.credencial_rele, a.secreto_vigia, a.clave_hermes_vigia):
            self.assertEqual((self.sis.modo(ruta), self.falso.dueños.get(ruta)), (0o600, "hh-vigia:hh-vigia"), ruta)
        self.assertEqual((self.sis.modo(a.vigia_ini), self.falso.dueños.get(a.vigia_ini)), (0o640, "root:hh-vigia"))
        self.assertEqual(self.falso.dueños.get(a.carpeta_vigia), "root:hh-vigia")
        self.assertIn("hh-vigia", self.falso.usuarios_sistema)
        # Las unidades: el socket (el puerto es de systemd) y el vigía, que solo sale hacia esta máquina y el relé.
        unidad = self.sis.leer_texto(a.unidad_vigia)
        self.assertIn("User=hh-vigia\n", unidad)
        self.assertIn("ExecStart=/opt/hehermes-canje/venv/bin/python -I -B -m hehermes_avisos.vigia --config "
                      "/etc/hehermes-avisos/vigia.ini servir\n", unidad)
        self.assertIn("IPAddressDeny=any\nIPAddressAllow=localhost %s\n" % RELE, unidad)
        self.assertIn("ListenStream=127.0.0.1:8790", self.sis.leer_texto(a.socket_vigia))
        self.assertTrue({"hehermes-vigia", "hehermes-vigia.socket"} <= self.falso.activos)
        self.assertTrue({"hehermes-vigia", "hehermes-vigia.socket"} <= self.falso.habilitados)
        # La pasarela le pasa /avisos/, con el secreto por credencial de systemd.
        self.assertIn("[avisos]\nvigia = 127.0.0.1:8790\nsecreto = /etc/hehermes-avisos/vigia/secreto-tunel\n",
                      self.sis.leer_texto(a.pasarela_ini))
        self.assertIn("LoadCredential=vigia:/etc/hehermes-avisos/vigia/secreto-tunel\n",
                      self.sis.leer_texto(a.unidad))
        # El manifiesto: lo que no es secreto del código, y nada de la credencial.
        man = self.manifiesto()
        self.assertEqual(man["vigia"], {"direccion": RELE, "puerto": 61999, "huella": HUELLA})
        self.assertNotIn(CREDENCIAL, json.dumps(man))
        self.assertIn("hh-vigia", man["usuarios"])
        self.assertTrue({"hehermes-vigia.service", "hehermes-vigia.socket"} <= set(man["unidades"]))
        # Y se ha comprobado: el vigía, con su propio `comprobar`.
        self.assertTrue(self.falso.comprobaciones_del_vigia)
        self.assertIn("bien vigía: el relé acepta la credencial de este vigía («probador»)", self.salida)

    def test_repetirlo_no_cambia_nada_y_repara_sin_pedir_el_codigo(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        self.assertIn("el vigía, con el relé de %s:61999" % RELE, self.salida)
        self.assertEqual(self.orden("avisos", codigo(), "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        # Algo que falta se repone sin el código (la credencial sigue en su fichero).
        self.sis.borrar(self.ambito().unidad_vigia)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertTrue(self.sis.existe(self.ambito().unidad_vigia))
        self.assertEqual(self.pedidos.count("Código de avisos: "), 0)

    def test_avisos_en_una_pasarela_de_antes_y_con_el_codigo_pegado(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        secreto = self.sis.leer(self.ambito().secreto_vigia)
        self.assertEqual(self.orden("avisos", "--si", terminal=False, pegado=codigo()), 0, self.salida)
        self.assertIn("Código de avisos: ", self.pedidos)
        self.assertEqual(self.sis.leer_texto(self.ambito().credencial_rele), CREDENCIAL + "\n")
        self.assertIn("url = https://%s:61999/v1/avisos\n" % RELE, self.sis.leer_texto(self.ambito().vigia_ini))
        self.assertEqual(self.manifiesto()["vigia"], {"direccion": RELE, "puerto": 61999, "huella": HUELLA})
        # Desde la 0.8.0 el vigía ya estaba (sin credencial): la pasarela ya le pasaba /avisos/ y no se toca.
        self.assertEqual(self.sis.leer(self.ambito().secreto_vigia), secreto)
        self.assertNotIn("hehermes-pasarela", self.falso.reinicios)
        self.assertIn("hehermes-vigia", self.falso.reinicios)
        self.assertEqual([t["nombre"] for t in json.loads(self.sis.leer(self.ambito().tokens))["tokens"]],
                         ["mi-iphone"], "los iPhone, como estaban")

    def test_un_codigo_nuevo_cambia_la_credencial_y_reinicia_el_vigia(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        secreto = self.sis.leer(self.ambito().secreto_vigia)
        antes = len(self.falso.reinicios)
        self.assertEqual(self.orden("avisos", "--si", codigo(OTRA, puerto=62000)), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.ambito().credencial_rele), OTRA + "\n")
        self.assertIn("url = https://%s:62000/v1/avisos\n" % RELE, self.sis.leer_texto(self.ambito().vigia_ini))
        self.assertEqual(self.sis.leer(self.ambito().secreto_vigia), secreto, "el secreto con la pasarela no cambia")
        self.assertIn("hehermes-vigia", self.falso.reinicios[antes:])
        self.assertEqual(self.manifiesto()["vigia"]["puerto"], 62000)

    def test_sin_la_pasarela_no_hay_avisos(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("avisos", codigo()), 1)
        self.assertIn("Primero la conexión directa", self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_unos_avisos_a_mano_no_se_tocan(self):
        """Los del VPS de Daniel (instalar.sh): su vigía ya está, y habla con su relé en 127.0.0.1."""
        self.sis.carpeta("/opt/hehermes-avisos/src")
        self.assertEqual(self.orden("instalar", "--plan", "--avisos", codigo()), 1)
        self.assertIn("unos avisos puestos a mano", self.salida)

    def test_unos_avisos_a_mano_tampoco_sin_codigo(self):
        """Desde la 0.8.0 el vigía va siempre, pero no en un servidor con los suyos: ni su vigía, ni su lector (el de
        /usr/local/libexec y sus unidades), ni sus secretos. La pasarela, sí, y les pasa /avisos/."""
        self.sis.carpeta("/opt/hehermes-avisos/src")
        suyos = {"/usr/local/libexec/hehermes-leer-media": ("#!/usr/bin/python3 -IS\n# el de Daniel\n", 0o755),
                 "/etc/systemd/system/hehermes-leer-media.socket": ("[Socket]\n# el de Daniel\n", 0o644),
                 "/etc/hehermes-avisos/vigia.ini": ("[rele]\nurl = http://127.0.0.1:8791/v1/avisos\n", 0o640),
                 "/etc/hehermes-avisos/vigia/secreto-tunel": ("s" * 43 + "\n", 0o600)}
        for ruta, (texto, modo) in suyos.items():
            self.sis.poner(ruta, texto, modo=modo)
        antes = {r: v for r, v in self.sis.foto().items() if r.startswith(("/etc/hehermes-avisos", "/usr/local/libexec",
                                                                           "/etc/systemd/system/hehermes-leer"))}
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertIn("ni el vigía ni el lector de ficheros los pongo yo", self.salida)
        despues = {r: v for r, v in self.sis.foto().items() if r.startswith(("/etc/hehermes-avisos", "/usr/local/libexec",
                                                                             "/etc/systemd/system/hehermes-leer"))}
        self.assertEqual(despues, antes)
        man = self.manifiesto()
        self.assertNotIn("vigia", man)
        # (Lo único suyo con ese nombre es su propia copia, con el instalador en /opt/hehermes-servidor.)
        self.assertFalse([r for r in man["ficheros"] if ("avisos" in r or "leer-media" in r or "vigia" in r)
                          and not r.startswith("/opt/hehermes-servidor/")])
        self.assertNotIn("hh-vigia", self.falso.usuarios_sistema)
        self.assertIn("LoadCredential=vigia:/etc/hehermes-avisos/vigia/secreto-tunel\n",
                      self.sis.leer_texto(self.ambito().unidad))
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)

    def test_si_el_vigia_no_llega_al_rele_se_dice_pero_la_pasarela_queda(self):
        self.falso.vigia_comprueba = ["mal:  el relé no contesta a la credencial: timed out"]
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone", "--avisos", codigo()), 0, self.salida)
        self.assertIn("MAL  vigía: el relé no contesta a la credencial", self.salida)
        self.assertIn("El vigía no está bien del todo", self.salida)
        self.assertIn("Escanéalo desde la app", self.salida, "el QR sale igual")
        self.assertEqual(len(self.falso.comprobaciones_del_vigia), 3, "recién arrancado, se le da otra oportunidad")
        self.assertEqual(self.orden("comprobar"), 1, "y comprobar lo cuenta como fallo")

    def test_desinstalar_se_lo_lleva_todo(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        self.sis.carpeta("/var/lib/hehermes-vigia", 0o700)
        self.sis.poner("/var/lib/hehermes-vigia/vigia.db", b"claves de los iPhone", modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in ("/etc/hehermes-avisos", "/var/lib/hehermes-vigia", "/opt/hehermes-servidor/hehermes_avisos",
                     self.ambito().unidad_vigia, self.ambito().socket_vigia):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertNotIn("hh-vigia", self.falso.usuarios_sistema)
        self.assertFalse({"hehermes-vigia", "hehermes-vigia.socket"} & self.falso.activos)

    def test_desinstalar_la_pasarela_tambien_quita_el_vigia(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        self.assertEqual(self.orden("desinstalar", "--modo", "tls", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe("/etc/hehermes-avisos"))
        self.assertNotIn("hh-vigia", self.falso.usuarios_sistema)

    def test_la_clave_de_hermes_nueva_llega_tambien_al_vigia(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        env = "/root/.hermes/.env"
        self.sis.poner(env, self.sis.leer_texto(env).replace(sf.CLAVE, "clave-nueva-de-hermes"), modo=0o600)
        antes = len(self.falso.reinicios)
        self.assertEqual(self.orden("pasarela-clave"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.ambito().clave_hermes_vigia), "clave-nueva-de-hermes\n")
        self.assertEqual(self.falso.dueños.get(self.ambito().clave_hermes_vigia), "hh-vigia:hh-vigia")
        self.assertIn("hehermes-vigia", self.falso.reinicios[antes:])

    def test_seguridad_mira_sus_secretos(self):
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.sis.escribir(self.ambito().credencial_rele, (CREDENCIAL + "\n").encode(), modo=0o644)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("/etc/hehermes-avisos/vigia/credencial-rele (0644)", self.salida)


class SinCodigo(Base):
    """`instalar` a secas (lo de la frase del chat y el comando por SSH), con root: el vigía sin credencial y el
    lector, sin que el probador haga nada más."""

    def test_el_vigia_sin_credencial_y_el_lector(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        a = self.ambito()
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("[rele]\n", ini)
        self.assertRegex(ini, r"\nurl =\n")
        self.assertNotIn("huella =", ini)
        self.assertNotIn("credencial", ini.replace("Sin credencial", "").replace("la credencial.", ""))
        self.assertIn("lector = /run/hehermes-leer-media.sock\ncasa = /root\n", ini)
        self.assertFalse(self.sis.existe(a.credencial_rele), "sin código, ninguna credencial")
        self.assertEqual(self.manifiesto()["vigia"], {"modo": "permisos"})
        for ruta in (a.secreto_vigia, a.clave_hermes_vigia):
            self.assertEqual((self.sis.modo(ruta), self.falso.dueños.get(ruta)), (0o600, "hh-vigia:hh-vigia"), ruta)
        # La red del vigía: esta máquina e internet, no las redes de dentro (spec, «El instalador 0.8.0»).
        unidad = self.sis.leer_texto(a.unidad_vigia)
        self.assertIn("IPAddressAllow=localhost\nIPAddressDeny=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 "
                      "100.64.0.0/10 fc00::/7 fe80::/10\n", unidad)
        self.assertNotIn("IPAddressDeny=any", unidad)
        self.assertIn("Wants=network-online.target hehermes-leer-media.socket hehermes-respaldo.socket "
                      "hehermes-entrada.socket hehermes-actualizar.socket hehermes-agentes.socket\n", unidad)
        for linea in ("User=hh-vigia", "ProtectSystem=strict", "ProtectHome=yes", "NoNewPrivileges=yes",
                      "CapabilityBoundingSet=", "PrivateTmp=yes"):
            self.assertIn(linea + "\n", unidad, "la jaula de siempre")
        # El lector, como en el VPS de Daniel: el script de root, su socket root:hh-vigia 0660 y su plantilla.
        self.assertEqual(self.sis.leer(a.lector), LECTOR.read_bytes())
        self.assertEqual(self.sis.modo(a.lector), 0o755)
        socket_ = self.sis.leer_texto(a.unidad_lector_socket)
        for linea in ("ListenStream=/run/hehermes-leer-media.sock", "SocketUser=root", "SocketGroup=hh-vigia",
                      "SocketMode=0660", "Accept=yes"):
            self.assertIn(linea + "\n", socket_)
        servicio = self.sis.leer_texto(a.unidad_lector)
        self.assertIn("ExecStart=/usr/bin/python3 -I -S -B /usr/local/libexec/hehermes-leer-media "
                      "--hermes-home=/root/.hermes --conexion\n", servicio)
        self.assertNotIn("--usuario", servicio)
        # Y desde la 0.11.0 los perfiles de los agentes (contrato §18.9): dentro, el lector mira lo de cada uno.
        self.assertIn("BindReadOnlyPaths=-/root/.hermes/image_cache -/root/.hermes/audio_cache -/root/.hermes/exports "
                      "-/root/.hermes/profiles\n", servicio)
        self.assertIn("ProtectHome=tmpfs\n", servicio)
        self.assertIn("CapabilityBoundingSet=\n", servicio, "desde la 0.9.0, ninguna capacidad")
        self.assertNotIn("CAP_DAC_READ_SEARCH", servicio)
        self.assertNotIn("User=", servicio, "Hermes es root: el lector también, pero sin capacidades")
        # La carpeta de exportaciones, creada y apuntada (desinstalar la quita solo si está vacía).
        self.assertTrue(self.sis.es_carpeta("/root/.hermes/exports"))
        self.assertEqual(self.sis.modo("/root/.hermes/exports"), 0o700)
        self.assertEqual(self.manifiesto()["exportaciones"], "/root/.hermes/exports")
        self.assertTrue({"hehermes-leer-media.socket", "hehermes-vigia", "hehermes-vigia.socket"} <= self.falso.activos)
        self.assertTrue({"hehermes-leer-media.socket"} <= self.falso.habilitados)
        man = self.manifiesto()
        self.assertIn("hehermes-leer-media.socket", man["unidades"])
        self.assertIn(a.lector, man["ficheros"])
        # Y se comprueba: el vigía (sin credencial) y el lector.
        self.assertIn("bien vigía: sin credencial; los avisos van con el permiso que la app le da al darse de alta",
                      self.salida)
        self.assertIn("bien lector de ficheros: su socket está en marcha (/run/hehermes-leer-media.sock)", self.salida)
        self.assertIn("Escanéalo desde la app", self.salida)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("lector de ficheros: su socket está en marcha", self.salida)

    def test_repetirlo_no_cambia_nada(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        self.assertIn("el vigía, sin credencial", self.salida)
        # Lo que falta se repone, sin preguntar nada.
        self.sis.borrar(self.ambito().unidad_lector)
        self.falso.activos.discard("hehermes-leer-media.socket")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertTrue(self.sis.existe(self.ambito().unidad_lector))
        self.assertIn("hehermes-leer-media.socket", self.falso.activos)
        self.assertEqual(self.pedidos.count("Código de avisos: "), 0)

    def test_por_chat_tambien(self):
        """Lo que ejecuta Hermes con la frase de la app: el vigía y el lector, sin nada más."""
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE), 0,
                         self.salida)
        self.assertEqual(self.manifiesto()["vigia"], {"modo": "permisos"})
        self.assertTrue({"hehermes-leer-media.socket", "hehermes-vigia"} <= self.falso.activos)

    def test_una_instalacion_de_la_0_6_0_se_pone_al_dia_sin_perder_nada(self):
        """La 0.6.0 no ponía el vigía: otro `instalar` lo pone, y el lector, con los iPhone y el certificado de antes."""
        with mock.patch.object(avisos, "planear", lambda *argumentos, **opciones: None):
            self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        a = self.ambito()
        self.assertFalse(self.sis.existe(a.vigia_ini))
        certificado, tokens = self.sis.leer(a.cert), self.sis.leer(a.tokens)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual((self.sis.leer(a.cert), self.sis.leer(a.tokens)), (certificado, tokens))
        self.assertTrue(self.sis.existe(a.vigia_ini))
        self.assertIn("hehermes-pasarela", self.falso.reinicios, "la pasarela, ahora con el secreto del vigía")
        self.assertIn("LoadCredential=vigia:", self.sis.leer_texto(a.unidad))
        self.assertTrue({"hehermes-leer-media.socket", "hehermes-vigia"} <= self.falso.activos)

    def test_una_de_la_0_7_0_con_codigo_lo_conserva(self):
        """Una 0.7.0 con código de avisos: su vigía no tenía lector (`lector =`). Otro `instalar`, sin el código, le
        pone el lector y le deja su credencial y su relé."""
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        a = self.ambito()
        # Como lo dejaba la 0.7.0: sin lector, en el ini y en el disco.
        from hehermes_servidor.manifiesto import Manifiesto
        man = Manifiesto.leer(self.sis, a.manifiesto)
        de_antes = p.vigia_ini(a, 8642, "/root/.hermes/.env", "/root", RELE, 61999, HUELLA).encode()
        self.sis.escribir(a.vigia_ini, de_antes, modo=0o640)
        man.apuntar_fichero(a.vigia_ini, de_antes)
        for ruta in (a.lector, a.unidad_lector_socket, a.unidad_lector):
            self.sis.borrar(ruta)
            man.olvidar(ruta)
        man.unidades.remove("hehermes-leer-media.socket")
        man.guardar(self.sis)
        self.falso.activos.discard("hehermes-leer-media.socket")
        antes = len(self.falso.reinicios)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("url = https://%s:61999/v1/avisos\nhuella = %s\n" % (RELE, HUELLA), ini)
        self.assertIn("lector = /run/hehermes-leer-media.sock\n", ini)
        self.assertEqual(self.sis.leer_texto(a.credencial_rele), CREDENCIAL + "\n")
        self.assertEqual(self.manifiesto()["vigia"], {"direccion": RELE, "puerto": 61999, "huella": HUELLA})
        self.assertIn("hehermes-vigia", self.falso.reinicios[antes:])
        self.assertIn("hehermes-leer-media.socket", self.falso.activos)
        self.assertIn("IPAddressDeny=any\nIPAddressAllow=localhost %s\n" % RELE, self.sis.leer_texto(a.unidad_vigia))
        self.assertEqual(self.pedidos.count("Código de avisos: "), 0)

    def test_desinstalar_se_lleva_el_lector(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.lector, a.unidad_lector_socket, a.unidad_lector, a.vigia_ini, "/etc/hehermes-avisos",
                     "/var/lib/hehermes-vigia"):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertFalse({"hehermes-leer-media.socket", "hehermes-vigia"} & self.falso.activos)
        self.assertIn(["systemctl", "stop", "hehermes-leer-media@*.service"], self.sis.ordenes)
        self.assertNotIn("hh-vigia", self.falso.usuarios_sistema)

    def test_desinstalar_la_pasarela_se_lleva_el_lector(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual(self.orden("desinstalar", "--modo", "tls", "--si"), 0, self.salida)
        a = self.ambito()
        for ruta in (a.lector, a.unidad_lector_socket, a.unidad_lector):
            self.assertFalse(self.sis.existe(ruta), ruta)


class SinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)
    CASA = "/home/hermes"

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_en_su_casa_con_una_unidad_de_usuario(self):
        suyo = (self.CASA, "/run/user/1000/")
        antes_fuera = {r: v for r, v in self.sis.foto().items() if not r.startswith(suyo)}
        self.assertEqual(self.orden("instalar", "--si", "--avisos", codigo()), 0, self.salida)
        self.assertEqual({r: v for r, v in self.sis.foto().items() if not r.startswith(suyo)}, antes_fuera,
                         "sin root no se escribe nada fuera de su casa")
        a = self.ambito()
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("clave = /home/hermes/.hermes/.env\n", ini, "lee el .env de Hermes, como la pasarela")
        self.assertIn("base_de_datos = /home/hermes/.local/state/hehermes-vigia/vigia.db\n", ini)
        self.assertEqual(self.sis.modo(a.carpeta_estado_vigia), 0o700)
        for ruta in (a.vigia_ini, a.credencial_rele, a.secreto_vigia):
            self.assertEqual(self.sis.modo(ruta), 0o600, ruta)
        self.assertFalse(self.sis.existe(a.clave_hermes_vigia), "sin root, ninguna copia de la clave")
        self.assertFalse(self.sis.existe(a.socket_vigia), "sin root, el vigía abre su puerto")
        unidad = self.sis.leer_texto(a.unidad_vigia)
        self.assertIn("WantedBy=default.target", unidad)
        self.assertNotIn("User=", unidad)
        self.assertIn("hehermes-vigia", self.falso.activos_usuario)
        self.assertIn("secreto = /home/hermes/.config/hehermes-avisos/vigia/secreto-tunel\n",
                      self.sis.leer_texto(a.pasarela_ini))
        for prohibida in (["useradd"], ["chown"], ["ufw"]):
            self.assertFalse([o for o in self.sis.ordenes if o[:1] == prohibida], prohibida)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe(a.carpeta_avisos))
        self.assertFalse(self.sis.existe(a.carpeta_estado_vigia))

    def test_sin_codigo_el_vigia_y_el_lector_de_su_usuario(self):
        """Lo que hace la frase del chat en un servidor sin root: todo en su casa y en su /run/user, con unidades de
        usuario, y el lector como él mismo, que solo le atiende a él."""
        suyo = (self.CASA, "/run/user/1000/")
        antes_fuera = {r: v for r, v in self.sis.foto().items() if not r.startswith(suyo)}
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual({r: v for r, v in self.sis.foto().items() if not r.startswith(suyo)}, antes_fuera,
                         "sin root no se escribe nada fuera de su casa")
        a = self.ambito()
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertRegex(ini, r"\nurl =\n")
        self.assertIn("lector = /run/user/1000/hehermes-leer-media.sock\ncasa = /home/hermes\n", ini)
        self.assertFalse(self.sis.existe(a.credencial_rele))
        # El lector: la copia que va con el instalador en su casa, lanzada por una unidad de usuario.
        self.assertEqual(a.lector, "/home/hermes/.local/share/hehermes-servidor/hehermes-leer-media")
        self.assertEqual(self.sis.leer(a.lector), LECTOR.read_bytes())
        socket_ = self.sis.leer_texto(a.unidad_lector_socket)
        self.assertIn("ListenStream=%t/hehermes-leer-media.sock\nSocketMode=0600\n", socket_)
        self.assertNotIn("SocketGroup", socket_)
        servicio = self.sis.leer_texto(a.unidad_lector)
        self.assertIn("ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=/home/hermes/.hermes "
                      "--conexion\n" % a.lector, servicio)
        self.assertIn("NoNewPrivileges=yes\nRestrictAddressFamilies=AF_UNIX\n", servicio)
        self.assertIn("NO puede ponerse", servicio, "dice lo que una unidad de usuario no puede, no lo finge")
        self.assertNotIn("CapabilityBoundingSet=CAP", servicio)
        self.assertNotIn("InaccessiblePaths=", servicio)
        vigia = self.sis.leer_texto(a.unidad_vigia)
        self.assertIn("Wants=hehermes-leer-media.socket hehermes-respaldo.socket hehermes-entrada.socket "
                      "hehermes-agentes.socket\n", vigia)
        self.assertNotIn("IPAddress", vigia.replace("IPAddressDeny necesita", ""))
        self.assertTrue({"hehermes-leer-media.socket", "hehermes-vigia"} <= self.falso.activos_usuario)
        self.assertFalse({"hehermes-leer-media.socket", "hehermes-vigia"} & self.falso.activos)
        self.assertIn("bien lector de ficheros: su socket está en marcha (/run/user/1000/hehermes-leer-media.sock)",
                      self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.lector, a.unidad_lector_socket, a.unidad_lector, a.carpeta_avisos, a.carpeta_estado_vigia):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertFalse({"hehermes-leer-media.socket", "hehermes-vigia"} & self.falso.activos_usuario)
        self.assertIn(["systemctl", "--user", "stop", "hehermes-leer-media@*.service"], self.sis.ordenes)


def activas(texto: str) -> dict:
    salida = {}
    for linea in texto.splitlines():
        if linea and not linea.startswith(("#", "[")) and "=" in linea:
            clave, _, valor = linea.partition("=")
            salida.setdefault(clave, []).append(valor)
    return salida


class CopiaEnICloud(Base):
    """El ayudante de la copia en iCloud (desde la 0.10.0), con root: como en el VPS de Daniel."""

    def test_con_root_el_ayudante_su_socket_y_su_jaula(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(self.sis.leer(a.respaldo), RESPALDO.read_bytes())
        self.assertEqual(self.sis.modo(a.respaldo), 0o755)
        self.assertIn("\n[respaldo]\n", self.sis.leer_texto(a.vigia_ini))
        self.assertIn("ayudante = /run/hehermes-respaldo.sock\n", self.sis.leer_texto(a.vigia_ini))
        socket_ = self.sis.leer_texto(a.unidad_respaldo_socket)
        for linea in ("ListenStream=/run/hehermes-respaldo.sock", "SocketUser=root", "SocketGroup=hh-vigia",
                      "SocketMode=0660", "Accept=yes"):
            self.assertIn(linea + "\n", socket_)
        servicio = activas(self.sis.leer_texto(a.unidad_respaldo))
        self.assertEqual(servicio["ExecStart"], [
            "/usr/bin/python3 -I -S -B /usr/local/libexec/hehermes-respaldo --hermes-home=/root/.hermes "
            "--trabajo=/var/lib/hehermes-respaldo --unidad-hermes=hermes-gateway.service --usuario-hermes=root "
            "--conexion"])
        # La jaula es la de server/avisos/despliegue/hehermes-respaldo@.service, línea a línea (menos la orden, que
        # lleva las rutas de este servidor, y los comentarios).
        despliegue = activas((RESPALDO.parent / "hehermes-respaldo@.service").read_text())
        for clave in set(despliegue) | set(servicio):
            if clave not in ("ExecStart", "Documentation"):
                self.assertEqual(servicio.get(clave), despliegue.get(clave), clave)
        self.assertIn("hehermes-respaldo.socket", self.falso.activos)
        self.assertIn("bien copia en iCloud: el socket de su ayudante está en marcha (/run/hehermes-respaldo.sock)",
                      self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        # Desinstalar: fuera el ayudante y sus unidades; su carpeta de trabajo, si no guarda nada de antes, también.
        self.sis.carpeta(a.carpeta_respaldo + "/instantaneas/" + "a" * 32, 0o700)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.respaldo, a.unidad_respaldo_socket, a.unidad_respaldo, a.carpeta_respaldo):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertNotIn("hehermes-respaldo.socket", self.falso.activos)

    def test_desinstalar_no_borra_la_copia_de_antes_de_restaurar(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        self.sis.poner(a.carpeta_respaldo + "/antes/casa/config.yaml", "lo de antes\n", modo=0o600)
        self.sis.carpeta(a.carpeta_respaldo + "/instantaneas/" + "b" * 32, 0o700)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertTrue(self.sis.existe(a.carpeta_respaldo + "/antes/casa/config.yaml"))
        self.assertFalse(self.sis.existe(a.carpeta_respaldo + "/instantaneas"))
        self.assertIn("la copia de lo que había en Hermes antes de la última restauración", self.salida)

    def test_con_hermes_de_otro_usuario_se_lo_dice_al_ayudante(self):
        unidad = p.unidad_respaldo(self.ambito(), "/srv/hermes", "hermes")
        self.assertIn("--hermes-home=/srv/hermes ", unidad)
        self.assertIn("--usuario-hermes=hermes ", unidad)
        for malo in ("root;x", "Hermes", "a b"):
            with self.assertRaises(ValueError):
                p.unidad_respaldo(self.ambito(), "/srv/hermes", malo)


class CopiaEnICloudSinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_como_el_usuario_de_hermes_en_su_casa(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(a.respaldo, "/home/hermes/.local/share/hehermes-servidor/hehermes-respaldo")
        self.assertEqual(self.sis.leer(a.respaldo), RESPALDO.read_bytes())
        self.assertIn("ayudante = /run/user/1000/hehermes-respaldo.sock\n", self.sis.leer_texto(a.vigia_ini))
        self.assertIn("ListenStream=%t/hehermes-respaldo.sock\nSocketMode=0600\n",
                      self.sis.leer_texto(a.unidad_respaldo_socket))
        servicio = self.sis.leer_texto(a.unidad_respaldo)
        self.assertIn("ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=/home/hermes/.hermes "
                      "--trabajo=/home/hermes/.local/state/hehermes-respaldo --unidad-hermes=hermes-gateway.service "
                      "--conexion\n" % a.respaldo, servicio)
        self.assertNotIn("CapabilityBoundingSet=", servicio)
        self.assertNotIn("--usuario-hermes", servicio)
        self.assertIn("hehermes-respaldo.socket", self.falso.activos_usuario)
        self.assertNotIn("hehermes-respaldo.socket", self.falso.activos)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.respaldo, a.unidad_respaldo_socket, a.unidad_respaldo):
            self.assertFalse(self.sis.existe(ruta), ruta)


class EntradaDeFicheros(Base):
    """El ayudante de la entrada (desde la 0.10.6), con root: como en el VPS de Daniel."""

    CASA = "/root/.hermes"

    def test_con_root_el_ayudante_su_socket_su_jaula_y_su_carpeta(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(self.sis.leer(a.entrada), ENTRADA.read_bytes())
        self.assertEqual(self.sis.modo(a.entrada), 0o755)
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("\n[entrada]\n", ini)
        self.assertIn("ayudante = /run/hehermes-entrada.sock\n", ini)
        # El socket y la jaula son los de server/avisos/despliegue, línea a línea (menos los comentarios).
        for nuestra, suya in ((a.unidad_entrada_socket, "hehermes-entrada.socket"),
                              (a.unidad_entrada, "hehermes-entrada@.service")):
            unidad = activas(self.sis.leer_texto(nuestra))
            despliegue = activas((ENTRADA.parent / suya).read_text())
            for clave in set(despliegue) | set(unidad):
                if clave != "Documentation":
                    self.assertEqual(unidad.get(clave), despliegue.get(clave), (suya, clave))
        servicio = activas(self.sis.leer_texto(a.unidad_entrada))
        self.assertEqual(servicio["ExecStart"], ["/usr/bin/python3 -I -S -B /usr/local/libexec/hehermes-entrada "
                                                 "--hermes-home=/root/.hermes --conexion"])
        self.assertEqual((servicio["CapabilityBoundingSet"], servicio["BindPaths"], servicio["LimitFSIZE"]),
                         ([""], ["-/root/.hermes/entrada -/root/.hermes/profiles"], ["16G"]))
        self.assertNotIn("User", servicio)
        # La carpeta, creada y apuntada (desinstalar la quita solo si está vacía).
        self.assertTrue(self.sis.es_carpeta("/root/.hermes/entrada"))
        self.assertEqual(self.sis.modo("/root/.hermes/entrada"), 0o700)
        self.assertEqual(self.manifiesto()["entrada"], "/root/.hermes/entrada")
        self.assertIn("==> la carpeta de entrada de Hermes: /root/.hermes/entrada", self.salida)
        self.assertIn("hehermes-entrada.socket", self.falso.activos)
        self.assertIn("hehermes-entrada.socket", self.manifiesto()["unidades"])
        self.assertIn("bien entrada de ficheros: el socket de su ayudante está en marcha (/run/hehermes-entrada.sock)",
                      self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        # Desinstalar: fuera el ayudante, sus unidades y lo que quedó a medias; la carpeta, vacía, también.
        self.sis.poner("/root/.hermes/entrada/.subidas/%s/datos" % ("a" * 32), b"a medias", modo=0o600)
        self.sis.poner("/root/.hermes/entrada/.subidas/.cerrojo", b"", modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.entrada, a.unidad_entrada_socket, a.unidad_entrada, "/root/.hermes/entrada"):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertNotIn("hehermes-entrada.socket", self.falso.activos)

    def test_desinstalar_deja_lo_que_ya_es_de_hermes(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.sis.poner("/root/.hermes/entrada/2026-10-04/informe.docx", b"de Hermes", modo=0o600)
        self.sis.poner("/root/.hermes/entrada/.subidas/%s/datos" % ("b" * 32), b"a medias", modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("/root/.hermes/entrada/.subidas (lo que la app dejó a medias) y /root/.hermes/entrada, si se "
                      "queda vacía", self.salida, "el resumen lo dice antes")
        self.assertTrue(self.sis.existe("/root/.hermes/entrada/2026-10-04/informe.docx"))
        self.assertFalse(self.sis.existe("/root/.hermes/entrada/.subidas"), "lo de a medias es del ayudante")
        self.assertIn("/root/.hermes/entrada: la carpeta de entrada de Hermes no está vacía", self.salida)

    def test_una_entrada_cambiada_por_un_enlace_no_lleva_el_borrado_a_otro_sitio(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.sis.poner("/srv/otra/.subidas/de-otro.txt", b"no se borra", modo=0o600)
        self.sis.borrar("/root/.hermes/entrada")
        self.sis.enlazar("/root/.hermes/entrada", self.sis.ruta("/srv/otra"))
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer("/srv/otra/.subidas/de-otro.txt"), b"no se borra")

    def test_una_carpeta_de_entrada_que_ya_estaba_no_es_mia(self):
        self.sis.carpeta("/root/.hermes/entrada", 0o750)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertNotIn("entrada", self.manifiesto())
        self.assertEqual(self.sis.modo("/root/.hermes/entrada"), 0o750)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertTrue(self.sis.es_carpeta("/root/.hermes/entrada"))

    def test_mientras_coloca_un_fichero_no_se_corta(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.sis.poner("/root/.hermes/entrada/.subidas/%s/datos" % ("c" * 32), b"terminandose", modo=0o600)
        self.falso.activos.add("hehermes-entrada@*")
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("la entrada de ficheros: su ayudante está colocando un fichero", self.salida)
        self.assertNotIn(["systemctl", "stop", "hehermes-entrada@*.service"], self.sis.ordenes)
        self.assertTrue(self.sis.existe("/root/.hermes/entrada/.subidas/%s/datos" % ("c" * 32)))

    def test_con_hermes_de_otro_usuario_escribe_como_el(self):
        unidad = p.unidad_entrada(self.ambito(), "/srv/hermes", "hermes")
        self.assertIn("--hermes-home=/srv/hermes --conexion\n", unidad)
        self.assertIn("User=hermes\n", unidad)
        self.assertIn("BindPaths=-/srv/hermes/entrada -/srv/hermes/profiles\n", unidad)
        self.assertNotIn("User=", p.unidad_entrada(self.ambito(), "/srv/hermes", "root"))
        for malo in ("root;x", "Hermes", "a b"):
            with self.assertRaises(ValueError):
                p.unidad_entrada(self.ambito(), "/srv/hermes", malo)
        with self.assertRaises(ValueError):
            p.unidad_entrada(self.ambito(), "/srv/her mes")


class EntradaDeFicherosSinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_como_el_usuario_de_hermes_en_su_casa(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(a.entrada, "/home/hermes/.local/share/hehermes-servidor/hehermes-entrada")
        self.assertEqual(self.sis.leer(a.entrada), ENTRADA.read_bytes())
        self.assertIn("[entrada]\n# El ayudante de la entrada (/avisos/v1/entrada/…): lo que la app le manda a "
                      "Hermes.\nayudante = /run/user/1000/hehermes-entrada.sock\n", self.sis.leer_texto(a.vigia_ini))
        self.assertIn("ListenStream=%t/hehermes-entrada.sock\nSocketMode=0600\n",
                      self.sis.leer_texto(a.unidad_entrada_socket))
        servicio = self.sis.leer_texto(a.unidad_entrada)
        self.assertIn("ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=/home/hermes/.hermes --conexion\n"
                      % a.entrada, servicio)
        self.assertIn("NO puede ponerse", servicio, "dice lo que una unidad de usuario no puede, no lo finge")
        for nunca in ("CapabilityBoundingSet=", "BindPaths=", "ProtectHome=", "User="):
            self.assertNotIn(nunca, servicio)
        self.assertIn("LimitFSIZE=16G\n", servicio)
        self.assertTrue(self.sis.es_carpeta("/home/hermes/.hermes/entrada"))
        self.assertEqual(self.sis.modo("/home/hermes/.hermes/entrada"), 0o700)
        self.assertIn("hehermes-entrada.socket", self.falso.activos_usuario)
        self.assertNotIn("hehermes-entrada.socket", self.falso.activos)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.entrada, a.unidad_entrada_socket, a.unidad_entrada, "/home/hermes/.hermes/entrada"):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertIn(["systemctl", "--user", "disable", "--now", "hehermes-entrada.socket"], self.sis.ordenes)


class ActualizarDesdeLaApp(Base):
    """El ayudante que actualiza el servidor (desde la 0.10.10), con root: como en el VPS de Daniel."""

    def test_con_root_el_ayudante_su_socket_su_jaula_y_lo_que_lee_el_vigia(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(self.sis.leer(a.actualizar), ACTUALIZAR.read_bytes())
        self.assertEqual(self.sis.modo(a.actualizar), 0o755)
        self.assertEqual(self.sis.leer("/opt/hehermes-servidor/hehermes-actualizar"), ACTUALIZAR.read_bytes(),
                         "y su copia con el instalador, para repararlo desde lo instalado")
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("\n[servidor]\n", ini)
        self.assertIn("instalador = /opt/hehermes-servidor\n", ini)
        self.assertIn("ayudante = /run/hehermes-actualizar.sock\n", ini)
        self.assertIn("servicios = hehermes-pasarela.service hehermes-vigia.service hehermes-leer-media.socket "
                      "hehermes-respaldo.socket hehermes-entrada.socket hehermes-actualizar.socket "
                      "hehermes-agentes.socket hehermes-agentes-memoria.timer\n", ini)
        self.assertIn("hermes = hermes-gateway.service\n", ini)
        # El socket y la jaula son los de server/avisos/despliegue, línea a línea (menos los comentarios).
        for nuestra, suya in ((a.unidad_actualizar_socket, "hehermes-actualizar.socket"),
                              (a.unidad_actualizar, "hehermes-actualizar@.service")):
            unidad = activas(self.sis.leer_texto(nuestra))
            despliegue = activas((ACTUALIZAR.parent / suya).read_text())
            for clave in set(despliegue) | set(unidad):
                if clave != "Documentation":
                    self.assertEqual(unidad.get(clave), despliegue.get(clave), (suya, clave))
        vigia = activas(self.sis.leer_texto(a.unidad_vigia))
        self.assertIn("hehermes-actualizar.socket", " ".join(vigia["Wants"]).split())
        self.assertNotIn("hehermes-actualizar.socket", " ".join(vigia.get("Requires", [])))
        self.assertIn("hehermes-actualizar.socket", self.falso.activos)
        self.assertIn("hehermes-actualizar.socket", self.manifiesto()["unidades"])
        self.assertIn("bien actualizar desde la app: el socket de su ayudante está en marcha "
                      "(/run/hehermes-actualizar.sock)", self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)
        # Desinstalar se lo lleva, y su carpeta (el estado de la última y lo que dijo el instalador).
        self.sis.poner("/var/lib/hehermes-actualizar/estado.json", b'{"estado": "hecho"}', modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.actualizar, a.unidad_actualizar_socket, a.unidad_actualizar, "/var/lib/hehermes-actualizar"):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertNotIn("hehermes-actualizar.socket", self.falso.activos)

    def test_lo_lee_el_vigia_de_verdad(self):
        import os
        import tempfile
        sys.path.insert(0, str(apoyo.REPO / "server" / "avisos"))
        self.addCleanup(sys.path.remove, str(apoyo.REPO / "server" / "avisos"))
        from hehermes_avisos.vigia.configuracion import ConfigVigia
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = os.path.join(carpeta, "vigia.ini")
            with open(ruta, "w") as f:
                f.write(self.sis.leer_texto(self.ambito().vigia_ini))
            config = ConfigVigia.leer(ruta)
        self.assertEqual((config.servidor_instalador, config.servidor_ayudante, config.servidor_hermes),
                         ("/opt/hehermes-servidor", "/run/hehermes-actualizar.sock", "hermes-gateway.service"))
        self.assertEqual(config.servidor_servicios[:2], ("hehermes-pasarela.service", "hehermes-vigia.service"))

    def test_con_los_avisos_a_mano_no_lo_pone_el_instalador(self):
        """En el VPS de Daniel lo pone `instalar.sh` con los avisos; el instalador solo deja su copia en /opt."""
        self.sis.carpeta(avisos.A_MANO, 0o755)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        for ruta in (a.actualizar, a.unidad_actualizar_socket, a.unidad_actualizar):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertTrue(self.sis.existe("/opt/hehermes-servidor/hehermes-actualizar"))

    def test_la_unidad_de_hermes_solo_si_el_vigia_la_puede_mirar(self):
        from hehermes_servidor import ambito as amb
        from hehermes_servidor.gestor import Gestor

        class Hermes:
            def __init__(self, gestor):
                self.gestor = gestor

        root, usuario = amb.de_root(), amb.de_usuario("hermes", "/home/hermes", 1000)
        casos = ((root, Gestor("sistema", "hermes-gateway-perfil.service"), "hermes-gateway-perfil.service"),
                 (root, Gestor("usuario", "hermes-gateway.service", "hermes", 1000), None),
                 (root, Gestor("docker", "a" * 64), None),
                 (root, None, None),
                 (root, Gestor("sistema", "hermes\\x2dgateway.service"), None),
                 (usuario, Gestor("usuario", "hermes-gateway.service", "hermes", 1000), "usuario:hermes-gateway.service"),
                 (usuario, Gestor("usuario", "hermes-gateway.service", "otro", 1001), None),
                 (usuario, Gestor("sistema", "hermes-gateway.service"), "hermes-gateway.service"))
        for a, gestor, esperada in casos:
            with self.subTest(root=a.root, gestor=gestor):
                self.assertEqual(avisos.unidad_de_hermes_para_el_vigia(Hermes(gestor), a), esperada)


class ActualizarDesdeLaAppSinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_sin_root_no_hay_ayudante_y_el_vigia_lo_sabe(self):
        """Instalar es cosa de root: sin root, la app enseña cómo hacerlo a mano (el comando o la frase)."""
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        self.assertIsNone(a.actualizar)
        self.assertFalse(self.sis.existe(a.unidad_actualizar_socket))
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("instalador = /home/hermes/.local/share/hehermes-servidor\n", ini)
        self.assertIn("\nayudante =\n", ini.split("[servidor]")[1])
        self.assertIn("servicios = usuario:hehermes-pasarela.service usuario:hehermes-vigia.service "
                      "usuario:hehermes-leer-media.socket usuario:hehermes-respaldo.socket "
                      "usuario:hehermes-entrada.socket usuario:hehermes-agentes.socket "
                      "usuario:hehermes-agentes-memoria.timer\n", ini)
        self.assertNotIn("hehermes-actualizar", self.sis.leer_texto(a.unidad_vigia))


def opciones_del_ayudante_de_los_agentes():
    """Las opciones que entiende `hehermes-agentes` (su `OPCIONES`), leídas de su código sin ejecutarlo."""
    import ast
    arbol = ast.parse(AGENTES.read_text())
    for nodo in arbol.body:
        if isinstance(nodo, ast.Assign) and [getattr(o, "id", None) for o in nodo.targets] == ["OPCIONES"]:
            return set(ast.literal_eval(nodo.value))
    raise AssertionError("hehermes-agentes no tiene OPCIONES")


class LosAgentes(Base):
    """El ayudante de los agentes (desde la 0.11.0, contrato §18), con root: como en el VPS de Daniel."""

    def instalar(self):
        with mock.patch.object(self.sis, "carpeta", wraps=self.sis.carpeta) as carpeta:
            self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        return [c.args for c in carpeta.call_args_list]

    def test_con_root_el_ayudante_su_socket_su_jaula_su_temporizador_y_sus_claves(self):
        carpetas = self.instalar()
        a = self.ambito()
        self.assertEqual(self.sis.leer(a.agentes), AGENTES.read_bytes())
        self.assertEqual(self.sis.modo(a.agentes), 0o755)
        self.assertEqual(self.sis.leer("/opt/hehermes-servidor/hehermes-agentes"), AGENTES.read_bytes(),
                         "y su copia con el instalador, para repararlo desde lo instalado")
        ini = self.sis.leer_texto(a.vigia_ini)
        self.assertIn("\n[agentes]\n", ini)
        self.assertIn("claves = /etc/hehermes-avisos/agentes\n", ini.split("[agentes]")[1])
        self.assertIn("ayudante = /run/hehermes-agentes.sock\n", ini.split("[agentes]")[1])
        self.assertIn("[agentes]\n# Las claves de los agentes (/p/<perfil>/…), una por perfil: las escribe "
                      "hehermes-agentes.\nclaves = /etc/hehermes-pasarela/agentes\n", self.sis.leer_texto(a.pasarela_ini))
        # El socket, la plantilla, el servicio de la memoria y su temporizador son los de server/avisos/despliegue,
        # línea a línea (menos los comentarios).
        for nuestra, suya in ((a.unidad_agentes_socket, "hehermes-agentes.socket"),
                              (a.unidad_agentes, "hehermes-agentes@.service"),
                              (a.unidad_agentes_memoria, "hehermes-agentes-memoria.service"),
                              (a.temporizador_agentes_memoria, "hehermes-agentes-memoria.timer")):
            unidad = activas(self.sis.leer_texto(nuestra))
            despliegue = activas((AGENTES.parent / suya).read_text())
            for clave in set(despliegue) | set(unidad):
                if clave != "Documentation":
                    self.assertEqual(unidad.get(clave), despliegue.get(clave), (suya, clave))
        # Lo que pone en su ExecStart lo entiende el ayudante.
        for ruta in (a.unidad_agentes, a.unidad_agentes_memoria):
            orden = activas(self.sis.leer_texto(ruta))["ExecStart"][0].split()
            self.assertEqual(orden[:5], ["/usr/bin/python3", "-I", "-S", "-B", a.agentes])
            opciones = {o[2:].split("=", 1)[0] for o in orden[5:] if o.startswith("--") and "=" in o}
            self.assertLessEqual(opciones, opciones_del_ayudante_de_los_agentes(), ruta)
        # Las carpetas de las claves: de root y del grupo de quien las lee, con setgid (cada clave nace de su grupo).
        for carpeta, grupo in ((a.claves_agentes_pasarela, "hh-pasarela"), (a.claves_agentes_vigia, "hh-vigia")):
            self.assertTrue(self.sis.es_carpeta(carpeta), carpeta)
            self.assertIn((carpeta, 0o2750), carpetas)
            self.assertEqual(self.falso.dueños.get(carpeta), "root:" + grupo)
            self.assertNotIn(carpeta, self.manifiesto()["carpetas"], "se van por su nombre, no por el manifiesto")
        vigia = activas(self.sis.leer_texto(a.unidad_vigia))
        self.assertIn("hehermes-agentes.socket", " ".join(vigia["Wants"]).split())
        self.assertNotIn("hehermes-agentes.socket", " ".join(vigia.get("Requires", [])))
        self.assertIn("servicios = hehermes-pasarela.service hehermes-vigia.service hehermes-leer-media.socket "
                      "hehermes-respaldo.socket hehermes-entrada.socket hehermes-actualizar.socket "
                      "hehermes-agentes.socket hehermes-agentes-memoria.timer\n", ini)
        for unidad in ("hehermes-agentes.socket", "hehermes-agentes-memoria.timer"):
            self.assertIn(unidad, self.falso.activos)
            self.assertIn(unidad, self.falso.habilitados)
            self.assertIn(unidad, self.manifiesto()["unidades"])
        self.assertIn("bien agentes: el socket de su ayudante está en marcha (/run/hehermes-agentes.sock)", self.salida)
        self.assertIn("bien agentes: la memoria que comparten se junta cada minuto (hehermes-agentes-memoria.timer)",
                      self.salida)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios.", self.salida)

    def test_desinstalar_se_lleva_las_claves_y_deja_los_agentes(self):
        self.instalar()
        a = self.ambito()
        for carpeta in (a.claves_agentes_pasarela, a.claves_agentes_vigia):
            self.sis.poner(carpeta + "/investigador.clave", b"clave-de-un-agente-de-las-pruebas\n", modo=0o640)
            self.sis.poner(carpeta + "/.redactor.clave.0123abcd", b"a medio escribir\n", modo=0o640)
        self.sis.poner(a.carpeta_agentes + "/trabajos/" + "a" * 32 + ".json", b'{"estado": "hecho"}', modo=0o600)
        self.sis.poner("/root/.hermes/profiles/investigador/SOUL.md", b"Eres un investigador.\n", modo=0o600)
        self.sis.poner("/root/hehermes-copias/agentes/investigador-1.tar.gz", b"la copia", modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("las claves de los agentes (/etc/hehermes-pasarela/agentes y /etc/hehermes-avisos/agentes) y lo "
                      "que apunta su ayudante (/var/lib/hehermes-agentes). Los agentes, que son perfiles de Hermes, y "
                      "sus copias se quedan", self.salida, "el resumen lo dice antes")
        for ruta in (a.agentes, a.unidad_agentes_socket, a.unidad_agentes, a.unidad_agentes_memoria,
                     a.temporizador_agentes_memoria, a.claves_agentes_pasarela, a.claves_agentes_vigia,
                     a.carpeta_agentes, "/opt/hehermes-servidor/hehermes-agentes"):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertEqual(self.sis.leer("/root/.hermes/profiles/investigador/SOUL.md"), b"Eres un investigador.\n")
        self.assertEqual(self.sis.leer("/root/hehermes-copias/agentes/investigador-1.tar.gz"), b"la copia")
        self.assertFalse({"hehermes-agentes.socket", "hehermes-agentes-memoria.timer"} & self.falso.activos)
        self.assertNotIn("Se queda", self.salida)

    def test_lo_que_no_es_una_clave_se_queda_y_un_enlace_no_lleva_el_borrado_a_otro_sitio(self):
        self.instalar()
        a = self.ambito()
        self.sis.poner(a.claves_agentes_vigia + "/investigador.clave", b"clave\n", modo=0o640)
        self.sis.poner(a.claves_agentes_vigia + "/notas.txt", b"de alguien", modo=0o640)
        self.sis.poner("/srv/otra/investigador.clave", b"no se borra", modo=0o600)
        self.sis.borrar(a.claves_agentes_pasarela)
        self.sis.enlazar(a.claves_agentes_pasarela, self.sis.ruta("/srv/otra"))
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer("/srv/otra/investigador.clave"), b"no se borra")
        self.assertFalse(self.sis.existe(a.claves_agentes_pasarela), "el enlace se va; lo de dentro, no")
        self.assertFalse(self.sis.existe(a.claves_agentes_vigia + "/investigador.clave"))
        self.assertEqual(self.sis.leer(a.claves_agentes_vigia + "/notas.txt"), b"de alguien")
        self.assertIn("/etc/hehermes-avisos/agentes: hay algo que no es la clave de un agente; no lo toco", self.salida)

    def test_un_agente_a_medio_crear_no_se_corta(self):
        self.instalar()
        a = self.ambito()
        self.sis.poner(a.carpeta_agentes + "/trabajos/" + "b" * 32 + ".json", b'{"estado": "creando"}', modo=0o600)
        self.falso.activos.add("hehermes-agentes@*")
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("los agentes: su ayudante está creando o borrando uno", self.salida)
        self.assertTrue(self.sis.existe(a.carpeta_agentes + "/trabajos/" + "b" * 32 + ".json"))

    def test_lo_que_dice_el_vigia_de_los_agentes_es_de_los_agentes(self):
        self.falso.vigia_comprueba = self.falso.vigia_comprueba + [
            "bien: agentes: el ayudante contesta; 2 agentes; claves en su sitio"]
        self.instalar()
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("bien  agentes: el ayudante contesta; 2 agentes; claves en su sitio", self.salida)
        self.assertNotIn("vigía: agentes:", self.salida)
        self.assertIn("bien  vigía: Hermes contesta", self.salida, "lo demás, como siempre")

    def test_el_vigia_de_verdad_lo_lee(self):
        import os
        import tempfile
        sys.path.insert(0, str(apoyo.REPO / "server" / "avisos"))
        self.addCleanup(sys.path.remove, str(apoyo.REPO / "server" / "avisos"))
        from hehermes_avisos.vigia.configuracion import ConfigVigia
        self.instalar()
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = os.path.join(carpeta, "vigia.ini")
            with open(ruta, "w") as f:
                f.write(self.sis.leer_texto(self.ambito().vigia_ini))
            config = ConfigVigia.leer(ruta)
            self.assertEqual((config.agentes_claves, config.agentes_ayudante),
                             ("/etc/hehermes-avisos/agentes", "/run/hehermes-agentes.sock"))
            with open(ruta, "w") as f:
                f.write(p.vigia_ini(self.ambito(), 8642, "/root/.hermes/.env", "/root"))
            config = ConfigVigia.leer(ruta)
            self.assertEqual((config.agentes_claves, config.agentes_ayudante), ("/etc/hehermes-avisos/agentes", ""),
                             "sin el ayudante, vacío: esas rutas contestan 503")

    def test_con_hermes_de_otro_usuario_lo_de_su_casa_como_el(self):
        unidad = p.unidad_agentes(self.ambito(), "/srv/hermes", "hermes", "hermes-gateway.service")
        self.assertIn("--hermes-home=/srv/hermes --usuario-hermes=hermes --unidad-hermes=hermes-gateway.service "
                      "--conexion\n", unidad)
        self.assertIn("CapabilityBoundingSet=CAP_SETUID CAP_SETGID\n", unidad)
        self.assertNotIn("User=", unidad, "de root: escribe las claves, que son de root")
        de_root = p.unidad_agentes(self.ambito(), "/root/.hermes")
        self.assertIn("CapabilityBoundingSet=\n", de_root)
        self.assertIn("--usuario-hermes=root ", de_root)
        memoria = p.unidad_agentes_memoria(self.ambito(), "/srv/hermes", "hermes")
        self.assertIn("--hermes-home=/srv/hermes --usuario-hermes=hermes sincronizar-memoria\n", memoria)
        self.assertIn("CapabilityBoundingSet=CAP_SETUID CAP_SETGID\n", memoria)
        self.assertIn("ReadWritePaths=-/srv/hermes\n", memoria)
        self.assertIn("PrivateNetwork=yes\n", memoria)
        for malo in ("root;x", "Hermes", "a b"):
            with self.assertRaises(ValueError):
                p.unidad_agentes(self.ambito(), "/srv/hermes", malo)
            with self.assertRaises(ValueError):
                p.unidad_agentes_memoria(self.ambito(), "/srv/hermes", malo)
        for mala in ("hermes gateway.service", "x.socket", "a;b.service"):
            with self.assertRaises(ValueError):
                p.unidad_agentes(self.ambito(), "/srv/hermes", "hermes", mala)
        with self.assertRaises(ValueError):
            p.unidad_agentes(self.ambito(), "/srv/her mes")

    def test_con_los_avisos_a_mano_no_lo_pone_el_instalador_pero_la_pasarela_tiene_su_carpeta(self):
        """En el VPS de Daniel lo pone `instalar.sh` con los avisos (y la carpeta del vigía); el instalador, la de la
        pasarela, que es suya, y su copia en /opt."""
        self.sis.carpeta(avisos.A_MANO, 0o755)
        self.sis.poner("/etc/hehermes-avisos/agentes/investigador.clave", b"de instalar.sh\n", modo=0o640)
        self.instalar()
        a = self.ambito()
        for ruta in (a.agentes, a.unidad_agentes_socket, a.unidad_agentes, a.unidad_agentes_memoria,
                     a.temporizador_agentes_memoria):
            self.assertFalse(self.sis.existe(ruta), ruta)
        self.assertTrue(self.sis.existe("/opt/hehermes-servidor/hehermes-agentes"))
        self.assertTrue(self.sis.es_carpeta(a.claves_agentes_pasarela))
        self.assertEqual(self.falso.dueños.get(a.claves_agentes_pasarela), "root:hh-pasarela")
        self.assertNotIn(a.claves_agentes_vigia, self.falso.dueños, "la del vigía es de instalar.sh")
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe(a.claves_agentes_pasarela))
        self.assertEqual(self.sis.leer("/etc/hehermes-avisos/agentes/investigador.clave"), b"de instalar.sh\n")


class LosAgentesConHermesDeOtroUsuario(Base):
    """Con root y un Hermes de otro usuario: el ayudante es de root (escribe las claves), con CAP_SETUID y CAP_SETGID
    para hacer lo de la casa de Hermes como él."""

    def servidor(self):
        return sf.servidor(usuario="hermes")

    def test_lo_de_su_casa_como_el(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        servicio = activas(self.sis.leer_texto(a.unidad_agentes))
        self.assertEqual(servicio["ExecStart"], ["/usr/bin/python3 -I -S -B /usr/local/libexec/hehermes-agentes "
                                                 "--hermes-home=/home/hermes/.hermes --usuario-hermes=hermes "
                                                 "--unidad-hermes=hermes-gateway.service --conexion"])
        self.assertEqual(servicio["CapabilityBoundingSet"], ["CAP_SETUID CAP_SETGID"])
        self.assertNotIn("User", servicio)
        memoria = activas(self.sis.leer_texto(a.unidad_agentes_memoria))
        self.assertEqual(memoria["ExecStart"], ["/usr/bin/python3 -I -S -B /usr/local/libexec/hehermes-agentes "
                                                "--hermes-home=/home/hermes/.hermes --usuario-hermes=hermes "
                                                "sincronizar-memoria"])
        self.assertEqual((memoria["CapabilityBoundingSet"], memoria["ReadWritePaths"]),
                         (["CAP_SETUID CAP_SETGID"], ["-/home/hermes/.hermes"]))


class LosAgentesSinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_como_el_usuario_de_hermes_en_su_casa(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        a = self.ambito()
        self.assertEqual(a.agentes, "/home/hermes/.local/share/hehermes-servidor/hehermes-agentes")
        self.assertEqual(self.sis.leer(a.agentes), AGENTES.read_bytes())
        ini = self.sis.leer_texto(a.vigia_ini).split("[agentes]")[1]
        self.assertIn("claves = /home/hermes/.config/hehermes-avisos/agentes\n", ini)
        self.assertIn("ayudante = /run/user/1000/hehermes-agentes.sock\n", ini)
        self.assertIn("claves = /home/hermes/.config/hehermes-pasarela/agentes\n", self.sis.leer_texto(a.pasarela_ini))
        self.assertIn("ListenStream=%t/hehermes-agentes.sock\nSocketMode=0600\n",
                      self.sis.leer_texto(a.unidad_agentes_socket))
        servicio = self.sis.leer_texto(a.unidad_agentes)
        self.assertIn("ExecStart=/usr/bin/python3 -I -S -B %s --usuario --hermes-home=/home/hermes/.hermes "
                      "--trabajo=/home/hermes/.local/state/hehermes-agentes "
                      "--claves-pasarela=/home/hermes/.config/hehermes-pasarela/agentes "
                      "--claves-vigia=/home/hermes/.config/hehermes-avisos/agentes "
                      "--unidad-hermes=hermes-gateway.service --conexion\n" % a.agentes, servicio)
        memoria = self.sis.leer_texto(a.unidad_agentes_memoria)
        self.assertIn("--usuario --hermes-home=/home/hermes/.hermes --trabajo=/home/hermes/.local/state/hehermes-agentes "
                      "--claves-pasarela=/home/hermes/.config/hehermes-pasarela/agentes "
                      "--claves-vigia=/home/hermes/.config/hehermes-avisos/agentes sincronizar-memoria\n", memoria)
        for texto in (servicio, memoria):
            for nunca in ("CapabilityBoundingSet=", "ProtectSystem=", "User=", "--usuario-hermes"):
                self.assertNotIn(nunca, texto)
            orden = activas(texto)["ExecStart"][0].split()
            opciones = {o[2:].split("=", 1)[0] for o in orden[5:] if o.startswith("--") and "=" in o}
            self.assertLessEqual(opciones, opciones_del_ayudante_de_los_agentes())
        for carpeta in (a.claves_agentes_pasarela, a.claves_agentes_vigia):
            self.assertEqual(self.sis.modo(carpeta), 0o700, carpeta)
            self.assertNotIn(carpeta, self.falso.dueños)
        for unidad in ("hehermes-agentes.socket", "hehermes-agentes-memoria.timer"):
            self.assertIn(unidad, self.falso.activos_usuario)
            self.assertNotIn(unidad, self.falso.activos)
        self.assertIn("Wants=hehermes-leer-media.socket hehermes-respaldo.socket hehermes-entrada.socket "
                      "hehermes-agentes.socket\n", self.sis.leer_texto(a.unidad_vigia))
        self.sis.poner(a.claves_agentes_vigia + "/investigador.clave", b"clave\n", modo=0o600)
        self.sis.poner(a.carpeta_agentes + "/trabajos/x.json", b"{}", modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in (a.agentes, a.unidad_agentes_socket, a.unidad_agentes, a.unidad_agentes_memoria,
                     a.temporizador_agentes_memoria, a.claves_agentes_pasarela, a.claves_agentes_vigia,
                     a.carpeta_agentes):
            self.assertFalse(self.sis.existe(ruta), ruta)
        for unidad in ("hehermes-agentes.socket", "hehermes-agentes-memoria.timer"):
            self.assertIn(["systemctl", "--user", "disable", "--now", unidad], self.sis.ordenes)


class ElPaquete(unittest.TestCase):
    def test_lleva_el_codigo_de_los_avisos(self):
        from test_paquete import cargar_empaquetar
        nombres = [dentro for dentro, _ in cargar_empaquetar().ficheros()]
        for esperado in ("hehermes_avisos/__init__.py", "hehermes_avisos/vigia/__main__.py",
                         "hehermes_avisos/rele/publico.py", "hehermes_servidor/avisos.py"):
            self.assertIn(esperado, nombres)
        self.assertFalse([n for n in nombres if "tests" in n or "__pycache__" in n or n.startswith("hehermes_avisos/")
                          and not n.endswith(".py")])


if __name__ == "__main__":
    unittest.main()
