"""La sección «Seguridad» de `comprobar`: bien, aviso o mal, y sale con 1 si hay algún mal. Solo lee."""

import apoyo

import re
import unittest

import servidor_falso as sf
from hehermes_servidor import cli
from hehermes_servidor import piezas as p
from hehermes_servidor import seguridad
from hehermes_servidor.manifiesto import Manifiesto



def con_modo_vpn(argv):
    """Estas pruebas son del modo VPN, que desde la pasarela (0.5.0) ya no es el de por defecto."""
    argv = list(argv)
    if argv[:1] == ["instalar"] and "--modo" not in argv:
        argv.append("--modo")
        argv.append("vpn")
    return argv


ORIGEN = str(apoyo.RAIZ)


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(con_modo_vpn(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def instalar(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)

    def revisar(self):
        antes = self.sis.foto()
        desde = len(self.sis.ordenes)
        resultado = seguridad.revisar(self.sis, Manifiesto.leer(self.sis))
        self.assertEqual(self.sis.foto(), antes, "solo lee")
        for orden in self.sis.ordenes[desde:]:
            self.assertNotIn(orden[:2], (["ufw", "allow"], ["ufw", "delete"], ["nft", "-f"], ["systemctl", "restart"]))
        return resultado

    def estados(self, que):
        return [(e, t) for e, t in self.revisar() if que in t]

    def mal(self, que):
        self.assertTrue([t for e, t in self.revisar() if e == "mal" and que in t], self.revisar())


class TrasInstalar(Base):
    def test_todo_cerrado_es_todo_bien(self):
        self.instalar()
        resultado = self.revisar()
        self.assertEqual([t for e, t in resultado if e == "mal"], [])
        textos = "\n".join(t for _, t in resultado)
        for trozo in ("solo escucha en 127.0.0.1:8642", "solo escucha en 10.77.0.1:80", "no al propio servidor",
                      "ufw, en marcha", "canje: ninguno abierto", "solo para su dueño",
                      "solo AES-256-GCM con PRF SHA-384 y ECP-384", "la clave de las firmas todavía es el marcador"):
            self.assertIn(trozo, textos)

    def test_comprobar_la_pinta_y_sale_con_cero(self):
        self.instalar()
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("\nSeguridad\n", self.salida)
        self.assertRegex(self.salida, r"\n  bien  la API de Hermes solo escucha")
        self.assertRegex(self.salida, r"\n  aviso actualizar:")

    def test_un_mal_hace_salir_con_uno(self):
        self.instalar()
        self.sis.poner(p.BEARER, self.sis.leer(p.BEARER), modo=0o644)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertRegex(self.salida, r"\n  MAL   secretos que se pueden leer .*hehermes-bearer.conf \(0644\)")


class LoQueSeVeAbierto(Base):
    def test_hermes_en_todas_las_interfaces(self):
        self.instalar()
        self.falso.tcp.append(("0.0.0.0:8642", "python3"))
        self.mal("--corregir-exposicion")

    def test_nginx_escuchando_de_mas_o_con_el_agujero(self):
        self.instalar()
        sitio = self.sis.leer_texto(p.SITIO)
        self.sis.poner(p.SITIO, sitio.replace("listen 10.77.0.1:80;", "listen 80;"))
        self.mal("escucha en 80")
        self.sis.poner(p.SITIO, re.sub(r"\n\s*(allow|deny) [^;]+;", "", sitio))
        self.mal("el agujero del túnel")

    def test_otro_sitio_con_la_clave(self):
        self.instalar()
        self.sis.poner("/etc/nginx/sites-enabled/otro", "server { include /etc/nginx/hehermes-bearer.conf; }\n")
        self.mal("/etc/nginx/sites-enabled/otro también pone la clave")

    def test_el_puerto_del_canje_que_quedo_abierto(self):
        self.instalar()
        self.falso.reglas_ufw.append("ufw allow proto tcp from any to any port 61000 comment hehermes-canje")
        self.mal("sigue abierto en ufw")
        self.falso.activos.add("hehermes-canje")
        self.assertEqual([e for e, t in self.estados("canje:")], ["aviso"], "con el canje en marcha, es lo suyo")

    def test_la_psk_o_el_env_legibles(self):
        self.instalar()
        self.sis.poner("/etc/swanctl/conf.d/hehermes-mi-iphone.conf",
                       self.sis.leer("/etc/swanctl/conf.d/hehermes-mi-iphone.conf"), modo=0o640)
        self.mal("hehermes-mi-iphone.conf (0640)")
        self.setUp()
        self.instalar()
        self.sis.poner("/root/.hermes/.env", self.sis.leer("/root/.hermes/.env"), modo=0o640)
        self.assertEqual([e for e, t in self.estados("desde su grupo")], ["aviso"])
        self.sis.poner("/root/.hermes/.env", self.sis.leer("/root/.hermes/.env"), modo=0o644)
        self.mal("/root/.hermes/.env (0644)")

    def test_una_conexion_con_otras_propuestas(self):
        self.instalar()
        ruta = "/etc/swanctl/conf.d/hehermes-mi-iphone.conf"
        texto = self.sis.leer_texto(ruta).replace("proposals = aes256gcm16-prfsha384-ecp384",
                                                  "proposals = aes128-sha1-modp1024,default")
        self.sis.poner(ruta, texto.replace("local_ts = 10.77.0.1/32", "local_ts = 0.0.0.0/0"), modo=0o600)
        self.mal("acepta otras propuestas")
        self.mal("no limita el túnel")

    def test_sin_cortafuegos_es_un_aviso(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual([e for e, t in self.estados("cortafuegos:")], ["aviso"])


class ElVpsDeDaniel(unittest.TestCase):
    """Lo que sale en su VPS, montado a mano (el doble de `servidor_falso.servidor_de_daniel`), y va en el README."""

    def test_es_lo_del_readme(self):
        sis, _ = sf.servidor_de_daniel()
        self.addCleanup(sis.limpiar)
        texto = "".join("  %-5s %s\n" % ("MAL" if e == "mal" else e, t)
                        for e, t in seguridad.revisar(sis, Manifiesto.leer(sis)))
        readme = (apoyo.RAIZ / "README.md").read_text()
        bloque = re.search(r"<!-- seguridad-de-daniel -->\n```\nSeguridad\n(.*?)```\n<!-- /seguridad-de-daniel -->",
                           readme, re.S)
        self.assertTrue(bloque, "falta el bloque en el README")
        self.assertEqual(bloque.group(1), texto)


if __name__ == "__main__":
    unittest.main()
