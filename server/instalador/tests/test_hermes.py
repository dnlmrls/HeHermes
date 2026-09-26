"""Que haya un Hermes de verdad (instalado, en marcha y con su api_server contestando) y que su API no esté expuesta.

La API de Hermes en 0.0.0.0 se deja a quien llegue al servidor sin pasar por la pasarela, con su clave como única
defensa. Se avisa muy claro y no se cambia sin permiso (`--corregir-exposicion`): podría romper otra cosa del usuario.
"""

import apoyo

import unittest

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli
from hehermes_servidor import deteccion as d
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import detectar_tls

ORIGEN = str(apoyo.RAIZ)
ENV = "/root/.hermes/.env"


class Base(unittest.TestCase):
    def montar(self, **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)

    def detectar(self, **opciones):
        return detectar_tls(self.sis, Manifiesto.leer(self.sis), amb.de_root(), **opciones)

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def bloqueos(self, det):
        return "\n".join(det.bloqueos)

    def reinicios(self):
        return [o for o in self.sis.ordenes if o[:1] == ["systemd-run"] and "--on-active=90" in o]


class QueHayaUnHermes(Base):
    def test_la_unidad_parada_se_dice(self):
        self.montar()
        self.falso.activos.discard("hermes-gateway")
        texto = self.bloqueos(self.detectar())
        self.assertIn("parado", texto)
        self.assertIn("systemctl start hermes-gateway", texto)

    def test_instalado_sin_unidad_ni_proceso(self):
        self.montar()
        self.falso.unidades_hermes.clear()
        self.falso.activos.discard("hermes-gateway")
        self.sis.poner("/home/ana/.hermes/.env", "API_SERVER_ENABLED=true\n")
        self.sis.carpeta("/home")
        texto = self.bloqueos(self.detectar())
        self.assertIn("/home/ana/.hermes", texto)
        self.assertIn("no está en marcha", texto)

    def test_sin_nada_de_hermes_dice_que_no_lo_instala(self):
        self.montar()
        self.falso.unidades_hermes.clear()
        self.sis.borrar(ENV)
        self.sis.borrar("/root/.hermes")
        self.assertIn("no instala Hermes", self.bloqueos(self.detectar()))

    def test_en_su_puerto_contesta_otra_cosa(self):
        self.montar()
        self.sis.respuestas_http["http://127.0.0.1:8642/health"] = (404, b"<html>nginx</html>")
        self.assertIn("no es la API de Hermes", self.bloqueos(self.detectar()))

    def test_bien_no_para(self):
        self.montar()
        self.assertEqual(self.detectar().bloqueos, [])


class LaExposicion(Base):
    def aviso(self, det):
        rojos = [a for a in det.avisos if a.startswith(d.ROJO)]
        self.assertEqual(len(rojos), 1, det.avisos)
        return rojos[0]

    def test_en_0000_por_el_env_avisa_en_rojo_y_propone_corregirlo(self):
        self.montar(host="0.0.0.0")
        texto = self.aviso(self.detectar())
        for trozo in ("0.0.0.0:8642", "sin pasar por la pasarela", "--corregir-exposicion", "No lo cambio"):
            self.assertIn(trozo, texto)

    def test_por_lo_que_escucha_aunque_el_env_no_lo_diga(self):
        self.montar()
        self.falso.tcp = [t for t in self.falso.tcp if not t[0].endswith(":8642")] + [("[::]:8642", "python3")]
        det = self.detectar()
        self.assertIn("[::]:8642", self.aviso(det))
        self.assertTrue(det.hermes.expuesta)

    def test_por_el_env_aunque_ahora_escuche_en_127(self):
        # Se ha cambiado el .env y Hermes todavía no se ha reiniciado: al reiniciarse, quedará abierta.
        self.montar(host="0.0.0.0")
        self.falso.tcp = [t for t in self.falso.tcp if not t[0].endswith(":8642")] + [("127.0.0.1:8642", "python3")]
        self.assertIn("0.0.0.0:8642", self.aviso(self.detectar()))

    def test_en_127_no_hay_aviso(self):
        self.montar()
        det = self.detectar()
        self.assertFalse([a for a in det.avisos if a.startswith(d.ROJO)])
        self.assertFalse(det.hermes.expuesta)

    def test_si_lo_fija_la_unidad_se_dice_donde_y_no_se_propone_el_env(self):
        self.montar(host="0.0.0.0")
        self.falso.unidades_hermes["hermes-gateway.service"]["Environment"] = "API_SERVER_HOST=0.0.0.0"
        texto = self.aviso(self.detectar())
        self.assertIn("Environment=", texto)
        self.assertNotIn("--corregir-exposicion", texto)

    def test_corregir_la_cierra_con_una_copia_y_reinicia_hermes_luego(self):
        self.montar(host="0.0.0.0")
        antes = self.sis.leer_texto(ENV)
        self.assertEqual(self.orden("instalar", "--si", "--corregir-exposicion"), 0, self.salida)
        despues = self.sis.leer_texto(ENV)
        self.assertEqual(despues, antes + "API_SERVER_HOST=127.0.0.1\n")
        man = Manifiesto.leer(self.sis)
        self.assertEqual(self.sis.leer_texto(man.datos["exposicion"]["copia"]["ruta"]), antes)
        self.assertEqual(len(self.reinicios()), 1)
        self.assertNotIn(sf.CLAVE, self.salida)

    def test_desinstalar_no_la_vuelve_a_abrir_y_lo_dice(self):
        self.montar(host="0.0.0.0")
        self.orden("instalar", "--si", "--corregir-exposicion")
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertTrue(self.sis.leer_texto(ENV).endswith("API_SERVER_HOST=127.0.0.1\n"))
        self.assertIn("volvería a abrir", self.salida)

    def test_sin_permiso_no_se_toca(self):
        self.montar(host="0.0.0.0")
        antes = self.sis.leer_texto(ENV)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(ENV), antes)
        self.assertEqual(self.reinicios(), [])

    def test_corregir_sin_poder_se_para(self):
        self.montar(host="0.0.0.0", como="proceso")
        self.assertEqual(self.orden("instalar", "--si", "--corregir-exposicion"), 1)
        self.assertIn("no sé reiniciarlo", self.salida)
        self.montar(host="0.0.0.0")
        self.falso.unidades_hermes["hermes-gateway.service"]["Environment"] = "API_SERVER_HOST=0.0.0.0"
        self.assertEqual(self.orden("instalar", "--si", "--corregir-exposicion"), 1)
        self.assertIn("Environment=", self.salida)

    def test_corregir_sin_exposicion_no_hace_nada(self):
        self.montar()
        antes = self.sis.leer_texto(ENV)
        self.assertEqual(self.orden("instalar", "--si", "--corregir-exposicion"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(ENV), antes)


if __name__ == "__main__":
    unittest.main()
