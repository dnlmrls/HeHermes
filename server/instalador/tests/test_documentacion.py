"""El README dice lo que de verdad pinta el instalador en un servidor como el de Daniel."""

import apoyo

import re
import unittest

import servidor_falso as sf
from hehermes_servidor.deteccion import detectar
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.plan import Opciones, calcular_plan, pintar


class Documentacion(unittest.TestCase):
    def test_el_plan_del_vps_de_daniel_es_el_del_readme(self):
        sis, _ = sf.servidor_de_daniel()
        self.addCleanup(sis.limpiar)
        man = Manifiesto.leer(sis)
        texto = pintar(calcular_plan(sis, detectar(sis, man), man, Opciones(iphone="mi-iphone"), str(apoyo.RAIZ)))
        readme = (apoyo.RAIZ / "README.md").read_text()
        bloque = re.search(r"<!-- plan-de-daniel -->\n```\n(.*?)```\n<!-- /plan-de-daniel -->", readme, re.S).group(1)
        self.assertEqual(bloque, texto[texto.index("Hay que saber:"):])

    def test_la_pasarela_al_lado_de_la_vpn_de_daniel_es_la_del_readme(self):
        from unittest import mock
        from hehermes_servidor import ambito, porchat
        from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
        sis, _ = sf.servidor_de_daniel()
        self.addCleanup(sis.limpiar)
        man = Manifiesto.leer(sis)
        with mock.patch.object(porchat, "_azar", lambda n: 3234):
            det = detectar_tls(sis, man, ambito.de_root())
        texto = pintar(calcular_plan_tls(sis, det, man, Opciones(iphone="mi-iphone", modo="tls"), str(apoyo.RAIZ)))
        readme = (apoyo.RAIZ / "README.md").read_text()
        bloque = re.search(r"<!-- pasarela-de-daniel -->\n```\n(.*?)```\n<!-- /pasarela-de-daniel -->", readme,
                           re.S).group(1)
        self.assertEqual(bloque, texto[texto.index("Hay que saber:"):])

    def test_el_readme_de_la_vpn_enlaza_aqui(self):
        vpn = (apoyo.REPO / "server" / "vpn" / "README.md").read_text()
        self.assertIn("../instalador/README.md", vpn)


if __name__ == "__main__":
    unittest.main()
