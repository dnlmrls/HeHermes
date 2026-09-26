"""El README dice lo que de verdad pinta el instalador en un servidor como el de Daniel."""

import apoyo

import re
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito, porchat
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
from hehermes_servidor.plan import Opciones, pintar


class Documentacion(unittest.TestCase):
    def test_la_pasarela_al_lado_de_la_vpn_de_daniel_es_la_del_readme(self):
        sis, _ = sf.servidor_de_daniel()
        self.addCleanup(sis.limpiar)
        man = Manifiesto.leer(sis)
        with mock.patch.object(porchat, "_azar", lambda n: 3234):
            det = detectar_tls(sis, man, ambito.de_root())
        texto = pintar(calcular_plan_tls(sis, det, man, Opciones(iphone="mi-iphone"), str(apoyo.RAIZ)))
        readme = (apoyo.RAIZ / "README.md").read_text()
        bloque = re.search(r"<!-- pasarela-de-daniel -->\n```\n(.*?)```\n<!-- /pasarela-de-daniel -->", readme,
                           re.S).group(1)
        self.assertEqual(bloque, texto[texto.index("Hay que saber:"):])

    def test_el_readme_de_la_vpn_enlaza_aqui(self):
        vpn = (apoyo.REPO / "server" / "vpn" / "README.md").read_text()
        self.assertIn("../instalador/README.md", vpn)

    def test_el_readme_ya_no_ofrece_instalar_la_vpn(self):
        """Solo como algo que ya no existe: ni un comando de ejemplo con `--modo vpn` que no sea para desinstalar."""
        readme = (apoyo.RAIZ / "README.md").read_text()
        for linea in readme.splitlines():
            if "--modo vpn" in linea and "instalar" in linea and "desinstalar" not in linea:
                self.assertRegex(linea, r"ya no existe|ya no se instala|hasta la 0\.5|Historia|antes", linea)
        self.assertNotIn("--avisos` (solo VPN)", readme)


if __name__ == "__main__":
    unittest.main()
