"""El `.env` de Hermes, como lo escribe la gente: con `export`, comillas y comentarios."""

import apoyo  # noqa: F401

import unittest

from hehermes_servidor.entorno import leer_env


class LeerEnv(unittest.TestCase):
    def test_las_formas_de_siempre(self):
        texto = (
            "# Hermes\n"
            "API_SERVER_ENABLED=true\n"
            "export API_SERVER_KEY=abc123\n"
            'API_SERVER_HOST="127.0.0.1"\n'
            "API_SERVER_PORT = 8642\n"
            "OTRA='con # dentro'\n"
            "CON_COMENTARIO=valor # esto no\n"
            'DOBLES="con # dentro" # y esto no\n'
            "PEGADO=a#b\n"
            "VACIA=\n"
            "linea sin igual\n"
            "   \n"
            "1MAL=no\n"
        )
        self.assertEqual(leer_env(texto), {
            "API_SERVER_ENABLED": "true",
            "API_SERVER_KEY": "abc123",
            "API_SERVER_HOST": "127.0.0.1",
            "API_SERVER_PORT": "8642",
            "OTRA": "con # dentro",
            "CON_COMENTARIO": "valor",
            "DOBLES": "con # dentro",
            "PEGADO": "a#b",
            "VACIA": "",
        })

    def test_la_ultima_gana(self):
        self.assertEqual(leer_env("K=1\nK=2\n")["K"], "2")

    def test_fin_de_linea_de_windows(self):
        self.assertEqual(leer_env("API_SERVER_KEY=abc\r\n")["API_SERVER_KEY"], "abc")


if __name__ == "__main__":
    unittest.main()
