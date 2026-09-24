"""El manifiesto: qué es del instalador, y la guarda de «no pisar» lo ajeno ni lo que alguien ha cambiado.

Es una de las dos piezas con mutaciones (la otra es la regla del túnel): cada rama de `clasificar` tiene aquí una
prueba que se pone en rojo si esa rama cambia.
"""

import apoyo

import json
import os
import stat
import unittest

from hehermes_servidor import manifiesto as m
from hehermes_servidor.manifiesto import Manifiesto, clasificar, guardar_copia, restaurar_copia

RUTA = "/etc/nginx/sites-available/hehermes-tunel"
ENLACE = "/etc/nginx/sites-enabled/hehermes-tunel"


class Clasificar(unittest.TestCase):
    def setUp(self):
        self.sis = apoyo.SistemaFalso()
        self.addCleanup(self.sis.limpiar)
        self.man = Manifiesto()

    def mio(self, contenido=b"mio\n"):
        self.sis.poner(RUTA, contenido)
        self.man.apuntar_fichero(RUTA, contenido)

    def test_lo_que_no_existe_es_nuevo(self):
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"x"), m.NUEVO)

    def test_lo_mio_que_han_borrado_vuelve_a_ser_nuevo(self):
        self.man.apuntar_fichero(RUTA, b"mio\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.NUEVO)

    def test_lo_mio_igual_ya_esta(self):
        self.mio()
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.YA_ESTA)

    def test_lo_mio_sin_tocar_con_otro_contenido_deseado_cambia(self):
        self.mio()
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"version nueva\n"), m.CAMBIA)

    def test_lo_que_no_esta_en_el_manifiesto_es_ajeno(self):
        self.sis.poner(RUTA, b"de Daniel\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.AJENO)

    def test_ajeno_aunque_sea_un_enlace_o_una_carpeta(self):
        self.sis.poner("/etc/otro", b"mio\n")
        self.sis.enlazar(RUTA, "/etc/otro")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.AJENO, "un enlace no se lee a través")
        self.sis.borrar(RUTA)
        self.sis.carpeta(RUTA)
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.AJENO)

    def test_ajeno_con_el_mismo_contenido_no_se_adopta(self):
        # No hay que escribir nada, pero tampoco es suyo: desinstalar no se lo puede llevar.
        self.sis.poner(RUTA, b"mio\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.AJENO_IGUAL)

    def test_lo_mio_tocado_a_mano_es_modificado(self):
        self.mio()
        self.sis.poner(RUTA, b"mio\n# y una linea de Daniel\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.MODIFICADO)
        # Aunque lo que se quiere escribir sea justo lo que ha dejado Daniel: el hash manda.
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n# y una linea de Daniel\n"), m.MODIFICADO)

    def test_lo_mio_cambiado_por_un_enlace_es_modificado(self):
        self.mio()
        self.sis.borrar(RUTA)
        self.sis.poner("/etc/otro", b"mio\n")
        self.sis.enlazar(RUTA, "/etc/otro")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n"), m.MODIFICADO)

    def test_reemplazar_solo_vale_para_lo_ajeno_o_modificado(self):
        self.sis.poner(RUTA, b"de Daniel\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n", reemplazar={RUTA}), m.REEMPLAZA)
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n", reemplazar={"/etc/otro"}), m.AJENO)
        self.man.apuntar_fichero(RUTA, b"mio\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n", reemplazar={RUTA}), m.REEMPLAZA)
        self.sis.poner(RUTA, b"mio\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n", reemplazar={RUTA}), m.YA_ESTA,
                         "lo mío sin tocar no se «reemplaza»: no hay nada que guardar")
        self.sis.borrar(RUTA)
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"mio\n", reemplazar={RUTA}), m.NUEVO)

    def test_lo_gestionado_no_se_compara(self):
        # La clave de nginx la reescribe `hehermes-dispositivo clave` cada vez que rota: su hash cambia sin que nadie
        # la haya tocado a mano.
        self.sis.poner(RUTA, b"clave 1\n")
        self.man.apuntar_gestionado(RUTA)
        self.sis.poner(RUTA, b"clave 2\n")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"clave 3\n"), m.YA_ESTA)
        self.sis.borrar(RUTA)
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"clave 3\n"), m.NUEVO)

    def test_lo_gestionado_cambiado_por_un_enlace_es_modificado(self):
        self.sis.poner(RUTA, b"clave\n")
        self.man.apuntar_gestionado(RUTA)
        self.sis.borrar(RUTA)
        self.sis.poner("/etc/otro", b"x")
        self.sis.enlazar(RUTA, "/etc/otro")
        self.assertEqual(clasificar(self.sis, self.man, RUTA, b"clave\n"), m.MODIFICADO)

    # Enlaces

    def test_enlaces(self):
        destino = "/etc/nginx/sites-available/hehermes-tunel"
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace=destino), m.NUEVO)
        self.sis.enlazar(ENLACE, destino)
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace=destino), m.AJENO_IGUAL)
        self.man.apuntar_enlace(ENLACE, destino)
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace=destino), m.YA_ESTA)
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace="/otro"), m.CAMBIA)
        self.sis.enlazar(ENLACE, "/etc/nginx/sites-available/de-daniel")
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace=destino), m.MODIFICADO)
        self.sis.borrar(ENLACE)
        self.sis.poner(ENLACE, b"un fichero donde va el enlace")
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace=destino), m.MODIFICADO)

    def test_un_enlace_ajeno(self):
        self.sis.enlazar(ENLACE, "/etc/nginx/sites-available/de-daniel")
        self.assertEqual(clasificar(self.sis, self.man, ENLACE, destino_enlace="/x"), m.AJENO)


class Guardar(unittest.TestCase):
    def setUp(self):
        self.sis = apoyo.SistemaFalso()
        self.addCleanup(self.sis.limpiar)

    def test_sin_manifiesto_esta_vacio(self):
        man = Manifiesto.leer(self.sis)
        self.assertFalse(man.en_disco)
        self.assertEqual((man.ficheros, man.paquetes, man.reglas, man.unidades), ({}, [], [], []))

    def test_se_guarda_0600_y_se_vuelve_a_leer_igual(self):
        man = Manifiesto()
        man.apuntar_fichero("/etc/a", b"a")
        man.apuntar_enlace("/etc/b", "/etc/a")
        man.apuntar_gestionado("/etc/c")
        man.paquetes.append("qrencode")
        man.reglas.append("ufw allow proto udp to any port 500,4500 comment hehermes")
        man.unidades.append("hehermes-xfrm.service")
        man.guardar(self.sis)
        real = self.sis.ruta(m.RUTA_MANIFIESTO)
        self.assertEqual(stat.S_IMODE(os.stat(real).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(real)).st_mode), 0o700)
        otra = Manifiesto.leer(self.sis)
        self.assertTrue(otra.en_disco)
        self.assertEqual(otra.datos, man.datos)
        self.assertEqual(json.loads(self.sis.leer(m.RUTA_MANIFIESTO))["v"], 1)

    def test_la_copia_de_lo_reemplazado_sobrevive_a_las_reescrituras(self):
        # Una versión nueva reescribe el fichero: la copia de lo que había antes de la primera vez tiene que seguir,
        # o desinstalar ya no podría devolverlo.
        man = Manifiesto()
        copia = {"tipo": "fichero", "ruta": m.CARPETA_COPIAS + "/x", "modo": 0o644}
        man.apuntar_fichero("/etc/a", b"v1", copia)
        man.apuntar_fichero("/etc/a", b"v2")
        self.assertEqual(man.ficheros["/etc/a"]["copia"], copia)
        man.apuntar_enlace("/etc/b", "/x", {"tipo": "enlace", "destino": "/de-antes"})
        man.apuntar_enlace("/etc/b", "/y")
        self.assertEqual(man.ficheros["/etc/b"]["copia"], {"tipo": "enlace", "destino": "/de-antes"})

    def test_un_manifiesto_roto_para_todo(self):
        self.sis.poner(m.RUTA_MANIFIESTO, b"{no es json")
        with self.assertRaises(m.ManifiestoRoto):
            Manifiesto.leer(self.sis)

    def test_la_copia_de_lo_que_se_reemplaza_vuelve_igual(self):
        self.sis.poner(RUTA, b"de Daniel\n", modo=0o640)
        copia = guardar_copia(self.sis, RUTA)
        self.assertTrue(copia["ruta"].startswith(m.CARPETA_COPIAS + "/"))
        self.sis.poner(RUTA, b"mio\n")
        restaurar_copia(self.sis, RUTA, copia)
        self.assertEqual(self.sis.leer(RUTA), b"de Daniel\n")
        self.assertEqual(self.sis.modo(RUTA), 0o640)
        self.assertFalse(self.sis.existe(copia["ruta"]))
        # Y la de un enlace.
        self.sis.enlazar(ENLACE, "/etc/nginx/sites-available/de-daniel")
        copia = guardar_copia(self.sis, ENLACE)
        self.sis.enlazar(ENLACE, RUTA)
        restaurar_copia(self.sis, ENLACE, copia)
        self.assertEqual(self.sis.enlace(ENLACE), "/etc/nginx/sites-available/de-daniel")


if __name__ == "__main__":
    unittest.main()
