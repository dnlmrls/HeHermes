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
from hehermes_servidor import piezas as p
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


class LoQueDejoUnaPasadaCortada(unittest.TestCase):
    """Un corte a mitad de un paso (el SIGHUP del SSH, Ctrl-C, el plazo de Hermes) deja escrito lo de ese paso sin
    apuntar en el manifiesto, que se guarda al acabar cada paso. Eso es suyo: se adopta en vez de parar con
    `ficheros-ajenos`, y repetir el comando acaba el trabajo. Lo ajeno de verdad sigue parando."""

    UNIDAD = "/etc/systemd/system/hehermes-pasarela.service"
    CODIGO = "/opt/hehermes-servidor/hehermes_servidor/pasarela.py"
    SUELTO = "/usr/local/libexec/hehermes-leer-media"

    def setUp(self):
        self.sis = apoyo.SistemaFalso()
        self.addCleanup(self.sis.limpiar)
        # Una instalación hecha: el manifiesto se guarda antes de escribir nada, así que está en disco.
        Manifiesto().guardar(self.sis)
        self.man = Manifiesto.leer(self.sis)

    def cortada(self, **ficheros):
        """La pasada que se cortó: lo que iba a escribir, apuntado antes de empezar (`m.A_MEDIAS`)."""
        self.man.datos[m.A_MEDIAS] = {"version": "0.11.0", "ficheros": {
            ruta: {"tipo": "fichero", "sha256": m.sha256(datos)} for ruta, datos in ficheros.items()}}

    def test_lo_suyo_igual_que_el_paquete_se_adopta(self):
        self.sis.poner(self.UNIDAD, b"[Unit]\n")
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, b"[Unit]\n"), m.ADOPTA)
        self.sis.enlazar(p.ORDEN, p.PREFIJO + "/hehermes-servidor")
        self.assertEqual(clasificar(self.sis, self.man, p.ORDEN, destino_enlace=p.PREFIJO + "/hehermes-servidor"),
                         m.ADOPTA)

    def test_sin_instalacion_no_se_adopta_nada(self):
        """Sin el manifiesto en disco no hubo ninguna pasada suya: lo que haya lo puso otro."""
        sin = Manifiesto()
        self.sis.poner(self.UNIDAD, p.CABECERA + "[Unit]\n")
        self.assertEqual(clasificar(self.sis, sin, self.UNIDAD, (p.CABECERA + "[Unit]\n").encode()), m.AJENO_IGUAL)
        self.assertEqual(clasificar(self.sis, sin, self.UNIDAD, b"otra\n"), m.AJENO)

    def test_fuera_de_lo_suyo_no_se_adopta(self):
        for ruta in ("/etc/systemd/system/nginx.service", "/root/.hermes/.env", "/etc/hermes/x"):
            with self.subTest(ruta=ruta):
                self.sis.poner(ruta, p.CABECERA + "x\n")
                self.assertEqual(clasificar(self.sis, self.man, ruta, (p.CABECERA + "x\n").encode()), m.AJENO_IGUAL)
                self.assertEqual(clasificar(self.sis, self.man, ruta, b"y\n"), m.AJENO)

    def test_con_su_marca_se_adopta_aunque_sea_de_otra_version(self):
        self.sis.poner(self.UNIDAD, p.CABECERA + "[Unit]\nDescription=la de antes\n")
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "[Unit]\n").encode()), m.ADOPTA)

    def test_sin_su_marca_y_distinto_sigue_siendo_ajeno(self):
        self.sis.poner(self.UNIDAD, b"[Unit]\nDescription=de otro\n")
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "[Unit]\n").encode()), m.AJENO)
        # Ni con la marca en otra línea que la primera.
        self.sis.poner(self.UNIDAD, "[Unit]\n" + p.CABECERA)
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "[Unit]\n").encode()), m.AJENO)

    def test_dentro_de_su_carpeta_es_suyo(self):
        """/opt/hehermes-servidor (y la de un usuario) solo la escribe él: lo que hay dentro es de una pasada suya."""
        for ruta in (self.CODIGO, "/home/hermes/.local/share/hehermes-servidor/hehermes-pasarela"):
            with self.subTest(ruta=ruta):
                self.sis.poner(ruta, b"# el codigo de la version de antes\n")
                self.assertEqual(clasificar(self.sis, self.man, ruta, b"# el de ahora\n"), m.ADOPTA)
        # El enlace del mismo nombre no es su carpeta.
        self.sis.poner(p.ORDEN, b"un fichero donde va el enlace\n")
        self.assertEqual(clasificar(self.sis, self.man, p.ORDEN, destino_enlace=p.PREFIJO + "/hehermes-servidor"),
                         m.AJENO)
        # Ni una carpeta o un enlace dentro de ella: solo ficheros.
        self.sis.carpeta(p.PREFIJO + "/hehermes_avisos")
        self.assertEqual(clasificar(self.sis, self.man, p.PREFIJO + "/hehermes_avisos", b"x"), m.AJENO)

    def test_lo_que_iba_a_escribir_la_pasada_cortada_se_adopta(self):
        self.cortada(**{self.SUELTO: b"#!/usr/bin/python3 -IS\n# la 0.11.0\n"})
        self.sis.poner(self.SUELTO, b"#!/usr/bin/python3 -IS\n# la 0.11.0\n")
        self.assertEqual(clasificar(self.sis, self.man, self.SUELTO, b"#!/usr/bin/python3 -IS\n# la 0.11.1\n"),
                         m.ADOPTA)
        self.sis.poner(self.SUELTO, b"#!/usr/bin/python3 -IS\n# otro\n")
        self.assertEqual(clasificar(self.sis, self.man, self.SUELTO, b"#!/usr/bin/python3 -IS\n# la 0.11.1\n"),
                         m.AJENO, "con otro contenido que el de la pasada, no es suyo")

    def test_lo_mio_que_la_pasada_cortada_ya_habia_reescrito_se_adopta(self):
        """Un corte al actualizar: el fichero ya es el nuevo y el manifiesto aún tiene el hash del de antes. No es que
        alguien lo haya tocado: era lo que iba a escribir esa pasada."""
        self.sis.poner(self.UNIDAD, p.CABECERA + "v1\n")
        self.man.apuntar_fichero(self.UNIDAD, (p.CABECERA + "v1\n").encode())
        self.sis.poner(self.UNIDAD, p.CABECERA + "v2\n")
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "v2\n").encode()), m.MODIFICADO,
                         "sin la pasada apuntada, el hash manda (como siempre)")
        self.cortada(**{self.UNIDAD: (p.CABECERA + "v2\n").encode()})
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "v2\n").encode()), m.ADOPTA)
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "v3\n").encode()), m.ADOPTA)
        self.sis.poner(self.UNIDAD, p.CABECERA + "v2\n# y una linea de Daniel\n")
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, (p.CABECERA + "v3\n").encode()), m.MODIFICADO,
                         "lo que alguien tocó después sigue parando")

    def test_una_pasada_apuntada_rara_no_adopta_nada(self):
        self.sis.poner(self.SUELTO, b"x\n")
        for rara in (None, [], {"ficheros": []}, {"ficheros": {self.SUELTO: "x"}},
                     {"ficheros": {self.SUELTO: {"tipo": "fichero"}}},
                     {"ficheros": {self.SUELTO: {"tipo": "gestionado"}}}):
            with self.subTest(rara=rara):
                self.man.datos[m.A_MEDIAS] = rara
                self.assertEqual(clasificar(self.sis, self.man, self.SUELTO, b"y\n"), m.AJENO)

    def test_reemplazar_no_hace_falta_con_lo_suyo(self):
        """Lo suyo no se «reemplaza»: la copia sería suya, y desinstalar la devolvería en lugar de quitarlo."""
        self.sis.poner(self.UNIDAD, p.CABECERA + "[Unit]\n")
        self.assertEqual(clasificar(self.sis, self.man, self.UNIDAD, b"[Unit]\n", reemplazar={self.UNIDAD}), m.ADOPTA)


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
