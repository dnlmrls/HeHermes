"""Los agentes en la pasarela (contrato §18.1): `/p/<perfil>/…` va a Hermes tal cual, con la clave de ese perfil.

Lo de la red, con la pasarela de verdad y el Hermes de mentira de `test_pasarela_red` (hace falta poder escuchar en
127.0.0.1: en el sandbox de Claude Code, fuera de él). Lo demás, sin abrir ningún puerto.
"""

import apoyo

import json
import os
import tempfile
import unittest

import test_pasarela_red as red
from hehermes_servidor import pasarela as pa

CLAVE_INVESTIGADOR = "Q2xhdmUtZGUtaW52ZXN0aWdhZG9yLWRlLXBydWViYXMx"
CLAVE_REDACTOR = "Q2xhdmUtZGVsLXJlZGFjdG9yLWRlLWxhcy1wcnVlYmFz"


def escribir(ruta, texto, modo=0o640):
    with open(ruta + ".n", "w") as f:
        f.write(texto)
    os.chmod(ruta + ".n", modo)
    os.replace(ruta + ".n", ruta)


class ConAgentes(red.ConPasarela):
    """La pasarela con `[agentes] claves`, y en la carpeta la clave de `investigador` (la de `redactor`, no)."""

    def ini_de_mas(self):
        os.mkdir(self.c("agentes"))
        escribir(self.c("agentes/investigador.clave"), CLAVE_INVESTIGADOR + "\n")
        return "[agentes]\nclaves = %s\n" % self.c("agentes")


class LaRutaDeUnAgente(ConAgentes):
    def test_va_a_hermes_tal_cual_y_con_la_clave_de_su_perfil(self):
        ruta = "/p/investigador/api/sessions?source=api_server&limit=200"
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion(ruta=ruta))
        self.assertEqual(estado, 200)
        vista = self.hermes.peticiones[-1]
        self.assertEqual(vista["ruta"], ruta, "con el prefijo y la consulta")
        self.assertEqual([v for k, v in vista["lista"] if k.lower() == "authorization"],
                         ["Bearer " + CLAVE_INVESTIGADOR], "la suya, una vez, y nunca la del principal")
        self.assertNotIn(red.CLAVE_HERMES, json.dumps(vista["lista"]))
        self.assertNotIn(red.TOKEN, json.dumps(vista["lista"]))

    def test_el_principal_sigue_con_la_suya(self):
        self.leer_respuesta(self.peticion(ruta="/api/sessions"))
        self.assertEqual(self.hermes.peticiones[-1]["cabeceras"]["Authorization"], "Bearer " + red.CLAVE_HERMES)

    def test_un_turno_y_su_sse(self):
        cuerpo = b'{"input": "hola"}'
        estado, _, _, _ = self.leer_respuesta(self.peticion("POST", "/p/investigador/v1/runs", cuerpo=cuerpo))
        self.assertEqual(estado, 200)
        self.assertEqual(self.hermes.peticiones[-1]["cuerpo"], cuerpo)
        self.assertEqual(self.hermes.peticiones[-1]["cabeceras"]["Authorization"], "Bearer " + CLAVE_INVESTIGADOR)

    def test_un_perfil_sin_clave_no_llega_a_hermes(self):
        for ruta in ("/p/redactor/api/sessions", "/p/default/api/sessions", "/p/investigador2/v1/runs"):
            with self.subTest(ruta=ruta):
                estado, cabeceras, cuerpo, _ = self.leer_respuesta(self.peticion(ruta=ruta))
                self.assertEqual(estado, 404)
                self.assertEqual(json.loads(cuerpo)["error"]["code"], "agente_desconocido")
                self.assertEqual(json.loads(cuerpo)["error"]["type"], "pasarela")
                self.assertEqual(cabeceras["connection"], "close")
        self.assertEqual(self.hermes.peticiones, [])

    def test_un_perfil_con_otra_forma_tampoco(self):
        for ruta in ("/p/Investigador/api/sessions", "/p/a.b/api/sessions", "/p/", "/p", "/p//api/sessions",
                     "/p/" + "a" * 25 + "/api/sessions", "/p/inv-estigador/api", "/p/%69nvestigador/api",
                     "/p?x=1", "/p/ñandu/api"):
            with self.subTest(ruta=ruta):
                tls = self.peticion(ruta=ruta)
                if not pa._RUTA.fullmatch(ruta):
                    # Lo que no es una ruta que la pasarela acepte es el 404 idéntico, como siempre.
                    self.assertEqual(self.todo(tls), red.NO_404)
                    continue
                estado, _, cuerpo, _ = self.leer_respuesta(tls)
                self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (404, "agente_desconocido"))
        self.assertEqual(self.hermes.peticiones, [])

    def test_sin_token_el_404_de_siempre(self):
        self.assertEqual(self.todo(self.peticion(ruta="/p/investigador/api/sessions", token=None)), red.NO_404)
        self.assertEqual(self.todo(self.peticion(ruta="/p/investigador/api/sessions", token=red.TOKEN[:-1] + "A")),
                         red.NO_404)
        self.assertEqual(self.hermes.peticiones, [])

    def test_una_clave_que_cambia_en_disco_se_relee(self):
        self.leer_respuesta(self.peticion(ruta="/p/investigador/api/sessions"))
        escribir(self.c("agentes/investigador.clave"), CLAVE_REDACTOR + "\n")
        self.leer_respuesta(self.peticion(ruta="/p/investigador/api/sessions"))
        self.assertEqual(self.hermes.peticiones[-1]["cabeceras"]["Authorization"], "Bearer " + CLAVE_REDACTOR)
        # Y la de uno nuevo vale en cuanto está, sin reiniciar.
        escribir(self.c("agentes/redactor.clave"), CLAVE_INVESTIGADOR + "\n")
        estado, _, _, _ = self.leer_respuesta(self.peticion(ruta="/p/redactor/api/sessions"))
        self.assertEqual(estado, 200)
        # Y la de uno borrado deja de valer.
        os.unlink(self.c("agentes/investigador.clave"))
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion(ruta="/p/investigador/api/sessions"))
        self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (404, "agente_desconocido"))

    def test_el_cuerpo_maximo_es_el_del_principal(self):
        tls = self.conectar()
        tls.sendall(("POST /p/investigador/v1/runs HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n"
                     % (red.TOKEN, pa.MAX_CUERPO + 1)).encode())
        estado, _, cuerpo, _ = self.leer_respuesta(tls)
        self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (413, "cuerpo_demasiado_grande"))
        cuerpo = os.urandom(300 * 1024)
        estado, _, _, _ = self.leer_respuesta(self.peticion("POST", "/p/investigador/v1/runs", cuerpo=cuerpo))
        self.assertEqual(estado, 200, "lo que cabe al principal cabe a un agente: no es el tope de /avisos/")
        tls = self.peticion("POST", "/p/investigador/v1/runs", extra="Transfer-Encoding: chunked\r\n")
        self.assertEqual(self.leer_respuesta(tls)[0], 400)
        self.assertEqual(len(self.hermes.peticiones), 1)

    def test_hermes_parado_es_un_502_como_el_del_principal(self):
        self.hermes.shutdown()
        self.hermes.server_close()
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion(ruta="/p/investigador/api/sessions"))
        self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (502, "hermes_no_contesta"))

    def test_el_registro_no_lleva_ni_la_ruta_ni_la_clave(self):
        self.leer_respuesta(self.peticion(ruta="/p/investigador/api/sessions?q=secreta"))
        self.leer_respuesta(self.peticion(ruta="/p/redactor/api/sessions"))
        diario = "\n".join(self.diario)
        for nunca in (CLAVE_INVESTIGADOR, "investigador", "redactor", "secreta", red.TOKEN):
            self.assertNotIn(nunca, diario)


class SinAgentes(red.ConPasarela):
    """Una pasarela.ini sin `[agentes]` (la de antes de la 0.11.0): `/p/…` no se reenvía."""

    def test_p_es_un_404_y_no_llega_a_hermes(self):
        estado, _, cuerpo, _ = self.leer_respuesta(self.peticion(ruta="/p/investigador/api/sessions"))
        self.assertEqual((estado, json.loads(cuerpo)["error"]["code"]), (404, "agente_desconocido"))
        self.assertEqual(self.hermes.peticiones, [])
        # Lo de siempre, igual.
        self.assertEqual(self.leer_respuesta(self.peticion(ruta="/api/sessions"))[0], 200)


class LasClaves(unittest.TestCase):
    """`ClavesDeAgentes`, sin red: un fichero por perfil, que se vuelve a leer si cambia."""

    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.c = lambda n: os.path.join(self.carpeta.name, n)  # noqa: E731
        self.claves = pa.ClavesDeAgentes(self.carpeta.name)

    def tearDown(self):
        self.carpeta.cleanup()

    def test_la_de_cada_perfil(self):
        escribir(self.c("investigador.clave"), CLAVE_INVESTIGADOR + "\n")
        escribir(self.c("redactor.clave"), CLAVE_REDACTOR)
        self.assertEqual(self.claves.clave("investigador"), CLAVE_INVESTIGADOR)
        self.assertEqual(self.claves.clave("redactor"), CLAVE_REDACTOR)
        self.assertIsNone(self.claves.clave("otro"))

    def test_solo_nombres_de_perfil(self):
        """El nombre va a una ruta: nada que no sea `[a-z0-9]{1,24}` llega al disco, ni `default`."""
        escribir(self.c("default.clave"), CLAVE_INVESTIGADOR)
        os.mkdir(self.c("sub"))
        escribir(self.c("sub/x.clave"), CLAVE_INVESTIGADOR)
        for malo in ("default", "../investigador", "sub/x", "Investigador", "", "a" * 25, "a.b", None, 7):
            with self.subTest(malo=malo):
                self.assertIsNone(self.claves.clave(malo))

    def test_lo_que_no_es_una_clave_no_vale(self):
        for texto in ("", "\n", "con espacio", 'con"comillas', "ñ" * 10, "a\nb", "a\x00b", "x" * 513):
            with self.subTest(texto=texto):
                escribir(self.c("investigador.clave"), texto)
                self.assertIsNone(self.claves.clave("investigador"))

    def test_no_sigue_un_enlace(self):
        """Un enlace en la carpeta no lleva a otro fichero que la pasarela pueda leer (tokens.json, por ejemplo)."""
        escribir(self.c("de-verdad"), CLAVE_INVESTIGADOR)
        os.symlink(self.c("de-verdad"), self.c("investigador.clave"))
        self.assertIsNone(self.claves.clave("investigador"))
        os.mkdir(self.c("redactor.clave"))
        self.assertIsNone(self.claves.clave("redactor"))

    def test_se_relee_y_lo_que_falta_no_se_recuerda(self):
        escribir(self.c("investigador.clave"), CLAVE_INVESTIGADOR)
        self.assertEqual(self.claves.clave("investigador"), CLAVE_INVESTIGADOR)
        escribir(self.c("investigador.clave"), CLAVE_REDACTOR + "\n")
        self.assertEqual(self.claves.clave("investigador"), CLAVE_REDACTOR)
        os.unlink(self.c("investigador.clave"))
        self.assertIsNone(self.claves.clave("investigador"))
        for n in range(500):
            self.claves.clave("p%d" % n)
        self.assertLessEqual(len(self.claves._vistas), 1, "los perfiles que no existen no se quedan en memoria")

    def test_sin_carpeta_nada(self):
        self.assertIsNone(pa.ClavesDeAgentes(self.c("no-existe")).clave("investigador"))


class ElDestino(unittest.TestCase):
    """`destino` mira la forma de la ruta por su cuenta, aunque las claves también miren la del nombre: con unas claves
    que lo dieran todo por bueno, una ruta rara seguiría sin llegar a Hermes."""

    class Permisivas:
        def __init__(self):
            self.pedidas = []

        def clave(self, perfil):
            self.pedidas.append(perfil)
            return "clave-de-" + str(perfil)

    def destino(self, ruta, con_claves=True):
        from types import SimpleNamespace
        claves = self.Permisivas()
        falsa = SimpleNamespace(config=SimpleNamespace(vigia=None, puerto_hermes=8642),
                                claves_agentes=claves if con_claves else None,
                                clave_hermes=SimpleNamespace(valor=lambda: "la-del-principal"), diario=lambda t: None)
        peticion = pa.Peticion("GET", ruta, "HTTP/1.1", [])
        return pa.Pasarela.destino(falsa, peticion, "127.0.0.1"), claves.pedidas

    def test_solo_un_perfil_con_su_forma_llega_a_las_claves(self):
        (destino, poner, _), pedidas = self.destino("/p/investigador/api/sessions?x=1")
        self.assertEqual((destino, poner), (("127.0.0.1", 8642), [("Authorization", "Bearer clave-de-investigador")]))
        self.assertEqual(pedidas, ["investigador"])
        for ruta in ("/p/Inv/x", "/p/a.b/x", "/p/", "/p", "/p//x", "/p/" + "a" * 25 + "/x", "/p/a-b", "/p/a%62/x",
                     "/p/a.b?x=1"):
            with self.subTest(ruta=ruta):
                with self.assertRaises(pa._Error) as error:
                    self.destino(ruta)
                self.assertEqual((error.exception.estado, error.exception.codigo), (404, "agente_desconocido"))

    def test_sin_agentes_no_se_pregunta_a_nadie(self):
        with self.assertRaises(pa._Error):
            self.destino("/p/investigador/api/sessions", con_claves=False)

    def test_lo_que_no_es_de_un_agente_va_al_principal(self):
        for ruta in ("/api/sessions", "/pp/x", "/p-x", "/v1/runs"):
            (_, poner, _), pedidas = self.destino(ruta)
            self.assertEqual((poner, pedidas), ([("Authorization", "Bearer la-del-principal")], []), ruta)


class LaConfiguracion(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.carpeta.cleanup()

    def ini(self, mas):
        ruta = os.path.join(self.carpeta.name, "pasarela.ini")
        with open(ruta, "w") as f:
            f.write("[pasarela]\npuerto = 61234\ncertificado = /c/cert.pem\nclave = /c/clave.pem\ntokens = /c/t.json\n"
                    "[hermes]\npuerto = 8642\nclave = /e\n" + mas)
        return ruta

    def test_lee_la_carpeta_de_las_claves(self):
        c = pa.Configuracion.leer(self.ini("[agentes]\nclaves = /etc/hehermes-pasarela/agentes\n"))
        self.assertEqual(c.claves_agentes, "/etc/hehermes-pasarela/agentes")
        self.assertIsNone(pa.Configuracion.leer(self.ini("")).claves_agentes)
        self.assertIsNone(pa.Configuracion.leer(self.ini("[agentes]\nclaves =\n")).claves_agentes)

    def test_la_escribe_el_instalador(self):
        """`piezas.pasarela_ini` lleva la carpeta de las claves (la de la pasarela, con root y sin él), y la pasarela la
        lee tal cual."""
        from hehermes_servidor import ambito
        from hehermes_servidor import piezas as p
        for a, carpeta in ((ambito.de_root(), "/etc/hehermes-pasarela/agentes"),
                           (ambito.de_usuario("hermes", "/home/hermes", 1000),
                            "/home/hermes/.config/hehermes-pasarela/agentes")):
            with self.subTest(root=a.root):
                self.assertEqual(a.claves_agentes_pasarela, carpeta)
                texto = p.pasarela_ini(a, 61234, 8642, "/home/hermes/.hermes/.env", "203.0.113.5", vigia=True)
                self.assertIn("\n[agentes]\n", texto)
                ruta = os.path.join(self.carpeta.name, "pasarela.ini")
                with open(ruta, "w") as f:
                    f.write(texto)
                self.assertEqual(pa.Configuracion.leer(ruta).claves_agentes, carpeta)

    def test_una_carpeta_relativa_no_vale(self):
        with self.assertRaises(ValueError):
            pa.Configuracion.leer(self.ini("[agentes]\nclaves = agentes\n"))

    def test_el_prefijo(self):
        self.assertEqual(pa.PREFIJO_AGENTE.fullmatch("/p/investigador/api/sessions").group(1), "investigador")
        self.assertEqual(pa.PREFIJO_AGENTE.fullmatch("/p/nandu2").group(1), "nandu2")
        for malo in ("/p/", "/p/A/x", "/p/a_b/x", "/p/" + "a" * 25, "/pp/a/x", "/x/p/a/x"):
            self.assertIsNone(pa.PREFIJO_AGENTE.fullmatch(malo), malo)


if __name__ == "__main__":
    unittest.main()
