"""El código de recuperación (spec 2026-10-06): el código, la clave y la firma (con el vector que comparte la app), el
registro del servidor, y `instalar --por-chat --recuperacion` sobre el servidor falso.

La firma se comprueba de verdad: el venv del canje del servidor falso lanza `recuperacion.main` con el `cryptography` de
las pruebas. Las rutas de la pasarela, con su red, están en `test_recuperacion_pasarela.py`.
"""

import apoyo

import base64
import json
import os
import stat
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import servidor_falso as sf
import test_modo_tls
import test_porchat
from hehermes_servidor import pasarela as pa
from hehermes_servidor import recuperacion as rec
from hehermes_servidor import tokens
from hehermes_servidor.manifiesto import Manifiesto

VECTOR = json.loads((apoyo.DATOS / "recuperacion.json").read_text(encoding="utf-8"))
ESTADO_PASARELA = "/var/lib/hehermes-pasarela"
TOKENS = test_porchat.TOKENS
LLAVE = test_porchat.LLAVE
OTRA_LLAVE = base64.urlsafe_b64encode(bytes(range(100, 132))).rstrip(b"=").decode()
#: Un código de prueba que no es el del vector: el de «otro servidor».
OTRO_CODIGO = "Q" * 26 + rec.control("Q" * 26)


def clave_de(codigo):
    privada = Ed25519PrivateKey.from_private_bytes(rec.semilla(codigo))
    return rec.b64url(privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def prueba(codigo, iphone, llave=LLAVE, momento=None):
    """Lo que pone la app en `--recuperacion`: la firma de este iPhone, esta llave y esta hora."""
    momento = int(time.time()) if momento is None else int(momento)
    crudo = base64.urlsafe_b64decode(llave + "=")
    firma = Ed25519PrivateKey.from_private_bytes(rec.semilla(codigo)).sign(rec.mensaje(iphone, crudo, momento))
    return "1.%d.%s" % (momento, rec.b64url(firma))


class ElCodigo(unittest.TestCase):
    def test_el_control_cuadra_y_un_simbolo_cambiado_no(self):
        self.assertEqual(rec.normalizar(VECTOR["codigo"]), VECTOR["canonico"])
        cambiado = "Q" + VECTOR["canonico"][1:]
        self.assertIsNone(rec.normalizar(cambiado))
        # Dos símbolos cambiados de sitio, también.
        canonico = VECTOR["canonico"]
        self.assertIsNone(rec.normalizar(canonico[1] + canonico[0] + canonico[2:]))

    def test_se_escribe_como_sea(self):
        escrito = " " + VECTOR["codigo"].lower().replace("0", "o").replace("-", " ") + "\n"
        self.assertEqual(rec.normalizar(escrito), VECTOR["canonico"])
        self.assertEqual(rec.normalizar(VECTOR["canonico"].replace("0", "O")), VECTOR["canonico"])

    def test_lo_que_no_es_un_codigo(self):
        for texto in ("", VECTOR["canonico"][:-1], VECTOR["canonico"] + "0", "U" * 28, None, 28):
            with self.subTest(texto=texto):
                self.assertIsNone(rec.normalizar(texto))

    def test_uno_nuevo_vale_y_no_se_repite(self):
        nuevos = {rec.codigo_nuevo() for _ in range(50)}
        self.assertEqual(len(nuevos), 50)
        for codigo in nuevos:
            self.assertEqual(rec.normalizar(codigo), codigo)


class ElVector(unittest.TestCase):
    """El vector que comparte la app (`Fixtures/recuperacion.json`): la semilla, la clave y la firma salen igual."""

    def test_la_semilla_y_la_clave(self):
        self.assertEqual(rec.semilla(VECTOR["canonico"]).hex(), VECTOR["semilla"])
        self.assertEqual(clave_de(VECTOR["canonico"]), VECTOR["clave"])

    def test_el_mensaje_y_la_firma(self):
        llave = rec.de_b64url(VECTOR["llave"], 32)
        datos = rec.mensaje(VECTOR["iphone"], llave, VECTOR["momento"])
        self.assertEqual(base64.b64encode(datos).decode(), VECTOR["mensaje"])
        firma = rec.de_b64url(VECTOR["firma"], 64)
        self.assertTrue(rec.verificar_firma(VECTOR["clave"], datos, firma))
        self.assertEqual(prueba(VECTOR["canonico"], VECTOR["iphone"], VECTOR["llave"], VECTOR["momento"]),
                         VECTOR["prueba"])
        self.assertEqual(rec.leer_prueba(VECTOR["prueba"]), (VECTOR["momento"], firma))

    def test_la_firma_no_vale_para_otra_llave_otro_nombre_otra_hora_ni_otra_clave(self):
        llave = rec.de_b64url(VECTOR["llave"], 32)
        firma = rec.de_b64url(VECTOR["firma"], 64)
        for datos in (rec.mensaje(VECTOR["iphone"], bytes(32), VECTOR["momento"]),
                      rec.mensaje("iphone-0abd", llave, VECTOR["momento"]),
                      rec.mensaje(VECTOR["iphone"], llave, VECTOR["momento"] + 1)):
            self.assertFalse(rec.verificar_firma(VECTOR["clave"], datos, firma))
        datos = rec.mensaje(VECTOR["iphone"], llave, VECTOR["momento"])
        self.assertFalse(rec.verificar_firma(clave_de(OTRO_CODIGO), datos, firma))
        self.assertFalse(rec.verificar_firma("no-es-una-clave", datos, firma))

    def test_la_prueba_tiene_una_sola_forma(self):
        firma = VECTOR["prueba"].rsplit(".", 1)[1]
        for texto in ("2.1791234567." + firma, "1.." + firma, "1.1791234567." + firma[:-1],
                      "1.1791234567." + firma + "=", " " + VECTOR["prueba"], VECTOR["prueba"] + "\n", None):
            with self.subTest(texto=texto):
                self.assertIsNone(rec.leer_prueba(texto))

    def test_el_mensaje_no_se_puede_leer_de_dos_formas(self):
        with self.assertRaises(ValueError):
            rec.mensaje("iphone\x00x", bytes(32), 1)
        with self.assertRaises(ValueError):
            rec.mensaje("iphone-0abc", bytes(31), 1)


class ElEstado(unittest.TestCase):
    AHORA = 1_800_000_000

    def con_clave(self):
        return rec.con_clave(rec.vacio(), VECTOR["clave"], "iphone-1a2b", self.AHORA - 3600)

    def test_lo_que_no_se_entiende_no_es_vacio(self):
        self.assertEqual(rec.leer_estado(None), rec.vacio())
        for datos in (b"{", b"[]", b'{"v": 2}', b'{"v": 1, "clave": "corta"}', "ñ".encode("latin-1")):
            with self.subTest(datos=datos):
                self.assertIsNone(rec.leer_estado(datos))

    def test_se_lee_lo_que_se_escribe_y_lo_raro_se_queda_fuera(self):
        estado = rec.con_exito(self.con_clave(), "iphone-9f3e", self.AHORA)
        self.assertEqual(rec.leer_estado(json.dumps(estado).encode()), estado)
        raro = dict(estado, por="Daniel's iPhone", fallos=-3, en_curso={"iphone": "x y", "desde": 1})
        leido = rec.leer_estado(json.dumps(raro).encode())
        self.assertEqual((leido["por"], leido["fallos"], leido["en_curso"]), (None, 0, None))

    def test_las_esperas_tras_cada_fallo_y_sin_cierre(self):
        """1, 2, 4 y 8 minutos, y a partir del quinto, 8 siempre: ni un día cerrado ni nada que deje de esperar."""
        estado = self.con_clave()
        self.assertIsNone(rec.espera_hasta(estado, self.AHORA))
        esperas, ahora = [], self.AHORA
        for vez in range(1, 9):
            estado = rec.con_fallo(estado, ahora)
            self.assertEqual(estado["fallos"], vez)
            esperas.append(rec.espera_hasta(estado, ahora) - ahora)
            # El siguiente, pasada la espera de este: es lo que puede hacer quien insiste.
            ahora += esperas[-1]
        self.assertEqual(esperas, [60, 120, 240, 480, 480, 480, 480, 480])
        self.assertIsNotNone(rec.espera_hasta(estado, ahora - 1))
        self.assertIsNone(rec.espera_hasta(estado, ahora))

    def test_pasada_la_espera_se_puede_probar(self):
        estado = rec.con_fallo(self.con_clave(), self.AHORA)
        self.assertIsNotNone(rec.espera_hasta(estado, self.AHORA + 59))
        self.assertIsNone(rec.espera_hasta(estado, self.AHORA + 60))

    def test_la_racha_empieza_sin_fallos_vigentes(self):
        estado = self.con_clave()
        self.assertTrue(rec.empieza_racha(estado, self.AHORA))
        estado = rec.con_fallo(estado, self.AHORA)
        self.assertFalse(rec.empieza_racha(estado, self.AHORA + 3600))
        # Un día sin fallos, u otra recuperación que entra, y la siguiente es otra racha.
        self.assertTrue(rec.empieza_racha(estado, self.AHORA + 24 * 3600))
        self.assertTrue(rec.empieza_racha(rec.con_exito(estado, "iphone-9f3e", self.AHORA + 60), self.AHORA + 120))

    def test_un_fallo_de_hace_mas_de_un_dia_ya_no_cuenta(self):
        estado = self.con_clave()
        for _ in range(4):
            estado = rec.con_fallo(estado, self.AHORA)
        estado = rec.con_fallo(estado, self.AHORA + 24 * 3600)
        self.assertEqual(estado["fallos"], 1)

    def test_entrar_olvida_los_fallos_y_apunta_quien_y_cuando(self):
        estado = rec.con_fallo(self.con_clave(), self.AHORA)
        estado = rec.con_exito(estado, "iphone-9f3e", self.AHORA + 600)
        self.assertEqual((estado["fallos"], estado["ultimo_fallo"]), (0, None))
        self.assertEqual(estado["en_curso"], {"iphone": "iphone-9f3e", "desde": self.AHORA + 600})
        self.assertEqual(estado["ultima"], {"iphone": "iphone-9f3e", "cuando": self.AHORA + 600})
        self.assertEqual(estado["clave"], VECTOR["clave"])

    def test_quien_puede_poner_un_codigo(self):
        self.assertTrue(rec.puede_poner(rec.vacio(), "iphone-1a2b"))
        self.assertFalse(rec.puede_poner(rec.vacio(), None))
        estado = self.con_clave()
        for nombre in ("iphone-1a2b", "iphone-9f3e"):
            self.assertFalse(rec.puede_poner(estado, nombre), nombre)
        estado = rec.con_exito(estado, "iphone-9f3e", self.AHORA)
        self.assertTrue(rec.puede_poner(estado, "iphone-9f3e"))
        self.assertFalse(rec.puede_poner(estado, "iphone-1a2b"))
        estado = rec.con_clave(estado, clave_de(OTRO_CODIGO), "iphone-9f3e", self.AHORA + 60)
        self.assertIsNone(estado["en_curso"])
        self.assertFalse(rec.puede_poner(estado, "iphone-9f3e"))

    def test_gastado_en_cuanto_el_de_la_recuperacion_usa_la_pasarela(self):
        estado = rec.con_exito(self.con_clave(), "iphone-9f3e", self.AHORA)
        usos = {"tokens": {"a" * 64: {"nombre": "iphone-9f3e", "primero": self.AHORA - 1},
                           "b" * 64: {"nombre": "iphone-1a2b", "primero": self.AHORA + 60}}}
        self.assertFalse(rec.gastado(estado, usos))
        usos["tokens"]["c" * 64] = {"nombre": "iphone-9f3e", "primero": self.AHORA}
        self.assertTrue(rec.gastado(estado, usos))
        self.assertFalse(rec.gastado(self.con_clave(), usos))
        self.assertFalse(rec.gastado(estado, None))

    def test_la_hora(self):
        self.assertTrue(rec.a_tiempo(self.AHORA - 40 * 60, self.AHORA))
        self.assertFalse(rec.a_tiempo(self.AHORA - 40 * 60 - 1, self.AHORA))
        self.assertTrue(rec.a_tiempo(self.AHORA + 10 * 60, self.AHORA))
        self.assertFalse(rec.a_tiempo(self.AHORA + 10 * 60 + 1, self.AHORA))

    def test_lo_publico_no_lleva_nada_secreto(self):
        estado = rec.con_fallo(rec.con_exito(self.con_clave(), "iphone-9f3e", self.AHORA), self.AHORA)
        publico = rec.publico(estado, "iphone-9f3e", ahora=self.AHORA)
        self.assertEqual(set(publico), {"clave", "creada", "por", "en_curso", "ultima", "fallos", "yo"})
        self.assertEqual((publico["fallos"], publico["yo"]), (1, "iphone-9f3e"))
        self.assertEqual(rec.publico(None, "iphone-9f3e"), {"ilegible": True, "yo": "iphone-9f3e"})


class ElRegistro(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.carpeta = tempfile.TemporaryDirectory()
        self.registro = rec.Registro(self.carpeta.name)

    def tearDown(self):
        self.carpeta.cleanup()

    def test_sin_fichero_esta_vacio_y_se_escribe_0600(self):
        self.assertEqual(self.registro.leer(), rec.vacio())
        hecho = self.registro.cambiar(lambda e: rec.con_clave(e, VECTOR["clave"], "iphone-1a2b", 1))
        self.assertEqual(self.registro.leer(), hecho)
        self.assertEqual(stat.S_IMODE(os.stat(self.registro.ruta).st_mode), 0o600)
        self.assertEqual([n for n in os.listdir(self.carpeta.name) if n != rec.ESTADO], [])

    def test_sin_cambio_no_escribe(self):
        self.assertEqual(self.registro.cambiar(lambda e: None), rec.vacio())
        self.assertFalse(os.path.exists(self.registro.ruta))

    def test_no_sigue_un_enlace(self):
        otro = os.path.join(self.carpeta.name, "otro.json")
        with open(otro, "w") as f:
            json.dump(rec.con_clave(rec.vacio(), VECTOR["clave"], "iphone-1a2b", 1), f)
        os.symlink(otro, self.registro.ruta)
        self.assertIsNone(self.registro.leer())

    def test_quitar(self):
        self.registro.cambiar(lambda e: rec.con_clave(e, VECTOR["clave"], "iphone-1a2b", 1))
        self.assertTrue(self.registro.quitar())
        self.assertEqual(self.registro.leer(), rec.vacio())
        self.assertFalse(self.registro.quitar())

    def test_el_buzon_del_vigia(self):
        """Un fichero por suceso, entero (escrito al lado y renombrado), 0600 y sin nada más en la carpeta."""
        buzon = os.path.join(self.carpeta.name, rec.BUZON)
        self.assertFalse(rec.dejar_en_el_buzon(buzon, rec.suceso("intentos", 1_800_000_000)), "sin buzón, nada")
        os.mkdir(buzon, 0o700)
        self.assertTrue(rec.dejar_en_el_buzon(buzon, rec.suceso("entrada", 1_800_000_000, "iphone-9f3e",
                                                                "0123456789abcdef", "fedcba9876543210")))
        (nombre,) = os.listdir(buzon)
        self.assertRegex(nombre, r"^recuperacion-1800000000-[0-9a-f]{8}\.json$")
        ruta = os.path.join(buzon, nombre)
        self.assertEqual(stat.S_IMODE(os.stat(ruta).st_mode), 0o600)
        with open(ruta) as f:
            self.assertEqual(json.load(f), {"v": 1, "tipo": "recuperacion", "que": "entrada", "iphone": "iphone-9f3e",
                                            "marca": "0123456789abcdef", "marca_anterior": "fedcba9876543210",
                                            "cuando": 1_800_000_000})

    def test_el_buzon_no_sigue_un_enlace_ni_se_llena(self):
        fuera = os.path.join(self.carpeta.name, "fuera")
        os.mkdir(fuera)
        os.symlink(fuera, os.path.join(self.carpeta.name, rec.BUZON))
        self.assertFalse(rec.dejar_en_el_buzon(os.path.join(self.carpeta.name, rec.BUZON),
                                               rec.suceso("intentos", 1)))
        self.assertEqual(os.listdir(fuera), [])
        for vez in range(rec.TOPE_BUZON):
            self.assertTrue(rec.dejar_en_el_buzon(fuera, rec.suceso("intentos", vez)))
        self.assertFalse(rec.dejar_en_el_buzon(fuera, rec.suceso("intentos", 99)))
        self.assertEqual(len(os.listdir(fuera)), rec.TOPE_BUZON)

    def test_un_suceso_que_no_es_de_la_recuperacion(self):
        marca, otra = "0123456789abcdef", "fedcba9876543210"
        for que, iphone, m, anterior in (("otro", None, None, None), ("entrada", None, marca, None),
                                         ("intentos", "iphone-9f3e", None, None), ("entrada", "Mi iPhone", marca, None),
                                         ("entrada", "iphone-9f3e", None, None), ("entrada", "iphone-9f3e", "x", None),
                                         ("entrada", "iphone-9f3e", marca, marca), ("intentos", None, marca, None),
                                         ("intentos", None, None, otra), ("entrada", "iphone-9f3e", marca, "A" * 16)):
            with self.subTest(que=que, iphone=iphone, marca=m, anterior=anterior), self.assertRaises(ValueError):
                rec.suceso(que, 1, iphone, m, anterior)

    def test_la_orden_verificar(self):
        dicho = []
        entrada = json.dumps({"clave": VECTOR["clave"], "mensaje": VECTOR["mensaje"],
                              "firma": base64.b64encode(rec.de_b64url(VECTOR["firma"], 64)).decode()})
        self.assertEqual(rec.main(["verificar"], entrada=entrada, salida=dicho.append), 0)
        mala = json.loads(entrada)
        mala["clave"] = clave_de(OTRO_CODIGO)
        self.assertEqual(rec.main(["verificar"], entrada=json.dumps(mala), salida=dicho.append), 1)
        self.assertEqual(rec.main(["verificar"], entrada="{", salida=dicho.append), 2)
        self.assertEqual(dicho, ["buena", "mala", "no entiendo lo que me das"])


class PorChat(test_porchat.Base):
    """`instalar --por-chat --recuperacion`: con el chat cerrado por la decisión 7, entra el iPhone de la frase si la
    firma es del código del servidor, y solo él."""

    CODIGO = VECTOR["canonico"]

    def setUp(self):
        super().setUp()
        # El primer iPhone, por chat, que ya ha usado la pasarela: el chat está cerrado.
        self.por_chat_de(3600)
        self.falso.usar("mi-iphone")
        self.poner_codigo(self.CODIGO, por="mi-iphone")
        self.token_viejo = tokens.rotar(self.sis.ruta(TOKENS), "mi-iphone")

    def registro(self):
        carpeta = self.sis.ruta(ESTADO_PASARELA)
        os.makedirs(carpeta, exist_ok=True)
        return rec.Registro(carpeta)

    def poner_codigo(self, codigo, por="mi-iphone"):
        self.registro().cambiar(lambda e: rec.con_clave(e, clave_de(codigo), por, time.time() - 600))

    def estado(self):
        return self.registro().leer()

    def recuperar(self, iphone="iphone-9f3e", codigo=None, llave=LLAVE, momento=None, extra=()):
        return self.por_chat("--recuperacion", prueba(codigo or self.CODIGO, iphone, llave, momento), *extra,
                             iphone=iphone, llave=llave)

    def quien(self, token):
        return pa.Tokens(self.sis.ruta(TOKENS)).quien(token)

    def error(self):
        """El código y el detalle de las dos últimas líneas, las de la app."""
        self.assertTrue(self.texto[-1].endswith("hehermes-error:recuperacion"), self.salida)
        return self.texto[-1].split("\n")[-2]

    # Lo que entra

    def test_otro_nombre_entra_y_los_demas_se_quedan(self):
        self.assertEqual(self.recuperar(), 0, self.salida)
        self.assertRegex(self.texto[-1], test_porchat.ElCanje.ENLACE)
        token = self.carga()["t"]
        self.assertEqual(self.quien(token), "iphone-9f3e")
        # Los demás no se tocan: el de chat sigue con su token.
        self.assertEqual(self.quien(self.token_viejo), "mi-iphone")
        self.assertIn("«iphone-9f3e» entra con el código de recuperación", self.salida)
        estado = self.estado()
        self.assertEqual(estado["en_curso"]["iphone"], "iphone-9f3e")
        self.assertEqual(estado["ultima"]["iphone"], "iphone-9f3e")
        self.assertEqual(estado["clave"], clave_de(self.CODIGO))
        self.assertEqual(len(self.falso.verificaciones), 1)

    def test_el_codigo_no_llega_nunca_al_servidor(self):
        """Ni el código ni su semilla: el servidor solo ve la pública (en su registro) y la firma (en la frase)."""
        self.assertEqual(self.recuperar(), 0, self.salida)
        secretos = (self.CODIGO, VECTOR["codigo"], rec.semilla(self.CODIGO).hex(),
                    rec.b64url(rec.semilla(self.CODIGO)))
        vistos = [self.salida, json.dumps(self.sis.ordenes), json.dumps(self.falso.verificaciones),
                  self.sis.leer_texto(ESTADO_PASARELA + "/" + rec.ESTADO)]
        for carpeta, _, nombres in os.walk(self.sis.ruta("/")):
            for nombre in nombres:
                ruta = os.path.join(carpeta, nombre)
                if os.path.isfile(ruta) and not os.path.islink(ruta):
                    with open(ruta, "rb") as f:
                        vistos.append(f.read().decode("latin-1"))
        for secreto in secretos:
            self.assertFalse([v for v in vistos if secreto in v], "el código o su semilla en el servidor")
        self.assertEqual(json.loads(self.falso.verificaciones[0])["clave"], clave_de(self.CODIGO))

    def test_el_mismo_nombre_cambia_de_token_y_el_de_antes_deja_de_valer(self):
        self.assertEqual(self.recuperar(iphone="mi-iphone"), 0, self.salida)
        token = self.carga()["t"]
        self.assertEqual(self.quien(token), "mi-iphone")
        self.assertIsNone(self.quien(self.token_viejo))
        self.assertIn("le doy una clave nueva, y la de antes deja de valer", self.salida)

    def test_la_recuperacion_no_vuelve_a_abrir_el_chat(self):
        """El `por_chat` del manifiesto no cambia: una frase sin código sigue parada, también para el que entró."""
        antes = Manifiesto.leer(self.sis).datos["por_chat"]
        self.assertEqual(self.recuperar(), 0, self.salida)
        self.assertEqual(Manifiesto.leer(self.sis).datos["por_chat"], antes)
        self.falso.activos.discard("hehermes-canje")
        for iphone in ("iphone-9f3e", "iphone-7777"):
            with self.subTest(iphone=iphone):
                self.assertEqual(self.por_chat(iphone=iphone), 1)
                self.assertTrue(self.texto[-1].endswith("hehermes-error:por-chat"), self.salida)

    def test_la_misma_frase_otra_vez_da_otro_token_mientras_no_la_use(self):
        frase = prueba(self.CODIGO, "iphone-9f3e")
        self.assertEqual(self.por_chat("--recuperacion", frase, iphone="iphone-9f3e"), 0, self.salida)
        primero = self.carga()["t"]
        self.falso.activos.discard("hehermes-canje")
        self.assertEqual(self.por_chat("--recuperacion", frase, iphone="iphone-9f3e"), 0, self.salida)
        self.assertIsNone(self.quien(primero))
        self.assertEqual(self.quien(self.carga()["t"]), "iphone-9f3e")

    def test_con_el_chat_abierto_la_prueba_ni_se_mira(self):
        sis, falso = sf.servidor()
        self.addCleanup(sis.limpiar)
        self.sis, self.falso = sis, falso
        self.assertEqual(self.recuperar(codigo=OTRO_CODIGO), 0, self.salida)
        self.assertEqual(self.falso.verificaciones, [])
        self.assertEqual(Manifiesto.leer(self.sis).datos["por_chat"]["iphone"], "iphone-9f3e")
        self.assertIsNone(self.estado()["ultima"])

    # Lo que no entra

    def test_otro_codigo_no_da_de_alta_nada_y_cuenta(self):
        antes, canje = self.sis.leer(TOKENS), self.sis.leer(test_porchat.porchat.RUN + "/canje.json")
        lanzados = len(self.falso.lanzados)
        self.assertEqual(self.recuperar(codigo=OTRO_CODIGO), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=firma")
        self.assertEqual(self.sis.leer(TOKENS), antes)
        # Ni canje nuevo ni nada lanzado.
        self.assertEqual(self.sis.leer(test_porchat.porchat.RUN + "/canje.json"), canje)
        self.assertEqual(len(self.falso.lanzados), lanzados)
        self.assertEqual(self.estado()["fallos"], 1)
        self.assertIsNone(self.estado()["en_curso"])

    def test_la_firma_es_de_esa_llave_y_ese_nombre(self):
        """Lo que ve el chat no vale con otra llave (la de quien lo lee) ni con otro nombre."""
        frase = prueba(self.CODIGO, "iphone-9f3e")
        for iphone, llave in (("iphone-9f3e", OTRA_LLAVE), ("iphone-6666", LLAVE)):
            with self.subTest(iphone=iphone, llave=llave):
                antes = self.sis.leer(TOKENS)
                self.assertEqual(self.por_chat("--recuperacion", frase, iphone=iphone, llave=llave), 1)
                self.assertEqual(self.error(), "hehermes-detalle:motivo=firma")
                self.assertEqual(self.sis.leer(TOKENS), antes)
                # La espera del fallo, pasada: que el siguiente se mire.
                self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 3600))

    def test_tras_un_fallo_espera_y_ni_el_bueno_se_mira(self):
        self.recuperar(codigo=OTRO_CODIGO)
        self.assertEqual(self.recuperar(), 1)
        self.assertRegex(self.error(), r"^hehermes-detalle:motivo=espera hasta=\d+$")
        self.assertEqual(self.estado()["fallos"], 1)
        self.assertEqual(len(self.falso.verificaciones), 1)
        # Pasada la espera, el bueno entra.
        self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 61))
        self.assertEqual(self.recuperar(), 0, self.salida)

    def test_sin_cierre_tras_muchos_fallos_solo_se_espera(self):
        """Con siete fallos seguidos, ocho minutos y nada más: el bueno entra en cuanto pasan. Y mientras, ni se mira."""
        for vez in range(7):
            self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 481 if e["fallos"] else None))
            self.assertEqual(self.recuperar(codigo=OTRO_CODIGO), 1)
            self.assertEqual(self.error(), "hehermes-detalle:motivo=firma")
        self.assertEqual(self.estado()["fallos"], 7)
        self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 470))
        self.assertEqual(self.recuperar(), 1)
        self.assertEqual(int(self.error().rsplit("hasta=", 1)[1]), self.estado()["ultimo_fallo"] + 480)
        self.assertEqual(len(self.falso.verificaciones), 7)
        self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 481))
        self.assertEqual(self.recuperar(), 0, self.salida)

    def test_una_frase_vieja_no_vale_ni_cuenta(self):
        self.assertEqual(self.recuperar(momento=time.time() - 41 * 60), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=caducada")
        self.assertEqual(self.estado()["fallos"], 0)
        self.assertEqual(self.recuperar(momento=time.time() + 11 * 60), 1)
        self.assertEqual(self.recuperar(momento=time.time() - 39 * 60), 0, self.salida)

    def test_usado_el_codigo_ya_no_vale_hasta_que_ponga_otro(self):
        self.assertEqual(self.recuperar(), 0, self.salida)
        self.falso.activos.discard("hehermes-canje")
        self.falso.usar("iphone-9f3e", cuando=time.time() + 1)
        self.assertEqual(self.recuperar(iphone="iphone-5555"), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=gastada")
        # El de la recuperación pone otro (lo que hace la pasarela con su PUT), y con ese vuelve a valer.
        self.registro().cambiar(lambda e: rec.con_clave(e, clave_de(OTRO_CODIGO), "iphone-9f3e", time.time()))
        self.assertEqual(self.recuperar(iphone="iphone-5555"), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=firma")
        self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 3600))
        self.assertEqual(self.recuperar(iphone="iphone-5555", codigo=OTRO_CODIGO), 0, self.salida)

    def test_sin_codigo_en_el_servidor(self):
        self.registro().quitar()
        self.assertEqual(self.recuperar(), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=sin-codigo")
        self.assertIn("hehermes-dispositivo alta iphone-9f3e", self.salida)

    def test_un_registro_que_no_se_entiende_no_es_un_servidor_sin_codigo(self):
        self.sis.escribir(ESTADO_PASARELA + "/" + rec.ESTADO, b"{roto", modo=0o600)
        self.assertEqual(self.recuperar(), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=sin-codigo")
        self.assertIn("No entiendo el registro", self.salida)
        self.assertEqual(self.sis.leer(ESTADO_PASARELA + "/" + rec.ESTADO), b"{roto")

    def test_sin_el_venv_no_se_puede_comprobar(self):
        self.falso.venvs_rotos.add(sf.VENV_CANJE)
        self.assertEqual(self.recuperar(), 1)
        self.assertEqual(self.error(), "hehermes-detalle:motivo=sin-comprobar")
        self.assertEqual(self.estado()["fallos"], 0)

    # El aviso a los demás iPhone

    def buzon(self):
        """El buzón de un vigía que lo entiende (lo crea él al arrancar)."""
        carpeta = self.sis.ruta("/var/lib/hehermes-vigia/" + rec.BUZON)
        os.makedirs(carpeta, mode=0o700, exist_ok=True)
        return carpeta

    def avisos(self):
        carpeta = self.buzon()
        sucesos = []
        for nombre in sorted(os.listdir(carpeta)):
            with open(os.path.join(carpeta, nombre)) as f:
                sucesos.append(json.load(f))
        return sucesos

    def test_al_entrar_se_avisa_a_los_demas_con_su_nombre(self):
        """Con la marca de su token nuevo, que es la que firma la pasarela en sus altas de avisos: a esas no se les
        avisa. Un nombre nuevo no tenía token de antes."""
        from hehermes_servidor import dispositivos as dis
        self.buzon()
        self.assertEqual(self.recuperar(), 0, self.salida)
        (aviso,) = self.avisos()
        self.assertEqual((aviso["tipo"], aviso["que"], aviso["iphone"]), ("recuperacion", "entrada", "iphone-9f3e"))
        self.assertEqual(aviso["cuando"], self.estado()["ultima"]["cuando"])
        self.assertEqual(aviso["marca"], dis.marca_del_token(pa.hash_token(self.carga()["t"])))
        self.assertNotIn("marca_anterior", aviso)
        self.assertIn("Se lo aviso a los demás iPhone", self.salida)

    def test_con_el_mismo_nombre_el_aviso_dice_cual_era_su_token_de_antes(self):
        """El nombre lo pone quien firma la frase: las altas del token de antes reciben el aviso (pueden ser de otro
        aparato) y después el vigía las borra. Ni el token ni su hash salen al buzón: solo sus marcas."""
        from hehermes_servidor import dispositivos as dis
        self.buzon()
        self.assertEqual(self.recuperar(iphone="mi-iphone"), 0, self.salida)
        (aviso,) = self.avisos()
        nuevo = self.carga()["t"]
        self.assertEqual((aviso["iphone"], aviso["marca"], aviso["marca_anterior"]),
                         ("mi-iphone", dis.marca_del_token(pa.hash_token(nuevo)),
                          dis.marca_del_token(pa.hash_token(self.token_viejo))))
        crudo = json.dumps(aviso)
        for secreto in (nuevo, self.token_viejo, pa.hash_token(nuevo), pa.hash_token(self.token_viejo)):
            self.assertNotIn(secreto, crudo)

    def test_sin_buzon_entra_igual_y_no_dice_que_avisa(self):
        self.assertEqual(self.recuperar(), 0, self.salida)
        self.assertNotIn("Se lo aviso", self.salida)
        self.assertFalse(os.path.exists(self.sis.ruta("/var/lib/hehermes-vigia/" + rec.BUZON)))

    def test_los_intentos_se_avisan_uno_por_racha(self):
        self.buzon()
        for vez in range(3):
            self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 481 if e["fallos"] else None))
            self.assertEqual(self.recuperar(codigo=OTRO_CODIGO), 1)
        # Lo que llega en la espera ni se mira: tampoco se avisa.
        self.assertEqual(self.recuperar(codigo=OTRO_CODIGO), 1)
        self.assertIn("motivo=espera", self.error())
        self.assertEqual([(a["que"], "iphone" in a) for a in self.avisos()], [("intentos", False)])
        # Pasado un día sin fallos, otra racha, y otro aviso.
        self.registro().cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 24 * 3600))
        self.assertEqual(self.recuperar(codigo=OTRO_CODIGO), 1)
        self.assertEqual([a["que"] for a in self.avisos()], ["intentos", "intentos"])
        self.assertEqual(self.estado()["fallos"], 1)

    def test_una_frase_vieja_no_se_avisa(self):
        """Solo los fallos de firma (los que cuentan) se avisan: una hora vieja o un código gastado, no."""
        self.buzon()
        self.assertEqual(self.recuperar(momento=time.time() - 41 * 60), 1)
        self.assertEqual(self.avisos(), [])

    # El uso

    def test_errores_de_uso(self):
        frase = prueba(self.CODIGO, "iphone-9f3e")
        self.assertEqual(self.orden("instalar", "--recuperacion", frase), 2)
        self.assertIn("solo van con --por-chat", self.salida)
        self.assertEqual(self.por_chat("--plan", "--recuperacion", frase, iphone="iphone-9f3e"), 2)
        self.assertIn("--recuperacion no va con --plan", self.salida)
        self.assertEqual(self.por_chat("--recuperacion", frase + "x", iphone="iphone-9f3e"), 2)
        self.assertIn("no es la de una frase de la app", self.salida)
        self.assertEqual(self.falso.verificaciones, [])

    def test_quitarlo_solo_desde_un_terminal(self):
        self.assertEqual(self.orden("recuperacion", "quitar"), 1)
        self.assertIn("solo se quita desde un terminal", self.salida)
        self.assertEqual(self.estado()["clave"], clave_de(self.CODIGO))
        self.texto = []
        codigo = test_porchat.cli.main(["recuperacion", "quitar"], "uso", test_porchat.ORIGEN, sis=self.sis,
                                       entrada=lambda _: "s", salida=self.texto.append, terminal=True, euid=0)
        self.assertEqual(codigo, 0, self.texto)
        self.assertIn("(lo puso «mi-iphone»)", "\n".join(self.texto))
        self.assertIsNone(self.estado()["clave"])


class PorChatSinRoot(test_modo_tls.Base):
    """Lo mismo con la pasarela en la casa del usuario de Hermes: el registro en `~/.local/state/hehermes-pasarela` y la
    firma con el venv de su casa. Con lo de `SinRoot`, pero sin heredar sus pruebas."""

    euid = test_modo_tls.SinRoot.euid
    cuenta = test_modo_tls.SinRoot.cuenta
    servidor = test_modo_tls.SinRoot.servidor
    ESTADO = "/home/hermes/.local/state/hehermes-pasarela"

    def por_chat(self, iphone, *extra):
        return self.orden("instalar", "--por-chat", "--iphone", iphone, "--llave", LLAVE, *extra, terminal=False)

    def test_vuelve_a_conectar_con_su_codigo_y_no_con_otro(self):
        self.assertEqual(self.por_chat("mi-iphone"), 0, self.salida)
        self.falso.activos_usuario.discard("hehermes-canje")
        self.falso.usar("mi-iphone")
        carpeta = self.sis.ruta(self.ESTADO)
        os.makedirs(carpeta, exist_ok=True)
        registro = rec.Registro(carpeta)
        registro.cambiar(lambda e: rec.con_clave(e, clave_de(VECTOR["canonico"]), "mi-iphone", time.time()))
        self.assertEqual(self.por_chat("iphone-9f3e", "--recuperacion", prueba(OTRO_CODIGO, "iphone-9f3e")), 1)
        self.assertTrue(self.texto[-1].endswith("hehermes-error:recuperacion"), self.salida)
        registro.cambiar(lambda e: dict(e, ultimo_fallo=int(time.time()) - 3600))
        self.assertEqual(self.por_chat("iphone-9f3e", "--recuperacion", prueba(VECTOR["canonico"], "iphone-9f3e")),
                         0, self.salida)
        self.assertEqual(registro.leer()["en_curso"]["iphone"], "iphone-9f3e")
        self.assertIn("iphone-9f3e", [t["nombre"] for t in self.tokens("/home/hermes/.config/hehermes-pasarela/"
                                                                      "tokens.json")])
        self.assertTrue(self.falso.verificaciones)


if __name__ == "__main__":
    unittest.main()
