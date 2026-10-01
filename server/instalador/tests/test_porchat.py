"""`instalar --por-chat`: la decisión 7, `--activar-api` y el canje que se lanza al acabar, sobre el servidor falso.

Desde la 0.6.0 el canje entrega solo el acceso a la pasarela, `{h, p, f, t}`: ya no hay PSK de una VPN que entregar.
Desde la 0.10.4 (Daniel, 2026-10-01), el chat sigue abierto hasta que el iPhone que se dio de alta por chat usa la
pasarela (`HastaQueLaUse`, y con una pasarela de antes, `DeAntesDeLa0104`): ya no hay media hora.
Sin `cryptography`: esto es el instalador, con el Python del sistema. El canje de verdad está en `test_canje_*.py`.
"""

import apoyo

import base64
import json
import re
import time
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli
from hehermes_servidor import pasarela as pa
from hehermes_servidor import porchat, tokens
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
from hehermes_servidor.plan import Opciones

ORIGEN = str(apoyo.RAIZ)
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()
DIA = 24 * 3600
TOKENS = "/etc/hehermes-pasarela/tokens.json"
USOS = "/var/lib/hehermes-pasarela/usos.json"


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv, terminal=False):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=terminal, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def por_chat(self, *extra, iphone="mi-iphone", llave=LLAVE):
        return self.orden("instalar", "--por-chat", "--iphone", iphone, "--llave", llave, *extra)

    def plan(self, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        opciones.setdefault("por_chat", True)
        opciones.setdefault("llave", LLAVE)
        man = Manifiesto.leer(self.sis)
        det = detectar_tls(self.sis, man, amb.de_root(), activar_api=opciones.get("activar_api", False))
        return calcular_plan_tls(self.sis, det, man, Opciones(**opciones), ORIGEN)

    def por_chat_de(self, segundos, canjeado=True, iphone="mi-iphone"):
        """Una instalación por chat de hace `segundos` (su alta, lo mismo), canjeada o no."""
        self.assertEqual(self.por_chat(iphone=iphone), 0, self.salida)
        cuando = time.time() - segundos
        datos = {"iphone": iphone, "alta": cuando}
        if canjeado:
            datos["canjeado"] = cuando + 60
        self.instalado_hace(segundos, por_chat=datos)
        self.falso.activos.discard("hehermes-canje")
        return cuando

    def alta_por_ssh(self, nombre):
        """Un iPhone dado de alta desde un terminal, con su QR: no por chat."""
        self.assertEqual(self.orden("instalar", "--si", "--iphone", nombre, terminal=True), 0, self.salida)
        self.assertIn("▀", self.salida)

    def carga(self):
        return json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))["carga"]

    def instalado_hace(self, segundos, **datos):
        man = Manifiesto.leer(self.sis)
        man.datos["instalado"] = time.time() - segundos
        man.datos.update(datos)
        man.guardar(self.sis)


class LaLlave(Base):
    def test_valida(self):
        self.assertTrue(porchat.llave_valida(LLAVE))
        for mala in (None, "", LLAVE[:-1], LLAVE + "A", LLAVE.replace(LLAVE[3], "/", 1), LLAVE[:-1] + "=",
                     "a" * 43 + " "):
            with self.subTest(mala=mala):
                self.assertFalse(porchat.llave_valida(mala))


class Uso(Base):
    def test_sin_llave_o_sin_iphone_es_un_error_de_uso(self):
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone"), 2)
        self.assertIn("--llave", self.salida)
        self.assertEqual(self.orden("instalar", "--por-chat", "--llave", LLAVE), 2)
        self.assertIn("--iphone", self.salida)
        self.assertEqual(self.sis.ordenes, [])

    def test_una_llave_mala_es_un_error_de_uso(self):
        self.assertEqual(self.por_chat(llave="no-es-una-llave"), 2)
        self.assertIn("la llave", self.salida)

    def test_la_llave_sin_por_chat_no_vale(self):
        self.assertEqual(self.orden("instalar", "--llave", LLAVE), 2)

    def test_el_plan_por_chat_no_cambia_nada(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE), 0)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("canje", self.salida)


class SoloElPrimero(Base):
    """Decisión 7: una inyección en algo que lea Hermes no puede pedirle un alta nueva con la llave de otro."""

    def test_limpio_pasa(self):
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_con_otro_iphone_ya_dado_de_alta_se_para(self):
        self.alta_por_ssh("el-de-antes")
        plan = self.plan()
        self.assertFalse(plan.puede_seguir)
        self.assertIn("solo se conecta el primer iPhone", "\n".join(plan.bloqueos))
        self.assertIn("el-de-antes", "\n".join(plan.bloqueos))

    def test_el_mismo_iphone_dado_de_alta_por_ssh_se_para(self):
        self.alta_por_ssh("mi-iphone")
        texto = "\n".join(self.plan().bloqueos)
        self.assertIn("no se dio de alta por chat", texto)
        self.assertIn("Por SSH: hehermes-dispositivo rotar mi-iphone", texto)

    def test_ya_canjeado_y_sin_usar_otro_nombre_entra_en_su_lugar(self):
        """La app cambia de nombre si se reinstala (y la de la 0.10.2 se llamaba «mi-iphone»): mientras el de chat no ha
        usado la pasarela, el nuevo entra en su lugar, y el token de antes deja de valer."""
        self.por_chat_de(60)
        plan = self.plan(iphone="iphone-b2c3")
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        (alta,) = [a for a in plan.acciones if a.tipo == "dispositivo"]
        self.assertEqual(alta.datos, {"sustituye": "mi-iphone"})
        self.assertIn("en lugar de «mi-iphone», que se dio de alta por chat y no ha usado la pasarela", alta.detalle)

    def test_ya_canjeado_el_mismo_iphone_pasa(self):
        """El fallo de un probador (0.10.2): la app canjeó el enlace mientras Hermes se reiniciaba y se quedó sin
        conexión; la misma frase otra vez acababa en «ya se canjeó», y por chat no había otra salida."""
        self.por_chat_de(60)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_ya_canjeado_el_mismo_iphone_dias_despues_pasa(self):
        """Hasta la 0.10.3, a la media hora se cerraba aunque nadie hubiera llegado a usar nada."""
        self.por_chat_de(10 * DIA)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_repetirlo_sin_canjear_pasa(self):
        self.por_chat_de(60, canjeado=False)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_una_alta_de_la_vpn_de_antes_cuenta_como_primer_iphone(self):
        import vpn_antigua
        vpn_antigua.montar(self.sis, self.falso, iphones=("el-de-la-vpn",), hace=60)
        texto = "\n".join(self.plan().bloqueos)
        self.assertIn("solo se conecta el primer iPhone, y aquí ya hay: el-de-la-vpn", texto)
        self.assertIn("(hehermes-dispositivo alta <nombre>)", texto)
        self.assertNotIn("--ikev2", texto)


class HastaQueLaUse(Base):
    """Decisión 7 desde el 2026-10-01: el chat se cierra en cuanto el iPhone que se dio de alta por chat usa la pasarela
    (un 2xx con su token, que apunta la pasarela en su `usos.json`), y no antes."""

    def bloqueo(self, plan):
        self.assertFalse(plan.puede_seguir)
        self.assertEqual([getattr(b, "codigo", None) for b in plan.bloqueos], ["por-chat"])
        return "\n".join(plan.bloqueos)

    def test_en_cuanto_lo_usa_se_cierra_para_el_y_para_otro(self):
        alta = self.por_chat_de(60)
        self.falso.usar("mi-iphone", cuando=alta + 120)
        for iphone in ("mi-iphone", "iphone-b2c3"):
            with self.subTest(iphone=iphone):
                texto = self.bloqueo(self.plan(iphone=iphone))
                self.assertIn("«mi-iphone» se dio de alta por chat y ya ha usado la pasarela (%s UTC)"
                              % time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(alta) + 120)), texto)
                self.assertIn("por chat ya no doy de alta nada más", texto)
                self.assertIn("hehermes-dispositivo rotar mi-iphone", texto)

    def test_sigue_cerrado_aunque_se_de_de_baja(self):
        self.por_chat_de(60)
        self.falso.usar("mi-iphone")
        tokens = json.loads(self.sis.leer(TOKENS))
        tokens["tokens"] = []
        self.sis.escribir(TOKENS, json.dumps(tokens).encode(), modo=0o600)
        self.assertIn("ya ha usado la pasarela", self.bloqueo(self.plan(iphone="iphone-b2c3")))

    def test_rotado_por_ssh_y_usado_tambien_cierra(self):
        """El uso cuenta por su nombre: un token nuevo de ese iPhone (hehermes-dispositivo rotar) también es él."""
        self.por_chat_de(60)
        tokens.rotar(self.sis.ruta(TOKENS), "mi-iphone")
        self.falso.usar("mi-iphone")
        self.assertIn("ya ha usado la pasarela", self.bloqueo(self.plan()))

    def test_un_uso_de_antes_de_su_alta_no_cuenta(self):
        """Uno que se llamaba igual y usó la pasarela antes (por SSH, y se dio de baja) no es este."""
        alta = self.por_chat_de(60)
        usos = json.loads(self.sis.leer(USOS))
        usos["tokens"]["0" * 64] = {"nombre": "mi-iphone", "primero": int(alta) - 3600}
        self.sis.escribir(USOS, json.dumps(usos).encode(), modo=0o600)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_el_uso_de_otro_iphone_no_lo_cierra(self):
        alta = self.por_chat_de(60)
        usos = json.loads(self.sis.leer(USOS))
        usos["tokens"]["1" * 64] = {"nombre": "el-de-otro", "primero": int(alta) + 60}
        self.sis.escribir(USOS, json.dumps(usos).encode(), modo=0o600)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_un_registro_que_no_se_entiende_no_cuenta_como_vacio(self):
        """Sin un registro que se entienda, lo que diga el diario (aquí, nada): no se reabre a ciegas."""
        self.por_chat_de(60)
        self.sis.escribir(USOS, b"{no es json", modo=0o600)
        self.assertIn("no sé si ha llegado a usar la pasarela", self.bloqueo(self.plan()))

    def test_sin_su_alta_cuenta_desde_la_instalacion_y_sin_ninguna_no_se_sabe(self):
        self.por_chat_de(60)
        man = Manifiesto.leer(self.sis)
        del man.datos["por_chat"]["alta"]
        man.guardar(self.sis)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)
        self.falso.usar("mi-iphone")
        self.assertIn("ya ha usado la pasarela", self.bloqueo(self.plan()))
        man = Manifiesto.leer(self.sis)
        del man.datos["instalado"]
        man.guardar(self.sis)
        self.sis.escribir(USOS, json.dumps({"v": 1, "desde": 1, "tokens": {}}).encode(), modo=0o600)
        self.assertIn("no sé si ha llegado a usar la pasarela (no sé cuándo se dio de alta)", self.bloqueo(self.plan()))

    def test_una_instalacion_vieja_sin_iphones_por_ssh_sigue_abierta(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.instalado_hace(30 * DIA)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_instalar_apunta_cuando_y_repetir_no_lo_mueve(self):
        antes = time.time()
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "otro"), 0, self.salida)
        instalado = Manifiesto.leer(self.sis).datos["instalado"]
        self.assertGreaterEqual(instalado, antes)
        self.sis.borrar("/etc/hehermes-pasarela/pasarela.ini")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertIn("pasarela.ini", self.salida, "ha reparado algo")
        self.assertEqual(Manifiesto.leer(self.sis).datos["instalado"], instalado)

    def test_una_instalacion_de_antes_sin_fecha_no_la_gana_al_repetir(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        man = Manifiesto.leer(self.sis)
        del man.datos["instalado"]
        man.guardar(self.sis)
        self.sis.borrar("/etc/hehermes-pasarela/pasarela.ini")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertNotIn("instalado", Manifiesto.leer(self.sis).datos)

    def test_sin_por_chat_no_hay_limite(self):
        self.por_chat_de(DIA)
        self.falso.usar("mi-iphone")
        plan = self.plan(por_chat=False, llave=None, iphone="otro")
        self.assertTrue(plan.puede_seguir, plan.bloqueos)


class DeAntesDeLa0104(Base):
    """Una pasarela de antes de la 0.10.4 no apuntaba quién la usa (como la del probador de la 0.10.2, que canjeó y cuya
    única petición dio un 502 con Hermes reiniciándose). Lo que falta lo dice su diario, si llega hasta el alta; si no,
    no se sabe, y no se reabre."""

    def setUp(self):
        super().setUp()
        self.alta = self.por_chat_de(3 * DIA)
        self.sis.borrar(USOS)
        self.falso.diario_pasarela = [(self.alta - 600, "pasarela escuchando en el puerto 61234"),
                                      (self.alta + 90, "198.51.100.7 GET 502"),
                                      (self.alta + 95, "198.51.100.7 rechazada: 404"),
                                      (self.alta + 99, "primer uso de otra cosa: 200 OK")]

    def test_sin_ningun_2xx_desde_el_alta_sigue_abierto(self):
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)
        plan = self.plan(iphone="iphone-b2c3")
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        miradas = [o for o in self.sis.ordenes if o[:1] == ["journalctl"]]
        self.assertIn(["journalctl", "-u", "hehermes-pasarela.service", "--no-pager", "-q", "-o", "short-unix",
                       "--until", "@%d" % int(self.alta), "-n", "1"], miradas)
        self.assertIn(["journalctl", "-u", "hehermes-pasarela.service", "--no-pager", "-q", "-o", "cat",
                       "--since", "@%d" % int(self.alta)], miradas)

    def test_un_2xx_en_el_diario_lo_cierra(self):
        self.falso.diario_pasarela.append((self.alta + 300, "198.51.100.7 GET 200 1534"))
        self.assertIn("«mi-iphone» se dio de alta por chat y ya ha usado la pasarela:",
                      "\n".join(self.plan().bloqueos))

    def test_un_2xx_de_antes_del_alta_no_cuenta(self):
        self.falso.diario_pasarela.append((self.alta - 300, "198.51.100.7 GET 200 1534"))
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)

    def test_un_diario_que_no_llega_hasta_el_alta_no_lo_sabe(self):
        self.falso.diario_pasarela = [(t, l) for t, l in self.falso.diario_pasarela if t > self.alta]
        self.assertIn("no sé si ha llegado a usar la pasarela", "\n".join(self.plan().bloqueos))

    def test_sin_diario_no_lo_sabe(self):
        self.falso.diario_pasarela = None
        texto = "\n".join(self.plan().bloqueos)
        self.assertIn("no sé si ha llegado a usar la pasarela (la pasarela no apuntaba entonces quién la usa y su "
                      "diario no llega hasta el alta)", texto)

    def test_un_registro_que_empezo_despues_tambien_mira_el_diario(self):
        """La pasarela de la 0.10.4 empieza su registro al arrancar: lo de antes, en el diario."""
        self.sis.escribir(USOS, json.dumps({"v": 1, "desde": int(self.alta) + DIA, "tokens": {}}).encode(), modo=0o600)
        self.assertTrue(self.plan().puede_seguir, self.plan().bloqueos)
        self.falso.diario_pasarela.append((self.alta + 300, "198.51.100.7 POST 202 87"))
        self.assertFalse(self.plan().puede_seguir)

    def test_sin_root_mira_su_diario_de_usuario(self):
        ambito = amb.de_usuario("hermes", "/home/hermes", 1000)
        self.assertTrue(porchat._diario_sin_2xx(self.sis, ambito, self.alta))
        self.assertTrue([o for o in self.sis.ordenes if o[:3] == ["journalctl", "--user", "-u"]])


class ActivarApi(Base):
    """Decisión 6: quien solo usa Telegram suele tener la API apagada. Se enciende tocando solo lo que falta."""

    def montar(self, **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)
        self.env = "/root/.hermes/.env"
        self.antes = self.sis.leer_texto(self.env)

    def instalar(self, *extra):
        codigo = self.orden("instalar", "--si", "--activar-api", "--iphone", "mi-iphone", *extra)
        self.assertEqual(codigo, 0, self.salida)

    def reinicios(self):
        return [o for o in self.sis.ordenes if o[:1] == ["systemd-run"] and "--on-active=90" in o]

    def test_apagada_con_clave_anade_solo_lo_que_falta(self):
        self.montar(habilitada=False)
        self.instalar()
        despues = self.sis.leer_texto(self.env)
        self.assertTrue(despues.startswith(self.antes), "lo de antes no se toca")
        self.assertEqual(despues[len(self.antes):], "API_SERVER_ENABLED=true\nAPI_SERVER_HOST=127.0.0.1\n")
        self.assertEqual(self.sis.modo(self.env), 0o600)
        # La copia, antes de tocarlo.
        copia = Manifiesto.leer(self.sis).datos["activar_api"]["copia"]
        self.assertEqual(self.sis.leer_texto(copia["ruta"]), self.antes)
        # La pasarela lleva la clave que ya había, y el reinicio va a los 90 s, una sola vez.
        self.assertEqual(self.sis.leer_texto("/etc/hehermes-pasarela/clave-hermes"), sf.CLAVE + "\n")
        self.assertEqual(len(self.reinicios()), 1)
        self.assertEqual(self.reinicios()[0][-3:], ["systemctl", "restart", "hermes-gateway.service"])

    def test_sin_nada_pone_las_tres_y_la_clave_nueva_no_sale(self):
        self.montar(habilitada=None, clave=None)
        self.instalar()
        nuevas = self.sis.leer_texto(self.env)[len(self.antes):].splitlines()
        self.assertEqual([l.split("=")[0] for l in nuevas], ["API_SERVER_ENABLED", "API_SERVER_HOST", "API_SERVER_KEY"])
        clave = nuevas[2].split("=", 1)[1]
        self.assertGreaterEqual(len(clave), 40)
        self.assertEqual(self.sis.leer_texto("/etc/hehermes-pasarela/clave-hermes"), clave + "\n")
        self.assertNotIn(clave, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if any(clave in a for a in o)], "la clave en una orden")
        self.assertIn("API_SERVER_KEY", self.salida, "dice qué añade, sin el valor")

    def test_false_explicito_se_enciende_detras(self):
        self.montar(habilitada=False, host="127.0.0.1")
        self.instalar()
        self.assertEqual(self.sis.leer_texto(self.env)[len(self.antes):], "API_SERVER_ENABLED=true\n")

    def test_encendida_no_toca_nada(self):
        self.montar()
        self.instalar()
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)
        self.assertEqual(self.reinicios(), [])
        self.assertNotIn("activar_api", Manifiesto.leer(self.sis).datos)

    def test_sin_activar_api_se_sigue_parando(self):
        self.montar(habilitada=False)
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 1)
        self.assertIn("--activar-api", self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)

    def test_un_hermes_suelto_no_se_sabe_reiniciar(self):
        """Desde la 0.10.2 se enciende igual y se para para que lo reinicie quien lo arrancó (`test_perfiles`)."""
        self.montar(habilitada=False, como="proceso")
        self.assertEqual(self.orden("instalar", "--si", "--activar-api", "--iphone", "mi-iphone"), 1)
        self.assertIn("no sé reiniciarlo", self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes + "API_SERVER_ENABLED=true\nAPI_SERVER_HOST=127.0.0.1\n")
        self.assertEqual(self.reinicios(), [])

    def test_el_plan_dice_lo_que_hara_sin_hacerlo(self):
        self.montar(habilitada=False)
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--activar-api"), 0, self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("API_SERVER_ENABLED", self.salida)
        self.assertIn("90 s", self.salida)

    def test_desinstalar_quita_las_lineas_y_deja_el_resto(self):
        self.montar(habilitada=False)
        self.instalar()
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), self.antes)

    def test_desinstalar_no_toca_lineas_cambiadas(self):
        self.montar(habilitada=False)
        self.instalar()
        tocado = self.sis.leer_texto(self.env).replace("API_SERVER_HOST=127.0.0.1", "API_SERVER_HOST=localhost")
        self.sis.poner(self.env, tocado, modo=0o600)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto(self.env), tocado)
        self.assertIn(".env", self.salida)


class ElCanje(Base):
    """Lo que deja `instalar --por-chat` al acabar: el alta, el canje lanzado y la línea del enlace."""

    ENLACE = r"^hehermes-canje:1\?h=%s&p=(\d+)&c=([A-Za-z0-9_-]{22})&f=%s$" % (re.escape(sf.IP_PUBLICA), sf.HUELLA)

    def lanzar(self, *extra):
        codigo = self.por_chat(*extra)
        self.assertEqual(codigo, 0, self.salida)
        import re
        ultima = self.texto[-1]
        hallado = re.match(self.ENLACE, ultima)
        self.assertTrue(hallado, "la última línea tiene que ser el enlace, y es: %r" % ultima)
        return hallado

    def canje_json(self):
        return json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))

    def lanzamiento(self):
        return next(o for o in self.falso.lanzados if "--unit=hehermes-canje" in o)

    def test_de_punta_a_punta_sin_el_token_fuera(self):
        hallado = self.lanzar()
        self.assertTrue(58000 <= int(hallado.group(1)) <= 65500, hallado.group(1))
        datos = self.canje_json()
        # Lo único que entrega: el acceso a la pasarela, {h, p, f, t} y en ese orden. Nada de la VPN.
        carga = datos["carga"]
        self.assertEqual(list(carga), ["h", "p", "f", "t"])
        puerto = Manifiesto.leer(self.sis).datos["pasarela"]["puerto"]
        self.assertEqual((carga["h"], carga["p"], carga["f"]), (sf.IP_PUBLICA, puerto, sf.HUELLA_PASARELA))
        self.assertEqual(pa.Tokens(self.sis.ruta(TOKENS)).quien(carga["t"]), "mi-iphone")
        # El token solo está en el fichero que se le pasa al canje, 0600 dentro de una carpeta 0700.
        self.assertNotIn(carga["t"], self.salida)
        self.assertFalse([o for o in self.sis.ordenes if any(carga["t"] in a for a in o)], "el token en una orden")
        self.assertEqual(datos["llave"], LLAVE)
        self.assertEqual(datos["codigo"], hallado.group(2))
        self.assertEqual(datos["huella"], sf.HUELLA)
        self.assertEqual(datos["puerto"], int(hallado.group(1)))
        self.assertEqual(self.sis.modo(porchat.RUN + "/canje.json"), 0o600)
        self.assertEqual(self.sis.modo(porchat.RUN), 0o700)
        # Por chat no se pinta el QR: lo leería el modelo.
        self.assertNotIn("▀", self.salida)
        self.assertFalse([o for o in self.sis.ordenes if o[:1] == ["/usr/local/sbin/hehermes-dispositivo"]])
        self.assertEqual(Manifiesto.leer(self.sis).datos["por_chat"]["iphone"], "mi-iphone")

    def test_la_unidad_es_de_usar_y_tirar_y_se_limpia_como_root(self):
        self.lanzar()
        orden = self.lanzamiento()
        for propiedad in ("DynamicUser=yes", "LoadCredential=canje:/run/hehermes-canje/canje.json",
                          "LoadCredential=cert:/run/hehermes-canje/cert.pem",
                          "LoadCredential=clave:/run/hehermes-canje/clave.pem",
                          "CapabilityBoundingSet=", "NoNewPrivileges=yes", "ProtectSystem=strict",
                          "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
                          "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictNamespaces=yes",
                          "RestrictSUIDSGID=yes", "LockPersonality=yes", "SystemCallArchitectures=native",
                          "UMask=0077", "RuntimeMaxSec=780",
                          "ExecStopPost=+/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor canje-limpiar"):
            with self.subTest(propiedad=propiedad):
                self.assertIn(propiedad, orden)
        self.assertEqual(orden[-6:], [sf.VENV_CANJE + "/bin/python", "-I", "-B", "-m", "hehermes_servidor.canje",
                                      "servir"])
        self.assertIn("--collect", orden)
        # Un puerto alto no pide ninguna capacidad: el canje corre sin ninguna.
        self.assertFalse([a for a in orden if "CAP_" in a or a.startswith("AmbientCapabilities")], orden)

    def test_el_venv_se_hace_una_vez_con_las_dependencias_fijadas(self):
        self.lanzar()
        self.assertEqual(len(self.falso.pip), 1)
        pip = self.falso.pip[0]
        for opcion in ("--require-hashes", "--only-binary=:all:", "/opt/hehermes-servidor/requirements-canje.txt"):
            self.assertIn(opcion, pip)
        self.assertEqual(self.sis.leer_texto(sf.VENV_CANJE + "/lib/python3.11/site-packages/hehermes-servidor.pth"),
                         "/opt/hehermes-servidor\n")
        self.falso.activos.discard("hehermes-canje")
        self.lanzar()
        self.assertEqual(len(self.falso.pip), 1, "el venv ya estaba")

    def test_el_puerto_sale_al_azar_y_se_salta_los_ocupados(self):
        # La pasarela, antes y en el 58000, para que no se cruce con el del canje.
        with mock.patch.object(porchat, "_azar", lambda n: 0):
            self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        # Al azar: el primero que se prueba es el 61234; está escuchando otro y el siguiente lo usa una conexión.
        self.falso.tcp += [("0.0.0.0:61234", "otro")]
        self.falso.tcp_conexiones += ["198.51.100.23:61235"]
        with mock.patch.object(porchat, "_azar", lambda n: 61234 - porchat.PUERTO_MINIMO):
            self.assertEqual(self.lanzar().group(1), "61236")
        self.assertEqual(self.canje_json()["puerto"], 61236)
        self.assertIn(["ss", "-H", "-tan"], self.sis.ordenes, "también las conexiones, no solo lo que escucha")

    def test_sin_puerto_libre_se_para(self):
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        with mock.patch.object(porchat, "elegir_puerto", lambda ocupados: None):
            self.assertEqual(self.por_chat(), 1)
        self.assertIn("no hay ningún puerto libre", self.salida)
        self.assertFalse(self.falso.lanzados and "--unit=hehermes-canje" in self.falso.lanzados[-1])
        self.assertFalse(self.sis.existe(porchat.RUN))

    def test_con_ufw_activo_abre_el_puerto_solo_para_el_canje(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        puerto = self.lanzar().group(1)
        regla = "ufw allow proto tcp from any to any port %s comment hehermes-canje" % puerto
        self.assertIn(regla, self.falso.reglas_ufw)
        self.assertNotIn(regla,
                         Manifiesto.leer(self.sis).reglas, "no es una regla de la instalación: se va con el canje")

    def test_con_ufw_apagado_no_hay_regla(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "inactivo"
        self.lanzar()
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])

    def test_repetirlo_da_otro_enlace_y_otro_token_para_el_mismo_iphone(self):
        primero = self.lanzar()
        token = self.carga()["t"]
        segundo = self.lanzar()
        self.assertNotEqual(primero.group(2), segundo.group(2))
        self.assertIn(["systemctl", "stop", "hehermes-canje"], self.sis.ordenes)
        # Del token solo queda el hash: va uno nuevo, y el de antes deja de valer.
        tokens = pa.Tokens(self.sis.ruta(TOKENS))
        self.assertIsNone(tokens.quien(token))
        self.assertEqual(tokens.quien(self.carga()["t"]), "mi-iphone")
        self.assertEqual([t["nombre"] for t in json.loads(self.sis.leer(TOKENS))["tokens"]], ["mi-iphone"])

    def test_con_qr_png_deja_el_enlace_y_nada_mas(self):
        self.sis.carpeta("/tmp", 0o1777)
        hallado = self.lanzar("--qr-png", "/tmp/hehermes-canje.png")
        self.assertEqual(self.sis.leer("/tmp/hehermes-canje.png"), b"\x89PNG falso de " + hallado.group(0).encode())
        self.assertFalse(self.sis.existe(porchat.RUN + "/qr.png"), "el de /run, fuera")

    def test_con_qr_png_no_pisa_nada_ni_sigue_enlaces(self):
        self.sis.poner("/etc/importante", "no me pises\n")
        self.lanzar("--qr-png", "/etc/importante")
        self.assertEqual(self.sis.leer_texto("/etc/importante"), "no me pises\n")
        self.assertIn("No he podido dejar el QR en /etc/importante", self.salida)
        self.sis.carpeta("/tmp")
        self.sis.enlazar("/tmp/trampa.png", "/etc/nuevo")
        self.falso.activos.discard("hehermes-canje")
        self.lanzar("--qr-png", "/tmp/trampa.png")
        self.assertFalse(self.sis.existe("/etc/nuevo"))

    def test_con_sudo_el_png_se_crea_como_su_usuario(self):
        self.sis.carpeta("/tmp", 0o1777)
        llamadas = []
        with mock.patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch("os.geteuid", lambda: 0), mock.patch("os.getgroups", lambda: [0]), \
                mock.patch("os.setgroups", lambda g: llamadas.append(("grupos", g))), \
                mock.patch("os.setegid", lambda g: llamadas.append(("egid", g))), \
                mock.patch("os.seteuid", lambda u: llamadas.append(("euid", u))):
            self.lanzar("--qr-png", "/tmp/hehermes-canje.png")
        self.assertEqual(llamadas, [("grupos", [1000]), ("egid", 1000), ("euid", 1000), ("euid", 0), ("egid", 0),
                                    ("grupos", [0])])
        self.assertTrue(self.sis.existe("/tmp/hehermes-canje.png"))

    def test_con_activar_api_hermes_se_reinicia_despues_del_canje(self):
        self.sis, self.falso = sf.servidor(habilitada=False)
        self.addCleanup(self.sis.limpiar)
        self.lanzar("--activar-api")
        indices = [i for i, o in enumerate(self.falso.lanzados)]
        canje_ = next(i for i in indices if "--unit=hehermes-canje" in self.falso.lanzados[i])
        reinicio = next(i for i in indices if "--on-active=90" in self.falso.lanzados[i])
        self.assertLess(canje_, reinicio)

    def test_si_la_unidad_no_arranca_se_para_y_limpia(self):
        original = self.falso._systemd_run
        self.falso._systemd_run = lambda args, entrada: (original(args, entrada), self.falso.activos.discard(
            "hehermes-canje"))[0]
        self.assertEqual(self.por_chat(), 1)
        self.assertIn("el canje no ha arrancado", self.salida)
        self.assertFalse(self.sis.existe(porchat.RUN))
        self.assertFalse(self.texto[-1].startswith("hehermes-canje:"))


class SinSecretos(Base):
    """Daniel: nada de secretos en la salida (que por chat lee el modelo), en una orden (que ve `ps` y puede acabar en
    el diario) ni en lo que se deja escrito fuera de su sitio. Lo único que lleva el token es el QR, y solo a un
    terminal."""

    def test_ni_el_token_ni_la_clave_de_hermes_salen_de_su_sitio(self):
        self.sis, self.falso = sf.servidor(habilitada=None, clave=None)
        self.addCleanup(self.sis.limpiar)
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.por_chat("--activar-api"), 0, self.salida)
        clave = [l for l in self.sis.leer_texto("/root/.hermes/.env").splitlines()
                 if l.startswith("API_SERVER_KEY=")][0].split("=", 1)[1]
        token = self.carga()["t"]
        salidas = self.salida
        self.orden("comprobar")
        salidas += self.salida
        for secreto in (token, clave):
            with self.subTest(secreto=secreto[:6]):
                self.assertNotIn(secreto, salidas)
                self.assertFalse([o for o in self.sis.ordenes if any(secreto in a for a in o)], "en una orden")
                for ruta, datos in self.sis.foto().items():
                    if datos[0] != "fichero" or secreto.encode() not in datos[2]:
                        continue
                    # Donde sí tiene que estar: su sitio, 0600, y las copias de /etc/hehermes y /run, también 0600.
                    self.assertEqual(datos[1], "0o600", ruta)
                    # Y desde la 0.8.0, que el vigía va siempre, su copia (la de la pasarela, para el vigía).
                    self.assertTrue(ruta.startswith(("/run/hehermes-canje/", "/root/.hermes/",
                                                     "/etc/hehermes-pasarela/clave-hermes", "/etc/hehermes/",
                                                     "/etc/hehermes-avisos/vigia/clave-hermes")), ruta)


class Limpiar(Base):
    """`canje-limpiar`, lo que corre como root en `ExecStopPost` al cerrarse el canje, por lo que sea."""

    def setUp(self):
        super().setUp()
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.falso.activos.discard("hehermes-canje")

    def limpiar(self, **entorno):
        return porchat.limpiar(self.sis, entorno)

    def test_lo_borra_todo(self):
        self.limpiar(SERVICE_RESULT="timeout", EXIT_CODE="killed", EXIT_STATUS="TERM")
        self.assertFalse(self.sis.existe(porchat.RUN))
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])
        self.assertNotIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])

    def test_canjeado_se_apunta_y_el_mismo_iphone_recibe_otra_clave(self):
        token = self.carga()["t"]
        self.limpiar(SERVICE_RESULT="success", EXIT_CODE="exited", EXIT_STATUS="0")
        self.assertIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])
        # La misma frase otra vez, con la llave nueva de la misma app: otro enlace y otra clave; la de antes, fuera.
        otra = base64.urlsafe_b64encode(bytes(range(80, 112))).rstrip(b"=").decode()
        self.assertEqual(self.por_chat(llave=otra), 0, self.salida)
        self.assertTrue(self.texto[-1].startswith("hehermes-canje:1?"), self.texto[-1])
        self.assertIn("«mi-iphone» ya se había conectado por chat: le doy una clave nueva", self.salida)
        tokens = pa.Tokens(self.sis.ruta(TOKENS))
        self.assertIsNone(tokens.quien(token))
        self.assertEqual(tokens.quien(self.carga()["t"]), "mi-iphone")
        self.assertEqual(json.loads(self.sis.leer_texto(porchat.RUN + "/canje.json"))["llave"], otra)
        por_chat = Manifiesto.leer(self.sis).datos["por_chat"]
        self.assertEqual(por_chat["iphone"], "mi-iphone")
        self.assertNotIn("canjeado", por_chat, "el canje nuevo lo vuelve a apuntar al acabar")
        self.assertNotIn(token, self.salida)

    def test_canjeado_y_sin_usar_otro_nombre_entra_en_su_lugar(self):
        token = self.carga()["t"]
        self.limpiar(SERVICE_RESULT="success", EXIT_CODE="exited", EXIT_STATUS="0")
        self.assertEqual(self.por_chat(iphone="iphone-b2c3"), 0, self.salida)
        self.assertTrue(self.texto[-1].startswith("hehermes-canje:1?"), self.texto[-1])
        self.assertIn("«mi-iphone» deja de valer: se dio de alta por chat y no llegó a usar la pasarela", self.salida)
        tokens_ = pa.Tokens(self.sis.ruta(TOKENS))
        self.assertIsNone(tokens_.quien(token))
        self.assertEqual(tokens_.quien(self.carga()["t"]), "iphone-b2c3")
        self.assertEqual([t["nombre"] for t in json.loads(self.sis.leer(TOKENS))["tokens"]], ["iphone-b2c3"])
        man = Manifiesto.leer(self.sis)
        self.assertEqual(man.datos["por_chat"]["iphone"], "iphone-b2c3")
        self.assertEqual(man.dispositivos, ["iphone-b2c3"])

    def test_canjeado_y_usado_otro_iphone_por_chat_se_para(self):
        self.limpiar(SERVICE_RESULT="success", EXIT_CODE="exited", EXIT_STATUS="0")
        self.falso.usar("mi-iphone")
        antes = self.sis.foto()
        self.assertEqual(self.por_chat(iphone="iphone-b2c3"), 1)
        self.assertIn("«mi-iphone» se dio de alta por chat y ya ha usado la pasarela", self.salida)
        self.assertEqual(self.texto[-1].strip(), "hehermes-error:por-chat")
        self.assertEqual(self.sis.foto(), antes, "no se ha tocado nada")

    def test_caducado_no_cuenta_como_canjeado(self):
        self.limpiar(SERVICE_RESULT="exit-code", EXIT_CODE="exited", EXIT_STATUS="3")
        self.assertNotIn("canjeado", Manifiesto.leer(self.sis).datos["por_chat"])

    def test_como_orden(self):
        codigo = self.orden("canje-limpiar")
        self.assertEqual(codigo, 0, self.salida)
        self.assertFalse(self.sis.existe(porchat.RUN))

    def test_una_regla_que_quedo_de_antes_de_reiniciar_se_quita_al_repetir(self):
        # Tras un reinicio /run está vacío, pero la regla de ufw sigue.
        self.sis.borrar_arbol(porchat.RUN)
        self.assertTrue([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(len([r for r in self.falso.reglas_ufw if "hehermes-canje" in r]), 1)

    def test_desinstalar_no_deja_nada_del_canje(self):
        self.sis.borrar_arbol(porchat.RUN)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe("/opt/hehermes-canje"))
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])


class ElegirPuerto(unittest.TestCase):
    """Daniel (2026-09-26): alto y al azar, para que no sea fácil de encontrar; y de un generador criptográfico."""

    def test_el_rango_es_de_58000_a_65500_con_los_dos_extremos(self):
        self.assertEqual((porchat.PUERTO_MINIMO, porchat.PUERTO_MAXIMO), (58000, 65500))
        total = 65500 - 58000 + 1
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: 0), 58000)
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: n - 1), 65500)
        pedidos = []
        porchat.elegir_puerto(set(), azar=lambda n: pedidos.append(n) or 0)
        self.assertEqual(pedidos, [total], "el azar se pide sobre el rango entero, ni uno más ni uno menos")

    def test_se_salta_los_ocupados_y_da_la_vuelta(self):
        self.assertEqual(porchat.elegir_puerto({65500}, azar=lambda n: n - 1), 58000)
        self.assertEqual(porchat.elegir_puerto({58000, 58001}, azar=lambda n: 0), 58002)

    def test_sin_ninguno_libre_no_hay_puerto(self):
        self.assertIsNone(porchat.elegir_puerto(set(range(58000, 65501)), azar=lambda n: 7))
        self.assertEqual(porchat.elegir_puerto(set(range(58000, 65500)), azar=lambda n: 7), 65500)

    def test_el_azar_es_el_criptografico(self):
        import secrets
        self.assertIs(porchat._azar, secrets.randbelow)

    def test_de_verdad_cae_siempre_dentro(self):
        vistos = {porchat.elegir_puerto(set()) for _ in range(300)}
        self.assertTrue(all(58000 <= p <= 65500 for p in vistos))
        self.assertGreater(len(vistos), 250, "al azar, casi nunca repite")


class LaCarga(unittest.TestCase):
    def test_es_la_del_qr_de_la_pasarela_y_en_su_orden(self):
        carga = porchat.carga_tls("198.51.100.23", 61234, sf.HUELLA_PASARELA, LLAVE)
        self.assertEqual(list(carga), ["h", "p", "f", "t"])
        self.assertEqual(carga["p"], 61234, "el puerto, como número")

    def test_lo_que_no_valdria_en_el_qr_tampoco_vale_aqui(self):
        for malo in (("a b", 61234, sf.HUELLA_PASARELA, LLAVE), ("198.51.100.23", "61234", sf.HUELLA_PASARELA, LLAVE),
                     ("198.51.100.23", 61234, "corta", LLAVE), ("198.51.100.23", 61234, sf.HUELLA_PASARELA, "x")):
            with self.subTest(malo=malo), self.assertRaises(ValueError):
                porchat.carga_tls(*malo)


if __name__ == "__main__":
    unittest.main()
