"""El modo TLS del instalador, de punta a punta contra el servidor falso: con root, sin root, al lado de la VPN de
Daniel, por chat, comprobar y desinstalar."""

import apoyo

import json
import re
import secrets
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import cli
from hehermes_servidor import pasarela as pa
from hehermes_servidor import porchat

ORIGEN = str(apoyo.RAIZ)
LLAVE = "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkc"
#: Lo que cambia algo en el servidor: nada de esto puede salir en un --plan ni al repetir.
QUE_CAMBIA = (["systemctl", "enable"], ["systemctl", "restart"], ["systemctl", "reload"], ["useradd"], ["userdel"],
              ["ufw", "allow"], ["ufw", "delete"], ["chown"], ["systemd-run"], ["apt-get", "install"])
#: Lo de la VPN, que el modo TLS no toca nunca.
DE_LA_VPN = ("swanctl", "nginx", "hehermes-xfrm", "semanage", "wg", "wg-quick", "strongswan")


def cambia(orden):
    sin_user = [a for a in orden if a != "--user"]
    return any(sin_user[:len(q)] == q for q in QUE_CAMBIA) or orden[:1] == ["env"]


class Base(unittest.TestCase):
    euid = 0
    cuenta = None

    def setUp(self):
        self.sis, self.falso = self.servidor()
        self.addCleanup(self.sis.limpiar)
        self.relanzados = []
        self.azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        self.azar.start()
        self.addCleanup(self.azar.stop)

    def servidor(self):
        return sf.servidor()

    def orden(self, *argv, terminal=True, euid=None):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "s", salida=self.texto.append,
                          terminal=terminal, euid=self.euid if euid is None else euid,
                          relanzar=lambda orden: self.relanzados.append(orden) or 0, usuario="hermes",
                          cuenta=self.cuenta)
        self.salida = "\n".join(self.texto)
        return codigo

    def ordenes_de(self, desde=0):
        return self.sis.ordenes[desde:]

    def tokens(self, ruta="/etc/hehermes-pasarela/tokens.json"):
        return json.loads(self.sis.leer(ruta))["tokens"]

    def manifiesto(self, ruta="/etc/hehermes/instalacion.json"):
        return json.loads(self.sis.leer(ruta))


class ElPuerto(unittest.TestCase):
    """Alto y al azar, del 58000 al 65500 (los dos entran), con el generador del sistema, y el siguiente libre."""

    def test_los_extremos_entran(self):
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: 0), 58000)
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: n - 1), 65500)
        self.assertEqual(porchat.PUERTO_MAXIMO - porchat.PUERTO_MINIMO + 1, 7501)

    def test_si_esta_ocupado_el_siguiente_y_da_la_vuelta(self):
        self.assertEqual(porchat.elegir_puerto({65500}, azar=lambda n: n - 1), 58000)
        self.assertEqual(porchat.elegir_puerto({61234, 61235}, azar=lambda n: 3234), 61236)
        self.assertIsNone(porchat.elegir_puerto(set(range(58000, 65501)), azar=lambda n: 0))

    def test_el_generador_es_el_criptografico_y_se_le_pide_el_rango_entero(self):
        self.assertIs(porchat._azar, secrets.randbelow)
        pedidos = []
        porchat.elegir_puerto(set(), azar=lambda n: pedidos.append(n) or 0)
        self.assertEqual(pedidos, [7501])

    def test_el_de_la_pasarela_se_queda_el_mismo(self):
        sis, falso = sf.servidor()
        self.addCleanup(sis.limpiar)
        with mock.patch.object(porchat, "_azar", lambda n: 100):
            self.assertEqual(cli.main(["instalar", "--si"], "uso", ORIGEN, sis=sis, salida=lambda *_: None,
                                      terminal=False, euid=0), 0)
        self.assertEqual(json.loads(sis.leer("/etc/hehermes/instalacion.json"))["pasarela"]["puerto"], 58100)
        with mock.patch.object(porchat, "_azar", lambda n: 7000):
            cli.main(["instalar", "--si"], "uso", ORIGEN, sis=sis, salida=lambda *_: None, terminal=False, euid=0)
        self.assertEqual(json.loads(sis.leer("/etc/hehermes/instalacion.json"))["pasarela"]["puerto"], 58100)
        self.assertIn("puerto = 58100\n", sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"))

    def test_no_elige_uno_ocupado(self):
        sis, falso = sf.servidor()
        self.addCleanup(sis.limpiar)
        falso.tcp.append(("0.0.0.0:61234", "otro"))
        with mock.patch.object(porchat, "_azar", lambda n: 3234):
            cli.main(["instalar", "--si"], "uso", ORIGEN, sis=sis, salida=lambda *_: None, terminal=False, euid=0)
        self.assertEqual(json.loads(sis.leer("/etc/hehermes/instalacion.json"))["pasarela"]["puerto"], 61235)


class ConRoot(Base):
    def test_el_plan_no_lleva_nada_de_la_vpn_y_no_cambia_nada(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertIn("Modo       TLS: la pasarela, en el TCP 61234", self.salida)
        for de_la_vpn in ("strongswan", "charon", "nginx", "hh-ipsec", "hehermes-xfrm", "UDP 500"):
            self.assertNotIn(de_la_vpn, self.salida)
        for parte in ("hh-pasarela", "/etc/hehermes-pasarela/pasarela.ini", "/etc/hehermes-pasarela/tokens.json",
                      "hehermes-pasarela.service", "/etc/hehermes-pasarela/cert.pem", "mi-iphone"):
            self.assertIn(parte, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if cambia(o)])
        self.assertNotIn(sf.CLAVE, self.salida)

    def test_instala_y_repetir_no_cambia_nada(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertEqual(self.falso.usuarios_sistema, {"hh-pasarela", "hh-vigia"})
        self.assertIn("hehermes-pasarela", self.falso.activos)
        self.assertIn("hehermes-pasarela-clave.path", self.falso.activos)
        self.assertIn("ufw allow proto tcp from any to any port 61234 comment hehermes", self.falso.reglas_ufw)
        self.assertEqual(self.falso.dueños["/etc/hehermes-pasarela"], "root:hh-pasarela")
        self.assertEqual(self.falso.dueños["/etc/hehermes-pasarela/tokens.json"], "root:hh-pasarela")
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/tokens.json"), 0o640)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/clave.pem"), 0o600)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/clave-hermes"), 0o600)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela"), 0o750)
        self.assertEqual(self.sis.leer_texto("/etc/hehermes-pasarela/clave-hermes"), sf.CLAVE + "\n")
        man = self.manifiesto()
        self.assertEqual((man["modos"], man["pasarela"]["puerto"]), (["tls"], 61234))
        self.assertEqual([t["nombre"] for t in self.tokens()], ["mi-iphone"])
        self.assertIn("▀", self.salida)
        self.assertIn("ni lo compartas", self.salida)
        self.assertNotIn(sf.CLAVE, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if o[0].rsplit("/", 1)[-1] in DE_LA_VPN])
        self.assertFalse(self.sis.existe("/etc/hehermes/servidor.ini"), "servidor.ini es de la VPN")
        self.assertFalse(self.sis.existe("/etc/wireguard"))
        # Repetir: todo al día, y ninguna orden que cambie algo.
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
        self.assertIn("hehermes-dispositivo rotar mi-iphone", self.salida)
        self.assertFalse([o for o in self.ordenes_de(desde) if cambia(o)])

    def test_por_chat_cada_parada_acaba_en_su_codigo(self):
        """Lo que no deja instalar, por chat, acaba en `hehermes-error:<código>`, sola y la última: la app lo explica
        donde se pega el enlace. Y no se ha tocado nada."""
        casos = {"nat": lambda f: setattr(f, "direccion_salida", "192.168.1.20"),
                 "varios-hermes": lambda f: f.con_hermes(usuario="ana", como="proceso", puerto=9000),
                 "api-apagada": lambda f: f.con_hermes(habilitada=False)}
        for codigo, preparar in casos.items():
            with self.subTest(codigo=codigo):
                sis, falso = sf.servidor()
                self.addCleanup(sis.limpiar)
                self.sis, self.falso = sis, falso
                preparar(falso)
                antes = sis.foto()
                self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE,
                                            terminal=False), 1, self.salida)
                self.assertEqual(self.texto[-1], "\nhehermes-error:" + codigo)
                self.assertEqual(sum("hehermes-error:" in linea for linea in self.texto), 1)
                self.assertEqual(sis.foto(), antes)
        # Por un terminal no sale: lo lee una persona.
        sis, falso = sf.servidor()
        self.addCleanup(sis.limpiar)
        self.sis, self.falso = sis, falso
        falso.direccion_salida = "192.168.1.20"
        self.assertEqual(self.orden("instalar", "--plan"), 1)
        self.assertNotIn("hehermes-error", self.salida)

    def test_el_certificado_siguiente_para_rotar_sin_emparejar(self):
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertIn("certificado siguiente de la pasarela: huella %s" % sf.HUELLA_SIGUIENTE, self.salida)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/siguiente/clave.pem"), 0o600)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/siguiente/cert.pem"), 0o644)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/siguiente"), 0o750)
        self.assertEqual(self.falso.dueños["/etc/hehermes-pasarela/siguiente"], "root:hh-pasarela")
        self.assertIn("certificado_siguiente = /etc/hehermes-pasarela/siguiente/cert.pem\n",
                      self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"))
        man = self.manifiesto()
        self.assertIn("/etc/hehermes-pasarela/siguiente/clave.pem", man["ficheros"])
        self.assertIn("/etc/hehermes-pasarela/siguiente", man["carpetas"])
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("la huella siguiente, para rotar sin volver a emparejar: %s" % sf.HUELLA_SIGUIENTE, self.salida)
        # Rotar: el siguiente pasa a ser el de ahora, el de antes queda en anterior/, y hay otro siguiente.
        cert_antes = self.sis.leer("/etc/hehermes-pasarela/cert.pem")
        clave_siguiente = self.sis.leer("/etc/hehermes-pasarela/siguiente/clave.pem")
        reinicios = len(self.falso.reinicios)
        self.assertEqual(self.orden("certificado", "rotar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer("/etc/hehermes-pasarela/anterior/cert.pem"), cert_antes)
        self.assertEqual(self.sis.leer("/etc/hehermes-pasarela/clave.pem"), clave_siguiente)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/clave.pem"), 0o600)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/anterior/clave.pem"), 0o600)
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/anterior"), 0o700)
        self.assertTrue(self.sis.existe("/etc/hehermes-pasarela/siguiente/cert.pem"), "y otro siguiente")
        self.assertIn("hehermes-pasarela", self.falso.reinicios[reinicios:])
        self.assertIn("ahora     %s" % sf.HUELLA_SIGUIENTE, self.salida)
        self.assertIn("antes     %s" % sf.HUELLA_PASARELA, self.salida)
        self.assertIn("hehermes-dispositivo rotar <nombre>", self.salida)
        self.assertNotIn("PRIVATE KEY", self.salida)
        # Y desinstalar se lo lleva todo, anterior/ incluida.
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        for ruta in ("/etc/hehermes-pasarela/anterior", "/etc/hehermes-pasarela/siguiente", "/etc/hehermes-pasarela"):
            self.assertFalse(self.sis.existe(ruta), ruta)

    def test_rotar_sin_siguiente_no_toca_nada(self):
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        self.sis.borrar("/etc/hehermes-pasarela/siguiente/cert.pem")
        antes = self.sis.foto()
        self.assertEqual(self.orden("certificado", "rotar", "--si"), 1, self.salida)
        self.assertIn("no hay certificado siguiente", self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_rotar_sin_terminal_ni_si_pregunta_y_no_toca_nada(self):
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        antes = self.sis.foto()
        self.assertEqual(self.orden("certificado", "rotar", terminal=False), 1, self.salida)
        self.assertIn("No he cambiado nada", self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_el_qr_lleva_la_direccion_el_puerto_la_huella_y_un_token_que_vale(self):
        from hehermes_servidor import qr
        vistos = []
        real = qr.terminal
        with mock.patch.object(qr, "terminal", lambda texto: vistos.append(texto) or real(texto)):
            self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        hallado = re.fullmatch(r"hehermes-tls:1\?h=198\.51\.100\.23&p=61234&f=%s&t=([A-Za-z0-9_-]{43})"
                               % sf.HUELLA_PASARELA, vistos[0])
        self.assertTrue(hallado, vistos)
        token = hallado.group(1)
        self.assertEqual(pa.Tokens(self.sis.ruta("/etc/hehermes-pasarela/tokens.json")).quien(token), "mi-iphone")
        self.assertNotIn(token, self.salida)

    def test_sin_un_terminal_no_da_el_alta(self):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone", terminal=False), 0, self.salida)
        self.assertEqual(self.tokens(), [])
        self.assertNotIn("▀", self.salida)
        self.assertIn("sudo hehermes-dispositivo alta mi-iphone", self.salida)

    def test_la_unidad_lleva_el_secreto_del_vigia_si_estan_los_avisos(self):
        """Los avisos puestos a mano (el VPS de Daniel, instalar.sh): no los toco, pero la pasarela les pasa /avisos/."""
        self.sis.carpeta("/opt/hehermes-avisos/src")
        self.sis.poner("/etc/hehermes-avisos/vigia/secreto-tunel", "s" * 43 + "\n", modo=0o600)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        unidad = self.sis.leer_texto("/etc/systemd/system/hehermes-pasarela.service")
        self.assertIn("LoadCredential=vigia:/etc/hehermes-avisos/vigia/secreto-tunel\n", unidad)
        self.assertIn("vigia = 127.0.0.1:8790\n", self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"))

    def test_un_codigo_de_avisos_que_no_lo_es_para_antes_de_nada(self):
        """--avisos era de la VPN y se fue con ella; desde la 0.7.0 lleva el código de avisos (`test_avisos`). Uno que
        no lo es se para antes de mirar nada, y el error no lo repite (un código de verdad lleva la credencial)."""
        antes = self.sis.foto()
        malo = "hehermes-avisos:1?h=198.51.100.7&p=61234&f=corta&c=hhr1.secreta"
        self.assertEqual(self.orden("instalar", "--plan", "--avisos", malo), 2)
        self.assertIn("la huella o la credencial", self.salida)
        self.assertNotIn("hhr1.secreta", self.salida)
        self.assertEqual(self.sis.ordenes, [])
        self.assertEqual(self.sis.foto(), antes)

    def test_modo_tls_explicito_se_sigue_aceptando(self):
        """Lo llevan los comandos de antes de la 0.6.0."""
        self.assertEqual(self.orden("instalar", "--plan", "--modo", "tls"), 0, self.salida)
        self.assertIn("Modo       TLS: la pasarela, en el TCP 61234\n", self.salida)

    def test_sobre_una_vpn_de_antes_la_pasarela_se_anade(self):
        """Lo de punta a punta, en `test_dos_modos`."""
        import vpn_antigua
        vpn_antigua.montar(self.sis, self.falso)
        for argv in (("instalar", "--plan"), ("instalar", "--plan", "--modo", "tls")):
            self.assertEqual(self.orden(*argv), 0, self.salida)
            self.assertIn("Modo       TLS: la pasarela, en el TCP 61234, al lado de la VPN IKEv2 de antes (no la toco)",
                          self.salida)
            self.assertIn("Aquí sigue la VPN IKEv2 que instaló una versión anterior (/etc/hehermes/instalacion.json). "
                          "Desde la 0.6.0 ya no la instalo ni la reparo", self.salida)
            self.assertIn("sudo hehermes-servidor desinstalar --modo vpn", self.salida)
            self.assertNotIn("No puedo seguir", self.salida)

    def test_comprobar_con_su_seguridad(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        for linea in ("bien  pasarela: en marcha", "bien  pasarela: escucha en el TCP 61234",
                      "bien  pasarela: su certificado es el del QR", "bien  pasarela: sin token, el 404 de siempre",
                      "bien  Hermes: contesta con su clave", "bien  pasarela: su copia de la clave de Hermes está al día",
                      "bien  pasarela: solo TLS 1.3", "bien  pasarela: a quien no trae token, el 404 de siempre",
                      "bien  pasarela: como hh-pasarela", "bien  secretos:", "bien  la API de Hermes solo escucha"):
            self.assertIn(linea, self.salida)
        self.assertNotIn("nginx", self.salida)
        self.assertNotIn("IKEv2", self.salida)

    def test_comprobar_ve_lo_que_esta_mal(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.falso.sonda = lambda puerto, maxima=None, **_: {"tls": "TLSv1.3", "huella": "otra",
                                                         "respuesta": b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n"}
        self.sis._sonda = self.falso.sonda
        self.sis.poner("/etc/hehermes-pasarela/tokens.json", '{"v": 1, "tokens": []}', modo=0o644)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   pasarela: sirve otro certificado", self.salida)
        self.assertIn("MAL   pasarela: sin token contesta con una cabecera Server", self.salida)
        self.assertIn("MAL   pasarela: acepta algo más viejo que TLS 1.3", self.salida)
        self.assertIn("MAL   secretos que se pueden leer sin ser su dueño: /etc/hehermes-pasarela/tokens.json",
                      self.salida)

    def test_comprobar_avisa_de_lo_que_quedo_de_la_vpn(self):
        """strongSwan escuchando en UDP 500/4500 y los sitios de nginx del túnel (auditoría §13.8): se dicen, con la
        orden exacta, y no se quita nada solo. Un sitio del túnel habilitado ya es un mal."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.falso.udp += [("0.0.0.0:500", "charon-systemd"), ("0.0.0.0:4500", "charon-systemd")]
        self.falso.activos.add("strongswan")
        self.falso.habilitados.add("nginx")
        for nombre in ("hehermes", "hehermes-tunel.antes-de-gzip", "hermes-dash"):
            self.sis.poner("/etc/nginx/sites-available/" + nombre, "server { listen 80; }\n")
        antes = self.sis.foto()
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("aviso restos de la VPN: strongSwan (charon) sigue escuchando en UDP 500 y 4500", self.salida)
        self.assertIn("sudo systemctl disable --now strongswan.service", self.salida)
        self.assertIn("sudo rm /etc/nginx/sites-available/hehermes /etc/nginx/sites-available/hehermes-tunel.antes-de-gzip",
                      self.salida)
        self.assertIn("sudo systemctl disable --now nginx", self.salida)
        self.assertNotIn("hermes-dash", self.salida, "lo que no es de HeHermes no se nombra")
        self.assertEqual(self.sis.foto(), antes, "no quita nada")
        self.assertFalse([o for o in self.sis.ordenes if o[:2] in (["systemctl", "disable"], ["rm"])])
        self.sis.enlazar("/etc/nginx/sites-enabled/hehermes", "/etc/nginx/sites-available/hehermes")
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   restos de la VPN: nginx tiene habilitado /etc/nginx/sites-enabled/hehermes", self.salida)
        # Sin restos, nada.
        self.falso.udp.clear()
        for ruta in ("/etc/nginx/sites-enabled/hehermes", "/etc/nginx/sites-available/hehermes",
                     "/etc/nginx/sites-available/hehermes-tunel.antes-de-gzip"):
            self.sis.borrar(ruta)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertNotIn("restos de la VPN", self.salida)

    def test_el_alcance_por_la_direccion_del_qr(self):
        """Además de 127.0.0.1, la dirección del QR, como la vería la app (auditoría §7)."""
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn((61234, None, sf.IP_PUBLICA), self.falso.sondas, "se asoma también por la dirección del QR")
        self.assertIn("bien  alcance: 198.51.100.23:61234 contesta, con el certificado del QR", "\n".join(
            self.texto) if self.orden("comprobar") == 0 else self.salida)
        self.assertIn("cortafuegos de tu proveedor", self.salida)
        # La dirección es de este servidor y no contesta por ella: mal (y por chat no se daría el enlace).
        sonda = self.falso.sonda
        self.sis._sonda = lambda puerto, maxima=None, anfitrion=None, plazo=None: (
            None if anfitrion else sonda(puerto, maxima))
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   alcance: la pasarela no contesta en 198.51.100.23:61234, que es una dirección de este",
                      self.salida)
        self.sis._sonda = sonda

    def test_el_alcance_detras_de_un_nat(self):
        """La dirección del QR no es de este servidor: si el NAT reenvía (y deja probar desde dentro), bien; si no, no
        se sabe, y se dice qué abrir; si lleva a otra máquina, mal."""
        self.falso.direccion_salida = "10.0.0.5"
        self.falso.enlaces_ip = {"eth0": {"ifname": "eth0", "addr": ["10.0.0.5/24"]}}
        self.assertEqual(self.orden("instalar", "--si", "--direccion", "203.0.113.50", terminal=False), 0,
                         self.salida)
        self.assertIn("alcance (aviso): no llego a 203.0.113.50:61234 desde dentro", self.salida)
        self.assertIn("Tu router o tu proveedor tienen que llevar el TCP 61234 a este servidor", self.salida)
        self.falso.alcance = "reenvía"
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("alcance: 203.0.113.50:61234 contesta a través de tu NAT", self.salida)
        self.falso.alcance = "otro"
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   alcance: en 203.0.113.50:61234 contesta otro certificado", self.salida)

    def test_por_chat_si_la_direccion_lleva_a_otra_maquina_no_hay_enlace(self):
        self.falso.direccion_salida = "10.0.0.5"
        self.falso.enlaces_ip = {"eth0": {"ifname": "eth0", "addr": ["10.0.0.5/24"]}}
        self.falso.alcance = "otro"
        codigo = self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE,
                            "--direccion", "203.0.113.50", terminal=False)
        self.assertEqual(codigo, 1, self.salida)
        self.assertIn("contesta otro certificado", self.salida)
        self.assertNotIn("hehermes-canje:", self.salida)

    def test_la_clave_nueva_de_hermes_llega_a_la_pasarela(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        env = self.sis.leer_texto("/root/.hermes/.env").replace(sf.CLAVE, "clave-nueva-de-hermes")
        self.sis.poner("/root/.hermes/.env", env, modo=0o600)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("su copia de la clave de Hermes es vieja", self.salida)
        self.assertEqual(self.orden("pasarela-clave"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto("/etc/hehermes-pasarela/clave-hermes"), "clave-nueva-de-hermes\n")
        self.assertEqual(self.sis.modo("/etc/hehermes-pasarela/clave-hermes"), 0o600)
        self.assertEqual(self.falso.dueños.get("/etc/hehermes-pasarela/clave-hermes"), "hh-pasarela:hh-pasarela")
        # Sin reiniciarla: la lee sola (y los SSE abiertos siguen).
        self.assertNotIn("hehermes-pasarela", self.falso.reinicios)
        self.assertIn("sin reiniciarla", self.salida)
        self.assertNotIn("clave-nueva-de-hermes", self.salida)

    def test_desinstalar_lo_deja_como_estaba(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("iPhone de la pasarela (sus tokens dejan de valer): mi-iphone", self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertEqual(self.falso.usuarios_sistema, set())
        self.assertNotIn("hehermes-pasarela", self.falso.activos)
        self.assertEqual([r for r in self.falso.reglas_ufw if "hehermes" in r], [])


class AlLadoDeLaVPNDeDaniel(Base):
    """El VPS de Daniel: una VPN montada a mano, sin manifiesto. La pasarela se instala al lado sin tocarla."""

    def servidor(self):
        return sf.servidor_de_daniel()

    RUTAS_DE_DANIEL = ("/etc/nginx", "/etc/swanctl", "/usr/local/sbin/hehermes-dispositivo", "/etc/wireguard",
                       "/etc/systemd/system/nginx.service.d")

    def de_daniel(self):
        return {r: v for r, v in self.sis.foto().items() if r.startswith(self.RUTAS_DE_DANIEL)}

    def test_el_plan_sigue_y_dice_que_convive(self):
        self.assertEqual(self.orden("instalar", "--plan", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertIn("Aquí hay una VPN de HeHermes", self.salida)
        self.assertIn("las dos conviven", self.salida)
        self.assertIn("/usr/local/sbin/hehermes-dispositivo no es mío: no lo toco", self.salida)
        self.assertIn("/opt/hehermes-servidor/hehermes-dispositivo alta <nombre>", self.salida)
        self.assertNotIn("No puedo seguir", self.salida)

    def test_instalar_y_desinstalar_no_tocan_nada_suyo(self):
        antes = self.de_daniel()
        reglas = list(self.falso.reglas_ufw)
        self.falso.ufw = "activo"
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertEqual(self.de_daniel(), antes)
        self.assertFalse([o for o in self.sis.ordenes if o[0].rsplit("/", 1)[-1] in DE_LA_VPN])
        self.assertFalse(self.sis.existe("/etc/hehermes/servidor.ini"))
        self.assertIn("hehermes-pasarela", self.falso.activos)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.de_daniel(), antes)
        self.assertEqual(self.falso.reglas_ufw, reglas)
        self.assertFalse([o for o in self.sis.ordenes if o[0].rsplit("/", 1)[-1] in DE_LA_VPN])


class PorChatConRoot(Base):
    def test_el_canje_entrega_h_p_f_t(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        codigo = self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE,
                            terminal=False)
        self.assertEqual(codigo, 0, self.salida)
        ultima = self.texto[-1]
        self.assertRegex(ultima, r"^hehermes-canje:1\?h=198\.51\.100\.23&p=\d+&c=[A-Za-z0-9_-]{22}&f=[A-Za-z0-9_-]{43}$")
        carga = json.loads(self.sis.leer("/run/hehermes-canje/canje.json"))["carga"]
        self.assertEqual(list(carga), ["h", "p", "f", "t"])
        self.assertEqual((carga["h"], carga["p"], carga["f"]), ("198.51.100.23", 61234, sf.HUELLA_PASARELA))
        self.assertEqual(pa.Tokens(self.sis.ruta("/etc/hehermes-pasarela/tokens.json")).quien(carga["t"]), "mi-iphone")
        self.assertNotIn(carga["t"], self.salida)
        self.assertNotIn("▀", self.salida)
        self.assertNotIn("hehermes-error", self.salida)
        self.assertTrue([o for o in self.falso.lanzados if "DynamicUser=yes" in o])

    def test_repetirlo_da_otro_token_y_el_de_antes_no_vale(self):
        argv = ("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE)
        self.assertEqual(self.orden(*argv, terminal=False), 0, self.salida)
        primero = json.loads(self.sis.leer("/run/hehermes-canje/canje.json"))["carga"]["t"]
        self.falso.activos.discard("hehermes-canje")
        self.assertEqual(self.orden(*argv, terminal=False), 0, self.salida)
        segundo = json.loads(self.sis.leer("/run/hehermes-canje/canje.json"))["carga"]["t"]
        self.assertNotEqual(primero, segundo)
        tokens = pa.Tokens(self.sis.ruta("/etc/hehermes-pasarela/tokens.json"))
        self.assertIsNone(tokens.quien(primero))
        self.assertEqual(tokens.quien(segundo), "mi-iphone")

    def test_solo_el_primer_iphone(self):
        self.assertEqual(self.orden("instalar", "--iphone", "otro"), 0, self.salida)
        codigo = self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE, terminal=False)
        self.assertEqual(codigo, 1)
        self.assertIn("Por chat solo se conecta el primer iPhone, y aquí ya hay: otro. El siguiente, desde la app o "
                      "por SSH (hehermes-dispositivo alta <nombre>)", self.salida)


class SinRoot(Base):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)
    CASA = "/home/hermes"

    def servidor(self):
        sis, falso = sf.servidor(usuario="hermes")
        # La carpeta que systemd le da a cada usuario con sesión o linger (XDG_RUNTIME_DIR).
        sis.carpeta("/run/user/1000", 0o700)
        return sis, falso

    def test_instala_en_su_casa_sin_paquetes_ni_cortafuegos(self):
        suyo = (self.CASA, "/run/user/1000/")
        antes_fuera = {r: v for r, v in self.sis.foto().items() if not r.startswith(suyo)}
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        despues_fuera = {r: v for r, v in self.sis.foto().items() if not r.startswith(suyo)}
        self.assertEqual(despues_fuera, antes_fuera, "sin root no se escribe nada fuera de su casa")
        self.assertIn("sin root (como hermes, en su casa)", self.salida)
        self.assertIn("ni miro ni toco el cortafuegos", self.salida)
        for prohibida in (["apt-get"], ["useradd"], ["ufw"], ["nft"], ["iptables"], ["firewall-cmd"], ["chown"]):
            self.assertFalse([o for o in self.sis.ordenes if o[:1] == prohibida], prohibida)
        self.assertEqual([o for o in self.sis.ordenes if o[:1] == ["sudo"]], [["sudo", "-n", "true"]])
        self.assertIn("hehermes-pasarela", self.falso.activos_usuario)
        self.assertNotIn("hehermes-pasarela", self.falso.activos)
        unidad = self.sis.leer_texto(self.CASA + "/.config/systemd/user/hehermes-pasarela.service")
        self.assertIn("ExecStart=/usr/bin/python3 -I -B /home/hermes/.local/share/hehermes-servidor/hehermes-pasarela",
                      unidad)
        ini = self.sis.leer_texto(self.CASA + "/.config/hehermes-pasarela/pasarela.ini")
        self.assertIn("clave = /home/hermes/.hermes/.env\n", ini)
        self.assertEqual(self.sis.modo(self.CASA + "/.config/hehermes-pasarela/tokens.json"), 0o600)
        self.assertEqual(self.sis.enlace(self.CASA + "/.local/bin/hehermes-servidor"),
                         self.CASA + "/.local/share/hehermes-servidor/hehermes-servidor")
        self.assertTrue(self.sis.existe(self.CASA + "/.local/bin/hehermes-dispositivo"))
        self.assertEqual([t["nombre"] for t in self.tokens(self.CASA + "/.config/hehermes-pasarela/tokens.json")],
                         ["mi-iphone"])
        self.assertIn("▀", self.salida)
        self.assertEqual(self.manifiesto(self.CASA + "/.config/hehermes/instalacion.json")["modos"], ["tls"])

    def test_repetir_y_comprobar_como_el_usuario(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
        self.assertFalse([o for o in self.ordenes_de(desde) if cambia(o)])
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("bien  pasarela: en marcha", self.salida)
        self.assertNotIn("sudo -n", " ".join(" ".join(o) for o in self.ordenes_de(desde)))

    def test_sin_linger_pero_con_sesion_avisa(self):
        self.falso.linger = False
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("sudo loginctl enable-linger hermes", self.salida)

    def test_por_chat_sin_linger_no_da_el_enlace(self):
        """El iPhone quedaría emparejado con una pasarela que se para al cerrarse la sesión: por chat no se da el
        enlace, se para antes de tocar nada y la última línea es la que lee la app."""
        self.falso.linger = False
        antes = self.sis.foto()
        codigo = self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE,
                            terminal=False)
        self.assertEqual(codigo, 1, self.salida)
        self.assertEqual(self.texto[-1], "\nhehermes-error:linger")
        self.assertIn("sudo loginctl enable-linger hermes", self.salida)
        self.assertIn("No he tocado nada", self.salida)
        self.assertNotIn("hehermes-canje:", self.salida)
        self.assertEqual(self.falso.lingers_pedidos, ["hermes"], "antes de pararse, prueba a encenderlo")
        self.assertEqual(self.sis.foto(), antes)

    def test_por_chat_sin_linger_lo_enciende_si_le_dejan(self):
        self.falso.linger = False
        self.falso.puede_linger = True
        codigo = self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE,
                            terminal=False)
        self.assertEqual(codigo, 0, self.salida)
        self.assertIn("He encendido linger para hermes", self.salida)
        self.assertTrue(self.texto[-1].startswith("hehermes-canje:1?"), self.texto[-1])

    def test_por_chat_con_plan_no_enciende_nada(self):
        self.falso.linger = False
        self.falso.puede_linger = True
        self.assertEqual(self.orden("instalar", "--plan", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE,
                                    terminal=False), 0, self.salida)
        self.assertEqual(self.falso.lingers_pedidos, [])
        self.assertIn("probaré a encenderlo", self.salida)

    def test_sin_gestor_de_usuario_se_para_y_lo_dice(self):
        self.falso.linger = False
        self.falso.gestor_usuario = False
        self.assertEqual(self.orden("instalar", "--plan"), 1)
        self.assertIn("No me invento otro arranque", self.salida)

    def test_sin_ensurepip_se_para_y_lo_dice(self):
        self.falso.ensurepip = False
        self.assertEqual(self.orden("instalar", "--plan"), 1)
        self.assertIn("sudo apt install python3-venv", self.salida)

    def test_con_sudo_sin_contrasena_se_relanza_como_root(self):
        self.falso.sudo = "sin-contrasena"
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0)
        self.assertEqual(len(self.relanzados), 1)
        self.assertEqual(self.relanzados[0][:5], ["sudo", "-n", "-u", "root", "--"])

    def test_la_vpn_ya_no_existe_ni_sin_root(self):
        """Antes, sin root, `--modo vpn` por chat acababa en `hehermes-error:sin-permisos`. Ya no hay VPN que instalar:
        se dice, sin preguntarle nada a sudo y sin esa línea."""
        codigo = self.orden("instalar", "--modo", "vpn", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE,
                            terminal=False)
        self.assertEqual(codigo, 2)
        self.assertEqual(self.texto, [cli.SIN_VPN])
        self.assertNotIn("hehermes-error", self.salida)
        self.assertEqual(self.sis.ordenes, [])
        self.assertEqual(self.relanzados, [])

    def test_por_chat_sin_root_el_canje_es_suyo(self):
        codigo = self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE,
                            terminal=False)
        self.assertEqual(codigo, 0, self.salida)
        self.assertTrue(self.texto[-1].startswith("hehermes-canje:1?h=198.51.100.23&p="), self.texto[-1])
        self.assertNotIn("hehermes-error", self.salida)
        carga = json.loads(self.sis.leer("/run/user/1000/hehermes-canje/canje.json"))["carga"]
        self.assertEqual((carga["p"], carga["f"]), (61234, sf.HUELLA_PASARELA))
        tokens = pa.Tokens(self.sis.ruta(self.CASA + "/.config/hehermes-pasarela/tokens.json"))
        self.assertEqual(tokens.quien(carga["t"]), "mi-iphone")
        lanzado = self.falso.lanzados[-1]
        self.assertIn("--user", lanzado)
        self.assertNotIn("DynamicUser=yes", lanzado)
        self.assertEqual(lanzado[-2:], ["--carpeta", "/run/user/1000/hehermes-canje"])
        self.assertIn("Sin root no toco el cortafuegos", self.salida)
        self.assertNotIn(carga["t"], self.salida)

    def test_desinstalar_lo_deja_como_estaba(self):
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertNotIn("hehermes-pasarela", self.falso.activos_usuario)


class ElCodigoNuevo(Base):
    """Actualizar sobre una instalación de antes: el código que cambia reinicia, una vez, el servicio que lo tiene
    cargado (la pasarela, el vigía), con root y sin él. En el VPS de Daniel, la 0.10.0 sobre la 0.9.0 reescribió
    /opt/hehermes-servidor y dejó la pasarela corriendo con el código de antes (el tope de 64 KiB del respaldo)."""

    def prefijo(self):
        return "/opt/hehermes-servidor"

    def manifiesto_de(self):
        return "/etc/hehermes/instalacion.json"

    def reinicios(self, unidad):
        return [o for o in self.sis.ordenes if [a for a in o if a != "--user"][:2] == ["systemctl", "restart"]
                and o[-1] == unidad]

    def de_antes(self, relativa):
        """Deja en disco (y en el manifiesto, como suyo) una versión anterior de un fichero de código: lo que hay
        tras una instalación de la versión de antes."""
        from hehermes_servidor.sistema import sha256
        ruta = self.prefijo() + "/" + relativa
        viejo = self.sis.leer(ruta) + b"\n# la version de antes\n"
        self.sis.escribir(ruta, viejo, modo=self.sis.modo(ruta))
        man = self.manifiesto(self.manifiesto_de())
        man["ficheros"][ruta]["sha256"] = sha256(viejo)
        self.sis.escribir(self.manifiesto_de(), json.dumps(man).encode(), modo=self.sis.modo(self.manifiesto_de()))

    def instalado(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        return len(self.sis.ordenes)

    def test_el_codigo_de_la_pasarela_cambia_y_se_reinicia_una_vez(self):
        self.instalado()
        self.de_antes("hehermes_servidor/pasarela.py")
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("se reinicia la pasarela: su código cambia", self.salida)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(len([o for o in self.reinicios("hehermes-pasarela.service")
                              if o in self.ordenes_de(desde)]), 1)
        self.assertIn("se reinicia la pasarela: su código cambia", self.salida)
        # El vigía también carga hehermes_servidor (la clave de Hermes, de hehermes_servidor.pasarela).
        self.assertEqual(len([o for o in self.reinicios("hehermes-vigia.service") if o in self.ordenes_de(desde)]), 1)
        self.assertNotIn("reinicios_pendientes", self.manifiesto(self.manifiesto_de()))
        # Y repetir: nada que reiniciar.
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
        self.assertFalse([o for o in self.ordenes_de(desde) if cambia(o)])

    def test_el_del_vigia_solo_reinicia_el_vigia(self):
        self.instalado()
        self.de_antes("hehermes_avisos/vigia/respaldo.py")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertIn("se reinicia el vigía: su código cambia", self.salida)
        self.assertEqual(len([o for o in self.reinicios("hehermes-vigia.service") if o in self.ordenes_de(desde)]), 1)
        self.assertFalse([o for o in self.reinicios("hehermes-pasarela.service") if o in self.ordenes_de(desde)])

    def test_lo_que_arranca_uno_por_conexion_no_reinicia_nada(self):
        # El lector, los ayudantes de la copia y de la entrada y hehermes-dispositivo se lanzan de nuevo cada vez: cogen
        # el código solos.
        self.instalado()
        for relativa in ("hehermes-leer-media", "hehermes-respaldo", "hehermes-entrada", "hehermes-dispositivo"):
            if self.sis.existe(self.prefijo() + "/" + relativa):
                self.de_antes(relativa)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertFalse([o for o in self.ordenes_de(desde)
                          if [a for a in o if a != "--user"][:2] == ["systemctl", "restart"]])

    def test_parada_en_medio_repetir_la_reinicia_igual(self):
        # El código se escribe y luego falla otro paso antes de reiniciar: el código ya «está», pero la pasarela sigue
        # con el de antes. Lo recuerda el manifiesto.
        self.instalado()
        self.de_antes("hehermes_servidor/pasarela.py")
        with mock.patch.object(porchat, "_venv", side_effect=porchat.ParadaDelCanje("sin pip")):
            self.assertNotEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertFalse(self.reinicios("hehermes-pasarela.service"))
        self.assertIn("hehermes-pasarela.service", self.manifiesto(self.manifiesto_de())["reinicios_pendientes"])
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(len([o for o in self.reinicios("hehermes-pasarela.service")
                              if o in self.ordenes_de(desde)]), 1)
        self.assertNotIn("reinicios_pendientes", self.manifiesto(self.manifiesto_de()))

    def test_parada_no_arranca_la_que_estaba_parada(self):
        # Parada (y habilitada o no): se arranca, como siempre, y ya con el código nuevo; nada de reiniciar.
        self.instalado()
        self.de_antes("hehermes_servidor/pasarela.py")
        self.parar("hehermes-pasarela")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertFalse([o for o in self.reinicios("hehermes-pasarela.service") if o in self.ordenes_de(desde)])
        self.assertTrue(self.en_marcha("hehermes-pasarela"))

    def test_en_marcha_sin_habilitar_se_habilita_y_se_reinicia(self):
        self.instalado()
        self.de_antes("hehermes_servidor/pasarela.py")
        self.deshabilitar("hehermes-pasarela")
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertEqual(len([o for o in self.reinicios("hehermes-pasarela.service")
                              if o in self.ordenes_de(desde)]), 1)

    def parar(self, unidad):
        self.falso.activos.discard(unidad)

    def deshabilitar(self, unidad):
        self.falso.habilitados.discard(unidad)

    def en_marcha(self, unidad):
        return unidad in self.falso.activos


class ElCodigoNuevoSinRoot(ElCodigoNuevo):
    euid = 1000
    cuenta = ("hermes", "/home/hermes", 1000)

    def servidor(self):
        return SinRoot.servidor(self)

    def prefijo(self):
        return "/home/hermes/.local/share/hehermes-servidor"

    def manifiesto_de(self):
        return "/home/hermes/.config/hehermes/instalacion.json"

    def reinicios(self, unidad):
        return [o for o in self.sis.ordenes if o[:3] == ["systemctl", "--user", "restart"] and o[-1] == unidad]

    def parar(self, unidad):
        self.falso.activos_usuario.discard(unidad)

    def deshabilitar(self, unidad):
        self.falso.habilitados_usuario.discard(unidad)

    def en_marcha(self, unidad):
        return unidad in self.falso.activos_usuario


if __name__ == "__main__":
    unittest.main()
