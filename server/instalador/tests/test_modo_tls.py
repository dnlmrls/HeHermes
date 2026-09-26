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
        self.assertEqual(self.falso.usuarios_sistema, {"hh-pasarela"})
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
        self.sis.poner("/etc/hehermes-avisos/vigia/secreto-tunel", "s" * 43 + "\n", modo=0o600)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        unidad = self.sis.leer_texto("/etc/systemd/system/hehermes-pasarela.service")
        self.assertIn("LoadCredential=vigia:/etc/hehermes-avisos/vigia/secreto-tunel\n", unidad)
        self.assertIn("vigia = 127.0.0.1:8790\n", self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"))

    def test_avisos_ya_no_es_una_opcion(self):
        """--avisos solo iba con la VPN (su instalador necesita el nginx del túnel), y se fue con ella."""
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--avisos"), 2)
        self.assertIn("--avisos", self.salida)
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
        self.falso.sonda = lambda puerto, maxima=None: {"tls": "TLSv1.3", "huella": "otra",
                                                         "respuesta": b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n"}
        self.sis._sonda = self.falso.sonda
        self.sis.poner("/etc/hehermes-pasarela/tokens.json", '{"v": 1, "tokens": []}', modo=0o644)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   pasarela: sirve otro certificado", self.salida)
        self.assertIn("MAL   pasarela: sin token contesta con una cabecera Server", self.salida)
        self.assertIn("MAL   pasarela: acepta algo más viejo que TLS 1.3", self.salida)
        self.assertIn("MAL   secretos que se pueden leer sin ser su dueño: /etc/hehermes-pasarela/tokens.json",
                      self.salida)

    def test_la_clave_nueva_de_hermes_llega_a_la_pasarela(self):
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        env = self.sis.leer_texto("/root/.hermes/.env").replace(sf.CLAVE, "clave-nueva-de-hermes")
        self.sis.poner("/root/.hermes/.env", env, modo=0o600)
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("su copia de la clave de Hermes es vieja", self.salida)
        self.assertEqual(self.orden("pasarela-clave"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto("/etc/hehermes-pasarela/clave-hermes"), "clave-nueva-de-hermes\n")
        self.assertIn("hehermes-pasarela", self.falso.reinicios)
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


if __name__ == "__main__":
    unittest.main()
