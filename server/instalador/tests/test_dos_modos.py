"""La pasarela y la VPN IKEv2 de antes de la 0.6.0 en una misma instalación, contra el servidor falso: la pasarela sobre
una VPN de antes, repetir y `comprobar` con las dos, y quitar la VPN (`desinstalar --modo vpn`) dejando la pasarela
como estaba, byte a byte.

Desde la 0.6.0 la VPN ya no se instala: se monta como la dejaba la 0.5.1 (`vpn_antigua`). Es lo de un servidor con la
VPN del instalador y `mi-iphone`, que pasa a la pasarela sin quedarse sin conexión por el camino.
"""

import apoyo  # noqa: F401

import json
import unittest

import servidor_falso as sf
import vpn_antigua
from hehermes_servidor import cli
from hehermes_servidor import desinstalar as des
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import Manifiesto
from test_modo_tls import DE_LA_VPN, LLAVE, Base, cambia

MANIFIESTO = "/etc/hehermes/instalacion.json"
REGLA_TLS = "ufw allow proto tcp from any to any port 61234 comment hehermes"
REGLAS_VPN = vpn_antigua.REGLAS_UFW


class Ayudas(Base):
    def servidor(self):
        return vpn_antigua.servidor()

    def vpn(self, **opciones):
        vpn_antigua.montar(self.sis, self.falso, **opciones)

    def tls(self, *extra):
        self.assertEqual(self.orden("instalar", "--iphone", "iphone-tls", *extra), 0, self.salida)

    def foto(self):
        """Todo menos el manifiesto, que se compara aparte (`lo_que_apunta`)."""
        return {r: v for r, v in self.sis.foto().items() if r != MANIFIESTO}

    def lo_que_apunta(self):
        man = self.manifiesto()
        return {"ficheros": man["ficheros"], "reglas": man["reglas"], "unidades": man["unidades"],
                "carpetas": sorted(man["carpetas"]), "modos": man["modos"], "pasarela": man.get("pasarela"),
                "usuarios": man.get("usuarios") or [], "dispositivos": man["dispositivos"]}


class ConLasDos(Ayudas):
    # La pasarela al lado de la VPN de antes

    def test_la_pasarela_sobre_la_vpn_no_toca_la_vpn(self):
        self.vpn()
        de_la_vpn = self.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--iphone", "iphone-tls"), 0, self.salida)
        self.assertIn("Aquí sigue la VPN IKEv2 que instaló una versión anterior (/etc/hehermes/instalacion.json)",
                      self.salida)
        self.assertIn("al lado de la VPN IKEv2 de antes (no la toco)", self.salida)
        self.assertNotIn("No puedo seguir", self.salida)
        desde = len(self.sis.ordenes)
        self.tls()
        self.assertFalse([o for o in self.ordenes_de(desde) if o[0].rsplit("/", 1)[-1] in DE_LA_VPN])
        despues = self.foto()
        self.assertEqual({r: v for r, v in despues.items() if r in de_la_vpn}, de_la_vpn,
                         "lo de la VPN, byte a byte como estaba")
        self.assertEqual(self.manifiesto()["modos"], ["vpn", "tls"])
        self.assertEqual([t["nombre"] for t in self.tokens()], ["iphone-tls"])
        self.assertEqual([d["nombre"] for d in json.loads(self.sis.leer(self.falso.dispositivos_json))["dispositivos"]],
                         ["mi-iphone"])
        self.assertEqual(self.falso.reglas_ufw, ["ufw allow 22/tcp"] + REGLAS_VPN + [REGLA_TLS])
        self.assertTrue({"hehermes-pasarela", "hehermes-xfrm", "hehermes-clave.path"} <= self.falso.activos)

    def test_sobre_un_manifiesto_de_antes_sin_modos(self):
        """Uno de antes de la pasarela (0.4): no lleva ni `modos` ni `modo`, y es de la VPN."""
        self.vpn(sin_modos=True)
        self.assertNotIn("modos", self.manifiesto())
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("al lado de la VPN IKEv2 de antes (no la toco)", self.salida)
        self.assertNotIn("Modo       VPN", self.salida)
        self.tls()
        self.assertEqual(self.manifiesto()["modos"], ["vpn", "tls"])
        self.assertNotIn("modo", self.manifiesto())

    def test_repetir_solo_repasa_la_pasarela_y_no_cambia_nada(self):
        self.vpn()
        self.tls()
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        self.assertEqual(self.salida.count("Todo al día: 0 cambios"), 1, self.salida)
        self.assertEqual(self.salida.count("Modo  "), 1, self.salida)
        self.assertIn("Modo       TLS: la pasarela, en el TCP 61234, al lado", self.salida)
        self.assertIn("ya no la instalo ni la reparo", self.salida)
        self.assertFalse([o for o in self.ordenes_de(desde) if cambia(o)])

    def test_repetir_repara_la_pasarela_y_no_la_vpn(self):
        self.vpn()
        self.tls()
        self.sis.borrar(p.UNIDAD_XFRM)
        self.sis.borrar("/etc/hehermes-pasarela/pasarela.ini")
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertTrue(self.sis.existe("/etc/hehermes-pasarela/pasarela.ini"))
        self.assertFalse(self.sis.existe(p.UNIDAD_XFRM), "la VPN ya no se repara")

    def test_un_iphone_va_a_la_pasarela(self):
        self.vpn()
        self.tls()
        self.assertEqual(self.orden("instalar", "--iphone", "otro"), 0, self.salida)
        self.assertEqual([t["nombre"] for t in self.tokens()], ["iphone-tls", "otro"])
        self.assertEqual([a[1] for a in self.falso.altas], ["mi-iphone"], "ninguna alta IKEv2 más")

    def test_por_chat_con_las_dos_va_a_la_pasarela(self):
        self.vpn(iphones=(), hace=60)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        codigo = self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE, terminal=False)
        self.assertEqual(codigo, 0, self.salida)
        self.assertTrue(self.texto[-1].startswith("hehermes-canje:1?"), self.texto[-1])
        carga = json.loads(self.sis.leer("/run/hehermes-canje/canje.json"))["carga"]
        self.assertEqual(list(carga), ["h", "p", "f", "t"])
        self.assertEqual(self.falso.altas, [], "ninguna alta IKEv2")

    def test_por_chat_el_primer_iphone_es_el_del_servidor_no_el_de_la_pasarela(self):
        """Con un iPhone en la VPN de antes, un alta por chat en la pasarela sería un segundo iPhone."""
        self.vpn(hace=60)
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        codigo = self.orden("instalar", "--por-chat", "--iphone", "otro", "--llave", LLAVE, terminal=False)
        self.assertEqual(codigo, 1)
        self.assertIn("Por chat solo se conecta el primer iPhone, y aquí ya hay: mi-iphone. El siguiente, desde la "
                      "app o por SSH (hehermes-dispositivo alta <nombre>)", self.salida)
        self.assertEqual(self.tokens(), [])

    # comprobar

    def test_comprobar_con_las_dos(self):
        self.vpn()
        self.tls()
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        for linea in ("bien  pasarela: en marcha", "bien  pasarela: escucha en el TCP 61234",
                      "bien  pasarela: su certificado es el del QR", "bien  ufw: la regla de la pasarela está",
                      "bien  pasarela: su copia de la clave de Hermes está al día",
                      "aviso " + cli.VPN_DE_ANTES,
                      # Seguridad: la de la VPN también, mientras esté.
                      "bien  la API de Hermes solo escucha en 127.0.0.1:8642",
                      "bien  nginx: el sitio del túnel solo escucha en 10.77.0.1:80",
                      "bien  pasarela: solo TLS 1.3", "bien  pasarela: como hh-pasarela",
                      "bien  secretos: la PSK de cada iPhone", "bien  secretos: la clave del certificado",
                      "bien  IKEv2: 1 conexión", "bien  cortafuegos: ufw, en marcha"):
            self.assertIn(linea, self.salida)
        # Lo de la VPN ya no se comprueba como algo que tenga que estar en marcha: no se repara.
        for de_la_vpn in ("strongSwan:", "hh-ipsec:", "túnel:", "nginx: en marcha"):
            self.assertNotIn(de_la_vpn, self.salida)
        for una_vez in ("Hermes: contesta con su clave", "cortafuegos: ufw, en marcha", "canje: ninguno abierto",
                        "la API de Hermes solo escucha", "actualizar: la clave de las firmas"):
            self.assertEqual(self.salida.count(una_vez), 1, una_vez)

    def test_comprobar_ve_lo_que_falla_en_la_pasarela(self):
        self.vpn()
        self.tls()
        self.falso._parar("hehermes-pasarela")
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   pasarela: parada", self.salida)

    def test_comprobar_con_solo_la_vpn_dice_que_falta_la_pasarela(self):
        self.vpn()
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   pasarela: no está instalada. La conexión directa se instala con: sudo hehermes-servidor "
                      "instalar", self.salida)
        self.assertIn("aviso " + cli.VPN_DE_ANTES, self.salida)
        self.assertNotIn("strongSwan:", self.salida)

    # Quitar un modo

    def test_quitar_la_vpn_deja_la_pasarela_byte_a_byte(self):
        self.tls()
        solo_la_pasarela, apuntado = self.foto(), self.lo_que_apunta()
        self.vpn()
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertIn("Voy a quitar la VPN IKEv2, y nada más", self.salida)
        self.assertIn("Queda la pasarela TLS, como estaba.", self.salida)
        self.assertNotIn("Se queda", self.salida)
        self.assertEqual(self.foto(), solo_la_pasarela)
        self.assertEqual(self.lo_que_apunta(), apuntado)
        self.assertEqual(self.falso.reglas_ufw, ["ufw allow 22/tcp", REGLA_TLS])
        self.assertIn(["/usr/local/sbin/hehermes-dispositivo", "baja", "mi-iphone"], self.sis.ordenes)
        self.assertNotIn("hh-ipsec", self.falso.enlaces_ip)
        self.assertIn("hehermes-pasarela", self.falso.activos)
        self.assertFalse({"hehermes-xfrm", "hehermes-clave.path"} & self.falso.activos)
        self.assertEqual([t["nombre"] for t in self.tokens()], ["iphone-tls"])
        # Y lo que queda se repite sin cambiar nada, y ya no se habla de la VPN.
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
        self.assertNotIn("VPN", self.salida)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertNotIn(cli.VPN_DE_ANTES, self.salida)

    def test_quitar_la_vpn_que_estaba_antes_que_la_pasarela(self):
        """El orden de verdad: la VPN de antes, la pasarela de la 0.6.0 a su lado, y luego fuera la VPN."""
        self.vpn()
        self.tls()
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertEqual(self.manifiesto()["modos"], ["tls"])
        for ruta in vpn_antigua.FICHEROS:
            self.assertFalse(self.sis.existe(ruta), ruta)
            self.assertNotIn(ruta, self.manifiesto()["ficheros"])
        self.assertFalse(self.sis.existe(p.REGISTRO))
        self.assertEqual(self.falso.reglas_ufw, ["ufw allow 22/tcp", REGLA_TLS])
        self.assertEqual(self.orden("comprobar"), 0, self.salida)

    def test_quitar_la_pasarela_deja_la_vpn_byte_a_byte(self):
        self.vpn()
        solo_la_vpn, apuntado = self.foto(), self.lo_que_apunta()
        self.tls()
        self.assertEqual(self.orden("desinstalar", "--modo", "tls", "--si"), 0, self.salida)
        self.assertIn("Voy a quitar la pasarela TLS, y nada más", self.salida)
        self.assertIn("iPhone de la pasarela (sus tokens dejan de valer): iphone-tls", self.salida)
        self.assertIn("Queda la VPN IKEv2, como estaba.", self.salida)
        self.assertNotIn("Se queda", self.salida)
        self.assertEqual(self.foto(), solo_la_vpn)
        self.assertEqual(self.lo_que_apunta(), apuntado)
        self.assertEqual(self.falso.reglas_ufw, ["ufw allow 22/tcp"] + REGLAS_VPN)
        self.assertEqual(self.falso.usuarios_sistema, set())
        self.assertNotIn("hehermes-pasarela", self.falso.activos)
        self.assertIn("hh-ipsec", self.falso.enlaces_ip)
        self.assertFalse([o for o in self.sis.ordenes if o[:2] == ["/usr/local/sbin/hehermes-dispositivo", "baja"]])

    def test_quitar_un_modo_no_toca_lo_cambiado_del_otro(self):
        """Un fichero de la pasarela que alguien cambió a mano tampoco se toca al quitar la VPN."""
        self.vpn()
        self.tls()
        ini = self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini") + "# de Daniel\n"
        self.sis.poner("/etc/hehermes-pasarela/pasarela.ini", ini, modo=0o640)
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertEqual(self.sis.leer_texto("/etc/hehermes-pasarela/pasarela.ini"), ini)
        self.assertNotIn("pasarela.ini", self.salida)

    def test_quitar_la_vpn_deja_los_avisos_y_lo_dice(self):
        """Los avisos los instalaba la VPN, pero la pasarela también los sirve."""
        self.vpn(avisos=True)
        self.tls()
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertIn("los avisos (el vigía y el relé): los instalé con la VPN", self.salida)
        self.assertTrue(self.sis.existe("/usr/local/libexec/hehermes-leer-media"))
        self.assertIn("hehermes-vigia", self.falso.activos)
        self.assertTrue(self.manifiesto()["avisos"])
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe("/usr/local/libexec/hehermes-leer-media"))

    def test_desinstalar_sin_modo_quita_las_dos(self):
        antes, reglas = self.sis.foto(), list(self.falso.reglas_ufw)
        self.vpn()
        self.tls()
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("El servidor está como antes de instalar.", self.salida)
        self.assertEqual(self.sis.foto(), antes)
        self.assertEqual(self.falso.reglas_ufw, reglas)
        self.assertEqual(self.falso.usuarios_sistema, set())

    def test_un_modo_que_no_esta_no_se_quita(self):
        self.vpn()
        antes = self.sis.foto()
        self.assertEqual(self.orden("desinstalar", "--modo", "tls", "--si"), 0, self.salida)
        self.assertIn("En este servidor no instalé la pasarela TLS (lo que hay es la VPN IKEv2)", self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_el_unico_modo_es_todo(self):
        antes = self.sis.foto()
        self.vpn()
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertIn("La VPN IKEv2 es lo único que instalé aquí: lo quito todo.", self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_desinstalar_la_vpn_de_un_manifiesto_sin_modos(self):
        antes = self.sis.foto()
        self.vpn(sin_modos=True)
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertIn("La VPN IKEv2 es lo único que instalé aquí: lo quito todo.", self.salida)
        self.assertIn(["/usr/local/sbin/hehermes-dispositivo", "baja", "mi-iphone"], self.sis.ordenes)
        self.assertEqual(self.sis.foto(), antes)

    def test_el_resumen_de_un_modo_solo_dice_lo_suyo(self):
        self.vpn()
        self.tls()
        texto = des.resumen(self.sis, Manifiesto.leer(self.sis), modo="vpn")
        for suyo in (p.SITIO, p.UNIDAD_XFRM, p.SERVIDOR_INI, "mi-iphone", REGLAS_VPN[0], "hehermes-xfrm.service"):
            self.assertIn(suyo, texto)
        for del_otro in ("pasarela", "iphone-tls", "61234", "/opt/hehermes-servidor", "hehermes-cortafuegos",
                         "/usr/local/sbin/hehermes-dispositivo"):
            self.assertNotIn(del_otro, texto)
        texto = des.resumen(self.sis, Manifiesto.leer(self.sis), modo="tls")
        for suyo in ("/etc/hehermes-pasarela/tokens.json", "iphone-tls", REGLA_TLS, "hehermes-pasarela.service",
                     "el usuario hh-pasarela", "/opt/hehermes-canje"):
            self.assertIn(suyo, texto)
        for del_otro in ("nginx", "hh-ipsec", "mi-iphone", "500,4500", "/opt/hehermes-servidor", "servidor.ini"):
            self.assertNotIn(del_otro, texto)


class ConNftables(Ayudas):
    """Las reglas de la VPN de antes y las de la pasarela van con la misma marca: quitar una vuelve a dejar solo las de
    la otra."""

    def servidor(self):
        sis, falso = sf.servidor()
        for paquete in vpn_antigua.PAQUETES:
            falso.instalar_paquete(paquete)
        falso.con_nft([("inet", "mio", "entrada", "input", "drop")],
                      [("inet", "mio", "entrada", [{"match": "ct state established,related"}, {"accept": None}])])
        return sis, falso

    def nuestras(self):
        return [r["texto"] for r in self.falso.nft_reglas if r.get("comment") == "hehermes"]

    VPN = ["udp dport { 500, 4500 } accept", 'iifname "hh-ipsec" ip daddr 10.77.0.1 tcp dport 80 accept']
    TLS = ["tcp dport 61234 accept"]

    def test_las_reglas_de_las_dos_y_quitar_la_vpn(self):
        self.vpn()
        self.assertEqual(self.nuestras(), self.VPN)
        self.tls()
        self.assertEqual(self.nuestras(), self.VPN + self.TLS)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertEqual(self.orden("cortafuegos", "poner"), 0, self.salida)
        self.assertEqual(self.nuestras(), self.VPN + self.TLS, "mientras esté la VPN, tras un reinicio van las dos")
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertEqual(self.nuestras(), self.TLS)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)

    def test_quitar_la_pasarela_deja_las_de_la_vpn(self):
        self.tls()
        self.vpn()
        self.assertEqual(sorted(self.nuestras()), sorted(self.VPN + self.TLS))
        self.assertEqual(self.orden("desinstalar", "--modo", "tls", "--si"), 0, self.salida)
        self.assertEqual(self.nuestras(), self.VPN)


if __name__ == "__main__":
    unittest.main()
