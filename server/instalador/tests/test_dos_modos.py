"""Los dos modos en una misma instalación, contra el servidor falso: la pasarela sobre la VPN y la VPN sobre la
pasarela, `comprobar` con los dos, y quitar uno (`desinstalar --modo`) dejando el otro como estaba, byte a byte.

Es lo del VPS de Daniel: la VPN del instalador con `mi-iphone`, y la pasarela a su lado para probarla sin quitársela.
"""

import apoyo

import json
import unittest

import servidor_falso as sf
from hehermes_servidor import desinstalar as des
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import Manifiesto
from test_modo_tls import DE_LA_VPN, LLAVE, Base, cambia

MANIFIESTO = "/etc/hehermes/instalacion.json"
REGLA_TLS = "ufw allow proto tcp from any to any port 61234 comment hehermes"
REGLAS_VPN = ["ufw allow proto udp from any to any port 500,4500 comment hehermes",
              "ufw allow in on hh-ipsec proto tcp from any to 10.77.0.1 port 80 comment hehermes"]


class Ayudas(Base):
    def servidor(self):
        """Con los paquetes de la VPN ya puestos y ufw en marcha: así lo único que cambia en /etc es del instalador."""
        sis, falso = sf.servidor()
        for paquete in ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "qrencode", "nginx",
                        "ufw"):
            falso.instalar_paquete(paquete)
        falso.ufw = "activo"
        falso.reglas_ufw = ["ufw allow 22/tcp"]
        return sis, falso

    def vpn(self, *extra):
        self.assertEqual(self.orden("instalar", "--modo", "vpn", "--iphone", "mi-iphone", *extra), 0, self.salida)

    def tls(self, *extra):
        self.assertEqual(self.orden("instalar", "--modo", "tls", "--iphone", "iphone-tls", *extra), 0, self.salida)

    def foto(self):
        """Todo menos el manifiesto, que se compara aparte (`lo_que_apunta`)."""
        return {r: v for r, v in self.sis.foto().items() if r != MANIFIESTO}

    def lo_que_apunta(self):
        man = self.manifiesto()
        return {"ficheros": man["ficheros"], "reglas": man["reglas"], "unidades": man["unidades"],
                "carpetas": sorted(man["carpetas"]), "modos": man["modos"], "pasarela": man.get("pasarela"),
                "usuarios": man.get("usuarios") or [], "dispositivos": man["dispositivos"]}


class ConLosDos(Ayudas):
    # Añadir un modo al otro

    def test_la_pasarela_sobre_la_vpn_no_toca_la_vpn(self):
        self.vpn()
        de_la_vpn = self.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--modo", "tls", "--iphone", "iphone-tls"), 0, self.salida)
        self.assertIn("Aquí ya está la VPN IKEv2 que instalé (/etc/hehermes/instalacion.json)", self.salida)
        self.assertIn("al lado de la VPN IKEv2 (no la toco)", self.salida)
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
        """El del VPS de Daniel es de antes de la pasarela: no lleva ni `modos` ni `modo`, y es de la VPN."""
        self.vpn()
        viejo = self.manifiesto()
        del viejo["modos"]
        self.sis.poner(MANIFIESTO, json.dumps(viejo), modo=0o600)
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("Modo       VPN IKEv2\n", self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
        self.tls()
        self.assertEqual(self.manifiesto()["modos"], ["vpn", "tls"])
        self.assertNotIn("modo", self.manifiesto())

    def test_la_vpn_sobre_la_pasarela_no_toca_la_pasarela(self):
        self.tls()
        de_la_pasarela = self.foto()
        self.assertEqual(self.orden("instalar", "--plan", "--modo", "vpn"), 0, self.salida)
        self.assertIn("Modo       VPN IKEv2, al lado de la pasarela TLS (no la toco)", self.salida)
        self.vpn()
        despues = self.foto()
        self.assertEqual({r: v for r, v in despues.items() if r in de_la_pasarela}, de_la_pasarela,
                         "lo de la pasarela, byte a byte como estaba")
        self.assertEqual(self.manifiesto()["modos"], ["vpn", "tls"])
        self.assertEqual(self.manifiesto()["pasarela"]["puerto"], 61234)
        self.assertEqual([t["nombre"] for t in self.tokens()], ["iphone-tls"])

    def test_repetir_sin_modo_repasa_los_dos_y_no_cambia_nada(self):
        self.vpn()
        self.tls()
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        self.assertEqual(self.salida.count("Todo al día: 0 cambios"), 2, self.salida)
        self.assertIn("Modo       VPN IKEv2, al lado", self.salida)
        self.assertIn("Modo       TLS: la pasarela, en el TCP 61234, al lado", self.salida)
        self.assertFalse([o for o in self.ordenes_de(desde) if cambia(o)])

    def test_repetir_sin_modo_repara_los_dos(self):
        self.vpn()
        self.tls()
        self.sis.borrar(p.UNIDAD_XFRM)
        self.sis.borrar("/etc/hehermes-pasarela/pasarela.ini")
        self.assertEqual(self.orden("instalar", "--si", terminal=False), 0, self.salida)
        self.assertTrue(self.sis.existe(p.UNIDAD_XFRM))
        self.assertTrue(self.sis.existe("/etc/hehermes-pasarela/pasarela.ini"))

    def test_un_iphone_sin_modo_va_a_la_pasarela(self):
        self.vpn()
        self.tls()
        self.assertEqual(self.orden("instalar", "--iphone", "otro"), 0, self.salida)
        self.assertIn("«otro» va a la pasarela (TLS), el modo por defecto; para darlo de alta en la VPN: --modo vpn",
                      self.salida)
        self.assertEqual([t["nombre"] for t in self.tokens()], ["iphone-tls", "otro"])
        self.assertNotIn("otro", [a[1] for a in self.falso.altas])

    def test_por_chat_con_los_dos_va_a_la_pasarela(self):
        self.assertEqual(self.orden("instalar", "--si", "--modo", "vpn", terminal=False), 0, self.salida)
        self.assertEqual(self.orden("instalar", "--si", "--modo", "tls", terminal=False), 0, self.salida)
        codigo = self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE, terminal=False)
        self.assertEqual(codigo, 0, self.salida)
        self.assertTrue(self.texto[-1].startswith("hehermes-canje:1?"), self.texto[-1])
        carga = json.loads(self.sis.leer("/run/hehermes-canje/canje.json"))["carga"]
        self.assertEqual(list(carga), ["h", "p", "f", "t"])
        self.assertEqual(self.falso.altas, [], "ninguna alta IKEv2")

    def test_por_chat_el_primer_iphone_es_el_del_servidor_no_el_del_modo(self):
        """Con un iPhone en la VPN, un alta por chat en la pasarela sería un segundo iPhone."""
        self.vpn()
        self.assertEqual(self.orden("instalar", "--si", "--modo", "tls", terminal=False), 0, self.salida)
        codigo = self.orden("instalar", "--por-chat", "--iphone", "otro", "--llave", LLAVE, terminal=False)
        self.assertEqual(codigo, 1)
        self.assertIn("Por chat solo se conecta el primer iPhone, y aquí ya hay: mi-iphone. El siguiente, desde la "
                      "app o por SSH (hehermes-dispositivo alta <nombre> --tls)", self.salida)
        self.assertEqual(self.tokens(), [])

    # comprobar

    def test_comprobar_con_los_dos(self):
        self.vpn()
        self.tls()
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        for linea in ("bien  nginx: la configuración pasa nginx -t", "bien  strongSwan: swanctl habla con charon",
                      "bien  hh-ipsec: XFRM con if_id 0x77", "bien  ufw: las reglas de HeHermes están",
                      "bien  túnel: nginx escucha en 10.77.0.1", "bien  pasarela: en marcha",
                      "bien  pasarela: escucha en el TCP 61234", "bien  pasarela: su certificado es el del QR",
                      "bien  ufw: la regla de la pasarela está",
                      "bien  pasarela: su copia de la clave de Hermes está al día",
                      # Seguridad
                      "bien  la API de Hermes solo escucha en 127.0.0.1:8642",
                      "bien  nginx: el sitio del túnel solo escucha en 10.77.0.1:80",
                      "bien  pasarela: solo TLS 1.3", "bien  pasarela: como hh-pasarela",
                      "bien  secretos: la PSK de cada iPhone", "bien  secretos: la clave del certificado",
                      "bien  IKEv2: 1 conexión", "bien  cortafuegos: ufw, en marcha"):
            self.assertIn(linea, self.salida)
        for una_vez in ("Hermes: contesta con su clave", "cortafuegos: ufw, en marcha", "canje: ninguno abierto",
                        "la API de Hermes solo escucha", "actualizar: la clave de las firmas"):
            self.assertEqual(self.salida.count(una_vez), 1, una_vez)

    def test_comprobar_ve_lo_que_falla_en_cada_uno(self):
        self.vpn()
        self.tls()
        self.falso._parar("hehermes-pasarela")
        self.falso.enlaces_ip.pop("hh-ipsec")
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("MAL   pasarela: parada", self.salida)
        self.assertIn("MAL   hh-ipsec: no está", self.salida)

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
        # Y lo que queda se repite sin cambiar nada.
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
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
        self.assertEqual(self.orden("instalar"), 0, self.salida)
        self.assertIn("Todo al día: 0 cambios", self.salida)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)

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
        """Los avisos los instala la VPN, pero la pasarela también los sirve."""
        self.vpn("--avisos")
        self.tls()
        self.assertEqual(self.orden("desinstalar", "--modo", "vpn", "--si"), 0, self.salida)
        self.assertIn("los avisos (el vigía y el relé): los instalé con la VPN", self.salida)
        self.assertTrue(self.sis.existe("/usr/local/libexec/hehermes-leer-media"))
        self.assertIn("hehermes-vigia", self.falso.activos)
        self.assertTrue(self.manifiesto()["avisos"])
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertFalse(self.sis.existe("/usr/local/libexec/hehermes-leer-media"))

    def test_desinstalar_sin_modo_quita_los_dos(self):
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
    """Las reglas de los dos modos van con la misma marca: quitar uno vuelve a dejar solo las del otro."""

    def servidor(self):
        sis, falso = sf.servidor()
        for paquete in ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "qrencode", "nginx"):
            falso.instalar_paquete(paquete)
        falso.con_nft([("inet", "mio", "entrada", "input", "drop")],
                      [("inet", "mio", "entrada", [{"match": "ct state established,related"}, {"accept": None}])])
        return sis, falso

    def nuestras(self):
        return [r["texto"] for r in self.falso.nft_reglas if r.get("comment") == "hehermes"]

    VPN = ["udp dport { 500, 4500 } accept", 'iifname "hh-ipsec" ip daddr 10.77.0.1 tcp dport 80 accept']
    TLS = ["tcp dport 61234 accept"]

    def test_las_reglas_de_los_dos_y_quitar_cada_uno(self):
        self.vpn()
        self.assertEqual(self.nuestras(), self.VPN)
        self.tls()
        self.assertEqual(self.nuestras(), self.VPN + self.TLS)
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertEqual(self.orden("cortafuegos", "poner"), 0, self.salida)
        self.assertEqual(self.nuestras(), self.VPN + self.TLS, "la unidad de tras un reinicio pone las de los dos")
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
