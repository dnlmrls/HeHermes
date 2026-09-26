"""Todos los cortafuegos: nftables con sus propias tablas e iptables a pelo, además de ufw y firewalld.

Tres casos (el encargo de Daniel del 2026-09-26): cierra y se sabe dónde, reglas justas con la marca `hehermes`; cierra
y no se sabe, se para y dice qué abrir; no hay nada, se avisa y no se enciende nada. Las reglas sobreviven a un
reinicio (`hehermes-cortafuegos.service`) sin tocar lo guardado del usuario, y desinstalar las quita.
"""

import apoyo

import json
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import cli
from hehermes_servidor import cortafuegos as cf
from hehermes_servidor import piezas as p
from hehermes_servidor import porchat
from hehermes_servidor.deteccion import detectar
from hehermes_servidor.manifiesto import Manifiesto

ORIGEN = str(apoyo.RAIZ)
LLAVE = "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkc"
DROP = [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]
SSH = [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
       {"accept": None}]
TELNET_FUERA = [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 23}},
                {"drop": None}]


def cadena(familia="inet", tabla="filter", nombre="input", hook="input", politica="drop"):
    return {"family": familia, "table": tabla, "name": nombre, "hook": hook, "type": "filter", "policy": politica}


def regla(expr, handle, familia="inet", tabla="filter", nombre="input", comentario=None):
    r = {"family": familia, "table": tabla, "chain": nombre, "handle": handle, "expr": expr}
    if comentario:
        r["comment"] = comentario
    return r


def ruleset(*objetos):
    return [{"chain": o} if "hook" in o or "policy" in o else {"rule": o} for o in objetos]


class AnalizarNft(unittest.TestCase):
    def test_policy_drop_va_al_final(self):
        lugares, dudas = cf.analizar_nft(ruleset(cadena(), regla(SSH, 4)))
        self.assertEqual(dudas, [])
        self.assertEqual([(l.nombre, l.antes) for l in lugares], [("nftables inet filter input", None)])

    def test_un_drop_final_sin_condiciones_va_justo_antes(self):
        lugares, _ = cf.analizar_nft(ruleset(cadena(politica="accept"), regla(SSH, 4), regla(DROP, 9)))
        self.assertEqual([l.antes for l in lugares], [9])
        lugares, _ = cf.analizar_nft(ruleset(cadena(politica="accept"), regla([{"reject": None}], 5)))
        self.assertEqual([l.antes for l in lugares], [5])

    def test_lo_que_deja_pasar_no_se_toca(self):
        for objetos in ((cadena(politica="accept"), regla(SSH, 4)),
                        (cadena(politica="accept"), regla(TELNET_FUERA, 4)),
                        (cadena(politica="drop"), regla(SSH, 4), regla([{"accept": None}], 5))):
            with self.subTest(objetos=objetos):
                self.assertEqual(cf.analizar_nft(ruleset(*objetos)), ([], []))

    def test_un_salto_final_sin_condiciones_es_una_duda(self):
        for salto in ("jump", "goto"):
            with self.subTest(salto=salto):
                lugares, dudas = cf.analizar_nft(ruleset(cadena(), regla([{salto: {"target": "entrada"}}], 4)))
                self.assertEqual(lugares, [])
                self.assertIn("saltando", dudas[0])

    def test_solo_las_cadenas_de_entrada_de_ipv4(self):
        for c in (cadena(familia="ip6"), cadena(familia="netdev"), cadena(hook="forward"), cadena(hook="output"),
                  {"family": "inet", "table": "filter", "name": "mia"}):
            with self.subTest(cadena=c):
                self.assertEqual(cf.analizar_nft(ruleset(c)), ([], []))
        self.assertEqual(len(cf.analizar_nft(ruleset(cadena(familia="ip")))[0]), 1)

    def test_las_tablas_de_iptables_nft_y_de_firewalld_no_son_suyas(self):
        de_iptables = cadena(familia="ip", tabla="filter", nombre="INPUT")
        self.assertEqual(cf.analizar_nft(ruleset(de_iptables), iptables_nft=True), ([], []))
        self.assertEqual(len(cf.analizar_nft(ruleset(de_iptables), iptables_nft=False)[0]), 1)
        self.assertEqual(cf.analizar_nft(ruleset(cadena(tabla="firewalld", nombre="filter_INPUT"))), ([], []))

    def test_las_nuestras_no_cuentan_como_el_final_y_se_cuentan(self):
        lugares, _ = cf.analizar_nft(ruleset(cadena(politica="accept"), regla(DROP, 9),
                                             regla([{"accept": None}], 20, comentario="hehermes"),
                                             regla([{"accept": None}], 21, comentario="hehermes-canje")))
        self.assertEqual([(l.antes, l.marcadas) for l in lugares], [(9, 1)])

    def test_un_nombre_raro_es_una_duda(self):
        self.assertIn("nombre", cf.analizar_nft(ruleset(cadena(tabla='x"; flush ruleset')))[1][0])


class AnalizarIptables(unittest.TestCase):
    def test_los_casos(self):
        casos = {
            "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n": ("lugar", None),
            "-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -j DROP\n": ("lugar", 2),
            "-P INPUT ACCEPT\n-A INPUT -j REJECT --reject-with icmp-port-unreachable\n": ("lugar", 1),
            "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 23 -j DROP\n": (None, None),
            "-P INPUT ACCEPT\n": (None, None),
            "-P INPUT DROP\n-A INPUT -j ACCEPT\n": (None, None),
            "-P INPUT DROP\n": ("lugar", None),
        }
        for texto, (que, antes) in casos.items():
            with self.subTest(texto=texto):
                lugar, duda = cf.analizar_iptables(texto)
                self.assertIsNone(duda)
                self.assertEqual(lugar is not None, que == "lugar")
                if lugar:
                    self.assertEqual(lugar.antes, antes)

    def test_un_salto_final_es_una_duda(self):
        for final in ("-A INPUT -j MI-CORTAFUEGOS", "-A INPUT -g OTRA"):
            with self.subTest(final=final):
                lugar, duda = cf.analizar_iptables("-P INPUT DROP\n%s\n" % final)
                self.assertIsNone(lugar)
                self.assertIn("saltando", duda)

    def test_las_nuestras_no_son_el_final(self):
        lugar, _ = cf.analizar_iptables("-P INPUT ACCEPT\n-A INPUT -j DROP\n-A INPUT -p udp -m multiport --dports "
                                        "500,4500 -m comment --comment hehermes -j ACCEPT\n")
        self.assertEqual((lugar.antes, lugar.marcadas), (1, 1))


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def instalar(self, *extra):
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone", *extra), 0, self.salida)

    def nft_mio(self):
        """El nftables.conf de alguien: SSH, lo ya establecido, y todo lo demás fuera (policy drop)."""
        self.falso.con_nft([("inet", "mio", "entrada", "input", "drop"), ("inet", "mio", "salida", "output", "accept")],
                           [("inet", "mio", "entrada", [{"match": "ct state established,related"}, {"accept": None}]),
                            ("inet", "mio", "entrada", SSH)])
        return [dict(r) for r in self.falso.nft_reglas]

    def nuestras(self, marca="hehermes"):
        return [r for r in self.falso.nft_reglas if r.get("comment") == marca]


class ConNftables(Base):
    def test_policy_drop_las_pone_al_final_de_su_cadena_y_nada_mas(self):
        del_usuario = self.nft_mio()
        self.instalar()
        entrada = self.falso.reglas_nft("inet", "mio", "entrada")
        self.assertEqual(entrada[:2], del_usuario, "lo suyo, delante y sin tocar")
        self.assertEqual([r["texto"] for r in entrada[2:]],
                         ["udp dport { 500, 4500 } accept", 'iifname "hh-ipsec" ip daddr 10.77.0.1 tcp dport 80 accept'])
        self.assertEqual({r["comment"] for r in entrada[2:]}, {"hehermes"})
        self.assertEqual(self.falso.reglas_nft("inet", "mio", "salida"), [])
        self.assertIn("nftables inet mio entrada", self.salida)

    def test_con_un_drop_final_van_justo_antes(self):
        self.falso.con_nft([("inet", "mio", "entrada", "input", "accept")],
                           [("inet", "mio", "entrada", SSH), ("inet", "mio", "entrada", DROP)])
        self.instalar()
        entrada = self.falso.reglas_nft("inet", "mio", "entrada")
        self.assertEqual([r.get("comment") for r in entrada], [None, "hehermes", "hehermes", None])
        self.assertEqual(entrada[-1]["expr"], DROP, "el drop del usuario sigue el último")

    def test_repetir_no_cambia_nada(self):
        self.nft_mio()
        self.instalar()
        antes = list(self.falso.nft_reglas)
        desde = len(self.sis.ordenes)
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 0, self.salida)
        self.assertIn("Todo al día", self.salida)
        self.assertEqual(self.falso.nft_reglas, antes)
        self.assertFalse([o for o in self.sis.ordenes[desde:] if o[:1] == ["nft"] and o[1:2] != ["-j"]])

    def test_tras_un_reinicio_las_vuelve_a_poner_la_unidad(self):
        self.nft_mio()
        self.instalar()
        self.falso.reiniciar()
        self.assertEqual(self.nuestras(), [], "el sistema carga su nftables.conf, que no las lleva")
        self.assertEqual(self.orden("cortafuegos", "poner"), 0, self.salida)
        self.assertEqual(len(self.nuestras()), 2)
        self.assertEqual(self.orden("cortafuegos", "poner"), 0, "se puede repetir")
        self.assertEqual(len(self.nuestras()), 2, "sin duplicarlas")
        self.assertIsNone(self.sis.leer_texto("/etc/nftables.conf"), "no se escribe en lo guardado del usuario")

    def test_la_unidad_va_despues_del_cortafuegos_del_sistema_y_con_el(self):
        self.nft_mio()
        self.instalar()
        unidad = self.sis.leer_texto(p.UNIDAD_CORTAFUEGOS)
        for linea in ("After=nftables.service netfilter-persistent.service iptables.service ufw.service "
                      "firewalld.service",
                      "PartOf=nftables.service netfilter-persistent.service iptables.service",
                      "ReloadPropagatedFrom=nftables.service netfilter-persistent.service iptables.service",
                      "ExecStart=/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor cortafuegos poner",
                      "ExecReload=/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor cortafuegos poner",
                      "ExecStop=/usr/bin/python3 -I -B /opt/hehermes-servidor/hehermes-servidor cortafuegos quitar",
                      "WantedBy=multi-user.target"):
            with self.subTest(linea=linea):
                self.assertIn(linea + "\n", unidad)
        self.assertIn("hehermes-cortafuegos", self.falso.habilitados)

    def test_desinstalar_las_quita_y_deja_lo_suyo_como_estaba(self):
        del_usuario = self.nft_mio()
        self.instalar()
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertEqual(self.falso.nft_reglas, del_usuario)
        self.assertFalse(self.sis.existe(p.UNIDAD_CORTAFUEGOS))

    def test_comprobar_ve_si_faltan(self):
        self.nft_mio()
        self.instalar()
        self.assertEqual(self.orden("comprobar"), 0, self.salida)
        self.assertIn("nftables inet mio entrada", self.salida)
        self.falso.nft_reglas = [r for r in self.falso.nft_reglas if r.get("comment") != "hehermes"]
        self.assertEqual(self.orden("comprobar"), 1)
        self.assertIn("faltan", self.salida)

    @mock.patch.object(porchat, "_azar", lambda n: 1234)
    def test_el_canje_abre_su_puerto_ahi_y_lo_cierra(self):
        self.nft_mio()
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE), 0,
                         self.salida)
        canje = self.nuestras("hehermes-canje")
        self.assertEqual([r["texto"] for r in canje], ["tcp dport 59234 accept"])
        self.assertEqual(canje[0]["chain"], "entrada")
        porchat.limpiar(self.sis, {})
        self.assertEqual(self.nuestras("hehermes-canje"), [])
        self.assertEqual(len(self.nuestras()), 2, "las de siempre se quedan")


class ConIptables(Base):
    def test_antes_del_drop_final_y_fuera_al_desinstalar(self):
        for variante in ("nf_tables", "legacy"):
            with self.subTest(variante=variante):
                self.setUp()
                self.falso.con_iptables("ACCEPT", ["-i lo -j ACCEPT", "-p tcp -m tcp --dport 22 -j ACCEPT", "-j DROP"],
                                        variante=variante)
                antes = [list(r) for r in self.falso.iptables["reglas"]]
                self.instalar()
                reglas = self.falso.iptables["reglas"]
                self.assertEqual(reglas[:2], antes[:2])
                self.assertEqual(reglas[-1], ["-j", "DROP"])
                self.assertEqual(reglas[2], ["-p", "udp", "-m", "multiport", "--dports", "500,4500", "-m", "comment",
                                             "--comment", "hehermes", "-j", "ACCEPT"])
                self.assertEqual(reglas[3], ["-i", "hh-ipsec", "-d", "10.77.0.1/32", "-p", "tcp", "-m", "tcp",
                                             "--dport", "80", "-m", "comment", "--comment", "hehermes", "-j", "ACCEPT"])
                self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
                self.assertEqual(self.falso.iptables["reglas"], antes)

    def test_con_ufw_en_marcha_iptables_es_suyo(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.falso.con_iptables("DROP", ["-j ufw-before-input"])
        self.instalar()
        self.assertEqual(self.falso.iptables["reglas"], [["-j", "ufw-before-input"]])
        self.assertFalse([o for o in self.sis.ordenes if o[:1] == ["iptables"] and o[1:2] in (["-I"], ["-A"])])

    def test_lo_que_el_sistema_guardo_con_las_nuestras_se_dice(self):
        self.falso.con_iptables("DROP")
        self.instalar()
        self.sis.poner("/etc/iptables/rules.v4", "-A INPUT -p udp -m comment --comment hehermes -j ACCEPT\n")
        self.assertEqual(self.orden("desinstalar", "--si"), 0, self.salida)
        self.assertIn("/etc/iptables/rules.v4", self.salida)


class SinSaberComo(Base):
    def test_un_salto_final_para_y_dice_que_abrir(self):
        self.falso.con_iptables("DROP", ["-j MI-CORTAFUEGOS"])
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--si", "--iphone", "mi-iphone"), 1)
        self.assertEqual(self.sis.foto(), antes)
        for texto in ("no sé abrirlo sin riesgo", "UDP 500 y 4500", "TCP 80", "hh-ipsec", "58000 al 65500",
                      "--cortafuegos-a-mano"):
            self.assertIn(texto, self.salida)

    def test_un_gestor_que_no_conozco_tambien(self):
        self.falso.con_iptables("DROP")
        self.falso.activos.add("shorewall")
        self.assertEqual(self.orden("instalar", "--si"), 1)
        self.assertIn("shorewall", self.salida)

    def test_a_mano_sigue_sin_tocarlo_y_lo_recuerda(self):
        self.falso.con_iptables("DROP", ["-j MI-CORTAFUEGOS"])
        self.instalar("--cortafuegos-a-mano")
        self.assertEqual(self.falso.iptables["reglas"], [["-j", "MI-CORTAFUEGOS"]])
        self.assertIn("lo llevas tú", self.salida)


class SinCortafuegos(Base):
    def test_avisa_y_no_enciende_nada(self):
        self.instalar()
        self.assertIn("No hay ningún cortafuegos", self.salida)
        self.assertIn("No enciendo ninguno", self.salida)
        self.assertFalse([o for o in self.sis.ordenes if o[:1] in (["nft"], ["iptables"], ["ufw"])])

    def test_un_nftables_que_deja_pasar_todo_tambien_es_no_tener(self):
        self.falso.con_nft([("inet", "mio", "entrada", "input", "accept")], [("inet", "mio", "entrada", SSH)])
        self.instalar()
        self.assertIn("No hay ningún cortafuegos", self.salida)
        self.assertEqual(self.nuestras(), [])


class FirewalldEnDebian(Base):
    def test_en_marcha_se_usa_como_en_red_hat(self):
        self.falso.programa("/usr/bin/firewall-cmd")
        self.falso.programa("/usr/bin/firewall-offline-cmd")
        self.falso.firewalld = "activo"
        self.falso.activos.add("firewalld")
        self.instalar()
        self.assertIn("port=500/udp", self.falso.fw_permanente)
        self.assertIn("port=4500/udp", self.falso.fw_ahora)


class ElCanjeTrasUnReinicio(Base):
    """Daniel: el puerto del canje se cierra siempre, también si el servidor se reinicia a mitad."""

    @mock.patch.object(porchat, "_azar", lambda n: 7)
    def test_la_regla_de_ufw_que_quedo_se_va_al_arrancar(self):
        self.falso.instalar_paquete("ufw")
        self.falso.ufw = "activo"
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE), 0,
                         self.salida)
        self.assertTrue([r for r in self.falso.reglas_ufw if "58007" in r])
        self.falso.reiniciar()
        self.assertTrue([r for r in self.falso.reglas_ufw if "58007" in r], "ufw guarda sus reglas")
        self.assertEqual(self.orden("cortafuegos", "poner"), 0, self.salida)
        self.assertFalse([r for r in self.falso.reglas_ufw if "hehermes-canje" in r])
        self.assertTrue([r for r in self.falso.reglas_ufw if "500,4500" in r], "las de siempre se quedan")

    def test_sin_manifiesto_poner_no_hace_nada(self):
        self.assertEqual(self.orden("cortafuegos", "poner"), 0, self.salida)
        self.assertFalse(self.sis.existe("/etc/hehermes"))


if __name__ == "__main__":
    unittest.main()
