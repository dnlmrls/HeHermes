"""La dirección pública detrás del NAT 1:1 de una nube, por su servicio de metadatos (desde la 0.11.1).

En AWS, Google Cloud, Azure y Oracle Cloud la ruta de salida da una IP privada, y el instalador se paraba con `nat` (por
chat, sin forma de darle `--direccion`). Cada nube de mentira contesta como la de verdad, con sus cabeceras
obligatorias (`servidor_falso.ServidorFalso.metadatos`).
"""

import apoyo

import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli, nube, porchat
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import detectar_tls

ORIGEN = str(apoyo.RAIZ)
PASARELA_INI = "/etc/hehermes-pasarela/pasarela.ini"


class Base(unittest.TestCase):
    def montar(self, proveedor=None, **nube_):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)
        if proveedor:
            self.falso.en_la_nube(proveedor, **nube_)
        return self.falso

    def detectar(self, **opciones):
        return detectar_tls(self.sis, Manifiesto.leer(self.sis), amb.de_root(), **opciones)

    def codigos(self, det):
        return [getattr(b, "codigo", None) for b in det.bloqueos]

    def aviso(self, det, *trozos):
        avisos = [a for a in det.avisos if all(t in a for t in trozos)]
        self.assertTrue(avisos, "no hay aviso con %s: %s" % (trozos, det.avisos))
        return avisos[0]


class LaPublicaDeCadaNube(Base):
    def test_cada_nube_da_su_publica_y_se_dice_de_donde_sale(self):
        for proveedor, nombre in (("aws", "AWS"), ("aws-xen", "AWS"), ("gcp", "Google Cloud"), ("azure", "Azure"),
                                  ("digitalocean", "DigitalOcean"), ("hetzner", "Hetzner Cloud")):
            with self.subTest(proveedor=proveedor):
                self.montar(proveedor)
                det = self.detectar()
                self.assertEqual(det.bloqueos, [])
                self.assertEqual(det.direccion, sf.IP_DE_LA_NUBE)
                self.assertFalse(det.direccion_privada, "no se pregunta: ya se sabe")
                texto = self.aviso(det, "metadatos")
                for trozo in (sf.IP_PRIVADA_DE_LA_NUBE, sf.IP_DE_LA_NUBE, nombre, "169.254.169.254", "--direccion"):
                    self.assertIn(trozo, texto)

    def test_aws_con_imdsv2_el_token_va_en_la_peticion_y_dura_poco(self):
        self.montar("aws")
        self.detectar()
        (put, url_put, cab_put), (get, url_get, cab_get) = self.sis.peticiones_metadatos
        self.assertEqual((put, url_put), ("PUT", "http://169.254.169.254/latest/api/token"))
        self.assertLessEqual(int(cab_put["X-aws-ec2-metadata-token-ttl-seconds"]), 300)
        self.assertEqual((get, url_get), ("GET", "http://169.254.169.254/latest/meta-data/public-ipv4"))
        self.assertEqual(cab_get, {"X-aws-ec2-metadata-token": sf.TOKEN_IMDS})

    def test_azure_con_una_ip_de_sku_estandar_la_saca_del_equilibrador(self):
        self.montar("azure").azure_basica = False
        self.assertEqual(self.detectar().direccion, sf.IP_DE_LA_NUBE)
        self.assertTrue(any("/metadata/loadbalancer?" in url for _, url, _ in self.sis.peticiones_metadatos))
        self.montar("azure").azure_basica = True
        self.assertEqual(self.detectar().direccion, sf.IP_DE_LA_NUBE)
        self.assertFalse(any("/metadata/loadbalancer?" in url for _, url, _ in self.sis.peticiones_metadatos))

    def test_una_nube_que_imita_a_ec2_sin_token_tambien_vale(self):
        # OpenStack (OVH, Infomaniak…): DMI no la reconoce, su metadatos no da token, y su public-ipv4 es la flotante.
        self.montar("openstack")
        det = self.detectar()
        self.assertEqual((det.bloqueos, det.direccion), ([], sf.IP_DE_LA_NUBE))
        self.aviso(det, "metadatos", "tu proveedor")

    def test_por_las_cabeceras_de_cada_una(self):
        """Lo que piden: sin su cabecera, Google da 403 y Azure 400 (la nube de mentira lo comprueba)."""
        for proveedor, cabecera in (("gcp", ("Metadata-Flavor", "Google")), ("azure", ("Metadata", "true"))):
            with self.subTest(proveedor=proveedor):
                self.montar(proveedor)
                self.detectar()
                self.assertTrue(all(cab.get(cabecera[0]) == cabecera[1] for _, _, cab in self.sis.peticiones_metadatos))


class CuandoNoSePuede(Base):
    def test_oracle_no_la_da_y_se_dice_donde_mirarla(self):
        self.montar("oracle")
        det = self.detectar()
        self.assertEqual(self.codigos(det), ["nat"])
        self.assertTrue(det.direccion_privada)
        for trozo in ("Oracle Cloud", "Dirección IP pública", "--direccion", sf.IP_PRIVADA_DE_LA_NUBE):
            self.assertIn(trozo, det.bloqueos[0])
        self.assertEqual(self.sis.peticiones_metadatos, [], "sus metadatos no la tienen: ni se pregunta")
        self.assertEqual(det.bloqueos[0].detalle, "proveedor=oracle")

    def test_una_instancia_sin_ip_publica(self):
        self.montar("aws", publica=None)
        det = self.detectar()
        self.assertEqual(self.codigos(det), ["nat"])
        for trozo in ("AWS", "consola de EC2", "--direccion"):
            self.assertIn(trozo, det.bloqueos[0])

    def test_aws_con_los_metadatos_apagados(self):
        self.montar("aws")
        self.sis.metadatos_falso = None
        self.assertEqual(self.codigos(self.detectar()), ["nat"])

    def test_en_casa_detras_del_router_una_sola_pregunta_sin_respuesta(self):
        falso = self.montar()
        falso.direccion_salida = "192.168.1.20"
        det = self.detectar()
        self.assertEqual(self.codigos(det), ["nat"])
        self.assertEqual([(m, u) for m, u, _ in self.sis.peticiones_metadatos],
                         [("PUT", "http://169.254.169.254/latest/api/token")])
        self.assertIn("router", det.bloqueos[0])
        self.assertIsNone(getattr(det.bloqueos[0], "detalle", None))

    def test_con_la_publica_en_la_tarjeta_o_dada_no_se_pregunta_a_nadie(self):
        self.montar()
        self.assertEqual(self.detectar().direccion, sf.IP_PUBLICA)
        self.montar("aws")
        det = self.detectar(direccion="servidor.example.com")
        self.assertEqual(det.direccion, "servidor.example.com")
        self.assertEqual(self.sis.peticiones_metadatos, [])

    def test_nunca_una_ip_privada_ni_nada_que_no_sea_una_publica(self):
        malas = ["10.0.0.5", "172.16.3.4", "192.168.1.20", "100.64.0.9", "169.254.169.254", "127.0.0.1", "0.0.0.0",
                 "224.0.0.1", "240.0.0.1", "255.255.255.255", "198.18.0.1", "203.0.113.50 198.51.100.1",
                 "203.0.113.50\n10.0.0.1", "2001:db8::1", "::ffff:203.0.113.50", "203.0.113", "203.0.113.050",
                 "203.0.113.500", "<html>no</html>", "", "203.0.113.50/32"]
        for mala in malas:
            with self.subTest(mala=mala):
                self.montar("aws", publica=mala)
                det = self.detectar()
                self.assertEqual(self.codigos(det), ["nat"])
                self.assertIsNone(det.direccion)
                self.assertIsNone(nube.publica(mala))
                self.assertIsNone(nube.publica(mala.encode()))
        for buena in ("203.0.113.50", " 203.0.113.50\n", "198.51.100.7", b"192.0.2.44"):
            with self.subTest(buena=buena):
                self.assertEqual(nube.publica(buena), (buena.decode() if isinstance(buena, bytes) else buena).strip())

    def test_ninguna_nube_cuela_una_privada(self):
        for proveedor in ("gcp", "azure", "azure-basica", "digitalocean", "hetzner", "openstack"):
            for mala in ("10.0.0.5", "100.64.0.9", "169.254.169.254", "0.0.0.0", "203.0.113.50 198.51.100.1"):
                with self.subTest(proveedor=proveedor, mala=mala):
                    falso = self.montar(proveedor.split("-")[0], publica=mala)
                    falso.azure_basica = proveedor == "azure-basica"
                    det = self.detectar()
                    self.assertEqual(self.codigos(det), ["nat"])
                    self.assertIsNone(det.direccion)

    def test_azure_no_toma_las_del_equilibrador_que_no_son_suyas_ni_privadas(self):
        self.montar("azure")
        cuerpo = (b'{"loadbalancer": {"publicIpAddresses": [{"frontendIpAddress": "10.1.0.4", "privateIpAddress": '
                  b'"172.31.20.5"}], "inboundRules": [{"frontendIpAddress": "198.51.100.77", "privateIpAddress": '
                  b'"172.31.20.5"}]}}')
        self.sis.metadatos_falso = lambda m, u, c: (200, {}, cuerpo) if "loadbalancer" in u else (200, {}, b"")
        self.assertEqual(self.codigos(self.detectar()), ["nat"])
        for roto in (b"[]", b"no es json", b'{"loadbalancer": []}', b'{"loadbalancer": {"publicIpAddresses": [1]}}'):
            with self.subTest(roto=roto):
                self.sis.metadatos_falso = lambda m, u, c, roto=roto: (200, {}, roto)
                self.assertEqual(self.codigos(self.detectar()), ["nat"])

    def test_la_clave_de_hermes_no_va_nunca_a_los_metadatos(self):
        self.montar("aws")
        self.detectar()
        self.assertNotIn(sf.CLAVE, repr(self.sis.peticiones_metadatos))


class PorLaOrden(Base):
    def setUp(self):
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)
        azar.start()
        self.addCleanup(azar.stop)

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: self.fail("no pregunta"),
                          salida=self.texto.append, terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo

    def test_en_aws_se_instala_sin_preguntar_con_la_de_los_metadatos(self):
        self.montar("aws")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertIn("direccion = %s\n" % sf.IP_DE_LA_NUBE, self.sis.leer_texto(PASARELA_INI))
        self.assertIn("me la da su servicio de metadatos", self.salida)
        self.assertNotIn(sf.TOKEN_IMDS, self.salida)

    def test_por_chat_en_oracle_acaba_en_nat_con_el_proveedor_para_la_app(self):
        self.montar("oracle")
        llave = "A" * 43
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "iphone-1a2b", "--llave", llave), 1)
        self.assertEqual(self.texto[-1].splitlines()[-2:], ["hehermes-detalle:proveedor=oracle", "hehermes-error:nat"])


if __name__ == "__main__":
    unittest.main()
