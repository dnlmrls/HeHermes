"""Los servidores que no son el de siempre (auditoría de servidores del 2026-10-06): usuarios de nombre largo o sin
nombre, Hermes en Docker como lo enseña su guía, el instalador dentro de un contenedor o en WSL, LXC sin anidamiento,
Amazon Linux 2023, el puerto del vigía ocupado y los puertos efímeros de Linux. Cada uno, con un código claro antes de
tocar nada, o funcionando.
"""

import apoyo

import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli, porchat
from hehermes_servidor import piezas as p
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import detectar_tls

ORIGEN = str(apoyo.RAIZ)


class Base(unittest.TestCase):
    def setUp(self):
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)
        azar.start()
        self.addCleanup(azar.stop)

    def montar(self, distro=("debian", "12"), **hermes):
        self.sis, self.falso = sf.servidor(distro, **hermes)
        self.addCleanup(self.sis.limpiar)
        return self.falso

    def detectar(self, ambito=None, **opciones):
        return detectar_tls(self.sis, Manifiesto.leer(self.sis), ambito or amb.de_root(), **opciones)

    def codigos(self, det):
        return [getattr(b, "codigo", None) for b in det.bloqueos]

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo


class LosUsuarios(Base):
    """`ps -eo user=` recorta a 8 letras los nombres más largos («cloud-u+»): el `ps` de mentira también."""

    def test_el_ps_de_mentira_recorta_como_el_de_verdad(self):
        self.montar(como="proceso", usuario="cloud-user")
        salida = self.sis.ejecutar(["ps", "-eo", "pid=,user=,args="]).salida
        self.assertIn(" cloud-u+ ", salida)

    def test_un_usuario_de_mas_de_8_letras_por_su_proceso(self):
        self.montar(como="proceso", usuario="cloud-user")
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertEqual((det.hermes.usuario, det.hermes.env), ("cloud-user", "/home/cloud-user/.hermes/.env"))

    def test_con_su_unidad_de_perfil_el_plan_sale_con_su_usuario(self):
        self.montar(como="unidad-perfil", usuario="almalinux", perfil="trabajo")
        self.assertEqual(self.orden("instalar", "--plan"), 0, self.salida)
        self.assertIn("de almalinux", self.salida)
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.assertIn("User=almalinux\n", self.sis.leer_texto(amb.de_root().unidad_lector))

    def test_un_uid_sin_nombre_se_para_con_su_codigo_y_sin_traceback(self):
        # El 10000 de la imagen de Docker de Hermes no existe en el servidor: systemd no arranca una unidad con él.
        self.montar(como="proceso", uid_sin_nombre=10000)
        det = self.detectar()
        self.assertEqual(det.hermes.usuario, "10000")
        self.assertEqual(det.hermes.env, "/root/.hermes/.env", "su casa, por el HOME de su proceso")
        self.assertEqual(self.codigos(det), ["usuario-hermes"])
        for trozo in ("10000", "useradd --system --uid 10000", "No he tocado nada"):
            self.assertIn(trozo, det.bloqueos[0])
        self.assertEqual(det.bloqueos[0].detalle, "uid=10000", "para que la app escriba la orden exacta")
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--plan"), 1, self.salida)
        self.assertEqual(self.orden("instalar", "--si"), 1, self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_las_unidades_aceptan_un_uid_y_los_nombres_largos_pero_no_lo_que_no_es_un_usuario(self):
        ambito = amb.de_root()
        for usuario in ("cloud-user", "almalinux", "nombre.apellido", "10000"):
            with self.subTest(usuario=usuario):
                self.assertIn("User=%s\n" % usuario, p.unidad_lector(ambito, "/srv/h", usuario))
                self.assertIn("User=%s\n" % usuario, p.unidad_entrada(ambito, "/srv/h", usuario))
                p.unidad_respaldo(ambito, "/srv/h", usuario)
                p.unidad_agentes(ambito, "/srv/h", usuario)
        for malo in ("a b", "x\nExecStart=/bin/sh", "%h", "-x", "4294967295", "65535", "99999999999", "a:b", "../x"):
            with self.subTest(malo=malo):
                with self.assertRaises(ValueError):
                    p.unidad_lector(ambito, "/srv/h", malo)


class HermesEnDocker(Base):
    """Como lo enseña la guía de Docker de Hermes: `-p 8642:8642`, la API por `-e` (no en su .env) y el uid 10000."""

    def montar_docker(self, red="bridge", publicado="0.0.0.0:8642", entorno=None):
        falso = self.montar(como="docker", habilitada=None, clave=None, uid_sin_nombre=10000,
                            entorno_extra=entorno if entorno is not None else
                            "API_SERVER_ENABLED=true\0API_SERVER_HOST=0.0.0.0\0API_SERVER_KEY=%s\0" % sf.CLAVE)
        falso.red_docker = red
        falso.hermes[8642] = sf.CLAVE
        falso.tcp.append((publicado, "docker-proxy"))
        return falso

    def test_la_api_por_su_entorno_no_es_una_api_apagada(self):
        self.montar_docker()
        det = self.detectar()
        self.assertNotIn("api-apagada", self.codigos(det))
        self.assertEqual(self.codigos(det), ["usuario-hermes"])
        self.assertTrue(det.hermes.habilitada)
        self.assertEqual(det.hermes.clave, sf.CLAVE)
        self.assertTrue(det.hermes.clave_vale)
        self.assertEqual(det.hermes.env, "/root/.hermes/.env", "su casa, la del servidor que va montada en /opt/data")
        self.assertNotIn(sf.CLAVE, repr(det.bloqueos) + repr(det.avisos))

    def test_lo_del_env_manda_sobre_su_entorno_como_en_hermes(self):
        # hermes_cli/env_loader.py carga el .env con override=True.
        self.montar_docker(entorno="API_SERVER_KEY=otra-que-no-vale\0API_SERVER_PORT=9000\0")
        self.sis.poner("/root/.hermes/.env", 'API_SERVER_ENABLED=true\nAPI_SERVER_KEY="%s"\n' % sf.CLAVE, modo=0o600)
        det = self.detectar()
        self.assertEqual((det.hermes.clave, det.hermes.puerto), (sf.CLAVE, 9000))

    def test_publicada_en_todas_las_direcciones_se_aconseja_publicarla_en_127(self):
        self.montar_docker()
        rojos = [a for a in self.detectar().avisos if "todas las interfaces" in a]
        self.assertEqual(len(rojos), 1)
        self.assertIn("-p 127.0.0.1:8642:8642", rojos[0])
        self.assertNotIn("cámbialo ahí a 127.0.0.1", rojos[0])

    def test_publicada_solo_en_127_no_esta_expuesta_aunque_dentro_escuche_en_todas(self):
        self.montar_docker(publicado="127.0.0.1:8642")
        det = self.detectar()
        self.assertFalse([a for a in det.avisos if "todas las interfaces" in a], det.avisos)
        self.assertIsNone(det.hermes.expuesta)

    def test_con_la_red_del_servidor_lo_de_dentro_es_lo_de_fuera(self):
        self.montar_docker(red="host", publicado="0.0.0.0:8642")
        rojos = [a for a in self.detectar().avisos if "todas las interfaces" in a]
        self.assertIn("cámbialo ahí a 127.0.0.1", rojos[0])


class DondeMeLanzan(Base):
    """Por chat, la orden corre donde corren las de Hermes: en su contenedor, en un sandbox o en el ordenador de casa.
    Antes salía `sistema` («no arranca con systemd»), que no le dice nada a nadie."""

    def test_dentro_de_un_contenedor(self):
        for marca, contenido in (("/.dockerenv", ""), ("/run/.containerenv", 'engine="podman-5.2"\n'),
                                 ("/run/systemd/container", "docker\n")):
            with self.subTest(marca=marca):
                self.montar()
                self.sis.borrar("/run/systemd/system")
                self.sis.poner(marca, contenido)
                det = self.detectar()
                self.assertEqual(self.codigos(det), ["contenedor"])
                for trozo in ("contenedor", "SSH", "No he tocado nada"):
                    self.assertIn(trozo, det.bloqueos[0])
                self.assertEqual(self.sis.ordenes, [], "ni mira lo demás")

    def test_sin_marcas_lo_dice_systemd_detect_virt(self):
        falso = self.montar()
        self.sis.borrar("/run/systemd/system")
        falso.programa("/usr/bin/systemd-detect-virt")
        falso.virt = "podman"
        self.assertEqual(self.codigos(self.detectar()), ["contenedor"])
        falso.virt = "none"
        self.assertEqual(self.codigos(self.detectar()), ["sistema"])

    def test_wsl_y_un_mac_no_son_un_servidor(self):
        for como in ({"nucleo": "5.15.153-microsoft-standard-WSL2"}, {"sistema_operativo": "Darwin"}):
            with self.subTest(como=como):
                self.montar()
                for clave, valor in como.items():
                    setattr(self.sis, clave, valor)
                det = self.detectar()
                self.assertEqual(self.codigos(det), ["no-es-servidor"])
                self.assertIn("No he tocado nada", det.bloqueos[0])
                self.assertEqual(self.sis.ordenes, [])

    def test_un_contenedor_lxc_sin_anidamiento_se_para_antes_de_empezar(self):
        falso = self.montar()
        self.sis.poner("/run/systemd/container", "lxc\n")
        falso.jaula = False
        det = self.detectar()
        self.assertEqual(self.codigos(det), ["contenedor"])
        for trozo in ("LXC", "nesting", "No he tocado nada"):
            self.assertIn(trozo, det.bloqueos[0])
        prueba = [o for o in self.sis.ordenes if o[:1] == ["systemd-run"]]
        self.assertEqual(len(prueba), 1)
        self.assertIn("--wait", prueba[0])
        self.assertIn("ProtectSystem=strict", prueba[0])
        self.assertEqual(prueba[0][-1], "/bin/true")
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--si"), 1, self.salida)
        self.assertEqual(self.sis.foto(), antes)

    def test_con_anidamiento_o_en_una_maquina_virtual_sigue(self):
        falso = self.montar()
        self.sis.poner("/run/systemd/container", "lxc\n")
        self.assertEqual(self.detectar().bloqueos, [])
        self.montar()
        self.assertEqual(self.detectar().bloqueos, [])
        self.assertFalse([o for o in self.sis.ordenes if o[:1] == ["systemd-run"]], "fuera de LXC no se prueba nada")
        # Sin root, las unidades de usuario no llevan jaula: no hay nada que probar.
        self.montar()
        self.sis.poner("/run/systemd/container", "lxc\n")
        falso = self.falso
        falso.jaula = False
        sin_root = amb.de_usuario("ana", "/home/ana", 1000)
        self.assertNotIn("contenedor", self.codigos(self.detectar(ambito=sin_root)))


class AmazonLinux(Base):
    def test_amazon_linux_2023_se_instala_como_un_el9(self):
        self.montar(("amzn", "2023"))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertEqual((det.familia, det.distro["base"]), ("rhel", "RHEL 9"))
        self.assertTrue(any("Amazon Linux 2023" in a and "RHEL 9" in a for a in det.avisos), det.avisos)

    def test_amazon_linux_2_no(self):
        self.montar(("amzn", "2"))
        self.assertEqual(self.codigos(self.detectar()), ["sistema"])


class ElPuertoDelVigia(Base):
    """El vigía escucha siempre en 127.0.0.1:8790 (lo abre systemd, `hehermes-vigia.socket`): si otro lo usa, su
    `enable --now` fallaría a mitad de la instalación."""

    def test_ocupado_por_otro_se_para_antes_de_tocar_nada(self):
        for local in ("127.0.0.1:8790", "0.0.0.0:8790", "[::]:8790", "*:8790"):
            with self.subTest(local=local):
                self.montar().tcp.append((local, "node"))
                antes = self.sis.foto()
                self.assertEqual(self.orden("instalar", "--si"), 1, self.salida)
                self.assertEqual(self.sis.foto(), antes)
                self.assertIn("8790", self.salida)
                self.assertIn("node", self.salida)

    def test_por_chat_con_su_codigo(self):
        self.montar().tcp.append(("127.0.0.1:8790", "node"))
        self.orden("instalar", "--por-chat", "--iphone", "iphone-1a2b", "--llave", "A" * 43)
        self.assertEqual(self.texto[-1].splitlines()[-1], "hehermes-error:puerto")

    def test_en_otra_direccion_no_choca_y_el_suyo_no_cuenta(self):
        self.montar().tcp.append(("10.0.0.5:8790", "otro"))
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        self.falso.tcp.append(("127.0.0.1:8790", "systemd"))
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)


class LosPuertosEfimeros(Base):
    """Del 32768 al 60999 (lo de serie en Linux) los coge el núcleo para las conexiones de salida: tras un reinicio, una
    pudo quedarse el de la pasarela antes de que arranque, y su unidad se rendiría."""

    RANGO = "/proc/sys/net/ipv4/ip_local_port_range"

    def test_la_pasarela_y_el_canje_los_evitan(self):
        self.montar()
        self.sis.poner(self.RANGO, "32768\t60999\n")
        for azar, puerto in ((lambda n: 0, 61000), (lambda n: n - 1, 65500), (lambda n: 100, 61100)):
            with self.subTest(puerto=puerto), mock.patch.object(porchat, "_azar", azar):
                self.assertEqual(self.detectar().puerto_pasarela, puerto)
                self.assertEqual(porchat._puerto_libre(self.sis), puerto)

    def test_se_sortea_entre_los_que_quedan(self):
        pedidos = []
        porchat.elegir_puerto(set(), azar=lambda n: pedidos.append(n) or 0, evitar=range(32768, 61000))
        self.assertEqual(pedidos, [4501])
        self.assertEqual(porchat.elegir_puerto({61000}, azar=lambda n: 0, evitar=range(32768, 61000)), 61001)
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: 0, evitar=range(60000, 62000)), 58000)
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: 1999, evitar=range(60000, 62000)), 59999)
        self.assertEqual(porchat.elegir_puerto(set(), azar=lambda n: 2000, evitar=range(60000, 62000)), 62000)

    def test_si_lo_cubren_todo_o_no_se_lee_como_siempre(self):
        for rango in ("1024 65535\n", "basura\n", "61000 60000\n", None):
            with self.subTest(rango=rango):
                self.montar()
                if rango is not None:
                    self.sis.poner(self.RANGO, rango)
                with mock.patch.object(porchat, "_azar", lambda n: 100):
                    self.assertEqual(self.detectar().puerto_pasarela, 58100)


if __name__ == "__main__":
    unittest.main()
