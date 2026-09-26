"""Más allá de Debian y Ubuntu: sus derivadas (por `ID_LIKE`) y la familia Red Hat (dnf, firewalld y SELinux), con el
servidor falso de cada una. Lo que no está en la lista se para al empezar, sin haber ejecutado nada."""

import apoyo

import json
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import cli
from hehermes_servidor import deteccion as d
from hehermes_servidor import piezas as p
from hehermes_servidor import porchat
from hehermes_servidor.aplicar import aplicar, comprobar
from hehermes_servidor.desinstalar import desinstalar
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.plan import Opciones, calcular_plan, pintar

ORIGEN = str(apoyo.RAIZ)
RICA = ('rich-rule=rule family="ipv4" source address="10.77.1.0/24" destination address="10.77.0.1/32" '
        'port port="80" protocol="tcp" accept')
NUESTRAS = {"port=500/udp", "port=4500/udp", RICA}


class Base(unittest.TestCase):
    def montar(self, distro, **hermes):
        self.sis, self.falso = sf.servidor(distro, **hermes)
        self.addCleanup(self.sis.limpiar)
        self.salida = []
        return self.sis, self.falso

    def detectar(self):
        return d.detectar(self.sis, Manifiesto.leer(self.sis))

    def plan(self, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        self.man = Manifiesto.leer(self.sis)
        return calcular_plan(self.sis, d.detectar(self.sis, self.man), self.man, Opciones(**opciones), ORIGEN)

    def instalar(self, **opciones):
        plan = self.plan(**opciones)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        aplicar(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        return plan

    def accion(self, plan, objeto):
        return next(a for a in plan.acciones if a.objeto == objeto)

    def rocky(self, **extra):
        """Rocky Linux 9 de serie: SELinux puesto, firewalld en marcha y EPEL activado."""
        self.montar(("rocky", "9.4"), **extra)
        self.falso.instalar_paquete("epel-release")
        return self.sis, self.falso


# MARK: Las derivadas de Debian y Ubuntu


class Derivadas(Base):
    def test_con_su_base_en_la_lista_se_instalan_como_ella(self):
        for distro, base in ((("linuxmint", "22", "noble"), "Ubuntu 24.04"), (("pop", "22.04", "jammy"), "Ubuntu 22.04"),
                             (("raspbian", "12", "bookworm"), "Debian 12"), (("linuxmint", "22.1", "noble"),
                                                                             "Ubuntu 24.04")):
            with self.subTest(distro=distro):
                self.montar(distro)
                det = self.detectar()
                self.assertEqual(det.bloqueos, [])
                self.assertEqual((det.familia, det.distro["base"], det.swanctl), ("debian", base, "/etc/swanctl"))
                self.assertTrue(any("es una derivada de %s: la instalo como ella" % base in a for a in det.avisos))
                plan = self.plan()
                self.assertTrue(plan.puede_seguir, plan.bloqueos)
                self.assertIn("charon-systemd", [a.objeto for a in plan.acciones if a.tipo == "paquete"])

    def test_con_una_base_fuera_de_la_lista_avisa_y_sigue(self):
        self.montar(("linuxmint", "20.3", "focal"))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertTrue(any("se basa en Ubuntu 20.04, que no está en la lista" in a for a in det.avisos), det.avisos)

    def test_sin_saber_su_base_avisa_y_sigue(self):
        self.montar(("kali", "2026.3"))
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertTrue(any("no sé de qué versión" in a for a in det.avisos), det.avisos)

    def test_debian_y_ubuntu_de_fuera_de_la_lista_siguen_parandose(self):
        for distro in (("debian", "11"), ("ubuntu", "24.10")):
            with self.subTest(distro=distro):
                self.montar(distro)
                det = self.detectar()
                self.assertEqual(len(det.bloqueos), 1)
                self.assertIn("no es una de las que sé instalar", det.bloqueos[0])


# MARK: Lo que no se soporta


class SinHueco(Base):
    def test_se_para_al_empezar_diciendo_cuales_si(self):
        for distro in (("rocky", "8.10"), ("almalinux", "8.9"), ("fedora", "41"), ("amzn", "2023"), ("arch", ""),
                       ("opensuse-leap", "15.6")):
            with self.subTest(distro=distro):
                self.montar(distro)
                det = self.detectar()
                self.assertEqual(len(det.bloqueos), 1, det.bloqueos)
                self.assertIn("no es una de las que sé instalar", det.bloqueos[0])
                self.assertIn("Rocky Linux, AlmaLinux, RHEL y CentOS Stream 9 y 10, y Fedora 42", det.bloqueos[0])
                self.assertEqual(self.sis.ordenes, [], "sin haber ejecutado nada")
                self.assertIn("No sigo: no he cambiado nada", pintar(self.plan()))

    def test_otra_arquitectura(self):
        self.montar(("fedora", "43"))
        self.falso.arquitectura = "ppc64le"
        self.assertTrue(any("ppc64le" in b for b in self.detectar().bloqueos))


# MARK: La familia Red Hat


class FamiliaRedHat(Base):
    def test_todas_las_de_la_lista(self):
        for distro in (("rocky", "9.4"), ("rocky", "10.0"), ("almalinux", "9.5"), ("almalinux", "10.0"),
                       ("rhel", "9.4"), ("rhel", "10.0"), ("centos", "9"), ("centos", "10"), ("fedora", "42"),
                       ("fedora", "44")):
            with self.subTest(distro=distro):
                self.montar(distro)
                self.falso.instalar_paquete("epel-release")
                det = self.detectar()
                self.assertEqual(det.bloqueos, [])
                self.assertEqual((det.familia, det.swanctl, det.firewalld, det.selinux),
                                 ("rhel", "/etc/strongswan/swanctl", "activo", "enforcing"))
                self.assertEqual(det.distro["arquitectura"], "amd64", "x86_64, con el nombre de Debian")
                self.assertFalse([a for a in det.avisos if "derivada" in a], "no son derivadas: son de la lista")

    def test_una_derivada_de_rhel_avisa(self):
        self.montar(("ol", "9.4"))
        self.falso.instalar_paquete("epel-release")
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertTrue(any("Oracle Linux Server 9.4 es una derivada de RHEL 9" in a for a in det.avisos), det.avisos)

    def test_el_python_de_rhel_9_vale_y_arm64(self):
        self.rocky()
        self.falso.arquitectura = "aarch64"
        det = self.detectar()
        self.assertEqual(self.sis.version_python[:2], (3, 9))
        self.assertEqual(det.bloqueos, [])
        self.assertEqual(det.distro["arquitectura"], "arm64")

    def test_sin_epel_se_para_y_no_lo_activa(self):
        self.montar(("almalinux", "9.5"))
        plan = self.plan()
        self.assertTrue(any("está en EPEL" in b and "No lo activo yo" in b for b in plan.bloqueos), plan.bloqueos)
        self.assertFalse([o for o in self.sis.ordenes if o[0] == "dnf"])
        # Fedora lo trae de serie.
        self.montar(("fedora", "42"))
        self.assertFalse([b for b in self.plan().bloqueos if "EPEL" in b])

    def test_una_instalacion_limpia(self):
        sis, falso = self.rocky()
        plan = self.instalar()
        # Paquetes con dnf, sin dependencias débiles; semanage, porque SELinux está puesto y no estaba.
        self.assertIn(["dnf", "install", "-y", "-q", "--setopt=install_weak_deps=False", "strongswan", "qrencode",
                       "nginx", "policycoreutils-python-utils"], sis.ordenes)
        self.assertFalse([o for o in sis.ordenes if "apt-get" in o or o[0] == "dpkg"])
        # strongSwan lo arranca él (dnf no), y nginx también; los dos, antes de dar el alta.
        self.assertIn(["systemctl", "enable", "--now", "strongswan"], sis.ordenes)
        self.assertLess(sis.ordenes.index(["systemctl", "enable", "--now", "strongswan"]),
                        next(i for i, o in enumerate(sis.ordenes) if o[:2] == [p.DISPOSITIVO, "alta"]))
        self.assertIn("nginx", falso.activos)
        # El sitio, en conf.d (el nginx.conf de Red Hat no tiene sites-enabled) y sin tocar su servidor de bienvenida.
        self.assertTrue(sis.existe(p.SITIO_CONF_D))
        self.assertFalse(sis.existe(p.SITIO))
        self.assertEqual(sis.leer_texto("/etc/nginx/nginx.conf"), sf.NGINX_CONF_RHEL)
        self.assertTrue(any("servidor de bienvenida" in a for a in plan.avisos))
        # SELinux: el puerto de Hermes, http_port_t; y cada fichero escrito, con su etiqueta.
        self.assertEqual(falso.etiquetas, {"8642": "http_port_t"})
        for ruta in (p.SITIO_CONF_D, p.BEARER, p.DROP_IN_NGINX, p.UNIDAD_XFRM, p.SCRIPT_XFRM, p.DISPOSITIVO,
                     p.SERVIDOR_INI):
            with self.subTest(ruta=ruta):
                self.assertIn(ruta, falso.etiquetados)
        # firewalld: en la de ahora y en la permanente, sin recargar (el falso para si se recarga).
        self.assertTrue(NUESTRAS <= falso.fw_ahora)
        self.assertTrue(NUESTRAS <= falso.fw_permanente)
        # servidor.ini dice dónde tiene swanctl su configuración, y el alta la deja ahí.
        self.assertIn("carpeta = /etc/strongswan/swanctl", sis.leer_texto(p.SERVIDOR_INI))
        self.assertTrue(sis.existe("/etc/strongswan/swanctl/conf.d/hehermes-mi-iphone.conf"))
        man = Manifiesto.leer(sis)
        self.assertEqual(man.datos["familia"], "rhel")
        self.assertEqual(man.datos["selinux_puertos"], ["8642"])
        self.assertIn("strongswan.service", man.unidades)
        self.assertEqual(sorted(man.reglas), sorted("firewall-cmd " + r.opcion for r in p.reglas_firewalld()))
        self.assertTrue(all(bien for bien, _ in comprobar(sis, man)), comprobar(sis, man))

    def test_repetirlo_no_cambia_nada(self):
        sis, falso = self.rocky()
        self.instalar()
        desde = len(sis.ordenes)
        plan = self.plan()
        self.assertEqual(plan.cambios, [], plan.cambios)
        self.assertIn("Todo al día: 0 cambios.", pintar(plan))
        self.assertIn("firewalld  activo", pintar(plan))
        self.assertIn("SELinux    enforcing", pintar(plan))
        aplicar(sis, plan, self.man, ORIGEN, salida=self.salida.append)
        cambian = [o for o in sis.ordenes[desde:] if o[0] in ("dnf", "semanage", "restorecon") and "-l" not in o
                   or o[:1] == ["firewall-cmd"] and any(x.startswith("--add-") for x in o)]
        self.assertEqual(cambian, [])

    def test_desinstalar_lo_deja_como_estaba(self):
        sis, falso = self.rocky()
        antes = sis.foto()
        activos, ahora, permanente = set(falso.activos), set(falso.fw_ahora), set(falso.fw_permanente)
        self.instalar()
        quedan = desinstalar(sis, Manifiesto.leer(sis), quitar_paquetes=True, salida=self.salida.append)
        self.assertEqual(quedan, [])
        self.assertEqual((falso.fw_ahora, falso.fw_permanente), (ahora, permanente))
        self.assertEqual(falso.etiquetas, {})
        self.assertIn(["systemctl", "disable", "--now", "strongswan.service"], sis.ordenes)
        self.assertIn(["dnf", "remove", "-y", "-q", "strongswan", "qrencode", "nginx", "policycoreutils-python-utils"],
                      sis.ordenes)
        despues = sis.foto()
        # Los ficheros que dejan los paquetes (nginx.conf, swanctl.conf) no son del instalador: el falso no los borra
        # al quitar el paquete, igual que dnf con los de configuración. Lo demás, exactamente como antes.
        de_paquetes = {r for r in set(despues) - set(antes) if r.startswith(("/etc/nginx", "/etc/strongswan", "/usr/"))}
        self.assertEqual(sorted((set(despues) ^ set(antes)) - de_paquetes), [])
        self.assertEqual(falso.activos - {"nginx"}, activos)

    def test_firewalld_apagado_se_queda_apagado(self):
        sis, falso = self.rocky()
        falso.firewalld = "inactivo"
        falso.fw_ahora = set()
        plan = self.instalar()
        self.assertTrue(any("firewalld está apagado" in a and "no lo enciendo" in a for a in plan.avisos))
        self.assertTrue(NUESTRAS <= falso.fw_permanente)
        self.assertIn(["firewall-offline-cmd", "--add-port=500/udp"], sis.ordenes)
        self.assertFalse([o for o in sis.ordenes if o[:1] == ["firewall-cmd"] and o[1:] != ["--state"]])
        self.assertEqual(falso.firewalld, "inactivo")
        self.assertIn("firewalld  apagado (no lo enciendo)", pintar(self.plan()))
        # Y desinstalar las quita igual, sin encenderlo.
        permanente = set(falso.fw_permanente) - NUESTRAS
        self.assertEqual(desinstalar(sis, Manifiesto.leer(sis), salida=self.salida.append), [])
        self.assertEqual(falso.fw_permanente, permanente)

    def test_las_reglas_de_otro_se_quedan(self):
        sis, falso = self.rocky()
        falso.fw_ahora.add("port=500/udp")
        falso.fw_permanente.add("port=500/udp")
        plan = self.instalar()
        self.assertEqual(self.accion(plan, "UDP 500 (IKEv2)").estado, "ya está (no es mío)")
        self.assertNotIn("firewall-cmd --add-port=500/udp", Manifiesto.leer(sis).reglas)
        desinstalar(sis, Manifiesto.leer(sis), salida=self.salida.append)
        self.assertIn("port=500/udp", falso.fw_permanente, "no es suya: no la quita")

    def test_sin_firewalld_ni_ufw_avisa(self):
        sis, falso = self.rocky()
        sis.borrar("/usr/bin/firewall-cmd")
        det = self.detectar()
        self.assertIsNone(det.firewalld)
        self.assertTrue(any("No hay ningún cortafuegos" in a for a in det.avisos))

    def test_selinux_con_el_puerto_ya_etiquetado(self):
        sis, falso = self.rocky()
        falso.instalar_paquete("policycoreutils-python-utils")
        falso.etiquetas["8642"] = "http_port_t"
        plan = self.instalar()
        self.assertEqual(self.accion(plan, "tcp/8642").estado, "ya está (no es mío)")
        self.assertNotIn("policycoreutils-python-utils", [a.objeto for a in plan.acciones if a.tipo == "paquete"])
        desinstalar(sis, Manifiesto.leer(sis), salida=self.salida.append)
        self.assertEqual(falso.etiquetas, {"8642": "http_port_t"}, "no es suya: no la quita")

    def test_selinux_con_el_puerto_de_otro_se_para(self):
        sis, falso = self.rocky()
        falso.instalar_paquete("policycoreutils-python-utils")
        falso.etiquetas["8642"] = "postgresql_port_t"
        plan = self.plan()
        self.assertTrue(any("postgresql_port_t" in b for b in plan.bloqueos), plan.bloqueos)

    def test_sin_selinux_ni_semanage_ni_restorecon(self):
        sis, falso = self.rocky()
        falso.selinux = "Disabled"
        plan = self.instalar()
        self.assertFalse([a for a in plan.acciones if a.tipo == "selinux"])
        self.assertFalse([o for o in sis.ordenes if o[0] in ("semanage", "restorecon")])
        self.assertNotIn("policycoreutils-python-utils", [a.objeto for a in plan.acciones if a.tipo == "paquete"])

    def test_un_strongswan_ajeno_y_parado_no_se_arranca(self):
        sis, falso = self.rocky()
        falso.instalar_paquete("strongswan")
        plan = self.plan()
        self.assertTrue(any("strongSwan está instalado pero parado" in b for b in plan.bloqueos), plan.bloqueos)

    def test_los_avisos_todavia_no(self):
        self.rocky()
        plan = self.plan(avisos=True)
        self.assertTrue(any("solo en Debian y Ubuntu" in b for b in plan.bloqueos), plan.bloqueos)

    @mock.patch.object(porchat, "_azar", lambda n: 443)
    def test_el_canje_por_chat_abre_su_puerto_solo_mientras_dura(self):
        sis, falso = self.rocky()
        texto = []
        codigo = cli.main(["instalar", "--modo", "vpn", "--por-chat", "--iphone", "mi-iphone", "--llave",
                           "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkc"], "uso", ORIGEN, sis=sis,
                          entrada=lambda _: "n", salida=texto.append, terminal=False, euid=0)
        self.assertEqual(codigo, 0, "\n".join(texto))
        self.assertTrue(texto[-1].startswith("hehermes-canje:1?h=%s&p=58443&" % sf.IP_PUBLICA), texto[-1])
        self.assertIn("port=58443/tcp", falso.fw_ahora)
        self.assertNotIn("port=58443/tcp", falso.fw_permanente, "solo en la de ahora: no sobrevive a un reinicio")
        estado = json.loads(sis.leer_texto(porchat.RUN + "/estado.json"))
        self.assertEqual(estado["cortafuegos"], "firewalld")
        carga = json.loads(sis.leer_texto(porchat.RUN + "/canje.json"))["carga"]
        self.assertEqual(carga["k"], sf.PSK, "la PSK, de la conexión en /etc/strongswan/swanctl")
        porchat.limpiar(sis, {})
        self.assertNotIn("port=58443/tcp", falso.fw_ahora)

    @mock.patch.object(porchat, "_azar", lambda n: 443)
    def test_el_canje_no_cierra_un_puerto_que_ya_estaba_abierto(self):
        sis, falso = self.rocky()
        falso.fw_ahora.add("port=58443/tcp")
        texto = []
        cli.main(["instalar", "--modo", "vpn", "--por-chat", "--iphone", "mi-iphone", "--llave",
                  "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkc"], "uso", ORIGEN, sis=sis, entrada=lambda _: "n",
                 salida=texto.append, terminal=False, euid=0)
        porchat.limpiar(sis, {})
        self.assertIn("port=58443/tcp", falso.fw_ahora)


if __name__ == "__main__":
    unittest.main()
