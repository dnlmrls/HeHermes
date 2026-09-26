"""Más allá de Debian y Ubuntu: sus derivadas (por `ID_LIKE`) y la familia Red Hat (dnf y firewalld), con el servidor
falso de cada una. Lo que no está en la lista se para al empezar, sin haber ejecutado nada."""

import apoyo

import json
import unittest
from unittest import mock

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import cli
from hehermes_servidor import porchat
from hehermes_servidor.desinstalar import desinstalar
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import aplicar_tls, calcular_plan_tls, comprobar_tls, detectar_tls
from hehermes_servidor.plan import Opciones, pintar

ORIGEN = str(apoyo.RAIZ)
LA_SUYA = "port=61234/tcp"
LLAVE = "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkc"


class Base(unittest.TestCase):
    def setUp(self):
        azar = mock.patch.object(porchat, "_azar", lambda n: 3234)  # el 61234
        azar.start()
        self.addCleanup(azar.stop)

    def montar(self, distro, **hermes):
        self.sis, self.falso = sf.servidor(distro, **hermes)
        self.addCleanup(self.sis.limpiar)
        self.salida = []
        return self.sis, self.falso

    def detectar(self):
        return detectar_tls(self.sis, Manifiesto.leer(self.sis), amb.de_root())

    def plan(self, **opciones):
        self.man = Manifiesto.leer(self.sis)
        return calcular_plan_tls(self.sis, detectar_tls(self.sis, self.man, amb.de_root()), self.man,
                                 Opciones(**opciones), ORIGEN)

    def instalar(self, **opciones):
        plan = self.plan(**opciones)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        aplicar_tls(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        return plan

    def accion(self, plan, objeto):
        return next(a for a in plan.acciones if a.objeto == objeto)

    def rocky(self, **extra):
        """Rocky Linux 9 de serie: SELinux puesto y firewalld en marcha."""
        return self.montar(("rocky", "9.4"), **extra)


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
                self.assertEqual((det.familia, det.distro["base"]), ("debian", base))
                self.assertTrue(any("es una derivada de %s: la instalo como ella" % base in a for a in det.avisos))
                plan = self.plan()
                self.assertTrue(plan.puede_seguir, plan.bloqueos)

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
                det = self.detectar()
                self.assertEqual(det.bloqueos, [], "sin EPEL también: la pasarela no necesita strongSwan")
                self.assertEqual((det.familia, det.firewalld), ("rhel", "activo"))
                self.assertEqual(det.distro["arquitectura"], "amd64", "x86_64, con el nombre de Debian")
                self.assertFalse([a for a in det.avisos if "derivada" in a], "no son derivadas: son de la lista")

    def test_una_derivada_de_rhel_avisa(self):
        self.montar(("ol", "9.4"))
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

    def test_una_instalacion_limpia(self):
        sis, falso = self.rocky()
        self.instalar(iphone="mi-iphone")
        # Ni dnf (python3 ya trae venv en la familia Red Hat) ni nada de apt.
        self.assertFalse([o for o in sis.ordenes if o[0] in ("dnf", "apt-get", "dpkg") or "apt-get" in o])
        # firewalld: la regla de la pasarela en la de ahora y en la permanente, sin recargar (el falso para si se
        # recarga).
        self.assertIn(LA_SUYA, falso.fw_ahora)
        self.assertIn(LA_SUYA, falso.fw_permanente)
        man = Manifiesto.leer(sis)
        self.assertEqual(man.datos["familia"], "rhel")
        self.assertEqual(man.reglas, ["firewall-cmd --add-port=61234/tcp"])
        self.assertEqual(man.datos["cortafuegos"], "firewalld")
        resultados = comprobar_tls(sis, man, amb.de_root())
        self.assertTrue(all(bien for bien, _ in resultados), resultados)
        self.assertIn("firewalld: la regla de la pasarela está", [t for _, t in resultados])

    def test_repetirlo_no_cambia_nada(self):
        sis, falso = self.rocky()
        self.instalar()
        plan = self.plan()
        self.assertEqual(plan.cambios, [], plan.cambios)
        self.assertIn("Todo al día: 0 cambios.", pintar(plan))
        self.assertIn("firewalld  activo", pintar(plan))

    def test_desinstalar_lo_deja_como_estaba(self):
        sis, falso = self.rocky()
        antes = sis.foto()
        activos, ahora, permanente = set(falso.activos), set(falso.fw_ahora), set(falso.fw_permanente)
        self.instalar(iphone="mi-iphone")
        quedan = desinstalar(sis, Manifiesto.leer(sis), quitar_paquetes=True, salida=self.salida.append)
        self.assertEqual(quedan, [])
        self.assertEqual((falso.fw_ahora, falso.fw_permanente), (ahora, permanente))
        self.assertEqual(sis.foto(), antes)
        self.assertEqual(falso.activos, activos)
        self.assertFalse([o for o in sis.ordenes if o[0] == "dnf"])

    def test_firewalld_apagado_se_queda_apagado(self):
        sis, falso = self.rocky()
        falso.firewalld = "inactivo"
        falso.fw_ahora = set()
        plan = self.instalar()
        self.assertTrue(any("firewalld está apagado" in a and "no lo enciendo" in a for a in plan.avisos))
        self.assertIn(LA_SUYA, falso.fw_permanente)
        self.assertIn(["firewall-offline-cmd", "--add-port=61234/tcp"], sis.ordenes)
        self.assertFalse([o for o in sis.ordenes if o[:1] == ["firewall-cmd"] and o[1:] != ["--state"]])
        self.assertEqual(falso.firewalld, "inactivo")
        self.assertIn("firewalld  apagado (no lo enciendo)", pintar(self.plan()))
        # Y desinstalar la quita igual, sin encenderlo.
        permanente = set(falso.fw_permanente) - {LA_SUYA}
        self.assertEqual(desinstalar(sis, Manifiesto.leer(sis), salida=self.salida.append), [])
        self.assertEqual(falso.fw_permanente, permanente)

    def test_una_regla_de_otro_se_queda(self):
        sis, falso = self.rocky()
        falso.fw_ahora.add(LA_SUYA)
        falso.fw_permanente.add(LA_SUYA)
        plan = self.instalar()
        self.assertEqual(self.accion(plan, "TCP 61234 (la pasarela)").estado, "ya está (no es mío)")
        self.assertNotIn("firewall-cmd --add-port=61234/tcp", Manifiesto.leer(sis).reglas)
        desinstalar(sis, Manifiesto.leer(sis), salida=self.salida.append)
        self.assertIn(LA_SUYA, falso.fw_permanente, "no es suya: no la quita")

    def test_sin_firewalld_ni_ufw_avisa(self):
        sis, falso = self.rocky()
        sis.borrar("/usr/bin/firewall-cmd")
        det = self.detectar()
        self.assertIsNone(det.firewalld)
        self.assertTrue(any("No hay ningún cortafuegos" in a for a in det.avisos))

    def test_el_canje_por_chat_abre_su_puerto_solo_mientras_dura(self):
        sis, falso = self.rocky()
        texto = []
        with mock.patch.object(porchat, "_azar", lambda n: 443):
            codigo = cli.main(["instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE], "uso", ORIGEN,
                              sis=sis, entrada=lambda _: "n", salida=texto.append, terminal=False, euid=0)
        self.assertEqual(codigo, 0, "\n".join(texto))
        self.assertTrue(texto[-1].startswith("hehermes-canje:1?h=%s&p=58444&" % sf.IP_PUBLICA), texto[-1])
        self.assertIn("port=58444/tcp", falso.fw_ahora)
        self.assertNotIn("port=58444/tcp", falso.fw_permanente, "solo en la de ahora: no sobrevive a un reinicio")
        estado = json.loads(sis.leer_texto(porchat.RUN + "/estado.json"))
        self.assertEqual(estado["cortafuegos"], "firewalld")
        carga = json.loads(sis.leer_texto(porchat.RUN + "/canje.json"))["carga"]
        self.assertEqual(list(carga), ["h", "p", "f", "t"])
        porchat.limpiar(sis, {})
        self.assertNotIn("port=58444/tcp", falso.fw_ahora)

    def test_el_canje_no_cierra_un_puerto_que_ya_estaba_abierto(self):
        sis, falso = self.rocky()
        falso.fw_ahora.add("port=58444/tcp")
        texto = []
        with mock.patch.object(porchat, "_azar", lambda n: 443):
            cli.main(["instalar", "--por-chat", "--iphone", "mi-iphone", "--llave", LLAVE], "uso", ORIGEN, sis=sis,
                     entrada=lambda _: "n", salida=texto.append, terminal=False, euid=0)
        porchat.limpiar(sis, {})
        self.assertIn("port=58444/tcp", falso.fw_ahora)


if __name__ == "__main__":
    unittest.main()
