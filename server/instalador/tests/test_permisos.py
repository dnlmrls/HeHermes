"""Los permisos, lo primero de todo: root, sudo sin contraseña, la pasarela como el usuario, o parar en seco sin haber
tocado nada.

Por chat es Hermes quien lanza el instalador, y puede no ser root ni tener sudo. `id -u` es el `euid` que se le pasa a
`cli.main`; `sudo -n` lo contesta el servidor falso (`ServidorFalso.sudo`). Nunca se pide una contraseña.

Sin root ni sudo, `instalar` pone la pasarela en la casa del usuario (`test_modo_tls.SinRoot`). Aquí, lo que se para:
un `instalar` cuya casa no se puede usar y las órdenes que no son de una instalación suya. Hasta la 0.6.0, por chat eso
acababa con `hehermes-error:sin-permisos`, que era de la VPN: ya no sale nunca.
"""

import apoyo

import base64
import os
import unittest

import servidor_falso as sf
from hehermes_servidor import VERSION, cli, permisos

ORIGEN = str(apoyo.RAIZ)
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()
LANZADOR = os.path.join(ORIGEN, "hehermes-servidor")
#: Un usuario cuya casa no se puede poner en una unidad de systemd: sin root, no hay dónde instalar.
SIN_CASA = ("hermes", "/", 1000)


class Base(unittest.TestCase):
    def setUp(self):
        self.sis, self.falso = sf.servidor()
        self.addCleanup(self.sis.limpiar)
        self.relanzados = []

    def orden(self, *argv, euid=1000, terminal=False, cuenta=SIN_CASA):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=terminal, euid=euid, relanzar=self.relanzados.append, usuario="hermes",
                          cuenta=cuenta)
        self.salida = "\n".join(self.texto)
        return codigo

    def por_chat(self, **kw):
        return self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE, **kw)

    def sin_cambios(self):
        """Ni una orden más que las que preguntan por los permisos, y ni un fichero nuevo."""
        for orden in self.sis.ordenes:
            self.assertEqual(orden[:2], ["sudo", "-n"], "orden de más sin permisos: %s" % orden)
            self.assertNotIn(orden[2:3], (["-S"], ["-v"]), "nunca se pide la contraseña")
        self.assertFalse(self.sis.existe("/etc/hehermes"))
        self.assertFalse(self.sis.existe("/run/hehermes-servidor.lock"))

    def sin_linea_de_error(self):
        self.assertNotIn("hehermes-error", self.salida)


class Decidir(unittest.TestCase):
    def test_los_casos(self):
        self.assertEqual(permisos.decidir(0, "no-permitido", False), "root")
        self.assertEqual(permisos.decidir(1000, "sin-contrasena", False), "sudo")
        self.assertEqual(permisos.decidir(1000, "sin-contrasena", True), "sudo")
        self.assertEqual(permisos.decidir(1000, "contrasena", True), "instalado")
        for sudo in ("sin-sudo", "contrasena", "no-permitido"):
            with self.subTest(sudo=sudo):
                self.assertEqual(permisos.decidir(1000, sudo, False), "nada")


class Root(Base):
    def test_como_root_ni_pregunta_a_sudo(self):
        self.assertEqual(self.orden("instalar", "--plan", euid=0), 0, self.salida)
        self.assertFalse([o for o in self.sis.ordenes if o[:1] == ["sudo"]])
        self.assertEqual(self.relanzados, [])


class SudoSinContrasena(Base):
    def test_se_relanza_con_sudo_n_y_los_mismos_argumentos(self):
        self.falso.sudo = "sin-contrasena"
        self.assertEqual(self.por_chat(cuenta=None), 0)
        self.assertEqual(self.relanzados, [["sudo", "-n", "-u", "root", "--", "/usr/bin/python3", "-I", "-B", LANZADOR,
                                            "instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone",
                                            "--llave", LLAVE]])
        self.assertIn(["sudo", "-n", "true"], self.sis.ordenes)
        self.sin_cambios()

    def test_tambien_comprobar_y_desinstalar(self):
        self.falso.sudo = "sin-contrasena"
        self.orden("comprobar")
        self.assertEqual(self.relanzados[-1][-1:], ["comprobar"])
        self.orden("desinstalar", "--modo", "vpn")
        self.assertEqual(self.relanzados[-1][-3:], ["desinstalar", "--modo", "vpn"])

    def test_un_error_de_uso_se_dice_antes_de_mirar_permisos(self):
        self.falso.sudo = "sin-contrasena"
        self.assertEqual(self.orden("instalar", "--por-chat", "--iphone", "mi-iphone"), 2)
        self.assertEqual(self.orden("instalar", "--modo", "vpn"), 2)
        self.assertEqual(self.sis.ordenes, [])
        self.assertEqual(self.relanzados, [])


class SoloElInstaladoPorSudoers(Base):
    """La salida (b): sudo solo para /usr/local/sbin/hehermes-servidor, que es de root."""

    def instalado(self, version=VERSION):
        self.sis.poner("/opt/hehermes-servidor/hehermes_servidor/__init__.py", 'VERSION = "%s"\n' % version)
        self.sis.poner("/opt/hehermes-servidor/hehermes-servidor", "#!/usr/bin/python3 -IB\n", modo=0o755)
        self.sis.enlazar("/usr/local/sbin/hehermes-servidor", "/opt/hehermes-servidor/hehermes-servidor")

    def test_con_la_linea_de_sudoers_se_relanza_el_instalado(self):
        self.falso.sudo = "contrasena"
        self.falso.sudo_instalador = True
        self.instalado()
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(self.relanzados[0][:6], ["sudo", "-n", "-u", "root", "--", "/usr/local/sbin/hehermes-servidor"])
        self.assertEqual(self.relanzados[0][6:8], ["instalar", "--por-chat"])
        self.assertIn(["sudo", "-n", "-l", "/usr/local/sbin/hehermes-servidor"], self.sis.ordenes)

    def test_si_el_instalado_es_de_otra_version_no_lo_usa(self):
        self.falso.sudo = "contrasena"
        self.falso.sudo_instalador = True
        self.instalado("0.1.0")
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.relanzados, [])
        self.assertIn("0.1.0", self.salida)
        self.sin_linea_de_error()

    def test_sin_el_instalado_la_linea_no_sirve_de_nada(self):
        self.falso.sudo = "contrasena"
        self.falso.sudo_instalador = True
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.relanzados, [])


class SinPermisos(Base):
    def test_sin_sudo_ni_casa_para_en_seco_y_lo_explica(self):
        self.falso.sudo = "sin-sudo"
        self.assertEqual(self.por_chat(), 1)
        self.assertEqual(self.relanzados, [])
        self.sin_cambios()
        self.assertIn("la de «hermes» no sé usarla", self.salida)
        self.assertIn("permisos de administrador", self.salida)
        self.assertIn("No he hecho nada", self.salida)
        self.assertIn("no hay sudo", self.salida)
        # Las dos salidas, en su orden (la tercera era usar la pasarela en vez de la VPN).
        self.assertLess(self.salida.index("1. "), self.salida.index("2. "))
        self.assertNotIn("3. ", self.salida)
        self.assertNotIn("VPN", self.salida)
        self.assertIn("hermes ALL=(root) NOPASSWD: /usr/local/sbin/hehermes-servidor", self.salida)
        self.assertIn("visudo -f /etc/sudoers.d/hehermes-servidor", self.salida)
        self.assertIn("en la media hora siguiente a instalar", self.salida)
        self.sin_linea_de_error()

    def test_con_contrasena_ni_se_intenta_y_tiene_su_mensaje(self):
        self.falso.sudo = "contrasena"
        self.assertEqual(self.por_chat(), 1)
        self.sin_cambios()
        self.assertIn("pide una contraseña", self.salida)
        self.assertNotIn("no hay sudo", self.salida)
        self.sin_linea_de_error()

    def test_sin_permiso_en_sudoers(self):
        self.falso.sudo = "no-permitido"
        self.assertEqual(self.por_chat(), 1)
        self.sin_cambios()
        self.assertIn("no puede usar sudo", self.salida)

    def test_lo_que_no_es_instalar_sin_una_instalacion_suya_tambien_se_para(self):
        self.falso.sudo = "sin-sudo"
        for argv in (("comprobar",), ("desinstalar", "--modo", "vpn", "--si"), ("actualizar", "--paquete", "x",
                                                                                 "--firma", "y")):
            with self.subTest(argv=argv):
                self.assertEqual(self.orden(*argv, cuenta=("hermes", "/home/hermes", 1000)), 1)
                self.assertIn("permisos de administrador", self.salida)
                self.assertNotIn("no sé usarla", self.salida)
                self.sin_linea_de_error()
        self.sin_cambios()

    def test_el_comando_del_administrador_es_el_mismo_con_sudo(self):
        self.falso.sudo = "sin-sudo"
        self.por_chat()
        self.assertIn("sudo ./hehermes-servidor-%s/hehermes-servidor instalar --por-chat --activar-api --iphone "
                      "mi-iphone --llave %s" % (VERSION, LLAVE), self.salida)

    def test_con_el_paquete_al_lado_el_comando_lo_descarga_y_comprueba_otra_vez(self):
        """El administrador no ejecuta nada de la carpeta de Hermes: lo baja de nuevo y comprueba la suma."""
        import hashlib
        import tempfile
        carpeta = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, carpeta)
        paquete = os.path.join(carpeta, "hehermes-servidor-%s.tar.gz" % VERSION)
        with open(paquete, "wb") as f:
            f.write(b"el paquete")
        suma = hashlib.sha256(b"el paquete").hexdigest()
        texto = permisos.comando_del_administrador(os.path.join(carpeta, "hehermes-servidor-%s" % VERSION),
                                                  ["instalar", "--iphone", "mi iphone"])
        self.assertIn('echo "%s  hehermes-servidor-%s.tar.gz" | sha256sum -c -' % (suma, VERSION), texto)
        self.assertTrue(texto.startswith('d=$(mktemp -d) && cd "$d" && curl -fsSLO https://'), texto)
        self.assertTrue(texto.endswith("instalar --iphone 'mi iphone'"), "los argumentos, citados para la shell")


class ElFormato(unittest.TestCase):
    def test_hehermes_error_sin_permisos_ya_no_sale_nunca(self):
        """Era de `--modo vpn`, que ya no existe. La app aún sabe leerla (de un instalador de antes), pero este no la
        escribe en ningún caso."""
        self.assertFalse(hasattr(permisos, "ERROR_SIN_PERMISOS"))
        for sudo in ("sin-sudo", "contrasena", "no-permitido"):
            for por_chat in (True, False):
                with self.subTest(sudo=sudo, por_chat=por_chat):
                    lineas = permisos.mensaje(sudo, "hermes", ORIGEN, ["instalar"], por_chat, otra_version="0.1.0")
                    self.assertFalse([l for l in lineas if "hehermes-error" in l])
        # Ni como texto que se pueda imprimir: solo la nombra la historia de permisos.py.
        codigo = "".join(p.read_text() for p in (apoyo.RAIZ / "hehermes_servidor").glob("*.py"))
        self.assertFalse('"hehermes-error' in codigo or "'hehermes-error" in codigo)

    def test_la_linea_de_sudoers_solo_para_un_usuario_que_valga(self):
        self.assertEqual(permisos.linea_sudoers("hermes"), "hermes ALL=(root) NOPASSWD: /usr/local/sbin/hehermes-servidor")
        self.assertIn("<tu-usuario>", permisos.linea_sudoers("mal usuario; ALL"))


if __name__ == "__main__":
    unittest.main()
