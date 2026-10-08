"""Actualizar Hermes antes de instalar (desde la 0.12.0, `hehermes_servidor/actualizar_hermes.py`; Daniel, 2026-10-08),
sobre el servidor falso: su `hermes update` de mentira trae una versión nueva al disco, mueve su checkout de git y, si se
le pide, reinicia él mismo la unidad; Hermes vuelve (o no) con lo que haya en el disco.

Por chat va en la unidad de segundo plano de mentira de `test_fondo` (`Base`): la de dentro corre entera al lanzarla, o se
queda a medias diciendo que va a reiniciar a Hermes. Los relojes de quien la sigue y de la espera a Hermes son de mentira:
avanzan con cada espera.
"""

import apoyo

import os
import re
import unittest
from unittest import mock

import servidor_falso as sf
import test_fondo
from hehermes_servidor import actualizar_hermes as ah
from hehermes_servidor import ambito as amb
from hehermes_servidor import capacidades as cap
from hehermes_servidor import cli, fondo, marcha
from hehermes_servidor.manifiesto import Manifiesto

ORIGEN = str(apoyo.RAIZ)
LLAVE = test_fondo.LLAVE
ENLACE = test_fondo.ENLACE
REINICIO = re.compile(r"^hehermes-reinicio: (\S+) \((\d+) s\)$")
ORDEN = "/root/.hermes/hermes-agent/venv/bin/hermes"


class Base(test_fondo.Base):
    """La de `test_fondo`, con un Hermes de julio (la 0.19.0, la del probador del 2026-10-08) instalado como lo deja su
    instalador (un checkout de git con su venv) y la espera a Hermes con el reloj de mentira."""

    version = "0.19.0"

    def setUp(self):
        super().setUp()
        self.carpeta = self.falso.con_checkout(self.version)
        for nombre, valor in (("_reloj", self.reloj), ("_dormir", self.reloj.dormir)):
            parche = mock.patch.object(ah, nombre, valor)
            parche.start()
            self.addCleanup(parche.stop)

    def por_chat(self, llave=LLAVE, iphone="mi-iphone", actualizar=True):
        return self.orden("instalar", "--por-chat", "--activar-api", *(["--actualizar-hermes"] if actualizar else []),
                          "--iphone", iphone, "--llave", llave)

    def por_ssh(self, *mas):
        return self.orden("instalar", "--si", "--actualizar-hermes", *mas)

    def updates(self):
        return [o for o in self.sis.ordenes if o[-1:] == ["update"]]

    def reinicios_de_hermes(self):
        return [r for r in self.falso.reinicios if "hermes-gateway" in r]

    def avisos(self):
        return [l for l in self.lineas if l.startswith(marcha.PREFIJO_AVISO)]


class PorChat(Base):
    def test_lo_actualiza_antes_de_nada_y_da_el_enlace(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        [update] = self.updates()
        self.assertEqual(update, ["env", "HOME=/root", update[2], "NO_COLOR=1", "GIT_TERMINAL_PROMPT=0",
                                  "LC_ALL=C.UTF-8", "LANG=C.UTF-8", ORDEN, "update"])
        self.assertTrue(update[2].startswith("PATH=/root/.local/bin:/root/.cargo/bin:"), update[2])
        self.assertEqual(self.falso.updates, [""], "sin nada en la entrada: si pregunta algo, lee el final")
        self.assertEqual(self.reinicios_de_hermes(), ["hermes-gateway"])
        self.assertEqual(self.falso.version_hermes, "0.21.4")
        # Lo que se lee en el chat: que se va a reiniciar (antes de tocar nada), que ha vuelto, y el aviso para la app.
        [reinicio] = [l for l in self.lineas if REINICIO.match(l.strip())]
        self.assertEqual(REINICIO.match(reinicio).group(1), "0.19.0")
        self.assertLess(self.lineas.index(reinicio), self.lineas.index(next(l for l in self.lineas
                                                                             if l.startswith(marcha.DE_VUELTA))))
        self.assertIn("vas a reiniciarte en cuanto acabe este turno, y es normal", self.salida)
        self.assertIn("%s ya es la 0.21.4 (antes, la 0.19.0)." % marcha.DE_VUELTA, self.lineas)
        self.assertIn("He actualizado tu Hermes antes de nada: de la 0.19.0 a la 0.21.4", self.salida)
        self.assertIn("hehermes-aviso:hermes-actualizado antes=0.19.0 version=0.21.4", self.avisos())
        self.assertNotIn("hermes-antiguo", self.salida)
        self.assertNotIn("hehermes-error:", self.salida)

    def test_espera_a_que_acabe_el_turno_antes_de_actualizarlo(self):
        """Lo primero, la línea del reinicio; después, el margen para que Hermes conteste; y solo después, `hermes
        update`. El que la sigue (el primero de los antepasados que le pasó) tiene que haber acabado."""
        momentos = {}
        hermes = self.falso._hermes

        def update(args, entrada):
            momentos.setdefault("update", self.reloj.ahora)
            return hermes(args, entrada)
        self.falso._hermes = update
        self.sis.pid = 9002
        self.sis.poner("/proc/9002/status", "Name:\tpython3\nPPid:\t1\n")
        self.sis.poner("/proc/9002/cmdline", b"/usr/bin/python3\0-I\0./hehermes-servidor-0.12.0/hehermes-servidor\0")
        self.reloj.a_los(25, lambda: os.unlink(self.sis.ruta("/proc/9002/cmdline")))
        inicio = self.reloj.ahora
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertGreaterEqual(momentos["update"] - inicio, 25 + ah.GRACIA_DEL_TURNO)
        self.assertLess(momentos["update"] - inicio, ah.ESPERA_AL_QUE_SIGUE)

    def test_el_que_la_sigue_acaba_con_la_linea_del_reinicio_y_la_deja_en_marcha(self):
        def hasta_el_reinicio(orden):
            self.unidad = orden
            with open(self.sis.ruta(self.fichero_de(orden)), "a", encoding="utf-8") as f:
                f.write("==> Tu Hermes es la 0.19.0…\n%s 0.19.0 (3 s)\n" % marcha.PREFIJO_REINICIO)
        self.falso.al_instalar_en_segundo_plano = hasta_el_reinicio
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertEqual(self.ultima(), "hehermes-reinicio: 0.19.0 (3 s)")
        self.assertIn("hehermes-instalar", self.falso.activos)
        self.assertLess(self.reloj.ahora - 1000, 5, "no espera al plazo: acaba en cuanto la ve")
        # El mismo comando otra vez, mientras sigue en eso (antes del reinicio): se engancha y acaba enseguida, igual.
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertIn("ya está en marcha", self.salida)
        self.assertEqual(self.ultima(), "hehermes-reinicio: 0.19.0 (3 s)")
        self.assertEqual(len(self.lanzadas()), 1)
        # Hermes vuelve y la instalación sigue: el mismo comando otra vez la sigue, ahora sí, hasta el enlace.
        with open(self.sis.ruta(self.fichero_de(self.unidad)), "a", encoding="utf-8") as f:
            f.write("%s ya es la 0.21.4 (antes, la 0.19.0).\n" % marcha.DE_VUELTA)
        self.falso.version_hermes = "0.21.4"
        self.reloj.a_los(5, self.acabarla)
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(len(self.lanzadas()), 1)
        self.assertGreaterEqual(self.reloj.ahora - 1000, 5, "esta vez la ha seguido")

    def test_con_su_api_apagada_espera_a_su_unidad_y_la_enciende_despues(self):
        """Lo de casi todos la primera vez: la API de Hermes apagada (`--activar-api`). Sin /health, vuelve cuando su
        unidad está en marcha con otro proceso, el mismo dos veces; la versión, la de su código; y la API se enciende al
        final, como siempre."""
        sis, falso = sf.servidor(habilitada=False)
        self.addCleanup(sis.limpiar)
        self.sis, self.falso = sis, falso
        falso.programa("/usr/bin/systemd-run")
        falso.al_instalar_en_segundo_plano = self.correr_la_de_dentro
        falso.con_checkout("0.19.0")
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(len(self.updates()), 1)
        self.assertIn("%s ya es la 0.21.4 (antes, la 0.19.0)." % marcha.DE_VUELTA, self.lineas)
        self.assertIn("hehermes-aviso:hermes-actualizado antes=0.19.0 version=0.21.4", self.avisos())
        self.assertIn("API_SERVER_ENABLED=true", self.sis.leer_texto("/root/.hermes/.env"))
        self.assertIn("versión 0.21.4 (la de su código", self.salida)

    def test_una_unidad_de_usuario_como_su_dueno(self):
        """`hermes gateway install` sin --system: su reinicio, en el systemd de su usuario, y `hermes update` con él a
        mano (el de verdad reinicia su unidad con `systemctl --user`)."""
        sis, falso = sf.servidor(usuario="hermes", como="unidad-usuario")
        self.addCleanup(sis.limpiar)
        self.sis, self.falso = sis, falso
        falso.programa("/usr/bin/systemd-run")
        falso.al_instalar_en_segundo_plano = self.correr_la_de_dentro
        falso.con_checkout("0.19.0", usuario="hermes")
        uid = falso.uid_de("hermes")
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        [update] = self.updates()
        self.assertEqual(update[:4], ["runuser", "-u", "hermes", "--"])
        self.assertIn("XDG_RUNTIME_DIR=/run/user/%d" % uid, update)
        self.assertEqual(self.reinicios_de_hermes(), ["usuario:hermes-gateway-3f2a9c1b"])
        self.assertIn("hehermes-aviso:hermes-actualizado antes=0.19.0 version=0.21.4", self.avisos())

    def test_con_la_frase_de_la_app_se_instala_al_momento_y_lo_dice(self):
        """La frase no lleva `--actualizar-hermes` (Daniel, 2026-10-08): con un Hermes antiguo se instala al momento con
        lo que tenga, sin tocarlo, y se dice claro que se instala y qué trae «/update»; para la app, el aviso
        `hermes-sin-actualizar` con `motivo=sin-permiso`."""
        self.assertEqual(self.por_chat(actualizar=False), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.updates(), [])
        self.assertEqual(self.reinicios_de_hermes(), [])
        self.assertIn("le falta elegir el modelo (GET /api/model/options); escribirle mientras trabaja (POST "
                      "/v1/runs/{id}/steer). Instalo igual: la app funciona sin eso, y lo tendrás en cuanto lo "
                      "actualices («/update» en su chat", self.salida)
        self.assertIn("Tu Hermes es la 0.19.0: la app funciona", self.salida)
        self.assertFalse([l for l in self.lineas if REINICIO.match(l.strip())])
        self.assertIn("hehermes-aviso:hermes-sin-actualizar version=0.19.0 motivo=sin-permiso", self.avisos())
        self.assertFalse([a for a in self.avisos() if "hermes-actualizado" in a])

    def test_aqui_mismo_no_lo_actualiza_porque_su_reinicio_me_cortaria(self):
        import os
        os.unlink(self.sis.ruta("/usr/bin/systemd-run"))
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.updates(), [])
        self.assertIn("hehermes-aviso:hermes-sin-actualizar version=0.19.0 motivo=primer-plano", self.avisos())
        self.assertIn("su reinicio me cortaría", self.salida)


class PorSSH(Base):
    def test_lo_actualiza_sin_esperar_a_ningun_turno(self):
        inicio = self.reloj.ahora
        self.assertEqual(self.por_ssh(), 0, self.salida)
        self.assertEqual(len(self.updates()), 1)
        self.assertEqual(self.falso.version_hermes, "0.21.4")
        self.assertLess(self.reloj.ahora - inicio, ah.GRACIA_DEL_TURNO, "por un terminal no hay turno que esperar")
        self.assertFalse([l for l in self.lineas if l.startswith((marcha.PREFIJO_REINICIO, "    Hermes:",
                                                                   marcha.PREFIJO_AVISO))], "nada para el chat")
        self.assertIn("He actualizado tu Hermes antes de nada: de la 0.19.0 a la 0.21.4", self.salida)
        self.assertIn("hehermes-pasarela", self.falso.activos)

    def test_si_el_update_ya_lo_reinicia_no_lo_reinicia_otra_vez(self):
        self.falso.update_reinicia = True
        self.assertEqual(self.por_ssh(), 0, self.salida)
        self.assertEqual(self.reinicios_de_hermes(), ["hermes-gateway"], "uno: el suyo")
        self.assertIn("hermes update lo ha reiniciado", self.salida)
        self.assertIn("He actualizado tu Hermes antes de nada: de la 0.19.0 a la 0.21.4", self.salida)

    def test_como_el_dueno_de_su_codigo(self):
        sis, falso = sf.servidor(usuario="hermes")
        self.addCleanup(sis.limpiar)
        self.sis, self.falso = sis, falso
        falso.con_checkout("0.19.0", usuario="hermes")
        self.assertEqual(self.por_ssh(), 0, self.salida)
        [update] = self.updates()
        self.assertEqual(update[:4], ["runuser", "-u", "hermes", "--"])
        self.assertIn("HOME=/home/hermes", update)
        self.assertEqual(update[-2:], ["/home/hermes/.hermes/hermes-agent/venv/bin/hermes", "update"])

    def test_con_plan_dice_lo_que_haria_y_no_lo_toca(self):
        self.assertEqual(self.orden("instalar", "--plan", "--actualizar-hermes"), 0, self.salida)
        self.assertEqual(self.updates(), [])
        self.assertIn("Con --actualizar-hermes: Tu Hermes es la 0.19.0, y la app lo aprovecha entero desde la 0.21.1: "
                      "lo actualizaría antes de nada", self.salida)

    def test_si_algo_mas_para_la_instalacion_no_lo_toca(self):
        """Hermes solo se actualiza para seguir: si la instalación se va a parar por otra cosa, ni se toca."""
        self.falso.direccion_salida = "10.0.0.5"
        self.falso.enlaces_ip["eth0"]["addr"] = ["10.0.0.5/24"]
        self.assertEqual(self.por_ssh(), 1, self.salida)
        self.assertEqual(self.updates(), [])
        self.assertNotIn("Con --actualizar-hermes", self.salida)


class ElQueYaLaTiene(Base):
    version = "0.21.3"

    def test_no_se_toca(self):
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.updates(), [])
        self.assertEqual(self.reinicios_de_hermes(), [])
        self.assertFalse([l for l in self.lineas if REINICIO.match(l.strip())])
        self.assertNotIn("actualiz", " ".join(self.avisos()))

    def test_tampoco_sin_decir_su_version_si_tiene_todo(self):
        self.falso.version_hermes = None
        self.assertEqual(self.por_ssh(), 0, self.salida)
        self.assertEqual(self.updates(), [])

    def test_la_recomendada_justa_tampoco(self):
        self.falso.version_hermes = "0.21.1"
        self.assertEqual(self.por_ssh(), 0, self.salida)
        self.assertEqual(self.updates(), [])


class SiFalla(Base):
    def test_un_update_que_falla_sin_cambiar_nada_deja_a_hermes_como_estaba_y_sigue(self):
        self.falso.update_trae, self.falso.update_sale_bien = None, False
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())
        self.assertEqual(self.reinicios_de_hermes(), [], "ni se reinicia")
        self.assertEqual(self.falso.version_hermes, "0.19.0")
        self.assertIn("hermes update ha fallado (ha salido con 1)", self.salida)
        self.assertIn("hehermes-aviso:hermes-sin-actualizar version=0.19.0 motivo=fallo", self.avisos())
        self.assertIn("No he actualizado tu Hermes: hermes update ha fallado sin cambiar su código", self.salida)
        # Lo que dijo, sin credenciales: lo lee el modelo.
        self.assertIn("error: git pull falló en https://…@servidor-git/x.git", self.salida)
        self.assertNotIn("TOKEN-DE-MENTIRA", self.salida)
        self.assertNotIn("secreto-de-mentira", self.salida)

    def test_uno_que_falla_despues_de_traer_el_codigo_se_reinicia_y_vale(self):
        """`hermes update` puede fallar al preguntar algo (su entrada está vacía) con el código ya traído: lo que cuenta
        es su código."""
        self.falso.update_sale_bien = False
        self.assertEqual(self.por_ssh(), 0, self.salida)
        self.assertEqual(self.reinicios_de_hermes(), ["hermes-gateway"])
        self.assertIn("He actualizado tu Hermes antes de nada: de la 0.19.0 a la 0.21.4", self.salida)

    def test_por_debajo_de_la_de_respaldo_y_sin_poder_actualizarlo_para_y_dice_por_que(self):
        self.falso.version_hermes = "0.14.0"
        self.falso.codigo_de_hermes("0.14.0")
        self.falso.update_trae, self.falso.update_sale_bien = None, False
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.lineas[-2:], ["hehermes-detalle:version=0.14.0 minima=0.15.0 "
                                            "falta=bandeja,nueva,historial,ficha actualizar=fallo",
                                            "hehermes-error:hermes-antiguo"])
        self.assertIn("No he actualizado tu Hermes: hermes update ha fallado", self.salida)
        self.assertFalse(Manifiesto.leer(self.sis).en_disco, "de HeHermes, nada")


class SiNoVuelve(Base):
    def test_se_deja_como_estaba_y_sigue_con_la_de_antes(self):
        self.falso.vuelve_tras_reiniciar = False
        inicio = self.reloj.ahora
        self.assertEqual(self.por_chat(), 0, self.salida)
        self.assertGreaterEqual(self.reloj.ahora - inicio, ah.PLAZO_DE_VUELTA, "le ha dado su plazo")
        self.assertEqual(self.falso.git_resets, ["a" * 40])
        self.assertEqual(self.reinicios_de_hermes(), ["hermes-gateway", "hermes-gateway"])
        self.assertEqual(self.falso.version_hermes, "0.19.0")
        self.assertIn("git reset --keep aaaaaaaaaaaa", self.salida)
        self.assertIn("hehermes-aviso:hermes-sin-actualizar version=0.19.0 motivo=no-volvio", self.avisos())
        self.assertTrue(ENLACE.match(self.ultima()), self.ultima())

    def test_no_se_toca_un_checkout_con_cambios_sin_guardar(self):
        self.falso.vuelve_tras_reiniciar = False
        self.falso.git_sucio = " M hermes_cli/main.py\n"
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.falso.git_resets, [])
        self.assertIn("No devuelvo su código a como estaba: tiene cambios sin guardar", self.salida)
        self.assertEqual(self.ultima(), "hehermes-error:hermes-no-volvio")

    def test_si_tampoco_vuelve_con_lo_de_antes_para_y_lo_dice(self):
        self.falso.vuelve_tras_reiniciar = self.falso.vuelve_tras_deshacer = False
        self.assertEqual(self.por_chat(), 1, self.salida)
        self.assertEqual(self.lineas[-2:], ["hehermes-detalle:version=0.19.0", "hehermes-error:hermes-no-volvio"])
        self.assertIn("Tu Hermes no ha vuelto después de actualizarlo (hermes update y su reinicio): en 15 minutos no "
                      "contesta, ni con su código devuelto a como estaba (la 0.19.0). No he instalado nada de HeHermes",
                      self.salida)
        self.assertIn("journalctl -u hermes-gateway.service -n 50", self.salida)
        self.assertFalse(Manifiesto.leer(self.sis).en_disco, "de HeHermes, nada")
        self.assertNotIn("hehermes-pasarela", self.falso.activos)

    def test_sin_checkout_de_git_no_hay_como_deshacerlo(self):
        self.falso.vuelve_tras_reiniciar = False
        self.falso.git_head = None
        self.assertEqual(self.por_ssh(), 1, self.salida)
        self.assertIn("No puedo devolver su código a como estaba", self.salida)
        self.assertIn("en 10 minutos no contesta. No he instalado nada", self.salida)
        self.assertFalse([l for l in self.lineas if l.startswith(("hehermes-error:", "hehermes-detalle:"))],
                         "por un terminal, nada para la app")


class EnUnContenedor(Base):
    """Hermes en Docker: no se actualiza (lo de dentro se pierde al recrearlo), y se dice; se sigue desde la 0.15.0."""

    def servidor(self):
        sis, falso = sf.servidor(como="docker")
        return sis, falso

    def setUp(self):
        super().setUp()
        self.falso.version_hermes = "0.19.0"

    def test_no_lo_actualiza_y_lo_dice(self):
        det_y_plan = self.decidir()
        self.assertEqual(det_y_plan.motivo, "contenedor")
        self.assertIn("va en el contenedor de Docker", det_y_plan.texto)
        self.assertIn("se pierde al recrearlo", det_y_plan.texto)

    def test_por_debajo_de_la_de_respaldo_para_y_dice_por_que(self):
        self.falso.version_hermes = "0.14.0"
        self.por_ssh()
        self.assertEqual(self.updates(), [])
        self.assertIn("No actualizo tu Hermes (la 0.14.0): va en el contenedor de Docker", self.salida)
        self.assertIn("No puedo seguir:", self.salida)

    def decidir(self):
        from hehermes_servidor.modo_tls import calcular_plan_tls, detectar_tls
        from hehermes_servidor.plan import Opciones
        man = Manifiesto.leer(self.sis)
        det = detectar_tls(self.sis, man, amb.de_root())
        opciones = Opciones(actualizar_hermes=True, si=True)
        plan = calcular_plan_tls(self.sis, det, man, opciones, ORIGEN)
        self.assertEqual([getattr(b, "codigo", None) for b in plan.bloqueos], [])
        self.assertEqual(det.hermes.version, "0.19.0")
        return ah.decidir(self.sis, det, plan, opciones, amb.de_root())


class LaDeRespaldo(unittest.TestCase):
    def test_lo_que_hace_falta_actualizar(self):
        class H:
            def __init__(self, version, ausentes=()):
                self.version = version
                self.sondeo = cap.Sondeo(version)
                self.sondeo.ausentes = set(ausentes)
        self.assertTrue(ah.hace_falta(H("0.19.0")))
        self.assertTrue(ah.hace_falta(H("0.21.0")))
        self.assertFalse(ah.hace_falta(H("0.21.1")))
        self.assertFalse(ah.hace_falta(H("0.21.4+canary.20260925T065930Z")))
        self.assertFalse(ah.hace_falta(H(None)), "sin saber nada, no se toca")
        self.assertTrue(ah.hace_falta(H(None, {"desviar"})), "sin versión, la sonda dice que es de antes")
        self.assertFalse(ah.hace_falta(H(None, {"tareas"})), "lo opcional de siempre no dice nada de su edad")
        self.assertFalse(ah.hace_falta(None))

    def test_la_frase_del_que_la_sigue(self):
        reinicio = "%s 0.19.0 (3 s)" % marcha.PREFIJO_REINICIO
        self.assertTrue(fondo.en_reinicio("hehermes-paso: 1/9 paquetes (0 s)\n" + reinicio + "\n"))
        for despues in (marcha.DE_VUELTA + " ya es la 0.21.4.", "hehermes-paso: 1/9 ficheros (300 s)",
                        "hehermes-error:hermes-no-volvio", "hehermes-canje:1?h=x", "hehermes-sigue: preparando (9 s)"):
            with self.subTest(despues=despues):
                self.assertFalse(fondo.en_reinicio(reinicio + "\n" + despues + "\n"))
        self.assertFalse(fondo.en_reinicio("Si acaba en «hehermes-reinicio:», es normal"), "lo que cita la frase, no")


if __name__ == "__main__":
    unittest.main()
