"""Lo que la app necesita del api_server de Hermes (`capacidades`, desde la 0.10.4), mirado antes de dar el QR o el
enlace, sin efectos, contra Hermes de mentira de distintas edades.

Las edades salen de `servidor_falso.RUTAS_HERMES`, la historia de verdad de sus rutas (las etiquetas de
NousResearch/hermes-agent), escrita aparte de la tabla del instalador: si las dos no dicen lo mismo, falla. La sonda de
verdad, contra aiohttp de verdad, en `ConAiohttp` (se salta sin aiohttp, y necesita poder escuchar en 127.0.0.1).
"""

import apoyo

import base64
import re
import threading
import unittest

import servidor_falso as sf
from hehermes_servidor import ambito as amb
from hehermes_servidor import capacidades as cap
from hehermes_servidor import cli
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.modo_tls import calcular_plan_tls, comprobar_tls, detectar_tls
from hehermes_servidor.plan import Opciones, pintar

ORIGEN = str(apoyo.RAIZ)
LLAVE = base64.urlsafe_b64encode(bytes(range(40, 72))).rstrip(b"=").decode()


def _plantilla(ruta):
    return re.sub(r"\{[^}]*\}", "{}", ruta)


class Base(unittest.TestCase):
    def montar(self, version="0.21.3", **hermes):
        self.sis, self.falso = sf.servidor(**hermes)
        self.addCleanup(self.sis.limpiar)
        self.falso.version_hermes = version
        return self.falso

    def detectar(self, **opciones):
        return detectar_tls(self.sis, Manifiesto.leer(self.sis), amb.de_root(), **opciones)

    def antiguo(self, det):
        return [b for b in det.bloqueos if getattr(b, "codigo", None) == "hermes-antiguo"]

    def orden(self, *argv):
        self.texto = []
        codigo = cli.main(list(argv), "uso", ORIGEN, sis=self.sis, entrada=lambda _: "n", salida=self.texto.append,
                          terminal=False, euid=0)
        self.salida = "\n".join(self.texto)
        return codigo


class LaTabla(unittest.TestCase):
    def test_la_minima_es_la_ultima_obligatoria_en_llegar(self):
        self.assertEqual(cap.MINIMA, max(cap.version(c.desde) for c in cap.CAPACIDADES if c.obligatoria))
        # Desde la 0.12.0 (Daniel, 2026-10-08): la de respaldo, las sesiones; el modelo y el desvío ya no paran.
        self.assertEqual(cap.texto_de(cap.MINIMA), "0.15.0")
        self.assertFalse(cap.POR_CLAVE["modelo"].obligatoria)
        self.assertFalse(cap.POR_CLAVE["desviar"].obligatoria)
        self.assertEqual(cap.texto_de(cap.RECOMENDADA), "0.21.1")

    def test_cada_capacidad_llega_cuando_dice_la_historia_de_hermes(self):
        historia = {}
        for metodo, ruta, desde in sf.RUTAS_HERMES:
            historia[(metodo, _plantilla(ruta))] = desde
        for c in cap.CAPACIDADES:
            with self.subTest(capacidad=c.clave):
                self.assertEqual(historia.get((c.metodo, _plantilla(c.ruta))), c.desde)

    def test_lo_que_usa_la_app_esta_en_la_tabla(self):
        """Cada ruta de §1 del contrato que la app llama tiene su capacidad (las de las tareas, por la de la lista)."""
        contrato = (apoyo.REPO / "server" / "API-CONTRACT.md").read_text()
        seccion = contrato[contrato.index("## 1. Rutas que usa HeHermes"):contrato.index("## 2.")]
        en_la_tabla = {(c.metodo, _plantilla(c.ruta)) for c in cap.CAPACIDADES}
        for metodo, ruta in re.findall(r"^(GET|POST|PATCH|DELETE)\s+(/\S+)", seccion, re.M):
            ruta = _plantilla(ruta.split("?", 1)[0])
            if ruta.startswith("/api/jobs") and (metodo, ruta) != ("GET", "/api/jobs"):
                # Las tareas llegaron todas juntas (la 0.4.0), y sin ellas la app dice «Tareas no disponibles».
                continue
            with self.subTest(ruta=(metodo, ruta)):
                self.assertIn((metodo, ruta), en_la_tabla)

    def test_la_version(self):
        for texto, esperada in (("0.21.3", (0, 21, 3)), ("v0.20.1", (0, 20, 1)), ("0.21.4+canary.20260925T065930Z",
                                                                                   (0, 21, 4)),
                                ("0.0.0", None), ("unknown", None), ("", None), (None, None), ("git.abc1234", None)):
            with self.subTest(texto=texto):
                self.assertEqual(cap.version(texto), esperada)

    def test_lo_que_dice_hermes_se_limpia_antes_de_pintarlo(self):
        self.assertEqual(cap.version_de_health(b'{"version": "0.21.3\\u001b[31m; rm -rf /"}'), "0.21.331mrm-rf")
        self.assertEqual(cap.version_de_health(b'{"version": "' + b"9" * 100 + b'"}'), "9" * 40)
        self.assertIsNone(cap.version_de_health(b"<html>"))
        self.assertIsNone(cap.version_de_health(b'{"status": "ok"}'))


class LasEdades(Base):
    """Un Hermes de cada edad: lo que la app necesita está o no, y se dice cuál falta."""

    def test_los_que_lo_tienen_todo_pasan_sin_avisos_de_hermes(self):
        for version in ("0.21.1", "0.21.3", "0.21.5", "0.0.0", None):
            with self.subTest(version=version):
                self.montar(version)
                det = self.detectar()
                self.assertEqual(self.antiguo(det), [])
                self.assertFalse([a for a in det.avisos if "Hermes" in a and ("versión" in a or "falta" in a)],
                                 det.avisos)
                self.assertTrue(det.hermes.sondeo.calibrada)
                self.assertEqual(det.hermes.sondeo.ausentes, set())

    def test_a_uno_sin_desvio_se_le_avisa_de_eso_y_sigue(self):
        """Desde la 0.12.0 el desvío no es obligatorio (2026-10-08): se avisa, y se sigue."""
        self.montar("0.20.0")
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        (aviso,) = [a for a in det.avisos if a.startswith("A tu Hermes")]
        self.assertIn("la 0.20.0, según su /health", aviso)
        self.assertIn("escribirle mientras trabaja (POST /v1/runs/{id}/steer)", aviso)
        self.assertNotIn("GET /api/model/options", aviso)
        self.assertIn("«/update» en su chat, o «hermes update» en el servidor, como root", aviso)

    def test_a_uno_de_julio_le_faltan_el_modelo_y_el_desvio_y_sigue(self):
        """El Hermes del probador del 2026-10-08 (la 0.19.0): hasta la 0.11.2, `hermes-antiguo`; ahora, un aviso."""
        self.montar("0.19.0")
        det = self.detectar()
        self.assertEqual(self.antiguo(det), [])
        (aviso,) = [a for a in det.avisos if a.startswith("A tu Hermes")]
        # Que se lea claro que se instala igual, y qué trae «/update» (Daniel, 2026-10-08).
        self.assertEqual(aviso, "A tu Hermes (la 0.19.0, según su /health) le falta elegir el modelo (GET "
                                "/api/model/options); escribirle mientras trabaja (POST /v1/runs/{id}/steer). Instalo "
                                "igual: la app funciona sin eso, y lo tendrás en cuanto lo actualices («/update» en su "
                                "chat, o «hermes update» en el servidor, como root)")
        self.assertTrue([a for a in det.avisos if a.startswith("Tu Hermes es la 0.19.0")])

    def test_uno_sin_sesiones_no_tiene_ni_la_bandeja(self):
        """Anterior a la 0.15.0: `GET /api/sessions` con su clave da 404. Antes era un «api-hermes» sin más."""
        self.montar("0.14.0")
        det = self.detectar()
        self.assertEqual([getattr(b, "codigo", None) for b in det.bloqueos], ["hermes-antiguo"])
        (bloqueo,) = self.antiguo(det)
        self.assertEqual(bloqueo.detalle, "version=0.14.0 minima=0.15.0 falta=bandeja,nueva,historial,ficha")
        self.assertIn("HeHermes necesita Hermes 0.15.0 o más nuevo", bloqueo)

    def test_hasta_la_recomendada_se_avisa_de_lo_que_no_se_ve(self):
        self.montar("0.20.1")
        det = self.detectar()
        self.assertEqual(self.antiguo(det), [])
        (aviso,) = [a for a in det.avisos if a.startswith("Tu Hermes es la 0.20.1")]
        self.assertIn("subagentes en segundo plano", aviso)
        self.assertIn("le puede llegar dos veces", aviso)
        self.montar("0.21.0")
        (aviso,) = [a for a in self.detectar().avisos if a.startswith("Tu Hermes es la 0.21.0")]
        self.assertIn("subagentes", aviso)
        self.assertNotIn("dos veces", aviso)

    def test_lo_que_la_app_puede_no_tener_se_avisa_y_sigue(self):
        falso = self.montar("0.21.3")
        falso.rutas_quitadas = {("DELETE", "/api/sessions/{session_id}"), ("GET", "/api/jobs"), ("POST", "/api/jobs")}
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        (aviso,) = [a for a in det.avisos if a.startswith("A tu Hermes")]
        self.assertIn("«Eliminar también de Hermes» (DELETE /api/sessions/{id})", aviso)
        self.assertIn("las tareas programadas (GET /api/jobs)", aviso)

    def test_uno_al_que_le_quitaron_una_obligatoria_se_para_aunque_su_version_la_traiga(self):
        falso = self.montar("0.21.3")
        falso.rutas_quitadas = {("PATCH", "/api/sessions/{session_id}")}
        (bloqueo,) = self.antiguo(self.detectar())
        self.assertIn("fijar, archivar y renombrar una conversación (PATCH /api/sessions/{id})", bloqueo)


class SinEfectos(Base):
    def test_solo_trace_sin_la_clave_y_solo_a_127_0_0_1(self):
        self.montar("0.21.3")
        antes = self.sis.foto()
        self.detectar()
        self.assertEqual(self.sis.foto(), antes)
        self.assertTrue(self.sis.peticiones_sonda)
        for metodo, url, cabeceras in self.sis.peticiones_sonda:
            self.assertEqual(metodo, "TRACE")
            self.assertTrue(url.startswith("http://127.0.0.1:8642/"), url)
            self.assertNotIn("Authorization", cabeceras)
            self.assertNotIn(sf.CLAVE, repr(cabeceras))
        rutas = [url[len("http://127.0.0.1:8642"):] for _, url, _ in self.sis.peticiones_sonda]
        self.assertEqual(len(rutas), len(set(rutas)), "una vez por ruta")
        self.assertEqual(rutas[0], "/health", "primero, la calibración")
        self.assertIn("/v1/runs/hehermes-sonda/steer", rutas)
        # Las de siempre siguen siendo dos GET: /health y la bandeja con la clave.
        self.assertEqual([u for u, _ in self.sis.peticiones_http],
                         ["http://127.0.0.1:8642/health", "http://127.0.0.1:8642/api/sessions?limit=1"])


class SinSonda(Base):
    """Un servidor que no contesta a TRACE como aiohttp (un 501): la sonda no vale, y queda la versión."""

    def test_con_una_version_buena_sigue(self):
        self.montar("0.21.3").trace_hermes = False
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertFalse(det.hermes.sondeo.calibrada)
        self.assertFalse([a for a in det.avisos if "No he podido comprobar" in a])

    def test_con_una_vieja_se_para(self):
        """Sin sonda, una anterior a la mínima: el 404 de su bandeja (con su clave) ya dice lo que falta."""
        self.montar("0.14.0").trace_hermes = False
        (bloqueo,) = self.antiguo(self.detectar())
        self.assertEqual(bloqueo.detalle, "version=0.14.0 minima=0.15.0 falta=bandeja")

    def test_con_una_de_respaldo_avisa_por_la_version_de_lo_que_falta(self):
        """Sin sonda, una 0.18.0 (desde la 0.12.0, de respaldo): sigue, y lo que le falta lo dice su versión."""
        self.montar("0.18.0").trace_hermes = False
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        (aviso,) = [a for a in det.avisos if a.startswith("A tu Hermes")]
        self.assertIn("GET /api/model/options", aviso)
        self.assertIn("POST /v1/runs/{id}/steer", aviso)

    def test_sin_version_avisa_y_sigue(self):
        self.montar(None).trace_hermes = False
        det = self.detectar()
        self.assertEqual(det.bloqueos, [])
        self.assertTrue([a for a in det.avisos if a.startswith("No he podido comprobar qué sabe hacer tu Hermes")])

    def test_un_servidor_que_contesta_trace_con_un_200_no_calibra(self):
        """Lo que dice `Allow` solo vale en un 405: un 200 a TRACE (un servidor que lo atiende) no dice qué rutas hay."""
        self.montar("0.14.0").trace_hermes = "eco"
        det = self.detectar()
        self.assertFalse(det.hermes.sondeo.calibrada)
        (bloqueo,) = self.antiguo(det)
        self.assertEqual(bloqueo.detalle, "version=0.14.0 minima=0.15.0 falta=bandeja")

    def test_sin_sonda_ni_version_un_404_a_la_bandeja_es_que_no_la_tiene(self):
        """El GET de la bandeja con su clave también es una sonda: su 404 es el de una ruta que no existe."""
        falso = self.montar(None)
        falso.trace_hermes = False
        falso.rutas_quitadas = {(metodo, ruta) for metodo, ruta, _ in sf.RUTAS_HERMES if ruta.startswith("/api/sessions")}
        (bloqueo,) = self.antiguo(self.detectar())
        self.assertEqual(bloqueo.detalle, "version=? minima=0.15.0 falta=bandeja")
        self.assertIn("Tu Hermes (no dice su versión)", bloqueo)

    def test_un_405_sin_get_en_health_no_calibra(self):
        falso = self.montar("0.18.0")
        falso.rutas_quitadas = {("GET", "/health")}
        sondeo = cap.sondear(self.sis, 8642, "0.18.0")
        self.assertFalse(sondeo.calibrada)
        self.assertEqual(sondeo.ausentes, set())


class ConLaApiApagada(Base):
    """Por chat, con `--activar-api` y la API apagada, no hay /health: vale la versión de su código. Uno demasiado viejo
    se para antes de encender nada."""

    def montar_apagado(self, version, **opciones):
        self.montar(habilitada=False)
        return self.falso.codigo_de_hermes(version, **opciones)

    def test_viejo_se_para_sin_tocar_su_env(self):
        carpeta = self.montar_apagado("0.14.2")
        antes = self.sis.foto()
        self.assertEqual(self.orden("instalar", "--por-chat", "--activar-api", "--iphone", "mi-iphone", "--llave", LLAVE),
                         1)
        self.assertEqual(self.sis.foto(), antes, "ni el .env de Hermes")
        self.assertIn("la 0.14.2, según su código, en %s" % carpeta, self.salida)
        self.assertEqual(self.texto[-1].splitlines()[-2:], ["hehermes-detalle:version=0.14.2 minima=0.15.0 "
                                                           "falta=bandeja,nueva,historial,ficha",
                                                           "hehermes-error:hermes-antiguo"])

    def test_la_version_sale_de_su_init_o_de_su_sello(self):
        for donde in ("init", "sello"):
            with self.subTest(donde=donde):
                self.montar_apagado("0.14.0", donde=donde)
                self.assertEqual(len(self.antiguo(self.detectar(activar_api=True))), 1)

    def test_una_buena_sigue_y_el_plan_lo_dice(self):
        carpeta = self.montar_apagado("0.21.3")
        det = self.detectar(activar_api=True)
        self.assertEqual(det.bloqueos, [])
        plan = calcular_plan_tls(self.sis, det, Manifiesto.leer(self.sis), Opciones(activar_api=True), ORIGEN)
        self.assertIn("versión 0.21.3 (la de su código, en %s)" % carpeta, pintar(plan))

    def test_sin_su_codigo_avisa_y_sigue(self):
        self.montar(habilitada=False)
        det = self.detectar(activar_api=True)
        self.assertEqual(det.bloqueos, [])
        self.assertTrue([a for a in det.avisos if a.startswith("No sé qué versión de Hermes es")])

    def test_su_codigo_se_encuentra_por_lo_que_ejecuta_su_proceso(self):
        self.montar(habilitada=False, como="proceso", orden="/opt/hermes/venv/bin/python -m hermes_cli.main gateway run")
        self.falso.codigo_de_hermes("0.14.1", carpeta="/opt/hermes")
        (bloqueo,) = self.antiguo(self.detectar(activar_api=True))
        self.assertIn("su código, en /opt/hermes", bloqueo)

    def test_en_un_contenedor_se_busca_dentro(self):
        self.montar(habilitada=False, como="docker", orden="/opt/hermes/.venv/bin/python /opt/hermes/.venv/bin/hermes "
                                                            "gateway run")
        pid = self.falso.pid_hermes
        self.falso.codigo_de_hermes("0.13.0", carpeta="/proc/%d/root/opt/hermes" % pid)
        (bloqueo,) = self.antiguo(self.detectar(activar_api=True))
        self.assertIn("la 0.13.0", bloqueo)
        self.assertIn("va en el contenedor de Docker", bloqueo, "en un contenedor no vale hermes update")


class LoQueSeVe(Base):
    def test_el_plan_dice_la_version(self):
        self.montar("0.21.3")
        det = self.detectar()
        plan = calcular_plan_tls(self.sis, det, Manifiesto.leer(self.sis), Opciones(), ORIGEN)
        self.assertRegex(pintar(plan), r"  Hermes     /root/\.hermes/\.env .*, la clave vale, versión 0\.21\.3\n")

    def test_por_ssh_no_hay_lineas_para_la_app(self):
        self.montar("0.14.0")
        self.assertEqual(self.orden("instalar", "--si"), 1)
        self.assertIn("No puedo seguir:", self.salida)
        self.assertNotIn("hehermes-error:", self.salida)
        self.assertNotIn("hehermes-detalle:", self.salida)

    def test_comprobar_dice_la_version_y_lo_que_falta(self):
        self.montar("0.21.3")
        self.assertEqual(self.orden("instalar", "--si"), 0, self.salida)
        man = Manifiesto.leer(self.sis)
        textos = [t for _, t in comprobar_tls(self.sis, man, amb.de_root())]
        self.assertIn("Hermes: versión 0.21.3, con todo lo que usa la app", textos)
        # Hermes vuelve a una versión de antes (o a un fork sin el desvío): comprobar lo dice, con un aviso desde la
        # 0.12.0 (el desvío ya no es obligatorio); sin lo obligatorio (un fork sin `PATCH`), con un MAL.
        self.falso.version_hermes = "0.20.0"
        resultados = comprobar_tls(self.sis, man, amb.de_root())
        self.assertEqual([t for bien, t in resultados if not bien], [])
        textos = [t for _, t in resultados]
        self.assertTrue([t for t in textos if t.startswith("Hermes (aviso): A tu Hermes") and "steer" in t], textos)
        self.assertIn("Hermes: versión 0.20.0, con lo que la app necesita (lo que le falta, en el aviso)", textos)
        self.falso.version_hermes = "0.21.3"
        self.falso.rutas_quitadas = {("PATCH", "/api/sessions/{session_id}")}
        malos = [t for bien, t in comprobar_tls(self.sis, man, amb.de_root()) if not bien]
        self.assertEqual(len(malos), 1, malos)
        self.assertIn("PATCH /api/sessions/{id}", malos[0])
        self.assertEqual(self.orden("comprobar"), 1)
        self.falso.rutas_quitadas = set()
        self.falso.version_hermes = "0.21.0"
        textos = [t for _, t in comprobar_tls(self.sis, man, amb.de_root())]
        self.assertTrue([t for t in textos if t.startswith("Hermes (aviso): Tu Hermes es la 0.21.0")], textos)


class ConAiohttp(unittest.TestCase):
    """La sonda de verdad (`Sistema.pedir`, con urllib) contra aiohttp de verdad, con las rutas de un Hermes de cada edad
    y sus middlewares (los de `gateway/platforms/api_server.py`: CORS, que contesta él a OPTIONS; el tope del cuerpo y
    las cabeceras de seguridad): el 405 con `Allow` y el 404 son los de aiohttp, y ningún manejador llega a correr."""

    def setUp(self):
        try:
            from aiohttp import web  # noqa: F401
        except ImportError:
            self.skipTest("sin aiohttp")

    def servir(self, version):
        import asyncio
        import socket
        from aiohttp import web

        llamadas = []

        # aiohttp llama a cada middleware con `handler=`: los nombres de los parámetros son los suyos.
        @web.middleware
        async def cors(request, handler):
            if request.method == "OPTIONS":
                return web.Response(status=403)
            return await handler(request)

        @web.middleware
        async def tope(request, handler):
            try:
                return await handler(request)
            except web.HTTPRequestEntityTooLarge:
                return web.json_response({}, status=413)

        @web.middleware
        async def seguridad(request, handler):
            respuesta = await handler(request)
            respuesta.headers.setdefault("X-Frame-Options", "DENY")
            return respuesta

        async def manejador(peticion):
            llamadas.append((peticion.method, peticion.path))
            return web.json_response({"version": version}) if peticion.path == "/health" else \
                web.json_response({"error": {"code": "no_deberia"}}, status=500)

        app = web.Application(middlewares=[cors, tope, seguridad])
        for metodo, ruta in sf.rutas_de_hermes(version):
            app.router.add_route(metodo, ruta, manejador)
            app.router.add_route(metodo, "/p/{profile}" + ruta, manejador)
        app.router.add_route("*", "/p/{profile}/{tail:.*}", manejador)
        bucle = asyncio.new_event_loop()
        corredor = web.AppRunner(app)
        bucle.run_until_complete(corredor.setup())
        enchufe = socket.socket()
        try:
            enchufe.bind(("127.0.0.1", 0))
        except PermissionError:
            self.skipTest("sin poder escuchar en 127.0.0.1 (el sandbox)")
        puerto = enchufe.getsockname()[1]
        enchufe.close()
        bucle.run_until_complete(web.TCPSite(corredor, "127.0.0.1", puerto).start())
        hilo = threading.Thread(target=bucle.run_forever, daemon=True)
        hilo.start()

        def parar():
            bucle.call_soon_threadsafe(bucle.stop)
            hilo.join(5)
            bucle.run_until_complete(corredor.cleanup())
            bucle.close()

        self.addCleanup(parar)
        return puerto, llamadas

    def test_cada_edad_con_aiohttp_de_verdad(self):
        from hehermes_servidor.sistema import Sistema
        sis = Sistema()
        for version, faltan in (("0.21.3", set()), ("0.20.0", {"desviar"}), ("0.19.0", {"modelo", "desviar"}),
                                ("0.14.0", {"bandeja", "nueva", "historial", "ficha", "consumo", "borrar", "modelo",
                                            "desviar"})):
            with self.subTest(version=version):
                puerto, llamadas = self.servir(version)
                sondeo = cap.sondear(sis, puerto, version)
                self.assertTrue(sondeo.calibrada)
                self.assertEqual(sondeo.sin_saber, set())
                self.assertEqual(sondeo.ausentes, faltan)
                self.assertEqual(llamadas, [], "TRACE no llega a ningún manejador")


if __name__ == "__main__":
    unittest.main()
