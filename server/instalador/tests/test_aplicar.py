"""Aplicar el plan, paso a paso, sobre el servidor falso: instalar, repetir (0 cambios), reparar y deshacer lo que
falla."""

import apoyo

import json
import unittest

import servidor_falso as sf
from hehermes_servidor import manifiesto as m
from hehermes_servidor import piezas as p
from hehermes_servidor.aplicar import Parada, aplicar, comprobar
from hehermes_servidor.deteccion import detectar
from hehermes_servidor.manifiesto import Manifiesto
from hehermes_servidor.plan import Opciones, calcular_plan

ORIGEN = str(apoyo.RAIZ)


class Base(unittest.TestCase):
    def montar(self, sis_falso):
        self.sis, self.falso = sis_falso
        self.addCleanup(self.sis.limpiar)
        self.salida = []

    def plan(self, **opciones):
        opciones.setdefault("iphone", "mi-iphone")
        op = Opciones(**opciones)
        self.man = Manifiesto.leer(self.sis)
        det = detectar(self.sis, self.man, direccion=op.direccion, hermes_home=op.hermes_home)
        return calcular_plan(self.sis, det, self.man, op, ORIGEN)

    def instalar(self, **opciones):
        plan = self.plan(**opciones)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        aplicar(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        return plan

    def ordenes_que_cambian(self, desde=0):
        leen = ("is-active", "is-enabled", "show")
        return [o for o in self.sis.ordenes[desde:]
                if not (o[0] == "systemctl" and o[1] in leen) and o[:1] not in (["dpkg"], ["dpkg-query"], ["ps"],
                                                                                  ["ss"], ["ip"])
                and o[:2] not in (["nginx", "-t"], ["swanctl", "--stats"], ["ufw", "status"], ["ufw", "show"])]


class Instalar(Base):
    def test_una_instalacion_limpia(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("ufw")
        falso.ufw = "inactivo"
        self.montar((sis, falso))
        self.instalar()
        man = Manifiesto.leer(sis)
        # Los ficheros, con su contenido y en el manifiesto con su hash.
        self.assertEqual(sis.leer(p.UNIDAD_XFRM), p.unidad_xfrm().encode())
        self.assertEqual(sis.modo(p.SCRIPT_XFRM), 0o755)
        self.assertEqual(sis.modo(p.DISPOSITIVO), 0o750)
        self.assertEqual(sis.modo(p.BEARER), 0o600)
        self.assertEqual(sis.enlace(p.SITIO_ENLACE), p.SITIO)
        self.assertEqual(sis.enlace(p.ORDEN), p.PREFIJO + "/hehermes-servidor")
        self.assertIn(b"deny 10.77.0.1;", sis.leer(p.SITIO))
        for ruta in (p.UNIDAD_XFRM, p.SCRIPT_XFRM, p.SITIO, p.SITIO_ENLACE, p.DROP_IN_NGINX, p.SERVIDOR_INI,
                     p.DISPOSITIVO, p.UNIDAD_CLAVE_PATH, p.UNIDAD_CLAVE_SERVICE, p.ORDEN,
                     p.PREFIJO + "/hehermes_servidor/plan.py"):
            with self.subTest(ruta=ruta):
                self.assertTrue(m.sin_tocar(sis, man, ruta))
        self.assertEqual(man.ficheros[p.BEARER]["tipo"], "gestionado")
        self.assertEqual(sorted(man.paquetes), sorted(["charon-systemd", "strongswan-swanctl", "nginx", "qrencode",
                                                        "libstrongswan-standard-plugins"]))
        self.assertEqual(man.unidades, ["hehermes-xfrm.service", "hehermes-clave.path"])
        self.assertEqual(len(man.reglas), 2)
        self.assertEqual(man.dispositivos, ["mi-iphone"])
        # El sitio default de nginx, fuera, y apuntado para volver a ponerlo.
        self.assertFalse(sis.existe(p.DEFAULT_NGINX))
        self.assertEqual(man.quitados[p.DEFAULT_NGINX], {"tipo": "enlace", "destino": "/etc/nginx/sites-available/default"})
        # Las órdenes: ufw sigue apagado, nada se reinicia, nginx se recarga.
        self.assertEqual(falso.ufw, "inactivo")
        self.assertEqual(falso.reinicios, [])
        self.assertIn(["systemctl", "reload", "nginx"], sis.ordenes)
        self.assertIn(["systemctl", "enable", "--now", "hehermes-xfrm.service"], sis.ordenes)
        self.assertIn(["systemctl", "enable", "--now", "hehermes-clave.path"], sis.ordenes)
        self.assertIn("hh-ipsec", falso.enlaces_ip)
        alta = [o for o in sis.ordenes if o[:2] == [p.DISPOSITIVO, "alta"]]
        self.assertEqual(alta, [[p.DISPOSITIVO, "alta", "mi-iphone", "--ikev2", "--servidor", sf.IP_PUBLICA]])
        self.assertIn([p.DISPOSITIVO, "qr", "mi-iphone"], sis.ordenes)
        # El orden de la spec: la interfaz antes que nginx, y el alta al final.
        indice = lambda orden: sis.ordenes.index(orden)  # noqa: E731
        self.assertLess(indice(["systemctl", "enable", "--now", "hehermes-xfrm.service"]),
                        indice(["systemctl", "reload", "nginx"]))
        self.assertLess(indice(["systemctl", "reload", "nginx"]), indice(alta[0]))
        self.assertNotIn(sf.CLAVE, "\n".join(self.salida))

    def test_repetir_da_cero_cambios_y_no_ejecuta_nada_que_cambie(self):
        self.montar(sf.servidor())
        self.instalar()
        desde = len(self.sis.ordenes)
        foto = self.sis.foto()
        plan = self.plan()
        self.assertEqual(plan.cambios, [])
        aplicar(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        self.assertEqual(self.ordenes_que_cambian(desde), [])
        self.assertEqual(self.sis.foto(), foto)

    def test_repetir_repara_lo_que_falta(self):
        self.montar(sf.servidor())
        self.instalar()
        self.sis.borrar(p.SITIO)
        self.sis.borrar(p.UNIDAD_CLAVE_PATH)
        self.falso.activos.discard("hehermes-xfrm")
        plan = self.plan()
        self.assertEqual(sorted(a.objeto for a in plan.cambios),
                         sorted([p.SITIO, p.UNIDAD_CLAVE_PATH, "recargar nginx", "hehermes-xfrm.service",
                                 "hehermes-clave.path"]))
        aplicar(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        self.assertEqual(self.sis.leer(p.SITIO), p.sitio_nginx(8642).encode())
        self.assertIn("hh-ipsec", self.falso.enlaces_ip)
        self.assertEqual(self.plan().cambios, [])

    def test_lo_instalado_en_opt_basta_para_repetir_y_reparar(self):
        # `sudo hehermes-servidor instalar` después, sin la carpeta temporal: su origen es /opt/hehermes-servidor.
        self.montar(sf.servidor())
        self.instalar()
        origen = self.sis.ruta(p.PREFIJO)
        man = Manifiesto.leer(self.sis)
        plan = calcular_plan(self.sis, detectar(self.sis, man), man, Opciones(iphone="mi-iphone"), origen)
        self.assertTrue(plan.puede_seguir, plan.bloqueos)
        self.assertEqual(plan.cambios, [])
        self.sis.borrar(p.DISPOSITIVO)
        plan = calcular_plan(self.sis, detectar(self.sis, man), man, Opciones(), origen)
        self.assertEqual([a.objeto for a in plan.cambios], [p.DISPOSITIVO])

    def test_una_version_nueva_de_la_unidad_se_recarga_sin_cortar(self):
        self.montar(sf.servidor())
        self.instalar()
        # Como si la versión de antes hubiera dejado otra unidad (sin tocar a mano: el manifiesto lo sabe).
        vieja = p.unidad_xfrm() + "# versión anterior\n"
        self.sis.poner(p.UNIDAD_XFRM, vieja)
        man = Manifiesto.leer(self.sis)
        man.apuntar_fichero(p.UNIDAD_XFRM, vieja.encode())
        man.guardar(self.sis)
        desde = len(self.sis.ordenes)
        plan = self.plan()
        self.assertEqual([(a.objeto, a.estado) for a in plan.cambios],
                         [(p.UNIDAD_XFRM, m.CAMBIA), ("hehermes-xfrm.service", m.CAMBIA)])
        aplicar(self.sis, plan, self.man, ORIGEN, salida=self.salida.append)
        self.assertIn(["systemctl", "reload", "hehermes-xfrm.service"], self.sis.ordenes[desde:])
        self.assertNotIn("stop", [o[1] for o in self.sis.ordenes[desde:] if o[0] == "systemctl"])

    def test_nginx_de_otro_se_recarga_y_conserva_su_default(self):
        sis, falso = sf.servidor()
        falso.instalar_paquete("nginx")
        self.montar((sis, falso))
        self.instalar()
        self.assertTrue(sis.existe(p.DEFAULT_NGINX))
        self.assertNotIn("nginx", Manifiesto.leer(sis).paquetes)
        self.assertIn(["systemctl", "reload", "nginx"], sis.ordenes)
        self.assertNotIn("nginx", falso.reinicios)

    def test_reemplazar_guarda_una_copia(self):
        sis, falso = sf.servidor()
        sis.poner(p.DROP_IN_NGINX, "[Unit]\nAfter=otra.service\n")
        self.montar((sis, falso))
        self.instalar(reemplazar={p.DROP_IN_NGINX})
        man = Manifiesto.leer(sis)
        copia = man.ficheros[p.DROP_IN_NGINX]["copia"]
        self.assertEqual(sis.leer(copia["ruta"]), b"[Unit]\nAfter=otra.service\n")
        self.assertEqual(sis.leer(p.DROP_IN_NGINX), p.drop_in_nginx().encode())

    def test_con_avisos(self):
        self.montar(sf.servidor())
        self.instalar(avisos=True)
        instalador = [o for o in self.sis.ordenes if o[0] == "bash"]
        self.assertEqual(len(instalador), 1)
        self.assertTrue(instalador[0][1].endswith("avisos/despliegue/instalar.sh"))
        self.assertTrue(Manifiesto.leer(self.sis).datos["avisos"])
        self.assertEqual([a for a in self.plan(avisos=True).cambios], [])


class Deshacer(Base):
    def test_si_nginx_no_da_por_bueno_el_sitio_todo_vuelve(self):
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        falso.nginx_t = lambda: not sis.existe(p.SITIO)
        with self.assertRaises(Parada) as parada:
            self.instalar()
        self.assertIn("nginx -t", str(parada.exception))
        for ruta in (p.SITIO, p.SITIO_ENLACE, p.DROP_IN_NGINX, p.BEARER):
            with self.subTest(ruta=ruta):
                self.assertFalse(sis.existe(ruta))
        self.assertTrue(sis.existe(p.DEFAULT_NGINX), "el default vuelve")
        man = Manifiesto.leer(sis)
        self.assertNotIn(p.SITIO, man.ficheros)
        self.assertNotIn(p.DEFAULT_NGINX, man.quitados)
        # Lo de antes de nginx se queda hecho y apuntado: repetir sigue desde ahí.
        self.assertTrue(m.sin_tocar(sis, man, p.UNIDAD_XFRM))
        self.assertNotIn(["systemctl", "reload", "nginx"], sis.ordenes)
        self.assertEqual([o for o in sis.ordenes if o[:2] == [p.DISPOSITIVO, "alta"]], [])

    def test_si_falla_apt_no_sigue(self):
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        sis.responder["env DEBIAN_FRONTEND=noninteractive apt-get install"] = apoyo.mal("E: sin red")
        with self.assertRaises(Parada) as parada:
            self.instalar()
        self.assertIn("sin red", str(parada.exception))
        self.assertFalse(sis.existe(p.UNIDAD_XFRM))

    def test_si_falla_el_alta_lo_dice(self):
        sis, falso = sf.servidor()
        self.montar((sis, falso))
        sis.responder[p.DISPOSITIVO + " alta"] = apoyo.mal("error: strongSwan no está listo")
        with self.assertRaises(Parada) as parada:
            self.instalar()
        self.assertIn("strongSwan no está listo", str(parada.exception))


class Comprobar(Base):
    def test_todo_bien_tras_instalar(self):
        self.montar(sf.servidor())
        self.instalar()
        resultados = comprobar(self.sis, Manifiesto.leer(self.sis))
        self.assertTrue(all(bien for bien, _ in resultados), resultados)
        self.assertTrue(any("403" in texto for _, texto in resultados), "el túnel, cerrado al propio servidor")

    def test_el_agujero_abierto_es_un_fallo(self):
        self.montar(sf.servidor())
        self.instalar()
        self.sis.respuestas_http["http://10.77.0.1/health"] = (200, b"{}")
        resultados = comprobar(self.sis, Manifiesto.leer(self.sis))
        self.assertTrue(any(not bien and "agujero" in texto for bien, texto in resultados), resultados)

    def test_sin_hh_ipsec_es_un_fallo(self):
        self.montar(sf.servidor())
        self.instalar()
        self.falso.enlaces_ip.pop("hh-ipsec")
        self.assertTrue(any(not bien and "hh-ipsec" in t for bien, t in comprobar(self.sis, Manifiesto.leer(self.sis))))


if __name__ == "__main__":
    unittest.main()
