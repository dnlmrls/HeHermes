"""`hehermes-servidor informe`: lo que lleva, que no lleva ningún secreto y que sin root no pide nada."""

from __future__ import annotations

import json
import unittest

import apoyo
from hehermes_servidor import VERSION, cli
from hehermes_servidor import ambito as amb
from hehermes_servidor.informe import construir, tapar
from hehermes_servidor.sistema import Resultado

TOKEN = "Zx9q-3mT_kP2vLr8wQ5nB7cY1dF4gH6jK0sA2eU9iO"
CLAVE_HERMES = "8f14e45fceea167a5a36dedd4bea2543c4ab9e1c2d3f4a5b6c7d8e9f0a1b2c3d"


def _instalado(sis, root=True, usuario="hermesito", casa="/home/hermesito"):
    ambito = amb.de_root() if root else amb.de_usuario(usuario, casa, 1000)
    sis.poner(ambito.manifiesto, json.dumps({
        "v": 1, "modos": ["tls"], "pasarela": {"puerto": 61234, "root": root},
        "unidad_hermes": "hermes-gateway.service", "usuario": usuario, "casa": casa,
        "por_chat": {"iphone": "iphone-1a2b", "alta": 1790000000, "canjeado": 1790000300}}))
    sis.poner(ambito.prefijo + "/hehermes_servidor/__init__.py", 'VERSION = "0.11.0"\n')
    sis.poner("/etc/os-release", 'NAME="Debian"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    sis.poner("/run/systemd/system/.marca", "")
    sis.responder["uname -m"] = apoyo.bien("x86_64\n")
    sis.responder["systemctl is-active"] = lambda args, entrada: Resultado(
        3, "\n".join("active" if "pasarela" in u or "hermes-gateway" in u else "inactive" for u in args[3:]), "")
    sis.responder["ss -Htln"] = apoyo.bien(
        "LISTEN 0 4096 0.0.0.0:61234 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8642 0.0.0.0:*\n"
        "LISTEN 0 128 203.0.113.9:22 0.0.0.0:*\n")
    # Lo que no puede salir: la IP de un iPhone, un token y la clave de Hermes, en los registros.
    sis.responder["journalctl"] = apoyo.bien(
        "2026-10-06T08:15:02+0000 vps hehermes-pasarela[812]: 198.51.100.23 GET /api/sessions 401 0\n"
        "2026-10-06T08:15:03+0000 vps hehermes-pasarela[812]: token=%s rechazado\n"
        "2026-10-06T08:15:04+0000 vps hehermes-vigia[90]: API_SERVER_KEY=%s\n"
        "2026-10-06T08:15:05+0000 vps hehermes-vigia[90]: 2001:db8:85a3::8a2e:370:7334 conecta\n"
        "2026-10-06T08:15:06+0000 vps hehermes-canje[77]: enlace hehermes-canje:1?h=x&p=61234&c=%s\n"
        "2026-10-06T08:15:07+0000 vps hehermes-pasarela[812]: leído /home/hermesito/.hermes/.env\n"
        % (TOKEN, CLAVE_HERMES, TOKEN))
    sis.respuestas_http["http://127.0.0.1:8642/health"] = (200, b'{"status": "ok", "version": "0.21.0"}')
    return ambito


class LoQueLleva(unittest.TestCase):
    def setUp(self):
        self.sis = apoyo.SistemaFalso()
        self.addCleanup(self.sis.limpiar)

    def test_con_root_lleva_las_versiones_los_servicios_y_los_puertos(self):
        ambito = _instalado(self.sis)
        self.sis.poner("/var/lib/hehermes-actualizar/estado.json",
                       json.dumps({"estado": "fallo", "motivo": "instalacion", "version": "0.11.1",
                                   "hora": 1790001000}))
        self.sis.poner("/var/lib/hehermes-actualizar/registro.txt", "error: hehermes-error:nat\n")
        texto = "\n".join(construir(self.sis, ambito, True, ahora=1790002000))
        for esperado in ("instalador que se ejecuta: %s" % VERSION, "instalador instalado: 0.11.0",
                         "Hermes: 0.21.0", "Debian GNU/Linux 12 (bookworm), x86_64", "systemd: sí",
                         "pasarela: puerto 61234", "Hermes lo lleva: hermes-gateway.service",
                         "hehermes-pasarela.service: active", "hehermes-vigia.service: inactive",
                         "hermes-gateway.service: active (Hermes)", "61234 (pasarela): 0.0.0.0",
                         "8642 (API de Hermes): 127.0.0.1", "8790 (vigía): no escucha",
                         "fallo (instalacion) a la 0.11.1", "hehermes-error:nat", "canjeada el"):
            self.assertIn(esperado, texto)
        self.assertNotIn("Sin root", texto)
        # Ni Hermes ni nada suyo: los registros son los de HeHermes.
        journal = next(o for o in self.sis.ordenes if o[0] == "journalctl")
        self.assertNotIn("hermes-gateway.service", journal)

    def test_no_lleva_ningun_secreto(self):
        ambito = _instalado(self.sis)
        texto = "\n".join(construir(self.sis, ambito, True, ahora=1790002000))
        for secreto in (TOKEN, CLAVE_HERMES, "198.51.100.23", "2001:db8:85a3", "203.0.113.9", "hermesito"):
            self.assertNotIn(secreto, texto)
        self.assertIn("<oculto>", texto)
        self.assertIn("<ip>", texto)
        self.assertIn("~/.hermes/.env", texto)
        # La hora de los registros no es una dirección.
        self.assertIn("08:15:02", texto)

    def test_sin_root_dice_lo_que_puede_leer_y_no_pide_sudo(self):
        _instalado(self.sis)
        salida = []
        codigo = cli.main(["informe"], "uso", "/x", sis=self.sis, salida=salida.append, euid=1000,
                          cuenta=("otro", "/home/otro", 1000))
        self.assertEqual(codigo, 0)
        texto = "\n".join(salida)
        self.assertIn("Sin root", texto)
        self.assertIn("(su estado es de root)", texto)
        self.assertFalse([o for o in self.sis.ordenes if o and o[0] == "sudo"])
        # Lo de root, en el diario del sistema: si este usuario no puede leerlo, journalctl lo dice.
        self.assertIn(["journalctl", "--no-pager"], [o[:2] for o in self.sis.ordenes])

    def test_sin_root_con_su_instalacion_usa_la_suya(self):
        ambito = _instalado(self.sis, root=False)
        salida = []
        cli.main(["informe"], "uso", "/x", sis=self.sis, salida=salida.append, euid=1000,
                 cuenta=(ambito.usuario, ambito.casa, 1000))
        texto = "\n".join(salida)
        self.assertIn("sin root, en la casa del usuario de Hermes", texto)
        self.assertIn("linger: no", texto)
        self.assertIn(["systemctl", "--user", "is-active"], [o[:3] for o in self.sis.ordenes])
        self.assertNotIn("hermesito", texto)

    def test_sin_nada_instalado_no_falla(self):
        texto = "\n".join(construir(self.sis, amb.de_root(), True, ahora=1790002000))
        self.assertIn("no hay manifiesto", texto)
        self.assertIn("alta por chat: ninguna", texto)


class Tapar(unittest.TestCase):
    def test_las_ip_que_no_son_de_esta_maquina(self):
        self.assertEqual(tapar("de 198.51.100.7 a 127.0.0.1 y 0.0.0.0"), "de <ip> a 127.0.0.1 y 0.0.0.0")
        self.assertEqual(tapar("fe80::1ff:fe23:4567:890a y ::1"), "<ip> y ::1")

    def test_lo_que_va_detras_de_una_clave(self):
        self.assertEqual(tapar("token=abc clave: xyz Bearer qwe"), "token=<oculto> clave: <oculto> Bearer <oculto>")
        self.assertEqual(tapar("--llave %s" % TOKEN), "--llave <oculto>")

    def test_las_cadenas_largas(self):
        self.assertEqual(tapar("va %s y sigue" % TOKEN), "va <oculto> y sigue")
        # Una palabra larga sin números, o un nombre de unidad, se quedan.
        self.assertEqual(tapar("hehermes-actualizar@3-81-0.service"), "hehermes-actualizar@3-81-0.service")

    def test_los_enlaces(self):
        self.assertEqual(tapar("hehermes-tls:1?h=x&t=y"), "hehermes-tls:1?<oculto>")

    def test_el_usuario_y_su_casa(self):
        self.assertEqual(tapar("/home/svc/.hermes de svc, no de svcx", usuario="svc", casa="/home/svc"),
                         "~/.hermes de <usuario>, no de svcx")


if __name__ == "__main__":
    unittest.main()
