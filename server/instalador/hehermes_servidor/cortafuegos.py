"""Los cortafuegos que no son ni ufw ni firewalld: nftables con sus propias tablas e iptables a pelo.

ufw y firewalld tienen su forma de añadir una regla y de quitarla, y el instalador la usa (`piezas`, `aplicar`). Un
nftables o un iptables escritos a mano no: la única manera de dejar pasar algo es poner una regla **dentro de su
cadena**, porque en netfilter un `accept` en otra cadena no salva a un paquete del `drop` de esta. Así que, cadena por
cadena de las que miran lo que entra (`hook input`):

- si deja pasar todo, no se toca;
- si cierra con `policy drop`, las reglas de HeHermes van al final, detrás de las del usuario (sus `drop` concretos, sus
  listas negras, siguen mandando); si cierra con un `drop` o un `reject` sin condiciones, justo antes de él;
- si acaba en un salto sin condiciones (`jump`, `goto`, `-j <cadena>`), no se sabe qué pasa después: no se toca nada,
  y se dice qué hay que abrir.

Cada regla lleva un comentario, `hehermes` (las de siempre) o `hehermes-canje` (la del canje, mientras dura), y se
quitan buscándolo: ni una regla del usuario se reescribe ni se borra. No se escribe en `/etc/nftables.conf` ni en
`/etc/iptables/rules.v4`: tras un reinicio las vuelve a poner `hehermes-cortafuegos.service`, que corre después de que
el sistema cargue las suyas (`piezas.unidad_cortafuegos`).

Solo IPv4: el QR lleva la dirección IPv4 de salida, y el túnel es 10.77.0.1.
"""

from __future__ import annotations

import json
import re
import shlex

from . import piezas as p

MARCA = "hehermes"
MARCA_CANJE = "hehermes-canje"
#: Los gestores que reescriben el cortafuegos a su manera: meterles una regla por debajo sería pelearse con ellos.
GESTORES_AJENOS = ("shorewall", "csf", "lfd", "ferm")
_NOMBRE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PROPIAS = (MARCA, MARCA_CANJE)


class Regla:
    __slots__ = ("nombre", "proto", "puertos", "entra", "destino")

    def __init__(self, nombre, proto, puertos, entra=None, destino=None):
        self.nombre, self.proto, self.puertos, self.entra, self.destino = nombre, proto, puertos, entra, destino

    def nft(self, marca) -> str:
        partes = []
        if self.entra:
            partes.append('iifname "%s"' % self.entra)
        if self.destino:
            partes.append("ip daddr %s" % self.destino)
        puertos = self.puertos.split(",")
        partes.append("%s dport %s" % (self.proto, puertos[0] if len(puertos) == 1 else "{ %s }" % ", ".join(puertos)))
        partes.append('accept comment "%s"' % marca)
        return " ".join(partes)

    def iptables(self, marca) -> list:
        args = []
        if self.entra:
            args += ["-i", self.entra]
        if self.destino:
            args += ["-d", self.destino + "/32"]
        args += ["-p", self.proto]
        if "," in self.puertos:
            args += ["-m", "multiport", "--dports", self.puertos]
        else:
            args += ["-m", self.proto, "--dport", self.puertos]
        return args + ["-m", "comment", "--comment", marca, "-j", "ACCEPT"]


def permanentes(modo: str = "vpn", puerto: int | None = None) -> list:
    """Lo mismo que las de ufw: solo el UDP de IKE queda abierto a internet; el TCP 80, solo por hh-ipsec. En modo
    TLS, solo el TCP de la pasarela."""
    if modo == "tls":
        return [Regla("TCP %d (la pasarela)" % int(puerto), "tcp", str(int(puerto)))]
    return [Regla("UDP 500 y 4500 (IKEv2)", "udp", "500,4500"),
            Regla("TCP 80 solo por %s hacia %s" % (p.INTERFAZ, p.IP_TUNEL), "tcp", "80", p.INTERFAZ, p.IP_TUNEL)]


def permanentes_de(datos: dict, modos=None, puerto=None) -> list:
    """Las de una instalación, por los modos de su manifiesto: las de la VPN, las de la pasarela o las de los dos (van
    todas con la misma marca, y `poner` las pone de una vez). `modos` y `puerto`, los que tendrá al acabar de
    instalar, si no son aún los del manifiesto."""
    from .manifiesto import modos_de
    modos = modos_de(datos) if modos is None else modos
    puerto = puerto or (datos.get("pasarela") or {}).get("puerto")
    return ((permanentes() if "vpn" in modos else [])
            + (permanentes("tls", puerto) if "tls" in modos and puerto else []))


def del_canje(puerto: int) -> list:
    return [Regla("TCP %d (el canje)" % puerto, "tcp", str(int(puerto)))]


class Lugar:
    """Una cadena que cierra el paso, y dónde van las reglas de HeHermes en ella."""

    __slots__ = ("herramienta", "familia", "tabla", "cadena", "antes", "marcadas")

    def __init__(self, herramienta, familia, tabla, cadena, antes=None, marcadas=0):
        self.herramienta, self.familia, self.tabla, self.cadena = herramienta, familia, tabla, cadena
        #: nftables: el handle de la regla delante de la que van; iptables: su posición. None: al final.
        self.antes = antes
        #: Cuántas reglas `hehermes` tiene ya.
        self.marcadas = marcadas

    @property
    def nombre(self) -> str:
        if self.herramienta == "iptables":
            return "iptables %s" % self.cadena
        return "nftables %s %s %s" % (self.familia, self.tabla, self.cadena)

    @property
    def donde(self) -> str:
        return "al final, antes de su policy drop" if self.antes is None else "justo antes de su drop final"

    def __repr__(self):
        return "Lugar(%s, antes=%r, marcadas=%d)" % (self.nombre, self.antes, self.marcadas)


class NoSe(Exception):
    """El cortafuegos cierra, pero no se sabe dónde poner las reglas sin riesgo. Lleva el porqué."""


# MARK: nftables


def _ruleset(sis) -> list:
    r = sis.ejecutar(["nft", "-j", "list", "ruleset"])
    if not r.bien:
        return []
    try:
        return json.loads(r.salida or "{}").get("nftables", [])
    except ValueError:
        return []


def _de_iptables(familia, tabla, iptables_nft) -> bool:
    """Las tablas que son de iptables-nft (o de ufw, que va por iptables), y la de firewalld: esas no son de nft a
    pelo, y se tocan con su herramienta o no se tocan."""
    if (familia, tabla) == ("inet", "firewalld"):
        return True
    return iptables_nft and familia in ("ip", "ip6") and tabla in ("filter", "raw", "mangle", "nat", "security")


def clasificar_nft(expr) -> tuple:
    """(veredicto, sin condiciones). Veredicto: drop, reject, accept, salto (jump o goto) o None."""
    veredicto, condiciones = None, False
    for item in expr or []:
        clave = next(iter(item), None) if isinstance(item, dict) else None
        if clave in ("drop", "reject", "accept"):
            veredicto = clave
        elif clave in ("jump", "goto"):
            veredicto = "salto"
        elif clave in ("counter", "log"):
            continue
        else:
            condiciones = True
    return veredicto, not condiciones


def analizar_nft(ruleset, iptables_nft=False) -> tuple:
    """(lugares que cierran, dudas) de un `nft -j list ruleset`."""
    cadenas, reglas = [], {}
    for objeto in ruleset:
        if "chain" in objeto:
            cadenas.append(objeto["chain"])
        elif "rule" in objeto:
            r = objeto["rule"]
            reglas.setdefault((r.get("family"), r.get("table"), r.get("chain")), []).append(r)
    lugares, dudas = [], []
    for c in cadenas:
        familia, tabla, nombre = c.get("family"), c.get("table"), c.get("name")
        if c.get("hook") != "input" or c.get("type", "filter") != "filter" or familia not in ("ip", "inet"):
            continue
        if _de_iptables(familia, tabla, iptables_nft):
            continue
        todas = reglas.get((familia, tabla, nombre), [])
        suyas = [r for r in todas if r.get("comment") not in _PROPIAS]
        marcadas = sum(1 for r in todas if r.get("comment") == MARCA)
        if not all(_NOMBRE.match(str(x or "")) for x in (familia, tabla, nombre)):
            dudas.append("la cadena %s %s %s tiene un nombre que no sé escribir" % (familia, tabla, nombre))
            continue
        ultima = suyas[-1] if suyas else None
        veredicto, incondicional = clasificar_nft(ultima.get("expr")) if ultima else (None, False)
        lugar = Lugar("nftables", familia, tabla, nombre, marcadas=marcadas)
        if ultima and incondicional and veredicto in ("drop", "reject"):
            lugar.antes = ultima.get("handle")
            lugares.append(lugar)
        elif ultima and incondicional and veredicto == "salto":
            dudas.append("la cadena %s acaba saltando a otra sin condiciones, y no sé qué hace esa" % lugar.nombre)
        elif c.get("policy") == "drop" and not (ultima and incondicional and veredicto == "accept"):
            lugares.append(lugar)
    return lugares, dudas


# MARK: iptables


_OBJETIVOS_FINALES = ("ACCEPT", "DROP", "REJECT", "RETURN", "LOG", "QUEUE", "NFQUEUE")


def _sin_comentario(tokens) -> list:
    salida, i = [], 0
    while i < len(tokens):
        if tokens[i:i + 2] == ["-m", "comment"]:
            i += 2
            continue
        if tokens[i] == "--comment":
            i += 2
            continue
        salida.append(tokens[i])
        i += 1
    return salida


def _comentario(tokens):
    return tokens[tokens.index("--comment") + 1] if "--comment" in tokens[:-1] else None


def analizar_iptables(texto) -> tuple:
    """(lugar o None, duda o None) de un `iptables -S INPUT`."""
    politica, reglas = "ACCEPT", []
    for linea in texto.splitlines():
        try:
            tokens = shlex.split(linea)
        except ValueError:
            return None, "no entiendo lo que dice «iptables -S INPUT»"
        if tokens[:2] == ["-P", "INPUT"] and len(tokens) >= 3:
            politica = tokens[2]
        elif tokens[:2] == ["-A", "INPUT"]:
            reglas.append(tokens[2:])
    suyas = [(i, t) for i, t in enumerate(reglas, 1) if _comentario(t) not in _PROPIAS]
    marcadas = sum(1 for t in reglas if _comentario(t) == MARCA)
    lugar = Lugar("iptables", "ip", "filter", "INPUT", marcadas=marcadas)
    if not suyas:
        return (lugar if politica == "DROP" else None), None
    posicion, ultima = suyas[-1]
    limpia = _sin_comentario(ultima)
    incondicional = len(limpia) >= 2 and limpia[0] in ("-j", "-g") and (
        len(limpia) == 2 or limpia[1] == "REJECT" and limpia[2:3] == ["--reject-with"] and len(limpia) == 4)
    objetivo = limpia[1] if incondicional else None
    if objetivo in ("DROP", "REJECT"):
        lugar.antes = posicion
        return lugar, None
    if incondicional and (limpia[0] == "-g" or objetivo not in _OBJETIVOS_FINALES):
        return None, "la cadena INPUT de iptables acaba saltando a %s sin condiciones, y no sé qué hace esa" % objetivo
    if politica == "DROP" and objetivo != "ACCEPT":
        return lugar, None
    return None, None


def _iptables_nft(sis) -> bool:
    return "nf_tables" in sis.ejecutar(["iptables", "-V"]).salida


# MARK: Todo junto


def analizar(sis, con_iptables=True) -> tuple:
    """(lugares, dudas) de lo que hay en marcha ahora. `con_iptables`: falso cuando ufw o firewalld llevan el
    cortafuegos, que van por debajo con iptables o con su propia tabla."""
    lugares, dudas = [], []
    for gestor in GESTORES_AJENOS:
        if sis.ejecutar(["systemctl", "is-active", gestor]).bien:
            dudas.append("%s lleva tu cortafuegos y lo reescribe a su manera" % gestor)
    iptables_nft = bool(sis.cual("iptables")) and _iptables_nft(sis)
    if con_iptables and sis.cual("iptables"):
        lugar, duda = analizar_iptables(sis.ejecutar(["iptables", "-S", "INPUT"]).salida)
        if lugar:
            lugares.append(lugar)
        if duda:
            dudas.append(duda)
    if sis.cual("nft"):
        de_nft, dudas_nft = analizar_nft(_ruleset(sis), iptables_nft)
        lugares += de_nft
        dudas += dudas_nft
    return lugares, dudas


def poner(sis, marca, reglas, con_iptables=True) -> list:
    """Quita las de esa marca y las vuelve a poner donde toca hoy: se puede repetir, y tras un reinicio o una recarga
    del cortafuegos las deja igual. Devuelve los lugares; sin ninguno, no hace nada."""
    quitar(sis, marca)
    lugares, dudas = analizar(sis, con_iptables)
    if dudas:
        raise NoSe("; ".join(dudas))
    for lugar in lugares:
        if lugar.herramienta == "nftables":
            verbo = ("insert rule %s %s %s position %d" % (lugar.familia, lugar.tabla, lugar.cadena, lugar.antes)
                     if lugar.antes is not None else "add rule %s %s %s" % (lugar.familia, lugar.tabla, lugar.cadena))
            guion = "".join("%s %s\n" % (verbo, r.nft(marca)) for r in reglas)
            r = sis.ejecutar(["nft", "-f", "-"], entrada=guion)
        else:
            for i, regla in enumerate(reglas):
                donde = ["-I", "INPUT", str(lugar.antes + i)] if lugar.antes is not None else ["-A", "INPUT"]
                r = sis.ejecutar(["iptables"] + donde + regla.iptables(marca))
                if not r.bien:
                    break
        if not r.bien:
            quitar(sis, marca)
            raise NoSe("%s no ha aceptado las reglas (%s)" % (lugar.nombre, (r.error or r.salida).strip()))
    return lugares


def quitar(sis, marca) -> int:
    """Todas las reglas con esa marca, de nftables y de iptables. Solo las nuestras: se buscan por su comentario."""
    quitadas = 0
    iptables_nft = bool(sis.cual("iptables")) and _iptables_nft(sis)
    if sis.cual("nft"):
        for objeto in _ruleset(sis):
            r = objeto.get("rule")
            if not r or r.get("comment") != marca or _de_iptables(r.get("family"), r.get("table"), iptables_nft):
                continue
            if all(_NOMBRE.match(str(r.get(k) or "")) for k in ("family", "table", "chain")):
                if sis.ejecutar(["nft", "delete", "rule", r["family"], r["table"], r["chain"], "handle",
                                 str(r.get("handle"))]).bien:
                    quitadas += 1
    if sis.cual("iptables"):
        for linea in reversed(sis.ejecutar(["iptables", "-S", "INPUT"]).salida.splitlines()):
            try:
                tokens = shlex.split(linea)
            except ValueError:
                continue
            if tokens[:2] == ["-A", "INPUT"] and _comentario(tokens) == marca:
                if sis.ejecutar(["iptables", "-D"] + tokens[1:]).bien:
                    quitadas += 1
    return quitadas


def guardadas(sis) -> list:
    """Los ficheros donde el sistema guarda su cortafuegos y que llevan reglas nuestras: pasa si alguien lo guardó
    (`netfilter-persistent save`) con ellas puestas. No se tocan; se dice."""
    return [ruta for ruta in ("/etc/iptables/rules.v4", "/etc/sysconfig/iptables", "/etc/nftables.conf",
                              "/etc/sysconfig/nftables.conf")
            if re.search(r"hehermes", sis.leer_texto(ruta) or "")]
