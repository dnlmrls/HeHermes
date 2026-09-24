"""El manifiesto: la lista de lo que es del instalador, y la guarda que decide qué se puede escribir.

La regla de la spec: solo se escribe en lo que está en el manifiesto y nadie ha cambiado desde que se escribió. Lo que
no está (lo ajeno) y lo que está pero ha cambiado (lo modificado) paran el instalador, salvo `--reemplazar`, que antes
guarda una copia para que desinstalar lo devuelva a como estaba.
"""

from __future__ import annotations

import json

from .sistema import sha256

RUTA_MANIFIESTO = "/etc/hehermes/instalacion.json"
CARPETA = "/etc/hehermes"
CARPETA_COPIAS = "/etc/hehermes/copias"

NUEVO = "nuevo"
YA_ESTA = "ya está"
CAMBIA = "cambia"
AJENO = "ajeno"
AJENO_IGUAL = "ya está (no es mío)"
MODIFICADO = "modificado"
REEMPLAZA = "reemplaza"

#: Lo que para el instalador si no se pide `--reemplazar`.
BLOQUEAN = (AJENO, MODIFICADO)
#: Lo que se escribe.
ESCRIBEN = (NUEVO, CAMBIA, REEMPLAZA)


class ManifiestoRoto(Exception):
    pass


class Manifiesto:
    def __init__(self, datos: dict | None = None, en_disco: bool = False):
        self.datos = datos or {"v": 1}
        for clave, vacio in (("ficheros", {}), ("paquetes", []), ("reglas", []), ("unidades", []),
                             ("quitados", {}), ("dispositivos", []), ("carpetas", [])):
            self.datos.setdefault(clave, vacio)
        self.datos.setdefault("avisos", False)
        self.en_disco = en_disco

    # Lo que lleva

    @property
    def ficheros(self) -> dict:
        return self.datos["ficheros"]

    @property
    def paquetes(self) -> list:
        return self.datos["paquetes"]

    @property
    def reglas(self) -> list:
        return self.datos["reglas"]

    @property
    def unidades(self) -> list:
        return self.datos["unidades"]

    @property
    def quitados(self) -> dict:
        """Lo que el instalador quitó y desinstalar tiene que volver a poner (`sites-enabled/default`)."""
        return self.datos["quitados"]

    @property
    def dispositivos(self) -> list:
        return self.datos["dispositivos"]

    @property
    def carpetas(self) -> list:
        """Las carpetas que creó el instalador (y que desinstalar quita si se han quedado vacías)."""
        return self.datos["carpetas"]

    def apuntar_carpetas(self, sis, ruta: str) -> None:
        """Antes de escribir `ruta`, apunta las carpetas de su camino que todavía no existen."""
        faltan = []
        carpeta = ruta.rsplit("/", 1)[0]
        while carpeta and not sis.existe(carpeta):
            faltan.append(carpeta)
            carpeta = carpeta.rsplit("/", 1)[0]
        for carpeta in reversed(faltan):
            if carpeta not in self.carpetas:
                self.carpetas.append(carpeta)

    def apuntar_fichero(self, ruta: str, datos: bytes, copia: dict | None = None) -> None:
        self.ficheros[ruta] = _con_copia({"tipo": "fichero", "sha256": sha256(datos)}, self.ficheros.get(ruta), copia)

    def apuntar_enlace(self, ruta: str, destino: str, copia: dict | None = None) -> None:
        self.ficheros[ruta] = _con_copia({"tipo": "enlace", "destino": destino}, self.ficheros.get(ruta), copia)

    def apuntar_gestionado(self, ruta: str, copia: dict | None = None) -> None:
        """Un fichero suyo cuyo contenido cambia sin que nadie lo toque a mano (la clave de nginx, que rota)."""
        self.ficheros[ruta] = _con_copia({"tipo": "gestionado"}, self.ficheros.get(ruta), copia)

    def olvidar(self, ruta: str) -> None:
        self.ficheros.pop(ruta, None)

    # Disco

    @classmethod
    def leer(cls, sis) -> "Manifiesto":
        datos = sis.leer(RUTA_MANIFIESTO)
        if datos is None:
            return cls()
        try:
            leido = json.loads(datos)
        except ValueError as error:
            raise ManifiestoRoto("%s no se puede leer (%s): no sigo sin saber qué es mío" % (RUTA_MANIFIESTO, error))
        if not isinstance(leido, dict) or leido.get("v") != 1:
            raise ManifiestoRoto("%s no es de una versión que conozca" % RUTA_MANIFIESTO)
        return cls(leido, en_disco=True)

    def guardar(self, sis) -> None:
        sis.carpeta(CARPETA, 0o700)
        sis.escribir(RUTA_MANIFIESTO, (json.dumps(self.datos, indent=2, ensure_ascii=False, sort_keys=True)
                                       + "\n").encode(), modo=0o600)
        self.en_disco = True


def _con_copia(entrada: dict, anterior: dict | None, copia: dict | None) -> dict:
    # La copia de lo que había antes de la primera vez se conserva en las siguientes escrituras: es lo que vuelve al
    # desinstalar.
    if copia is not None:
        entrada["copia"] = copia
    elif anterior and "copia" in anterior:
        entrada["copia"] = anterior["copia"]
    return entrada


def clasificar(sis, man: Manifiesto, ruta: str, deseado: bytes | None = None, destino_enlace: str | None = None,
               reemplazar=frozenset()) -> str:
    """Qué es lo que hay en `ruta` respecto a lo que se quiere dejar: un fichero con `deseado` o un enlace a
    `destino_enlace`."""
    entrada = man.ficheros.get(ruta)
    hay_algo = sis.existe(ruta)
    if not hay_algo:
        return NUEVO
    if destino_enlace is not None:
        actual_enlace = sis.enlace(ruta)
        igual = actual_enlace == destino_enlace
    else:
        actual = sis.leer(ruta)
        igual = actual is not None and actual == deseado
    if entrada is None:
        if igual:
            return AJENO_IGUAL
        return REEMPLAZA if ruta in reemplazar else AJENO
    if _sin_tocar(sis, ruta, entrada):
        return YA_ESTA if (igual or entrada["tipo"] == "gestionado") else CAMBIA
    return REEMPLAZA if ruta in reemplazar else MODIFICADO


def _sin_tocar(sis, ruta: str, entrada: dict) -> bool:
    """Si lo que hay es lo que el instalador dejó: el mismo contenido, el mismo destino o, si es gestionado, un fichero
    normal (su contenido cambia solo)."""
    if entrada["tipo"] == "enlace":
        return sis.enlace(ruta) == entrada["destino"]
    actual = sis.leer(ruta)
    if actual is None:
        return False
    if entrada["tipo"] == "gestionado":
        return True
    return sha256(actual) == entrada["sha256"]


def sin_tocar(sis, man: Manifiesto, ruta: str) -> bool:
    """Para desinstalar: lo que se puede quitar porque sigue como lo dejó el instalador."""
    entrada = man.ficheros.get(ruta)
    return entrada is not None and sis.existe(ruta) and _sin_tocar(sis, ruta, entrada)


# Copias de lo que se reemplaza


def guardar_copia(sis, ruta: str) -> dict:
    """Guarda lo que hay en `ruta` antes de reemplazarlo. Un enlace se apunta por su destino."""
    destino = sis.enlace(ruta)
    if destino is not None:
        return {"tipo": "enlace", "destino": destino}
    datos = sis.leer(ruta)
    if datos is None:
        raise ValueError("%s no es un fichero ni un enlace: no sé guardarlo" % ruta)
    sis.carpeta(CARPETA, 0o700)
    sis.carpeta(CARPETA_COPIAS, 0o700)
    nombre = ruta.strip("/").replace("/", "%")
    copia = CARPETA_COPIAS + "/" + nombre
    sis.escribir(copia, datos, modo=0o600)
    return {"tipo": "fichero", "ruta": copia, "modo": sis.modo(ruta) or 0o644}


def restaurar_copia(sis, ruta: str, copia: dict) -> None:
    if copia["tipo"] == "enlace":
        sis.borrar(ruta)
        sis.enlazar(ruta, copia["destino"])
        return
    datos = sis.leer(copia["ruta"])
    if datos is None:
        raise ValueError("falta la copia %s de %s" % (copia["ruta"], ruta))
    sis.escribir(ruta, datos, modo=copia["modo"])
    sis.borrar(copia["ruta"])

