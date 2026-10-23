"""El manifiesto de lo instalado y su comparación (desde la 1.6.4): para saber si alguien ha tocado a mano un fichero del
servidor (2026-10-22: ``vigia/fichero.py`` del VPS llevaba un parche puesto a mano el 2026-10-08, y la actualización de
ese día lo habría borrado sin que nadie lo supiera).

- **Al instalar** (``despliegue/instalar.sh`` y el instalador, ``hehermes_servidor.avisos``) se deja el manifiesto junto
  a ``vigia.ini``: una línea por fichero con su suma SHA-256, el nombre corto con el que se le nombra a la app y su ruta
  de verdad. Son el código de los avisos y los ayudantes de ``/usr/local/libexec/hehermes-*``.
- **En marcha** el vigía (``observatorio``) vuelve a sumar esos ficheros y dice cuáles ya no coinciden: **solo nombres**,
  nunca contenido ni rutas. Compara el vigía y no el ayudante que actualiza: ni el código ni los ayudantes tienen
  permisos que se lo impidan (el código es 0644 y los ayudantes 0755, y su unidad solo esconde ``/etc/hehermes-avisos/rele``
  y poco más), así que no hace falta pedirle nada a un proceso de root.

El formato es de texto, uno por línea, con tabuladores (una ruta puede llevar espacios)::

    # hehermes-manifiesto 1
    <sha256>\\t<nombre>\\t<ruta absoluta>

El instalador (que no importa este paquete) lo escribe con su propia copia de ``linea``, y una prueba cruza las dos
(``test_avisos.LosAvisosYElManifiesto``). Se puede escribir a mano con
``python -I -m hehermes_avisos.vigia.integridad escribir SALIDA CARPETA [FICHERO…]``.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys

NOMBRE = "manifiesto.sha256"
CABECERA = "# hehermes-manifiesto 1"
#: Más que esto no es un manifiesto: no se lee (el de un servidor lleva un centenar de líneas).
TOPE = 1024 * 1024
PATRON_SHA = re.compile(r"[0-9a-f]{64}")
#: Lo que se le dice a la app es solo el nombre: sin barra delante, sin «..», sin nada raro.
PATRON_NOMBRE = re.compile(r"[A-Za-z0-9_@+-][A-Za-z0-9_./@+-]{0,199}")


def nombre_valido(nombre: str) -> bool:
    return bool(PATRON_NOMBRE.fullmatch(nombre)) and ".." not in nombre.split("/")


def linea(suma: str, nombre: str, ruta: str) -> str:
    if not PATRON_SHA.fullmatch(suma) or not nombre_valido(nombre) or not ruta.startswith("/") \
            or any(c in ruta for c in "\t\n\r\0"):
        raise ValueError("entrada de manifiesto no válida: %r" % (nombre,))
    return "%s\t%s\t%s\n" % (suma, nombre, ruta)


def texto(entradas) -> str:
    """El manifiesto de ``entradas`` (``(suma, nombre, ruta)``), ordenado por nombre para que dos instalaciones iguales
    dejen el mismo fichero."""
    return CABECERA + "\n" + "".join(linea(*e) for e in sorted(entradas, key=lambda e: (e[1], e[2])))


def leer(contenido: str) -> list | None:
    """Las entradas de un manifiesto, o ``None`` si no lo es (cabecera distinta, una línea con otra forma): no se
    adivina con un fichero a medias, que daría todo por cambiado."""
    lineas = contenido.split("\n")
    if not lineas or lineas[0] != CABECERA:
        return None
    entradas = []
    for crudo in lineas[1:]:
        if not crudo or crudo.startswith("#"):
            continue
        partes = crudo.split("\t")
        if len(partes) != 3:
            return None
        suma, nombre, ruta = partes
        if not PATRON_SHA.fullmatch(suma) or not nombre_valido(nombre) or not ruta.startswith("/"):
            return None
        entradas.append((suma, nombre, ruta))
    return entradas


def suma_de(ruta: str) -> str:
    """El SHA-256 de un fichero; ``OSError`` si no se puede leer (``FileNotFoundError``, si no existe)."""
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for trozo in iter(lambda: f.read(65536), b""):
            h.update(trozo)
    return h.hexdigest()


def cambiados(entradas, sumar=suma_de) -> list:
    """Los nombres de los ficheros del manifiesto que ya no son lo instalado: otra suma, o que faltan. Uno que no se puede
    leer por otra razón (permisos) no se da por cambiado: no se sabe, y no es lo que se busca."""
    distintos = set()
    for suma, nombre, ruta in entradas:
        try:
            if sumar(ruta) != suma:
                distintos.add(nombre)
        except FileNotFoundError:
            distintos.add(nombre)
        except OSError:
            continue
    return sorted(distintos)


def comprobar(ruta_manifiesto: str, sumar=suma_de) -> list | None:
    """Los ficheros cambiados a mano desde que se instaló, o ``None`` si no hay manifiesto que valga (una instalación
    de antes de la 1.6.4: de eso no se dice nada)."""
    try:
        with open(ruta_manifiesto, "rb") as f:
            crudo = f.read(TOPE + 1)
        if len(crudo) > TOPE:
            return None
        entradas = leer(crudo.decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return None
    return None if entradas is None else cambiados(entradas, sumar)


def entradas_de(carpeta: str, ficheros=()) -> list:
    """Las entradas de lo que hay instalado: todo lo de ``carpeta`` (menos ``__pycache__``, que se hace después), con el
    nombre relativo a ella, y cada fichero suelto (un ayudante), con su nombre a secas. Lo que no existe no se apunta."""
    entradas = []
    carpeta = os.path.abspath(carpeta)
    for raiz, subcarpetas, nombres in os.walk(carpeta):
        subcarpetas[:] = sorted(s for s in subcarpetas if s != "__pycache__")
        for nombre in sorted(nombres):
            ruta = os.path.join(raiz, nombre)
            if os.path.isfile(ruta) and not os.path.islink(ruta):
                entradas.append((suma_de(ruta), os.path.relpath(ruta, carpeta).replace(os.sep, "/"), ruta))
    for ruta in ficheros:
        ruta = os.path.abspath(ruta)
        if os.path.isfile(ruta):
            entradas.append((suma_de(ruta), os.path.basename(ruta), ruta))
    return entradas


def escribir(salida: str, carpeta: str, ficheros=()) -> int:
    """Deja el manifiesto en ``salida`` (0644, de golpe: nadie lo ve a medias). Devuelve cuántos ficheros apunta."""
    entradas = entradas_de(carpeta, ficheros)
    temporal = salida + ".nuevo"
    with open(temporal, "w", encoding="utf-8") as f:
        f.write(texto(entradas))
    os.chmod(temporal, 0o644)
    os.replace(temporal, salida)
    return len(entradas)


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 3 or argv[0] != "escribir":
        print("uso: python -I -m hehermes_avisos.vigia.integridad escribir SALIDA CARPETA [FICHERO…]", file=sys.stderr)
        return 2
    print("%d ficheros apuntados en %s" % (escribir(argv[1], argv[2], argv[3:]), argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
