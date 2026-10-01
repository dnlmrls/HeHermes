"""Lo que se le dice a Hermes en su `SOUL.md` para que sepa mandar ficheros al iPhone (desde la 0.10.4).

La app solo descarga lo que una respuesta de Hermes marca con una línea `MEDIA:<ruta>`, y el lector de ficheros
(`hehermes-leer-media`) solo sirve sus caches y `<HERMES_HOME>/exports` (server/API-CONTRACT.md, §11). Hermes no lo sabe
solo: al de Daniel se lo dice su `SOUL.md`, puesto a mano. Desde la 0.10.4, `instalar` añade al de cada Hermes un párrafo
con eso, una sola vez:

- **El `SOUL.md` que usa Hermes**: el de su HERMES_HOME, que con un perfil es la casa del perfil
  (`agent/prompt_builder.py`, `load_soul_md`: `get_hermes_home() / "SOUL.md"`, la identidad de su prompt de sistema; lo
  relee en cada mensaje). Es `Hermes.home`, como la decide `deteccion.casa_del_proceso`.
- **Al final, con una copia antes**, sin tocar nada más y sin cambiarle el dueño ni el modo. Lo que ya lo dice (este
  párrafo, o uno que ya habla de `MEDIA:` y de `exports`, como el de Daniel) no se toca. Desinstalar quita exactamente
  lo que se añadió, si sigue tal cual.
- **Lo que no se toca:** un `SOUL.md` que no está, vacío o que es un enlace (sin él, o vacío, Hermes usa su personalidad
  de serie, y uno con solo este párrafo se la quitaría), y el de un perfil instalado de una distribución
  (`distribution.yaml`: `hermes profile update` lo reescribe, y Hermes bloquea entero uno así si algo en él le parece una
  inyección). Se avisa y se sigue: sin el párrafo, la app ofrece «Pedírselo a Hermes» cuando un fichero está fuera.
- **El texto no dispara el escáner de inyecciones de Hermes** (`tools/threat_patterns.py`, ámbito «context» y
  «strict»): comprobado con los de la 0.15.0 a `main` (2026-10-01).
"""

from __future__ import annotations

from . import manifiesto as m

TITULO = "## Ficheros para el iPhone (HeHermes)"
#: Lo que dice que alguien ya le ha explicado a Hermes cómo mandar ficheros (el `SOUL.md` de Daniel).
_YA_LO_DICE = (b"MEDIA:", b"exports")


def parrafo(carpeta: str) -> str:
    """El párrafo, con la carpeta de exportaciones como la ve Hermes (en un contenedor, la de dentro)."""
    return ("%s\n\nCuando quieras mandarme un fichero al iPhone (un PDF, una imagen, un informe…), guárdalo como un "
            "fichero normal (no un enlace ni una carpeta) en %s y, en tu respuesta, pon una línea aparte con MEDIA: y "
            "su ruta absoluta; por ejemplo, MEDIA:%s/informe.pdf. La app HeHermes solo descarga lo que está en esa "
            "carpeta.\n" % (TITULO, carpeta, carpeta))


def ruta_de(hermes) -> str:
    return hermes.home.rstrip("/") + "/SOUL.md"


def exportaciones_de(hermes) -> str:
    return (getattr(hermes, "casa_de_hermes", None) or hermes.home).rstrip("/") + "/exports"


def planear(sis, det, man, acciones, avisos) -> None:
    """La acción `soul` del plan (sección «Hermes»), o un aviso si no se toca."""
    from .plan import Accion
    hermes = det.hermes
    ruta = ruta_de(hermes)
    exportaciones = exportaciones_de(hermes)
    a_mano = ("Si quieres que Hermes sepa mandarte ficheros al iPhone, dile que los deje en %s y que los mande con una "
              "línea MEDIA:<ruta>" % exportaciones)
    if sis.existe(hermes.home.rstrip("/") + "/distribution.yaml"):
        avisos.append("El SOUL.md de Hermes (%s) es de una distribución de perfiles: no lo toco. %s" % (ruta, a_mano))
        return
    if sis.enlace(ruta) is not None:
        avisos.append("El SOUL.md de Hermes (%s) es un enlace: no lo toco. %s" % (ruta, a_mano))
        return
    datos = sis.leer(ruta)
    if datos is None:
        avisos.append("No encuentro el SOUL.md de Hermes (%s): no lo creo, porque sin él Hermes usa su personalidad de "
                      "serie. %s" % (ruta, a_mano))
        return
    if not datos.strip():
        avisos.append("El SOUL.md de Hermes (%s) está vacío (usa su personalidad de serie): no lo toco. %s"
                      % (ruta, a_mano))
        return
    mio = (man.datos.get("soul") or {}).get("ruta") == ruta
    if TITULO.encode("utf-8") in datos:
        acciones.append(Accion("soul", ruta, m.YA_ESTA if mio else m.AJENO_IGUAL,
                               "ya le dice a Hermes cómo mandar ficheros al iPhone"))
    elif all(trozo in datos for trozo in _YA_LO_DICE):
        acciones.append(Accion("soul", ruta, m.AJENO_IGUAL, "ya le dice a Hermes cómo mandar ficheros al iPhone (con "
                                                            "MEDIA: y exports)"))
    else:
        acciones.append(Accion("soul", ruta, m.NUEVO, "añado a SOUL.md cómo mandar ficheros al iPhone (con una copia "
                                                      "antes)", parrafo(exportaciones)))


def anadir(sis, man, accion, salida, ambito=None) -> None:
    """El párrafo al final, con una copia antes: lo añadido, tal cual, queda en el manifiesto para quitarlo. En bytes,
    para no cambiar ni uno de lo que ya había. Si entre el plan y esto alguien lo ha puesto, no se repite."""
    ruta = accion.objeto
    datos = sis.leer(ruta)
    if datos is None or TITULO.encode("utf-8") in datos:
        return
    carpeta = None if ambito is None or ambito.root else ambito.carpeta_config
    # Las carpetas de las copias que no estuvieran, apuntadas: desinstalar las quita si se quedan vacías.
    man.apuntar_carpetas(sis, (m.CARPETA_COPIAS if carpeta is None else carpeta + "/copias") + "/x")
    copia = m.guardar_copia(sis, ruta, carpeta)
    anadido = (b"" if datos.endswith(b"\n") else b"\n") + b"\n" + accion.datos.encode("utf-8")
    sis.escribir(ruta, datos + anadido, modo=sis.modo(ruta) or 0o644, mismo_dueno=True)
    man.datos["soul"] = {"ruta": ruta, "anadido": anadido.decode("utf-8"), "copia": copia}
    man.guardar(sis)
    salida("==> el SOUL.md de Hermes: le añado cómo mandarte ficheros al iPhone (%s)" % ruta)


def resumen(man) -> list:
    """Lo que dice desinstalar antes de quitarlo."""
    datos = man.datos.get("soul")
    return ["  lo que añadí a %s (cómo mandar ficheros al iPhone)" % datos["ruta"]] if datos else []


def quitar(sis, man, quedan, salida) -> None:
    """Desinstalar: fuera exactamente lo que se añadió, si sigue tal cual (lo de después, si lo hay, se queda), y su
    copia de antes, que ya no hace falta (queda como estaba)."""
    datos = man.datos.pop("soul", None)
    if not datos:
        return
    ruta, anadido = datos.get("ruta"), (datos.get("anadido") or "").encode("utf-8")
    actual = sis.leer(ruta) if ruta else None
    if actual is not None and anadido and anadido in actual:
        i = actual.rindex(anadido)
        sis.escribir(ruta, actual[:i] + actual[i + len(anadido):], modo=sis.modo(ruta) or 0o644, mismo_dueno=True)
        salida("==> el SOUL.md de Hermes: quito lo que le añadí (%s)" % ruta)
    elif actual is not None:
        quedan.append("%s: lo que le añadí para mandar ficheros al iPhone ha cambiado, así que no lo quito" % ruta)
    copia = (datos.get("copia") or {}).get("ruta")
    if isinstance(copia, str) and copia.startswith("/") and "/copias/" in copia:
        sis.borrar(copia)
        sis.borrar(copia.rsplit("/", 1)[0])
