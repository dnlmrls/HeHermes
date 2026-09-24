"""Lo que se lee en un aviso: el principio de la respuesta sin markdown, en una línea y con 200 caracteres como mucho.

Sigue las reglas con las que la app pinta la vista previa de una respuesta (``VistaPrevia.texto(de:)``,
``ExtraccionMedia``, ``BloquesMarkdown.textoPlano``): que el aviso diga lo mismo que dirá la fila de la conversación al
abrirla. No es un intérprete de markdown completo; es lo bastante para que no se vean asteriscos, almohadillas ni
comillas invertidas en un banner.
"""

from __future__ import annotations

import html
import os
import re
import unicodedata

# Lo que cabe en el texto y en el título del aviso: los mismos topes que aplica la extensión
# (`ComposicionDelAviso.topeCuerpo` y `topeTitulo`), para que la extensión no tenga que volver a recortar nada.
TOPE_TEXTO = 200
TOPE_TITULO = 100
# Una conversación sin título se llama como su primera petición, recortada como en la app (`Hilo.titulo(desde:)`).
TOPE_TITULO_DESDE_PETICION = 40
# Lo que se lee de un texto antes de limpiarlo. Para 200 caracteres de aviso sobra de largo, y es lo que impide que una
# respuesta enorme (la salida de un comando, un volcado) le cueste segundos al vigía: alguna de las expresiones de abajo,
# como la de las cursivas con «_», tarda con el cuadrado de lo que lee (medido: 41 KB de «_a », 3,3 s).
TOPE_ENTRADA = 4096

PREFIJO_MEDIA = "MEDIA:"


def _preparar(texto: str) -> str:
    """El texto recortado a ``TOPE_ENTRADA`` y sin caracteres de control, salvo saltos de línea y tabuladores.

    En un aviso no pintan nada, y un NUL rompía la limpieza de ``_en_linea``, que los usa para apartar el código: una
    respuesta con «\\x001\\x00» hacía saltar un ``IndexError`` en cada vuelta.
    """
    recortado = texto[:TOPE_ENTRADA].replace("\r\n", "\n").replace("\r", "\n")
    return "".join(c for c in recortado if c in "\n\t" or unicodedata.category(c) != "Cc")

# ---------------------------------------------------------------------------------------------------------------------
# Ficheros que anuncia Hermes


def sin_media(texto: str) -> tuple[str, list[str]]:
    """El texto sin las líneas ``MEDIA:<ruta>`` y las rutas que traía, como ``ExtraccionMedia.separar``.

    Una línea cuenta si, sin espacios en los bordes y sin unas comillas invertidas alrededor, empieza por ``MEDIA:`` y
    lo que sigue es una ruta (empieza por ``/`` o ``~``). Así «MEDIA: la carpeta de fotos» sigue siendo texto.
    """
    rutas: list[str] = []
    lineas: list[str] = []
    for linea in texto.split("\n"):
        limpia = linea.strip()
        if len(limpia) > 2 and limpia.startswith("`") and limpia.endswith("`"):
            limpia = limpia[1:-1]
        if limpia.startswith(PREFIJO_MEDIA):
            ruta = limpia[len(PREFIJO_MEDIA):].strip()
            if ruta.startswith(("/", "~")):
                if ruta not in rutas:
                    rutas.append(ruta)
                continue
        lineas.append(linea)
    if not rutas:
        return texto, []
    return "\n".join(lineas).strip(), rutas


# ---------------------------------------------------------------------------------------------------------------------
# Markdown

_VALLA = re.compile(r"^( *)(`{3,}|~{3,})")
_SEPARADOR = re.compile(r"^(?:\*[ \t]*){3,}$|^(?:-[ \t]*){3,}$|^(?:_[ \t]*){3,}$")
_FILA_DE_GUIONES = re.compile(r"^\|?[ \t]*:?-{3,}:?[ \t]*(?:\|[ \t]*:?-{3,}:?[ \t]*)*\|?$")
_SUBRAYADO_SETEXT = re.compile(r"^=+$")
_CITA = re.compile(r"^ {0,3}> ?")
_ENCABEZADO = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
_TAREA = re.compile(r"^(\s*)[-*+][ \t]+\[([ xX])\][ \t]+(.*)$")
_VINETA = re.compile(r"^(\s*)[-*+][ \t]+(.*)$")
_NUMERO = re.compile(r"^(\s*)(\d{1,9}[.)])[ \t]+(.*)$")

_CODIGO_EN_LINEA = re.compile(r"(`+)(.+?)(?<!`)\1(?!`)")
_ESCAPE = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])")
_IMAGEN = re.compile(r"!\[([^\]]*)\]\((?:[^()\s]|\([^)]*\))*(?:\s+\"[^\"]*\")?\)")
_ENLACE = re.compile(r"\[([^\]]+)\]\((?:[^()\s]|\([^)]*\))*(?:\s+\"[^\"]*\")?\)")
_ENLACE_REFERENCIA = re.compile(r"\[([^\]]+)\]\[[^\]]*\]")
_AUTOENLACE = re.compile(r"<((?:https?|mailto):[^>\s]+)>")
_SALTO_HTML = re.compile(r"<br\s*/?>", re.IGNORECASE)
_ENFASIS = [
    re.compile(r"\*\*\*(?!\s)(.+?)(?<!\s)\*\*\*"),
    re.compile(r"\*\*(?!\s)(.+?)(?<!\s)\*\*"),
    re.compile(r"(?<!\w)__(?!\s)(.+?)(?<!\s)__(?!\w)"),
    re.compile(r"\*(?!\s)(.+?)(?<!\s)\*"),
    re.compile(r"(?<!\w)_(?!\s)(.+?)(?<!\s)_(?!\w)"),
    re.compile(r"~~(?!\s)(.+?)(?<!\s)~~"),
]


def sin_markdown(texto: str) -> str:
    """El texto que se ve de un markdown: sin marcas de bloque ni de línea, conservando las líneas.

    El código se deja tal cual, sin sus vallas; las listas llevan «•» (o su número, o ☐/☑), como en la app; las tablas
    pasan a sus celdas y los separadores desaparecen.
    """
    lineas = texto.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    salida: list[str] = []
    i = 0
    while i < len(lineas):
        linea = lineas[i]
        valla = _VALLA.match(linea)
        if valla:
            sangria, marca = len(valla.group(1)), valla.group(2)
            i += 1
            while i < len(lineas):
                cierre = re.match(r"^ *(`{3,}|~{3,})[ \t]*$", lineas[i])
                if cierre and cierre.group(1)[0] == marca[0] and len(cierre.group(1)) >= len(marca):
                    i += 1
                    break
                dentro = lineas[i]
                salida.append(dentro[sangria:] if dentro.startswith(" " * sangria) else dentro.lstrip(" "))
                i += 1
            continue
        plana = _linea_plana(linea)
        if plana is not None:
            salida.append(plana)
        i += 1
    return "\n".join(salida)


def _linea_plana(linea: str) -> str | None:
    recortada = linea.strip()
    if _SEPARADOR.match(recortada) or _SUBRAYADO_SETEXT.match(recortada):
        return None
    if "|" in recortada and "-" in recortada and _FILA_DE_GUIONES.match(recortada):
        return None
    if len(recortada) > 1 and recortada.startswith("|") and recortada.endswith("|"):
        celdas = [celda.strip() for celda in recortada[1:-1].split("|")]
        return " ".join(_en_linea(celda) for celda in celdas if celda)
    resto = linea
    while True:
        cita = _CITA.match(resto)
        if not cita:
            break
        resto = resto[cita.end():]
    encabezado = _ENCABEZADO.match(resto)
    if encabezado:
        return _en_linea(encabezado.group(1) or "")
    tarea = _TAREA.match(resto)
    if tarea:
        marca = "☐" if tarea.group(2) == " " else "☑"
        return f"{tarea.group(1)}{marca} {_en_linea(tarea.group(3))}"
    vineta = _VINETA.match(resto)
    if vineta:
        return f"{vineta.group(1)}• {_en_linea(vineta.group(2))}"
    numero = _NUMERO.match(resto)
    if numero:
        return f"{numero.group(1)}{numero.group(2)} {_en_linea(numero.group(3))}"
    return _en_linea(resto)


def _en_linea(texto: str) -> str:
    """Las marcas de dentro de una línea. El código y los caracteres escapados se apartan antes, para que un ``*``
    dentro de ``\\`a*b\\``` o un ``\\*`` escrito a propósito no abran una cursiva."""
    apartados: list[str] = []

    def apartar(contenido: str) -> str:
        apartados.append(contenido)
        return f"\x00{len(apartados) - 1}\x00"

    def devolver(numero: str) -> str:
        indice = int(numero)
        return apartados[indice] if indice < len(apartados) else ""

    # Los apartados se marcan con NUL: uno que ya viniera en el texto se confundiría con una marca.
    texto = texto.replace("\x00", "")
    texto = _CODIGO_EN_LINEA.sub(lambda m: apartar(_quitar_un_espacio(m.group(2))), texto)
    texto = _ESCAPE.sub(lambda m: apartar(m.group(1)), texto)
    texto = _IMAGEN.sub(r"\1", texto)
    texto = _ENLACE.sub(r"\1", texto)
    texto = _ENLACE_REFERENCIA.sub(r"\1", texto)
    texto = _AUTOENLACE.sub(r"\1", texto)
    texto = _SALTO_HTML.sub(" ", texto)
    for patron in _ENFASIS:
        texto = patron.sub(r"\1", texto)
    texto = html.unescape(texto)
    return re.sub(r"\x00(\d+)\x00", lambda m: devolver(m.group(1)), texto)


def _quitar_un_espacio(codigo: str) -> str:
    # CommonMark quita un espacio a cada lado del código en línea si los dos lados lo tienen (`` ` `a` ` ``).
    if len(codigo) >= 2 and codigo.startswith(" ") and codigo.endswith(" ") and codigo.strip():
        return codigo[1:-1]
    return codigo


# ---------------------------------------------------------------------------------------------------------------------
# Una línea, recortada


def una_linea(texto: str) -> str:
    """Las líneas con texto, sin espacios en los bordes y unidas por un espacio: un banner no tiene saltos."""
    return " ".join(parte.strip() for parte in texto.split("\n") if parte.strip())


def recortar(texto: str, tope: int) -> str:
    """El texto recortado a ``tope`` caracteres **contando** los puntos suspensivos, por la última palabra entera.

    Se cuentan puntos de código, que en Swift son como mucho tantos caracteres como aquí: lo que cabe aquí cabe en la
    extensión, que así no vuelve a recortar. Y un corte no deja medio emoji: un modificador, un unidor o media bandera
    sueltos al final se verían como un fallo, no como un recorte.
    """
    if len(texto) <= tope:
        return texto
    cabe = texto[:tope - 1]
    espacio = cabe.rfind(" ")
    if espacio >= tope // 2:
        cabe = cabe[:espacio]
    return _sin_trozos_sueltos(cabe.rstrip()) + "…"


def _sin_trozos_sueltos(texto: str) -> str:
    def es_pegadizo(caracter: str) -> bool:
        codigo = ord(caracter)
        return (unicodedata.combining(caracter) != 0 or caracter in "\u200d\ufe0e\ufe0f"
                or 0x1F3FB <= codigo <= 0x1F3FF or 0xE0020 <= codigo <= 0xE007F)

    while True:
        antes = texto
        while texto and es_pegadizo(texto[-1]):
            texto = texto[:-1]
        # Un emoji hecho de varios unidos (👨‍👩‍👧) cortado por la mitad sería otro emoji: fuera la parte unida.
        while len(texto) >= 2 and texto[-2] == "\u200d":
            texto = texto[:-2]
        if texto == antes:
            break
    banderas = 0
    while banderas < len(texto) and 0x1F1E6 <= ord(texto[-1 - banderas]) <= 0x1F1FF:
        banderas += 1
    if banderas % 2:
        texto = texto[:-1]
    return texto.rstrip()


# ---------------------------------------------------------------------------------------------------------------------
# Lo que se enseña


def de_respuesta(texto: str) -> str:
    """El texto de un aviso de respuesta: el principio de lo que contestó Hermes, como la vista previa de la app.

    Una respuesta que solo trae un fichero dice «Hermes ha creado informe.pdf», que es lo que pone la fila de la lista.
    """
    resto, rutas = sin_media(_preparar(texto))
    plano = una_linea(sin_markdown(resto))
    if not plano and rutas:
        plano = f"Hermes ha creado {os.path.basename(rutas[0].rstrip('/')) or rutas[0]}"
    return recortar(plano, TOPE_TEXTO)


def titulo_de_sesion(sesion: dict) -> str:
    """El nombre de la conversación como lo enseña la app (``HistorialHermes.titulo``): el título que puso Hermes; si no
    hay, su primera petición recortada; si tampoco, «Hermes»."""
    titulo = sesion.get("title")
    if isinstance(titulo, str) and _preparar(titulo).strip():
        return recortar(una_linea(_preparar(titulo)), TOPE_TITULO)
    vista = sesion.get("preview")
    if isinstance(vista, str) and _preparar(vista).strip():
        primera = next((parte for parte in _preparar(vista).strip().split("\n") if parte), "")
        if len(primera) > TOPE_TITULO_DESDE_PETICION:
            primera = primera[:TOPE_TITULO_DESDE_PETICION].strip() + "…"
        if primera.strip():
            return primera
    return "Hermes"


def corto(texto: str, tope: int = TOPE_TEXTO) -> str:
    """Un texto cualquiera (un error, un comando que pide permiso) en una línea y recortado."""
    return recortar(una_linea(_preparar(texto)), tope)
