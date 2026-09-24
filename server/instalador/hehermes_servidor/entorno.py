"""La lectura del `.env` de Hermes. Solo se lee: el instalador nunca lo escribe (eso es `--activar-api`, pieza B)."""

from __future__ import annotations

import re

_LINEA = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def leer_env(texto: str) -> dict:
    """Como lo leen python-dotenv y la shell en lo que importa aquí: `export` delante, comillas simples o dobles, y un
    comentario solo si va detrás de un espacio (`a#b` es un valor). Lo que no se entiende se salta."""
    valores = {}
    for linea in texto.splitlines():
        hallado = _LINEA.match(linea)
        if not hallado:
            continue
        clave, valor = hallado.groups()
        if valor[:1] in ("'", '"'):
            cierre = valor.find(valor[0], 1)
            valor = valor[1:cierre] if cierre > 0 else valor[1:]
        else:
            valor = re.split(r"\s+#", valor, maxsplit=1)[0].strip()
        valores[clave] = valor
    return valores
