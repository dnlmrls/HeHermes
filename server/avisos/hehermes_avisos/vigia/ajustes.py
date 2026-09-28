"""Los ajustes de avisos de un iPhone, tal y como los manda la app (``PreferenciasDeAvisos.swift``)::

    {"tipos": {"respuestas": true, "aprobaciones": true, "segundo_plano": true, "errores": true},
     "vista_previa": "siempre", "sonido": "mensajes", "numero": true, "silenciados": ["api_…"]}

Se leen con la mano floja, igual que en la app: lo que falte o no se entienda vale lo de fábrica. Un ajuste de una
versión más nueva de la app no puede dejar al vigía sin saber qué hacer, y lo de fábrica es avisar de todo, que es lo que
Daniel aprobó.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

VISTAS_PREVIAS = ("siempre", "nombre", "nunca")
SONIDOS = ("mensajes", "ninguno")
# De qué interruptor depende cada tipo de aviso. El de prueba no depende de ninguno: quien lo pide quiere verlo.
INTERRUPTOR_DE = {"respuesta": "respuestas", "aprobacion": "aprobaciones", "segundo-plano": "segundo_plano",
                  "error": "errores"}
# Tope de chats silenciados y de lo que mide cada id: la lista la manda la app, pero un cliente roto no puede hacer que
# cada alta pese megas.
MAX_SILENCIADOS = 1000
MAX_ID_SESION = 256


@dataclass(frozen=True)
class Ajustes:
    respuestas: bool = True
    aprobaciones: bool = True
    segundo_plano: bool = True
    errores: bool = True
    vista_previa: str = "siempre"
    sonido: str = "mensajes"
    # El vigía no lo usa: el número del icono lo lleva la extensión con lo que sabe la app (nunca va `badge` en el
    # push). Se guarda para devolver los ajustes tal cual si algún día hace falta.
    numero: bool = True
    silenciados: tuple = field(default_factory=tuple)

    @classmethod
    def desde_json(cls, objeto: object) -> Ajustes:
        ajustes = cls()
        if not isinstance(objeto, dict):
            return ajustes
        tipos = objeto.get("tipos")
        if isinstance(tipos, dict):
            for clave in ("respuestas", "aprobaciones", "segundo_plano", "errores"):
                if isinstance(tipos.get(clave), bool):
                    ajustes = replace(ajustes, **{clave: tipos[clave]})
        if objeto.get("vista_previa") in VISTAS_PREVIAS:
            ajustes = replace(ajustes, vista_previa=objeto["vista_previa"])
        if objeto.get("sonido") in SONIDOS:
            ajustes = replace(ajustes, sonido=objeto["sonido"])
        if isinstance(objeto.get("numero"), bool):
            ajustes = replace(ajustes, numero=objeto["numero"])
        silenciados = objeto.get("silenciados")
        if isinstance(silenciados, list):
            validos = sorted({s for s in silenciados if isinstance(s, str) and 0 < len(s) <= MAX_ID_SESION})
            ajustes = replace(ajustes, silenciados=tuple(validos[:MAX_SILENCIADOS]))
        return ajustes

    def a_json(self) -> dict:
        return {"tipos": {"respuestas": self.respuestas, "aprobaciones": self.aprobaciones,
                          "segundo_plano": self.segundo_plano, "errores": self.errores},
                "vista_previa": self.vista_previa, "sonido": self.sonido, "numero": self.numero,
                "silenciados": list(self.silenciados)}

    def avisa_de(self, tipo: str) -> bool:
        """Si este tipo de aviso está encendido. Un tipo que no depende de ningún interruptor (la prueba) siempre."""
        interruptor = INTERRUPTOR_DE.get(tipo)
        return True if interruptor is None else getattr(self, interruptor)

    @property
    def todos_apagados(self) -> bool:
        """Los cuatro tipos apagados: a este iPhone solo le llegará el aviso de prueba."""
        return not any((self.respuestas, self.aprobaciones, self.segundo_plano, self.errores))

    def silenciada(self, sesion: str | None) -> bool:
        return bool(sesion) and sesion in self.silenciados

    def cambios(self, antes: Ajustes | None) -> str:
        """Qué cambia respecto de ``antes`` (o de lo de fábrica, en un alta nueva), para el registro: «respuestas sí → no,
        sonido mensajes → ninguno». De los silenciados, solo cuántos: sus ids son de conversaciones.

        El 2026-09-27 el iPhone de Daniel apagó los cuatro tipos y el sonido a la 01:04, y el registro solo decía
        «ajustes … al día» cinco veces: qué había cambiado hubo que sacarlo de la base de datos, y cuándo, del registro.
        """
        antes = antes or Ajustes()
        partes = []
        for campo in ("respuestas", "aprobaciones", "segundo_plano", "errores", "vista_previa", "sonido", "numero"):
            viejo, nuevo = getattr(antes, campo), getattr(self, campo)
            if viejo != nuevo:
                partes.append(f"{campo} {_legible(viejo)} → {_legible(nuevo)}")
        if len(antes.silenciados) != len(self.silenciados) or set(antes.silenciados) != set(self.silenciados):
            partes.append(f"silenciados {len(antes.silenciados)} → {len(self.silenciados)}")
        return ", ".join(partes) if partes else "sin cambios"


def _legible(valor: object) -> str:
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    return str(valor)
