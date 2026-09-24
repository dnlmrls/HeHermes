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

    def silenciada(self, sesion: str | None) -> bool:
        return bool(sesion) and sesion in self.silenciados
