"""La configuración del relé: un INI (``despliegue/rele.ini.ejemplo`` la explica línea a línea).

Como en el vigía, los secretos no van aquí: la ruta a la clave .p8 (0600, del usuario del relé) y la ruta a
``credenciales.ini``, donde solo hay huellas.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..comun import direccion, leer_ini
from .apns import BASES

TEMA = "com.danielmorales.HeHermesMensajes"
EQUIPO = "8X7L8YHD9M"
RESERVA = ("Hermes", "Tienes una respuesta nueva")


@dataclass(frozen=True)
class ConfigRele:
    escucha: tuple = ("127.0.0.1", 8791)
    tema: str = TEMA
    equipo: str = EQUIPO
    clave_id: str = ""
    clave_p8: str = "/etc/hehermes-avisos/rele/AuthKey.p8"
    credenciales: str = "/etc/hehermes-avisos/rele/credenciales.ini"
    renovar_jwt: float = 45 * 60.0
    # Todo lo que puede tardar un aviso en Apple, con su reintento: menos que lo que espera el vigía (8 s).
    plazo_apns: float = 6.0
    registro: str = "INFO"
    # Los textos de reserva que se aceptan en `aps.alert`, como pares (título, cuerpo).
    reservas: list = field(default_factory=lambda: [RESERVA])
    bases: dict = field(default_factory=lambda: dict(BASES))
    por_credencial: int = 60
    por_token: int = 10
    recordar_bajas: float = 3600.0

    @classmethod
    def leer(cls, ruta: str) -> ConfigRele:
        ini = leer_ini(ruta)
        base = cls()

        def texto(seccion: str, clave: str, defecto):
            return ini.get(seccion, clave, fallback=defecto) if ini.has_section(seccion) else defecto

        reservas = []
        for linea in str(texto("rele", "reserva", "|".join(RESERVA))).splitlines():
            titulo, separador, cuerpo = linea.strip().partition("|")
            if separador and titulo.strip() and cuerpo.strip():
                reservas.append((titulo.strip(), cuerpo.strip()))
        renovar = float(texto("rele", "renovar_jwt", base.renovar_jwt))
        if not 20 * 60 <= renovar < 60 * 60:
            raise ValueError("renovar_jwt tiene que estar entre 1200 y 3599 segundos: Apple rechaza un token de más de "
                             "una hora y castiga renovarlo más de una vez cada veinte minutos")
        return cls(
            escucha=direccion(texto("rele", "escucha", "%s:%d" % base.escucha)),
            tema=texto("rele", "tema", base.tema).strip(),
            equipo=texto("rele", "equipo", base.equipo).strip(),
            clave_id=texto("rele", "clave_id", base.clave_id).strip(),
            clave_p8=texto("rele", "clave_p8", base.clave_p8).strip(),
            credenciales=texto("rele", "credenciales", base.credenciales).strip(),
            renovar_jwt=renovar,
            plazo_apns=float(texto("rele", "plazo_apns", base.plazo_apns)),
            registro=texto("rele", "registro", base.registro),
            reservas=reservas or [RESERVA],
            bases={"sandbox": texto("apns", "sandbox", BASES["sandbox"]).rstrip("/"),
                   "production": texto("apns", "production", BASES["production"]).rstrip("/")},
            por_credencial=int(texto("limites", "por_credencial", base.por_credencial)),
            por_token=int(texto("limites", "por_token", base.por_token)),
            recordar_bajas=float(texto("limites", "recordar_bajas", base.recordar_bajas)),
        )
