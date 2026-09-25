"""La configuración del vigía: un INI (``despliegue/vigia.ini.ejemplo`` la explica línea a línea).

Los secretos no van aquí: el INI solo dice **dónde** están (ficheros 0600 del usuario del vigía), y así se puede leer,
copiar o pegar en un informe sin enseñar nada.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..comun import direccion, leer_ini


@dataclass(frozen=True)
class ConfigVigia:
    escucha: tuple = ("127.0.0.1", 8790)
    base_de_datos: str = "/var/lib/hehermes-vigia/vigia.db"
    intervalo: float = 5.0
    intervalo_en_calma: float = 25.0
    antiguedad_maxima: float = 900.0
    filas_por_lectura: int = 100
    max_dispositivos: int = 20
    caducidad_aprobacion: int = 120
    caducidad_prueba: int = 300
    registro: str = "INFO"
    # El secreto que pone nginx en cada petición de /avisos/ (`X-HeHermes-Vigia`): sin él no se atiende nada.
    secreto_tunel: str = "/etc/hehermes-avisos/vigia/secreto-tunel"
    # Directo a Hermes, con su propia copia de la clave (la escribe `hehermes-dispositivo clave`): así el vigía no
    # depende del nginx del túnel, que pone el Bearer a cualquier conexión local, y cerrar eso es una línea de nginx.
    hermes_base: str = "http://127.0.0.1:8642"
    hermes_clave: str | None = "/etc/hehermes-avisos/vigia/clave-hermes"
    hermes_plazo: float = 15.0
    rele_url: str = "http://127.0.0.1:8791/v1/avisos"
    rele_credencial: str = "/etc/hehermes-avisos/vigia/credencial-rele"
    rele_plazo: float = 8.0
    # Los ficheros que Hermes marca con `MEDIA:`: el socket del lector de root (`hehermes-leer-media.socket`), la casa
    # de Hermes (lo que vale `~`) y cuántas descargas se aceptan por minuto y a la vez.
    ficheros_lector: str = "/run/hehermes-leer-media.sock"
    ficheros_casa: str = "/root"
    ficheros_por_minuto: int = 30
    ficheros_simultaneos: int = 2

    @classmethod
    def leer(cls, ruta: str) -> ConfigVigia:
        ini = leer_ini(ruta)
        base = cls()

        def texto(seccion: str, clave: str, defecto):
            return ini.get(seccion, clave, fallback=defecto) if ini.has_section(seccion) else defecto

        def numero(seccion: str, clave: str, defecto: float) -> float:
            return float(texto(seccion, clave, defecto))

        clave_hermes = (texto("hermes", "clave", base.hermes_clave) or "").strip() or None
        return cls(
            escucha=direccion(texto("vigia", "escucha", "%s:%d" % base.escucha)),
            base_de_datos=texto("vigia", "base_de_datos", base.base_de_datos),
            intervalo=max(1.0, numero("vigia", "intervalo", base.intervalo)),
            intervalo_en_calma=max(1.0, numero("vigia", "intervalo_en_calma", base.intervalo_en_calma)),
            antiguedad_maxima=numero("vigia", "antiguedad_maxima", base.antiguedad_maxima),
            filas_por_lectura=max(10, min(500, int(numero("vigia", "filas_por_lectura", base.filas_por_lectura)))),
            max_dispositivos=max(1, int(numero("vigia", "max_dispositivos", base.max_dispositivos))),
            caducidad_aprobacion=int(numero("vigia", "caducidad_aprobacion", base.caducidad_aprobacion)),
            caducidad_prueba=int(numero("vigia", "caducidad_prueba", base.caducidad_prueba)),
            registro=texto("vigia", "registro", base.registro),
            secreto_tunel=texto("vigia", "secreto_tunel", base.secreto_tunel).strip(),
            hermes_base=texto("hermes", "base", base.hermes_base),
            hermes_clave=clave_hermes,
            hermes_plazo=numero("hermes", "plazo", base.hermes_plazo),
            rele_url=texto("rele", "url", base.rele_url),
            rele_credencial=texto("rele", "credencial", base.rele_credencial),
            rele_plazo=numero("rele", "plazo", base.rele_plazo),
            ficheros_lector=texto("ficheros", "lector", base.ficheros_lector).strip(),
            ficheros_casa=texto("ficheros", "casa", base.ficheros_casa).strip(),
            ficheros_por_minuto=max(1, int(numero("ficheros", "por_minuto", base.ficheros_por_minuto))),
            ficheros_simultaneos=max(1, int(numero("ficheros", "simultaneos", base.ficheros_simultaneos))),
        )
