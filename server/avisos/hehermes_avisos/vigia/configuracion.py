"""La configuración del vigía: un INI (``despliegue/vigia.ini.ejemplo`` la explica línea a línea).

Los secretos no van aquí: el INI solo dice **dónde** están (ficheros 0600 del usuario del vigía), y así se puede leer,
copiar o pegar en un informe sin enseñar nada.
"""

from __future__ import annotations

import re

from dataclasses import dataclass

from ..comun import direccion, leer_ini
from .entregas import ReglasDeEntrega
from .servidor import unidad_valida

#: Las unidades de HeHermes cuyo estado enseña Ajustes › Tu servidor si `vigia.ini` no dice otras: las de un servidor
#: con los avisos de `despliegue/instalar.sh` (el VPS de Daniel, con su relé), cuyo `vigia.ini` puede ser de antes de la
#: 1.5.5. El instalador escribe las suyas.
SERVICIOS_DE_SERIE = ("hehermes-pasarela.service", "hehermes-vigia.service", "hehermes-rele.service",
                      "hehermes-leer-media.socket", "hehermes-respaldo.socket", "hehermes-entrada.socket",
                      "hehermes-actualizar.socket", "hehermes-agentes.socket", "hehermes-agentes-memoria.timer")


def _si_o_no(valor: str, nombre: str) -> bool:
    """«sí»/«no», y lo que entiende configparser (yes, true, on, 1…). Lo demás es un error, no un «no» callado."""
    limpio = valor.strip().lower()
    if limpio in ("sí", "si", "yes", "true", "on", "1"):
        return True
    if limpio in ("no", "false", "off", "0"):
        return False
    raise ValueError(f"{nombre} tiene que ser «sí» o «no», no {valor!r}")


def _comprobar_rele(url: str, huella: str | None) -> None:
    """La credencial del vigía va en cada petición al relé: o por HTTPS con la huella anclada, o en claro solo dentro de
    la propia máquina. Lo demás no arranca."""
    import ipaddress
    import re
    import urllib.parse
    partes = urllib.parse.urlsplit(url)
    if partes.scheme == "https":
        if not huella or not re.fullmatch(r"[A-Za-z0-9_-]{43}", huella):
            raise ValueError("[rele] url es https: hace falta [rele] huella, la del código de avisos (43 caracteres)")
        if not partes.hostname or not partes.port:
            raise ValueError("[rele] url tiene que llevar la dirección y el puerto del relé")
        return
    if partes.scheme == "http":
        try:
            local = ipaddress.ip_address(partes.hostname or "").is_loopback
        except ValueError:
            local = False
        if not local:
            raise ValueError("[rele] url en claro (http) solo a 127.0.0.1: la credencial viaja en cada aviso. Para el "
                             "relé de otra máquina, https y su huella")
        return
    raise ValueError("[rele] url tiene que ser http://127.0.0.1:… o https://…")


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
    # Vacía (o sin poner en el INI): **sin credencial**, el «modo permisos» (spec 2026-09-28, «Avisos sin comandos»).
    # Cada aviso va a la entrada pública del relé con el permiso que trae la app en el alta de cada iPhone, y a la
    # dirección y con la huella que trae con él; la credencial ni se busca.
    rele_url: str = "http://127.0.0.1:8791/v1/avisos"
    rele_credencial: str = "/etc/hehermes-avisos/vigia/credencial-rele"
    rele_plazo: float = 8.0
    # El relé de otra máquina (la entrada pública del de Daniel): `https://…` y la huella de su certificado, que se
    # ancla. Sin huella no se habla HTTPS con nadie, y en claro solo con 127.0.0.1: la credencial va en cada petición.
    rele_huella: str | None = None
    #: La huella del certificado que el relé pondrá cuando rote el suyo (la da su `GET /hehermes/v1/huellas`): con ella,
    #: la rotación no deja a este vigía fuera. Opcional.
    rele_huella_siguiente: str | None = None
    # Los ficheros que Hermes marca con `MEDIA:`: el socket del lector de root (`hehermes-leer-media.socket`), la casa
    # de Hermes (lo que vale `~`) y cuántas descargas se aceptan por minuto y a la vez.
    ficheros_lector: str = "/run/hehermes-leer-media.sock"
    ficheros_casa: str = "/root"
    ficheros_por_minuto: int = 30
    ficheros_simultaneos: int = 2
    # La copia de Hermes en iCloud: el socket del ayudante (`hehermes-respaldo.socket`). Vacío: sin copia (503).
    respaldo_ayudante: str = "/run/hehermes-respaldo.sock"
    # Lo que la app le manda a Hermes (`/avisos/v1/entrada/…`, desde la 1.5.2): el socket del ayudante
    # (`hehermes-entrada.socket`; vacío, 503), lo más grande que se acepta, lo que tiene que quedar libre en el disco
    # después de guardarlo (los dos en MiB: el ayudante los recorta a 16 GiB y a 256 MiB) y los días que se guarda cada
    # carpeta del día de `<HERMES_HOME>/entrada`. Sin la sección (un `vigia.ini` de antes), estos.
    entrada_ayudante: str = "/run/hehermes-entrada.sock"
    entrada_tope_mb: int = 2048
    entrada_margen_mb: int = 1024
    entrada_dias: int = 30
    # Ajustes › Tu servidor (`/avisos/v1/servidor`, desde la 1.5.5): la carpeta del instalador (su versión), el socket
    # del ayudante que actualiza (`hehermes-actualizar.socket`; vacío, 503), las unidades de HeHermes cuyo estado se
    # enseña (con «usuario:» delante, una de `systemctl --user`) y la de Hermes (vacía, si no tiene: tmux, contenedor…).
    servidor_instalador: str = "/opt/hehermes-servidor"
    servidor_ayudante: str = "/run/hehermes-actualizar.sock"
    servidor_servicios: tuple = SERVICIOS_DE_SERIE
    servidor_hermes: str | None = "hermes-gateway.service"
    # Las entregas de los subagentes que el vigía contesta con el turno de continuación de la app (`entregas`).
    entregas_contestar: bool = True
    entregas_gracia: float = 60.0
    entregas_antiguedad_maxima: float = 10800.0
    entregas_cadena_maxima: int = 3
    # Los ficheros nuevos de `exports/` (`exportaciones.py`, desde la 1.5.1): si se vigila la carpeta (por el lector),
    # cuántos segundos tiene que quedarse igual un fichero para avisar de él, y desde qué edad ya no se avisa.
    exportaciones_vigilar: bool = True
    exportaciones_estabilidad: float = 5.0
    exportaciones_antiguedad_maxima: float = 3600.0
    # Los agentes (contrato §18, desde la 1.6.0): la carpeta de sus claves (una por perfil, `<perfil>.clave`, de root y
    # del grupo del vigía, 0640), los que se vigilan; y el socket de su ayudante (`hehermes-agentes.socket`; vacío, las
    # rutas de /avisos/v1/agentes contestan 503). Sin la sección (un `vigia.ini` de antes), estos.
    agentes_claves: str = "/etc/hehermes-avisos/agentes"
    agentes_ayudante: str = "/run/hehermes-agentes.sock"

    @classmethod
    def leer(cls, ruta: str) -> ConfigVigia:
        ini = leer_ini(ruta)
        base = cls()

        def texto(seccion: str, clave: str, defecto):
            return ini.get(seccion, clave, fallback=defecto) if ini.has_section(seccion) else defecto

        def numero(seccion: str, clave: str, defecto: float) -> float:
            return float(texto(seccion, clave, defecto))

        clave_hermes = (texto("hermes", "clave", base.hermes_clave) or "").strip() or None
        contestar = _si_o_no(texto("entregas", "contestar", "sí"), "[entregas] contestar")
        vigilar_exportaciones = _si_o_no(texto("exportaciones", "vigilar", "sí"), "[exportaciones] vigilar")
        # Sin `url`, sin credencial: lo escribe así el instalador cuando no hay código de avisos. Con ella, las reglas de
        # siempre (https con huella, o en claro solo a 127.0.0.1).
        rele_url = (texto("rele", "url", "") or "").strip()
        rele_huella = (texto("rele", "huella", "") or "").strip() or None
        rele_huella_siguiente = (texto("rele", "huella_siguiente", "") or "").strip() or None
        if rele_url:
            _comprobar_rele(rele_url, rele_huella)
            if rele_huella_siguiente is not None and not re.fullmatch(r"[A-Za-z0-9_-]{43}", rele_huella_siguiente):
                raise ValueError("[rele] huella_siguiente tiene que ser una huella (43 caracteres), o no estar")
        else:
            rele_huella = rele_huella_siguiente = None
        servicios = texto("servidor", "servicios", None)
        servicios = base.servidor_servicios if servicios is None else tuple(servicios.split())
        servidor_hermes = (texto("servidor", "hermes", base.servidor_hermes) or "").strip() or None
        for unidad in servicios + ((servidor_hermes,) if servidor_hermes else ()):
            unidad_valida(unidad)
        instalador = (texto("servidor", "instalador", base.servidor_instalador) or "").strip()
        if not instalador.startswith("/"):
            raise ValueError("[servidor] instalador tiene que ser una carpeta absoluta")
        agentes_claves = (texto("agentes", "claves", base.agentes_claves) or "").strip()
        if agentes_claves and not agentes_claves.startswith("/"):
            raise ValueError("[agentes] claves tiene que ser una carpeta absoluta")
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
            rele_url=rele_url,
            rele_credencial=texto("rele", "credencial", base.rele_credencial),
            rele_plazo=numero("rele", "plazo", base.rele_plazo),
            rele_huella=rele_huella,
            rele_huella_siguiente=rele_huella_siguiente,
            ficheros_lector=texto("ficheros", "lector", base.ficheros_lector).strip(),
            ficheros_casa=texto("ficheros", "casa", base.ficheros_casa).strip(),
            ficheros_por_minuto=max(1, int(numero("ficheros", "por_minuto", base.ficheros_por_minuto))),
            ficheros_simultaneos=max(1, int(numero("ficheros", "simultaneos", base.ficheros_simultaneos))),
            respaldo_ayudante=texto("respaldo", "ayudante", base.respaldo_ayudante).strip(),
            entrada_ayudante=texto("entrada", "ayudante", base.entrada_ayudante).strip(),
            entrada_tope_mb=max(1, int(numero("entrada", "tope_mb", base.entrada_tope_mb))),
            entrada_margen_mb=max(0, int(numero("entrada", "margen_mb", base.entrada_margen_mb))),
            entrada_dias=max(1, min(3650, int(numero("entrada", "dias", base.entrada_dias)))),
            servidor_instalador=instalador,
            servidor_ayudante=texto("servidor", "ayudante", base.servidor_ayudante).strip(),
            servidor_servicios=servicios,
            servidor_hermes=servidor_hermes,
            entregas_contestar=contestar,
            # Menos de 30 s no deja a la app, si está delante, lanzar la suya con las instrucciones de la conversación.
            entregas_gracia=max(30.0, numero("entregas", "gracia", base.entregas_gracia)),
            entregas_antiguedad_maxima=numero("entregas", "antiguedad_maxima", base.entregas_antiguedad_maxima),
            entregas_cadena_maxima=max(1, int(numero("entregas", "cadena_maxima", base.entregas_cadena_maxima))),
            exportaciones_vigilar=vigilar_exportaciones,
            # Menos de 2 s avisaría de lo que aún se está copiando entre dos miradas del lector (cada 2 s).
            exportaciones_estabilidad=max(2.0, numero("exportaciones", "estabilidad", base.exportaciones_estabilidad)),
            exportaciones_antiguedad_maxima=numero("exportaciones", "antiguedad_maxima",
                                                   base.exportaciones_antiguedad_maxima),
            agentes_claves=agentes_claves,
            agentes_ayudante=texto("agentes", "ayudante", base.agentes_ayudante).strip(),
        )

    @property
    def entrada_tope(self) -> int:
        return self.entrada_tope_mb * 1024 * 1024

    @property
    def entrada_margen(self) -> int:
        return self.entrada_margen_mb * 1024 * 1024

    @property
    def con_credencial(self) -> bool:
        """Si este vigía habla con el relé con su credencial (`[rele] url` puesta) o con el permiso de cada iPhone."""
        return bool(self.rele_url)

    def reglas_de_entrega(self) -> ReglasDeEntrega | None:
        """Las reglas con las que el vigía contesta las entregas, o ``None`` si no las contesta."""
        if not self.entregas_contestar:
            return None
        return ReglasDeEntrega(gracia=self.entregas_gracia, antiguedad_maxima=self.entregas_antiguedad_maxima,
                               cadena_maxima=self.entregas_cadena_maxima)
