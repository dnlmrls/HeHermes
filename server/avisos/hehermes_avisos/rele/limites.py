"""Los límites del relé, para que un vigía roto no inunde a nadie.

- **Por credencial**: lo que puede mandar un vigía entero. Protege al relé y a la cuenta de Apple de Daniel de un bucle
  que se vuelva loco en un servidor.
- **Por token**: lo que puede recibir un iPhone. Protege a la persona, que es a quien le suena el teléfono.

Son cubos que se rellenan poco a poco (``N`` por minuto, con ráfagas de hasta ``N``), en memoria. Tampoco se guarda
aquí ningún token: los cubos van por la huella del token con su entorno.

Y los tokens que Apple ha dado por muertos se recuerdan un rato: si un vigía no hace caso de la baja, el relé le
contesta lo mismo sin volver a preguntar a Apple, que no quiere que le insistan con tokens que ya no valen.
"""

from __future__ import annotations

import hashlib
import threading
import time


def huella_de_token(token: str, entorno: str) -> str:
    return hashlib.sha256(f"{entorno}:{token}".encode("ascii")).hexdigest()


class _Cubo:
    __slots__ = ("capacidad", "ritmo", "fichas", "cuando")

    def __init__(self, por_minuto: int, ahora: float):
        self.capacidad = float(por_minuto)
        self.ritmo = por_minuto / 60.0
        self.fichas = float(por_minuto)
        self.cuando = ahora

    def rellenar(self, ahora: float) -> None:
        self.fichas = min(self.capacidad, self.fichas + (ahora - self.cuando) * self.ritmo)
        self.cuando = ahora

    def espera(self) -> float:
        """Lo que falta para tener una ficha, en segundos (0 si ya la hay)."""
        return 0.0 if self.fichas >= 1 else (1 - self.fichas) / self.ritmo


class Limitador:
    def __init__(self, por_credencial: int = 60, por_token: int = 10, recordar_bajas: float = 3600.0,
                 reloj=time.monotonic):
        self.por_credencial = por_credencial
        self.por_token = por_token
        self.recordar_bajas = recordar_bajas
        self.reloj = reloj
        self._cerrojo = threading.Lock()
        self._credenciales: dict = {}
        self._tokens: dict = {}
        self._bajas: dict = {}
        self._desde_la_limpieza = 0

    def admitir(self, credencial: str, token: str, por_minuto: int | None = None) -> float | None:
        """``None`` si el aviso puede salir (y lo cuenta), o los segundos que hay que esperar si no.

        Se miran los dos cubos antes de gastar de ninguno: un aviso que no sale no puede gastar el cupo de su credencial
        porque el de su token estaba vacío.
        """
        with self._cerrojo:
            ahora = self.reloj()
            self._limpiar(ahora)
            cubo_credencial = self._cubo(self._credenciales, credencial, por_minuto or self.por_credencial, ahora)
            cubo_token = self._cubo(self._tokens, token, self.por_token, ahora)
            espera = max(cubo_credencial.espera(), cubo_token.espera())
            if espera > 0:
                return espera
            cubo_credencial.fichas -= 1
            cubo_token.fichas -= 1
            return None

    def dar_de_baja(self, token: str) -> None:
        with self._cerrojo:
            self._bajas[token] = self.reloj() + self.recordar_bajas

    def de_baja(self, token: str) -> bool:
        with self._cerrojo:
            hasta = self._bajas.get(token)
            if hasta is None:
                return False
            if self.reloj() >= hasta:
                del self._bajas[token]
                return False
            return True

    @staticmethod
    def _cubo(cubos: dict, clave: str, por_minuto: int, ahora: float) -> _Cubo:
        cubo = cubos.get(clave)
        if cubo is None or cubo.capacidad != por_minuto:
            cubo = cubos[clave] = _Cubo(por_minuto, ahora)
        cubo.rellenar(ahora)
        return cubo

    def _limpiar(self, ahora: float) -> None:
        # De vez en cuando, fuera los cubos llenos (nadie los está usando) y las bajas vencidas: así la memoria no crece
        # con cada iPhone que pasa por el relé.
        self._desde_la_limpieza += 1
        if self._desde_la_limpieza < 1000:
            return
        self._desde_la_limpieza = 0
        for cubos in (self._credenciales, self._tokens):
            for clave in [c for c, cubo in cubos.items() if cubo.fichas + (ahora - cubo.cuando) * cubo.ritmo
                          >= cubo.capacidad]:
                del cubos[clave]
        for clave in [c for c, hasta in self._bajas.items() if ahora >= hasta]:
            del self._bajas[clave]
