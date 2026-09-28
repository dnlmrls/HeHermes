"""Un lector de CBOR (RFC 8949) pequeño y estricto, solo para lo que manda App Attest.

Una atestación es ``{fmt, attStmt: {x5c: [bytes, bytes], receipt: bytes}, authData: bytes}`` y una aserción,
``{signature: bytes, authenticatorData: bytes}``: mapas, listas, cadenas de bytes y de texto, y enteros. Nada más.

Por qué uno propio y no una dependencia: lo que se lee viene de internet sin autenticar (la entrada pública del relé),
así que el lector tiene que ser pequeño, sin nada que no haga falta (ni etiquetas, ni números de coma flotante, ni
largos indefinidos, que son donde suelen estar los fallos de los lectores grandes) y con topes que no dependan de lo que
diga el propio mensaje: profundidad, número de elementos y que todo quepa en los bytes que quedan **antes** de reservar
nada. Son unas cien líneas que se prueban enteras (``tests/test_cbor.py``); una biblioteca serían miles más en el
proceso que da a internet, y otra actualización de seguridad que vigilar en el VPS.
"""

from __future__ import annotations

#: Lo más hondo que se anida: una atestación llega a 3 (mapa → mapa → lista).
PROFUNDIDAD_MAXIMA = 8
#: Elementos (contando los de dentro) de un mensaje: una atestación tiene menos de 20.
ELEMENTOS_MAXIMOS = 256


class ErrorCBOR(ValueError):
    """El mensaje no es el CBOR que se espera. El texto no lleva nada del mensaje."""


class _Lector:
    __slots__ = ("datos", "pos", "elementos")

    def __init__(self, datos: bytes):
        self.datos = datos
        self.pos = 0
        self.elementos = 0

    def _tomar(self, n: int) -> bytes:
        if n < 0 or n > len(self.datos) - self.pos:
            raise ErrorCBOR("el CBOR se corta antes de tiempo")
        trozo = self.datos[self.pos:self.pos + n]
        self.pos += n
        return trozo

    def _argumento(self, info: int) -> int:
        if info < 24:
            return info
        if info == 24:
            return self._tomar(1)[0]
        if info == 25:
            return int.from_bytes(self._tomar(2), "big")
        if info == 26:
            return int.from_bytes(self._tomar(4), "big")
        if info == 27:
            return int.from_bytes(self._tomar(8), "big")
        # 28–30 no existen; 31 es un largo indefinido, que aquí no se acepta.
        raise ErrorCBOR("largo indefinido o reservado")

    def leer(self, profundidad: int = 0):
        if profundidad > PROFUNDIDAD_MAXIMA:
            raise ErrorCBOR("demasiado anidado")
        self.elementos += 1
        if self.elementos > ELEMENTOS_MAXIMOS:
            raise ErrorCBOR("demasiados elementos")
        inicial = self._tomar(1)[0]
        tipo, info = inicial >> 5, inicial & 0x1F
        if tipo == 7:
            # Solo false, true y null; ni undefined, ni simples, ni números de coma flotante.
            valores = {20: False, 21: True, 22: None}
            if info not in valores:
                raise ErrorCBOR("valor simple no admitido")
            return valores[info]
        if tipo == 6:
            raise ErrorCBOR("etiquetas no admitidas")
        argumento = self._argumento(info)
        if tipo == 0:
            return argumento
        if tipo == 1:
            return -1 - argumento
        if tipo == 2:
            return self._tomar(argumento)
        if tipo == 3:
            try:
                return self._tomar(argumento).decode("utf-8")
            except UnicodeDecodeError:
                raise ErrorCBOR("texto que no es UTF-8") from None
        # Una lista o un mapa no pueden tener más elementos que bytes quedan: se mira antes de reservar nada.
        quedan = len(self.datos) - self.pos
        if tipo == 4:
            if argumento > quedan:
                raise ErrorCBOR("la lista dice tener más elementos de los que caben")
            return [self.leer(profundidad + 1) for _ in range(argumento)]
        # tipo == 5, un mapa: claves de texto o enteras, sin repetir.
        if argumento * 2 > quedan:
            raise ErrorCBOR("el mapa dice tener más elementos de los que caben")
        mapa = {}
        for _ in range(argumento):
            clave = self.leer(profundidad + 1)
            if not isinstance(clave, (str, int)) or isinstance(clave, bool):
                raise ErrorCBOR("clave de mapa que no es texto ni un entero")
            if clave in mapa:
                raise ErrorCBOR("clave de mapa repetida")
            mapa[clave] = self.leer(profundidad + 1)
        return mapa


def leer(datos: bytes):
    """El valor de ``datos``, que tiene que ser **un** elemento CBOR entero, sin nada detrás."""
    if not isinstance(datos, (bytes, bytearray)):
        raise ErrorCBOR("no son bytes")
    lector = _Lector(bytes(datos))
    valor = lector.leer()
    if lector.pos != len(lector.datos):
        raise ErrorCBOR("sobran bytes detrás del CBOR")
    return valor
