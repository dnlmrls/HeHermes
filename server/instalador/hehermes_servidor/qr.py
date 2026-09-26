"""Un codificador QR (ISO/IEC 18004), solo lo que hace falta aquí: modo byte, niveles L, M, Q y H, versiones 1 a 40.

Sin root no se instalan paquetes, y `qrencode` no viene de serie en Debian ni en Ubuntu; el QR del alta, sin embargo,
se tiene que poder pintar. Es la construcción de siempre (la de qrcodegen, de Nayuki, que es la más clara): los datos
en bytes, Reed-Solomon por bloques, entrelazado, los patrones fijos, la máscara con menos penalización y la
información de formato y de versión. Las pruebas (`tests/test_qr.py`) lo comparan módulo a módulo con `segno`.
"""

from __future__ import annotations

#: Los módulos de margen alrededor (la norma pide 4).
MARGEN = 4
_NIVELES = {"L": 1, "M": 0, "Q": 3, "H": 2}  # sus bits de formato
_INDICE = {"L": 0, "M": 1, "Q": 2, "H": 3}

_ECC_POR_BLOQUE = (
    (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28,
     28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30))
_BLOQUES = (
    (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18,
     19, 19, 20, 21, 22, 24, 25),
    (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31,
     33, 35, 37, 38, 40, 43, 45, 47, 49),
    (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40,
     43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48,
     51, 54, 57, 60, 63, 66, 70, 74, 77, 81))


def _modulos_de_datos(version):
    total = (16 * version + 128) * version + 64
    if version >= 2:
        alineaciones = version // 7 + 2
        total -= (25 * alineaciones - 10) * alineaciones - 55
        if version >= 7:
            total -= 36
    return total


def _palabras_de_datos(version, nivel):
    i = _INDICE[nivel]
    return _modulos_de_datos(version) // 8 - _ECC_POR_BLOQUE[i][version] * _BLOQUES[i][version]


def _bits_de_largo(version):
    return 8 if version <= 9 else 16


def capacidad(version, nivel="M") -> int:
    """Los bytes que caben en esa versión y ese nivel, en modo byte."""
    return (_palabras_de_datos(version, nivel) * 8 - 4 - _bits_de_largo(version)) // 8


def version_para(largo, nivel="M") -> int:
    for version in range(1, 41):
        if largo <= capacidad(version, nivel):
            return version
    raise ValueError("demasiado largo para un QR: %d bytes" % largo)


# MARK: Reed-Solomon en GF(256), con el polinomio 0x11D


def _por(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _divisor(grado):
    resultado = [0] * (grado - 1) + [1]
    raiz = 1
    for _ in range(grado):
        for j in range(grado):
            resultado[j] = _por(resultado[j], raiz)
            if j + 1 < grado:
                resultado[j] ^= resultado[j + 1]
        raiz = _por(raiz, 0x02)
    return resultado


def _resto(datos, divisor):
    resultado = [0] * len(divisor)
    for b in datos:
        factor = b ^ resultado.pop(0)
        resultado.append(0)
        for i, coeficiente in enumerate(divisor):
            resultado[i] ^= _por(coeficiente, factor)
    return resultado


# MARK: Las palabras


def _palabras(datos: bytes, version, nivel):
    bits = []

    def poner(valor, cuantos):
        bits.extend((valor >> i) & 1 for i in reversed(range(cuantos)))

    poner(0b0100, 4)
    poner(len(datos), _bits_de_largo(version))
    for b in datos:
        poner(b, 8)
    capacidad_bits = _palabras_de_datos(version, nivel) * 8
    poner(0, min(4, capacidad_bits - len(bits)))
    poner(0, -len(bits) % 8)
    relleno = 0xEC
    while len(bits) < capacidad_bits:
        poner(relleno, 8)
        relleno ^= 0xEC ^ 0x11
    palabras = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    # Los bloques, con su corrección, y entrelazados.
    i = _INDICE[nivel]
    bloques, por_bloque = _BLOQUES[i][version], _ECC_POR_BLOQUE[i][version]
    brutas = _modulos_de_datos(version) // 8
    cortos = bloques - brutas % bloques
    largo_corto = brutas // bloques
    divisor = _divisor(por_bloque)
    trozos, k = [], 0
    for b in range(bloques):
        dat = palabras[k:k + largo_corto - por_bloque + (0 if b < cortos else 1)]
        k += len(dat)
        ecc = _resto(dat, divisor)
        if b < cortos:
            dat = dat + [0]
        trozos.append(dat + ecc)
    salida = []
    for j in range(len(trozos[0])):
        for b, trozo in enumerate(trozos):
            if j != largo_corto - por_bloque or b >= cortos:
                salida.append(trozo[j])
    return salida


# MARK: La matriz


class _Matriz:
    def __init__(self, version):
        self.version = version
        self.n = version * 4 + 17
        self.m = [[False] * self.n for _ in range(self.n)]
        self.fija = [[False] * self.n for _ in range(self.n)]

    def fijar(self, x, y, oscuro):
        self.m[y][x] = oscuro
        self.fija[y][x] = True

    def patrones(self):
        n = self.n
        for i in range(n):
            self.fijar(6, i, i % 2 == 0)
            self.fijar(i, 6, i % 2 == 0)
        for x, y in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    if 0 <= x + dx < n and 0 <= y + dy < n:
                        self.fijar(x + dx, y + dy, max(abs(dx), abs(dy)) not in (2, 4))
        posiciones = self._alineaciones()
        ultima = len(posiciones) - 1
        for i, a in enumerate(posiciones):
            for j, b in enumerate(posiciones):
                if (i, j) in ((0, 0), (0, ultima), (ultima, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.fijar(a + dx, b + dy, max(abs(dx), abs(dy)) != 1)
        self.formato(0, "M")  # sitio reservado; se escribe de verdad con la máscara
        self._version()

    def _alineaciones(self):
        if self.version == 1:
            return []
        cuantas = self.version // 7 + 2
        paso = (self.version * 8 + cuantas * 3 + 5) // (cuantas * 4 - 4) * 2
        return [6] + list(reversed([self.n - 7 - i * paso for i in range(cuantas - 1)]))

    def formato(self, mascara, nivel):
        datos = _NIVELES[nivel] << 3 | mascara
        resto = datos
        for _ in range(10):
            resto = (resto << 1) ^ ((resto >> 9) * 0x537)
        bits = (datos << 10 | resto) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 != 0  # noqa: E731
        n = self.n
        for i in range(6):
            self.fijar(8, i, bit(i))
        self.fijar(8, 7, bit(6))
        self.fijar(8, 8, bit(7))
        self.fijar(7, 8, bit(8))
        for i in range(9, 15):
            self.fijar(14 - i, 8, bit(i))
        for i in range(8):
            self.fijar(n - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.fijar(8, n - 15 + i, bit(i))
        self.fijar(8, n - 8, True)

    def _version(self):
        if self.version < 7:
            return
        resto = self.version
        for _ in range(12):
            resto = (resto << 1) ^ ((resto >> 11) * 0x1F25)
        bits = self.version << 12 | resto
        for i in range(18):
            oscuro = (bits >> i) & 1 != 0
            a, b = self.n - 11 + i % 3, i // 3
            self.fijar(a, b, oscuro)
            self.fijar(b, a, oscuro)

    def datos(self, palabras):
        i, n, total = 0, self.n, len(palabras) * 8
        derecha = n - 1
        while derecha >= 1:
            if derecha == 6:
                derecha = 5
            for vertical in range(n):
                for j in range(2):
                    x = derecha - j
                    arriba = ((derecha + 1) & 2) == 0
                    y = n - 1 - vertical if arriba else vertical
                    if not self.fija[y][x] and i < total:
                        self.m[y][x] = (palabras[i >> 3] >> (7 - (i & 7))) & 1 != 0
                        i += 1
            derecha -= 2

    def enmascarar(self, mascara):
        for y in range(self.n):
            for x in range(self.n):
                if not self.fija[y][x] and _MASCARAS[mascara](x, y):
                    self.m[y][x] = not self.m[y][x]


_MASCARAS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


def _penalizacion(m) -> int:
    """Las cuatro reglas de la norma: rachas de cinco o más, cuadros de 2×2, lo que se parece a un localizador y el
    equilibrio entre oscuros y claros. Con ella se elige la máscara; cualquiera de las ocho da un QR válido."""
    n = len(m)
    total = 0
    columnas = [[m[y][x] for y in range(n)] for x in range(n)]
    parecido = ([True, False, True, True, True, False, True, False, False, False, False],
                [False, False, False, False, True, False, True, True, True, False, True])
    for linea in list(m) + columnas:
        racha, anterior = 0, None
        for v in linea:
            if v == anterior:
                racha += 1
            else:
                if racha >= 5:
                    total += 3 + racha - 5
                racha, anterior = 1, v
        if racha >= 5:
            total += 3 + racha - 5
        for i in range(n - 10):
            if linea[i:i + 11] in parecido:
                total += 40
    for y in range(n - 1):
        for x in range(n - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                total += 3
    oscuros = sum(map(sum, m))
    total += abs(oscuros * 20 - n * n * 10) // (n * n) * 10
    return total


def matriz(texto, nivel="M", mascara=None, version=None) -> list:
    """La matriz del QR de `texto` (UTF-8, en modo byte): filas de booleanos, True es oscuro, sin margen."""
    datos = texto.encode("utf-8") if isinstance(texto, str) else bytes(texto)
    version = version or version_para(len(datos), nivel)
    if len(datos) > capacidad(version, nivel):
        raise ValueError("no cabe en la versión %d" % version)
    palabras = _palabras(datos, version, nivel)
    mejores = []
    for m in ([mascara] if mascara is not None else range(8)):
        q = _Matriz(version)
        q.patrones()
        q.datos(palabras)
        q.enmascarar(m)
        q.formato(m, nivel)
        mejores.append((_penalizacion(q.m) if mascara is None else 0, m, q.m))
    return min(mejores, key=lambda t: (t[0], t[1]))[2]


def terminal(texto, nivel="M") -> str:
    """El QR para un terminal: medios bloques, dos filas por línea, negro sobre blanco forzado con ANSI (en un
    terminal de fondo oscuro, sin forzarlo, saldría en negativo), con su margen."""
    m = matriz(texto, nivel)
    n = len(m) + 2 * MARGEN
    claro = [False] * n
    filas = [claro] * MARGEN + [[False] * MARGEN + fila + [False] * MARGEN for fila in m] + [claro] * MARGEN
    if len(filas) % 2:
        filas.append(claro)
    lineas = []
    for y in range(0, len(filas), 2):
        arriba, abajo = filas[y], filas[y + 1]
        lineas.append("\033[30;47m" + "".join("█" if a and b else "▀" if a else "▄" if b else " "
                                             for a, b in zip(arriba, abajo)) + "\033[0m")
    return "\n".join(lineas) + "\n"
