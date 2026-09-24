"""El vigía: vive al lado del Hermes de un usuario y le avisa al iPhone de lo que pasa con la app cerrada.

- ``api``: lo que la app le pide por el túnel (``/avisos/v1/…``): alta, ajustes, primer plano, prueba y baja.
- ``hermes``: lee el api_server como la app, sin tocarlo (Hermes está congelado a propósito).
- ``deteccion``: de las filas del historial, qué hay que avisar. Funciones puras.
- ``avisos``: a quién se avisa y con qué sobre. Funciones puras.
- ``vigilante``: el bucle que junta todo cada pocos segundos.
- ``almacen``: SQLite, para no avisar dos veces tras un reinicio ni de todo el historial la primera vez.
"""
