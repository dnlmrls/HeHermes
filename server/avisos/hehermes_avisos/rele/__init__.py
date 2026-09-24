"""El relé: uno para todos los usuarios, y el único que tiene la clave .p8 de APNs.

Recibe de cada vigía avisos **ya cifrados** (``POST /v1/avisos``), comprueba que traen solo el sobre y el texto de
reserva, los limita por credencial y por token, y se los manda a Apple por HTTP/2 al entorno que toque. Devuelve lo que
diga Apple de forma que el vigía sepa si tiene que dar de baja el token.

No guarda nada de nadie: los límites y los tokens que Apple dio por muertos viven en memoria y se olvidan solos.

- ``validacion``: qué acepta, y por qué no deja pasar nada que no sea el sobre.
- ``firmante``: el JWT de APNs (ES256), cacheado y renovado antes de la hora.
- ``apns``: el cliente HTTP/2.
- ``limites``: cubos por credencial y por token.
- ``credenciales``: las de cada vigía, guardadas como huella.
- ``api``: la API y lo que contesta.
"""
