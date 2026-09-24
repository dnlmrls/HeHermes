"""Los avisos push de HeHermes Mensajes, del lado del servidor.

Dos servicios que no se conocen más que por HTTP:

- ``vigia``: vive al lado del Hermes de cada usuario, lo lee como la app (sin tocarlo), decide qué avisar, lo cifra con
  la clave de cada iPhone y se lo pasa al relé.
- ``rele``: uno para todos, el único con la clave .p8 de APNs. Recibe sobres ya cifrados y se los manda a Apple.

``comun``, ``cifrado`` y ``texto`` son lo poco que comparten. El relé solo usa ``comun``: el día que se mude a su propia
máquina se lleva este paquete entero y arranca solo su mitad.
"""

VERSION = "1.0.0"
