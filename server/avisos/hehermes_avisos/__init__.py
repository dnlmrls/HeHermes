"""Los avisos push de HeHermes Mensajes, del lado del servidor.

Dos servicios que no se conocen más que por HTTP:

- ``vigia``: vive al lado del Hermes de cada usuario, lo lee como la app, decide qué avisar, lo cifra con la clave de
  cada iPhone y se lo pasa al relé. Lo único que le escribe a Hermes es el turno que contesta la entrega de un subagente
  cuando la app no está para lanzarlo (``vigia.entregas``).
- ``rele``: uno para todos, el único con la clave .p8 de APNs. Recibe sobres ya cifrados y se los manda a Apple.

``comun``, ``cifrado`` y ``texto`` son lo poco que comparten. El relé solo usa ``comun``: el día que se mude a su propia
máquina se lleva este paquete entero y arranca solo su mitad.
"""

# 1.1.0: el vigía contesta las entregas de los subagentes (`vigia.entregas`).
# 1.1.1: el registro dice qué ajustes cambian en cada alta y en cada `PUT …/ajustes`.
# 1.1.2: el registro dice por qué no sale un aviso (un tipo apagado, un chat silenciado, la app delante) y avisa de un
#        iPhone con los cuatro tipos apagados.
# 1.2.0: el relé para los probadores. El relé tiene una entrada pública (`rele.publico`: TLS 1.3 con la huella anclada,
#        la maquinaria de la pasarela) y credenciales que se dan y se quitan en caliente (`hehermes-rele credencial
#        alta|baja|lista`, con su «código de avisos»); el vigía habla con un relé de otra máquina por HTTPS anclado.
# 1.3.0: avisos sin comandos. Permisos por dispositivo avalados con App Attest: la oficina de permisos en la entrada
#        pública del relé (`rele.permisos`, `rele.appattest`, `rele.cbor`), el relé acepta `Authorization: Permiso`, y
#        el vigía sin credencial manda los avisos con el permiso que le da la app en el alta.
VERSION = "1.3.0"
