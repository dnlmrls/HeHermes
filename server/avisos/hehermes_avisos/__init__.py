"""Los avisos push de HeHermes, del lado del servidor.

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
# 1.4.0: la auditoría del 2026-09-29. El lector de ficheros lee de una lista de permitidas (las caches de Hermes y su
#        exports/), sin ninguna capacidad, y el vigía contesta con el mismo 404 todo lo que no deja leer (pide 50 filas
#        y 500 solo si hace falta, y recuerda una marca 2 minutos). Las credenciales de systemd en 0440 valen dentro de
#        $CREDENTIALS_DIRECTORY, y un secreto mal puesto sale con 78 y no en bucle. La entrada pública del relé tiene
#        un certificado siguiente y `rotar`, y el vigía ancla varias huellas ([rele] huella_siguiente).
# 1.5.0: la copia de Hermes en iCloud (spec 2026-09-29, contrato §15). El vigía atiende /avisos/v1/respaldo/… y se lo
#        pasa al ayudante `hehermes-respaldo` (despliegue/), que corre como el dueño de Hermes: instantáneas troceadas
#        con las bases limpias de lo borrado, y restaurar con `hermes import`, la copia de antes y el deshacer. Cuerpos
#        de hasta 4 MiB + 64 KiB en esas rutas; `comprobar` mira también el ayudante.
# 1.5.1: la conversación que Hermes compacta en el sitio (contrato §7). Las marcas de un fichero se buscan en la
#        conversación entera, con lo compactado (`include_compacted=true`) y hacia atrás de 500 en 500 hasta 5000 filas,
#        recordando todo lo marcado que se ve; lo que nombra el resumen oculto no marca. Un iPhone que se va a mitad de una
#        petición deja una línea en el registro y no una traza. Y los ficheros nuevos de exports/ (contrato §11.1): el
#        vigía vigila la carpeta por el lector (`?exports`), avisa «Nuevo fichero listo» con su conversación y la app los
#        pide en GET /avisos/v1/ficheros; lo de exports/ se descarga sin marca.
# 1.5.2: mandarle un fichero a Hermes (spec 2026-10-04, contrato §16). El vigía atiende /avisos/v1/entrada/… y se lo pasa
#        al ayudante `hehermes-entrada` (despliegue/), que corre como el dueño de Hermes sin ninguna capacidad y solo ve
#        <HERMES_HOME>/entrada: trozos de 4 MiB con su SHA-256, el fichero entero comprobado y colocado con `link` en la
#        carpeta del día, con un nombre limpio, y la limpieza cada hora ([entrada] en vigia.ini). La copia en iCloud deja
#        fuera esa carpeta.
VERSION = "1.5.2"
