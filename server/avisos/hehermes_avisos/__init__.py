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
# 1.5.3: una compactación ya no repite el aviso de la última respuesta (contrato §7). Hermes vuelve a escribir la cola
#        con ids nuevos y sus horas de siempre, y el vigía la tomaba por nueva si era de hace menos de 15 minutos. Ahora
#        recuerda la hora de la última respuesta vista de cada conversación (base de datos 4) y no avisa de una que no
#        sea posterior.
# 1.5.4: aprobar y denegar desde el aviso (spec 2026-10-04). El aviso de una aprobación con `request_id` lleva dentro del
#        sobre lo que la app necesita para contestarla sin abrirse (`aprobacion`: el run, la petición y las opciones de
#        Hermes) y la petición entera, con sus líneas, para leerla al mantener pulsado el aviso. Solo con la vista previa
#        en «Siempre» y si cabe entera en el push (`avisos.TOPE_CLARO`); si no, el aviso de siempre.
# 1.5.5: actualizar el servidor con un toque, y su estado en Ajustes (spec 2026-10-04, contrato §17). El vigía atiende
#        /avisos/v1/servidor (las versiones, si Hermes contesta, el espacio libre, los servicios, la última copia y la
#        actualización en curso, sin secretos) y /avisos/v1/servidor/actualizar, que se lo pasa al ayudante
#        `hehermes-actualizar` (despliegue/): de root por conexión, sin capacidades ni red, que lanza la actualización en
#        su propia unidad tras mirar la forma, el cerrojo y el tope; la descarga sale solo de la URL del paquete
#        instalado y se comprueban la suma de la app y la firma de Daniel. El ayudante del respaldo dice cuándo hizo la
#        última instantánea (`ultima`). [servidor] en vigia.ini.
# 1.6.0: los agentes (spec 2026-10-05, contrato §18): varios perfiles de Hermes por una sola conexión. El vigía lee cada
#        perfil con su prefijo /p/<perfil>/ y su clave ([agentes] claves), guarda lo visto por perfil (base de datos 5) y
#        avisa con el perfil (en el sobre, el hilo y el colapso); atiende /avisos/v1/agentes/… y se lo pasa al ayudante
#        `hehermes-agentes` (despliegue/): de root por conexión, sin capacidades, que crea (con `hermes profile create
#        --clone`, su clave y su personalidad), cambia y borra (con una copia antes) los perfiles, y cada minuto junta lo
#        que saben de ti los que lo comparten, con el flock de Hermes. Un Hermes que ya sirve otros perfiles sirve los
#        nuevos en caliente, y el ayudante se lo pide por su socket de control (`rescan-profiles`); con el primer agente
#        (aún no los sirve: lo decide al arrancar), pone `gateway.multiplex_profiles: true` y reinicia su unidad una vez,
#        con drenaje y en un rato tranquilo (el trabajo dice su `paso`). La lista no lanza `hermes`: lee `profiles/` y
#        mira cada agente con su clave, a la vez. La personalidad la escribe el principal. El lector y la entrada atienden
#        lo de cada perfil (`?exports <perfil>`, `perfil=`).
# 1.6.1: «Detener» de la app (contrato §6, punto 10): la entrega de un subagente que el usuario detuvo llega igual, con
#        lo que hizo hasta pararse, y ni se contesta ni se avisa (`deteccion.delegaciones_detenidas`). El `hermes` del
#        ayudante de los agentes manda lo de internet a un puerto cerrado de localhost: su jaula tira esos paquetes y
#        crear un agente esperaba 2 minutos. `instalar.sh` fija su umask (pip dejaba lo nuevo sin leer para el relé).
#        `hehermes-actualizar` comprueba la firma también sin la orden openssl, y si no puede, `sin_openssl`. Las
#        dependencias del relé, sin fallos conocidos (anyio, h2 y hpack).
# 1.6.2: el modelo de cada agente (contrato §18.11): el ayudante lo pone al crear y al cambiar, solo uno de los que
#        ofrece el principal, con `hermes config set|unset` y devolviendo el `config.yaml` como estaba si algo falla; el
#        vigía lo deja pasar y lo dice en la lista. Cada alta de avisos sabe de qué iPhone es (esquema 6): la pasarela
#        se lo dice con su nombre y una marca de su token, firmados con el secreto que comparten (contrato §12.10), y al
#        quitar un iPhone desde la app se barren sus altas (`/avisos/v1/iphones/barrer`, firmado). Y el aviso del código
#        de recuperación (§12.9): un buzón que deja el instalador, y el aviso a los demás iPhone, nunca al que entra; no
#        se barre mientras quede uno por mandar.
VERSION = "1.6.2"
