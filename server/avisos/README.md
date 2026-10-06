# Avisos push: el vigía y el relé

Lo del servidor de los avisos de HeHermes (spec: `docs/superpowers/specs/2026-09-23-avisos-push-design.md`).
La app y su extensión ya están hechas; esto es lo que les falta para avisar con la app cerrada.

El vigía sirve además, de solo lectura, los ficheros que Hermes marca con `MEDIA:` (`GET /avisos/v1/fichero`): el
contrato está en `server/API-CONTRACT.md` §11, y cómo se lee sin darle al vigía nada de root, en
[«El lector de ficheros»](#el-lector-de-ficheros-de-hermes).

```
iPhone ──pasarela TLS──▶ vigía 127.0.0.1:8790 ──▶ relé 127.0.0.1:8791 ──HTTP/2──▶ APNs ──▶ iPhone
         (o, antes, el nginx del túnel)  └── lee a Hermes 127.0.0.1:8642 (sin tocarlo)

Otro servidor (un probador):
iPhone ──su pasarela──▶ su vigía ──HTTPS anclado──▶ entrada pública del relé (TCP alto) ──▶ relé 127.0.0.1:8791
```

Desde la 1.3.0, sin credencial: con **permisos por dispositivo avalados con App Attest**
([abajo](#los-permisos-por-dispositivo-app-attest-construido-130)). Desde la 1.2.0, el relé de Daniel atiende también a
los vigías de otros servidores, por su **entrada pública**
([abajo](#la-entrada-pública-del-relé-los-vigías-de-otros-servidores); spec
`docs/superpowers/specs/2026-09-28-rele-para-probadores-design.md`). El vigía de un probador lo pone el instalador
(`hehermes-servidor avisos`, 0.7.0).

| Pieza | Qué hace | Qué guarda |
|---|---|---|
| **Vigía** (`hehermes_avisos.vigia`, usuario `hh-vigia`) | Atiende a la app (`/avisos/v1/…`), y solo lo que llega por el túnel: nginx deja pasar a `/avisos/` solo las direcciones de los iPhone y les pone un secreto sin el que el vigía no atiende. Cada 5 s lee la bandeja de Hermes (directo, con su copia de la clave) y, de las conversaciones que han cambiado, sus últimas filas; decide qué avisar, lo cifra con la clave de cada iPhone y se lo pasa al relé. | SQLite en `/var/lib/hehermes-vigia/`: dispositivos (token, entorno, clave, ajustes, primer plano) y hasta qué fila ha leído de cada conversación. Nada de texto. |
| **Relé** (`hehermes_avisos.rele`, usuario `hh-rele`) | El único con la clave .p8. Comprueba que lo que le llega es solo el sobre cifrado y el texto de reserva, lo limita y se lo manda a Apple al entorno que toque. Devuelve lo que dice Apple (`baja: true` si el token ha muerto). | Nada en disco. En memoria, los cubos de los límites y los tokens que Apple dio por muertos, por huella. |

Lo que ven el relé y Apple de un aviso: el token, el entorno, la prioridad, la caducidad, un hilo y un colapso que no
dicen de qué conversación son (abajo), si es una aprobación (`interruption-level: time-sensitive`, que es lo que la deja
atravesar un modo de concentración) y un sobre ChaCha20-Poly1305 que solo abre ese iPhone. El texto de reserva es
siempre «Hermes» / «Tienes una respuesta nueva», y el relé rechaza cualquier otro. El relé no recibe ni la sesión ni el
tipo del aviso.

### El hilo y el colapso (contrato con la app)

Los dos salen de una subclave de la clave del iPhone (`K`, los 32 bytes con los que se cifra su sobre), para no usar
la misma clave en el ChaCha20-Poly1305 del sobre y en un HMAC:

- `K_ids` = HKDF-SHA256 (RFC 5869) con `ikm` = `K`, la sal **vacía** (0 bytes), `info` = `"hehermes-avisos ids v1"`
  en UTF-8 y 32 bytes de salida. (La sal vacía y la de 32 ceros que pone la RFC cuando no hay sal dan lo mismo.)
- `aps.thread-id` = `HMAC-SHA256(K_ids, "hilo:" + sesión)`. Es lo que la app calcula para reagrupar un aviso que no
  pudo descifrar y abrir su conversación. La prueba no lleva hilo.
- `apns-collapse-id` = `HMAC-SHA256(K_ids, "colapso:" + sesión + "\n" + suceso)`, con `suceso` =
  `respuesta:<id de la fila>`, `segundo-plano:<id de la fila>`, `entrega:<id de la fila>`, `aprobacion` (todas las de una
  conversación colapsan entre sí), `error:<run_id>` o `prueba` (y la sesión vacía).

Los HMAC van sobre el texto en UTF-8, y de cada uno se usan los **32 primeros caracteres del hexadecimal en
minúsculas**.

Vector de referencia, con `K` = `00 01 02 … 1f` y la sesión `api_1790000000_abcd1234`:

| | |
|---|---|
| `K_ids` | `42d45f089104b627485827d130b660cfe956bc8ded4135f6aca83ffdd86c051a` |
| hilo | `74350adac3a212cd739e0a5858f28188` |
| colapso de `respuesta:42716` | `50b9c30fdf04a56a01bf496393a20ca1` |
| colapso de la prueba | `fa1bf3329ebbcdbd7ece9a0f699f420f` |

(`tests/test_avisos.py` y `tests/test_cifrado.py`, que también comprueba el HKDF contra el caso 3 de la RFC 5869, el de
la sal vacía.)

## Instalar (en el VPS, con sudo)

Con `server/` del repo copiado al VPS (a donde sea: el instalador busca el código junto a él), en este orden:

1. El `hehermes-dispositivo` nuevo, que sabe escribir la copia de la clave de Hermes del vigía (el instalador se para si
   el instalado es de antes): `sudo install -m 0750 server/vpn/hehermes-dispositivo /usr/local/sbin/`
2. nginx: dentro del `server { … }` de `/etc/nginx/sites-available/hehermes-tunel`, justo antes de `location / {`, la
   línea `include /etc/nginx/hehermes-avisos/sitio/*.conf;` (como en `server/vpn/hehermes-tunel.nginx`). Con el
   comodín no rompe nada aunque los avisos aún no estén instalados, así que puede ir antes; el instalador lo prueba y
   recarga nginx.
3. `sudo server/avisos/despliegue/instalar.sh`: usuarios, dependencias (solo ruedas, comprobadas por hash, y antes de
   cambiar el código), código, configuración, credencial del vigía ante el relé, secreto entre nginx y el vigía, la
   clave de Hermes del vigía (con `hehermes-dispositivo clave --solo-vigia`, que no toca nginx), el fragmento de nginx y
   las unidades de systemd (dos sockets, que tienen los puertos, y dos servicios), además del lector y de los ayudantes
   de la copia, de la entrada, el que actualiza y el de los agentes (con su temporizador y las carpetas de sus claves),
   con sus sockets. Deja los dos en marcha: el relé, sin su clave, contesta 503 a los avisos.
4. La clave de APNs (developer.apple.com › Certificates, IDs & Profiles › Keys, con «Apple Push Notifications service»):
   `sudo install -m 0600 -o hh-rele -g hh-rele AuthKey_XXXXXXXXXX.p8 /etc/hehermes-avisos/rele/AuthKey.p8`, y su Key ID
   en `/etc/hehermes-avisos/rele.ini` (`clave_id = …`). El Team ID (`8X7L8YHD9M`) y el tema ya están.
5. El instalador otra vez: reinicia el relé, ya con su clave.

Es idempotente: se puede repetir tras cada cambio de código, y nunca pisa la configuración, las credenciales, el secreto
ni la clave. En nginx, lo suyo vive en `/etc/nginx/hehermes-avisos/`: `sitio/` lo que va en el `server {}` del túnel
(la `location /avisos/`) y `secreto/` lo que va dentro de esa location. Los dos se incluyen con comodín, así que si
falta algo nginx sigue arrancando y nada queda abierto (sin el secreto, el vigía contesta 403). Todo lo que cambia ahí
el instalador se prueba con `nginx -t`, incluido o no, y si no vale vuelve a como estaba; nginx solo se recarga si algo
suyo cambió. El fragmento no lleva el Bearer de Hermes, solo deja pasar las direcciones del túnel, pone el secreto del
vigía y no apunta las rutas en el registro (llevan el token entero).

**Los puertos son de systemd.** `hehermes-vigia.socket` y `hehermes-rele.socket` atan 127.0.0.1:8790 y 8791 y los
servicios heredan el socket al arrancar (`LISTEN_FDS`): con un servicio parado o reiniciándose, ningún otro proceso de
la máquina puede escuchar ahí y quedarse con lo que llega (el secreto del túnel y las claves de las altas, la
credencial del vigía). Por eso un servicio que no puede arrancar no sale enseguida: con el socket de systemd, contesta
503 a todo durante un minuto y luego sale para que systemd lo vuelva a intentar (si saliera al momento, cada conexión
en espera lo arrancaría otra vez y, a los cinco fallos seguidos, systemd soltaría el socket). El relé sin clave de APNs
no es un fallo: se queda en marcha contestando 503 hasta que se le reinicie con ella. Sin socket heredado (las
pruebas, o arrancado a mano) cada servicio abre su puerto como siempre.

El instalador acaba con `comprobar` de los dos servicios (configuración, permisos de los secretos, el propio vigía por
su puerto, Hermes y el relé, sin mandar nada). Se puede repetir a mano, siempre con `-I` (así no se importa nada del directorio actual):

```bash
sudo -u hh-vigia /opt/hehermes-avisos/venv/bin/python -I -m hehermes_avisos.vigia comprobar
sudo -u hh-rele  /opt/hehermes-avisos/venv/bin/python -I -m hehermes_avisos.rele comprobar
```

## La entrada pública del relé (los vigías de otros servidores)

El relé sigue en `127.0.0.1:8791`. Delante, en un TCP alto elegido una vez al azar (58000–65500), va su entrada
pública (`hehermes_avisos.rele.publico`), que es **la pasarela** (`hehermes_servidor.pasarela`, la del instalador,
copiada por `instalar.sh` junto a este paquete) con las credenciales de los vigías en lugar de los tokens de los iPhone:
TLS 1.3 con un certificado propio cuya huella ancla el vigía, el 404 idéntico y con retraso a lo que no trae una
credencial válida, el bloqueo por IP tras 10 fallos, 16 conexiones por IP y 128 en total, 10 s para las cabeceras,
16 KiB de cuerpo, y un registro sin credenciales, rutas ni cuerpos. Lo que pasa va al relé **con la misma credencial**:
el relé la vuelve a comprobar, la limita (por credencial y por token) y apunta su nombre. El contrato está en
`server/API-CONTRACT.md` §13.

```bash
sudo server/avisos/despliegue/instalar.sh --rele-publico      # la primera vez: puerto, certificado, ufw
sudo hehermes-rele credencial alta <nombre>                   # su código de avisos, solo en un terminal
sudo hehermes-rele credencial alta <nombre> --a-fichero /root/hehermes-codigos/<nombre>.txt   # o a un fichero 0600
sudo hehermes-rele credencial lista                            # nombres y fechas, sin huellas
sudo hehermes-rele credencial baja <nombre>                   # deja de valer al momento
sudo server/avisos/despliegue/instalar.sh --quitar-rele-publico   # la para y cierra su puerto
```

- **El código de avisos** (`hehermes-avisos:1?h=…&p=…&f=…&c=…`) lleva la dirección, el puerto, la huella y la
  credencial: es secreto. `alta` lo saca una vez; del secreto, el relé solo guarda su SHA-256. En el otro servidor:
  `sudo hehermes-servidor avisos`, y se pega (sin eco).
- **En caliente**: el relé y su entrada vuelven a leer `credenciales.ini` en cuanto cambia (`credenciales.Almacen`), y
  la entrada corta en un segundo las conexiones de una credencial dada de baja. Un fichero roto no deja pasar a nadie.
- **Quién es quién**: la entrada corre como `hh-rele-publico` (en el grupo `hh-rele`, para leer `credenciales.ini`), sin
  poder leer la `.p8` (`hh-rele 0600`, y además `InaccessiblePaths`). La clave de su certificado le llega por
  `LoadCredential`.
- **Qué deja**: `/etc/hehermes-avisos/rele-publico.ini` (puerto y dirección, `root:hh-rele-publico 0640`),
  `/etc/hehermes-avisos/rele-publico/{cert.pem,clave.pem}`, `hehermes-rele-publico.service`, `/usr/local/sbin/hehermes-rele`
  y la regla de ufw (`comment hehermes-rele`). Quitarla (`--quitar-rele-publico`) deja el puerto y el certificado:
  volver a ponerla no invalida ningún código.
- `sudo /opt/hehermes-avisos/venv/bin/python -I -B -m hehermes_avisos.rele.publico comprobar` se asoma como cualquiera:
  TLS 1.3, la huella de los códigos y el 404.
- **El vigía de otro servidor** tiene en su `vigia.ini` `[rele] url = https://<h>:<p>/v1/avisos` y `huella = <f>`. Sin
  huella no habla HTTPS con nadie, y en claro solo con `127.0.0.1`: la credencial va en cada aviso. La huella se mira al
  acabar el apretón TLS, antes de mandar nada. Su `comprobar` no se asoma sin credencial (contaría como un fallo de su
  IP): solo `GET /v1/credencial`, anclado. Desde la 1.4.0 puede llevar también `huella_siguiente` (vale cualquiera de
  las dos, comparadas en tiempo constante).
- **Rotar el certificado** (desde la 1.4.0): `preparar` deja hecho el siguiente (`rele-publico/siguiente/`, su clave
  sin usar) y su huella se da a quien trae una credencial o un permiso en `GET /hehermes/v1/huellas`. Cuando los vigías
  (su `huella_siguiente`) y la app (que hoy lleva una sola huella horneada: contrato §12.7) la anclen:
  `sudo /opt/hehermes-avisos/venv/bin/python -I -B -m hehermes_avisos.rele.publico rotar` y
  `sudo systemctl restart hehermes-rele-publico`. El de antes queda en `rele-publico/anterior/`: volver atrás es
  copiarlo encima y reiniciar.
- **Un secreto mal puesto falla una vez.** La clave de la oficina de permisos llega por `LoadCredential` en 0440, y
  `leer_secreto` lo acepta solo dentro de `$CREDENTIALS_DIRECTORY` (fuera, 0600 u 0400). Si algo de la configuración o
  de un secreto no sirve, sale con 78 y un mensaje con el remedio, y la unidad no la reinicia
  (`RestartPreventExitStatus=78`; y a los 5 arranques en 2 minutos, `StartLimitBurst`): el 28-sep, con el 0440, se
  reinició 15 veces.
- **Límites y CGNAT** (desde la 1.4.0, los de la pasarela 0.9.0): el cupo por IP es de conexiones sin credencial; una IP
  bloqueada por sus fallos deja pasar lo que trae una credencial o un permiso buenos, y cierra al momento lo demás.

## El lector de ficheros de Hermes

`GET /avisos/v1/fichero?sesion=&ruta=` (contrato: `server/API-CONTRACT.md` §11) le trae a la app un fichero que Hermes
marcó con una línea `MEDIA:<ruta>`. Hermes corre como root y deja sus ficheros donde quiere, y `hh-vigia` no los puede
leer, así que el reparto es este:

- **El vigía decide si se puede pedir.** Lee las 50 últimas filas de la sesión (y las 500 solo si esas vuelven llenas
  y sin la marca; desde la 1.5.1, de la conversación entera con lo que Hermes compactó, `include_compacted`, y después
  hacia atrás de 500 en 500 hasta 5000) y exige una fila `assistant` no oculta con una línea que, con las reglas de la
  app (`ExtraccionMedia.swift`), dé esa ruta exacta. Si no la hay, 404, sin mirar el disco. Toda marca que ve se
  recuerda 2 minutos, y una conversación recorrida hacia atrás no se vuelve a recorrer en ese rato. Además limita: 30
  por minuto, contando también las que no estaban marcadas, y 2 a la vez. Desde la 1.4.0, lo que el lector no deja
  leer es **el mismo 404** que lo que no está marcado, salvo, desde la 1.5.0, lo marcado **fuera de las carpetas
  permitidas** (el lector lo dice por el texto, `fuera`): un 409 `fichero_fuera_de_la_carpeta` con `"carpeta":
  "exports"`, para que la app ofrezca pedirle a Hermes que lo copie ahí. Desde la 1.5.1, lo de **dentro de `exports/`**
  (por el texto limpio de la ruta) se da **sin buscar su marca**: es la carpeta de Hermes para el iPhone, y un
  subagente deja ahí sus ficheros horas antes de escribir su línea `MEDIA:`. Lo de cualquier otro sitio, las caches
  incluidas, sigue necesitando la marca.
- **El lector decide qué se puede leer.** Es `/usr/local/libexec/hehermes-leer-media` (`despliegue/`), Python sin
  dependencias:
  - desde la 1.4.0, **solo lee de una lista de permitidas**: `image_cache/`, `audio_cache/` y `exports/` de la carpeta
    de Hermes (la última la crea `instalar.sh`, 0700, del dueño de Hermes: ahí tiene que dejar Hermes lo que quiera
    mandar al iPhone). Lo pedido y lo resuelto tienen que estar en la misma permitida; la lista de prohibidas de antes
    sigue como segunda red. Si el entorno de `hermes-gateway` dice otro `HERMES_HOME`, `instalar.sh` deja un añadido a
    la unidad (`hehermes-leer-media@.service.d/hermes-home.conf`) con `--hermes-home=` y sus carpetas visibles (y
    `User=` si Hermes no es root), y lo quita si vuelve a `/root/.hermes`;
  - baja desde `/` carpeta a carpeta con `O_NOFOLLOW`, así que un enlace colado a mitad de camino hace fallar la
    apertura;
  - comprueba con `fstat` del descriptor abierto que es el mismo inodo, un fichero normal, con un solo enlace duro y de
    no más de 50 MB;
  - y lo manda por partes.
- **Cómo se llega al lector: un socket de systemd, no sudo.** `hehermes-leer-media.socket` (`/run/hehermes-leer-media.sock`,
  `root:hh-vigia 0660`, `Accept=yes`) lanza un `hehermes-leer-media@.service` por cada conexión, con su propia jaula:
  - como el dueño de la casa de Hermes (root en el VPS) y, desde la 1.4.0, **sin ninguna capacidad**;
  - todo de solo lectura, sin red y con su propio `/tmp`;
  - las casas tapadas (`ProtectHome=tmpfs`) salvo las carpetas permitidas (`BindReadOnlyPaths`), y los secretos del
    sistema tapados también (`InaccessiblePaths`): aunque el código fallara, dentro no se ven.

  Solo atiende a root o a `hh-vigia` (`SO_PEERCRED`).

  Con sudo habría que quitarle al vigía `NoNewPrivileges` (con él, sudo no puede subir de privilegios) y `ProtectHome`
  (su hijo vería un `/root` vacío). Sería darle una puerta a root al proceso que atiende al túnel, y encima con una
  regla de sudoers con comodín, porque la ruta va en los argumentos.

**El protocolo por el socket:**

- el vigía manda una línea `<ruta>\n`;
- el lector contesta `ok <tamaño>\n` y los bytes, o `<estado>\n`;
- el estado es uno de `invalida`, `no_existe`, `prohibida`, `no_es_fichero`, `demasiado_grande`, `carrera`, `error` o
  `no_autorizado`;
- cada uno tiene su código de salida (`SALIDAS`, en el lector).

Y desde la 1.5.1, **la vigilancia de `exports/`**: a la línea `?exports` el lector contesta `{"carpeta": …}` y, cada
2 s durante 10 minutos, `{"ficheros": [{"nombre", "tamano", "mtime", "ctime"}, …]}` de los ficheros normales de esa
carpeta (sin subcarpetas, ocultos ni temporales, con un solo enlace duro; ni un byte de dentro). El vigía la mantiene
abierta (`vigia/exportaciones.py`) y, de cada fichero nuevo que lleva 5 s igual, busca su conversación (su nombre en las
últimas filas de las de la bandeja y de sus subagentes) y avisa «Nuevo fichero listo: <nombre>» (`segundo-plano`). La
app lo enseña en su conversación con `GET /avisos/v1/ficheros?sesion=` (contrato §11.1). Ocupa una de las 4 conexiones
del socket (`MaxConnections`): quedan 3 para las 2 descargas a la vez. `[exportaciones] vigilar = no` lo apaga.

**Para root, a mano:** `sudo /usr/local/libexec/hehermes-leer-media <ruta>`, con los bytes por la salida estándar. Lo
que se aplica así es solo el código del lector, sin la jaula de systemd.

**En el VPS:**

- `sudo -u hh-vigia …vigia comprobar` dice si el lector contesta: le pide `/`, que tiene que dar su rechazo
  (`prohibida`; uno de antes de la 1.4.0, `no_es_fichero`).
- Lo que pasa, en `journalctl -u 'hehermes-leer-media@*' -u hehermes-vigia`: solo el estado, el tamaño y la
  extensión, nunca la ruta ni el contenido.
- `sudo server/avisos/despliegue/instalar.sh --desinstalar-lector` lo quita, y la ruta pasa a contestar 503.

## La copia de Hermes en iCloud (desde la 1.5.0)

Spec `docs/superpowers/specs/2026-09-29-respaldo-de-hermes-en-icloud-design.md`, contrato `server/API-CONTRACT.md` §15.
La app cifra y guarda en iCloud; aquí solo se hace la instantánea, se sirven sus trozos y se restaura.

- **El vigía** atiende `/avisos/v1/respaldo/…` (`vigia/respaldo.py`): comprueba la forma de lo que llega, deja cuatro
  trozos a la vez y pide una limpieza cada hora. Todo lo demás lo hace el ayudante.
- **El ayudante** es `/usr/local/libexec/hehermes-respaldo` (`despliegue/`), Python sin dependencias, de root, lanzado
  por `hehermes-respaldo.socket` (`/run/hehermes-respaldo.sock`, `root:hh-vigia 0660`, `Accept=yes`) en un
  `hehermes-respaldo@.service` por conexión, con su jaula. **No acepta rutas**: órdenes fijas, ids y números. Qué entra
  en una copia lo dice su código (`clase_de`). Su carpeta de trabajo es `/var/lib/hehermes-respaldo` (0700, root): las
  instantáneas (24 h), las restauraciones y la copia de antes de restaurar (7 días).
- **Restaurar** monta y comprueba todo antes de parar `hermes-gateway`; guarda lo que había; `hermes import --force`
  como el dueño de Hermes; deja las `API_SERVER_*` de este servidor; arranca, espera a `/health` y a
  `/api/sessions` y cuenta. Si algo falla, deshace solo. «Deshacer» (7 días) pone lo de antes tal cual.
- **Si Hermes no vive en `/root/.hermes`** o no es de root, `instalar.sh` deja un añadido
  (`hehermes-respaldo@.service.d/hermes.conf`) con `--hermes-home=` y `--usuario-hermes=`.
- **Quitarlo:** `sudo …/instalar.sh --desinstalar-respaldo` (no con una operación en marcha). La carpeta de trabajo se
  queda.

**Para root, a mano:** `sudo /usr/bin/python3 -I -S /usr/local/libexec/hehermes-respaldo estado` (lo que ve el
ayudante, sin secretos) y `… limpiar`. Lo que pasa, en `journalctl -u 'hehermes-respaldo@*'`: ids, fases, tamaños y
resultados; nunca una ruta ni un contenido. La copia deja fuera `entrada/` (abajo): son copias de lo que ya está en el
iPhone, y se borran solas.

## Lo que la app le manda a Hermes (desde la 1.5.2)

Spec `docs/superpowers/specs/2026-10-04-ficheros-sin-limite-design.md`, contrato `server/API-CONTRACT.md` §16. Lo que no
es texto que quepa en el mensaje, la app lo sube en trozos de 4 MiB, y Hermes recibe en el mismo mensaje la ruta donde
ha quedado: `<HERMES_HOME>/entrada/<AAAA-MM-DD>/<nombre>`.

- **El vigía** atiende `/avisos/v1/entrada/…` (`vigia/entrada.py`): comprueba la forma de lo que llega (ids, números,
  el nombre, el SHA-256 de cada trozo en `X-HeHermes-SHA256`), deja cuatro trozos a la vez, le pasa al ayudante los
  topes de `[entrada]` en `vigia.ini` y le pide la limpieza cada hora. Cuerpos de hasta 4 MiB + 64 KiB, como en la copia.
- **El ayudante** es `/usr/local/libexec/hehermes-entrada` (`despliegue/`), Python sin dependencias, lanzado por
  `hehermes-entrada.socket` (`/run/hehermes-entrada.sock`, `root:hh-vigia 0660`, `Accept=yes`) en un
  `hehermes-entrada@.service` por conexión, **como el dueño de la casa de Hermes y sin ninguna capacidad**: la jaula del
  lector, pero lo único de las casas que ve es `<HERMES_HOME>/entrada`, de lectura y escritura, y `LimitFSIZE=16G`.
  **No acepta rutas**: el nombre del disco lo decide él (`nombre_seguro`: letras, cifras y `. - _ + , @`, nada al
  principio que lo esconda o lo haga una opción, 180 bytes como mucho, `-2`, `-3`… si se repite ese día); los ids son
  suyos. Baja con descriptores y sin seguir enlaces, comprueba cada trozo y el fichero entero, y coloca lo acabado con
  `link` (no pisa nada), 0600.
- **Sus topes, que el vigía no puede saltarse**: 16 GiB por fichero como mucho (el de `vigia.ini`, 2048 MiB, si es
  menor), al menos 256 MiB libres después de guardarlo (1024 MiB de serie), contando lo que les falta a las demás
  subidas a medias; ocho a medias y sesenta nuevas por hora.
- **La limpieza**, cada hora: lo que lleva 24 horas sin un trozo nuevo, el registro de lo colocado hace más de 24 horas
  (el fichero se queda) y, enteras, las carpetas de los días de hace más de `[entrada] dias` (30). `entrada/` es una
  bandeja de entrada: lo que Hermes quiera conservar, que lo copie a otro sitio.
- **La carpeta** la crea `instalar.sh` (0700, del dueño de Hermes), como `exports/`. Si Hermes no vive en `/root/.hermes`
  o no es de root, deja un añadido (`hehermes-entrada@.service.d/hermes.conf`) con `--hermes-home=`, la carpeta que ve y
  su usuario. Sin la carpeta, la ruta contesta 503 (`entrada_no_disponible`).
- **Quitarlo:** `sudo …/instalar.sh --desinstalar-entrada` (no mientras termina una subida). La carpeta se queda: lo de
  dentro es de Hermes.

**Para root, a mano:** `sudo /usr/bin/python3 -I -S /usr/local/libexec/hehermes-entrada estado` (el disco libre, las
subidas a medias y la carpeta) y `… --dias=30 limpiar`. Lo que pasa, en `journalctl -u 'hehermes-entrada@*'`: el
principio del id, los tamaños, los números de trozo y el resultado; nunca el nombre, la ruta ni nada de dentro.

## Tu servidor, y actualizarlo desde la app (desde la 1.5.5)

Spec `docs/superpowers/specs/2026-10-04-actualizar-el-servidor-design.md`, contrato `server/API-CONTRACT.md` §17. La app
enseña en Ajustes › Tu servidor cómo está el servidor y, si su instalador es más viejo que el que ella conoce, ofrece
«Actualizar», con un toque y sin pegar ningún comando.

- **El vigía** atiende `GET /avisos/v1/servidor` (`vigia/servidor.py`): las versiones del instalador (de su carpeta,
  `[servidor] instalador`), de los avisos y de Hermes (su `/health`), si Hermes contesta, lo libre en el disco de su casa
  (se lo pregunta al ayudante de la entrada, que la ve), el estado de las unidades de `[servidor] servicios` y
  `[servidor] hermes` (`systemctl is-active`, sin root), la última instantánea del ayudante de la copia (su orden
  `ultima`) y la actualización en curso. Todo a la vez y como mucho 5 s cada parte; lo que no se sabe, `null`. **Sin
  secretos**: lo que dicen los ayudantes se vuelve a filtrar. Y `/avisos/v1/servidor/actualizar` (`POST` con la versión
  y la suma que lleva la app, y `GET` para ver cómo va), que se lo pasa al ayudante que actualiza.
- **El ayudante** es `/usr/local/libexec/hehermes-actualizar` (`despliegue/`), Python sin dependencias, lanzado por
  `hehermes-actualizar.socket` (`/run/hehermes-actualizar.sock`, `root:hh-vigia 0660`, `Accept=yes`) en un
  `hehermes-actualizar@.service` por conexión, **de root** (`systemd-run` solo se lo deja a root) **y sin nada más**:
  ninguna capacidad, sin red, de solo lectura salvo su carpeta (`/var/lib/hehermes-actualizar`). Solo mira y lanza:
  - la forma de la versión (tres números) y de la suma, y nada más en la petición: **la URL es fija**, la del paquete
    instalado (`URL_BASE`, la de `empaquetar`);
  - **nunca hacia atrás** (ni la instalada ni una anterior), **una a la vez** (`actualizar.lock`) y **tres por hora**
    (`intentos.json`);
  - y lanza el trabajo en **su propia unidad**, `systemd-run --unit hehermes-actualizacion --collect`, sin jaula
    (instalar es tocarlo todo): la versión nueva reinicia el vigía, la pasarela y este socket, y el trabajo no muere con
    ninguno.
- **El trabajo** descarga el paquete y su `.sig` (solo por HTTPS, y redirecciones solo a HTTPS), comprueba **la suma
  que manda la app** y **la firma** con la clave principal o la de rescate del instalador instalado
  (`/opt/hehermes-servidor/clave-publica.pem` y `clave-rescate.pem`), y que por dentro es esa versión, y lanza
  `hehermes-servidor actualizar --paquete … --firma …`, que la vuelve a comprobar. Su estado, con su hora, en
  `estado.json`: `descargando`, `comprobando`, `instalando`, `hecho` o `fallo` con su motivo. Con las dos claves de
  marcador (un instalador de antes de que Daniel tuviera las suyas), se niega sin descargar nada (`sin_firmas`): ese
  servidor se actualiza una vez a mano.
- **En el VPS de Daniel** lo pone `instalar.sh`, con los demás ayudantes. Ahí actualiza lo del instalador (la pasarela,
  `/opt/hehermes-servidor`); los avisos siguen con `instalar.sh`.
- **Quitarlo:** `sudo …/instalar.sh --desinstalar-actualizar` (no con una actualización en marcha). Su carpeta se queda.

**Para root, a mano:** `sudo /usr/bin/python3 -I -S /usr/local/libexec/hehermes-actualizar estado`. Lo que pasa, en
`journalctl -u 'hehermes-actualizar@*' -u hehermes-actualizacion`: la versión, la fase y el resultado. Lo que dijo el
instalador (que puede llevar rutas y nombres de los iPhone), en `/var/lib/hehermes-actualizar/registro.txt`, de root, y
no en el journal.

## Los agentes (desde la 1.6.0)

Spec `docs/superpowers/specs/2026-10-05-agentes-design.md` («Revisión del 2026-10-05»), contrato
`server/API-CONTRACT.md` §18. Cada agente es un **perfil de Hermes** (`<HERMES_HOME>/profiles/<perfil>`), que la
pasarela de Hermes 0.21 sirve en su mismo proceso bajo `/p/<perfil>/`, con su propia `API_SERVER_KEY`. La app habla con
todos por la misma conexión: la pasarela de HeHermes cambia el token del iPhone por la clave de cada perfil
(`[agentes] claves` de `pasarela.ini`, `<perfil>.clave`), y a un perfil sin clave le contesta `404 agente_desconocido`.

- **El vigía** vigila todos los perfiles: el principal como siempre y cada agente con su prefijo y su clave (la carpeta
  `[agentes] claves`, `/etc/hehermes-avisos/agentes`, de root y del grupo `hh-vigia`). Lo visto va por perfil (base de
  datos 5: la clave es `(perfil, id)`; lo de antes, del principal) y cada aviso lleva su `perfil` dentro del sobre; el
  hilo y el colapso de un agente llevan `<perfil>/` delante (el principal, como antes). Un agente que no contesta no para
  a los demás. Atiende `/avisos/v1/agentes/…` (listar, crear, ver, cambiar, borrar y el estado de un trabajo) y se lo
  pasa al ayudante; `POST /avisos/v1/agentes/personalidad` se lo pide al principal (`/v1/chat/completions`, con un
  mensaje de sistema fijo y la descripción como mensaje del usuario), uno a la vez. El lector y la entrada atienden lo
  de cada perfil (`?exports <perfil>`, `perfil=`), nunca una ruta.
- **El ayudante** es `/usr/local/libexec/hehermes-agentes` (`despliegue/`), Python sin dependencias, lanzado por
  `hehermes-agentes.socket` (`/run/hehermes-agentes.sock`, `root:hh-vigia 0660`, `Accept=yes`) en un
  `hehermes-agentes@.service` por conexión, **de root y sin ninguna capacidad** (con un Hermes de otro usuario,
  `CAP_SETUID` y `CAP_SETGID`: lo de su casa lo hace un hijo que ya es ese usuario), `/etc` de solo lectura salvo las
  dos carpetas de las claves, y solo `127.0.0.1`. Crear y borrar son **trabajos**: contestan al momento y siguen en el
  mismo proceso con la conexión cerrada, uno a la vez (su estado en `/var/lib/hehermes-agentes/trabajos`). Todo `hermes`
  que lanza va con `-p default` delante (el principal, aunque `hermes profile use` haya dejado otro perfil activo: sin
  él, el `--clone` saldría de ese). Crear es
  `hermes profile create <perfil> --clone` y, lo primero, una clave nueva en su `.env` (32 bytes; el `--clone` le deja
  la del principal, y Hermes aparca un perfil con la clave de otro), su `SOUL.md`, su memoria (compartida, copiada o
  de cero) y su clave en las dos carpetas (0640); luego le pide a la pasarela de Hermes que lo vuelva a mirar (el
  verbo `rescan-profiles` de su socket de control, `<casa>/gateway.sock`) y espera hasta 2 minutos a que lo sirva,
  mirándolo cada 2 s. Un Hermes que ya sirve otros perfiles sirve en caliente los nuevos (y vuelve a mirar cada 30 s el
  que cambia su `.env`), **sin reiniciarlo**; si no lo sirve a tiempo, `fallo` con `no_se_sirve`, y el perfil se queda.
  La lista no lanza `hermes` (tarda segundos): lee `profiles/` con la regla con la que Hermes elige los que sirve
  (alguna de sus marcas, sin lápida, sin `gateway.parked` ni `gateway.standalone`) y pregunta a cada uno con su
  clave, todos a la vez y con un plazo de 1 s (`servido`). Borrar hace antes una copia (`hermes profile export`, en
  `~/hehermes-copias/agentes/` del dueño de Hermes): sin ella, no se borra. El principal no se borra nunca.
- **El primer agente reinicia Hermes, una vez.** Con `gateway.multiplex_profiles` sin poner, Hermes decide al arrancar
  si sirve otros perfiles: solo si hay dos o más (`resolve_multiplex_mode`, en la 0.21.5 y en main). El del VPS de
  pruebas arrancó con el principal solo, así que contestó `multiplex: false` y no sirvió el primero. Cuando pasa eso, y
  solo entonces, el ayudante:
  1. mira que la unidad de Hermes (`--unidad-hermes`) esté en marcha y que la pasarela de Hermes corra dentro (el
     `pid` de su `gateway_state.json` y su `/proc/<pid>/cgroup`): si no, no la toca, porque arrancar una parada sería
     otra pasarela al lado de la que sirve;
  2. espera hasta 10 minutos a un rato tranquilo, mirándolo cada 10 s: sin turnos en marcha (`active_agents` de su
     `gateway_state.json`, que su pasarela apunta en cada turno: los chats, la API, cron y lo de segundo plano) y sin
     escribir en el `state.db` ni en el `-wal` de ningún perfil que sirve en 2 minutos. La actividad de la pasarela de
     HeHermes no sirve para esto: la app pregunta por el trabajo a través de ella cada pocos segundos;
  3. pone el flag con la orden de Hermes, `hermes -p default config set gateway.multiplex_profiles true` (en el
     principal aunque `hermes profile use` haya dejado otro activo; el mismo escritor, que conserva los comentarios,
     que usa su `gateway migrate`), y comprueba que está en su `config.yaml`;
  4. le vuelve a preguntar (`rescan-profiles`: si ya los sirve, no lo reinicia; si no contesta, tampoco), vuelve a
     mirar la unidad y la reinicia una vez: `systemctl restart`, que para Hermes como diga ella (con la del VPS de
     pruebas, `KillMode=mixed` y `TimeoutStopSec=210`: SIGTERM, y Hermes drena lo que tenga en marcha);
  5. espera hasta 4 minutos a que lo sirva.

  **No** usa `hermes gateway migrate --multiplex`: deja su manifiesto, activa la unidad al arrancar la máquina y, si no
  reconoce la unidad por su nombre, instala otra o mata la pasarela y lanza otra suelta (`_restart_default` de
  `hermes_cli/gateway_migrate.py`); y su reinicio (`hermes gateway restart`) puede reescribir la unidad
  (`refresh_systemd_unit_if_needed`). Nunca reinicia si Hermes ya sirve otros perfiles, ni dos veces en un trabajo. Si
  no llega un rato tranquilo, o la orden o el reinicio fallan, `no_se_sirve`: el perfil se queda, y el registro dice que
  Hermes lo servirá en su próximo reinicio. Mientras, el trabajo dice en qué está (`paso`: `esperando_a_hermes` o
  `reiniciando_hermes`, §18.4). **Deshacerlo**: borrar los agentes y quitar la línea `multiplex_profiles: true` del
  bloque `gateway:` del `config.yaml` de Hermes (`false` está retirado: Hermes lo reescribe a `true`); con el principal
  solo, en su siguiente arranque vuelve a servir solo a él.
- **Borrar tarda minutos, y es de Hermes**: en el VPS de pruebas, la copia y el borrado de un agente recién creado,
  261 s entre los dos (1 min 18 s de CPU, 368 MB de pico). `hermes profile export` copia el perfil a una carpeta
  temporal y le pasa el redactor de secretos a cada fichero de texto (las habilidades que trajo el `--clone`) antes de
  comprimirlo; `hermes profile delete` arranca la CLI entera, para lo del perfil (servicios, procesos, su socket) y, con
  una pasarela que no multiplexa (no apunta `served_profiles`), purga su identidad abriendo él mismo el `state.db` del
  principal (`purge_profile_identity`: unas filas de `gateway_routing`, `gateway_heartbeats`, `delivery_obligations` y
  las de Telegram; el historial no se toca); con una que multiplexa, se lo pide a ella por su socket. Nada de eso es del
  ayudante, que solo los espera: cada uno con hasta 10 minutos, con el trabajo latiendo mientras (la lista lo sigue
  viendo en marcha), y el vigía no espera a ninguno (cada orden contesta al momento; el estado del trabajo, también). Si
  `hermes profile delete` sale con error pero el perfil ya no está, se da por borrado.
- **La memoria que comparten**: `hehermes-agentes-memoria.timer`, cada minuto, lanza el mismo ayudante
  (`sincronizar-memoria`, sin red y sin `hermes`): entre el principal y los que comparten, el `USER.md` más nuevo va a
  los demás, cada uno con el `flock` de Hermes (`memories/USER.md.lock`).
- **Las claves nunca** van en un argumento, en el registro ni en una respuesta. En el registro, el perfil, el principio
  del trabajo, la orden y el resultado: ni una personalidad ni lo que sabe de ti.
- **En el VPS de Daniel** lo pone `instalar.sh`, con los demás ayudantes, y las dos carpetas de las claves (la de la
  pasarela, si está). **Quitarlo:** `sudo …/instalar.sh --desinstalar-agentes` (no con un agente a medio crear): se
  van el ayudante, sus unidades y sus claves; los agentes, que son perfiles de Hermes, y sus copias se quedan, y volver
  a instalarlo copia otra vez sus claves de su `.env`.

**Para root, a mano:** `sudo /usr/bin/python3 -I -S /usr/local/libexec/hehermes-agentes listar` (los agentes y cuántos
caben). Lo que pasa, en `journalctl -u 'hehermes-agentes@*' -u hehermes-agentes-memoria`.

**Comprobado en el VPS de Daniel** (tarea 7; su Hermes es la rama main del 2026-10-05, no la 0.21.5 etiquetada, y en
la App Store puede haber de las dos): crear, la copia antes de borrar y borrar, sin tocar el `USER.md` del principal.
Y que Hermes sirve un perfil nuevo en caliente, pero aparca el que trae la clave del principal hasta que vuelve a
mirarlo: de ahí la clave lo primero y el `rescan-profiles`. Ese día, con su Hermes arrancado con el principal solo,
crear dio `no_se_sirve` a los 7 s (`multiplex: false`) y borrar tardó 261 s: de ahí el reinicio del primer agente y
los plazos largos de borrar. **Sin comprobar todavía:** el reinicio del primer agente en el VPS, y un Hermes que ya es
un perfil de otro (`hermes -p <nombre>`): ahí no se crean agentes.

## Probar de punta a punta

1. Con la VPN puesta, en Safari del iPhone: `http://10.77.0.1/avisos/v1/salud` → `{"estado": "ok", "servicio": "vigia", …}`.
   Si sale un 404 de Hermes, falta el `include` de nginx. Desde el propio VPS, la misma dirección da 403 (de nginx: solo
   entran los iPhone del túnel), y `http://127.0.0.1:8790/avisos/v1/salud`, 403 del vigía (falta el secreto).
2. En la app, Ajustes › Notificaciones: «Tu servidor» tiene que decir «Conectado» (el alta ha llegado al vigía).
   «Sin servicio de avisos» es un 404: nginx no lleva `/avisos/` al vigía. «Sin conexión» con la VPN puesta es un 5xx:
   un 502 si nadie tiene el puerto del vigía (`systemctl status hehermes-vigia.socket`), un 503 si el vigía está fuera
   de servicio (`journalctl -u hehermes-vigia` dice por qué).
3. «Mandar un aviso de prueba». El vigía espera a lo que diga Apple antes de contestar, así que si la app dice «Aviso
   de prueba pedido», Apple lo ha aceptado; en unos segundos llega «Aviso de prueba» descifrado por la extensión.
4. Mientras, en el VPS: `journalctl -u hehermes-vigia -u hehermes-rele -f`. Tienen que salir
   `aviso de prueba → …xxxxxx (sandbox)` y `enviado` en los dos. Los tokens salen siempre recortados a sus seis últimos
   caracteres; el texto de los avisos no sale nunca.
5. Después: una pregunta a Hermes y bloquear el iPhone (llega la respuesta), un chat silenciado (no llega nada) y la
   app delante (no llega nada: avisa ella).

Si la prueba falla, la app lo dice debajo del botón: «error 502» es el relé (sin clave, que es `sin_clave_apns`, fuera
de servicio, o Apple rechazando la configuración: `journalctl -u hehermes-rele`); «error 410», que Apple da el token por muerto (se ha dado de baja, y la
app se vuelve a dar de alta la próxima vez que arranque); «todavía no tiene el servicio de avisos», que el vigía no conoce ese
iPhone.

Los iPhone dados de alta: `sudo -u hh-vigia /opt/hehermes-avisos/venv/bin/python -I -m hehermes_avisos.vigia dispositivos`.

## Qué se avisa, y cómo se sabe

Leyendo el historial como la app (el SSE de un run es de un solo uso: si el vigía lo abriera, se lo quitaría a ella):

- **Respuesta**: una fila `assistant` con texto que no es un paso intermedio ni un «Operation interrupted». Una por
  conversación y vuelta: la última. No se avisa la respuesta a una retirada de «Deshacer envío», que la app no pinta.
- **Trabajo en segundo plano**: la respuesta a la continuación que lanza la app o el vigía (`⟦hehermes:continuar⟧`, abajo)
  o de una conversación sin ninguna petición; y la entrega de un subagente (`display_kind: async_delegation_complete`)
  solo cuando nadie la va a contestar (el vigía con `[entregas] contestar = no`, o tras una cadena de delegaciones).
- **Aprobación pendiente y error**: no dejan rastro fiable en el historial. Salen del estado del run
  (`GET /v1/runs/{id}`), y para eso el vigía necesita el `run_id`, que solo tiene la app: se lo da en el primer plano
  (la ampliación de abajo). Una aprobación se puede contestar desde el propio aviso desde la 1.5.4 (abajo).

No se avisa de nada con la app delante (ni de lo que llegó mientras lo estaba, aunque el vigía lo lea después), ni de
lo escrito hace más de 15 minutos, ni de nada anterior a la primera vuelta del vigía. Desde la 1.5.3, tampoco de las
copias que deja una compactación: Hermes vuelve a escribir la cola de la conversación con ids nuevos y sus horas de
siempre, y el vigía recuerda la hora de la última respuesta que vio en cada una (contrato §7).

### Aprobar y denegar desde el aviso (desde la 1.5.4)

Spec `docs/superpowers/specs/2026-10-04-aprobar-desde-el-aviso-design.md`. El aviso de una aprobación sale con
«Aprobar» y «Denegar», y la app la contesta sin abrirse (`POST /v1/runs/{id}/approval`, contrato §5). Para eso, dentro
del sobre y nunca en claro, el contenido lleva además `aprobacion`, y su `texto` es la petición entera, con sus líneas:

```json
{"tipo": "aprobacion", "sesion": "api_…", "titulo": "Limpieza",
 "texto": "Pide permiso para ejecutar: rm -rf /tmp/x \\\n  --one-file-system",
 "aprobacion": {"run": "run_…", "peticion": "<request_id>", "opciones": ["once", "session", "always", "deny"]}}
```

- Solo si Hermes da el `request_id` de la petición: sin él, `POST …/approval` resuelve «la más antigua», que puede no
  ser la del aviso.
- Solo con la vista previa en «Siempre»: con las otras, el aviso no dice qué se pide, y no se aprueba lo que no se ve.
- Solo si cabe entera en el push: el claro del sobre no pasa de `TOPE_CLARO` (2800 bytes), y así el push no pasa de los
  4096 que acepta el relé. Si no cabe, el aviso de siempre (una línea de 200 caracteres) y sin `aprobacion`.
- `opciones` son las `choices` de Hermes tal cual, o vacías si no las da (la app entiende entonces `once` y `deny`).

Una app de antes no lee `aprobacion` y enseña el texto; uno largo, recortado.

### Las entregas de los subagentes: el vigía lanza el turno que falta

Cuando un subagente en segundo plano acaba, Hermes escribe su entrega en el historial y **no lanza ningún turno**: en
el api_server el cliente es dueño del turno siguiente (`gateway/wake.py` del VPS, #85957, sin ajuste que lo cambie).
La app lo lanza si está viva; con el iPhone dormido, nadie. El 2026-09-27, en una conversación de Daniel, la entrega llegó a
las 02:36 y la respuesta no salió hasta que Daniel preguntó «¿cómo vas?» a las 08:43.

Ahora lo lanza el vigía (`vigia/entregas.py`), que corre siempre y ya lee ese historial: el **mismo turno** que la app
(`⟦hehermes:continuar⟧ …`) con la **misma `Idempotency-Key`** (`continuar-<delegation_id>` de la entrega más reciente),
por `POST /v1/runs`, la única escritura del vigía en Hermes. Solo si la entrega no tiene ningún turno detrás, han
pasado 60 s (los de la app, que si está delante la contesta con las instrucciones y el esfuerzo de la conversación),
no hay un turno a medias, tiene menos de 3 h y no van ya 3 continuaciones seguidas sin un mensaje de Daniel (Hermes
puede volver a delegar al recibirla). No se duplica: una entrega con un turno detrás no se toca, lo lanzado se recuerda,
y la misma clave con el mismo cuerpo da el mismo run (con el de la app, un 409). Su run se vigila como los de la app
(aviso de error si falla sin respuesta), y el aviso que llega es el de la **respuesta**, no «ha terminado un trabajo».
Se ajusta o se apaga en `[entregas]` de `vigia.ini`; en el registro sale `continuación … lanzada`.

### La ampliación del contrato que falta (compatible con lo de hoy)

`PUT /avisos/v1/dispositivos/{token}/primer-plano` con un campo opcional más, los turnos que la app tiene en marcha:

```json
{"activa": false, "conversacion": null, "caduca": 90,
 "turnos": [{"run_id": "run_…", "sesion": "api_…"}]}
```

El vigía ya lo acepta (si no viene, no pasa nada): vigila esos runs hasta que acaban y avisa de `waiting_for_approval`
(urgente, con el comando) y de `failed` sin salida o `interrupted` (error). Un `failed` con salida no, porque deja su
respuesta en el historial y ya la avisa la bandeja.

## Pruebas (sin red)

```bash
# En el Mac:
python3 -m venv /tmp/hh-avisos && /tmp/hh-avisos/bin/pip install --require-hashes -r server/avisos/requirements.txt
/tmp/hh-avisos/bin/python -I -m unittest discover server/avisos/tests
# En el VPS, con el venv que deja el instalador y sin root:
/opt/hehermes-avisos/venv/bin/python -I -m unittest discover server/avisos/tests
```

Hace falta un venv: el `python3` del sistema no tiene `cryptography` ni `httpx`, y sin ellos fallan al importar los
módulos que los usan. Vale el `python3` de Xcode (3.9): el código evita lo que solo existe desde 3.10. Las pruebas
cargan el código de `server/avisos` del repo, no el instalado.

Hermes y Apple son dobles (un api_server falso y un APNs de mentira, uno con `httpx.MockTransport` y otro con `h2` y
TLS, contra el que habla el cliente de producción, `cliente_http2()`); el vigía y el relé son los de producción,
hablando por `127.0.0.1`, y también se arrancan como procesos con el socket de systemd pasado en el descriptor 3.
Además del Hermes inventado, el vigía se pasa por dos historiales de verdad de un api_server
(`tests/datos/hermes/`, los mismos que usa la app en sus pruebas), servidos por HTTP como los da Hermes. Por eso las
pruebas de los avisos no se publican con el código. El cifrado se
fija contra el vector de la app en los dos sentidos (`tests/datos/`). Del instalador se ejecutan de verdad el paso de
nginx y el del secreto, sobre una carpeta temporal y con `nginx` y `systemctl` simulados; lo demás (root, systemd) se
ensayó aparte.

La entrada pública del relé (`tests/test_rele_publico.py`) va de verdad: el relé con Apple de mentira, su entrada con
TLS en `127.0.0.1` y el vigía de otro servidor delante, con su HTTPS anclado. Carga la pasarela de
`server/instalador` (como en el VPS, donde `instalar.sh` la copia al lado). En el Mac, con TLS 1.2 (el Python de Xcode
trae LibreSSL 2.8, sin 1.3); lo que exige 1.3 corre donde haya OpenSSL 3. Las pruebas que escuchan en `127.0.0.1` fallan
dentro del sandbox de Claude Code: fuera de él.

## Los permisos por dispositivo: App Attest (construido, 1.3.0)

Hasta la 1.2.0 cada vigía tenía **una credencial por servidor, emitida a mano**. Desde la 1.3.0 hay además
**permisos por dispositivo avalados con App Attest** (spec `docs/superpowers/specs/2026-09-28-avisos-con-app-attest-design.md`,
contrato `server/API-CONTRACT.md` §13.5 y §14), y con ellos un probador tiene avisos **sin ejecutar nada**: el
instalador 0.8.0 pone el vigía sin credencial y la app hace el resto.

```
iPhone ──reto, atestación/aserción──▶ entrada pública del relé (la oficina de permisos, sin la .p8)
   │    ◀──────── permiso firmado ──────┘
   └─alta con el permiso──▶ su vigía ──aviso + «Authorization: Permiso …»──▶ entrada pública ──▶ relé ──▶ APNs
```

- **La oficina** (`rele/permisos.py`, `rele/appattest.py`, `rele/cbor.py`) vive en la entrada pública, que no puede leer
  la .p8. Comprueba la atestación (la cadena hasta la raíz de Apple, incrustada; el nonce; el keyId; el App ID
  `8X7L8YHD9M.com.danielmorales.HeHermesMensajes`; el contador; el aaguid de desarrollo o de producción) y las
  aserciones (la firma sobre el nonce, el contador que sube), guarda lo mínimo de cada clave
  (`/var/lib/hehermes-rele-publico/permisos.db`) y firma el permiso con Ed25519
  (`/etc/hehermes-avisos/rele-publico/permisos.pem`, de root, por `LoadCredential`).
- **El relé** solo tiene la pública (`/etc/hehermes-avisos/rele/permisos.pub.pem`): comprueba la firma, la fecha, la
  revocación y que el token y el entorno del aviso son los del permiso.
- **Revocar**: `sudo hehermes-rele permiso revocar <keyId|token>` (y `readmitir`, `lista`). Vale al momento en los dos
  (`/etc/hehermes-avisos/rele/permisos-revocados.txt`, que vuelven a leer en cuanto cambia; roto, no vale ningún permiso).
- **Las credenciales siguen valiendo** igual: el vigía de Daniel y los de los códigos de avisos no cambian.
- `instalar.sh` (con la entrada pública puesta) crea las claves la primera vez y añade la sección `[permisos]` a
  `rele-publico.ini`; después no las toca (otra clave dejaría sin valor todos los permisos dados).
- El vigía (`vigia/envio.py`): con credencial, como siempre; sin ella, con el permiso de cada iPhone, a la dirección y
  la huella que la app le da en el alta (solo IPs públicas o nombres que resuelven a IPs públicas).

Lo que queda para miles: el relé en su propia máquina (con conexiones HTTP/2 a APNs que se quedan abiertas), un dominio
en lugar de la IP, y los límites en un almacén compartido si hay más de una instancia.

Las pruebas: `tests/test_cbor.py`, `tests/test_appattest.py` (con la atestación y la aserción de un iPhone de verdad,
`tests/datos/app-attest/`, y con cadenas fabricadas con una raíz de prueba, `tests/atestaciones_de_prueba.py`, que no es
la de Apple), `tests/test_permisos.py` y, por TLS, `tests/test_rele_publico.py`.

## Límites conocidos

- El vigía ve lo mismo que la bandeja de la app: las 200 conversaciones de `GET /api/sessions` más las fijadas. Una muy
  antigua que reviviera fuera de esa ventana no avisaría (no está comprobado cómo ordena Hermes esa lista).
- Si el «ya no estoy delante» no llega (VPN caída al irse), el vigía sigue dando la app por delante hasta 90 s después
  de su último latido (el plazo que pone la app, que lo repite cada 30 s). Lo que llegue en los 35 s siguientes a ese
  latido se da por visto; lo que llegue después se avisa cuando vence el plazo, con ese retraso.
- El nginx del túnel pone el Bearer de Hermes a **cualquier** conexión a `10.77.0.1:80`, también a las de procesos de la
  propia máquina (llegan desde `10.77.0.1`), si el sitio del túnel es uno escrito a mano sin `allow` ni `deny` (el de
  `server/vpn/hehermes-tunel.nginx`; el que escribe el instalador ya lo cierra). `/avisos/` ya lo cierra en su
  propia location, y el vigía no depende de ese agujero (lee a Hermes directo, con su copia de la clave), así que
  cerrarlo no rompe nada: en la `location /` del túnel, antes de lo demás, lo mismo que lleva la de los avisos,
  `deny 10.77.0.1; allow 10.77.0.0/24; allow 10.77.1.0/24; deny all;`.
- Los agentes (1.6.0): la limpieza de noche de lo que la app borra (`hehermes-borrado`, del instalador) compacta solo
  el `state.db` del principal; lo que se borra de un agente queda en el suyo hasta que Hermes lo compacte. Y el lector y
  la entrada ven `profiles/` entero por el núcleo (`BindReadOnlyPaths`, `BindPaths`): dentro, lo que leen y escriben de
  cada perfil lo decide su lista de permitidas, no la jaula. Un perfil que ya estaba antes del ayudante, sin clave en su
  `.env`, sale en la lista con `servido: false` hasta que la tenga.
