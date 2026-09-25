# Avisos push: el vigía y el relé

Lo del servidor de los avisos de HeHermes Mensajes (spec: `docs/superpowers/specs/2026-09-23-avisos-push-design.md`).
La app y su extensión ya están hechas; esto es lo que les falta para avisar con la app cerrada.

El vigía sirve además, de solo lectura, los ficheros que Hermes marca con `MEDIA:` (`GET /avisos/v1/fichero`): el
contrato está en `server/API-CONTRACT.md` §11, y cómo se lee sin darle al vigía nada de root, en
[«El lector de ficheros»](#el-lector-de-ficheros-de-hermes).

```
iPhone ──túnel──▶ nginx 10.77.0.1 ──/avisos/──▶ vigía 127.0.0.1:8790 ──▶ relé 127.0.0.1:8791 ──HTTP/2──▶ APNs ──▶ iPhone
                                   └──── / ────▶ Hermes 127.0.0.1:8642 ◀── el vigía lo lee (sin tocarlo)
```

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
   las unidades de systemd (dos sockets, que tienen los puertos, y dos servicios). Deja los dos en marcha: el relé, sin
   su clave, contesta 503 a los avisos.
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

## El lector de ficheros de Hermes

`GET /avisos/v1/fichero?sesion=&ruta=` (contrato: `server/API-CONTRACT.md` §11) le trae a la app un fichero que Hermes
marcó con una línea `MEDIA:<ruta>`. Hermes corre como root y deja sus ficheros donde quiere, y `hh-vigia` no los puede
leer, así que el reparto es este:

- **El vigía decide si se puede pedir.** Lee las 500 últimas filas de la sesión y exige una fila `assistant` con una
  línea que, con las reglas de la app (`ExtraccionMedia.swift`), dé esa ruta exacta. Si no la hay, 404, sin mirar el
  disco. Además limita: 30 por minuto, contando también las que no estaban marcadas, y 2 a la vez.
- **El lector decide qué se puede leer.** Es `/usr/local/libexec/hehermes-leer-media` (`despliegue/`), Python sin
  dependencias:
  - resuelve la ruta y rechaza las prohibidas, sobre la pedida y sobre la resuelta (la lista está en el propio
    lector, y la copia en el contrato);
  - prohíbe la carpeta de Hermes entera (su `.env`, `auth.json`, `config.yaml` y sus copias, `state.db`, `backups/`…),
    menos `image_cache/` y `audio_cache/`, donde deja lo que genera. Lo pedido en una cache tiene que estar, resuelto,
    en esa misma cache. Si el entorno de `hermes-gateway` dice otro `HERMES_HOME`, `instalar.sh` deja un añadido a la
    unidad (`hehermes-leer-media@.service.d/hermes-home.conf`) con `--hermes-home=`, y lo quita si vuelve a
    `/root/.hermes`;
  - baja desde `/` carpeta a carpeta con `O_NOFOLLOW`, así que un enlace colado a mitad de camino hace fallar la
    apertura;
  - comprueba con `fstat` del descriptor abierto que es el mismo inodo, un fichero normal, con un solo enlace duro y de
    no más de 50 MB;
  - y lo manda por partes.
- **Cómo se llega al lector: un socket de systemd, no sudo.** `hehermes-leer-media.socket` (`/run/hehermes-leer-media.sock`,
  `root:hh-vigia 0660`, `Accept=yes`) lanza un `hehermes-leer-media@.service` de root por cada conexión, con su propia
  jaula:
  - todo de solo lectura;
  - sin red;
  - de las capacidades de root, solo `CAP_DAC_READ_SEARCH`;
  - y las rutas prohibidas tapadas también por el núcleo (`InaccessiblePaths`): aunque el código fallara, dentro no
    se ven.

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

**Para root, a mano:** `sudo /usr/local/libexec/hehermes-leer-media <ruta>`, con los bytes por la salida estándar. Lo
que se aplica así es solo el código del lector, sin la jaula de systemd.

**En el VPS:**

- `sudo -u hh-vigia …vigia comprobar` dice si el lector contesta: le pide `/`, que tiene que dar «no es un fichero».
- Lo que pasa, en `journalctl -u 'hehermes-leer-media@*' -u hehermes-vigia`: solo el estado, el tamaño y la
  extensión, nunca la ruta ni el contenido.
- `sudo server/avisos/despliegue/instalar.sh --desinstalar-lector` lo quita, y la ruta pasa a contestar 503.

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
- **Trabajo en segundo plano**: la entrega de un subagente (`display_kind: async_delegation_complete`), que con la app
  dormida es la única señal de que ha acabado, y la respuesta a la continuación que lanza la app (`⟦hehermes:continuar⟧`)
  o de una conversación sin ninguna petición.
- **Aprobación pendiente y error**: no dejan rastro fiable en el historial. Salen del estado del run
  (`GET /v1/runs/{id}`), y para eso el vigía necesita el `run_id`, que solo tiene la app. **Hoy no llegan**: hace falta
  la ampliación de abajo.

No se avisa de nada con la app delante (ni de lo que llegó mientras lo estaba, aunque el vigía lo lea después), ni de
lo escrito hace más de 15 minutos, ni de nada anterior a la primera vuelta del vigía.

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

## El camino para miles (documentado, no construido)

Hoy cada vigía tiene **una credencial por servidor, emitida a mano** (`python -m hehermes_avisos.rele credencial`), y
el relé guarda solo su huella. Sirve para uno o para unos pocos, pero una credencial filtrada deja pedir avisos para
cualquier token. Para miles:

1. **Permisos por dispositivo avalados con App Attest.** Al darse de alta, la app pide al relé un permiso de avisos
   para su token: le manda una atestación de App Attest (la primera vez) o una aserción (después), que demuestra que es
   la app de verdad, firmada por el equipo `8X7L8YHD9M` y sin tocar. El relé la comprueba con Apple y devuelve un
   permiso firmado por él (token, entorno, caducidad).
2. La app le pasa ese permiso a **su** vigía por el túnel, dentro del alta (un campo más, `permiso`), y el vigía lo
   manda con cada aviso. El relé solo acepta avisos para tokens con permiso vigente y firmado por él: un vigía, o quien
   robe su credencial, solo puede avisar a los iPhone que se lo han dado. Los permisos caducan (p. ej. a los 30 días) y
   la app los renueva al arrancar.
3. La credencial por servidor queda para limitar y para saber de quién es cada aviso, no para autorizar.
4. El relé, en su propia máquina: detrás de un proxy con TLS, con conexiones HTTP/2 a APNs que se quedan abiertas y
   se vigilan con PING (hoy se abre una por aviso, que al ritmo de un usuario es lo sensato), un servidor asíncrono o
   varios procesos, y los límites en un almacén compartido si hay más de una instancia. Sigue sin guardar
   estado de nadie más allá de los límites, las bajas y la lista de permisos revocados (por huella).
5. Nada cambia en la extensión ni en el formato del aviso: el sobre ya es de extremo a extremo.

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
