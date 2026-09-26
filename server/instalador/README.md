# hehermes-servidor: el instalador de un solo comando

En un Linux que ya tiene Hermes (Debian, Ubuntu y sus derivadas, o la familia Red Hat: [más abajo](#los-sistemas)), deja lo que necesita la app HeHermes Mensajes para hablar con él y acaba pintando el QR
del iPhone en el terminal: **la conexión directa**, la pasarela (`hehermes-pasarela`). Un puerto TCP alto con TLS 1.3,
un certificado propio cuya huella ancla la app y un token por iPhone. **No necesita root**: sin él se instala en la casa
del usuario de Hermes. Es `docs/superpowers/specs/2026-09-26-pasarela-tls-design.md`, con su plan en
`docs/superpowers/plans/2026-09-26-pasarela-servidor.md`.

**Desde la 0.6.0 es lo único que instala.** La VPN IKEv2 de las versiones anteriores ya no se instala, ni se repara,
ni se actualiza, y la app ya no la usa: `instalar --modo vpn` se para y dice que ya no existe. La de un servidor que la
tenga **se quita** con `desinstalar --modo vpn`, sin tocar la pasarela: [abajo](#la-vpn-de-antes), paso a paso.

```bash
sudo ./hehermes-servidor instalar --plan --iphone mi-iphone   # enseña lo que haría, sin cambiar nada
sudo ./hehermes-servidor instalar --iphone mi-iphone          # lo mismo, pregunta «¿Sigo? [s/N]» y lo hace
./hehermes-servidor instalar --iphone mi-iphone               # sin root: la pasarela, en la casa de este usuario
sudo hehermes-servidor instalar                               # repetirlo: «Todo al día: 0 cambios», o repara
sudo hehermes-servidor comprobar                              # lo que tiene que estar en marcha, y «Seguridad»
sudo hehermes-servidor desinstalar [--quitar-paquetes]        # enseña lo que quita, pregunta y lo quita
sudo hehermes-servidor desinstalar --modo vpn                 # solo la VPN de una versión anterior
sudo hehermes-dispositivo alta otro-iphone                    # otro iPhone, con el instalador ya puesto
```

Más opciones de `instalar`: `--direccion <IP o nombre>` (la del QR, si el servidor está detrás de un NAT),
`--hermes-home <carpeta>` (si hay varios Hermes), `--reemplazar <fichero>` (repetible), `--si` (sin preguntar; sin un
terminal es obligatorio), `--activar-api`, `--corregir-exposicion` (la API de Hermes, solo en 127.0.0.1:
[abajo](#la-api-de-hermes-sin-exponer)), `--cortafuegos-a-mano` (el cortafuegos lo llevas tú:
[abajo](#los-cortafuegos)) y, para el alta por chat, `--por-chat --llave <llave> [--qr-png <fichero>]` (abajo).
`--modo tls` se sigue aceptando (lo llevan los comandos de antes), y no cambia nada.

## La pasarela

La app habla con `https://<dirección>:<puerto>` y la pasarela reenvía a Hermes en `127.0.0.1`, poniéndole la
`API_SERVER_KEY` (la app no la conoce), o al vigía de avisos si la ruta es `/avisos/…` y está instalado. El contrato
con la app, entero, está en `server/API-CONTRACT.md`, §12: el QR, lo que entrega el canje, la cabecera del token, las
rutas y los errores.

| | |
|---|---|
| Qué es | `hehermes_servidor/pasarela.py` y su lanzador `hehermes-pasarela`: `asyncio` y `ssl` de la biblioteca estándar, con el `python3` del sistema. `cryptography` solo hace falta para el certificado, en el venv del canje |
| Dónde escucha | Un TCP al azar del **58000 al 65500** (los dos entran), de `secrets.randbelow`, libre en `ss -tan`, elegido la primera vez y **fijo** desde entonces (va en el manifiesto) |
| TLS | Solo 1.3. ECDSA P-256 autofirmado, con un nombre al azar, sin SAN y diez años (`canje.preparar --dias 3650`). La app ancla el SHA-256 de su SPKI y no mira nada más |
| Cada iPhone | Un token de 256 bits (`Authorization: Bearer`). En `tokens.json` solo va su SHA-256, y se compara con `hmac.compare_digest` contra **todas** las entradas. Una baja o una rotación valen al momento: la pasarela vuelve a leer el fichero en cuanto cambia y corta en un segundo las conexiones abiertas con ese token, también un SSE |
| A quien no trae token | Siempre los mismos bytes (`404`, `Content-Length: 0`, `Connection: close`), un segundo después, y sin cabecera `Server` (la de Hermes también se quita) |
| Límites | 10 intentos fallidos desde una IP en 10 minutos la bloquean 15 (ni llega al apretón TLS); 16 conexiones por IP y 128 en total; 10 s para las cabeceras (slowloris); 75 s de conexión parada; 16 KiB y 100 líneas de cabeceras; cuerpos de 25 MiB (64 KiB en `/avisos/`); 4096 IP recordadas. Lo que llega de 127.0.0.1 no cuenta como intento: `comprobar` se asoma sin token |
| SSE | Sin búfer: cada trozo sale en cuanto llega, y sin plazo mientras siga abierto |
| Registro | La IP, el método, el estado y los bytes. **Nunca** el token, la ruta con su consulta (llevan tokens de avisos y rutas de ficheros) ni ningún cuerpo |

### Con root

| Pieza | Qué deja |
|---|---|
| El usuario | `hh-pasarela`, de sistema, sin casa ni shell |
| Código | `/opt/hehermes-servidor/` (con `hehermes-pasarela` y la clave pública de las firmas), `/usr/local/sbin/hehermes-servidor` y `/usr/local/sbin/hehermes-dispositivo` (si no hay ya uno ajeno) |
| La pasarela | `/etc/hehermes-pasarela/` (0750, `root:hh-pasarela`): `pasarela.ini` y `tokens.json` (0640, del grupo), `cert.pem` (0644), `clave.pem` y `clave-hermes` (0600, de root). **No** escribe `/etc/hehermes/servidor.ini`, que era de la VPN |
| La unidad | `hehermes-pasarela.service`: `User=hh-pasarela`, sin capacidades, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectProc=invisible`, `RestrictNamespaces`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` sin `@privileged` ni `@resources` y `UMask=0077`. La clave del certificado, la de Hermes y (si están los avisos) el secreto del vigía le llegan con `LoadCredential` |
| La clave de Hermes | `hehermes-pasarela-clave.path` vigila el `.env` y, si cambia, `hehermes-servidor pasarela-clave` pone al día `clave-hermes` y reinicia la pasarela |
| Cortafuegos | Solo el TCP de la pasarela: `ufw allow proto tcp … port P comment hehermes`, `--add-port=P/tcp` en firewalld, o su regla en las cadenas de nftables o iptables, con `hehermes-cortafuegos.service` para después de un reinicio ([abajo](#los-cortafuegos)). **No enciende ninguno** |
| Paquetes | Ninguno, salvo `python3-venv` en Debian si a su Python le falta `ensurepip` |
| El manifiesto | `/etc/hehermes/instalacion.json` (0600): lo que es suyo ([abajo](#cómo-no-pisa-nada)) |

### Sin root

Si no hay root, ni `sudo` sin contraseña (con él, se relanza como root), el instalador **sigue** como el usuario que lo
lanza, que tiene que ser el de Hermes (lee su `.env`):

- **Nada de paquetes** (le basta Python 3.9 y `cryptography` en su venv) y **nada de cortafuegos**: no lo mira
  (sin root no se puede) y dice qué hay que abrir, el TCP de la pasarela, en el suyo y en el del proveedor.
- **Todo en su casa**: el código en `~/.local/share/hehermes-servidor` (y sus órdenes en `~/.local/bin`), el venv en
  `~/.local/share/hehermes-venv`, la pasarela en `~/.config/hehermes-pasarela` (todo 0600) y el manifiesto en
  `~/.config/hehermes/instalacion.json`. La pasarela lee la clave del `.env` de Hermes y la vuelve a leer si cambia.
- **El arranque**, una unidad de `systemctl --user`. Con `loginctl enable-linger` puesto, sigue siempre. Sin linger
  pero con una sesión abierta, arranca y **avisa** de que se parará al cerrar la última sesión (lo arregla un
  administrador con `sudo loginctl enable-linger <usuario>`). Sin ningún gestor de usuario, **se para y lo dice**: no
  se inventa otro arranque.
- Sin `ensurepip` (Debian sin `python3-venv`), se para y dice qué pedirle al administrador.
- `comprobar` y `desinstalar` (sin `sudo`) son de esa instalación; `actualizar`, todavía no (el comando de la app
  repara).

### Los iPhone, con `hehermes-dispositivo`

```bash
sudo hehermes-dispositivo alta <nombre>    # el token nuevo y su QR hehermes-tls:1?…, solo en un terminal (y con sudo)
sudo hehermes-dispositivo baja <nombre>    # su token deja de valer, y su conexión se corta en un segundo
sudo hehermes-dispositivo rotar <nombre>   # otro token, y su QR; el de antes deja de valer
sudo hehermes-dispositivo lista            # todos, con su modo: tls, o ikev2 y wireguard los de una VPN de antes
```

`alta <nombre>` es siempre de la pasarela; `alta <nombre> --tls`, lo mismo (es lo que enseñaban las versiones
anteriores). **La VPN ya no da altas nuevas ni cambia claves**: `--ikev2` (y `--pubkey` o `--servidor`, de WireGuard)
se paran y dicen por qué, y `rotar` o `qr` de un alta de la VPN, también. Lo que quede de ella se ve en `lista` y se da
de baja con `baja <nombre>`, como siempre: su conexión de swanctl, la recarga y el corte de la sesión (o, de WireGuard,
`wg0.conf` sin él). Si el mismo nombre está en la pasarela y en la VPN, `baja` pide cuál (`--tls` o `--ikev2`).

Sin root, lo mismo sin `sudo` (`~/.local/bin/hehermes-dispositivo`). El QR lleva el token: se pinta solo en un terminal
(como root, además, lanzado con `sudo`), y **no se puede volver a pintar**, porque del token solo queda el hash: `qr
<nombre>` dice que se use `rotar`. Si ya había un `/usr/local/sbin/hehermes-dispositivo` ajeno (el de una VPN hecha a
mano), no se toca: el de la pasarela es `/opt/hehermes-servidor/hehermes-dispositivo`. El QR no depende de `qrencode`:
lo dibuja `hehermes_servidor/qr.py` (modo byte, versiones 1 a 40), que las pruebas comparan módulo a módulo con `segno`.

### «Seguridad», en la pasarela

`comprobar` se asoma a la pasarela como lo haría cualquiera, sin token (`Sistema.sondear_pasarela`), y mira: que
negocie TLS 1.3 y no acepte 1.2, que sirva el certificado cuya huella va en los QR, que conteste el 404 de siempre y
sin `Server`; que la API de Hermes solo escuche en 127.0.0.1; que la clave del certificado, la de Hermes y el manifiesto
solo los lea su dueño, que `tokens.json` y `pasarela.ini` no los lea cualquiera y que en `tokens.json` no haya más que
hashes; con root, que la unidad lleve su usuario y su sandbox, el cortafuegos, el canje y la firma.

## La VPN de antes

Hasta la 0.5.1 el instalador ponía también una VPN IKEv2 (`--modo vpn`), y desde la 0.5.1 las dos podían convivir.
Desde la 0.6.0 **la VPN ya no se instala**: lo que sigue es cómo se trata un servidor que la tiene.

| Orden | En un servidor con la VPN de antes |
|---|---|
| `instalar` | Pone (o repara) la pasarela a su lado, sin tocarla, y el plan dice que la VPN sigue ahí y cómo quitarla (lo de la VPN no sale en el plan: ni se repara lo que falte) |
| `instalar --modo vpn` | Se para antes de mirar nada (ni pregunta a sudo) y dice que ya no existe y cómo quitar la de antes |
| `comprobar` | Ya no comprueba la VPN (no se repara): dice que sigue aquí y cómo quitarla. Sin la pasarela, sale con 1 y dice cómo instalarla. «Seguridad» sí la sigue mirando mientras esté (el sitio del túnel, las PSK, las conexiones IKEv2) |
| `actualizar` | Sin la pasarela, no instala nada: dice qué hay y qué hacer (instalar la pasarela abre un puerto a internet, y eso no se hace por la puerta de atrás de una actualización). Con ella, actualiza solo la pasarela (`instalar --si` de la versión nueva) |
| `desinstalar --modo vpn` | Quita solo la VPN: da de baja sus altas IKEv2 (y corta sus sesiones), quita el sitio de nginx (y lo recarga), la XFRM, `hehermes-clave.path`, `servidor.ini`, el registro, las reglas de UDP 500 y 4500 y del TCP 80, y la etiqueta de SELinux. La pasarela se queda byte a byte como estaba. Si es lo único que hay, es lo mismo que `desinstalar` |
| `desinstalar` | Todo: la VPN, la pasarela y lo común |
| `hehermes-cortafuegos` | Mientras quede la VPN, vuelve a poner sus reglas de nftables o iptables tras un reinicio, con las de la pasarela |

Qué es de cada uno lo decide `hehermes_servidor/modos.py` por la ruta, el nombre o el texto de cada cosa, no por lo que
apuntó cada pasada, así que vale también para un manifiesto de antes de la 0.5.1, que no dice de qué modo es (y es de
la VPN):

| | La VPN de antes | La pasarela | Común (se va solo con `desinstalar` a secas) |
|---|---|---|---|
| Ficheros | `servidor.ini`, la XFRM, el sitio de nginx y su clave, el drop-in de nginx, `hehermes-clave.*` | `/etc/hehermes-pasarela/`, `hehermes-pasarela.service`, `hehermes-pasarela-clave.*` | `/opt/hehermes-servidor/`, `hehermes-servidor`, `hehermes-dispositivo`, `hehermes-cortafuegos.service` |
| Otras cosas | Las reglas de ufw o firewalld de IKEv2 y el TCP 80, SELinux, los paquetes (menos `python3-venv`), el `default` de nginx que apagó, las altas IKEv2 | La regla del TCP de la pasarela, el usuario `hh-pasarela`, sus tokens, el venv de `cryptography` | Las líneas de `--activar-api`, `python3-venv` |

- **Por chat, el primer iPhone** (decisión 7) es el primero del servidor: con un iPhone en la VPN de antes, un alta por
  chat en la pasarela sería un segundo iPhone, y se para.
- **Las reglas de nftables o iptables** de las dos llevan la misma marca (`hehermes`) y se ponen juntas; quitar la VPN
  vuelve a dejar solo la de la pasarela.
- **Los avisos** (`--avisos`) los instalaba la VPN, pero la pasarela también los sirve: `desinstalar --modo vpn` no se
  los lleva, y lo dice. `desinstalar` a secas, sí.
- Los paquetes de la VPN (strongSwan, nginx, qrencode) solo se van con `--quitar-paquetes`, y solo los que instaló.

Lo prueban `tests/test_dos_modos.py`, `tests/test_desinstalar.py` y `tests/test_cli.py` con el doble de servidor y la
VPN montada como la dejaba la 0.5.1 (`tests/vpn_antigua.py`): la pasarela sobre ella, repetir, `comprobar` y
`actualizar` con las dos, y quitar la VPN dejando la pasarela **byte a byte** como estaría si se hubiera instalado sola
(con ufw y con nftables), también desde un manifiesto sin modos y en la familia Red Hat.

#### De la VPN a la pasarela, paso a paso

Para un servidor con la VPN del instalador (`mi-iphone` por IKEv2):

1. **Añadir la pasarela, sin tocar la VPN.** Primero el plan, que no cambia nada:
   `sudo ./hehermes-servidor-0.6.0/hehermes-servidor instalar --plan --iphone iphone-tls`. Tiene que decir «Aquí sigue
   la VPN IKEv2 que instaló una versión anterior», el TCP elegido y ningún «No puedo seguir».
2. **Instalarla:** lo mismo sin `--plan`, en un terminal (pinta el QR del token, que no se puede volver a pintar).
3. **Abrir el TCP de la pasarela en el cortafuegos del proveedor**, si tiene uno en su panel (el plan lo dice con su
   número): el del servidor ya lo abre el instalador.
4. **Comprobar:** `sudo hehermes-servidor comprobar`. La pasarela, toda `bien`, y un aviso de que la VPN sigue ahí.
5. **En el iPhone,** escanear el QR con la app HeHermes Mensajes.
6. **Quitar la VPN:** `sudo hehermes-servidor desinstalar --modo vpn`. Enseña lo que quita (solo lo de la VPN, y
   `mi-iphone`), pregunta y lo quita. Con `--quitar-paquetes`, también strongSwan, nginx y qrencode, si los instaló él.
7. **Comprobar otra vez:** `sudo hehermes-servidor comprobar` ya solo habla de la pasarela, y `sudo hehermes-servidor
   instalar` dice «Todo al día: 0 cambios».

Lo que no está probado de verdad: todo esto en un servidor real (solo con el doble), y en particular que strongSwan y
nginx se queden bien al quitar solo la VPN en uno que los tenga también para otras cosas.

### Al lado de una VPN hecha a mano

La pasarela no toca nada de una VPN: ni strongSwan, ni nginx, ni XFRM, ni `servidor.ini`, ni el registro de
`hehermes-dispositivo`. En un servidor con una VPN de HeHermes hecha a mano (la de `server/vpn/README.md`, en su
historia), lo dice y sigue; desinstalar la pasarela no la toca tampoco, y una hecha a mano no se desinstala nunca: no es
suya. Lo compara `tests/test_modo_tls.py` con el doble de un VPS así. Esto es lo que avisa el plan allí
(`sudo hehermes-servidor instalar --plan --iphone mi-iphone`; lo compara `tests/test_documentacion.py`):

<!-- pasarela-de-daniel -->
```
Hay que saber:
  - Si tu proveedor tiene un cortafuegos propio, en su panel, abre ahí el TCP 61234
  - Aquí hay una VPN de HeHermes (/etc/nginx/sites-available/hehermes-tunel, /etc/swanctl/conf.d/hehermes-poc.conf, /etc/wireguard/hehermes). No la toco: la pasarela va aparte, en su puerto, y las dos conviven
  - /usr/local/sbin/hehermes-dispositivo no es mío: no lo toco. Para los iPhone de la pasarela usa el mío: sudo /opt/hehermes-servidor/hehermes-dispositivo alta <nombre>

43 cambios.
```
<!-- /pasarela-de-daniel -->

## El comando de la app

El paquete es `hehermes-servidor-<versión>.tar.gz`, con una URL por versión que no cambia nunca, y la app lleva su
SHA-256 en el comando: si el fichero cambia, no se ejecuta. `mktemp -d` da una carpeta 0700, así que entre la suma y el
`sudo` nadie más puede tocar lo descargado.

```
d=$(mktemp -d) && cd "$d" && curl -fsSLO {url-base}/v{versión}/hehermes-servidor-{versión}.tar.gz && echo "{sha256}  hehermes-servidor-{versión}.tar.gz" | sha256sum -c - && tar -xzf hehermes-servidor-{versión}.tar.gz && sudo ./hehermes-servidor-{versión}/hehermes-servidor instalar --iphone {nombre}
```

Con el instalador ya puesto, otro iPhone no necesita el comando entero: `sudo hehermes-dispositivo alta <nombre>` (sin
`sudo` si la pasarela es de un usuario).

`server/instalador/empaquetar` genera el paquete, su `.sha256` y esa línea ya rellena:

```bash
server/instalador/empaquetar                                   # dist/hehermes-servidor-0.6.0.tar.gz y .sha256
server/instalador/empaquetar --url-base https://ejemplo.org/hehermes --iphone mi-iphone
server/instalador/empaquetar --firmar hehermes-firma.pem       # y el .sig (hace falta OpenSSL 3)
```

- **Dónde está:** por ahora, en las Releases del repositorio público: `{url-base}` es
  `https://github.com/dnlmrls/HeHermes/releases/download`, y cada versión es una Release `v{versión}` con el `.tar.gz`
  y su `.sha256` como assets. Más adelante irá a un dominio propio, con el mismo esquema (`{url-base}/v{versión}/…`);
  `--url-base` o `HEHERMES_URL_BASE` la cambian. `curl -O` guarda el fichero con el nombre del final de la URL, no con
  el de la redirección de GitHub, así que la suma se comprueba sobre el nombre de siempre.
- **Es reproducible:** la misma versión da siempre el mismo fichero y la misma suma (orden fijo, dueño root, hora fija
  y gzip sin nombre ni hora). Si se cambia algo, hay que subir la versión.
- **Lleva:** `hehermes-servidor`, `hehermes-pasarela` y `hehermes_servidor/`, `hehermes-dispositivo` (de `server/vpn`),
  `clave-publica.pem`, `requirements-canje.txt` y este README. Ni pruebas ni `__pycache__`. Desde la 0.6.0 ya no lleva
  los avisos (`server/avisos`): solo los instalaba `--avisos`, que iba con la VPN.

### La firma de las actualizaciones

`sudo hehermes-servidor actualizar --paquete <tar.gz> --firma <tar.gz.sig>` no pasa por la app, así que no hay suma
que la ancle: se fía de una firma Ed25519 de Daniel, comprobada con
`openssl pkeyutl -verify -pubin -inkey /opt/hehermes-servidor/clave-publica.pem -rawin -in <tar.gz> -sigfile <sig>`.
Solo si la firma es buena desempaqueta (y solo ficheros y carpetas dentro de `hehermes-servidor-X.Y.Z/`) y lanza
`instalar --si` de la versión nueva, que repara hasta dejarlo todo al día. Solo actualiza una pasarela: sin ella (en un
servidor que solo tenga la VPN de antes), no instala nada ([arriba](#la-vpn-de-antes)).

- **Todo sobre una copia.** Antes de nada copia el paquete y su firma a una carpeta 0700 de root, y comprueba y abre
  la copia: quien pueda escribir donde está el original no puede cambiarlo entre la firma y el `tar`.
- **Sin vuelta atrás.** Una versión más vieja que la instalada no se instala aunque esté firmada: una vieja puede tener
  un fallo ya arreglado. La primera instalación sigue anclada a la suma SHA-256 que lleva la app.

- **No hay ninguna clave real.** `clave-publica.pem` es un marcador (`PENDIENTE-DE-DANIEL`) y, mientras lo sea,
  `actualizar` se niega. La privada irá en el llavero del Mac de Daniel, nunca en un servidor ni en el repositorio;
  cómo crearla está dentro del propio `clave-publica.pem`. Hace falta OpenSSL 3: el LibreSSL de macOS no sabe Ed25519.
- Las pruebas usan `tests/datos/clave-de-prueba-NO-ES-DE-DANIEL.pem`, marcada en el nombre y en el fichero.

## El alta por chat (`--por-chat`)

Es la pieza B de la spec: para quien solo habla con su Hermes por Telegram, WhatsApp o Slack. La app copia una frase
con este comando y con su **llave**, la clave pública X25519 de un par que acaba de crear (la privada se queda en su
llavero, 30 minutos y sin salir del iPhone). Hermes la ejecuta con su terminal:

```
… && ./hehermes-servidor-{versión}/hehermes-servidor instalar --por-chat --activar-api --iphone {nombre} --llave {llave}
```

- **Sin `sudo` delante, a propósito.** Hermes puede no correr como root ni tener sudo, y un `sudo` que pide contraseña
  fallaría antes de que el instalador pudiera explicar nada. Lo primero que hace, antes de detectar nada, es mirar los
  permisos (abajo, «Los permisos»).
- **No pregunta nada y no pinta el QR** (lo leería el modelo). Da el alta en la pasarela, lanza el canje y acaba con una
  sola línea, el enlace: `hehermes-canje:1?h={dirección}&p={puerto}&c={código}&f={huella}`. **No lleva ningún
  secreto:** sin la privada del iPhone no sirve de nada.
- **Lo que entrega el canje** es `{"h", "p", "f", "t"}` (la dirección, el puerto de la pasarela como número, su huella y
  el token), en ese orden, y nada más: el canje se niega a arrancar con otra cosa. Lo fija `tests/datos/canje-tls.json`,
  que comparte la app.
- **Solo el primer iPhone, y en la media hora siguiente a instalar** (decisión 7): se para si hay otro dado de alta (en
  la pasarela o en una VPN de antes), si este no se dio por chat, si ya se canjeó o si la instalación es de hace más de
  30 minutos (una sin fecha cuenta como vieja). Repetirlo dentro de la media hora, sin haberse canjeado, da un enlace
  nuevo con un token nuevo (el de antes no se puede recuperar, y deja de valer).
- **Sin root sí sigue:** el canje es una unidad de usuario (`systemd-run --user`, sin `DynamicUser` ni cortafuegos) con
  sus secretos en `/run/user/<uid>/hehermes-canje`.
- **`--activar-api`** (decisión 6): si la API de Hermes está apagada o sin clave, añade al final de su `.env` solo las
  líneas que faltan (`API_SERVER_ENABLED=true`, `API_SERVER_HOST=127.0.0.1`, una `API_SERVER_KEY` nueva que no se
  imprime), con una copia antes y sin cambiarle el dueño, y reinicia `hermes-gateway` **90 s después de acabar**, para
  no cortarle a Hermes el turno en el que contesta. Solo si Hermes es esa unidad. Desinstalar quita esas líneas si
  siguen tal cual.
- **`--qr-png <fichero>`** deja además el enlace en un PNG con su QR, por si Hermes puede mandar imágenes (con
  `qrencode`, si está).

### Los permisos

Antes de nada (`hehermes_servidor/permisos.py`), y sin pedir nunca una contraseña (`sudo -n`):

| Qué hay | Qué hace |
|---|---|
| root | Sigue |
| `sudo -n true` sale bien (sudo sin contraseña) | Se relanza a sí mismo: `sudo -n -u root -- /usr/bin/python3 -I -B <lanzador> <los mismos argumentos>` |
| sudo solo para `/usr/local/sbin/hehermes-servidor` (la salida 2), y el instalado es de esta versión | Se relanza con ese, que es de root: no ejecuta como root nada de la carpeta de Hermes |
| Nada de eso | `instalar` pone la pasarela como el usuario, en su casa ([arriba](#sin-root)). Lo demás (`comprobar`, `desinstalar`, `actualizar` sin una instalación suya), y un `instalar` cuya casa no se puede usar, se para sin haber ejecutado nada más que esas preguntas a sudo, y lo explica |

El mensaje dice qué falta (permisos de administrador), que no ha hecho nada, por qué (cada caso con el suyo) y dos
salidas, en este orden:

1. Que quien administre el servidor entre por SSH y ejecute **el mismo comando con `sudo`**. Si el paquete está al
   lado, se le da entero: descargarlo otra vez a una carpeta suya y comprobar la suma, para no ejecutar como root nada
   de la carpeta de otro usuario.
2. Que le dé al usuario de Hermes sudo **solo para el instalador**, una vez instalado (con 1, o con el comando de la app
   sin `--iphone`), con `sudo visudo -f /etc/sudoers.d/hehermes-servidor` y la línea
   `<usuario> ALL=(root) NOPASSWD: /usr/local/sbin/hehermes-servidor`. Por chat, dentro de la media hora siguiente a
   instalar (decisión 7).

**`hehermes-error:sin-permisos` ya no sale nunca.** Hasta la 0.6.0 era la última línea de ese mensaje por chat con
`--modo vpn`, para que la app la reconociera; sin VPN, un alta por chat sin root se instala como el usuario.

**El canje** (`hehermes_servidor/canje.py`) es una unidad temporal, `hehermes-canje`, lanzada con `systemd-run` para que
sobreviva al comando de Hermes:

| | |
|---|---|
| Quién | Con root, `DynamicUser=yes`, **sin ninguna capacidad** (`CapabilityBoundingSet=` vacío: un puerto alto no la pide), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `RestrictNamespaces`, `RestrictSUIDSGID`, `SystemCallFilter=@system-service`, `UMask=0077` y `RuntimeMaxSec=660`. Sin root, una unidad de usuario |
| Con qué | El venv de la pasarela (`/opt/hehermes-canje/venv`, o `~/.local/share/hehermes-venv` sin root), con `cryptography` fijada por hash (`requirements-canje.txt`) y el código por un `.pth` |
| Secretos | El token, el código, la llave y la clave del certificado del canje, en `/run/hehermes-canje` (0700, en memoria), y al canje por `LoadCredential` |
| Puerto | **Uno al azar entre el 58000 y el 65500** (los dos entran), de `secrets.randbelow`, libre en `ss -tan` (ni escuchando ni en una conexión); si está ocupado, el siguiente libre. En ufw, si está activo, `allow … port P comment hehermes-canje`; en firewalld, si está en marcha y el puerto no estaba abierto, `--add-port=P/tcp` solo en la configuración de ahora (nunca en la permanente); en nftables o iptables a pelo, en las mismas cadenas que las de siempre, con el comentario `hehermes-canje`. Solo mientras dure |
| TLS | 1.3, con un certificado ECDSA P-256 autofirmado para ese canje, con un nombre al azar y sin ningún dato (ni «hehermes»). La huella del enlace es el SHA-256 de su SPKI, y la app no acepta otra |
| Protocolo | `POST /canje/v1/reto {c}` devuelve un reto cifrado para la llave (el código no se gasta); `POST /canje/v1/canjear {c, reto}` devuelve `{h, p, f, t}` cifrado para la llave, y se cierra |
| Límites | 10 minutos, 5 fallos (o 3 de una IP), una petición por segundo y por IP, 20 conexiones por IP (la siguiente ni llega al TLS) y 1024 IP recordadas |
| A un escáner | Lo que no es un POST del protocolo (otra ruta, otro método, una petición rota, un cuerpo de más) recibe siempre el mismo `404` sin cuerpo y sin cabecera `Server`, y no gasta intentos |
| Al cerrarse | Por lo que sea, `ExecStopPost=+… canje-limpiar`, como root: fuera su regla (ufw, firewalld, nftables o iptables) y `/run/hehermes-canje`; si salió con 0 por sí mismo (se canjeó), lo apunta en el manifiesto y no hay otro alta por chat. Si no llega a arrancar, lo mismo antes de salir |

El sobre es el de los avisos, pero para una clave pública: una X25519 efímera por sobre, HKDF-SHA256 con la huella, el
código, el paso y las dos claves públicas dentro, y ChaCha20-Poly1305. Un sobre de otro servidor, de otro canje o del
otro paso no se abre. El segundo paso se sigue llamando «psk» (de cuando entregaba la PSK de la VPN): va dentro del
HKDF, y la app lo usa igual. Los vectores que lo fijan los comparten el servidor y la app:
`HeHermes/HeHermesMensajesTests/Fixtures/canje-vpn.json` (el sobre) y `canje-modo-tls.json`.

**Tras un reinicio** el canje ya no existe y `/run` está vacío; la regla de firewalld (solo en la de ahora) y la de
nftables o iptables se van con él, pero ufw guarda las suyas: la quita `hehermes-cortafuegos.service` al arrancar (y
también el siguiente `instalar --por-chat` y `desinstalar`). La app acepta cualquier puerto del enlace, del 1 al 65535
(`EnlaceDelCanje.leer`).

### Cifrado, de punta a punta

| Tramo | Cómo va |
|---|---|
| La frase y el enlace, por el chat | Sin ningún secreto: la llave es una clave pública X25519 y el enlace, dónde está el canje, un código de 128 bits y la huella del certificado. Sin la privada, que no sale del iPhone, no sirven |
| El canje | TLS 1.3 y la app ancla la SPKI del certificado (no se fía de ninguna autoridad ni del nombre). Dentro, el token va otra vez cifrado para la llave: X25519 efímera, HKDF-SHA256 atado a la huella, el código, el paso y las dos claves, y ChaCha20-Poly1305 |
| La pasarela | TLS 1.3 con la SPKI de su certificado anclada en la app, y un token de 256 bits por iPhone del que el servidor solo guarda el hash |
| De la pasarela a Hermes | En `127.0.0.1`, con la `API_SERVER_KEY` que pone la pasarela: no sale de la máquina |

## Cómo no pisa nada

- **Solo escribe en lo suyo** (`hehermes-*`, `/etc/hehermes*/`, `/opt/hehermes*`). Nunca Hermes, salvo las líneas
  de `--activar-api` y `--corregir-exposicion` en su `.env`, con una copia antes.
- **El manifiesto**, `/etc/hehermes/instalacion.json` (0600): cada fichero con su hash (o el destino, si es un enlace),
  las carpetas que creó, los paquetes que instaló, las reglas que puso, las unidades que habilitó y los usuarios que
  creó. Un fichero que no está en él es **ajeno**, y uno que está pero ha cambiado es **cambiado**: los dos paran el
  plan y se dice cuál. `--reemplazar <fichero>` lo sustituye, guardando antes una copia en `/etc/hehermes/copias/`, que
  desinstalar devuelve. Los tokens y la clave de Hermes de la pasarela son «gestionados»: suyos, pero sin comparar el
  hash, porque cambian.
- **Cada paso deja el manifiesto al día**, y uno que falla vuelve a como estaba: tras un fallo basta con repetir el
  comando.
- **Ningún cortafuegos se enciende.** ufw, firewalld, nftables e iptables reciben las reglas justas y marcadas; el del
  proveedor, un aviso. Una regla de ufw o firewalld que ya estaba (de otro) se queda como «ya está*» y desinstalar no
  la quita.
- **Nada de VPN.** Ni una instalación nueva ni una reparación tocan strongSwan, nginx, WireGuard ni XFRM.

## Qué detecta, sin cambiar nada

- **El sistema:** los de [la lista](#los-sistemas), en amd64 o arm64, con systemd y Python 3.9 o más (el de RHEL 9).
  En otro, se para al empezar sin haber ejecutado nada.
- **Hermes, de verdad:** la unidad `hermes-gateway` (y si está en marcha) o su proceso, su usuario y su `HERMES_HOME`;
  del `.env` (con `export`, comillas y comentarios) y del entorno de la unidad, que manda sobre él, `API_SERVER_ENABLED`,
  `API_SERVER_KEY`, `API_SERVER_HOST` y `API_SERVER_PORT`; que `GET /health` conteste 200 en `127.0.0.1` y que la clave
  valga en `GET /api/sessions?limit=1`. Cada fallo con su mensaje: no está, está instalado pero parado (la unidad, o
  solo su carpeta `.hermes`), su API está apagada, en su puerto contesta otra cosa, su clave no vale (o lleva algo que
  no puede ir en una cabecera). Varios Hermes se enumeran. La clave no se imprime nunca.
- **La dirección pública:** la de salida (`ip route get`); si es privada, `--direccion` o se pregunta en un terminal.
- **Lo que ya hay:** el puerto de la pasarela (uno libre), el cortafuegos (ufw, firewalld, nftables e iptables:
  [abajo](#los-cortafuegos)), `python3-venv`, el gestor de usuario y linger (sin root), y una VPN de HeHermes, hecha a
  mano o de antes, que no se toca.

### La API de Hermes, sin exponer

Si la API de Hermes escucha en todas las interfaces (`API_SERVER_HOST=0.0.0.0`, o lo que se ve en `ss`: `0.0.0.0`, `::`
o `*`), cualquiera que llegue al servidor habla con ella sin pasar por la pasarela, y solo la protege su clave. Se avisa
en rojo y **no se cambia sin permiso**, porque puede que otra cosa del usuario la use así:

- `--corregir-exposicion` añade `API_SERVER_HOST=127.0.0.1` al final del `.env` (con una copia antes, sin cambiarle el
  dueño) y reinicia `hermes-gateway` 90 s después de acabar, como `--activar-api`. Solo si Hermes es esa unidad.
- Si lo fija el entorno de la unidad (`Environment=`), o el `.env` ya dice 127.0.0.1, no se toca: se dice dónde está.
- Desinstalar **no** lo deshace (volvería a abrir la API) y lo dice.

### Los cortafuegos

`hehermes_servidor/cortafuegos.py`. Quién lo lleva, por este orden: firewalld en marcha (también en Debian) o en la
familia Red Hat; si no, ufw; y, siempre que no lo lleven ufw o firewalld por debajo, nftables con sus propias tablas e
iptables a pelo. En nftables e iptables no basta con añadir una tabla propia: un `accept` en otra cadena no salva a un
paquete del `drop` de la del usuario, así que las reglas van **dentro de su cadena**. En cada cadena de entrada
(`hook input`, `ip` o `inet`; las de iptables-nft y la de firewalld se dejan a su herramienta):

| Lo que hay | Qué hace |
|---|---|
| Deja pasar todo (sin `policy drop`, o acaba en un `accept` sin condiciones) | Nada |
| `policy drop` | La regla al final, detrás de las del usuario: sus `drop` concretos y sus listas negras siguen mandando |
| Un `drop` o un `reject` final sin condiciones | Justo antes de él (`insert … position`, o `iptables -I INPUT <n>`) |
| Acaba en un salto sin condiciones (`jump`, `goto`, `-j <cadena>`), o lo lleva un gestor que no conozco (Shorewall, CSF, ferm) | **Para y dice qué abrir**: el TCP de la pasarela y, por chat, el TCP del canje mientras dure. Con `--cortafuegos-a-mano` sigue sin tocarlo |
| No hay ninguno que cierre | Lo avisa, y **no enciende ninguno**: podría dejar fuera el SSH, y mejor que no sea el instalador quien lo haga |

Cada regla lleva el comentario `hehermes` (o `hehermes-canje`) y se quita buscándolo: ni una del usuario se reescribe.
**Sobreviven a un reinicio sin tocar lo guardado del usuario** (`/etc/nftables.conf`, `/etc/iptables/rules.v4`,
`/etc/sysconfig/iptables`): `hehermes-cortafuegos.service` va `After=`, `PartOf=` y `ReloadPropagatedFrom=`
`nftables.service`, `netfilter-persistent.service` e `iptables.service`, y con cada arranque o recarga de ellos quita
las suyas y las vuelve a poner donde toque ese día; al pararse, las quita. Desinstalar las quita, y si alguien guardó
el cortafuegos con ellas puestas (`netfilter-persistent save`), lo dice, sin tocar ese fichero. Solo IPv4: el QR lleva
la dirección IPv4 de salida.

## Los sistemas

| Familia | Cuáles | Cómo |
|---|---|---|
| Debian y Ubuntu | Debian 12 y 13; Ubuntu 22.04, 24.04 y 26.04 | ufw; `python3-venv` con apt, si falta |
| Sus derivadas | Por `ID_LIKE`: Linux Mint, Pop!_OS, Raspberry Pi OS, LMDE… Su base sale de `UBUNTU_CODENAME`, `DEBIAN_CODENAME` o `VERSION_CODENAME` | Como su base. Si la base no está en la lista (Mint 20, sobre Ubuntu 20.04) o no se sabe cuál es (Kali), lo avisa y sigue: lo que falte (Python, systemd) lo para igual |
| Red Hat | Rocky Linux, AlmaLinux, RHEL y CentOS Stream 9 y 10 (por `PLATFORM_ID`, también sus derivadas, como Oracle Linux, con aviso); Fedora 42 o más nueva | firewalld. Sin paquetes: su python3 ya trae venv, y la pasarela no necesita EPEL |

Lo demás (RHEL 8, Fedora 41, Amazon Linux, Arch, openSUSE…) se para al empezar, diciendo cuáles sí, sin haber
ejecutado nada.

## «Seguridad», en `comprobar`

`sudo hehermes-servidor comprobar` acaba con una sección «Seguridad» (`hehermes_servidor/seguridad.py`) que solo lee y
marca cada cosa con `bien`, `aviso` o `MAL`; con un `MAL`, sale con 1. La de la pasarela está
[arriba](#seguridad-en-la-pasarela). Mientras quede una VPN de HeHermes (la de antes, o una hecha a mano sin
manifiesto), mira también:

- que la API de Hermes solo escuche en 127.0.0.1 (en el `.env` y en lo que de verdad escucha);
- que el sitio del túnel solo escuche en `10.77.0.1:80`, que su `location /` niegue al propio servidor (el agujero del
  túnel, [en la historia](#el-agujero-del-túnel)) y que ningún otro sitio de nginx incluya `hehermes-bearer.conf`;
- el cortafuegos: quién lo lleva, y si a alguna cadena que cierra le faltan las reglas de HeHermes;
- que no quede ningún puerto del canje abierto sin un canje en marcha;
- que la PSK de cada iPhone, `hehermes-bearer.conf`, el manifiesto, las copias, la clave del vigía y `/run/hehermes-canje`
  solo los lea root, y que el `.env` de Hermes no lo lea nadie más que su dueño (su grupo, un aviso);
- que cada conexión IKEv2 acepte solo AES-256-GCM, PRF SHA-384 y ECP-384, con el túnel solo hasta 10.77.0.1, y que la
  PSK de las que dio `hehermes-dispositivo` tenga sus 44 caracteres (264 bits);
- con los avisos, que el vigía y el relé solo escuchen en 127.0.0.1;
- y si la clave de las firmas sigue siendo el marcador.

En el doble de un VPS montado a mano con la VPN (`tests/servidor_falso.py`, `servidor_de_daniel`, sin manifiesto) sale
esto; lo compara `tests/test_seguridad.py`:

<!-- seguridad-de-daniel -->
```
Seguridad
  bien  la API de Hermes solo escucha en 127.0.0.1:8642
  bien  nginx: el sitio del túnel solo escucha en 10.77.0.1:80
  MAL   nginx: la location / del túnel no niega a 10.77.0.1: cualquier proceso de este servidor usa la API de Hermes con su clave (el agujero del túnel)
  bien  cortafuegos: ufw, en marcha
  bien  canje: ninguno abierto, y ningún puerto suyo en el cortafuegos
  bien  secretos: la PSK de cada iPhone, la clave de Hermes en nginx, el .env y las copias, solo para su dueño
  bien  IKEv2: 1 conexión, solo AES-256-GCM con PRF SHA-384 y ECP-384, y el túnel solo hasta 10.77.0.1
  aviso IKEv2: hh-iphone-poc no la generó hehermes-dispositivo: no sé si su PSK es de 256 bits al azar
  aviso actualizar: la clave de las firmas todavía es el marcador, así que actualizar se niega (lo nuevo, con el comando de la app)
```
<!-- /seguridad-de-daniel -->

El `MAL` del agujero es el del sitio escrito a mano (`server/vpn/hehermes-tunel.nginx`), que el doble copia tal cual.
Lo arregla quitar esa VPN (a mano: no es del instalador), o cerrarlo con `deny 10.77.0.1;` al principio de su
`location /`.

## Decisiones de esta versión (0.6.0)

- **Sin VPN.** La conexión directa es el único modo: la app ya no usa la VPN, y mantener dos caminos al mismo Hermes era
  el doble de superficie. Lo que la reconoce y la quita se queda; lo que la creaba, se ha ido.
- **`actualizar` no convierte una VPN en pasarela por su cuenta.** Poner la pasarela abre un puerto a internet: lo decide
  quien lanza `instalar`, que ve el plan.
- **Sin avisos en el paquete.** Solo los instalaba `--avisos`, que necesitaba el nginx del túnel. Los avisos que ya
  estén en un servidor siguen funcionando: la pasarela les pasa `/avisos/`.

## Pruebas

```bash
# Con un venv que tenga cryptography (el de los avisos vale: server/avisos/README.md, «Pruebas»):
/tmp/hh-avisos/bin/python -I -B -m unittest discover -s server/instalador/tests -t server/instalador/tests
# En el sandbox de Claude Code, las del canje y las de la pasarela necesitan poder escuchar en 127.0.0.1
# (allowLocalBinding).
```

Las del canje (`tests/test_canje_*.py`) necesitan `cryptography` y no importan sin ella; las demás corren también con el
`python3` del sistema (`-p "test_[!c]*"`). Las del QR (`tests/test_qr.py`) se comparan con `segno` si está en el venv
(`pip install segno`, solo para las pruebas: al servidor no va); sin él, esas se saltan.

La pasarela también se prueba de verdad (`tests/test_pasarela_red.py`): TLS en 127.0.0.1 con el certificado de prueba
(`tests/datos/pasarela-NO-ES-DE-DANIEL.*`), un Hermes y un vigía de mentira detrás y un cliente que hace de iPhone: el
token, el 404 idéntico y su segundo de espera, la clave que se añade, el SSE evento a evento, las bajas que cortan un
SSE abierto, los límites y que el registro no lleva nada de la petición. Las de la lógica (tokens, límites, huella,
configuración), sin red, en `tests/test_pasarela_logica.py`; el instalador, con root, sin root, al lado de una VPN hecha
a mano y por chat, en `tests/test_modo_tls.py`; `hehermes-dispositivo`, en `tests/test_dispositivo_tls.py` (la
pasarela) y `tests/test_dispositivo_vpn.py` (las bajas de la VPN de antes, y que ya no da altas). El canje se prueba de
verdad: un servidor TLS en `127.0.0.1` y un cliente de Python que hace de iPhone (ancla la huella, abre el reto, canjea y
abre `{h, p, f, t}`). **En el Mac va con TLS 1.2:** el Python de Xcode trae LibreSSL 2.8, que no sabe 1.3, así que las
dos pruebas que lo exigen se saltan aquí y corren donde haya OpenSSL 3 (en el servidor, siempre).

Sin root, sin red y en el Mac: la raíz del `Sistema` es una carpeta temporal y las órdenes las contesta
`tests/servidor_falso.py`, un servidor de mentira con estado (paquetes, servicios, ufw o firewalld, SELinux, interfaces,
Hermes) que cambia con cada orden, como los dobles de `server/avisos/tests`, de la familia Debian (con sus derivadas) o
de la Red Hat (`tests/test_distros.py`). La VPN de antes la monta `tests/vpn_antigua.py` como la dejaba la 0.5.1, sin el
código que la instalaba. Cubren la detección caso a caso, el plan, instalar, repetir (0 cambios y ninguna orden que
cambie algo), reparar, deshacer lo que falla, desinstalar hasta dejar `/etc` exactamente como estaba (también la VPN de
antes), las órdenes, el paquete y la firma.

Lo que **no** está probado de verdad: una instalación en un Debian, un Ubuntu, una derivada o un Red Hat reales (en el
Mac no hay Docker ni Podman, ni máquinas virtuales); la unidad de sistema con su sandbox de verdad (que
`MemoryDenyWriteExecute`, `SystemCallFilter` sin `@resources`, `ProtectProc` y `LoadCredential` dejen correr al
`python3` de cada distribución), `useradd` y `userdel`, `systemctl --user` y `loginctl` de verdad (con y sin linger, y
lanzado desde Hermes, sin `XDG_RUNTIME_DIR`), `systemd-run` (y `--user`) para el canje con esas propiedades, `ufw delete`
con el comentario, `nft -j list ruleset` y `nft -f -` de verdad, `iptables -S` de iptables-nft y de iptables-legacy, que
`hehermes-cortafuegos.service` corra detrás de nftables, netfilter-persistent e iptables al arrancar y al recargarlos
(`ReloadPropagatedFrom=`), `sudo -n` y sus mensajes en cada distribución, crear el PNG con `seteuid`, el reinicio a los
90 s con `systemd-run --on-active`, `pip` desde el servidor, la pasarela y el canje con TLS 1.3 de OpenSSL 3 (en el Mac,
1.2) y contra un iPhone de verdad fuera de localhost, un Hermes de verdad ejecutando la frase, el QR leído por la cámara
(el dibujo es el de `segno` módulo a módulo, pero ninguna cámara lo ha visto), y la firma con OpenSSL 3 (la prueba que
la hace se salta en el Mac). De la VPN de antes: quitarla en un servidor real (`swanctl --load-all` y `--terminate`,
`nginx -t` y la recarga, `semanage port -d`), solo con el doble.

## Historia: la VPN IKEv2 (hasta la 0.5.1)

Hasta la 0.4.0 el instalador solo ponía una VPN IKEv2, la pieza A de
`docs/superpowers/specs/2026-09-24-instalador-servidor-design.md` (su plan,
`docs/superpowers/plans/2026-09-24-instalador-servidor.md`): la app la instalaba en el iPhone con un QR (`hehermes-vpn:`),
y nginx, dentro del túnel, le ponía a cada petición la clave de Hermes. La 0.5.0 trajo la pasarela como modo por
defecto, y la 0.5.1 dejó que los dos convivieran para pasar de uno a otro. La 0.6.0 la quita: la app ya solo habla con
la pasarela. Lo que dejaba en un servidor, y lo que quita `desinstalar --modo vpn`:

| Pieza | Qué dejaba |
|---|---|
| Paquetes | `charon-systemd`, `strongswan-swanctl`, `libstrongswan-standard-plugins`, `qrencode` y `nginx` (en la familia Red Hat, `strongswan`, `qrencode`, `nginx` y `policycoreutils-python-utils`, y arrancaba strongSwan) |
| Dispositivos | `/etc/hehermes/servidor.ini` (la dirección, el `.env` de Hermes, el registro y la carpeta de swanctl) y el registro en `/etc/hehermes/dispositivos`; cada iPhone, su conexión en `conf.d/hehermes-<nombre>.conf` con su PSK de 264 bits |
| Interfaz XFRM | `hehermes-xfrm.service` y `/usr/local/sbin/hehermes-xfrm`: `hh-ipsec` con `if_id 0x77`, `10.77.0.1/32` y la ruta a `10.77.1.0/24` |
| nginx | `/etc/nginx/sites-available/hehermes-tunel` y su enlace (o `conf.d/hehermes-tunel.conf`), `hehermes-bearer.conf` (0600) y el drop-in `nginx.service.d/hehermes-xfrm.conf`; si instalaba nginx, apagaba su sitio `default` |
| Cortafuegos | UDP 500 y 4500 abiertos a internet y el TCP 80 solo por `hh-ipsec` hacia `10.77.0.1` (ufw, firewalld con una regla rica, o nftables e iptables); en SELinux, `http_port_t` al puerto de Hermes |
| La clave de Hermes | `hehermes-clave.path`, que la copiaba a nginx con `hehermes-dispositivo clave` |
| Avisos (`--avisos`) | El `instalar.sh` de `server/avisos`: vigía, relé local y el lector de ficheros |

### Por qué UDP 500 y 4500 no eran aleatorios

La VPN nativa de iOS (IKEv2, `NEVPNProtocolIKEv2`) habla **siempre** por UDP 500 y, tras un NAT, por UDP 4500: iOS no
deja cambiarlos. Así que esos dos puertos quedaban abiertos a internet, y lo que los protegía era otra cosa: una PSK de
264 bits por iPhone, ligada a su identidad; solo AES-256-GCM, PRF SHA-384 y ECP-384 (strongSwan no negociaba nada más
débil); el túnel dividido, solo hasta `10.77.0.1`; y que strongSwan no le da nada útil a quien no se autentica (en IKEv2
el que inicia se autentica primero, y sin la PSK recibe `AUTHENTICATION_FAILED` sin la autenticación del servidor), sin
identificadores de versión y con su protección contra inundaciones encendida. La pasarela no tiene esa limitación: su
puerto es alto y al azar.

### El agujero del túnel

nginx ponía la clave de Hermes a todo lo que le llegaba a `10.77.0.1:80`, y los procesos del propio servidor llegan
desde `10.77.0.1`. En un sitio escrito a mano sin `allow` ni `deny`, como `server/vpn/hehermes-tunel.nginx`, eso deja
la API entera a cualquier usuario de la máquina. El sitio que escribía el instalador lo cerraba en su `location /` con
`deny 10.77.0.1; allow 10.77.1.0/24; deny all;`, el `deny` del servidor delante. «Seguridad» lo sigue mirando mientras
quede un sitio del túnel. La pasarela no tiene este problema: no pone la clave a quien no trae un token.

### Decisiones de entonces

- **Sin `hehermes-base.conf`:** las propuestas iban en la conexión de cada iPhone, que tenía su propio pool.
- **La XFRM, con un oneshot y no con systemd-networkd:** en Debian la red es de ifupdown, y encender networkd era
  tocarle la red a otro.
