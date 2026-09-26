# hehermes-servidor: el instalador de un solo comando

En un Linux que ya tiene Hermes (Debian, Ubuntu y sus derivadas, o la familia Red Hat: [más abajo](#los-sistemas)), deja lo que necesita la app HeHermes Mensajes para hablar con él y acaba pintando el QR
del iPhone en el terminal. Desde la 0.5.0 hay dos modos:

- **`--modo tls`, el de por defecto: la pasarela** (`hehermes-pasarela`). Un puerto TCP alto con TLS 1.3, un
  certificado propio cuya huella ancla la app y un token por iPhone. **No necesita root**: sin él se instala en la
  casa del usuario de Hermes. Es `docs/superpowers/specs/2026-09-26-pasarela-tls-design.md`, con su plan en
  `docs/superpowers/plans/2026-09-26-pasarela-servidor.md`; está [aquí abajo](#el-modo-tls-la-pasarela).
- **`--modo vpn`: la VPN IKEv2** que instala la propia app, como hasta la 0.4.0. Necesita root. Es la pieza A de
  `docs/superpowers/specs/2026-09-24-instalador-servidor-design.md` (su plan, `docs/superpowers/plans/2026-09-24-instalador-servidor.md`),
  y es todo lo que hay en este README desde [«El comando de la app»](#el-comando-de-la-app) salvo donde se diga.

Desde la 0.5.1 **los dos modos pueden convivir** en una misma instalación: `instalar --modo tls` sobre una VPN añade la
pasarela, y `instalar --modo vpn` sobre una pasarela añade la VPN, sin tocar lo del otro. `desinstalar --modo vpn` (o
`--modo tls`) quita solo ese modo. Así se pasa de la VPN a la pasarela sin dejar restos: [abajo](#los-dos-modos-a-la-vez),
paso a paso. Una instalación de antes (VPN) sigue en VPN al repetir `instalar` sin `--modo`.

```bash
sudo ./hehermes-servidor instalar --plan --iphone mi-iphone   # enseña lo que haría, sin cambiar nada
sudo ./hehermes-servidor instalar --iphone mi-iphone          # lo mismo, pregunta «¿Sigo? [s/N]» y lo hace
./hehermes-servidor instalar --iphone mi-iphone               # sin root: la pasarela, en la casa de este usuario
sudo hehermes-servidor instalar                               # repetirlo: «Todo al día: 0 cambios», o repara
sudo hehermes-servidor comprobar                              # lo que tiene que estar en marcha, y «Seguridad»
sudo hehermes-servidor desinstalar [--quitar-paquetes]        # enseña lo que quita, pregunta y lo quita
sudo ./hehermes-servidor instalar --modo vpn --iphone mi-iphone   # la VPN IKEv2 de siempre
sudo hehermes-servidor desinstalar --modo vpn                 # solo la VPN: la pasarela se queda como está
```

Más opciones de `instalar`: `--direccion <IP o nombre>` (la del QR, si el servidor está detrás de un NAT),
`--hermes-home <carpeta>` (si hay varios Hermes), `--avisos` (solo VPN), `--reemplazar <fichero>` (repetible), `--si`
(sin preguntar; sin un terminal es obligatorio), `--activar-api`, `--corregir-exposicion` (la API de Hermes, solo en
127.0.0.1: [abajo](#la-api-de-hermes-sin-exponer)), `--cortafuegos-a-mano` (el cortafuegos lo llevas tú:
[abajo](#los-cortafuegos)) y, para el alta por chat, `--por-chat --llave <llave> [--qr-png <fichero>]` (abajo).

## El modo TLS: la pasarela

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
| Código | `/opt/hehermes-servidor/` (con `hehermes-pasarela`), `/usr/local/sbin/hehermes-servidor` y `/usr/local/sbin/hehermes-dispositivo` (si no hay ya uno ajeno) |
| La pasarela | `/etc/hehermes-pasarela/` (0750, `root:hh-pasarela`): `pasarela.ini` y `tokens.json` (0640, del grupo), `cert.pem` (0644), `clave.pem` y `clave-hermes` (0600, de root). **No** escribe `/etc/hehermes/servidor.ini`, que es de la VPN |
| La unidad | `hehermes-pasarela.service`: `User=hh-pasarela`, sin capacidades, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectProc=invisible`, `RestrictNamespaces`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` sin `@privileged` ni `@resources` y `UMask=0077`. La clave del certificado, la de Hermes y (si están los avisos) el secreto del vigía le llegan con `LoadCredential` |
| La clave de Hermes | `hehermes-pasarela-clave.path` vigila el `.env` y, si cambia, `hehermes-servidor pasarela-clave` pone al día `clave-hermes` y reinicia la pasarela |
| Cortafuegos | Solo el TCP de la pasarela: `ufw allow proto tcp … port P comment hehermes`, `--add-port=P/tcp` en firewalld, o su regla en las cadenas de nftables o iptables, con `hehermes-cortafuegos.service` para después de un reinicio (lo mismo que en la VPN, [abajo](#los-cortafuegos)) |
| Paquetes | Ninguno, salvo `python3-venv` en Debian si a su Python le falta `ensurepip` |

### Sin root

Si no hay root, ni `sudo` sin contraseña (con él, se relanza como root, como en la VPN), el instalador **sigue** como
el usuario que lo lanza, que tiene que ser el de Hermes (lee su `.env`):

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
sudo hehermes-dispositivo alta <nombre> --tls   # el token nuevo y su QR hehermes-tls:1?…, solo en un terminal (y con sudo)
sudo hehermes-dispositivo baja <nombre>    # su token deja de valer, y su conexión se corta en un segundo
sudo hehermes-dispositivo rotar <nombre>   # otro token, y su QR; el de antes deja de valer
sudo hehermes-dispositivo lista            # todos, con su modo: tls, ikev2 o wireguard
```

`alta <nombre>` sin más da el alta en el modo que haya: la pasarela, o la VPN IKEv2 si es la VPN del instalador (la
que deja `/etc/hehermes/servidor.ini`). **Con los dos, no adivina:** se para y pide `--tls` o `--ikev2`. `baja` y
`rotar` lo buscan donde esté, y si el mismo nombre está en los dos, piden también cuál (`--tls` o `--ikev2`).

Sin root, lo mismo sin `sudo` (`~/.local/bin/hehermes-dispositivo`). El QR lleva el token, así que tiene las mismas
reglas que el de la VPN: se pinta solo en un terminal (como root, además, lanzado con `sudo`), y **no se puede volver
a pintar**, porque del token solo queda el hash: `qr <nombre>` de uno de la pasarela dice que se use `rotar`. Si ya
había un `/usr/local/sbin/hehermes-dispositivo` ajeno (el de una VPN hecha a mano), no se toca: el de la pasarela es
`/opt/hehermes-servidor/hehermes-dispositivo`. El QR no depende de `qrencode`: lo dibuja `hehermes_servidor/qr.py`
(modo byte, versiones 1 a 40), que las pruebas comparan módulo a módulo con `segno`.

### Por chat, en modo TLS

El canje de siempre ([abajo](#el-alta-por-chat---por-chat)), con la misma frase, el mismo enlace y el mismo sobre.
Lo que va dentro del sobre es `{"h", "p", "f", "t"}` (la dirección, el puerto de la pasarela como número, su huella y el
token), en vez de la PSK; lo fija `tests/datos/canje-tls.json`, que comparte la app. Sin root **sí** sigue: el canje es
una unidad de usuario (`systemd-run --user`, sin `DynamicUser` ni cortafuegos) con sus secretos en
`/run/user/<uid>/hehermes-canje`, y `hehermes-error:sin-permisos` solo sale en `--modo vpn`. Repetirlo en la media hora,
sin canjear, da un token nuevo (el de antes no se puede recuperar) y deja sin valor el anterior.

### Los dos modos a la vez

En el mismo manifiesto (`/etc/hehermes/instalacion.json`, con `"modos": ["vpn", "tls"]`), cada uno con lo suyo. Qué es
de cada modo lo decide `hehermes_servidor/modos.py` por la ruta, el nombre o el texto de cada cosa, no por lo que
apuntó cada pasada, así que vale también para un manifiesto de antes de la 0.5.1, que no dice de qué modo es (y es de
la VPN):

| | La VPN | La pasarela | Común (se va solo con `desinstalar` a secas) |
|---|---|---|---|
| Ficheros | `servidor.ini`, la XFRM, el sitio de nginx y su clave, el drop-in de nginx, `hehermes-clave.*` | `/etc/hehermes-pasarela/`, `hehermes-pasarela.service`, `hehermes-pasarela-clave.*` | `/opt/hehermes-servidor/`, `hehermes-servidor`, `hehermes-dispositivo`, `hehermes-cortafuegos.service` |
| Otras cosas | Las reglas de ufw o firewalld de IKEv2 y el TCP 80, SELinux, los paquetes (menos `python3-venv`), el `default` de nginx que apagó, las altas IKEv2 | La regla del TCP de la pasarela, el usuario `hh-pasarela`, sus tokens, el venv de `cryptography` | Las líneas de `--activar-api`, `python3-venv` |

- **`instalar`**, con `--modo`, instala o repara ese modo, y el otro no se toca (se ve en el plan: «Modo VPN IKEv2, al
  lado de la pasarela TLS (no la toco)»). Sin `--modo` y con los dos: sin `--iphone`, repasa los dos, primero la VPN y
  luego la pasarela, cada uno con su plan; con `--iphone`, el iPhone va a la pasarela, y lo dice.
- **Por chat, con los dos, el modo es la pasarela.** Es el de por defecto: no pide root ni el permiso de VPN del iPhone,
  y no choca con otra VPN que lleve (iOS solo deja una). La frase de la app no lleva `--modo`, y no hace falta. Y «el
  primer iPhone» (decisión 7) es el primero del servidor, de cualquiera de los dos: con un iPhone en la VPN, un alta por
  chat en la pasarela sería un segundo iPhone, y se para.
- **Las reglas de nftables o iptables** de los dos llevan la misma marca (`hehermes`) y se ponen juntas; quitar un modo
  vuelve a dejar solo las del otro.
- **`comprobar`** mira lo de los dos, y su «Seguridad» también (lo común, una vez).
- **`desinstalar --modo vpn`** quita solo la VPN: da de baja las altas IKEv2 (y corta sus sesiones), quita el sitio de
  nginx (y lo recarga), la XFRM, `hehermes-clave.path`, `servidor.ini`, el registro, las reglas de UDP 500 y 4500 y del
  TCP 80, y la etiqueta de SELinux. **`desinstalar --modo tls`**, solo la pasarela: su unidad, sus tokens, su
  certificado, su usuario, su regla y el venv (la VPN lo vuelve a crear si un día da un alta por chat). Lo del otro modo
  se queda byte a byte como estaba, y el manifiesto sigue, sin el modo quitado. Si es el único modo que hay, es lo mismo
  que `desinstalar`.
- **Los avisos** (`--avisos`) los instala la VPN, pero la pasarela también los sirve: `desinstalar --modo vpn` no se los
  lleva, y lo dice. `desinstalar` a secas, sí.

Lo prueba `tests/test_dos_modos.py`, con el doble de servidor: la pasarela sobre la VPN y la VPN sobre la pasarela,
repetir y reparar los dos, `comprobar` con los dos, y quitar cada uno dejando el otro **byte a byte** como estaría si
se hubiera instalado solo (con ufw y con nftables). Catorce fallos reintroducidos a propósito en `desinstalar.py` y
`modos.py` (un fichero, una unidad, una regla, el venv, nginx, el registro, las carpetas, el usuario o los avisos del
otro modo; las reglas de nftables del otro sin volver a poner; lo quitado sin olvidar) los caza alguna de esas pruebas.

#### De la VPN a la pasarela, paso a paso

Para un servidor con la VPN del instalador, como el VPS de Daniel (`mi-iphone` por IKEv2):

1. **Añadir la pasarela, sin tocar la VPN.** Primero el plan, que no cambia nada:
   `sudo ./hehermes-servidor-0.5.1/hehermes-servidor instalar --plan --modo tls --iphone iphone-tls`. Tiene que decir
   «Aquí ya está la VPN IKEv2 que instalé… las dos conviven», el TCP elegido y ningún «No puedo seguir».
2. **Instalarla:** lo mismo sin `--plan`, en un terminal (pinta el QR del token, que no se puede volver a pintar).
3. **Abrir el TCP de la pasarela en el cortafuegos del proveedor**, si tiene uno en su panel (el plan lo dice con su
   número): el del servidor ya lo abre el instalador.
4. **Comprobar:** `sudo hehermes-servidor comprobar`. Salen las líneas de los dos modos, y todo `bien`.
5. **En el iPhone,** escanear el QR con la app HeHermes Mensajes. La VPN sigue en el servidor: si algo falla, se vuelve
   a ella.
6. **Probarla unos días.** `sudo hehermes-dispositivo lista` dice por dónde entra cada iPhone (`tls` o `ikev2`).
7. **Cuando todo vaya por la pasarela, quitar la VPN:** `sudo hehermes-servidor desinstalar --modo vpn`. Enseña lo que
   quita (solo lo de la VPN, y `mi-iphone`), pregunta y lo quita. Con `--quitar-paquetes`, también strongSwan, nginx y
   qrencode, si los instaló él.
8. **Comprobar otra vez:** `sudo hehermes-servidor comprobar` ya solo habla de la pasarela, y `sudo hehermes-servidor
   instalar` dice «Todo al día: 0 cambios».

Lo que no está probado de verdad: todo esto en un servidor real (solo con el doble), y en particular que strongSwan y
nginx se queden bien al quitar solo la VPN en uno que los tenga también para otras cosas.

### Al lado de una VPN hecha a mano

El modo TLS no toca nada de la VPN: ni strongSwan, ni nginx, ni XFRM, ni `servidor.ini`, ni el registro de
`hehermes-dispositivo`. En un servidor con una VPN de HeHermes hecha a mano, como el VPS de Daniel, lo dice y sigue;
desinstalar la pasarela no la toca tampoco. Lo compara `tests/test_modo_tls.py` con el doble de su VPS. Esto es lo que
avisa el plan allí (`sudo hehermes-servidor instalar --plan --iphone mi-iphone`; lo compara
`tests/test_documentacion.py`):

<!-- pasarela-de-daniel -->
```
Hay que saber:
  - Si tu proveedor tiene un cortafuegos propio, en su panel, abre ahí el TCP 61234
  - Aquí hay una VPN de HeHermes (/etc/nginx/sites-available/hehermes-tunel, /etc/swanctl/conf.d/hehermes-poc.conf, /etc/wireguard/hehermes). No la toco: la pasarela va aparte, en su puerto, y las dos conviven
  - /usr/local/sbin/hehermes-dispositivo no es mío: no lo toco. Para los iPhone de la pasarela usa el mío: sudo /opt/hehermes-servidor/hehermes-dispositivo alta <nombre>

43 cambios.
```
<!-- /pasarela-de-daniel -->

### «Seguridad», en modo TLS

`comprobar` se asoma a la pasarela como lo haría cualquiera, sin token (`Sistema.sondear_pasarela`), y mira: que
negocie TLS 1.3 y no acepte 1.2, que sirva el certificado cuya huella va en los QR, que conteste el 404 de siempre y
sin `Server`; que la API de Hermes solo escuche en 127.0.0.1; que la clave del certificado, la de Hermes y el manifiesto
solo los lea su dueño, que `tokens.json` y `pasarela.ini` no los lea cualquiera y que en `tokens.json` no haya más que
hashes; con root, que la unidad lleve su usuario y su sandbox, el cortafuegos, el canje y la firma, como en la VPN.

## El comando de la app

El paquete es `hehermes-servidor-<versión>.tar.gz`, con una URL por versión que no cambia nunca, y la app lleva su
SHA-256 en el comando: si el fichero cambia, no se ejecuta. `mktemp -d` da una carpeta 0700, así que entre la suma y el
`sudo` nadie más puede tocar lo descargado.

```
d=$(mktemp -d) && cd "$d" && curl -fsSLO {url-base}/v{versión}/hehermes-servidor-{versión}.tar.gz && echo "{sha256}  hehermes-servidor-{versión}.tar.gz" | sha256sum -c - && tar -xzf hehermes-servidor-{versión}.tar.gz && sudo ./hehermes-servidor-{versión}/hehermes-servidor instalar --iphone {nombre}
```

`server/instalador/empaquetar` genera el paquete, su `.sha256` y esa línea ya rellena:

```bash
server/instalador/empaquetar                                   # dist/hehermes-servidor-0.5.1.tar.gz y .sha256
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
- **Lleva:** `hehermes-servidor`, `hehermes-pasarela` y `hehermes_servidor/`, `hehermes-dispositivo` (de `server/vpn`), `clave-publica.pem`,
  este README y `avisos/` (el código, `despliegue/` y `requirements.txt` de `server/avisos`). Ni pruebas ni `__pycache__`.

### La firma de las actualizaciones

`sudo hehermes-servidor actualizar --paquete <tar.gz> --firma <tar.gz.sig>` no pasa por la app, así que no hay suma
que la ancle: se fía de una firma Ed25519 de Daniel, comprobada con
`openssl pkeyutl -verify -pubin -inkey /opt/hehermes-servidor/clave-publica.pem -rawin -in <tar.gz> -sigfile <sig>`.
Solo si la firma es buena desempaqueta (y solo ficheros y carpetas dentro de `hehermes-servidor-X.Y.Z/`) y lanza
`instalar --si` de la versión nueva, que repara hasta dejarlo todo al día.

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
- **No pregunta nada y no pinta el QR** (la guarda de `qr` no lo deja, y lo leería el modelo). Da el alta IKEv2, lanza
  el canje y acaba con una sola línea, el enlace: `hehermes-canje:1?h={dirección}&p={puerto}&c={código}&f={huella}`.
  **No lleva ningún secreto:** sin la privada del iPhone no sirve de nada.
- **Solo el primer iPhone, y en la media hora siguiente a instalar** (decisión 7): se para si hay otro dado de alta, si
  este no se dio por chat, si ya se canjeó o si la instalación es de hace más de 30 minutos (una sin fecha cuenta como
  vieja). Repetirlo dentro de la media hora, sin haberse canjeado, da un enlace nuevo con la misma PSK, que nunca ha
  salido del servidor.
- **`--activar-api`** (decisión 6): si la API de Hermes está apagada o sin clave, añade al final de su `.env` solo las
  líneas que faltan (`API_SERVER_ENABLED=true`, `API_SERVER_HOST=127.0.0.1`, una `API_SERVER_KEY` nueva que no se
  imprime), con una copia antes y sin cambiarle el dueño, y reinicia `hermes-gateway` **90 s después de acabar**, para
  no cortarle a Hermes el turno en el que contesta. Solo si Hermes es esa unidad. Desinstalar quita esas líneas si
  siguen tal cual.
- **`--qr-png <fichero>`** deja además el enlace en un PNG con su QR, por si Hermes puede mandar imágenes.

### Los permisos

Antes de nada (`hehermes_servidor/permisos.py`), y sin pedir nunca una contraseña (`sudo -n`):

| Qué hay | Qué hace |
|---|---|
| root | Sigue |
| `sudo -n true` sale bien (sudo sin contraseña) | Se relanza a sí mismo: `sudo -n -u root -- /usr/bin/python3 -I -B <lanzador> <los mismos argumentos>` |
| sudo solo para `/usr/local/sbin/hehermes-servidor` (la salida 2), y el instalado es de esta versión | Se relanza con ese, que es de root: no ejecuta como root nada de la carpeta de Hermes |
| Nada de eso: no hay sudo, sudo pide contraseña (ni se intenta) o el usuario no está en sudoers | Para en seco, sin haber ejecutado nada más que esas preguntas a sudo, y lo explica |

El mensaje dice qué falta (permisos de administrador), que no ha hecho nada, por qué (cada caso con el suyo) y tres
salidas, en este orden:

1. Que quien administre el servidor entre por SSH y ejecute **el mismo comando con `sudo`**. Si el paquete está al
   lado, se le da entero: descargarlo otra vez a una carpeta suya y comprobar la suma, para no ejecutar como root nada
   de la carpeta de otro usuario.
2. Que le dé al usuario de Hermes sudo **solo para el instalador**, una vez instalado (con 1, o con el comando de la app
   sin `--iphone`), con `sudo visudo -f /etc/sudoers.d/hehermes-servidor` y la línea
   `<usuario> ALL=(root) NOPASSWD: /usr/local/sbin/hehermes-servidor`. Por chat, dentro de la media hora siguiente a
   instalar (decisión 7).
3. «No tengo forma de ser administrador»: la conexión directa, el modo por defecto (sin `--modo vpn`), no lo necesita.

Todo esto es del modo VPN: en modo TLS, sin root ni sudo, se instala como el usuario ([arriba](#sin-root)).

**Por chat, la última línea es `hehermes-error:sin-permisos`**, en lugar del enlace del canje, para que la app la
reconozca. El formato es `hehermes-error:<código>`, una sola línea, sola y la última, sin nada secreto; hoy el único
código es `sin-permisos`. Sin `--por-chat` (una persona en su terminal) no se imprime.

**El canje** (`hehermes_servidor/canje.py`) es una unidad temporal, `hehermes-canje`, lanzada con `systemd-run` para que
sobreviva al comando de Hermes:

| | |
|---|---|
| Quién | `DynamicUser=yes`, **sin ninguna capacidad** (`CapabilityBoundingSet=` vacío: un puerto alto no la pide), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `RestrictNamespaces`, `RestrictSUIDSGID`, `SystemCallFilter=@system-service`, `UMask=0077` y `RuntimeMaxSec=660` |
| Con qué | Su venv, `/opt/hehermes-canje/venv`, con `cryptography` fijada por hash (`requirements-canje.txt`, los mismos bloques que los avisos) y el código por un `.pth`. Hace falta `python3-venv` |
| Secretos | La PSK, el código, la llave y la clave del certificado, en `/run/hehermes-canje` (0700, en memoria), y al canje por `LoadCredential` |
| Puerto | **Uno al azar entre el 58000 y el 65500** (los dos entran), de `secrets.randbelow`, libre en `ss -tan` (ni escuchando ni en una conexión); si está ocupado, el siguiente libre. Alto y al azar, para que no sea fácil de encontrar. En ufw, si está activo, `allow … port P comment hehermes-canje`; en firewalld, si está en marcha y el puerto no estaba abierto, `--add-port=P/tcp` solo en la configuración de ahora (nunca en la permanente); en nftables o iptables a pelo, en las mismas cadenas que las de siempre, con el comentario `hehermes-canje`. Solo mientras dure |
| TLS | 1.3, con un certificado ECDSA P-256 autofirmado para ese canje, con un nombre al azar y sin ningún dato (ni «hehermes»). La huella del enlace es el SHA-256 de su SPKI, y la app no acepta otra |
| Protocolo | `POST /canje/v1/reto {c}` devuelve un reto cifrado para la llave (el código no se gasta); `POST /canje/v1/canjear {c, reto}` devuelve `{h, rid, lid, k}` cifrado para la llave, y se cierra |
| Límites | 10 minutos, 5 fallos (o 3 de una IP), una petición por segundo y por IP, 20 conexiones por IP (la siguiente ni llega al TLS) y 1024 IP recordadas |
| A un escáner | Lo que no es un POST del protocolo (otra ruta, otro método, una petición rota, un cuerpo de más) recibe siempre el mismo `404` sin cuerpo y sin cabecera `Server`, y no gasta intentos |
| Al cerrarse | Por lo que sea, `ExecStopPost=+… canje-limpiar`, como root: fuera su regla (ufw, firewalld, nftables o iptables) y `/run/hehermes-canje`; si salió con 0 por sí mismo (se canjeó), lo apunta en el manifiesto y no hay otro alta por chat. Si no llega a arrancar, lo mismo antes de salir |

El sobre es el de los avisos, pero para una clave pública: una X25519 efímera por sobre, HKDF-SHA256 con la huella, el
código, el paso y las dos claves públicas dentro, y ChaCha20-Poly1305. Un sobre de otro servidor, de otro canje o del
otro paso no se abre. El vector que lo fija lo comparten el servidor y la app:
`HeHermes/HeHermesMensajesTests/Fixtures/canje-vpn.json`.

**Tras un reinicio** el canje ya no existe y `/run` está vacío; la regla de firewalld (solo en la de ahora) y la de
nftables o iptables se van con él, pero ufw guarda las suyas: la quita `hehermes-cortafuegos.service` al arrancar (y
también el siguiente `instalar --por-chat` y `desinstalar`). La app acepta cualquier puerto del enlace, del 1 al 65535
(`EnlaceDelCanje.leer`).

### Cifrado, de punta a punta

| Tramo | Cómo va |
|---|---|
| La frase y el enlace, por el chat | Sin ningún secreto: la llave es una clave pública X25519 y el enlace, dónde está el canje, un código de 128 bits y la huella del certificado. Sin la privada, que no sale del iPhone, no sirven |
| El canje | TLS 1.3 y la app ancla la SPKI del certificado (no se fía de ninguna autoridad ni del nombre). Dentro, la PSK va otra vez cifrada para la llave: X25519 efímera, HKDF-SHA256 atado a la huella, el código, el paso y las dos claves, y ChaCha20-Poly1305 |
| La VPN | IKEv2 con PSK de 264 bits por iPhone; solo AES-256-GCM, PRF SHA-384 y ECP-384 (DH grupo 20), en IKE y en el Child, con PFS; el túnel es dividido y solo llega a `10.77.0.1/32` |
| Del túnel a Hermes | nginx en `10.77.0.1:80`, dentro del túnel, pone la clave de Hermes; de ahí a `127.0.0.1` no sale de la máquina |

### Por qué UDP 500 y 4500 no son aleatorios

La VPN nativa de iOS (IKEv2, `NEVPNProtocolIKEv2`) habla **siempre** por UDP 500 y, tras un NAT, por UDP 4500: iOS no
deja cambiarlos. Así que esos dos puertos quedan abiertos a internet, y lo que los protege es otra cosa:

- **Una PSK de 264 bits por iPhone**, al azar (`hehermes-dispositivo`), ligada a su identidad: no hay una clave común
  que adivinar, y cada una se puede dar de baja o rotar (`hehermes-dispositivo rotar <nombre>`) sin tocar las demás.
- **Solo AES-256-GCM, PRF SHA-384 y ECP-384**: strongSwan no negocia nada más débil (`proposals` sin `default`).
- **El túnel dividido, solo hasta `10.77.0.1`**: aunque alguien entrara, no llega a la red del servidor ni a internet
  por él, y nginx solo deja pasar a los iPhone de `10.77.1.0/24`.
- **strongSwan no le da nada útil a quien no se autentica.** Contesta al primer mensaje (`IKE_SA_INIT`: las propuestas
  y el Diffie-Hellman), como cualquier IKEv2; pero en IKEv2 el que inicia se autentica primero, y sin la PSK recibe
  `AUTHENTICATION_FAILED` sin la autenticación del servidor, así que no se lleva nada con lo que probar claves fuera de
  línea. No manda identificadores de versión (`send_vendor_id` va apagado de serie) y tiene su protección contra
  inundaciones (`dos_protection`, con cookies) encendida de serie.

## Qué deja

| Pieza | Qué deja |
|---|---|
| Paquetes | `charon-systemd`, `strongswan-swanctl`, `libstrongswan-standard-plugins`, `qrencode` y `nginx`, los que falten (`--no-install-recommends`). En la familia Red Hat, con dnf (`--setopt=install_weak_deps=False`): `strongswan`, `qrencode`, `nginx` y, con SELinux y sin `semanage`, `policycoreutils-python-utils`; y arranca strongSwan, que dnf deja parado (desinstalar lo para) |
| El instalador | `/opt/hehermes-servidor/` (su código, `hehermes-dispositivo` y la clave pública) y `/usr/local/sbin/hehermes-servidor`, para repetir, comprobar, actualizar o desinstalar sin la carpeta temporal |
| Dispositivos | `/usr/local/sbin/hehermes-dispositivo` (0750) y `/etc/hehermes/servidor.ini`, de donde lee la dirección del servidor, el `.env` de Hermes, la carpeta del registro (`/etc/hehermes/dispositivos`) y la de swanctl (`/etc/swanctl`, o `/etc/strongswan/swanctl` en la familia Red Hat) |
| Interfaz XFRM | `hehermes-xfrm.service` y `/usr/local/sbin/hehermes-xfrm`: `hh-ipsec` con `if_id 0x77`, `10.77.0.1/32` y la ruta a `10.77.1.0/24`, antes que strongSwan y nginx |
| nginx | `/etc/nginx/sites-available/hehermes-tunel` y su enlace (o `conf.d/hehermes-tunel.conf` si nginx no usa `sites-enabled`), `hehermes-bearer.conf` (0600) y el drop-in `nginx.service.d/hehermes-xfrm.conf`. Si nginx lo instala él, apaga el sitio `default` (y desinstalar lo devuelve) |
| ufw | `allow proto udp to any port 500,4500` y `allow in on hh-ipsec proto tcp to 10.77.0.1 port 80`, con el comentario `hehermes`. **No enciende ufw** |
| nftables o iptables a pelo | En cada cadena de entrada que cierra el paso, UDP 500 y 4500 y el TCP 80 por `hh-ipsec` hacia `10.77.0.1`, con el comentario `hehermes` ([abajo](#los-cortafuegos)) |
| `hehermes-cortafuegos.service` | Al arrancar, después del cortafuegos del sistema: vuelve a poner esas reglas y quita la del canje que un reinicio dejó en ufw |
| firewalld (en marcha, o en la familia Red Hat) | En la zona por defecto: `--add-port=500/udp`, `--add-port=4500/udp` y una regla rica que deja entrar el TCP 80 solo desde `10.77.1.0/24` hacia `10.77.0.1` (firewalld no sabe de «entra por hh-ipsec»). En marcha, en la configuración de ahora y en la permanente, **sin `--reload`**, que se llevaría las reglas de ahora de los demás; apagado, con `firewall-offline-cmd`. **No lo enciende** |
| SELinux (si está puesto) | `semanage port -a -t http_port_t -p tcp <puerto de Hermes>`, para que nginx llegue a Hermes, y nada más (no el booleano `httpd_can_network_connect`, que le dejaría llegar a todo); si el puerto ya lo tiene otro tipo, se para. Cada fichero que escribe, con `restorecon` |
| La clave de Hermes | `hehermes-clave.path` vigila el `.env` y, si cambia, `hehermes-clave.service` ejecuta `hehermes-dispositivo clave` |
| Avisos (`--avisos`) | El `instalar.sh` de `server/avisos`, tal cual: vigía, relé local y el lector de los ficheros que marca Hermes (`/usr/local/libexec/hehermes-leer-media` y `hehermes-leer-media.socket`, que desinstalar también quita) |
| El primer iPhone | `hehermes-dispositivo alta <nombre> --ikev2 --servidor <dirección>` y su `qr`, que se pinta directo en el terminal |

### El agujero del túnel, cerrado de fábrica

nginx pone la clave de Hermes a todo lo que le llega a `10.77.0.1:80`, y los procesos del propio servidor llegan desde
`10.77.0.1`. En un sitio escrito a mano sin `allow` ni `deny`, como `server/vpn/hehermes-tunel.nginx`, eso deja la API
entera a cualquier usuario de la máquina. El sitio que escribe el instalador lleva en su `location /`:

```nginx
deny 10.77.0.1;
allow 10.77.1.0/24;
deny all;
```

El `deny` del servidor va delante, para que siga cerrado aunque un día se abra más red. `comprobar` lo mira: pide
`http://10.77.0.1/health` desde el propio servidor y espera un **403**. En una instalación hecha a mano, el
instalador lo detecta, lo dice y no lo toca.

## Cómo no pisa nada

- **Solo escribe en lo suyo** (`hehermes-*`, `/etc/hehermes/`, `/opt/hehermes*`). Nunca `nginx.conf`,
  `strongswan.conf`, `swanctl.conf`, `ipsec.conf` ni Hermes.
- **El manifiesto**, `/etc/hehermes/instalacion.json` (0600): cada fichero con su hash (o el destino, si es un enlace),
  las carpetas que creó, los paquetes que instaló, las reglas que puso, las unidades que habilitó y lo que apagó. Un
  fichero que no está en él es **ajeno**, y uno que está pero ha cambiado es **cambiado**: los dos paran el plan y se
  dice cuál. `--reemplazar <fichero>` lo sustituye, guardando antes una copia en `/etc/hehermes/copias/`, que
  desinstalar devuelve. La clave de nginx es «gestionada»: suya, pero sin comparar el hash, porque rota.
- **Prueba antes y después:** si `nginx -t` ya fallaba, no empieza; si falla con el sitio nuevo, todo lo de nginx vuelve
  a como estaba. Cada paso deja el manifiesto al día, así que tras un fallo basta con repetir el comando.
- **Recarga, no reinicia:** nginx con `reload`, la XFRM con su `ExecReload` (idempotente, no corta los túneles) y
  strongSwan con `swanctl --load-all`, que hace `hehermes-dispositivo alta`. Un nginx o un strongSwan ajeno y parado
  para el plan: arrancarlos arrancaría también lo demás que sirven.
- **Ningún cortafuegos se enciende.** ufw, firewalld, nftables e iptables reciben las reglas justas y marcadas; el del
  proveedor, un aviso. Una regla de ufw o firewalld que ya estaba (de otro) se queda como «ya está*» y desinstalar no
  la quita.
- **Solo IKEv2.** Nada de WireGuard en una instalación nueva.

## Qué detecta, sin cambiar nada

- **El sistema:** los de [la lista](#los-sistemas), en amd64 o arm64, con systemd, apt o dnf, núcleo 4.19 o más y
  Python 3.9 o más (el de RHEL 9). En otro, se para al empezar sin haber ejecutado nada.
- **Hermes, de verdad:** la unidad `hermes-gateway` (y si está en marcha) o su proceso, su usuario y su `HERMES_HOME`;
  del `.env` (con `export`, comillas y comentarios) y del entorno de la unidad, que manda sobre él, `API_SERVER_ENABLED`,
  `API_SERVER_KEY`, `API_SERVER_HOST` y `API_SERVER_PORT`; que `GET /health` conteste 200 en `127.0.0.1` y que la clave
  valga en `GET /api/sessions?limit=1`. Cada fallo con su mensaje: no está, está instalado pero parado (la unidad, o
  solo su carpeta `.hermes`), su API está apagada, en su puerto contesta otra cosa, su clave no vale. Varios Hermes se
  enumeran. La clave no se imprime nunca.
- **La dirección pública:** la de salida (`ip route get`); si es privada, `--direccion` o se pregunta en un terminal.
- **Lo que ya hay:** nginx (y si sus sitios van por `sites-enabled` o `conf.d`), quién tiene el TCP 80 y los UDP 500 y
  4500, strongSwan con `ipsec.conf` (se para), las conexiones de swanctl (nombres `hh-*`, pools en `10.77.0.0/16`, el
  `if_id 0x77`, PSK para `%any`), otras redes en `10.77.0.0/16` (Docker), el cortafuegos (ufw, firewalld, nftables e
  iptables: [abajo](#los-cortafuegos)) y SELinux (`getenforce`, y la etiqueta del puerto de Hermes con
  `semanage port -l`).

### La API de Hermes, sin exponer

Si la API de Hermes escucha en todas las interfaces (`API_SERVER_HOST=0.0.0.0`, o lo que se ve en `ss`: `0.0.0.0`, `::`
o `*`), cualquiera que llegue al servidor habla con ella sin pasar por la VPN, y solo la protege su clave. Se avisa en
rojo y **no se cambia sin permiso**, porque puede que otra cosa del usuario la use así:

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
| `policy drop` | Las reglas al final, detrás de las del usuario: sus `drop` concretos y sus listas negras siguen mandando |
| Un `drop` o un `reject` final sin condiciones | Justo antes de él (`insert … position`, o `iptables -I INPUT <n>`) |
| Acaba en un salto sin condiciones (`jump`, `goto`, `-j <cadena>`), o lo lleva un gestor que no conozco (Shorewall, CSF, ferm) | **Para y dice qué abrir**: UDP 500 y 4500, el TCP 80 por `hh-ipsec` hacia `10.77.0.1` y, por chat, el TCP del canje mientras dure. Con `--cortafuegos-a-mano` sigue sin tocarlo |
| No hay ninguno que cierre | Lo avisa, y **no enciende ninguno**: podría dejar fuera el SSH, y mejor que no sea el instalador quien lo haga |

Cada regla lleva el comentario `hehermes` (o `hehermes-canje`) y se quita buscándolo: ni una del usuario se reescribe.
**Sobreviven a un reinicio sin tocar lo guardado del usuario** (`/etc/nftables.conf`, `/etc/iptables/rules.v4`,
`/etc/sysconfig/iptables`): `hehermes-cortafuegos.service` va `After=`, `PartOf=` y `ReloadPropagatedFrom=`
`nftables.service`, `netfilter-persistent.service` e `iptables.service`, y con cada arranque o recarga de ellos quita
las suyas y las vuelve a poner donde toque ese día; al pararse, las quita. Desinstalar las quita, y si alguien guardó
el cortafuegos con ellas puestas (`netfilter-persistent save`), lo dice, sin tocar ese fichero. Solo IPv4: el QR lleva
la dirección IPv4 de salida.
- **Una instalación a mano** (la de `server/vpn/README.md`). Sin `--adoptar` (que todavía no existe) no se toca.

## Los sistemas

| Familia | Cuáles | Cómo |
|---|---|---|
| Debian y Ubuntu | Debian 12 y 13; Ubuntu 22.04, 24.04 y 26.04 | apt, ufw |
| Sus derivadas | Por `ID_LIKE`: Linux Mint, Pop!_OS, Raspberry Pi OS, LMDE… Su base sale de `UBUNTU_CODENAME`, `DEBIAN_CODENAME` o `VERSION_CODENAME` | Como su base. Si la base no está en la lista (Mint 20, sobre Ubuntu 20.04) o no se sabe cuál es (Kali), lo avisa y sigue: lo que falte (Python, núcleo, systemd) lo para igual |
| Red Hat | Rocky Linux, AlmaLinux, RHEL y CentOS Stream 9 y 10 (por `PLATFORM_ID`, también sus derivadas, como Oracle Linux, con aviso); Fedora 42 o más nueva | dnf, firewalld, SELinux; strongSwan con su configuración en `/etc/strongswan/swanctl`; nginx por `conf.d`. En RHEL y sus reconstrucciones, strongSwan viene de **EPEL**: si no está, se para y dice cómo activarlo, sin activarlo él |

Lo demás (RHEL 8, Fedora 41, Amazon Linux, Arch, openSUSE…) se para al empezar, diciendo cuáles sí, sin haber
ejecutado nada. En la familia Red Hat, **los avisos (`--avisos`) todavía no**: su instalador usa apt, y se para si se
piden. El nginx de Red Hat trae en su `nginx.conf` un servidor de bienvenida en el TCP 80 de todas las direcciones; el
instalador no lo toca (no es suyo) y lo dice: el cortafuegos no abre el 80.

## Decisiones de esta versión

- **Sin `hehermes-base.conf`.** El pool `hh-pool` de `10.77.1.0/24` de la spec dejaría sin direcciones a
  `hehermes-dispositivo`, que da a cada iPhone su propio pool y cuenta como ocupado todo pool de un fichero ajeno. Las
  propuestas ya van en la conexión de cada iPhone.
- **La XFRM, con un oneshot y no con systemd-networkd** (el punto 1 de «Lo que sigue faltando» de `server/vpn/README.md`
  lo proponía con `Kind=xfrm`). La spec lo descarta: en Debian la red es de ifupdown, y encender networkd es tocarle la
  red a otro; con el oneshot, además, nginx arranca siempre después de que exista `10.77.0.1`.
- **Avisos, por defecto no:** el relé central todavía no existe (decisión 9). `--avisos` instala el vigía con un relé
  local, que contesta 503 hasta que tenga la `.p8`.

## Lo que se espera en un servidor montado a mano

Con strongSwan, nginx y ufw montados a mano como en `server/vpn/README.md` (una conexión `hh-iphone-poc` escrita a
mano, WireGuard, `hh-ipsec` hecha a mano y el sitio del túnel sin `allow` ni `deny`),
`sudo hehermes-servidor instalar --plan --iphone mi-iphone` pinta el plan entero (los paquetes y las reglas, «ya
está»; el sitio y el `hehermes-dispositivo` desplegado, «ajeno») y acaba así (lo compara `tests/test_documentacion.py`
con el doble de un servidor así):

<!-- plan-de-daniel -->
```
Hay que saber:
  - El sitio /etc/nginx/sites-available/hehermes-tunel deja que cualquier proceso de este servidor use la clave de Hermes (el agujero del túnel: su location / no niega a 10.77.0.1). Es tuyo y sigue abierto: no lo toco.
  - Si tu proveedor tiene un cortafuegos propio, en su panel, abre ahí UDP 500 y 4500

No puedo seguir:
  - Esto es una instalación hecha a mano. Encuentro:
      - la conexión hh-iphone-poc (/etc/swanctl/conf.d/hehermes-poc.conf)
      - wg0 con 10.77.0.1
      - hh-ipsec con 10.77.0.1
      - /usr/local/sbin/hehermes-dispositivo
      - /etc/nginx/sites-available/hehermes-tunel
      - /etc/wireguard/hehermes (dispositivos de WireGuard)
    Sin --adoptar no la toco, y --adoptar todavía no existe
  - /usr/local/sbin/hehermes-dispositivo no es mío (no está en mi manifiesto): no lo toco. Si quieres que lo sustituya, guardando antes una copia: --reemplazar /usr/local/sbin/hehermes-dispositivo
  - /etc/nginx/sites-available/hehermes-tunel no es mío (no está en mi manifiesto): no lo toco. Si quieres que lo sustituya, guardando antes una copia: --reemplazar /etc/nginx/sites-available/hehermes-tunel

No sigo: no he cambiado nada. Arregla lo de arriba y vuelve a lanzarme.
```
<!-- /plan-de-daniel -->

Es lo que tiene que salir: no toca nada ajeno y dice que el agujero sigue abierto. Lo que cambiaría eso es
`--adoptar`, que no existe todavía.

## «Seguridad», en `comprobar`

`sudo hehermes-servidor comprobar` acaba con una sección «Seguridad» (`hehermes_servidor/seguridad.py`) que solo lee y
marca cada cosa con `bien`, `aviso` o `MAL`; con un `MAL`, sale con 1. Mira:

- que la API de Hermes solo escuche en 127.0.0.1 (en el `.env` y en lo que de verdad escucha);
- que el sitio del túnel solo escuche en `10.77.0.1:80`, que su `location /` niegue al propio servidor y que ningún otro
  sitio de nginx incluya `hehermes-bearer.conf`;
- el cortafuegos: quién lo lleva, y si a alguna cadena que cierra le faltan las reglas de HeHermes;
- que no quede ningún puerto del canje abierto sin un canje en marcha;
- que la PSK de cada iPhone, `hehermes-bearer.conf`, el manifiesto, las copias, la clave del vigía y `/run/hehermes-canje`
  solo los lea root, y que el `.env` de Hermes no lo lea nadie más que su dueño (su grupo, un aviso);
- que cada conexión IKEv2 acepte solo AES-256-GCM, PRF SHA-384 y ECP-384, con el túnel solo hasta 10.77.0.1, y que la
  PSK de las que da `hehermes-dispositivo` tenga sus 44 caracteres (264 bits);
- con los avisos, que el vigía y el relé solo escuchen en 127.0.0.1;
- y si la clave de las firmas sigue siendo el marcador.

En el doble del VPS de Daniel (`tests/servidor_falso.py`, `servidor_de_daniel`: montado a mano, sin manifiesto) sale
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

El `MAL` del agujero es el del sitio escrito a mano (`server/vpn/hehermes-tunel.nginx`), que el doble copia tal cual; si
en el VPS ya se ha cerrado a mano (`deny 10.77.0.1;` al principio de su `location /`), esa línea sale `bien`.

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
configuración), sin red, en `tests/test_pasarela_logica.py`; el modo TLS del instalador, con root, sin root, al lado de
la VPN de Daniel y por chat, en `tests/test_modo_tls.py`. El canje se prueba de verdad: un servidor TLS en `127.0.0.1` y un cliente de
Python que hace de iPhone (ancla la huella, abre el reto, canjea y abre la PSK). **En el Mac va con TLS 1.2:** el Python
de Xcode trae LibreSSL 2.8, que no sabe 1.3, así que las dos pruebas que lo exigen se saltan aquí y corren donde haya
OpenSSL 3 (en el servidor, siempre).

Sin root, sin red y en el Mac: la raíz del `Sistema` es una carpeta temporal y las órdenes las contesta
`tests/servidor_falso.py`, un servidor de mentira con estado (paquetes, servicios, ufw o firewalld, SELinux, interfaces,
Hermes) que cambia con cada orden, como los dobles de `server/avisos/tests`, de la familia Debian (con sus derivadas) o
de la Red Hat (`tests/test_distros.py`). Cubren la detección caso a caso, el plan, instalar,
repetir (0 cambios y ninguna orden que cambie algo), reparar, deshacer lo que falla, desinstalar hasta dejar `/etc`
exactamente como estaba, las órdenes, el paquete y la firma.

Lo que **no** está probado de verdad: una instalación en un Debian, un Ubuntu, una derivada o un Red Hat reales (en el
Mac no hay Docker ni Podman, ni máquinas virtuales), y por tanto los nombres de las unidades de cada distribución (que
en Fedora y EPEL `strongswan.service` sea el de swanctl), las rutas de strongSwan en `/etc/strongswan/swanctl`, que
firewalld ponga `hh-ipsec` en la zona por defecto, la regla rica, `semanage` y `restorecon` de verdad, que el `swanctl.conf` de serie
incluya `conf.d`, el JSON de `ip -d -j link` para una XFRM y la salida de `ufw show added`; un cliente strongSwan de
Linux llegando por el túnel a `http://10.77.0.1/health`; y la firma con OpenSSL 3 (la prueba que la hace se salta en
el Mac y corre donde lo haya). Del alta por chat, además: `systemd-run` con esas propiedades (sobre todo
`ExecStopPost=+` y `LoadCredential` con `DynamicUser`, y que `CapabilityBoundingSet=` vacío y `SystemCallFilter` dejen
correr al canje), `ufw delete` con el comentario, `nft -j list ruleset` y `nft -f -` de verdad, `iptables -S` de iptables-nft y
de iptables-legacy, que `hehermes-cortafuegos.service` corra detrás de nftables, netfilter-persistent e iptables al arrancar
y al recargarlos (`ReloadPropagatedFrom=`), `sudo -n` y sus mensajes en cada distribución, crear el PNG con `seteuid`, el reinicio a los 90 s con `systemd-run --on-active`, `pip` desde el servidor, el canje con TLS 1.3 de
verdad y un Hermes de verdad ejecutando la frase.

De la pasarela, además: la unidad de sistema con su sandbox de verdad (que `MemoryDenyWriteExecute`,
`SystemCallFilter` sin `@resources`, `ProtectProc` y `LoadCredential` dejen correr al `python3` de cada distribución),
`useradd` y `userdel`, `systemctl --user` y `loginctl` de verdad (con y sin linger, y lanzado desde Hermes, sin
`XDG_RUNTIME_DIR`), `systemd-run --user` para el canje, la pasarela con TLS 1.3 de OpenSSL 3 (en el Mac, 1.2) y contra un
iPhone de verdad fuera de localhost, y el QR leído por la cámara (el dibujo es el de `segno` módulo a módulo, pero ninguna
cámara lo ha visto).
