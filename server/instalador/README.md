# hehermes-servidor: el instalador de un solo comando

En un Linux que ya tiene Hermes (Debian, Ubuntu y sus derivadas, o la familia Red Hat: [más abajo](#los-sistemas)), deja lo que necesita la app HeHermes para hablar con él y acaba pintando el QR
del iPhone en el terminal: **la conexión directa**, la pasarela (`hehermes-pasarela`). Un puerto TCP alto con TLS 1.3,
un certificado propio cuya huella ancla la app y un token por iPhone. **No necesita root**: sin él se instala en la casa
del usuario de Hermes. Es `docs/superpowers/specs/2026-09-26-pasarela-tls-design.md`, con su plan en
`docs/superpowers/plans/2026-09-26-pasarela-servidor.md`.

**Desde la 0.8.0, también los avisos push y el lector de ficheros, siempre y sin ningún comando más**: `instalar` pone
el vigía sin credencial, y la app le da en cada alta el permiso de su iPhone para el relé de Daniel (App Attest); y el
lector de los ficheros que Hermes marca con `MEDIA:`. Con un código de avisos (la 0.7.0), el vigía va con su credencial,
como antes ([abajo](#los-avisos-push-y-el-lector-de-ficheros-siempre-desde-la-080)).

**La 0.9.0 es la de la auditoría del 2026-09-29** ([abajo](#decisiones-de-la-090)): el lector de ficheros solo lee de
una lista de permitidas (las caches de Hermes y `<HERMES_HOME>/exports`, sin ninguna capacidad); la pasarela vuelve a
leer la clave de Hermes sin reiniciarse, no castiga a los iPhone de un CGNAT por los fallos de otros, tiene un
certificado siguiente para rotar sin volver a emparejar (`certificado rotar`) y apunta lo que la app borra de Hermes
para compactarlo de noche (`hehermes-borrado.timer`); por chat, la última línea vuelve a ser `hehermes-error:<código>`
cuando no se puede instalar, y sin linger no se da el enlace; `comprobar` se asoma también por la dirección del QR y
avisa de lo que quedó de la VPN.

**La 0.10.0 trae la copia de Hermes en iCloud** ([abajo](#la-copia-de-hermes-en-icloud-desde-la-0100)): el ayudante
`hehermes-respaldo`, con su socket, como el lector, y la pasarela deja pasar trozos de 4 MiB en `/avisos/v1/respaldo/`.

**La 0.10.1 reinicia lo que corre con código viejo.** Hasta la 0.10.0, actualizar solo reiniciaba la pasarela si
cambiaban su unidad, su configuración o sus certificados: la 0.10.0 sobre la 0.9.0 reescribió `/opt/hehermes-servidor`
y la pasarela siguió con el código de antes (el tope de 64 KiB en vez de 4 MiB en `/avisos/v1/respaldo/`). Ahora, si
cambia el código de un servicio que no se para, y está en marcha, se reinicia una vez, con root y sin él, y el plan lo
dice («se reinicia la pasarela: su código cambia»): [abajo](#cómo-no-pisa-nada).

**La 0.10.2 conecta cualquier Hermes bajo systemd, con perfiles o sin ellos.** Hasta la 0.10.1, `--activar-api` solo
sabía reiniciar la unidad `hermes-gateway`, y un probador con un perfil (`hermes-gateway-<perfil>.service`, como la
llama `hermes gateway install`) se quedó en `hehermes-error:api-apagada`. Ahora lo que se reinicia es lo que lleva el
proceso de Hermes, leído de su `/proc/<pid>/cgroup` (`hehermes_servidor/gestor.py`): su unidad, del sistema o de usuario
y se llame como se llame, o su contenedor; y todo lo de Hermes (su `.env`, su clave, su `exports/`, su `state.db`) es lo
de la casa de su perfil. Uno suelto (tmux, nohup) acaba en `reinicia-hermes`: [abajo](#el-alta-por-chat---por-chat).

**La 0.10.3 no deja a nadie sin salida por chat.** Con la 0.10.2, un probador canjeó el enlace mientras Hermes se
reiniciaba para encender su API; la app no se quedó con la conexión, y la misma frase otra vez acababa en «ya se canjeó».
Ahora el mismo iPhone (el mismo `--iphone`) puede volver a pedirla en la media hora siguiente a instalar: otro enlace,
otro token, y el de antes deja de valer. El canje dura 12 minutos y el reinicio de Hermes no lo toca: [abajo](#el-alta-por-chat---por-chat).

**La 0.10.4 mira el Hermes del probador antes de dar nada, y deja el chat abierto hasta que se use.** Tres cosas:
- **Lo que la app necesita de Hermes, antes del QR o del enlace** ([abajo](#el-hermes-que-necesita-la-app-desde-la-0104)):
  la sonda de sus capacidades (`hehermes_servidor/capacidades.py`, con `TRACE`, sin lanzar ni tocar nada) y su versión.
  A uno que no tiene algo que la app necesita (anterior a la **0.20.1**) se le para con `hehermes-error:hermes-antiguo`,
  su versión, lo que le falta y cómo actualizarlo; lo que la app puede no tener, se avisa. El plan y `comprobar` dicen su
  versión.
- **El alta por chat sigue abierta hasta que el iPhone que se dio de alta por chat usa la pasarela** (decisión 7, Daniel,
  2026-10-01; antes, la media hora siguiente a instalar): la pasarela apunta el primer 2xx de cada token en su
  `usos.json`. Mientras no la ha usado, la misma frase vuelve a dar un enlace, y uno nuevo (otro nombre) entra en su
  lugar: [abajo](#el-alta-por-chat---por-chat).
- **El `SOUL.md` de Hermes** (el de su perfil) lleva, una vez y con una copia antes, cómo mandar ficheros al iPhone
  (`<su casa>/exports` y una línea `MEDIA:<ruta>`); desinstalar lo quita: [abajo](#el-soulmd-de-hermes-desde-la-0104).

**Desde la 0.6.0 la pasarela es lo único que instala para conectar.** La VPN IKEv2 de las versiones anteriores ya no se instala, ni se repara,
ni se actualiza, y la app ya no la usa: `instalar --modo vpn` se para y dice que ya no existe. La de un servidor que la
tenga **se quita** con `desinstalar --modo vpn`, sin tocar la pasarela: [abajo](#la-vpn-de-antes), paso a paso.

```bash
sudo ./hehermes-servidor instalar --plan --iphone mi-iphone   # enseña lo que haría, sin cambiar nada
sudo ./hehermes-servidor instalar --iphone mi-iphone          # lo mismo, pregunta «¿Sigo? [s/N]» y lo hace
./hehermes-servidor instalar --iphone mi-iphone               # sin root: la pasarela, en la casa de este usuario
sudo hehermes-servidor instalar                               # repetirlo: «Todo al día: 0 cambios», o repara
sudo hehermes-servidor comprobar                              # lo que tiene que estar en marcha, y «Seguridad»
sudo hehermes-servidor certificado rotar                      # el certificado siguiente pasa a ser el de la pasarela
sudo hehermes-servidor desinstalar [--quitar-paquetes]        # enseña lo que quita, pregunta y lo quita
sudo hehermes-servidor desinstalar --modo vpn                 # solo la VPN de una versión anterior
sudo hehermes-dispositivo alta otro-iphone                    # otro iPhone, con el instalador ya puesto
sudo hehermes-servidor avisos                                 # los avisos con un código de avisos (se pega), si te lo dan
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
| La pasarela | `/etc/hehermes-pasarela/` (0750, `root:hh-pasarela`): `pasarela.ini` y `tokens.json` (0640, del grupo), `cert.pem` (0644), `clave.pem` (0600, de root), `clave-hermes` (0600, de `hh-pasarela`, que la lee sola), `siguiente/` (el certificado que viene después: su `cert.pem` 0644 y su `clave.pem` 0600 de root, sin usar hasta rotar) y, tras rotar, `anterior/`. **No** escribe `/etc/hehermes/servidor.ini`, que era de la VPN |
| La unidad | `hehermes-pasarela.service`: `User=hh-pasarela`, sin capacidades, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectProc=invisible`, `RestrictNamespaces`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` sin `@privileged` ni `@resources` y `UMask=0077`. La clave del certificado y (si están los avisos) el secreto del vigía le llegan con `LoadCredential`. Solo escribe en su `StateDirectory` (`/var/lib/hehermes-pasarela`: el borrado pendiente, su actividad y, desde la 0.10.4, `usos.json`: el primer 2xx de cada token, con su hash, su nombre y cuándo, sin nada de la petición). Un error de configuración sale con 78, que no se reinicia en bucle (`RestartPreventExitStatus=78`, `StartLimitBurst=5`) |
| La clave de Hermes | `hehermes-pasarela-clave.path` vigila el `.env` y, si cambia, `hehermes-servidor pasarela-clave` pone al día `clave-hermes`; desde la 0.9.0 la pasarela la vuelve a leer sola, **sin reiniciarse** (los SSE abiertos siguen) |
| El borrado de verdad | `hehermes-borrado.timer` (cada 15 minutos de 2:00 a 6:00): si la app ha borrado algo de Hermes, lo compacta con Hermes parado unos segundos ([abajo](#el-borrado-de-verdad)) |
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

## Los avisos push y el lector de ficheros, siempre (desde la 0.8.0)

Con la app cerrada, los avisos los pide el **vigía** (`server/avisos`), que vive al lado de Hermes, y los manda el
**relé de Daniel**, el único con la clave de Apple, por su entrada pública (HTTPS, con la huella de su certificado
anclada). Desde la 0.8.0 (spec `docs/superpowers/specs/2026-09-28-avisos-con-app-attest-design.md`), `instalar` pone el
vigía **siempre**, sin preguntar y se pueda repetir, por cualquiera de sus caminos (la frase del chat, `--por-chat`, o
el comando por SSH; con root o sin él):

- **Sin código de avisos, sin credencial.** `vigia.ini` lleva `[rele] url =` vacía y no hay ningún secreto del relé.
  La app, al darse de alta (la bienvenida, y cada registro después), le da al vigía **el permiso de su iPhone**: firmado
  por el relé tras comprobar con App Attest que es la app de verdad en un iPhone de verdad, atado a ese token y con
  caducidad, con la dirección, el puerto y la huella de la entrada pública. Cada aviso va con él
  (`Authorization: Permiso …`). Si el relé lo rechaza, el vigía lo olvida y, en el siguiente primer plano, le pide otro a
  la app. El probador no hace nada más.
- **Con un código de avisos** (el camino de la 0.7.0), el vigía va con la credencial de este servidor, como antes: lo
  de abajo.

Y **el lector de ficheros** (`hehermes-leer-media`, de `server/avisos/despliegue`), para que la app descargue lo que
Hermes marca con `MEDIA:` (`GET /avisos/v1/fichero`; sin él, 503).

| | Con root | Sin root |
|---|---|---|
| El lector | `/usr/local/libexec/hehermes-leer-media` (root 0755), el mismo que pone `instalar.sh` en el VPS de Daniel | La copia que va con el instalador en su casa (`~/.local/share/hehermes-servidor/hehermes-leer-media`) |
| Su socket | `hehermes-leer-media.socket`: `/run/hehermes-leer-media.sock`, `root:hh-vigia` 0660, `Accept=yes` | Una unidad de usuario: `%t/hehermes-leer-media.sock` (en `/run/user/<uid>`), 0600 |
| Cada lectura | `hehermes-leer-media@.service`: un lector por conexión, con la jaula del VPS de Daniel: desde la 0.9.0 **como el dueño de la casa de Hermes y sin ninguna capacidad** (root si Hermes es root), todo de solo lectura, sin red, las casas tapadas (`ProtectHome=tmpfs`) salvo las carpetas permitidas (`BindReadOnlyPaths`: `image_cache/`, `audio_cache/` y `exports/` de `--hermes-home`), y los secretos del sistema y de `/etc/hehermes-pasarela`, tapados | Un lector **como el usuario de Hermes** por conexión, con `--usuario`: solo atiende a su propio uid (`SO_PEERCRED`). Lo que una unidad de usuario no puede ponerse (`ProtectSystem`, `ProtectHome`, `InaccessiblePaths`, `PrivateNetwork`, `IPAddressDeny`, capacidades), no lo lleva, y la unidad lo dice: ahí lo que se lee lo decide solo el lector (su lista de permitidas, y la de prohibidas como segunda red); sin red lo deja `RestrictAddressFamilies=AF_UNIX` |
| El vigía | `[ficheros] lector = /run/hehermes-leer-media.sock` y su unidad lo quiere (`Wants=`) | `lector = /run/user/<uid>/hehermes-leer-media.sock` |
| Lo que se puede descargar | Solo lo que Hermes deja en sus caches o en **`<HERMES_HOME>/exports`**, que crea el instalador (0700, del dueño de Hermes; desinstalar la quita solo si está vacía). Un `MEDIA:/tmp/…` o `MEDIA:/root/informe.pdf` ya no se descarga: un 409 `fichero_fuera_de_la_carpeta` (desde los avisos 1.5.0), y la app ofrece pedirle a Hermes que lo copie a `exports`. A Hermes hay que decirle que deje ahí lo que quiera mandar al iPhone | Lo mismo, en `~/.hermes/exports` |
| La red del vigía sin credencial | Esta máquina e internet; las redes de dentro, no: `IPAddressDeny=` 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, fc00::/7 y fe80::/10 (el relé no se sabe al instalar) | Una unidad de usuario no puede filtrar direcciones: se lo impide el propio vigía, que resuelve la dirección del relé de cada permiso y no se conecta si no es pública |

### La copia de Hermes en iCloud (desde la 0.10.0)

Spec `docs/superpowers/specs/2026-09-29-respaldo-de-hermes-en-icloud-design.md`, contrato `server/API-CONTRACT.md` §15.
`instalar` pone también el ayudante `hehermes-respaldo` (de `server/avisos/despliegue`): hace las instantáneas de la
casa de Hermes que la app cifra y sube a iCloud, y restaura una copia (con `hermes import`, la copia de antes y el
deshacer de 7 días). Sin él, `/avisos/v1/respaldo/…` contesta 503.

| | Con root | Sin root |
|---|---|---|
| El ayudante | `/usr/local/libexec/hehermes-respaldo` (root 0755), el mismo que pone `instalar.sh` en el VPS de Daniel | La copia que va con el instalador (`~/.local/share/hehermes-servidor/hehermes-respaldo`) |
| Su socket | `hehermes-respaldo.socket`: `/run/hehermes-respaldo.sock`, `root:hh-vigia` 0660, `Accept=yes` | `%t/hehermes-respaldo.sock`, 0600, unidad de usuario |
| Cada orden | `hehermes-respaldo@.service`, **de root** (restaurar para y arranca `hermes-gateway` y escribe en la casa de Hermes; `hermes import` va como el dueño de Hermes): `ProtectSystem=full`, las capacidades justas, solo 127.0.0.1, los secretos del sistema y de HeHermes tapados | Como el usuario de Hermes, con `--usuario` (solo atiende a su uid). Restaurar para Hermes con `systemctl --user`: si Hermes es una unidad del sistema, las copias van y restaurar dice que no puede |
| Su carpeta | `/var/lib/hehermes-respaldo` (0700, `StateDirectory`) | `~/.local/state/hehermes-respaldo` |
| El vigía | `[respaldo] ayudante = /run/hehermes-respaldo.sock` y su unidad lo quiere (`Wants=`) | `ayudante = /run/user/<uid>/hehermes-respaldo.sock` |
| Desinstalar | Quita el ayudante y sus unidades; de su carpeta, las instantáneas. **La copia de antes de una restauración se queda** (lo dice): es lo que había en Hermes | Lo mismo |

Lo del código de avisos (la 0.7.0), que sigue valiendo: el código lo da Daniel (`sudo hehermes-rele credencial alta
<nombre>`, en su VPS):

```bash
sudo hehermes-servidor avisos                  # lo pide: se pega sin eco (no queda ni en la pantalla ni en el historial)
sudo hehermes-servidor avisos --plan           # lo mismo, sin cambiar nada
sudo ./hehermes-servidor instalar --iphone mi-iphone --avisos   # la pasarela y los avisos a la vez (también lo pide)
```

El código es `hehermes-avisos:1?h=<dirección>&p=<puerto>&f=<huella>&c=<credencial>`: la entrada pública del relé, la
huella de su certificado (el vigía la ancla: con otra, no manda ni un byte) y la credencial de este servidor ante el
relé. **Es secreto.** También vale `--avisos <código>` o `avisos <código>`, pero así queda en el historial del shell.
Contrato: `server/API-CONTRACT.md` §13; spec: `docs/superpowers/specs/2026-09-28-rele-para-probadores-design.md`.

| | Con root | Sin root |
|---|---|---|
| El usuario | `hh-vigia`, de sistema, sin casa ni shell | El de Hermes |
| El código | `hehermes_avisos/`, junto al del instalador; corre con el venv de `cryptography` (el del canje) | Lo mismo, en su casa |
| Configuración | `/etc/hehermes-avisos/vigia.ini` (`root:hh-vigia` 0640): Hermes, el relé (`https://…` y su huella) y dónde está cada secreto | `~/.config/hehermes-avisos/vigia.ini` (0600) |
| Secretos | En `/etc/hehermes-avisos/vigia/` (`hh-vigia` 0600): la credencial, el secreto con la pasarela y su copia de la clave de Hermes, que `pasarela-clave` pone al día cuando cambia el `.env` | La credencial y el secreto, 0600; la clave la lee del `.env` de Hermes (si cambia, `systemctl --user restart hehermes-vigia`) |
| Base de datos | `/var/lib/hehermes-vigia` (la crea systemd, 0700): los iPhone dados de alta, con su clave | `~/.local/state/hehermes-vigia` |
| Unidades | `hehermes-vigia.socket` (el 127.0.0.1:8790 es de systemd) y `hehermes-vigia.service`, con la jaula de la del VPS de Daniel y la red solo hacia esta máquina y la IP del relé (sin código, la de arriba) | `hehermes-vigia.service` de usuario, que abre su puerto |
| La pasarela | Le pasa `/avisos/` con el secreto del vigía (por `LoadCredential`); se reinicia una vez | Lo mismo, leyendo el secreto |

- **Se puede repetir.** Sin código, `instalar` repara el vigía con el de antes (la dirección, el puerto y la huella van
  en el manifiesto; la credencial, en su fichero), o lo deja sin credencial si nunca se dio ninguno (el manifiesto dice
  `"vigia": {"modo": "permisos"}`). Con otro código, cambia la credencial y reinicia el vigía.
- **Se pone al día.** Una instalación de la 0.6.0 (sin vigía) o de la 0.7.0 (sin avisos, o con su código) pasa a la
  0.8.0 con otro `instalar`, sin perder nada: los iPhone, el certificado y, si lo había, el código de avisos.
- **Se comprueba** al instalar (`vigia comprobar`: Hermes, su puerto, el lector de ficheros y, con credencial, el relé,
  sin mandar nada) y en `comprobar`, con el socket del lector. Si algo del vigía falla, se dice, **pero no para**: la
  pasarela ya funciona, y el relé es de otra máquina.
- **No toca** unos avisos puestos a mano (`/opt/hehermes-avisos`, los del VPS de Daniel, o los de la VPN de antes): ni
  su vigía, ni su lector, ni sus secretos. Sin código, el plan lo dice y sigue con la pasarela (que les pasa `/avisos/`);
  con un código, para.
- El vigía **contesta las entregas de los subagentes** con el turno de continuación de la app, como en el Hermes de
  Daniel (`[entregas]` de `vigia.ini`): es la única escritura que hace en Hermes.
- `desinstalar` (y `desinstalar --modo tls`) se lo lleva todo, base de datos y lector incluidos.

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
   `sudo ./hehermes-servidor-0.10.0/hehermes-servidor instalar --plan --iphone iphone-tls`. Tiene que decir «Aquí sigue
   la VPN IKEv2 que instaló una versión anterior», el TCP elegido y ningún «No puedo seguir».
2. **Instalarla:** lo mismo sin `--plan`, en un terminal (pinta el QR del token, que no se puede volver a pintar).
3. **Abrir el TCP de la pasarela en el cortafuegos del proveedor**, si tiene uno en su panel (el plan lo dice con su
   número): el del servidor ya lo abre el instalador.
4. **Comprobar:** `sudo hehermes-servidor comprobar`. La pasarela, toda `bien`, y un aviso de que la VPN sigue ahí.
5. **En el iPhone,** escanear el QR con la app HeHermes.
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
  - Aquí ya hay unos avisos puestos a mano (/opt/hehermes-avisos, los de server/avisos/despliegue/instalar.sh): ni el vigía ni el lector de ficheros los pongo yo, y lo suyo no lo toco

54 cambios.
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
server/instalador/empaquetar                                   # dist/hehermes-servidor-0.10.0.tar.gz y .sha256
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
  `clave-publica.pem`, `requirements-canje.txt`, este README, desde la 0.7.0 el código de los avisos
  (`hehermes_avisos/`, sus `.py`: el vigía) y, desde la 0.8.0, el lector de ficheros (`hehermes-leer-media`, de
  `server/avisos/despliegue`) y, desde la 0.10.0, el ayudante de la copia en iCloud (`hehermes-respaldo`, de ahí
  también). Ni pruebas ni `__pycache__`, ni el resto del despliegue a mano del relé.

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
- **Hasta que el iPhone que se dio de alta por chat usa la pasarela** (decisión 7, Daniel, 2026-10-01): en cuanto
  Hermes (o la pasarela) le contesta un 2xx a su token, el chat se cierra, y los demás van por SSH o desde la app. Lo
  apunta la pasarela, en `usos.json` (su carpeta de estado), el primer 2xx de cada token: su hash, su nombre y cuándo;
  cuenta un uso de ese nombre desde su alta (también con un token rotado por SSH), y se queda cerrado aunque se dé de
  baja. Mientras no la ha usado, se canjeara o no y pase el tiempo que pase:
  - la misma frase **para el mismo iPhone** (el mismo `--iphone`) da un enlace nuevo con un token nuevo (el de antes no
    se puede recuperar, y deja de valer);
  - la de **otro nombre** entra **en su lugar**: el token del de chat deja de valer. La app cambia de nombre si se
    reinstala (`iphone-` y cuatro cifras hexadecimales; la de la 0.10.2 era `mi-iphone` para todos), y el probador al
    que se le quedó la conexión a medias (su única petición dio un 502, con Hermes reiniciándose) no tenía otra salida.

  Se sigue parando si hay otro iPhone dado de alta por SSH (en la pasarela o en una VPN de antes), o si este nombre lo
  está y no se dio por chat. **Una pasarela de antes de la 0.10.4 no apuntaba los usos**: lo que falta lo dice su diario
  (`journalctl -u hehermes-pasarela`, sus líneas «ip método estado bytes»): si llega hasta antes del alta y desde
  entonces no hay ningún 2xx, sigue abierto; si hay uno, cerrado; y si no llega (un diario solo en memoria y un
  reinicio) o no hay diario, no se sabe, y no se reabre (`hehermes-error:por-chat`; por SSH, `hehermes-dispositivo
  rotar`). Hasta la 0.10.3 era «solo en la media hora siguiente a instalar».
- **El canje dura 12 minutos** (la frase promete diez; el enlace sale después de arrancarlo) y **es su propia unidad**
  (`systemd-run --unit=hehermes-canje`, ni `--scope` ni atada a Hermes): el reinicio de Hermes de `--activar-api`, a los
  90 s, no lo toca.
- **Sin root sí sigue:** el canje es una unidad de usuario (`systemd-run --user`, sin `DynamicUser` ni cortafuegos) con
  sus secretos en `/run/user/<uid>/hehermes-canje`.
- **`--activar-api`** (decisión 6): si la API de Hermes está apagada o sin clave, añade al final de su `.env` solo las
  líneas que faltan (`API_SERVER_ENABLED=true`, `API_SERVER_HOST=127.0.0.1`, una `API_SERVER_KEY` nueva que no se
  imprime), con una copia antes y sin cambiarle el dueño, y reinicia Hermes **90 s después de acabar**, para no cortarle
  el turno en el que contesta. Desinstalar quita esas líneas si siguen tal cual. Lo que se reinicia (desde la 0.10.2)
  es lo que lleva su proceso, según su `/proc/<pid>/cgroup`:
  - **una unidad del sistema**, se llame como se llame (`hermes-gateway`, la de un perfil `hermes-gateway-trabajo`, o
    cualquiera cuyo nombre o `ExecStart` sea de Hermes: una que no lo es, como `cron.service`, no se reinicia):
    `systemctl restart <unidad>`;
  - **una de usuario** (`hermes gateway install` sin `--system`): con root, `runuser -u <su usuario> -- env
    XDG_RUNTIME_DIR=/run/user/<uid> systemctl --user restart <unidad>`; sin root, si es suya, `systemd-run --user`;
  - **un contenedor** de Docker o Podman con la red del servidor (`--network host`): `docker restart <id>`; su casa es
    la del servidor que va montada en su `HERMES_HOME`. Con su propia red no se puede (`api-apagada`): una API en el
    127.0.0.1 del contenedor no la alcanza la pasarela;
  - **nada que se sepa reiniciar** (tmux, screen, nohup; con root): se añaden igual las líneas al `.env` (con su copia,
    y un apunte en `/etc/hehermes/api-pendiente.json` que la vez siguiente pasa al manifiesto, para que desinstalar las
    quite) y se para con `hehermes-error:reinicia-hermes`. La app le dice a la persona que le mande `/restart` a Hermes
    (su orden del chat, que lo reinicia también suelto) y le vuelva a pegar la frase: la API ya está encendida y sigue.
    Si además hay otra cosa que para, no se toca nada y el código es el de esa otra.
- **Con varios perfiles en marcha**, el que ha lanzado el instalador: por chat, el Hermes que es su antepasado (lo
  lanza su terminal), o el del `HERMES_HOME` que hereda. Si no se sabe, se enumeran (`varios-hermes`).
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
   `<usuario> ALL=(root) NOPASSWD: /usr/local/sbin/hehermes-servidor`. Por chat, mientras el iPhone que se dé de alta
   por chat no haya usado la pasarela (decisión 7).

**`hehermes-error:sin-permisos` ya no sale nunca.** Hasta la 0.6.0 era la última línea de ese mensaje por chat con
`--modo vpn`, para que la app la reconociera; sin VPN, un alta por chat sin root se instala como el usuario.

**Desde la 0.9.0, por chat, lo que no deja instalar acaba en `hehermes-error:<código>`**, sola y la última, y solo
antes de tocar nada (la app dice «No se ha cambiado nada», y es verdad), salvo `reinicia-hermes` (0.10.2), que sale
después de encender la API en el `.env` y que la app explica aparte. El texto de encima es para la persona; el
código, para la app (`ErrorDelInstalador`). La frase le pide a Hermes que acabe con esa línea; el instalador no le da
instrucciones a Hermes (la spec, «La frase», dice por qué):

| Código | Qué pasa |
|---|---|
| `nat` | La dirección de salida es privada: hace falta `--direccion <IP o nombre>` (no se descubre con un servicio de fuera) |
| `direccion` | No se sabe la dirección pública, o la dada no vale |
| `linger` | Sin root y sin linger (y no se ha podido encender): la pasarela se pararía al cerrarse la sesión. `sudo loginctl enable-linger <usuario>` |
| `sin-hermes`, `hermes-parado`, `varios-hermes` | No hay Hermes, está parado, o hay varios (`--hermes-home`) |
| `api-apagada`, `api-hermes`, `clave-hermes` | La API de Hermes apagada (y no se puede encender: sin `--activar-api`, o en un contenedor con su propia red), que no contesta o no en 127.0.0.1, o su `API_SERVER_KEY` que falta o no vale |
| `hermes-antiguo` | Desde la 0.10.4: a Hermes le falta algo que la app necesita (anterior a la 0.20.1, o uno al que le falta una ruta). Justo antes de la última línea va otra para la app: `hehermes-detalle:version=<la suya, o ?> minima=0.20.1 falta=<claves>` ([abajo](#el-hermes-que-necesita-la-app-desde-la-0104)) |
| `reinicia-hermes` | Hermes no corre bajo systemd ni en un contenedor: su API ya está encendida en el `.env`, y hay que reiniciarlo (`/restart`) y volver a lanzar lo mismo |
| `ensurepip`, `sin-disco`, `puerto`, `sistema`, `paquete` | Sin `python3-venv`, sin sitio (150 MB), sin puerto libre, un sistema que no sabe, o un paquete incompleto |
| `cortafuegos` | El cortafuegos cierra el paso y no se sabe abrir sin riesgo |
| `por-chat`, `nombre-iphone`, `ficheros-ajenos`, `avisos-a-mano`, `avisos-credencial` | Lo de siempre de cada uno (el texto lo dice) |
| `bloqueo` | Cualquier otro |

**El canje** (`hehermes_servidor/canje.py`) es una unidad temporal, `hehermes-canje`, lanzada con `systemd-run` para que
sobreviva al comando de Hermes:

| | |
|---|---|
| Quién | Con root, `DynamicUser=yes`, **sin ninguna capacidad** (`CapabilityBoundingSet=` vacío: un puerto alto no la pide), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `RestrictNamespaces`, `RestrictSUIDSGID`, `SystemCallFilter=@system-service`, `UMask=0077` y `RuntimeMaxSec=780`. Sin root, una unidad de usuario |
| Con qué | El venv de la pasarela (`/opt/hehermes-canje/venv`, o `~/.local/share/hehermes-venv` sin root), con `cryptography` fijada por hash (`requirements-canje.txt`) y el código por un `.pth` |
| Secretos | El token, el código, la llave y la clave del certificado del canje, en `/run/hehermes-canje` (0700, en memoria), y al canje por `LoadCredential` |
| Puerto | **Uno al azar entre el 58000 y el 65500** (los dos entran), de `secrets.randbelow`, libre en `ss -tan` (ni escuchando ni en una conexión); si está ocupado, el siguiente libre. En ufw, si está activo, `allow … port P comment hehermes-canje`; en firewalld, si está en marcha y el puerto no estaba abierto, `--add-port=P/tcp` solo en la configuración de ahora (nunca en la permanente); en nftables o iptables a pelo, en las mismas cadenas que las de siempre, con el comentario `hehermes-canje`. Solo mientras dure |
| TLS | 1.3, con un certificado ECDSA P-256 autofirmado para ese canje, con un nombre al azar y sin ningún dato (ni «hehermes»). La huella del enlace es el SHA-256 de su SPKI, y la app no acepta otra |
| Protocolo | `POST /canje/v1/reto {c}` devuelve un reto cifrado para la llave (el código no se gasta); `POST /canje/v1/canjear {c, reto}` devuelve `{h, p, f, t}` cifrado para la llave, y se cierra |
| Límites | 12 minutos, 5 fallos (o 3 de una IP), una petición por segundo y por IP, 20 conexiones por IP (la siguiente ni llega al TLS) y 1024 IP recordadas |
| A un escáner | Lo que no es un POST del protocolo (otra ruta, otro método, una petición rota, un cuerpo de más) recibe siempre el mismo `404` sin cuerpo y sin cabecera `Server`, y no gasta intentos |
| Al cerrarse | Por lo que sea, `ExecStopPost=+… canje-limpiar`, como root: fuera su regla (ufw, firewalld, nftables o iptables) y `/run/hehermes-canje`; si salió con 0 por sí mismo (se canjeó), lo apunta en el manifiesto, y por chat solo ese iPhone puede volver a pedirla (en la media hora). Si no llega a arrancar, lo mismo antes de salir |

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
  de `--activar-api` y `--corregir-exposicion` en su `.env` y, desde la 0.10.4, el párrafo de su `SOUL.md`
  ([abajo](#el-soulmd-de-hermes-desde-la-0104)), siempre con una copia antes.
- **El manifiesto**, `/etc/hehermes/instalacion.json` (0600): cada fichero con su hash (o el destino, si es un enlace),
  las carpetas que creó, los paquetes que instaló, las reglas que puso, las unidades que habilitó y los usuarios que
  creó. Un fichero que no está en él es **ajeno**, y uno que está pero ha cambiado es **cambiado**: los dos paran el
  plan y se dice cuál. `--reemplazar <fichero>` lo sustituye, guardando antes una copia en `/etc/hehermes/copias/`, que
  desinstalar devuelve. Los tokens y la clave de Hermes de la pasarela son «gestionados»: suyos, pero sin comparar el
  hash, porque cambian.
- **Cada paso deja el manifiesto al día**, y uno que falla vuelve a como estaba: tras un fallo basta con repetir el
  comando.
- **El código nuevo, con el servicio reiniciado** (desde la 0.10.1). La pasarela carga `hehermes-pasarela` y
  `hehermes_servidor/`, y el vigía, `hehermes_avisos/` y `hehermes_servidor/` (la clave de Hermes): si alguno de esos
  ficheros cambia y el servicio está en marcha, se reinicia una vez (`systemctl [--user] restart`); si no hay nada que
  cambie, nada. Antes de escribir el código, los que se van a reiniciar quedan en el manifiesto
  (`reinicios_pendientes`) hasta que se reinician: si el comando se para entre medias, repetirlo los reinicia igual. El
  lector, el ayudante de la copia (`Accept=yes`, uno por conexión), el borrado (lo lanza su temporizador), la clave de
  Hermes (su `.path`) y el canje (uno nuevo cada vez) arrancan de cero y cogen el código nuevo solos: ni se reinician
  ni se cortan (el borrado puede estar compactando la base de Hermes).
- **Ningún cortafuegos se enciende.** ufw, firewalld, nftables e iptables reciben las reglas justas y marcadas; el del
  proveedor, un aviso. Una regla de ufw o firewalld que ya estaba (de otro) se queda como «ya está*» y desinstalar no
  la quita.
- **Nada de VPN.** Ni una instalación nueva ni una reparación tocan strongSwan, nginx, WireGuard ni XFRM.

## Qué detecta, sin cambiar nada

- **El sistema:** los de [la lista](#los-sistemas), en amd64 o arm64, con systemd y Python 3.9 o más (el de RHEL 9).
  En otro, se para al empezar sin haber ejecutado nada.
- **Hermes, de verdad:** la unidad `hermes-gateway` (y si está en marcha) o su proceso, quién lo lleva (su cgroup: su
  unidad o su contenedor, arriba), su usuario y su `HERMES_HOME`, como lo decide Hermes al arrancar (el perfil de su
  orden, `-p trabajo`; un `HERMES_HOME` que ya es de un perfil; el perfil activo de `hermes profile use`, si no lo lanza un
  supervisor; o `~/.hermes`);
  del `.env` (con `export`, comillas y comentarios) y del entorno de la unidad, que manda sobre él, `API_SERVER_ENABLED`,
  `API_SERVER_KEY`, `API_SERVER_HOST` y `API_SERVER_PORT`; que `GET /health` conteste 200 en `127.0.0.1` y que la clave
  valga en `GET /api/sessions?limit=1`. Cada fallo con su mensaje: no está, está instalado pero parado (la unidad, o
  solo su carpeta `.hermes`), su API está apagada, en su puerto contesta otra cosa, su clave no vale (o lleva algo que
  no puede ir en una cabecera). Varios Hermes se enumeran. La clave no se imprime nunca. Desde la 0.10.4, también su
  versión y lo que la app necesita de su api_server (abajo).

### El Hermes que necesita la app (desde la 0.10.4)

La app solo se ha probado contra el Hermes de Daniel (el `main` del 2026-09-17, que dice «0.21.3»), y un probador puede
tener uno de hace meses: si le falta una ruta que la app usa, el alta sale bien y la app falla después sin decir por qué
(lo primero que pregunta al conectar, `GET /api/model/options`, no existe antes de la 0.19.1). `instalar` lo mira antes
de dar el QR o el enlace (`hehermes_servidor/capacidades.py`), y `comprobar` lo vuelve a mirar:

- **Sin efectos.** Con `TRACE` a la ruta de cada cosa, con un id que no existe y sin la clave: aiohttp (el api_server de
  Hermes) contesta a un método que una ruta no tiene con un 405 cuyo `Allow` dice los que sí tiene, y a una ruta que no
  existe con su 404, sin llegar a ningún manejador ni mirar la clave. Así se sabe si están `POST /v1/runs` o
  `PATCH /api/sessions/{id}` sin lanzar ningún turno, ni crear o tocar ninguna sesión, ni mandar nada. `OPTIONS` no
  sirve (el middleware de CORS de Hermes lo contesta él, con un 403). Antes se calibra con `TRACE /health`: si no da un
  405 con `GET` (otro servidor, o un Hermes que algún día lo conteste de otra forma), la sonda no vale y queda la
  versión. Comprobado contra aiohttp de verdad, con las rutas y los middlewares de Hermes (`tests/test_capacidades.py`).
- **Lo que necesita** (obligatorio: sin ello la app falla de forma confusa), con la versión de Hermes en que llegó, de sus
  etiquetas de GitHub (`NousResearch/hermes-agent`, la tabla de rutas de cada una): la bandeja, empezar una conversación,
  su historial y fijarla, archivarla o renombrarla (`GET`/`POST /api/sessions`, `GET …/messages`, `PATCH
  /api/sessions/{id}`: 0.15.0); mandar un mensaje y ver la respuesta mientras se escribe (`POST /v1/runs`,
  `GET /v1/runs/{id}/events`: 0.8.0); recuperarla y pararla (`GET /v1/runs/{id}`, `POST …/stop`: 0.12.0); aprobar una
  orden (`POST …/approval`: 0.14.0); el modelo (`GET /api/model/options`: 0.19.1); y escribir mientras trabaja
  (`POST …/steer`: **0.20.1**). **La mínima es la 0.20.1.**
- **Lo que la app puede no tener** (se avisa y sigue): el consumo de la ficha (`GET /api/sessions/{id}`), «Eliminar
  también de Hermes» (`DELETE /api/sessions/{id}`) y las tareas programadas (`GET /api/jobs`).
- **Lo que no se ve en las rutas, por la versión:** hasta la **0.21.1** Hermes no lleva a los subagentes en segundo plano
  (`delegation_id`), y antes de la 0.21.0 no reconoce un mensaje repetido (`Idempotency-Key`): la app funciona, pero se
  avisa. Lo que no se avisa, porque un `main` dice la versión publicada anterior (el de Daniel dice «0.21.3» y ya lo
  tiene): hasta la 0.21.3 el keepalive del SSE es cada 30 s, y la app, que corta a los 25 s sin nada, sigue el turno
  sondeando en los silencios largos.
- **Con la API apagada** (`--activar-api`) no hay a quién preguntar: vale la versión de su código (desde lo que ejecuta su
  proceso, su carpeta de trabajo o `<casa>/hermes-agent`, la de su instalador; en un contenedor, dentro de él): su
  `install-stamp.json`, el `__version__` de `hermes_cli` o su `pyproject.toml`. Uno anterior a la mínima se para antes de
  encender nada; si no se encuentra, se avisa y lo mira `comprobar`.
- **Lo que dice:** la versión en el plan (`Hermes … versión 0.21.3`) y en `comprobar`; a uno viejo, `hermes-antiguo` con
  su versión, lo que le falta (cada cosa con su ruta) y cómo actualizarlo: `hermes update` como su usuario o `/update` en
  su chat (lo actualiza y lo reinicia); en un contenedor, su imagen nueva. Por chat, antes de la última línea,
  `hehermes-detalle:version=0.19.0 minima=0.20.1 falta=modelo,desviar`, para la app.
- **La dirección pública:** la de salida (`ip route get`); si es privada, `--direccion` o se pregunta en un terminal.
- **Lo que ya hay:** el puerto de la pasarela (uno libre), el cortafuegos (ufw, firewalld, nftables e iptables:
  [abajo](#los-cortafuegos)), `python3-venv`, el gestor de usuario y linger (sin root), y una VPN de HeHermes, hecha a
  mano o de antes, que no se toca.

### La API de Hermes, sin exponer

Si la API de Hermes escucha en todas las interfaces (`API_SERVER_HOST=0.0.0.0`, o lo que se ve en `ss`: `0.0.0.0`, `::`
o `*`), cualquiera que llegue al servidor habla con ella sin pasar por la pasarela, y solo la protege su clave. Se avisa
en rojo y **no se cambia sin permiso**, porque puede que otra cosa del usuario la use así:

- `--corregir-exposicion` añade `API_SERVER_HOST=127.0.0.1` al final del `.env` (con una copia antes, sin cambiarle el
  dueño) y reinicia Hermes 90 s después de acabar, como `--activar-api` (su unidad o su contenedor). Suelto, no.
- Si lo fija el entorno de la unidad (`Environment=`), o el `.env` ya dice 127.0.0.1, no se toca: se dice dónde está.
- Desinstalar **no** lo deshace (volvería a abrir la API) y lo dice.

### El SOUL.md de Hermes (desde la 0.10.4)

La app solo descarga lo que Hermes marca con una línea `MEDIA:<ruta>`, y el lector solo sirve sus caches y
`<su casa>/exports`: Hermes no lo sabe solo (al de Daniel se lo dice su `SOUL.md`, puesto a mano). `instalar` le añade
al de cada Hermes, al final y una sola vez, este párrafo (`hehermes_servidor/alma.py`), con la carpeta como la ve él (en
un contenedor, la de dentro):

> ## Ficheros para el iPhone (HeHermes)
>
> Cuando quieras mandarme un fichero al iPhone (un PDF, una imagen, un informe…), guárdalo como un fichero normal (no un
> enlace ni una carpeta) en /root/.hermes/exports y, en tu respuesta, pon una línea aparte con MEDIA: y su ruta
> absoluta; por ejemplo, MEDIA:/root/.hermes/exports/informe.pdf. La app HeHermes solo descarga lo que está en esa
> carpeta.

- **El que usa Hermes:** el de su HERMES_HOME, que con un perfil es la casa del perfil (`agent/prompt_builder.py`,
  `load_soul_md`). El plan lo dice: «añado a SOUL.md cómo mandar ficheros al iPhone».
- **Con una copia antes** (`/etc/hehermes/copias`, o `~/.config/hehermes/copias` sin root), en bytes (no cambia ni uno de
  lo que había), sin cambiarle el dueño ni el modo. Lo añadido, tal cual, va al manifiesto: **desinstalar quita
  exactamente eso** (lo que se escribiera después se queda) y la copia; si alguien lo ha cambiado, no lo quita y lo dice.
- **No se toca** uno que ya lo dice (el título de arriba, o uno que ya habla de `MEDIA:` y de `exports`, como el de
  Daniel: «ya está*»), uno que no está o está vacío (Hermes usaría su personalidad de serie, y con solo este párrafo la
  perdería), uno que es un enlace, ni el de un perfil de una distribución (`distribution.yaml`: `hermes profile update`
  lo reescribe). Se avisa de cómo decírselo a mano.
- El texto no casa con ningún patrón del escáner de inyecciones de Hermes (`tools/threat_patterns.py`, de la 0.15.0 a
  `main`), que en las versiones anteriores a la 0.21.4, o en un perfil de una distribución, bloquea el fichero entero.

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

## Decisiones de la 0.10.4

- **La sonda, con `TRACE` y sin la clave.** Un `GET` a un run o a una sesión que no existe obligaría a distinguir el 404
  del recurso del de la ruta (y el `POST`, el `PATCH` o el `DELETE` llegarían a su manejador); el 405 de aiohttp con su
  `Allow` lo dice todo de una ruta sin que nada corra. La lista de lo que ve la sonda la escribe aparte la historia de
  Hermes de las pruebas (`servidor_falso.RUTAS_HERMES`), y las dos tienen que decir lo mismo.
- **La mínima la pone lo que se puede mirar** (la ruta del desvío, la 0.20.1); lo que no (los subagentes en segundo
  plano, la idempotencia de los turnos), se avisa por la versión, que en un `main` miente hacia abajo.
- **Por chat, otro nombre entra en lugar del de chat que no ha usado la pasarela.** La decisión de Daniel nombra «el
  mismo nombre»; pero la app cambia de nombre al reinstalarse, y la del probador de la 0.10.2 se llamaba «mi-iphone»
  (la de ahora le pondría `iphone-xxxx`): con solo el mismo nombre, el caso que lo motivó seguiría sin salida. Lo que
  una inyección puede hacer antes del primer uso es lo mismo con un nombre que con otro (`mi-iphone` se adivina).
- **Sin saber si se usó, cerrado.** Una pasarela de antes no apuntaba los usos: vale su diario solo si llega hasta el
  alta; si no, el chat no se reabre a ciegas.
- **El `SOUL.md`, solo si ya existe y dice algo.** Crear uno, o escribir en uno vacío, cambiaría la personalidad de
  Hermes; uno de una distribución lo reescribe `hermes profile update`.

## Decisiones de la 0.9.0

La auditoría del 2026-09-29 (§5, §7, §13, §14.5, §14.9), comprobada antes en el código:

- **El lector, con lista de permitidas.** La lista negra dejaba salir `/root/.bash_history`, `/var/log` o el cron si
  Hermes escribía la línea `MEDIA:`. Ahora solo las caches y `exports/` (lo pedido y lo resuelto en la misma permitida,
  la lista negra como segunda red), sin `CAP_DAC_READ_SEARCH` y con el núcleo tapando el resto de las casas.
- **La clave de Hermes sin reiniciar.** La copia es de `hh-pasarela` y la pasarela la vuelve a leer al cambiar;
  rotarla ya no corta los SSE.
- **CGNAT.** El cupo por IP (16) es solo de conexiones sin autenticar: las de un iPhone con su token no lo ocupan. El
  segundo del 404 se espera fuera del cupo (16 por IP y 256 en total). Una IP bloqueada por sus fallos ya no se queda
  sin pasarela: con token pasa, sin token se cierra al momento y solo 4 sin autenticar a la vez. Con el cupo lleno, una
  conexión sin autenticar de más de 3 s deja su sitio (slowloris).
- **El fuzz del HTTP** (`tests/test_pasarela_fuzz.py`) encontró que `$` casa delante de un «\n» final: con un token,
  una ruta o una cabecera con un salto suelto llegaba a Hermes. Ahora `fullmatch`, también en los validadores del
  instalador.
- **Rotar el certificado sin volver a emparejar.** `siguiente/` hecho de antemano, su huella en
  `GET /hehermes/v1/huellas` (con token) y `hehermes-servidor certificado rotar`. La app aún ancla una sola huella: lo
  que le falta está en `server/API-CONTRACT.md`, §12.7. Volver atrás: `anterior/cert.pem` y `anterior/clave.pem`
  encima de los de ahora, y `systemctl restart hehermes-pasarela`.
- **Por chat, los códigos y linger** (arriba, «Los permisos»).
- **El alcance, por la dirección del QR.** Desde dentro se distingue: otra máquina detrás de la dirección (mal), la
  dirección propia sin contestar (mal), la propia contestando (si la app no llega, es el cortafuegos del proveedor,
  que desde dentro no se ve), o un NAT (reenvía, o no se sabe y se dice qué abrir). La regla de ufw, aparte. La IP
  pública detrás de un NAT no se descubre sola: un servicio de eco de fuera sería una dependencia (y una fuga de que
  este servidor instala HeHermes) sin una forma robusta en la biblioteca estándar; por chat se para con
  `hehermes-error:nat` y se pide `--direccion`.
- **Los restos de la VPN**, en «Seguridad»: strongSwan en UDP 500/4500 y los sitios de nginx del túnel, con la orden
  exacta; nada se quita solo.
- **El borrado de verdad** (abajo).

### El borrado de verdad

«Eliminar también de Hermes» borra filas, pero SQLite deja lo borrado en páginas libres de `state.db` y en el índice
FTS, recuperable del disco. La pasarela apunta en su carpeta de estado que hay algo pendiente (solo desde cuándo) cuando
Hermes contesta 2xx a `DELETE /api/sessions/{id}`, y `hehermes-borrado.timer` lanza `hehermes-servidor borrado-seguro`
cada 15 minutos de 2:00 a 6:00. Con algo pendiente y un rato tranquilo (ninguna petición con Hermes, ni escrituras en
su `state.db`, en 10 minutos), para la unidad de Hermes (la de su perfil, o una de usuario, desde la 0.10.2), ejecuta `hermes sessions optimize` como el usuario de Hermes (o,
si ese Hermes no lo sabe, `optimize` de cada índice FTS5 y `VACUUM` con sqlite), lo vuelve a arrancar y espera a su
`/health`. Tope duro de 15 minutos; Hermes arrancado pase lo que pase; un intento por noche; a los tres fallos, para.
Si Hermes no es una unidad de systemd (o va en un contenedor), o sin root no es una unidad suya, no se intenta: `comprobar` dice cómo hacerlo a mano
(con Hermes parado, `HERMES_HOME=<su casa> hermes sessions optimize`). El estado, en `GET /hehermes/v1/mantenimiento`.

## Decisiones de la 0.8.0

- **Los avisos sin ningún comando.** El vigía va siempre, sin credencial, y cada iPhone trae su permiso (App Attest):
  el probador instala desde la bienvenida y ya está. El código de avisos sigue valiendo.
- **El lector de ficheros, también siempre.** Con root, como en el VPS de Daniel; sin root, como una unidad de usuario
  del usuario de Hermes, con lo que una unidad de usuario puede ponerse, y dicho lo que no.
- **La red del vigía sin credencial, a internet pero no a la red de dentro.** La dirección del relé la trae la app en
  cada alta, y el alta la puede mandar cualquiera con un token de la pasarela: el vigía solo acepta IP públicas o
  nombres, no se conecta a un nombre que resuelva a una privada y, con root, systemd le niega además las redes de
  dentro. Lo que cierra el paso a cualquier otro es la huella anclada.

## Decisiones de la 0.7.0

- **Los avisos, con un código.** El vigía vuelve, pero no con un relé propio: con el de Daniel, por su entrada pública,
  una credencial por servidor y la huella anclada. Sin código no se instala nada de los avisos.
- **El código se pega, no se escribe en la orden.** Lleva la credencial: `avisos` lo pide sin eco.
- **Un relé que no contesta no tumba la instalación.** Lo del relé es de otra máquina; lo que depende de este servidor
  (la pasarela) ya funciona, y los avisos llegarán cuando se arregle.

## Decisiones de la 0.6.0

- **Sin VPN.** La conexión directa es el único modo: la app ya no usa la VPN, y mantener dos caminos al mismo Hermes era
  el doble de superficie. Lo que la reconoce y la quita se queda; lo que la creaba, se ha ido.
- **`actualizar` no convierte una VPN en pasarela por su cuenta.** Poner la pasarela abre un puerto a internet: lo decide
  quien lanza `instalar`, que ve el plan.
- **Sin avisos en el paquete.** Solo los instalaba `--avisos`, que necesitaba el nginx del túnel. Los avisos que ya
  estén en un servidor siguen funcionando: la pasarela les pasa `/avisos/`. (La 0.7.0 los vuelve a traer, de otra
  forma: arriba.)

## Pruebas

```bash
# Con un venv que tenga cryptography (el de los avisos vale: server/avisos/README.md, «Pruebas»):
/tmp/hh-avisos/bin/python -I -B -m unittest discover -s server/instalador/tests -t server/instalador/tests
# En el sandbox de Claude Code, las del canje y las de la pasarela necesitan poder escuchar en 127.0.0.1
# (allowLocalBinding).
```

Las del canje (`tests/test_canje_*.py`) necesitan `cryptography` y no importan sin ella; las demás corren también con el
`python3` del sistema (`-p "test_[!c]*"`). Las del QR (`tests/test_qr.py`) se comparan con `segno` si está en el venv
(`pip install segno`, solo para las pruebas: al servidor no va); sin él, esas se saltan. Igual la sonda de las
capacidades de Hermes contra aiohttp de verdad (`tests/test_capacidades.py`, `ConAiohttp`), con `aiohttp` en el venv;
las demás de la sonda van contra Hermes de mentira de cada edad (`servidor_falso.RUTAS_HERMES`).

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
