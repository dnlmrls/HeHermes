# hehermes-servidor: el instalador de un solo comando

En un Linux que ya tiene Hermes (Debian, Ubuntu y sus derivadas, o la familia Red Hat: [más abajo](#los-sistemas)), deja lo que necesita la app HeHermes Mensajes para hablar con él por la
VPN IKEv2 que instala ella misma, y acaba pintando el QR del iPhone en el terminal. Es la pieza A de
`docs/superpowers/specs/2026-09-24-instalador-servidor-design.md`; el plan con el que se hizo está en
`docs/superpowers/plans/2026-09-24-instalador-servidor.md`.

```bash
sudo ./hehermes-servidor instalar --plan --iphone mi-iphone   # enseña lo que haría, sin cambiar nada
sudo ./hehermes-servidor instalar --iphone mi-iphone          # lo mismo, pregunta «¿Sigo? [s/N]» y lo hace
sudo hehermes-servidor instalar                               # repetirlo: «Todo al día: 0 cambios», o repara
sudo hehermes-servidor comprobar                              # nginx, strongSwan, hh-ipsec, el cortafuegos, Hermes y el túnel
sudo hehermes-servidor desinstalar [--quitar-paquetes]        # enseña lo que quita, pregunta y lo quita
```

Más opciones de `instalar`: `--direccion <IP o nombre>` (la del QR, si el servidor está detrás de un NAT),
`--hermes-home <carpeta>` (si hay varios Hermes), `--avisos`, `--reemplazar <fichero>` (repetible), `--si` (sin
preguntar; sin un terminal es obligatorio), `--activar-api` y, para el alta por chat, `--por-chat --llave <llave>
[--qr-png <fichero>]` (abajo).

## El comando de la app

El paquete es `hehermes-servidor-<versión>.tar.gz`, con una URL por versión que no cambia nunca, y la app lleva su
SHA-256 en el comando: si el fichero cambia, no se ejecuta. `mktemp -d` da una carpeta 0700, así que entre la suma y el
`sudo` nadie más puede tocar lo descargado.

```
d=$(mktemp -d) && cd "$d" && curl -fsSLO {url-base}/v{versión}/hehermes-servidor-{versión}.tar.gz && echo "{sha256}  hehermes-servidor-{versión}.tar.gz" | sha256sum -c - && tar -xzf hehermes-servidor-{versión}.tar.gz && sudo ./hehermes-servidor-{versión}/hehermes-servidor instalar --iphone {nombre}
```

`server/instalador/empaquetar` genera el paquete, su `.sha256` y esa línea ya rellena:

```bash
server/instalador/empaquetar                                   # dist/hehermes-servidor-0.3.0.tar.gz y .sha256
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
- **Lleva:** `hehermes-servidor` y `hehermes_servidor/`, `hehermes-dispositivo` (de `server/vpn`), `clave-publica.pem`,
  este README y `avisos/` (el código, `despliegue/` y `requirements.txt` de `server/avisos`). Ni pruebas ni `__pycache__`.

### La firma de las actualizaciones

`sudo hehermes-servidor actualizar --paquete <tar.gz> --firma <tar.gz.sig>` no pasa por la app, así que no hay suma
que la ancle: se fía de una firma Ed25519 de Daniel, comprobada con
`openssl pkeyutl -verify -pubin -inkey /opt/hehermes-servidor/clave-publica.pem -rawin -in <tar.gz> -sigfile <sig>`.
Solo si la firma es buena desempaqueta (y solo ficheros y carpetas dentro de `hehermes-servidor-X.Y.Z/`) y lanza
`instalar --si` de la versión nueva, que repara hasta dejarlo todo al día.

- **No hay ninguna clave real.** `clave-publica.pem` es un marcador (`PENDIENTE-DE-DANIEL`) y, mientras lo sea,
  `actualizar` se niega. La privada irá en el llavero del Mac de Daniel, nunca en un servidor ni en el repositorio;
  cómo crearla está dentro del propio `clave-publica.pem`. Hace falta OpenSSL 3: el LibreSSL de macOS no sabe Ed25519.
- Las pruebas usan `tests/datos/clave-de-prueba-NO-ES-DE-DANIEL.pem`, marcada en el nombre y en el fichero.

## El alta por chat (`--por-chat`)

Es la pieza B de la spec: para quien solo habla con su Hermes por Telegram, WhatsApp o Slack. La app copia una frase
con este comando y con su **llave**, la clave pública X25519 de un par que acaba de crear (la privada se queda en su
llavero, 30 minutos y sin salir del iPhone). Hermes la ejecuta con su terminal:

```
… && sudo ./hehermes-servidor-{versión}/hehermes-servidor instalar --por-chat --activar-api --iphone {nombre} --llave {llave}
```

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

**El canje** (`hehermes_servidor/canje.py`) es una unidad temporal, `hehermes-canje`, lanzada con `systemd-run` para que
sobreviva al comando de Hermes:

| | |
|---|---|
| Quién | `DynamicUser=yes`, con solo `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges` y `RuntimeMaxSec=660` |
| Con qué | Su venv, `/opt/hehermes-canje/venv`, con `cryptography` fijada por hash (`requirements-canje.txt`, los mismos bloques que los avisos) y el código por un `.pth`. Hace falta `python3-venv` |
| Secretos | La PSK, el código, la llave y la clave del certificado, en `/run/hehermes-canje` (0700, en memoria), y al canje por `LoadCredential` |
| Puerto | El TCP 443 si está libre; si no, el primero libre de 8443 a 8453. En ufw, si está activo, `allow … port P comment hehermes-canje`; en firewalld, si está en marcha y el puerto no estaba abierto, `--add-port=P/tcp` solo en la configuración de ahora (nunca en la permanente). Solo mientras dure |
| TLS | 1.3, con un certificado ECDSA P-256 autofirmado para ese canje y sin ningún dato. La huella del enlace es el SHA-256 de su SPKI, y la app no acepta otra |
| Protocolo | `POST /canje/v1/reto {c}` devuelve un reto cifrado para la llave (el código no se gasta); `POST /canje/v1/canjear {c, reto}` devuelve `{h, rid, lid, k}` cifrado para la llave, y se cierra |
| Límites | 10 minutos, 5 fallos (o 3 de una IP), una petición por segundo y por IP. Lo que no es un POST del protocolo (un escáner) no cuenta |
| Al cerrarse | Por lo que sea, `ExecStopPost=+… canje-limpiar`, como root: fuera la regla de ufw y `/run/hehermes-canje`; si salió con 0 por sí mismo (se canjeó), lo apunta en el manifiesto y no hay otro alta por chat |

El sobre es el de los avisos, pero para una clave pública: una X25519 efímera por sobre, HKDF-SHA256 con la huella, el
código, el paso y las dos claves públicas dentro, y ChaCha20-Poly1305. Un sobre de otro servidor, de otro canje o del
otro paso no se abre. El vector que lo fija lo comparten el servidor y la app:
`HeHermes/HeHermesMensajesTests/Fixtures/canje-vpn.json`.

**Tras un reinicio** el canje ya no existe y `/run` está vacío, pero una regla de ufw podría quedar: la quitan el siguiente
`instalar --por-chat` y `desinstalar`.

## Qué deja

| Pieza | Qué deja |
|---|---|
| Paquetes | `charon-systemd`, `strongswan-swanctl`, `libstrongswan-standard-plugins`, `qrencode` y `nginx`, los que falten (`--no-install-recommends`). En la familia Red Hat, con dnf (`--setopt=install_weak_deps=False`): `strongswan`, `qrencode`, `nginx` y, con SELinux y sin `semanage`, `policycoreutils-python-utils`; y arranca strongSwan, que dnf deja parado (desinstalar lo para) |
| El instalador | `/opt/hehermes-servidor/` (su código, `hehermes-dispositivo` y la clave pública) y `/usr/local/sbin/hehermes-servidor`, para repetir, comprobar, actualizar o desinstalar sin la carpeta temporal |
| Dispositivos | `/usr/local/sbin/hehermes-dispositivo` (0750) y `/etc/hehermes/servidor.ini`, de donde lee la dirección del servidor, el `.env` de Hermes, la carpeta del registro (`/etc/hehermes/dispositivos`) y la de swanctl (`/etc/swanctl`, o `/etc/strongswan/swanctl` en la familia Red Hat) |
| Interfaz XFRM | `hehermes-xfrm.service` y `/usr/local/sbin/hehermes-xfrm`: `hh-ipsec` con `if_id 0x77`, `10.77.0.1/32` y la ruta a `10.77.1.0/24`, antes que strongSwan y nginx |
| nginx | `/etc/nginx/sites-available/hehermes-tunel` y su enlace (o `conf.d/hehermes-tunel.conf` si nginx no usa `sites-enabled`), `hehermes-bearer.conf` (0600) y el drop-in `nginx.service.d/hehermes-xfrm.conf`. Si nginx lo instala él, apaga el sitio `default` (y desinstalar lo devuelve) |
| ufw | `allow proto udp to any port 500,4500` y `allow in on hh-ipsec proto tcp to 10.77.0.1 port 80`, con el comentario `hehermes`. **No enciende ufw** |
| firewalld (familia Red Hat) | En la zona por defecto: `--add-port=500/udp`, `--add-port=4500/udp` y una regla rica que deja entrar el TCP 80 solo desde `10.77.1.0/24` hacia `10.77.0.1` (firewalld no sabe de «entra por hh-ipsec»). En marcha, en la configuración de ahora y en la permanente, **sin `--reload`**, que se llevaría las reglas de ahora de los demás; apagado, con `firewall-offline-cmd`. **No lo enciende** |
| SELinux (si está puesto) | `semanage port -a -t http_port_t -p tcp <puerto de Hermes>`, para que nginx llegue a Hermes, y nada más (no el booleano `httpd_can_network_connect`, que le dejaría llegar a todo); si el puerto ya lo tiene otro tipo, se para. Cada fichero que escribe, con `restorecon` |
| La clave de Hermes | `hehermes-clave.path` vigila el `.env` y, si cambia, `hehermes-clave.service` ejecuta `hehermes-dispositivo clave` |
| Avisos (`--avisos`) | El `instalar.sh` de `server/avisos`, tal cual: vigía y relé local |
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
- **ufw y firewalld, sin encender.** En Debian y Ubuntu, firewalld, nftables y el cortafuegos del proveedor: solo se
  avisa. Una regla que ya estaba (de otro) se queda como «ya está*» y desinstalar no la quita.
- **Solo IKEv2.** Nada de WireGuard en una instalación nueva.

## Qué detecta, sin cambiar nada

- **El sistema:** los de [la lista](#los-sistemas), en amd64 o arm64, con systemd, apt o dnf, núcleo 4.19 o más y
  Python 3.9 o más (el de RHEL 9). En otro, se para al empezar sin haber ejecutado nada.
- **Hermes:** la unidad `hermes-gateway` o su proceso, su usuario y su `HERMES_HOME`; del `.env` (con `export`,
  comillas y comentarios), `API_SERVER_ENABLED`, `API_SERVER_KEY`, `API_SERVER_HOST` y `API_SERVER_PORT`, y la clave
  probada con `GET /health` y `GET /api/sessions?limit=1` en `127.0.0.1`. Hermes en `0.0.0.0` se avisa en rojo; varios
  Hermes se enumeran. La clave no se imprime nunca.
- **La dirección pública:** la de salida (`ip route get`); si es privada, `--direccion` o se pregunta en un terminal.
- **Lo que ya hay:** nginx (y si sus sitios van por `sites-enabled` o `conf.d`), quién tiene el TCP 80 y los UDP 500 y
  4500, strongSwan con `ipsec.conf` (se para), las conexiones de swanctl (nombres `hh-*`, pools en `10.77.0.0/16`, el
  `if_id 0x77`, PSK para `%any`), otras redes en `10.77.0.0/16` (Docker), ufw, firewalld y nftables, y SELinux
  (`getenforce`, y la etiqueta del puerto de Hermes con `semanage port -l`).
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

## Pruebas

```bash
# Con un venv que tenga cryptography (el de los avisos vale: server/avisos/README.md, «Pruebas»):
/tmp/hh-avisos/bin/python -I -B -m unittest discover -s server/instalador/tests -t server/instalador/tests
```

Las del canje (`tests/test_canje_*.py`) necesitan `cryptography` y no importan sin ella; las demás corren también con el
`python3` del sistema (`-p "test_[!c]*"`). El canje se prueba de verdad: un servidor TLS en `127.0.0.1` y un cliente de
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
`ExecStopPost=+` y `LoadCredential` con `DynamicUser`), que el canje escuche en el 443 como DynamicUser, `ufw delete` con
el comentario, el reinicio a los 90 s con `systemd-run --on-active`, `pip` desde el servidor, el canje con TLS 1.3 de
verdad y un Hermes de verdad ejecutando la frase.
