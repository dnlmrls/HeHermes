# La VPN de HeHermes y `hehermes-dispositivo`

El iPhone habla con el api_server de Hermes por un túnel que termina en `10.77.0.1`, donde escucha nginx y donde nginx pone la clave del api_server. Hay **dos** túneles que llegan a esa IP y pueden convivir:

- **IKEv2 nativo** ([más abajo](#vpn-ikev2-nativa-sin-apps-de-terceros)): la propia app crea la VPN personal de iOS con `NEVPNManager`, autenticada con una clave compartida por dispositivo. Sin apps de terceros. Es lo único que monta el instalador.
- **WireGuard**, lo de antes: la app WireGuard en el iPhone, `wg0`, UDP 51820. La credencial de cada dispositivo es su clave WireGuard. Solo en servidores montados a mano.

**En un servidor nuevo, todo esto lo monta el instalador de un solo comando, solo con IKEv2: [`server/instalador`](../instalador/README.md).** Lo de esta página es el script de los dispositivos, que el instalador también usa, y cómo se monta a mano un servidor como el de antes, que el instalador detecta y no toca. Quien solo habla con su Hermes por chat tiene el alta por chat (`instalar --por-chat`): el mismo alta IKEv2, sin QR, con la PSK entregada cifrada por un canje de un solo uso (mismo README, «El alta por chat»).

Solo puede estar activo uno de los dos a la vez en el iPhone: los dos encaminan `10.77.0.1` y la VPN «enterprise» de WireGuard gana a la personal.

| Fichero | Va en el servidor a |
|---|---|
| `hehermes-dispositivo` | `/usr/local/sbin/hehermes-dispositivo` (root, 0750) |
| `hehermes-tunel.nginx` | `/etc/nginx/sites-available/hehermes-tunel` + enlace en `sites-enabled` (solo a mano; léelo antes: su `location /` no cierra el agujero del túnel) |
| `nginx-despues-de-wg0.conf` | `/etc/systemd/system/nginx.service.d/hehermes-wg0.conf` (solo con WireGuard) |

## Instalación a mano con WireGuard

```bash
sudo apt-get install --no-install-recommends wireguard-tools qrencode
sudo install -m 0750 hehermes-dispositivo /usr/local/sbin/
sudo hehermes-dispositivo iniciar                 # clave del servidor y wg0.conf
sudo systemctl enable --now wg-quick@wg0          # 10.77.0.1/24, UDP 51820
sudo ufw allow 51820/udp
sudo ufw allow in on wg0 to 10.77.0.1 port 80 proto tcp
sudo hehermes-dispositivo clave                   # /etc/nginx/hehermes-bearer.conf (0600)
# sitio nginx + drop-in de systemd (tabla de arriba), luego:
sudo systemctl daemon-reload && sudo nginx -t && sudo systemctl enable --now nginx
```

## Uso

En el servidor, en un terminal tuyo:

```bash
# IKEv2, la VPN que instala la propia app (lo que enseña la bienvenida):
sudo hehermes-dispositivo alta mi-iphone --ikev2 && sudo hehermes-dispositivo qr mi-iphone
# WireGuard, con la app WireGuard:
sudo hehermes-dispositivo alta otro-iphone && sudo hehermes-dispositivo qr otro-iphone
sudo hehermes-dispositivo limpiar otro-iphone   # tras importar el QR en la app WireGuard
sudo hehermes-dispositivo lista                 # tipo, IP y si hay sesión (handshake o SA IKEv2)
sudo hehermes-dispositivo baja otro-iphone      # corta el acceso al momento, sea del tipo que sea
sudo hehermes-dispositivo estado
sudo hehermes-dispositivo iniciar --ikev2       # solo mira si strongSwan tiene lo que hace falta
```

`alta <nombre> --pubkey <clave>` no genera ninguna clave privada: imprime el fichero `.hehermes` (sin secretos) para el alta iniciada en el iPhone. Si cambia la `API_SERVER_KEY`, basta con `sudo hehermes-dispositivo clave`: escribe la de nginx y, si el vigía de avisos está instalado (`server/avisos`), también su copia (`/etc/hehermes-avisos/vigia/clave-hermes`, 0600 de `hh-vigia`), y lo reinicia si la copia ha cambiado. El vigía lee al api_server directo, sin pasar por este nginx. `clave --solo-vigia` hace solo lo del vigía, sin tocar ni recargar nginx: es lo que usa el instalador de los avisos en cada pasada.

### La dirección del servidor

La dirección pública del servidor (la IP de tu servidor o su nombre) va en el QR, en el `local.id` de strongSwan y en el `Endpoint` de WireGuard. **No va escrita en el script**: cada alta la saca, por este orden, de

1. `alta … --servidor <dirección>`;
2. `/etc/hehermes/servidor.ini` (`[servidor] direccion`), que deja el instalador;
3. el registro: la `servidor` del último alta IKEv2;
4. el `Endpoint` de un `.conf` de WireGuard que el script ya haya dado.

Si no hay ninguna, el alta se para antes de apuntar nada y pide `--servidor`. Lo demás (`lista`, `estado`, `qr`, `baja`, `limpiar`, `clave`, `iniciar`) no la necesita. `servidor.ini` dice además dónde está el `.env` de Hermes, la carpeta del registro y, si no es `/etc/swanctl`, la de swanctl (`[strongswan] carpeta`, `/etc/strongswan/swanctl` en la familia Red Hat).

## VPN IKEv2 nativa (sin apps de terceros)

La app crea ella misma una **VPN personal de iOS** (`NEVPNManager` + `NEVPNProtocolIKEv2`) contra el strongSwan del servidor. Se escanea un código QR dentro de la app, iOS pide permiso una vez (alerta + código o Face ID) y ya está: no hace falta la app WireGuard ni pasar por Ajustes.

Una conexión escrita a mano para un iPhone, como la primera que se probó (`hh-iphone-poc`, en `/etc/swanctl/conf.d/hehermes-poc.conf`), es así, y el alta por dispositivo ([más abajo](#alta-ikev2-por-dispositivo)) no la toca:

| En el servidor | Valor |
|---|---|
| Conexión strongSwan | `hh-iphone-poc` (en `/etc/swanctl/conf.d/`) |
| Autenticación | PSK en los dos lados, sin EAP y sin certificados |
| Identidad del iPhone | `iphone-poc` (en strongSwan es `remote.id`; en iOS, `localIdentifier`) |
| Identidad del servidor | la IP de tu servidor (en iOS, `remoteIdentifier`) |
| Pool | `10.77.1.2/32` |
| Túnel dividido | `local_ts = 10.77.0.1/32`: por el túnel solo va Hermes |
| Interfaz | XFRM `hh-ipsec` (`if_id 0x77`), con `10.77.0.1/32` y ruta a `10.77.1.0/24` |
| Puertos | UDP 500 y 4500 (`encap = yes`) |

### Lo que pide la app

Coincide con lo que el servidor propone:

- IKE y Child: **AES-256-GCM**, PRF **SHA2-384**, grupo **20** (ECP-384), **PFS**. Con AES-GCM la integridad no se negocia: iOS deduce de ella la PRF.
- Vidas que pide el iPhone: IKE 24 h, Child 8 h (iOS usa 60 y 30 minutos por defecto). Quién empieza el rekey depende de `rekey_time`/`life_time` de la conexión: con los valores por defecto de swanctl (4 h y 1 h) lo empieza el servidor, que también es normal.
- `deadPeerDetectionRate = .medium`, `disconnectOnSleep = false`, MOBIKE activo (la IP de dentro del túnel aguanta el salto de Wi-Fi a datos y el SSE del turno no se corta).
- `includeAllNetworks = false` y `useConfigurationAttributeInternalIPSubnet = false`: el túnel dividido lo marcan los traffic selectors del servidor.
- «Conectar a petición»: `NEOnDemandRuleConnect` con cualquier interfaz. iOS levanta el túnel solo en cuanto algo pide red; con el túnel dividido, por él solo sale lo de `10.77.0.1`.
- La clave compartida vive en el **llavero** del iPhone (`kSecClassGenericPassword`, `AfterFirstUnlockThisDeviceOnly`) y a la configuración VPN se le pasa su **referencia persistente**, nunca la clave. No se guarda en `UserDefaults` ni sale en ningún texto de la app.
- La app solo ve **su** configuración VPN: ni toca ni ve la de WireGuard.

### El código QR del alta

El código lleva la PSK, así que es un secreto: se pinta **solo en un terminal tuyo**, nunca por Hermes, nunca en un fichero, nunca en un chat. Es el mismo trato que tiene `hehermes-dispositivo qr` con la clave privada de WireGuard.

Leer el código **no instala nada**: la app enseña una hoja «Instalar esta VPN» con el servidor y el nombre de este iPhone, y avisa en rojo si el servidor no es el que ya estaba puesto. Hay que tocar «Instalar». Es el único freno que hay: las rutas del túnel las fija el servidor con sus traffic selectors, así que un código de otro servidor podría quedarse con lo que la app habla con Hermes y contestar como si fuera él.

La app acepta dos formas y cualquiera de las dos vale:

```
hehermes-vpn:1?h=<servidor>&rid=<id del servidor>&lid=<id del iPhone>&k=<clave>
{"v":1,"servidor":"…","remoto":"…","local":"…","psk":"…"}
```

- `rid` / `remoto` se puede omitir: entonces vale la dirección del servidor, que es lo que manda strongSwan cuando no le ponen `local.id`.
- La clave viaja como **texto**, y son esos mismos bytes los que tiene que tener el `secret` del servidor. Una conexión escrita a mano puede guardarlo en hexadecimal (`secret = 0x…`), que es el hexadecimal de ese texto.
- En la forma `hehermes-vpn:1?…` la clave va **percent-encodeada** (`%41%42…`). Sin codificar, un `&` dentro de la clave la parte en dos y solo se guarda el trozo de delante, un `#` manda el resto al fragmento y un `%xy` se descodifica a otra cosa: el QR se aceptaría, la VPN se instalaría y el único síntoma llegaría minutos después, al conectar, como «El servidor ha rechazado la clave de este iPhone». El comando de abajo codifica byte a byte, así que la clave llega entera lleve lo que lleve. La app, además, rechaza una clave de menos de 16 caracteres: una clave partida no llega al llavero.
- La clave tiene que ser **texto imprimible**. La app guarda en el llavero los bytes UTF-8 del texto leído, así que un `secret` que sean bytes aleatorios no se puede pasar por el QR: hay que rotarlo a uno en base64. El comando lo comprueba y se para. Y si aun así llega un código con la clave en bytes crudos, la app lo distingue de uno al que le faltan datos y dice el remedio de verdad: «La clave de ese código no es texto. Cámbiala en el VPS por una en base64 y vuelve a pintarlo.»
- `hehermes-vpn:` **no** está registrado como esquema de URL de la app, a propósito: otra app podría reclamarlo. El texto lo lee el escáner de dentro de la app (VisionKit), sin pasar por la Cámara del sistema ni por el portapapeles.

Para volver a pintar el QR de una conexión escrita a mano, en una sesión SSH interactiva tuya (no desde una sesión automática), con la IP de tu servidor en `SERVIDOR`:

```bash
sudo -s
SERVIDOR=203.0.113.7   # la IP de tu servidor (esta es de documentación)
# El valor del `secret`, anclado en la asignación: `awk '/secret/'` casaba antes con la cabecera `secrets {` y
# pintaba un QR sin clave ninguna. No se parte por «=»: una clave en base64 lleva «=» de relleno.
BRUTO=$(sed -n 's/^[[:space:]]*secret[[:space:]]*=[[:space:]]*//p' /etc/swanctl/conf.d/hehermes-poc.conf \
        | head -1 | tr -d '"')
# El secreto puede estar en hexadecimal (`0x…`) o entre comillas: se admiten las dos formas.
case "$BRUTO" in 0x*|0X*) PSK=$(printf '%s' "${BRUTO#0[xX]}" | xxd -r -p) ;; *) PSK=$BRUTO ;; esac

# Las dos comprobaciones tienen que parar el QR, no solo avisar: van como `if`/`elif` y no como un `exit`, porque
# esto se pega en una shell interactiva, y un `exit` cerraría el `sudo -s` dejando que las líneas que quedaran
# pegadas se ejecutaran fuera.
if [ -z "$PSK" ]; then
  echo 'PSK vacía: el QR saldría sin clave. No sigas: mira el fichero.'
elif ! printf '%s' "$PSK" | LC_ALL=C grep -q '^[[:print:]]\{16,\}$'; then
  echo 'La clave no es texto imprimible de 16 o más caracteres: rótala a base64 antes de seguir.'
else
  # Cada byte codificado: ni «&» ni «#» ni «%» pueden partir la clave por el camino.
  PSKURL=$(printf '%s' "$PSK" | od -An -tx1 -v | tr -s ' ' '\n' | grep . | sed 's/^/%/' | tr -d '\n')
  printf 'hehermes-vpn:1?h=%s&rid=%s&lid=iphone-poc&k=%s' "$SERVIDOR" "$SERVIDOR" "$PSKURL" | qrencode -t ansiutf8
fi
unset BRUTO PSK PSKURL
```

Ese bloque es solo para una conexión escrita a mano. Para un iPhone nuevo, o para rotar la clave, está `hehermes-dispositivo alta <nombre> --ikev2` y `qr <nombre>` (abajo), que hacen lo mismo con las mismas comprobaciones: la clave son 33 bytes aleatorios en base64 y va **entre comillas** como `secret`.

### Bajas

- **En el servidor:** `sudo hehermes-dispositivo baja <nombre>`, que quita su fichero de `conf.d`, hace `swanctl --load-all --noprompt` y `swanctl --terminate --ike hh-<nombre> --force`, por ese orden. Sin el `terminate`, la sesión viva sigue: el rekey de IKE no vuelve a mirar las credenciales. Para una conexión escrita a mano, que el script no conoce, lo mismo a mano.
- **En el iPhone:** «Eliminar la VPN» en la pantalla de la VPN de la app (quita la configuración de Ajustes y la clave del llavero). Si en vez de eso se borra el perfil en Ajustes › General › VPN y gestión de dispositivos, **la clave se queda en el llavero del iPhone**: la app lo detecta al abrir su pantalla y deja ahí el botón de eliminar para quitarla. Ni una cosa ni otra revocan nada en el servidor.

### Alta IKEv2 por dispositivo

- **Registro:** `dispositivos.json` es la única lista de quién hay, y cada entrada lleva `tipo: wireguard | ikev2`. Las de antes, sin `tipo`, son de WireGuard y no se reescriben. Una IKEv2 guarda su `ip`, su `servidor` y su `conexion` (`hh-<nombre>`), **no** la clave.
- **IP:** de `10.77.1.0/24`, que no se solapa con `wg0`. Nunca la .1 ni la .2 (la de la conexión escrita a mano de la tabla), ni una que ya haya tenido alguien, dado de baja o no, ni ninguna que reparta un pool de otro fichero de `conf.d` (`addrs`, sean direcciones, redes o `a-b`).
- **Clave:** `secrets.token_bytes(33)` en base64: 264 bits, 44 caracteres sin relleno y sin nada que el QR tenga que proteger. Es lo mismo que `openssl rand -base64 33`, sin depender de él.
- **Una conexión por fichero**, `/etc/swanctl/conf.d/hehermes-<nombre>.conf` (0600, root). Así un alta o una baja escriben o borran solo lo suyo, un fallo a medias no se lleva las claves de los demás y la clave de cada uno vive en un solo sitio, que es de donde la lee `qr`. Los ficheros llevan una primera línea de cabecera; los que no la llevan (los escritos a mano) el script no los sobrescribe ni los borra nunca, y se niega a un alta cuyo fichero, conexión, pool, secreto o identidad ya estén en uno de ellos.
- **La conexión** es la de la tabla: PSK, `aes256gcm16-prfsha384-ecp384` en IKE y `aes256gcm16-ecp384` en el Child (PFS), `encap = yes`, `if_id_in/out = 0x77`, `local_ts = 10.77.0.1/32`, `remote.id = <nombre>`, y además `unique = replace` y el secreto ligado a esa identidad.
  - **`pools` con una sola dirección, y no `remote_ts` fijo:** iOS pide siempre una dirección interna y, si la conexión no tiene pool, no la recibe y no levanta el túnel. Con el pool, el `remote_ts` por defecto (`dynamic`) ya es esa dirección y nada más.
  - **`local.id = <servidor>` explícito:** es el `rid` del QR. Sin él strongSwan manda su IP, que coincide mientras el servidor sea una IP, pero no si con `--servidor` se da un nombre de host.
- **Carga:** `swanctl --load-all --noprompt`, que carga lo nuevo y descarga lo que ya no está sin tocar las sesiones de las demás conexiones. Si falla o la conexión no aparece en `--list-conns`, el alta se deshace.
- **`qr`:** `hehermes-vpn:1?h=<servidor>&rid=<servidor>&lid=<nombre>&k=<clave>` con cada byte de la clave como `%XX`, con la guarda de siempre (`SUDO_USER` y terminal) y a `qrencode` por su entrada, nunca en la línea de órdenes. Se para si la clave no es texto imprimible de 16 o más, o si empieza o acaba en espacio (la app lo quitaría).
- **`servidor`:** el de [la dirección del servidor](#la-dirección-del-servidor), que se queda en el registro.
- **`lista` y `estado`:** el tipo de cada uno y, de los IKEv2, si su SA está viva (`swanctl --list-sas`). `estado` cuenta también las SA vivas que no son del registro, como las de una conexión escrita a mano.
- **`iniciar --ikev2`**, y el alta antes de nada: que estén `swanctl` y charon, `conf.d` incluido en `swanctl.conf`, la interfaz XFRM `hh-ipsec` con `if_id 0x77` y UDP 500 y 4500 abiertos en ufw o en firewalld, si hay uno de los dos en marcha (sin ninguno, `iniciar --ikev2` dice que no lo sabe y el alta sigue). Si falta algo, dice qué y se para; no instala nada.
- **`limpiar`** no tiene nada que hacer con un IKEv2: la clave la necesita el servidor.

### Actualizar el script en un servidor montado a mano

Solo cambia un fichero, `/usr/local/sbin/hehermes-dispositivo`. Ni las conexiones escritas a mano ni `wg0` se tocan, y hasta el primer `alta --ikev2` no se escribe nada nuevo en `conf.d`.

```bash
# Antes: cómo está la conexión que ya funciona, para compararlo después.
sudo swanctl --list-sas; sudo sha256sum /etc/swanctl/conf.d/*.conf
sudo install -m 0750 hehermes-dispositivo /usr/local/sbin/
sudo hehermes-dispositivo iniciar --ikev2 && sudo hehermes-dispositivo lista   # solo lee
# Después: las mismas SA (mismo número #N, ESTABLISHED) y los mismos hashes.
sudo swanctl --list-sas; sudo sha256sum /etc/swanctl/conf.d/*.conf
```

Sin `servidor.ini`, la primera alta IKEv2 necesita `--servidor <la IP de tu servidor>`; las siguientes la sacan del registro. Volver atrás es reinstalar el script de antes. Las altas IKEv2 que se hayan dado, con `baja` antes de volver.

### Lo que sigue faltando

1. **Persistencia de `hh-ipsec` en un servidor montado a mano:** hecha a mano no sobrevive a un reinicio. En las instalaciones nuevas ya la deja el instalador: `hehermes-xfrm.service`, un oneshot antes de strongSwan y nginx, y el drop-in de nginx que depende de él. No es systemd-networkd con `Kind=xfrm`: en Debian la red es de ifupdown y encender networkd es tocarle la red a otro.
2. **Rotación sin secreto en el QR (más adelante):** con el túnel ya levantado, la app podría mandar una clave nueva por dentro del túnel a un endpoint detrás de nginx, y la del QR dejaría de servir a los pocos minutos. Hace falta ese endpoint, que hoy no existe.
3. **Pasar una conexión escrita a mano al script:** `alta` de un nombre nuevo, escanear su QR en el iPhone y, ya conectado por él, quitar el fichero a mano con la baja de arriba.
