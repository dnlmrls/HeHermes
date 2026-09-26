# `hehermes-dispositivo`, y lo que queda de la VPN de HeHermes

**La VPN ya no existe.** Desde la versión 0.6.0 del instalador la app habla con Hermes solo por la conexión directa, la
pasarela TLS, que instala [`server/instalador`](../instalador/README.md) de un solo comando (y, sin root, en la casa del
usuario de Hermes). Aquí queda `hehermes-dispositivo`, el script de los iPhone de la pasarela, que también da de baja
lo que quede de una VPN de antes; y, como historia, cómo era esa VPN.

| Fichero | Qué es |
|---|---|
| `hehermes-dispositivo` | Los iPhone de la pasarela (altas, bajas, tokens nuevos) y las bajas de la VPN de antes. Lo instala el instalador en `/usr/local/sbin/hehermes-dispositivo` (root, 0750), o en `~/.local/bin` sin root |
| `hehermes-tunel.nginx` | Historia: el sitio del túnel que se escribía a mano. Lo copian las pruebas para el doble de un servidor montado así; su `location /` no cierra el agujero del túnel ([la historia del instalador](../instalador/README.md#el-agujero-del-túnel)) |
| `nginx-despues-de-wg0.conf` | Historia: el drop-in de nginx de un servidor con WireGuard, también para las pruebas |

## Uso

En el servidor, en un terminal tuyo (con `sudo` si la pasarela es de root, sin él si es de tu usuario):

```bash
sudo hehermes-dispositivo alta otro-iphone     # el token nuevo y su QR (hehermes-tls:1?…), solo en un terminal
sudo hehermes-dispositivo lista                # todos, con su modo: tls, o ikev2 y wireguard los de la VPN de antes
sudo hehermes-dispositivo rotar otro-iphone    # otro token y su QR, si el de antes ha podido verse
sudo hehermes-dispositivo baja otro-iphone     # su acceso deja de valer al momento, sea de la pasarela o de la VPN
sudo hehermes-dispositivo clave                # si cambia la API_SERVER_KEY: la copia del vigía de avisos (y la de nginx)
```

- **`alta <nombre>`** es siempre de la pasarela; `alta <nombre> --tls` hace lo mismo (lo enseñaban las versiones de
  antes, y la app se lo enseña a quien ya tiene el instalador). Sin la pasarela instalada, se para y dice cómo
  instalarla. El QR lleva el token: solo se pinta en un terminal (como root, además, lanzado con `sudo`), y **no se puede
  volver a pintar**, porque del token solo se guarda el hash; para uno nuevo, `rotar`. Lo de la pasarela está entero en
  el [README del instalador](../instalador/README.md#los-iphone-con-hehermes-dispositivo).
- **La VPN no da altas nuevas ni cambia claves.** `alta … --ikev2`, `alta … --pubkey` o `--servidor` (WireGuard),
  `rotar` y `qr` de un alta de la VPN se paran y dicen por qué. Ya no hay `iniciar`.
- **Lo de antes se sigue viendo y quitando.** `lista` enseña las altas IKEv2 (con si su SA está viva) y las de
  WireGuard (con su último contacto). `baja <nombre>` las quita como siempre: una IKEv2, su fichero de `conf.d`,
  `swanctl --load-all --noprompt` y `swanctl --terminate --ike hh-<nombre> --force`, por ese orden (sin el `terminate`
  la sesión viva seguiría); una de WireGuard, `wg0.conf` regenerado sin ella y aplicado en caliente. Si el mismo nombre
  está en la pasarela y en la VPN, pide cuál (`--tls` o `--ikev2`). Los ficheros de `conf.d` que no escribió el script
  (los que no llevan su primera línea, como el `hehermes-poc.conf` de una VPN a mano) no se tocan nunca.
- **`limpiar <nombre>`** borra el `.conf` con la clave privada que quedara de un alta de WireGuard, y **`estado`** dice
  cómo están WireGuard, strongSwan y nginx.
- **`clave`** escribe la copia de la clave de Hermes del vigía de avisos (`/etc/hehermes-avisos/vigia/clave-hermes`,
  0600 de `hh-vigia`) y lo reinicia si ha cambiado; mientras quede el nginx del túnel, también `hehermes-bearer.conf`.
  `clave --solo-vigia` hace solo lo del vigía: es lo que usa el instalador de los avisos. La pasarela tiene su propia
  vigilancia de la clave (`hehermes-pasarela-clave.path`).
- Si existe `/etc/hehermes/servidor.ini` (lo dejaba la VPN del instalador), de ahí salen el `.env` de Hermes, la carpeta
  del registro y la de swanctl (`/etc/strongswan/swanctl` en la familia Red Hat); sin él, las de una instalación a mano.

## Quitar la VPN

- **La del instalador** (hasta la 0.5.1): `sudo hehermes-servidor desinstalar --modo vpn`. Da de baja sus altas IKEv2,
  quita el sitio de nginx, la XFRM, `servidor.ini`, sus reglas y su registro, y deja la pasarela como estaba. El paso a
  paso, en el [README del instalador](../instalador/README.md#la-vpn-de-antes).
- **Una hecha a mano**, que el instalador no toca: `sudo hehermes-dispositivo baja <nombre>` de cada alta del registro;
  la conexión escrita a mano, quitando su fichero de `/etc/swanctl/conf.d`, `swanctl --load-all --noprompt` y
  `swanctl --terminate --ike <conexión> --force`; `systemctl disable --now wg-quick@wg0` si había WireGuard; el sitio
  `hehermes-tunel` de nginx, su enlace, `hehermes-bearer.conf` y el drop-in, con `nginx -t` y un `reload`; y las reglas
  de ufw de UDP 500 y 4500, 51820 y el TCP 80 por el túnel. Los paquetes (strongSwan, WireGuard), si no sirven para nada
  más.

## Historia: la VPN

El iPhone hablaba con el api_server de Hermes por un túnel que terminaba en `10.77.0.1`, donde escuchaba nginx y donde
nginx ponía la clave del api_server. Hubo dos túneles a esa IP:

- **IKEv2 nativo:** la propia app creaba la VPN personal de iOS (`NEVPNManager`, `NEVPNProtocolIKEv2`) con un QR
  `hehermes-vpn:1?h=…&rid=…&lid=…&k=…` que llevaba la clave compartida del dispositivo. strongSwan, una conexión por
  iPhone en `conf.d/hehermes-<nombre>.conf` con una PSK de 264 bits, solo AES-256-GCM, PRF SHA-384 y ECP-384 con PFS, el
  túnel dividido hasta `10.77.0.1/32`, un pool de una sola dirección de `10.77.1.0/24` y la interfaz XFRM `hh-ipsec`
  (`if_id 0x77`). Es lo que montaba el instalador con `--modo vpn`, hasta la 0.5.1.
- **WireGuard**, lo de antes: la app WireGuard en el iPhone, `wg0`, UDP 51820 y `10.77.0.0/24`. Solo en servidores
  montados a mano.

Por qué los puertos UDP 500 y 4500 no podían ser aleatorios, y el agujero del túnel, están en la
[historia del instalador](../instalador/README.md#historia-la-vpn-ikev2-hasta-la-051). La pasarela no tiene ninguna de
las dos cosas: su puerto es alto y al azar, y no le pone la clave de Hermes a quien no trae un token.
