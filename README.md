# HeHermes: el instalador de servidor

El código que se ejecuta en tu servidor cuando conectas la app **HeHermes Mensajes** (iPhone) con tu
[Hermes Agent](https://hermes-agent.nousresearch.com). Está aquí para que puedas **leer y auditar lo que instalas**
antes de darle `sudo`.

La app no está en este repositorio: aquí solo está lo que corre en el servidor.

## Qué hace

En un servidor Linux que ya tiene Hermes, deja lo que hace falta para que el iPhone hable con él por una VPN IKEv2
que instala la propia app, y acaba pintando en el terminal el código QR del iPhone:

- strongSwan (IKEv2) con una conexión y una clave por iPhone, una interfaz XFRM `hh-ipsec` y nginx escuchando solo
  dentro del túnel (`10.77.0.1`), que pone la clave de la API de Hermes para que la app no la lleve nunca;
- las reglas del cortafuegos (ufw o firewalld), **sin encenderlo** si está apagado;
- un manifiesto de todo lo que deja (`/etc/hehermes/instalacion.json`): no pisa nada que no sea suyo, repetirlo no
  cambia nada y desinstalarlo deja el servidor como estaba.

Todo con Python 3 del sistema y la biblioteca estándar. El detalle, en
[`server/instalador/README.md`](server/instalador/README.md).

| Carpeta | Qué hay |
|---|---|
| `server/instalador` | `hehermes-servidor` (instalar, comprobar, actualizar, desinstalar), `empaquetar` y sus pruebas |
| `server/vpn` | `hehermes-dispositivo`, el script de las altas y bajas de cada iPhone, y la instalación a mano |
| `server/avisos` | El código de los avisos push (el vigía y el relé) y su instalador. Sus pruebas no están aquí: usan datos de un Hermes de verdad |

## Cómo se instala

La app te da una sola línea, con la versión y la **suma SHA-256** del paquete escritas dentro. Si el fichero
descargado no es exactamente ese, `sha256sum -c` lo para antes del `sudo`:

```
d=$(mktemp -d) && cd "$d" && curl -fsSLO https://github.com/dnlmrls/HeHermes/releases/download/v{versión}/hehermes-servidor-{versión}.tar.gz && echo "{sha256}  hehermes-servidor-{versión}.tar.gz" | sha256sum -c - && tar -xzf hehermes-servidor-{versión}.tar.gz && sudo ./hehermes-servidor-{versión}/hehermes-servidor instalar --iphone {nombre}
```

Antes, si quieres, `sudo ./hehermes-servidor-{versión}/hehermes-servidor instalar --plan --iphone mi-iphone` enseña
todo lo que haría sin cambiar nada.

**Comprobar que el paquete es este código:** `server/instalador/empaquetar` es reproducible (la misma versión da
siempre el mismo fichero), así que desde este repositorio, en la etiqueta de la versión:

```bash
git checkout v{versión}
python3 server/instalador/empaquetar --salida /tmp/hh    # imprime la SHA-256
```

tiene que dar la misma suma que el asset de la Release y que el comando de la app.

## Sistemas

Debian 12 y 13; Ubuntu 22.04, 24.04 y 26.04; sus derivadas (Linux Mint, Pop!_OS, Raspberry Pi OS…); y la familia
Red Hat: Rocky Linux, AlmaLinux, RHEL y CentOS Stream 9 y 10, y Fedora 42 o más nueva. En amd64 o arm64, con
systemd. En cualquier otro, se para al empezar sin haber tocado nada.

## Pruebas

```bash
python3 -m venv /tmp/hh && /tmp/hh/bin/pip install --only-binary=:all: --require-hashes -r server/avisos/requirements.txt
/tmp/hh/bin/python -I -B -m unittest discover -s server/instalador/tests -t server/instalador/tests
```

Sin root, sin red y sin tocar nada: el sistema es una carpeta temporal y las órdenes las contesta un servidor falso.
Las que comparan el instalador con la app (la suma, la frase y el vector del canje) se saltan aquí, porque la app no
está.

**Las claves de las pruebas son de prueba.** `server/instalador/tests/datos/clave-de-prueba-NO-ES-DE-DANIEL.pem` (y su
`.pub.pem`) es un par Ed25519 hecho solo para las pruebas, marcado en el nombre y dentro; no firma nada que se
distribuya. `server/instalador/clave-publica.pem` es un marcador: mientras lo sea, `actualizar` se niega. Las
direcciones de los ejemplos y de las pruebas son de documentación (RFC 5737: `192.0.2.x`, `198.51.100.x`,
`203.0.113.x`).

## Licencia

**Todos los derechos reservados** (ver `LICENCIA`). El código está visible para que puedas auditar lo que instalas;
la licencia está por decidir.
