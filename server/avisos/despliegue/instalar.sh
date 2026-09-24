#!/usr/bin/env bash
# Instala o actualiza el vigía y el relé de avisos de HeHermes en el VPS. Se puede repetir cuantas veces haga falta:
# lo que ya está bien no se toca, y lo que es de Daniel (configuración, credenciales, la clave .p8) no se pisa nunca.
#
#   sudo <donde esté server/avisos>/despliegue/instalar.sh
#
# Antes, una vez: el hehermes-dispositivo de server/vpn en /usr/local/sbin (escribe la copia de la clave de Hermes del
# vigía; el script se para si el instalado es de antes).
#
# Qué deja:
#   /opt/hehermes-avisos/src      el código (root, solo lectura para los servicios)
#   /opt/hehermes-avisos/venv     Python con las dependencias de requirements.txt, comprobadas por hash
#   /etc/hehermes-avisos/         vigia.ini (root:hh-vigia 0640), rele.ini (root:hh-rele 0640)
#   /etc/hehermes-avisos/vigia/   credencial-rele, secreto-tunel y clave-hermes (hh-vigia 0600)
#   /etc/hehermes-avisos/rele/    credenciales.ini (root:hh-rele 0640) y, cuando Daniel la ponga, AuthKey.p8 (hh-rele 0600)
#   /var/lib/hehermes-vigia/      la base de datos del vigía (la crea systemd, hh-vigia 0700)
#   /etc/systemd/system/hehermes-{vigia,rele}.{socket,service}
#   /etc/nginx/hehermes-avisos/sitio/avisos.conf    la location /avisos/, que incluye el server {} del túnel
#   /etc/nginx/hehermes-avisos/secreto/vigia.conf   el secreto que esa location le pone al vigía (root 0600)
#   /etc/nginx/hehermes-avisos/sello                la huella de lo último que nginx cargó bien de los avisos
#
# Los puertos del vigía y del relé (127.0.0.1:8790 y 8791) son de systemd, con activación por socket: nadie más puede
# escuchar en ellos, esté o no en marcha el servicio. El relé se habilita siempre: sin la clave de APNs arranca igual,
# con su puerto, y a los avisos contesta 503 hasta que se le reinicie con ella (lo hace volver a ejecutar esto).
set -euo pipefail

fallar() { echo "error: $*" >&2; exit 1; }
paso() { echo "==> $*"; }

[[ $EUID -eq 0 ]] || fallar "hay que ejecutarlo como root (sudo)"

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEN="$(dirname "$AQUI")"
# Nada de lo que corre como root puede leer nada del directorio desde el que se lanzó (un json.py de ahí se importaría
# en lugar del de verdad): se sale de él, y todo Python va con -I, que tampoco mira las variables PYTHON* del entorno.
cd /

PREFIJO=/opt/hehermes-avisos
CONF=/etc/hehermes-avisos
PY="${PYTHON:-python3}"
NOMBRE_CREDENCIAL="${NOMBRE_CREDENCIAL:-$(hostname -s)}"
SITIO_TUNEL=/etc/nginx/sites-available/hehermes-tunel
# Lo de los avisos en nginx, en dos carpetas que no se mezclan: sitio/, lo que va en el server {} del túnel, y secreto/,
# lo que va dentro de la location /avisos/. Cada una se incluye con su comodín, así que ningún comodín puede meter el
# secreto al nivel del server, y si falta algo nginx arranca igual (ver el paso de nginx).
NGINX_AVISOS=/etc/nginx/hehermes-avisos
FRAGMENTO="$NGINX_AVISOS/sitio/avisos.conf"
SECRETO_NGINX="$NGINX_AVISOS/secreto/vigia.conf"
SELLO="$NGINX_AVISOS/sello"
DISPOSITIVO=/usr/local/sbin/hehermes-dispositivo
VENV_PY="$PREFIJO/venv/bin/python"

[[ -f "$ORIGEN/requirements.txt" && -d "$ORIGEN/hehermes_avisos" ]] || fallar "no encuentro el código junto a $AQUI"
if ! grep -q -- "--solo-vigia" "$DISPOSITIVO" 2>/dev/null; then
  fallar "$DISPOSITIVO no sabe del vigía (es de antes, o no está): instala el de server/vpn con
    sudo install -m 0750 <repo>/server/vpn/hehermes-dispositivo /usr/local/sbin/
  y vuelve a ejecutar este script"
fi

# --- Python ------------------------------------------------------------------------------------------------------------
paso "Python"
command -v "$PY" >/dev/null || fallar "no hay $PY"
"$PY" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || fallar "hace falta Python 3.10 o más nuevo ($("$PY" -I --version 2>&1))"
if ! "$PY" -I -c 'import ensurepip, venv' 2>/dev/null; then
  # En Debian y Ubuntu, venv sin ensurepip viene aparte.
  paso "instalando python3-venv"
  apt-get install -y --no-install-recommends python3-venv
fi

# --- Usuarios ----------------------------------------------------------------------------------------------------------
paso "usuarios del sistema"
for usuario in hh-vigia hh-rele; do
  if ! id -u "$usuario" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$usuario"
    echo "    creado $usuario"
  fi
done

# --- Dependencias, antes que el código ---------------------------------------------------------------------------------
paso "entorno de Python en $PREFIJO/venv"
install -d -m 0755 -o root -g root "$PREFIJO"
[[ -x "$VENV_PY" ]] || "$PY" -I -m venv "$PREFIJO/venv"
# Antes de cambiar el código: sin red, o sin una rueda para este Python, se para aquí con el código de antes y sus
# dependencias de antes, que siguen funcionando juntos. Solo ruedas (--only-binary): nada se compila como root en el
# VPS. Y con --require-hashes: lo que se instala es exactamente lo que se probó, porque el relé tiene la clave de APNs
# y una dependencia cambiada por el camino la tendría también.
"$VENV_PY" -I -m pip install --disable-pip-version-check --no-input --quiet --only-binary=:all: --require-hashes \
  -r "$ORIGEN/requirements.txt"

# --- Código ------------------------------------------------------------------------------------------------------------
paso "código en $PREFIJO/src"
NUEVO="$PREFIJO/src.nuevo"
rm -rf "$NUEVO"
install -d -m 0755 "$NUEVO"
cp -R "$ORIGEN/hehermes_avisos" "$NUEVO/"
cp "$ORIGEN/README.md" "$ORIGEN/requirements.txt" "$NUEVO/"
find "$NUEVO" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$NUEVO"
find "$NUEVO" -type d -exec chmod 0755 {} +
find "$NUEVO" -type f -exec chmod 0644 {} +
# El cambio de código es un rename: los servicios nunca ven medio código viejo y medio nuevo.
rm -rf "$PREFIJO/src.viejo"
[[ -d "$PREFIJO/src" ]] && mv "$PREFIJO/src" "$PREFIJO/src.viejo"
mv "$NUEVO" "$PREFIJO/src"
rm -rf "$PREFIJO/src.viejo"
# El paquete, por un .pth del venv: con -I no vale PYTHONPATH, y así ni las unidades ni el README lo necesitan.
SITIO="$("$VENV_PY" -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
printf '%s\n' "$PREFIJO/src" > "$SITIO/hehermes-avisos.pth"
chmod 0644 "$SITIO/hehermes-avisos.pth"
# Precompilar ahorra el primer arranque, nada más (los servicios corren con -B): si falla, se dice y se sigue.
"$VENV_PY" -I -m compileall -q "$PREFIJO/src" \
  || echo "    no se ha podido precompilar el código: no pasa nada, Python lo lee del fuente"

# --- Configuración y secretos ------------------------------------------------------------------------------------------
paso "configuración en $CONF"
install -d -m 0755 -o root -g root "$CONF"
install -d -m 0750 -o root -g hh-vigia "$CONF/vigia"
install -d -m 0750 -o root -g hh-rele "$CONF/rele"
if [[ ! -e "$CONF/vigia.ini" ]]; then
  install -m 0640 -o root -g hh-vigia "$AQUI/vigia.ini.ejemplo" "$CONF/vigia.ini"
  echo "    escrito $CONF/vigia.ini (de ejemplo)"
fi
if [[ ! -e "$CONF/rele.ini" ]]; then
  install -m 0640 -o root -g hh-rele "$AQUI/rele.ini.ejemplo" "$CONF/rele.ini"
  echo "    escrito $CONF/rele.ini (de ejemplo)"
fi

paso "credencial del vigía ante el relé («$NOMBRE_CREDENCIAL»)"
# Reutiliza el secreto si ya existe; si no, lo crea. La huella va a credenciales.ini, el secreto no sale de su fichero.
"$VENV_PY" -I -m hehermes_avisos.rele --config "$CONF/rele.ini" credencial \
  --nombre "$NOMBRE_CREDENCIAL" --secreto "$CONF/vigia/credencial-rele" --credenciales "$CONF/rele/credenciales.ini"
chown hh-vigia:hh-vigia "$CONF/vigia/credencial-rele"
chmod 0600 "$CONF/vigia/credencial-rele"
chown root:hh-rele "$CONF/rele/credenciales.ini"
chmod 0640 "$CONF/rele/credenciales.ini"

paso "secreto entre el nginx del túnel y el vigía"
# nginx lo pone en cada petición de /avisos/ (X-HeHermes-Vigia) y el vigía no atiende nada sin él: quien le hable
# directo, sin pasar por nginx, no puede darse de alta en lugar del iPhone (y a nginx, esa location solo deja pasar lo
# que llega por el túnel). Se genera una vez, no se imprime nunca y no se pisa: si falta uno de los dos ficheros, se
# rehace desde el otro.
SECRETO_VIGIA="$CONF/vigia/secreto-tunel"
install -d -m 0755 -o root -g root "$NGINX_AVISOS" "$NGINX_AVISOS/sitio"
install -d -m 0700 -o root -g root "$NGINX_AVISOS/secreto"
# Si el de nginx se crea en esta pasada, el paso de nginx lo prueba (y lo quita si nginx no lo da por bueno).
SECRETO_NGINX_NUEVO=0
[[ -e "$SECRETO_NGINX" ]] || SECRETO_NGINX_NUEVO=1
"$VENV_PY" -I - "$SECRETO_VIGIA" "$SECRETO_NGINX" <<'PY'
import os, re, secrets, sys

vigia, nginx = sys.argv[1], sys.argv[2]
# Lo que da token_urlsafe: nada que pueda cerrar las comillas de nginx ni meterle otra directiva. El del vigía es de
# hh-vigia (tiene que poder leerlo), así que antes de copiarlo a la configuración de nginx se mira que sea eso y nada más.
SECRETO = r"[A-Za-z0-9_-]{32,128}"


def leer(ruta):
    """Lo que hay (unos pocos bytes: es un secreto), o None si no existe. Sin seguir enlaces."""
    try:
        fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as fichero:
        return fichero.read(4096).decode("utf-8", "replace")


def extraer(ruta, patron):
    texto = leer(ruta)
    if not texto or not texto.strip():
        return ""
    hallado = re.fullmatch(patron, texto)
    if not hallado:
        sys.exit("%s no tiene la forma que deja este instalador: míralo, bórralo si sobra y vuelve a ejecutarlo" % ruta)
    return hallado.group(1)


def escribir(ruta, texto):
    temporal = ruta + ".nuevo"
    fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fichero:
        fichero.write(texto)
    os.replace(temporal, ruta)


del_vigia = extraer(vigia, r"(%s)\n?" % SECRETO)
de_nginx = extraer(nginx, r'proxy_set_header X-HeHermes-Vigia "(%s)";\n?' % SECRETO)
if del_vigia and de_nginx and del_vigia != de_nginx:
    # Se pide borrar solo la copia del vigía: el instalador la rehace desde la de nginx, que es de root, y nginx no se
    # toca, así que ningún include se queda sin su fichero ni hace falta recargar nada.
    sys.exit("%s no lleva el mismo secreto que %s: borra la copia del vigía (%s) y vuelve a ejecutar el instalador, "
             "que la rehace desde la de nginx" % (vigia, nginx, vigia))
secreto = del_vigia or de_nginx or secrets.token_urlsafe(32)
if not del_vigia:
    escribir(vigia, secreto + "\n")
if not de_nginx:
    escribir(nginx, 'proxy_set_header X-HeHermes-Vigia "%s";\n' % secreto)
PY
chown hh-vigia:hh-vigia "$SECRETO_VIGIA"
chmod 0600 "$SECRETO_VIGIA"
chown root:root "$SECRETO_NGINX"
chmod 0600 "$SECRETO_NGINX"

# La clave .p8, si Daniel ya la ha puesto: que sea del relé y solo suya.
valor_de() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF/rele.ini" | head -1 | sed 's/[[:space:]]*$//'; }
P8="$(valor_de clave_p8)"
CLAVE_ID="$(valor_de clave_id)"
RELE_LISTO=0
if [[ -n "$P8" && ( -e "$P8" || -L "$P8" ) ]]; then
  # Es root cambiando el dueño de una ruta que sale de la configuración: solo un fichero de su carpeta (ni enlaces, ni
  # subcarpetas, ni «..»), que es además lo único que el relé puede leer.
  [[ "$(dirname -- "$P8")" == "$CONF/rele" && -f "$P8" && ! -L "$P8" ]] \
    || fallar "clave_p8 tiene que ser un fichero normal en $CONF/rele/ (es $P8)"
  chown hh-rele:hh-rele "$P8"
  chmod 0600 "$P8"
  if [[ -n "$CLAVE_ID" && "$CLAVE_ID" != "CAMBIAME" ]]; then RELE_LISTO=1; fi
fi

# --- nginx -------------------------------------------------------------------------------------------------------------
paso "nginx"
# Los includes de los avisos van con comodín: si falta algo, nginx sigue arrancando y nada queda abierto. Sin sitio/,
# /avisos/ no existe; sin secreto/, nginx no pone la cabecera y el vigía contesta 403 a todo.
# Todo lo que el instalador cambia aquí se prueba con `nginx -t`, lo incluya ya el sitio del túnel o no, y si no vale
# se deshace: un fichero roto que se quedara puesto tumbaría todos los sitios en el siguiente reinicio de nginx. Y nginx
# se recarga cuando algo suyo (el sitio del túnel, el fragmento o el secreto) cambió desde la última recarga buena, que
# es lo que guarda el sello: así también cuando Daniel añade el include y vuelve a ejecutar esto.
INCLUIDO=0
if [[ -f "$SITIO_TUNEL" ]] && grep -Eq '^[^#]*include[[:space:]]+/etc/nginx/hehermes-avisos/sitio/[^;]*;' "$SITIO_TUNEL"; then
  INCLUIDO=1
fi
ANTERIOR=""
CAMBIADO=0
if ! cmp -s "$AQUI/nginx-avisos.conf" "$FRAGMENTO"; then
  if [[ -f "$FRAGMENTO" ]]; then
    ANTERIOR="$(mktemp "$NGINX_AVISOS/.anterior.XXXXXX")"
    cp -p "$FRAGMENTO" "$ANTERIOR"
  fi
  install -m 0644 -o root -g root "$AQUI/nginx-avisos.conf" "$FRAGMENTO"
  CAMBIADO=1
fi
HUELLA="$({ cat -- "$SITIO_TUNEL" "$FRAGMENTO" "$SECRETO_NGINX" 2>/dev/null || true; } | sha256sum | cut -d' ' -f1)"
if [[ $CAMBIADO -eq 0 && $SECRETO_NGINX_NUEVO -eq 0 && "$HUELLA" == "$(cat "$SELLO" 2>/dev/null || true)" ]]; then
  echo "    nginx ya está al día: ni se prueba ni se recarga"
elif nginx -t -q; then
  # Sin hacer nada si nginx está parado: al arrancar, leerá lo nuevo.
  systemctl try-reload-or-restart nginx
  printf '%s\n' "$HUELLA" > "$SELLO"
  echo "    probado y recargado"
else
  MOTIVO="nginx -t falla (arriba dice por qué) y no se ha recargado"
  if [[ $CAMBIADO -eq 1 || $SECRETO_NGINX_NUEVO -eq 1 ]]; then
    if [[ $CAMBIADO -eq 1 ]]; then
      if [[ -n "$ANTERIOR" ]]; then mv "$ANTERIOR" "$FRAGMENTO"; else rm -f "$FRAGMENTO"; fi
      ANTERIOR=""
    fi
    # Un secreto de nginx recién creado se quita: la pasada siguiente lo rehace desde la copia del vigía.
    if [[ $SECRETO_NGINX_NUEVO -eq 1 ]]; then rm -f "$SECRETO_NGINX"; fi
    MOTIVO="$MOTIVO; lo que había cambiado de los avisos en nginx ha vuelto a como estaba"
  fi
  fallar "$MOTIVO"
fi
if [[ -n "$ANTERIOR" ]]; then rm -f "$ANTERIOR"; fi

paso "clave del api_server para el vigía (hehermes-dispositivo clave --solo-vigia)"
# El vigía lee a Hermes directo, con su propia copia de la clave. La escribe el mismo camino que la de nginx, para que
# cuando la clave cambie `sudo hehermes-dispositivo clave` lo arregle todo. Aquí, --solo-vigia: la de nginx no es
# asunto de este script, y así una pasada sin cambios no recarga nginx; si la copia ya está al día, tampoco se escribe
# ni reinicia el vigía. No la imprime nunca.
"$PY" -I "$DISPOSITIVO" clave --solo-vigia

# --- systemd -----------------------------------------------------------------------------------------------------------
paso "servicios de systemd"
# Primero los sockets: son los que tienen los puertos, y los servicios los heredan al arrancar. Un socket que cambia
# solo se aplica parándolo, y un socket no se para con su servicio en marcha: así que, solo si cambió, se para el
# servicio, se reinicia el socket y el servicio vuelve a arrancar con el nuevo.
CAMBIADOS=""
for unidad in hehermes-vigia hehermes-rele; do
  cmp -s "$AQUI/$unidad.socket" "/etc/systemd/system/$unidad.socket" || CAMBIADOS="$CAMBIADOS $unidad"
  install -m 0644 -o root -g root "$AQUI/$unidad.socket" "/etc/systemd/system/$unidad.socket"
  install -m 0644 -o root -g root "$AQUI/$unidad.service" "/etc/systemd/system/$unidad.service"
done
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/hehermes-vigia.socket /etc/systemd/system/hehermes-vigia.service \
  /etc/systemd/system/hehermes-rele.socket /etc/systemd/system/hehermes-rele.service \
  || echo "    (systemd-analyze avisa de algo en las unidades: míralo arriba)"
for unidad in hehermes-vigia hehermes-rele; do
  systemctl enable --quiet "$unidad.socket" "$unidad.service"
  if [[ " $CAMBIADOS " == *" $unidad "* ]]; then
    systemctl stop "$unidad.service"
    systemctl restart "$unidad.socket"
  else
    systemctl start "$unidad.socket"
  fi
done
# Con los dos puertos ya de systemd, los servicios: con el código nuevo, y el relé con la clave si Daniel ya la ha
# puesto (sin ella, arranca igual y contesta 503).
for unidad in hehermes-vigia hehermes-rele; do
  systemctl restart "$unidad.service"
done

# --- Comprobación ------------------------------------------------------------------------------------------------------
paso "comprobación (con los usuarios de los servicios)"
sleep 2
runuser -u hh-vigia -- "$VENV_PY" -I -m hehermes_avisos.vigia --config "$CONF/vigia.ini" comprobar || true
if [[ $RELE_LISTO -eq 1 ]]; then
  runuser -u hh-rele -- "$VENV_PY" -I -m hehermes_avisos.rele --config "$CONF/rele.ini" comprobar || true
fi

echo
estado() { systemctl is-active "$1" 2>/dev/null || true; }
echo "Hecho. Vigía: $(estado hehermes-vigia.service) (su puerto: $(estado hehermes-vigia.socket)). Relé:" \
  "$(estado hehermes-rele.service) (su puerto: $(estado hehermes-rele.socket))."
if [[ $RELE_LISTO -eq 0 ]]; then
  cat <<EOF

Falta la clave de APNs para el relé (mientras, está en marcha y contesta 503 a los avisos):
  1. sudo install -m 0600 -o hh-rele -g hh-rele AuthKey_XXXXXXXXXX.p8 ${P8:-$CONF/rele/AuthKey.p8}
  2. En $CONF/rele.ini, clave_id = el Key ID de esa clave (Team ID: 8X7L8YHD9M, ya puesto).
  3. Vuelve a ejecutar este script.
EOF
fi
if [[ $INCLUIDO -eq 0 ]]; then
  cat <<EOF

Falta que nginx lleve /avisos/ al vigía. Dentro del server { … } de $SITIO_TUNEL, antes de location / { … }:
    include /etc/nginx/hehermes-avisos/sitio/*.conf;
y vuelve a ejecutar este script (prueba nginx y lo recarga).
EOF
fi
