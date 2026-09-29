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
#   /usr/local/libexec/hehermes-leer-media          el lector de los ficheros que Hermes marca con MEDIA: (root 0755)
#   /etc/systemd/system/hehermes-leer-media.socket y hehermes-leer-media@.service   su socket (root:hh-vigia 0660) y
#                                                   un lector de root, enjaulado, por cada conexión
#
#   sudo …/instalar.sh --desinstalar-lector         quita solo el lector (y con él, GET /avisos/v1/fichero da 503)
#
# La entrada pública del relé (spec 2026-09-28, «El relé para los probadores»): por donde llegan los avisos de los
# vigías de otros servidores. Se pone una vez, y desde entonces cada pasada la mantiene:
#
#   sudo …/instalar.sh --rele-publico               la primera vez: elige su puerto, hace su certificado y abre el
#                                                   cortafuegos. RELE_DIRECCION=<ip o nombre> si la de los códigos no
#                                                   es la de la pasarela
#   sudo …/instalar.sh --quitar-rele-publico        la para y cierra su puerto; el puerto, el certificado y las
#                                                   credenciales se quedan (volver a ponerla no invalida los códigos)
#
#   /etc/hehermes-avisos/rele-publico.ini           su puerto y su dirección (root:hh-rele-publico 0640)
#   /etc/hehermes-avisos/rele-publico/              cert.pem (0644), clave.pem y permisos.pem (root 0600, le llegan por
#                                                   LoadCredential); la pública de los permisos en rele/permisos.pub.pem
#   /var/lib/hehermes-rele-publico/permisos.db      las claves de App Attest atestadas (la crea systemd)
#   /etc/hehermes-avisos/rele/permisos-revocados.txt   los permisos revocados (root:hh-rele 0640)
#   /etc/systemd/system/hehermes-rele-publico.service   como hh-rele-publico, que no puede leer la .p8
#   /usr/local/sbin/hehermes-rele                   `sudo hehermes-rele credencial alta|baja|lista`
#   /opt/hehermes-avisos/src/hehermes_servidor      la maquinaria de la pasarela, copiada de server/instalador
#
# El lector va por un socket de systemd y no por sudo: el vigía corre con NoNewPrivileges (sudo no podría subir) y
# ProtectHome (no vería /root), y quitárselos sería abrir el proceso que atiende al túnel. Así el vigía no tiene nada
# de root y el lector, su propia jaula (despliegue/hehermes-leer-media@.service).
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
SYSTEMD=/etc/systemd/system
LECTOR=/usr/local/libexec/hehermes-leer-media
UNIDADES_LECTOR="hehermes-leer-media.socket hehermes-leer-media@.service"
PROC=/proc

# --- El lector de ficheros (funciones) ---------------------------------------------------------------------------------
# Lo usan la instalación (en el paso de systemd) y --desinstalar-lector. Todo por las variables de arriba.
LECTOR_CAMBIADO=0
HERMES_DE_SERIE=/root/.hermes
# Lo único que sale de la carpeta de Hermes (desde la 1.4.0, una lista de permitidas): sus dos caches y la carpeta de
# exportaciones, que crea este instalador. La unidad las deja ver (BindReadOnlyPaths) y tapa el resto de las casas.
PERMITIDAS_HERMES="image_cache audio_cache exports"
ANADIDO_LECTOR="$SYSTEMD/hehermes-leer-media@.service.d/hermes-home.conf"

hermes_del_gateway() {
  # HERMES_HOME de hermes-gateway: el de su proceso en marcha (así cuenta también un EnvironmentFile=), y si no está
  # en marcha, el Environment= de su unidad. Sin nada, el de serie.
  local pid casa="" variable
  pid="$(systemctl show -p MainPID --value hermes-gateway 2>/dev/null || true)"
  if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "$PROC/$pid/environ" ]]; then
    # Cada variable hasta su NUL, con lo que lleve dentro (un salto de línea incluido: así lo ve la comprobación).
    while IFS= read -r -d '' variable; do
      if [[ "$variable" == HERMES_HOME=* ]]; then casa="${variable#HERMES_HOME=}"; break; fi
    done < "$PROC/$pid/environ"
  fi
  if [[ -z "$casa" ]]; then
    local entorno
    entorno="$(systemctl show -p Environment --value hermes-gateway 2>/dev/null || true)"
    casa="$(printf '%s\n' "$entorno" | tr ' ' '\n' | sed -n 's/^HERMES_HOME=//p' | head -1)"
    # systemd pone entre comillas lo que lleva espacios: eso no se adivina, se dice.
    [[ -n "$casa" || "$entorno" != *HERMES_HOME=* ]] \
      || fallar "no entiendo el HERMES_HOME de la unidad de hermes-gateway (${entorno})"
  fi
  casa="${casa:-$HERMES_DE_SERIE}"
  casa="${casa%/}"
  # Va a una línea de systemd: solo lo que no puede romperla ni meterle otra opción.
  [[ "$casa" =~ ^/[A-Za-z0-9._/-]+$ && "$casa" != *"/../"* && "$casa" != *"/.." ]] \
    || fallar "HERMES_HOME de hermes-gateway («${casa}») no es una carpeta absoluta que el lector pueda usar"
  echo "$casa"
}

instalar_lector() {
  # El script, con un rename: systemd lanza uno por conexión, y ninguno puede encontrarse medio fichero escrito.
  install -d -m 0755 -o root -g root "$(dirname "$LECTOR")"
  if ! cmp -s "$AQUI/hehermes-leer-media" "$LECTOR"; then
    install -m 0755 -o root -g root "$AQUI/hehermes-leer-media" "$LECTOR.nuevo"
    mv -f "$LECTOR.nuevo" "$LECTOR"
    echo "    lector puesto en $LECTOR"
  fi
  local unidad
  for unidad in $UNIDADES_LECTOR; do
    if ! cmp -s "$AQUI/$unidad" "$SYSTEMD/$unidad"; then
      install -m 0644 -o root -g root "$AQUI/$unidad" "$SYSTEMD/$unidad"
      LECTOR_CAMBIADO=1
    fi
  done
  # Si Hermes no vive en /root/.hermes, un añadido a la unidad le dice al lector dónde (y qué carpetas dejarle ver).
  local casa texto permitida vistas="" dueno usuario=""
  casa="$(hermes_del_gateway)"
  crear_exportaciones "$casa"
  if [[ "$casa" == "$HERMES_DE_SERIE" ]]; then
    if [[ -e "$ANADIDO_LECTOR" ]]; then
      rm -f "$ANADIDO_LECTOR"
      rmdir "$(dirname "$ANADIDO_LECTOR")" 2>/dev/null || true
      LECTOR_CAMBIADO=1
    fi
    return 0
  fi
  for permitida in $PERMITIDAS_HERMES; do vistas="$vistas -$casa/$permitida"; done
  # Sin capacidades, el lector lee como el dueño de la casa de Hermes: si no es root, como él.
  dueno="$(stat -c %U "$casa" 2>/dev/null || echo root)"
  [[ "$dueno" =~ ^[a-z_][a-z0-9_-]*$ && "$dueno" != root ]] && usuario="
User=$dueno"
  texto="# Lo escribe instalar.sh: el HERMES_HOME de hermes-gateway es $casa, no $HERMES_DE_SERIE.
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I -S -B $LECTOR --hermes-home=$casa --conexion
BindReadOnlyPaths=
BindReadOnlyPaths=${vistas# }$usuario"
  if [[ ! -f "$ANADIDO_LECTOR" || "$(cat "$ANADIDO_LECTOR")" != "$texto" ]]; then
    install -d -m 0755 -o root -g root "$(dirname "$ANADIDO_LECTOR")"
    printf '%s\n' "$texto" > "$ANADIDO_LECTOR.nuevo"
    chmod 0644 "$ANADIDO_LECTOR.nuevo"
    mv -f "$ANADIDO_LECTOR.nuevo" "$ANADIDO_LECTOR"
    LECTOR_CAMBIADO=1
  fi
  echo "    Hermes vive en $casa (del entorno de hermes-gateway): de ahí el lector solo lee sus caches y exports/"
}

crear_exportaciones() {
  # La carpeta donde Hermes deja lo que quiere mandarle al iPhone, del dueño de su casa y solo suya. Si la casa aún no
  # existe (Hermes sin instalar), no se inventa: el lector contesta que no está hasta que se vuelva a lanzar esto.
  local casa="$1" dueno grupo
  [[ -d "$casa" ]] || return 0
  [[ -d "$casa/exports" ]] && return 0
  dueno="$(stat -c %U "$casa" 2>/dev/null || echo root)"
  grupo="$(stat -c %G "$casa" 2>/dev/null || echo root)"
  install -d -m 0700 -o "$dueno" -g "$grupo" "$casa/exports"
  echo "    carpeta de exportaciones de Hermes: $casa/exports (lo que Hermes deje ahí con MEDIA:, la app lo descarga)"
}

arrancar_lector() {
  # Solo el socket se habilita: el servicio es una plantilla, que lanza el socket por cada conexión. Si su unidad cambió,
  # se reinicia (las descargas en marcha siguen: cada una es su propio proceso con su propia conexión).
  systemctl enable --quiet hehermes-leer-media.socket
  if [[ $LECTOR_CAMBIADO -eq 1 ]]; then
    systemctl restart hehermes-leer-media.socket
  else
    systemctl start hehermes-leer-media.socket
  fi
}

desinstalar_lector() {
  paso "quitando el lector de ficheros"
  systemctl disable --now --quiet hehermes-leer-media.socket 2>/dev/null || true
  systemctl stop 'hehermes-leer-media@*.service' 2>/dev/null || true
  local unidad
  for unidad in $UNIDADES_LECTOR; do
    rm -f "$SYSTEMD/$unidad"
  done
  rm -f "$ANADIDO_LECTOR" "$ANADIDO_LECTOR.nuevo"
  rmdir "$(dirname "$ANADIDO_LECTOR")" 2>/dev/null || true
  rm -f "$LECTOR" "$LECTOR.nuevo"
  systemctl daemon-reload
  echo "    quitado: GET /avisos/v1/fichero contesta 503 hasta que se vuelva a instalar"
}
# --- fin del lector ----------------------------------------------------------------------------------------------------

# --- La entrada pública del relé (funciones) ---------------------------------------------------------------------------
PUBLICO_INI="$CONF/rele-publico.ini"
PUBLICO_CARPETA="$CONF/rele-publico"
PUBLICO_UNIDAD=hehermes-rele-publico.service
PUBLICO_USUARIO=hh-rele-publico
ORDEN_RELE=/usr/local/sbin/hehermes-rele
COMENTARIO_UFW=hehermes-rele

puerto_publico() { sed -n 's/^[[:space:]]*puerto[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$PUBLICO_INI" | head -1; }

abrir_cortafuegos() {
  # Con la herramienta que haya, como el instalador con la pasarela: se añade la regla, no se enciende nada.
  local puerto="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow proto tcp from any to any port "$puerto" comment "$COMENTARIO_UFW" | sed 's/^/    ufw: /'
    ufw status | head -1 | grep -q "Status: active" \
      || echo "    ufw está apagado: la regla queda puesta para cuando se encienda"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --quiet --add-port="$puerto/tcp"
    firewall-cmd --quiet --permanent --add-port="$puerto/tcp"
    echo "    firewalld: abierto el TCP $puerto"
  else
    echo "    no hay ufw ni firewalld: si nftables o iptables cierran el paso, abre el TCP $puerto a mano"
  fi
  echo "    y si tu proveedor tiene un cortafuegos en su panel, abre ahí también el TCP $puerto"
}

cerrar_cortafuegos() {
  local puerto="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow proto tcp from any to any port "$puerto" | sed 's/^/    ufw: /' || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --quiet --remove-port="$puerto/tcp" || true
    firewall-cmd --quiet --permanent --remove-port="$puerto/tcp" || true
  fi
}

quitar_rele_publico() {
  paso "quitando la entrada pública del relé"
  systemctl disable --now --quiet "$PUBLICO_UNIDAD" 2>/dev/null || true
  rm -f "$SYSTEMD/$PUBLICO_UNIDAD"
  systemctl daemon-reload
  if [[ -f "$PUBLICO_INI" ]]; then
    cerrar_cortafuegos "$(puerto_publico)"
  fi
  echo "    quitada: los vigías de otros servidores ya no llegan al relé. Se quedan $PUBLICO_INI y el certificado, así"
  echo "    que volver a ponerla (--rele-publico) no invalida ningún código; las credenciales, en «hehermes-rele credencial"
  echo "    lista». Para borrarlo todo: rm -r $PUBLICO_INI $PUBLICO_CARPETA y userdel $PUBLICO_USUARIO"
}
# --- fin de la entrada pública -----------------------------------------------------------------------------------------

RELE_PUBLICO=0
if [[ $# -gt 0 ]]; then
  [[ $# -eq 1 ]] || fallar "uso: instalar.sh [--desinstalar-lector | --rele-publico | --quitar-rele-publico]"
  case "$1" in
    --desinstalar-lector) desinstalar_lector; exit 0 ;;
    --quitar-rele-publico) quitar_rele_publico; exit 0 ;;
    --rele-publico) RELE_PUBLICO=1 ;;
    *) fallar "uso: instalar.sh [--desinstalar-lector | --rele-publico | --quitar-rele-publico]" ;;
  esac
fi
# Una vez puesta, cada pasada la mantiene (con el código nuevo): se sabe por su unidad.
if [[ -f "$SYSTEMD/$PUBLICO_UNIDAD" ]]; then RELE_PUBLICO=1; fi
PASARELA_ORIGEN="$(cd "$ORIGEN/.." && pwd)/instalador/hehermes_servidor"

[[ -f "$ORIGEN/requirements.txt" && -d "$ORIGEN/hehermes_avisos" ]] || fallar "no encuentro el código junto a $AQUI"
if [[ $RELE_PUBLICO -eq 1 && ! -f "$PASARELA_ORIGEN/pasarela.py" ]]; then
  fallar "la entrada pública del relé usa la pasarela del instalador, y no está en $PASARELA_ORIGEN (copia server/ entero)"
fi
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
# El lector de ficheros corre con el Python del sistema, sin venv (no tiene dependencias).
/usr/bin/python3 -I -S -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || fallar "el lector de ficheros necesita /usr/bin/python3, 3.9 o más nuevo"
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
# La maquinaria de la pasarela, que usa la entrada pública del relé (y el vigía sin root, para leer el .env): la misma
# que la del instalador, copiada tal cual. Sin ella, el relé y el vigía de esta máquina funcionan igual.
if [[ -f "$PASARELA_ORIGEN/pasarela.py" ]]; then
  install -d -m 0755 "$NUEVO/hehermes_servidor"
  cp "$PASARELA_ORIGEN"/*.py "$NUEVO/hehermes_servidor/"
fi
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
instalar_lector
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/hehermes-vigia.socket /etc/systemd/system/hehermes-vigia.service \
  /etc/systemd/system/hehermes-rele.socket /etc/systemd/system/hehermes-rele.service \
  "$SYSTEMD/hehermes-leer-media.socket" \
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
# El socket del lector, antes que el vigía: el vigía no lo necesita para arrancar, pero así nunca contesta 503 a un
# fichero por haber arrancado primero.
arrancar_lector
# Con los dos puertos ya de systemd, los servicios: con el código nuevo, y el relé con la clave si Daniel ya la ha
# puesto (sin ella, arranca igual y contesta 503).
for unidad in hehermes-vigia hehermes-rele; do
  systemctl restart "$unidad.service"
done

# La orden de las credenciales, siempre (sin la entrada pública, `alta` dice que falta).
install -m 0755 -o root -g root "$AQUI/hehermes-rele" "$ORDEN_RELE.nuevo"
mv -f "$ORDEN_RELE.nuevo" "$ORDEN_RELE"

# --- La entrada pública del relé ---------------------------------------------------------------------------------------
if [[ $RELE_PUBLICO -eq 1 ]]; then
  paso "la entrada pública del relé"
  if ! id -u "$PUBLICO_USUARIO" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$PUBLICO_USUARIO"
    echo "    creado $PUBLICO_USUARIO"
  fi
  install -d -m 0755 -o root -g root "$PUBLICO_CARPETA"
  # La primera vez elige el puerto y hace el certificado; después no toca nada (van en los códigos que ya se dieron).
  "$VENV_PY" -I -B -m hehermes_avisos.rele.publico preparar --config "$PUBLICO_INI" --carpeta "$PUBLICO_CARPETA" \
    --credenciales "$CONF/rele/credenciales.ini" ${RELE_DIRECCION:+--direccion "$RELE_DIRECCION"} | grep -v '^PUERTO='
  PUERTO_PUBLICO="$(puerto_publico)"
  [[ "$PUERTO_PUBLICO" =~ ^[0-9]+$ ]] || fallar "$PUBLICO_INI no dice su puerto"
  chown "root:$PUBLICO_USUARIO" "$PUBLICO_INI"
  chmod 0640 "$PUBLICO_INI"
  chown root:root "$PUBLICO_CARPETA/cert.pem" "$PUBLICO_CARPETA/clave.pem" "$PUBLICO_CARPETA/permisos.pem"
  chmod 0644 "$PUBLICO_CARPETA/cert.pem"
  chmod 0600 "$PUBLICO_CARPETA/clave.pem" "$PUBLICO_CARPETA/permisos.pem"
  # La oficina de permisos (App Attest): la privada, de root (le llega por LoadCredential); la pública, para el relé;
  # la lista de revocados, que leen los dos y escribe `hehermes-rele permiso revocar`.
  chown root:root "$CONF/rele/permisos.pub.pem"
  chmod 0644 "$CONF/rele/permisos.pub.pem"
  if [[ ! -f "$CONF/rele/permisos-revocados.txt" ]]; then
    printf '%s\n' "# Permisos de avisos revocados: k:<SHA-256 del keyId> o t:<SHA-256 del token>, uno por línea." \
      "# Lo escribe \`hehermes-rele permiso revocar|readmitir\`." > "$CONF/rele/permisos-revocados.txt"
  fi
  chown root:hh-rele "$CONF/rele/permisos-revocados.txt"
  chmod 0640 "$CONF/rele/permisos-revocados.txt"
  install -m 0644 -o root -g root "$AQUI/$PUBLICO_UNIDAD" "$SYSTEMD/$PUBLICO_UNIDAD"
  systemctl daemon-reload
  systemctl enable --quiet "$PUBLICO_UNIDAD"
  # Con el código nuevo. Las conexiones abiertas de los vigías se cortan: reintentan solos.
  systemctl restart "$PUBLICO_UNIDAD"
  abrir_cortafuegos "$PUERTO_PUBLICO"
fi

# --- Comprobación ------------------------------------------------------------------------------------------------------
paso "comprobación (con los usuarios de los servicios)"
sleep 2
runuser -u hh-vigia -- "$VENV_PY" -I -m hehermes_avisos.vigia --config "$CONF/vigia.ini" comprobar || true
if [[ $RELE_LISTO -eq 1 ]]; then
  runuser -u hh-rele -- "$VENV_PY" -I -m hehermes_avisos.rele --config "$CONF/rele.ini" comprobar || true
fi
if [[ $RELE_PUBLICO -eq 1 ]]; then
  "$VENV_PY" -I -B -m hehermes_avisos.rele.publico comprobar --config "$PUBLICO_INI" || true
fi

echo
estado() { systemctl is-active "$1" 2>/dev/null || true; }
echo "Hecho. Vigía: $(estado hehermes-vigia.service) (su puerto: $(estado hehermes-vigia.socket)). Relé:" \
  "$(estado hehermes-rele.service) (su puerto: $(estado hehermes-rele.socket))."
if [[ $RELE_PUBLICO -eq 1 ]]; then
  echo "Entrada pública del relé: $(estado "$PUBLICO_UNIDAD"), en el TCP $PUERTO_PUBLICO. Un vigía de otro servidor:" \
    "sudo hehermes-rele credencial alta <nombre>"
fi
# Con la pasarela (el VPS de hoy), /avisos/ le llega al vigía por ella: el nginx del túnel ya no hace falta.
if grep -Eq '^[[:space:]]*vigia[[:space:]]*=' /etc/hehermes-pasarela/pasarela.ini 2>/dev/null; then
  INCLUIDO=1
fi
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
