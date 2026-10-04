#!/usr/bin/env bash
# Установка панели в Linux / WSL (Ubuntu, Debian) рядом с nginx.
# Запуск из папки проекта:
#   sudo bash deploy/install-linux.sh
# Переменные: SITE_DOMAIN=домен сайта, NGINX_SITE=файл сайта nginx, ROTATE_ADMIN_PATH=1 (новый случайный адрес админки)
# Повторный запуск = обновление кода (данные в /opt/hy2panel/data и .env сохраняются).
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/hy2panel
SVC_USER=hy2panel
NGINX_SITE="${NGINX_SITE:-}"

[ "$(id -u)" = 0 ] || { echo "Запустите через sudo / Run with sudo"; exit 1; }

echo "== [1/6] Пакеты / Packages"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip

if [ -d "$DEST/app" ]; then
  BK="/opt/hy2panel-backup-$(date +%Y%m%d-%H%M%S).tgz"
  echo "== Бэкап текущей установки / Backup of the current install (code + database + keys) -> $BK"
  tar -C "$DEST" --exclude=./.venv --exclude=__pycache__ -czf "$BK" .
  chmod 600 "$BK"
  ls -1t /opt/hy2panel-backup-*.tgz 2>/dev/null | tail -n +6 | xargs -r rm -f   # хранить последние 5
fi

echo "== [2/6] Копирование / Copying: $SRC -> $DEST"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DEST" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$DEST"
tar -C "$SRC" --exclude=./.venv --exclude=./data --exclude=__pycache__ --exclude=./.env --exclude=./.git -cf - . \
  | tar -C "$DEST" -xf -
FRESH_ENV=0
if [ ! -f "$DEST/.env" ]; then
  FRESH_ENV=1
  if [ -f "$SRC/.env" ]; then cp "$SRC/.env" "$DEST/.env"; else cp "$DEST/.env.example" "$DEST/.env"; fi
fi
sed -i 's/\r$//' "$DEST/.env" "$DEST"/deploy/*.sh "$DEST"/deploy/*.service   # CRLF после Windows

# ---- чтение/запись параметров .env ----
getenv() { grep -E "^$1=" "$DEST/.env" | tail -n1 | cut -d= -f2- | tr -d '"'"'"' \r'; }
setenv() {
  if grep -qE "^$1=" "$DEST/.env"; then sed -i "s|^$1=.*|$1=$2|" "$DEST/.env"; else echo "$1=$2" >> "$DEST/.env"; fi
}

# ---- случайные адреса: сканеры перебирают известные пути (/admin, /panel…), поэтому по умолчанию они случайные ----
rand() { LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c "$1" || true; }
if [ "$FRESH_ENV" = 1 ]; then
  echo "== Адреса панели / Panel addresses"
  read -rp "Префикс для клиентов (кабинет, подписки): Enter = случайный, или свой, например /hy / Public prefix [random]: " BPIN || true
  BPIN="$(printf '%s' "$BPIN" | tr -cd 'A-Za-z0-9._/-' | sed -E 's|/+|/|g; s|^/||; s|/$||')"   # безопасные символы, без лишних /
  [ -n "$BPIN" ] || BPIN="$(rand 10)"
  setenv HY_BASE_PATH "/$BPIN"
  setenv HY_ADMIN_PATH "$(rand 16)"
fi
if [ "${ROTATE_ADMIN_PATH:-0}" = 1 ]; then
  setenv HY_ADMIN_PATH "$(rand 16)"
  echo "== Новый случайный адрес админки создан / New random admin path generated"
fi

# ---- переход на схему адресов: клиенты BASE/, админка BASE/admin/ (старый .env без HY_ADMIN_PATH) ----
if ! grep -qE '^HY_ADMIN_PATH=' "$DEST/.env"; then
  OLD="$(getenv HY_BASE_PATH)"; OLD="/${OLD#/}"; OLD="${OLD%/}"
  NEW="${NEW_BASE:-/hy}"
  cp -a "$DEST/.env" "$DEST/.env.bak-$(date +%Y%m%d-%H%M%S)"
  [ -n "$OLD" ] && [ "$OLD" != "$NEW" ] && setenv HY_LEGACY_BASE "$OLD"
  setenv HY_BASE_PATH "$NEW"
  setenv HY_ADMIN_PATH admin
  PU="$(getenv HY_PUBLIC_URL)"; PU="${PU%/}"
  if [ -n "$PU" ] && [ -n "$OLD" ] && [ "${PU%$OLD}" != "$PU" ]; then setenv HY_PUBLIC_URL "${PU%$OLD}$NEW"; fi
  echo "== Адреса изменены: клиенты ${NEW}/, админка ${NEW}/admin/ (старый префикс ${OLD:-—} перенаправляется, подписки по нему работают / old prefix kept for subscriptions)"
fi

# ---- домен сайта: для адресов в сообщениях и поиска конфига nginx ----
PU="$(getenv HY_PUBLIC_URL)"
if [ -z "${SITE_DOMAIN:-}" ]; then
  SITE_DOMAIN="$(printf '%s' "$PU" | sed -E 's|^https?://([^/:]+).*|\1|')"
  case "$SITE_DOMAIN" in
    ""|*example.com|http*) read -rp "Домен вашего сайта в nginx (например panel.mydomain.com) / Your site domain in nginx: " SITE_DOMAIN || true ;;
  esac
fi
[ -n "$SITE_DOMAIN" ] || { echo "Домен не указан / Domain is required"; exit 1; }
case "$PU" in
  ""|*example.com*) setenv HY_PUBLIC_URL "https://${SITE_DOMAIN}$(getenv HY_BASE_PATH)" ;;
esac

echo "== [3/6] Виртуальное окружение Python / Python virtual environment"
[ -x "$DEST/.venv/bin/python" ] || python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install -q --upgrade pip
"$DEST/.venv/bin/pip" install -q -r "$DEST/requirements.txt"
mkdir -p "$DEST/data"
chown -R "$SVC_USER:$SVC_USER" "$DEST"
chmod 700 "$DEST/data"
chmod 600 "$DEST/.env"

echo "== [4/6] Администратор панели / Panel administrator"
cd "$DEST"
N=$(sudo -u "$SVC_USER" .venv/bin/python -c "from app import db; db.init(); print(len(db.q('SELECT 1 FROM admins')))")
if [ "$N" = "0" ]; then
  read -rp "Логин администратора панели / Panel admin login: " ADMIN
  sudo -u "$SVC_USER" .venv/bin/python manage.py create-admin "$ADMIN"
else
  echo "Администраторы уже есть / Administrators already exist ($N)"
fi

echo "== [5/6] Служба systemd / systemd service"
if [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
  install -m 644 "$DEST/deploy/hy2panel.service" /etc/systemd/system/hy2panel.service
  systemctl daemon-reload
  systemctl enable hy2panel >/dev/null
  systemctl restart hy2panel
  sleep 3
  systemctl --no-pager --lines=5 status hy2panel || true
else
  cat <<'MSG'
!! systemd в этом WSL не включён. Включите его:
   1) sudo tee /etc/wsl.conf >/dev/null <<'EOF'
[boot]
systemd=true
EOF
   2) в PowerShell Windows: wsl --shutdown   (затем снова откройте Ubuntu)
   3) повторите: sudo bash /opt/hy2panel/deploy/install-linux.sh

!! systemd is not enabled in this WSL. Enable it: 1) put "systemd=true" under [boot] in /etc/wsl.conf,
   2) run "wsl --shutdown" in Windows PowerShell and reopen Ubuntu, 3) run this installer again.
MSG
fi

echo "== [6/6] nginx"
BP="$(getenv HY_BASE_PATH)"; BP="/${BP#/}"; BP="${BP%/}"
AP="$(getenv HY_ADMIN_PATH)"; AP="${AP:-admin}"; AP="${AP#/}"; AP="${AP%/}"
ADMIN="${BP}/${AP}"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/${SITE_DOMAIN}}"
if [ -z "$BP" ]; then
  echo "!! Задайте HY_BASE_PATH в $DEST/.env (например /hy) / Set HY_BASE_PATH in $DEST/.env (e.g. /hy) so the site is not shadowed"; exit 1
fi
PORT="$(getenv HY_PORT)"
PORT=${PORT:-8088}

mkdir -p /etc/nginx/snippets
# Правила доступа к админке — отдельный файл, создаётся один раз и при обновлении не перезаписывается
ACL=/etc/nginx/snippets/hy2panel-admin-acl.conf
if [ ! -f "$ACL" ]; then
  cat > "$ACL" <<'EOF'
# Кому разрешён вход в АДМИНКУ панели. Кабинет клиентов, подписки и статика открыты всем.
# Раскомментируйте и впишите свои адреса, затем: sudo nginx -t && sudo systemctl reload nginx
# Who may open the ADMIN area. The client cabinet, subscriptions and static files stay public.
# Uncomment and put your own addresses, then: sudo nginx -t && sudo systemctl reload nginx
# allow 192.168.1.0/24;
# allow <ваш_внешний_IP>;
# deny all;
EOF
fi

PROXY="proxy_pass http://127.0.0.1:${PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;"

# Прежние префиксы: подписки по старым ссылкам продолжают работать, остальное приложение перенаправляет на новые адреса
LEGACY_BLOCK=""
for LB in $(getenv HY_LEGACY_BASE | tr ',' ' '); do
  LB="/${LB#/}"; LB="${LB%/}"
  [ "$LB" = "/" ] || [ "$LB" = "$BP" ] && continue
  LEGACY_BLOCK="${LEGACY_BLOCK}
# Прежний адрес ${LB}: подписки работают, остальное перенаправляется
location ${LB}/ {
    limit_except GET { deny all; }
    ${PROXY}
}
location = ${LB} {
    limit_except GET { deny all; }
    ${PROXY}
}
"
done

cat > /etc/nginx/snippets/hy2panel.conf <<EOF
# Панель — генерируется install-linux.sh (не редактируйте, правила доступа — в hy2panel-admin-acl.conf).
# Подключается строкой include в server { listen 443 ... } сайта.
# Клиенты: ${BP}/    Админка: ${ADMIN}/    Подписки: ${BP}/sub/<токен>

# Подписки клиентов: открыты в интернет (защищены длинным случайным токеном), только GET
location ${BP}/sub/ {
    limit_except GET { deny all; }
    ${PROXY}
}

# Админка (длиннее префикс — выигрывает у ${BP}/)
location ${ADMIN}/ {
    include snippets/hy2panel-admin-acl.conf;
    ${PROXY}
    proxy_read_timeout 300s;
    client_max_body_size 2m;
}
location = ${ADMIN} { return 301 ${ADMIN}/; }

# Кабинет клиентов и файлы оформления: открыты в интернет (вход по логину/паролю клиента)
location ${BP}/ {
    ${PROXY}
    client_max_body_size 64k;
}
location = ${BP} { return 301 ${BP}/; }
${LEGACY_BLOCK}
EOF
echo "Создан / Created /etc/nginx/snippets/hy2panel.conf: clients ${BP}/ , admin ${ADMIN}/ -> 127.0.0.1:${PORT}"

reload_nginx() {
  if nginx -t; then
    systemctl reload nginx 2>/dev/null || nginx -s reload
    echo "nginx перезагружен / nginx reloaded"
  else
    echo "!! nginx -t не прошёл / failed — check /etc/nginx/snippets/hy2panel*.conf"
    return 1
  fi
}

if [ ! -f "$NGINX_SITE" ]; then
  echo "!! Не найден / Not found: $NGINX_SITE. Добавьте вручную / Add manually inside server { listen 443 ... }:"
  echo "   include snippets/hy2panel.conf;"
elif grep -q "snippets/hy2panel.conf" "$NGINX_SITE"; then
  echo "include уже есть / already present in $NGINX_SITE"
  reload_nginx
elif ! grep -Eq '^\s*listen\s+(0\.0\.0\.0:)?443' "$NGINX_SITE"; then
  echo "!! В $NGINX_SITE не найден 'listen 443' / no 'listen 443' in $NGINX_SITE. Добавьте вручную в HTTPS-блок / Add to the HTTPS server block:"
  echo "   include snippets/hy2panel.conf;"
else
  BAK="$NGINX_SITE.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$NGINX_SITE" "$BAK"
  # вставляем include сразу после первой строки "listen 443 ..." (внутри HTTPS-блока)
  awk '!done && /^[ \t]*listen[ \t]+(0\.0\.0\.0:)?443/ {print; print "    include snippets/hy2panel.conf;  # panel"; done=1; next} {print}' \
    "$BAK" > "$NGINX_SITE"
  if ! reload_nginx; then
    cp -a "$BAK" "$NGINX_SITE"
    echo "!! Конфиг сайта восстановлен / Site config restored from $BAK. Добавьте include вручную / Add the include by hand."
    exit 1
  fi
  echo "Бэкап конфига сайта / Site config backup: $BAK"
fi

echo
echo "Готово / Done."
echo "Клиенты / Clients:  https://${SITE_DOMAIN}${BP}/"
echo "Админка / Admin:    https://${SITE_DOMAIN}${ADMIN}/   <-- СОХРАНИТЕ этот адрес / SAVE this address (random)"
echo "Сменить адрес админки / New admin address: sudo ROTATE_ADMIN_PATH=1 bash deploy/install-linux.sh"
echo "Доступ к админке по IP / Restrict admin by IP: sudo nano $ACL"
echo "Логи / Logs:   journalctl -u hy2panel -f"
