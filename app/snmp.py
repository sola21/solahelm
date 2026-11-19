"""SNMP на VPS для внешнего мониторинга (LibreNMS и т. п.): v3 (authPriv) или v2c/v1 (сообщество).

Панель ставит snmpd, пишет /etc/snmp/snmpd.conf и открывает UDP 161 только для адреса мониторинга
(по умолчанию — адрес, с которого к VPS подключается сама панель). Пароли/сообщество генерируются панелью
и хранятся зашифрованными; их нужно один раз ввести в LibreNMS при добавлении устройства.
Пользователь v3 создаётся строкой createUser в /var/lib/snmp/snmpd.conf при остановленном snmpd —
так же делает net-snmp-create-v3-user, но без пакета libsnmp-dev.
"""
import ipaddress
import re
import secrets
import shlex
import time

from . import db, security
from .hy import HyError, RUN_SCRIPT, get_server, server_lock, sh_echo
from .ssh import Conn

VERSIONS = ("v3", "v2c", "v1")
AUTH_PROTOS = ("SHA", "SHA-256", "SHA-512")
PRIV_PROTOS = ("AES",)
USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
CONF = "/etc/snmp/snmpd.conf"
STATE = "/var/lib/snmp/snmpd.conf"


def secret(s: dict, key: str) -> str:
    return security.decrypt(s[key]) if s.get(key) else ""


def creds(s: dict) -> dict:
    """Параметры для LibreNMS (показываются на странице сервера)."""
    return {"version": s.get("snmp_version") or "v3", "user": s.get("snmp_user") or "librenms",
            "auth_proto": s.get("snmp_auth_proto") or "SHA", "priv_proto": s.get("snmp_priv_proto") or "AES",
            "auth": secret(s, "snmp_auth"), "priv": secret(s, "snmp_priv"), "community": secret(s, "snmp_community"),
            "allow": s.get("snmp_allow") or "", "location": s.get("snmp_location") or ""}


def check_opts(o: dict) -> str:
    if o["version"] not in VERSIONS:
        return "Неизвестная версия SNMP"
    if o["version"] == "v3":
        if not USER_RE.match(o["user"]):
            return "Имя пользователя SNMP: латиница, цифры, _ . - (до 32 символов, начинается с буквы)"
        if o["auth_proto"] not in AUTH_PROTOS or o["priv_proto"] not in PRIV_PROTOS:
            return "Неизвестный алгоритм SNMPv3"
    if o["allow"]:
        try:
            ipaddress.ip_network(o["allow"], strict=False)
        except ValueError:
            return "Адрес мониторинга: IP или подсеть, например 203.0.113.7 или 203.0.113.0/24"
    if len(o["location"]) > 100 or any(c in o["location"] for c in "\n\r\"\\$`'"):
        return "Местоположение: до 100 символов, без кавычек, символов $ и ` и переводов строки"
    return ""


def build_script(o: dict, auth: str, priv: str, community: str) -> str:
    q = shlex.quote
    allow = o["allow"]
    L = ["set -e", "export DEBIAN_FRONTEND=noninteractive",
         sh_echo("== [1/5] Пакеты snmpd и snmp"), "apt-get update -y", "apt-get install -y snmpd snmp",
         sh_echo("== [2/5] Адрес мониторинга"),
         f"ALLOW={q(allow)}",
         'if [ -z "$ALLOW" ]; then ALLOW="${SSH_CLIENT%% *}"; fi',
         'echo "SNMP будет доступен с: ${ALLOW:-любого адреса}"',
         "systemctl stop snmpd || true",
         sh_echo("== [3/5] Конфигурация"),
         f"if [ -f {CONF} ]; then cp -a {CONF} {CONF}.bak.$(date +%Y%m%d-%H%M%S); fi",
         "mkdir -p /var/lib/snmp /etc/snmp/snmpd.conf.d",
         # пользователи v3 управляются панелью: старые записи убираем, нового создаём при запуске snmpd
         f"touch {STATE}; sed -i '/^usmUser /d; /^createUser /d' {STATE}"]
    if o["version"] == "v3":
        L.append(f"echo {q('createUser ' + o['user'] + ' ' + o['auth_proto'] + ' ' + auth + ' ' + o['priv_proto'] + ' ' + priv)} >> {STATE}")
        access = f"rouser {o['user']} priv"
    else:
        # rocommunity: источник — адрес мониторинга из переменной оболочки (default — любой адрес)
        access = f"rocommunity {community} ${{ALLOW:-default}}"
    conf = ["# Created by SolaHelm. Changes are overwritten when SNMP is applied from the panel.",
            "agentaddress udp:161", access,
            f"sysLocation {o['location'] or 'SolaHelm VPS'}", "includeDir /etc/snmp/snmpd.conf.d"]
    # heredoc без кавычек вокруг метки, чтобы подставился $ALLOW; в остальных строках нет $ и ` (их не пускает check_opts)
    L += [f"cat > {CONF} <<HY2PANEL_SNMP", "\n".join(conf), "HY2PANEL_SNMP", f"chmod 600 {CONF}",
          sh_echo("== [4/5] Запуск snmpd"), "systemctl enable snmpd", "systemctl restart snmpd", "sleep 2",
          "systemctl is-active --quiet snmpd || { journalctl -u snmpd -n 30 --no-pager -o cat; exit 1; }",
          sh_echo("== [5/5] ufw и проверка"),
          "if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then",
          "  ufw status numbered | grep -E '161/udp' | sed -E 's/^\\[ *([0-9]+)\\].*/\\1/' | sort -rn | while read -r n; do ufw --force delete \"$n\"; done",
          '  if [ -n "$ALLOW" ]; then ufw allow from "$ALLOW" to any port 161 proto udp; else ufw allow 161/udp; fi',
          "fi"]
    if o["version"] == "v3":
        L.append(f"snmpget -v3 -l authPriv -u {q(o['user'])} -a {o['auth_proto']} -A {q(auth)} -x {o['priv_proto']} -X {q(priv)} "
                 "127.0.0.1 SNMPv2-MIB::sysDescr.0 SNMPv2-MIB::sysUpTime.0 SNMPv2-MIB::sysLocation.0")
    else:
        L.append(f"snmpget -v{'2c' if o['version'] == 'v2c' else '1'} -c {q(community)} 127.0.0.1 "
                 "SNMPv2-MIB::sysDescr.0 SNMPv2-MIB::sysUpTime.0 SNMPv2-MIB::sysLocation.0 || "
                 + sh_echo("(проверка с 127.0.0.1 не прошла: доступ ограничен адресом мониторинга — это нормально)"))
    L.append(sh_echo("== Готово: SNMP работает"))
    return "\n".join(L) + "\n"


def apply(sid: int, o: dict, log) -> None:
    """Установить/перенастроить snmpd. o: version, user, auth_proto, priv_proto, allow, location, regen."""
    with server_lock(sid):
        s = get_server(sid)
        auth, priv, community = secret(s, "snmp_auth"), secret(s, "snmp_priv"), secret(s, "snmp_community")
        if o["regen"] or (o["version"] == "v3" and not (auth and priv)):
            auth, priv = secrets.token_hex(16), secrets.token_hex(16)
        if o["regen"] or (o["version"] != "v3" and not community):
            community = secrets.token_hex(12)
        log(f"Подключение к {s['host']}:{s['ssh_port']} как {s['ssh_user']}…\n")
        with Conn(s, timeout=20) as c:
            code = c.run_stream(RUN_SCRIPT, build_script(o, auth, priv, community), log, timeout=900)
        if code != 0:
            raise HyError(f"Настройка SNMP завершилась с кодом {code}")
        db.ex("UPDATE servers SET snmp_enabled=1, snmp_version=?, snmp_user=?, snmp_auth_proto=?, snmp_priv_proto=?, "
              "snmp_auth=?, snmp_priv=?, snmp_community=?, snmp_allow=?, snmp_location=? WHERE id=?",
              (o["version"], o["user"], o["auth_proto"], o["priv_proto"], security.encrypt(auth), security.encrypt(priv),
               security.encrypt(community), o["allow"], o["location"], sid))
        db.audit("server.snmp", f"{s['name']}: {o['version']}", "system")
        log("\nПараметры для LibreNMS — на странице сервера, в блоке «Мониторинг SNMP».\n")


REMOVE = """set -e
systemctl disable --now snmpd 2>/dev/null || true
if command -v ufw >/dev/null 2>&1; then
  ufw status numbered | grep -E '161/udp' | sed -E 's/^\\[ *([0-9]+)\\].*/\\1/' | sort -rn | while read -r n; do ufw --force delete "$n"; done
fi
DEBIAN_FRONTEND=noninteractive apt-get remove -y snmpd || true
echo "SNMP removed"
"""


def remove(sid: int, log) -> None:
    with server_lock(sid):
        s = get_server(sid)
        if not s.get("snmp_enabled"):
            raise HyError("SNMP на этом сервере не настроен")
        with Conn(s, timeout=20) as c:
            code = c.run_stream(RUN_SCRIPT, REMOVE, log, timeout=600)
        if code != 0:
            raise HyError(f"Удаление SNMP завершилось с кодом {code}")
        db.ex("UPDATE servers SET snmp_enabled=0 WHERE id=?", (sid,))
        db.audit("server.snmp.remove", s["name"], "system")
        log("Мониторинг SNMP выключен. Удалите устройство в LibreNMS, если оно больше не нужно.\n")
