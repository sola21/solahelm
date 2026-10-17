"""Защита SSH на VPS: fail2ban (jail sshd) и запрет входа по паролю.

Панель сама входит на сервер по SSH, поэтому всё делается с подстраховкой:
- IP, с которого подключается панель, всегда попадает в ignoreip fail2ban (панель не забанит саму себя);
- вход по паролю запрещается, только если панель уже входит по ключу, и после изменения проверяется новым
  SSH-подключением; если оно не удалось, настройка откатывается через ещё открытое старое соединение.
"""
import ipaddress
import json
import re
import shlex
import time

from . import db
from .hy import HyError, RUN_SCRIPT, get_server, server_lock, sh_echo
from .ssh import Conn, SSHError

JAIL_FILE = "/etc/fail2ban/jail.d/solahelm.local"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-solahelm.conf"
DEFAULTS = {"maxretry": 5, "findtime": 10, "bantime": 60}  # попыток, минут, минут
PUBKEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|"
                       r"sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]{40,}( [^\r\n]{0,200})?$")

# Состояние: одна команда, вывод key=value. Неудачные входы считаются по журналу sshd в journald за сутки.
STATUS_SCRIPT = r"""
echo "client=${SSH_CLIENT%% *}"
if command -v fail2ban-client >/dev/null 2>&1; then echo f2b_installed=1; else echo f2b_installed=0; fi
echo "f2b_active=$(systemctl is-active fail2ban 2>/dev/null || true)"
[ -f __JAIL__ ] && echo jail_file=1 || echo jail_file=0
if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd >/tmp/.sh_f2b 2>/dev/null; then
  echo "jail=1"
  echo "banned_now=$(sed -n 's/.*Currently banned:[[:space:]]*//p' /tmp/.sh_f2b)"
  echo "banned_total=$(sed -n 's/.*Total banned:[[:space:]]*//p' /tmp/.sh_f2b)"
  echo "banned_list=$(sed -n 's/.*Banned IP list:[[:space:]]*//p' /tmp/.sh_f2b)"
else
  echo "jail=0"
fi
rm -f /tmp/.sh_f2b
n=$(journalctl -q --no-pager --since "24 hours ago" -t sshd -t sshd-session 2>/dev/null \
    | awk '/Invalid user/ || (/Failed (password|keyboard-interactive)/ && !/for invalid user/) {c++} END {print c+0}')
echo "failed_24h=${n:-0}"
sshd -T 2>/dev/null | awk '$1=="passwordauthentication"||$1=="permitrootlogin"||$1=="kbdinteractiveauthentication"{print "sshd_"$1"="$2}'
echo "sshd_port=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | paste -sd, -)"
[ -f __DROPIN__ ] && echo dropin=1 || echo dropin=0
grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config 2>/dev/null && echo include=1 || echo include=0
""".replace("__JAIL__", JAIL_FILE).replace("__DROPIN__", SSHD_DROPIN)


def _parse(out: str) -> dict:
    d: dict = {}
    for line in out.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            d[k.strip()] = v.strip()
    return {
        "client_ip": d.get("client", ""),
        "f2b_installed": d.get("f2b_installed") == "1",
        "f2b_active": d.get("f2b_active", ""),
        "jail_file": d.get("jail_file") == "1",
        "jail": d.get("jail") == "1",
        "banned_now": int(d.get("banned_now") or 0),
        "banned_total": int(d.get("banned_total") or 0),
        "banned": [x for x in (d.get("banned_list") or "").split() if x],
        "failed_24h": int(d.get("failed_24h") or 0),
        "password_auth": d.get("sshd_passwordauthentication", ""),
        "kbd_auth": d.get("sshd_kbdinteractiveauthentication", ""),
        "root_login": d.get("sshd_permitrootlogin", ""),
        "ssh_port": d.get("sshd_port", ""),
        "dropin": d.get("dropin") == "1",
        "include": d.get("include") == "1",
    }


def status(sid: int) -> dict:
    s = get_server(sid)
    with Conn(s, timeout=20) as c:
        code, out, err = c.run(RUN_SCRIPT, input=STATUS_SCRIPT, timeout=60)
    st = _parse(out)
    st["key_login"] = s.get("ssh_auth") in ("panelkey", "key")
    st["ssh_user"] = s.get("ssh_user") or "root"
    st["ts"] = int(time.time())
    db.ex("UPDATE servers SET guard_cache=? WHERE id=?", (json.dumps(st), sid))
    return st


def cached(s: dict) -> dict | None:
    """Последнее сохранённое состояние (без подключения к серверу)."""
    try:
        return json.loads(s.get("guard_cache") or "null")
    except ValueError:
        return None


# ---------------- fail2ban ----------------
def parse_ignore(text: str) -> list[str]:
    """Список IP/сетей через пробел, запятую или с новой строки; неверные записи — ошибка."""
    items = []
    for tok in re.split(r"[\s,;]+", text or ""):
        if not tok:
            continue
        try:
            items.append(str(ipaddress.ip_network(tok, strict=False)))
        except ValueError:
            raise HyError(f"Неверный IP или сеть в списке исключений: {tok}")
    return items


def jail_config(port: str, ignore: list[str], maxretry: int, findtime: int, bantime: int) -> str:
    ign = " ".join(["127.0.0.1/8", "::1"] + [x for x in ignore if x not in ("127.0.0.1/8", "::1")])
    return (
        "# Created by SolaHelm (SSH protection). Changes made in the panel overwrite this file.\n"
        "[DEFAULT]\n"
        f"ignoreip = {ign}\n"
        f"bantime = {bantime}m\n"
        f"findtime = {findtime}m\n"
        f"maxretry = {maxretry}\n"
        "# repeat offenders get longer bans (x2 each time), capped at one week\n"
        "bantime.increment = true\n"
        "bantime.maxtime = 1w\n\n"
        "[sshd]\n"
        "enabled = true\n"
        f"port = {port or 'ssh'}\n"
        "backend = __BACKEND__\n"
    )


def install_fail2ban(sid: int, opts: dict, log) -> None:
    with server_lock(sid):
        s = get_server(sid)
        with Conn(s, timeout=25) as c:
            st = _parse(c.run(RUN_SCRIPT, input=STATUS_SCRIPT, timeout=60)[1])
            ignore = list(dict.fromkeys(([st["client_ip"]] if st["client_ip"] else []) + opts["ignore"]))
            log(f"IP панели (не будет забанен): {st['client_ip'] or 'не определён'}\n")
            cfg = jail_config(st["ssh_port"], ignore, opts["maxretry"], opts["findtime"], opts["bantime"])
            q = shlex.quote
            script = "\n".join([
                "set -e", "export DEBIAN_FRONTEND=noninteractive",
                sh_echo("== [1/4] Установка fail2ban"),
                "apt-get update -y -q >/dev/null",
                # Debian 12+ без rsyslog: журналы только в journald, fail2ban нужен python3-systemd
                "if [ -r /var/log/auth.log ] && [ -s /var/log/auth.log ]; then BACKEND=auto; PK=fail2ban; "
                "else BACKEND=systemd; PK='fail2ban python3-systemd'; fi",
                "apt-get install -y -q $PK >/dev/null",
                "fail2ban-client --version | head -n 1",
                sh_echo("== [2/4] Настройка jail sshd"),
                f"J={q(JAIL_FILE)}",
                'if [ -f "$J" ]; then cp -a "$J" "$J.bak"; fi',
                "cat > \"$J\" <<'SOLAHELM_EOF'\n" + cfg + "SOLAHELM_EOF",
                'sed -i "s/__BACKEND__/$BACKEND/" "$J"',
                'echo "backend: $BACKEND"',
                sh_echo("== [3/4] Проверка конфигурации"),
                'if ! fail2ban-client -t >/tmp/.f2b_test 2>&1; then cat /tmp/.f2b_test; '
                'if [ -f "$J.bak" ]; then mv -f "$J.bak" "$J"; else rm -f "$J"; fi; '
                + sh_echo("!! Ошибка в конфигурации fail2ban, изменения откачены") + "; exit 1; fi",
                'rm -f "$J.bak" /tmp/.f2b_test',
                sh_echo("== [4/4] Запуск службы"),
                "systemctl enable fail2ban >/dev/null 2>&1",
                "systemctl restart fail2ban",
                "for i in 1 2 3 4 5 6 7 8 9 10; do fail2ban-client status sshd >/dev/null 2>&1 && break; sleep 1; done",
                "fail2ban-client status sshd",
                sh_echo("Готово: fail2ban защищает SSH."),
            ])
            code = c.run_stream(RUN_SCRIPT, script, log, timeout=900)
            if code != 0:
                raise HyError(f"Установка fail2ban завершилась с кодом {code}")
        db.ex("UPDATE servers SET f2b_ignore=? WHERE id=?", (" ".join(opts["ignore"]), sid))


def unban(sid: int, ip: str) -> str:
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HyError("Неверный IP-адрес")
    s = get_server(sid)
    with Conn(s, timeout=20) as c:
        code, out, err = c.run(f"fail2ban-client set sshd unbanip {shlex.quote(ip)}", timeout=30)
    if code != 0:
        raise HyError(f"Не удалось разбанить {ip}: {(err or out).strip()[-300:]}")
    return ip


# ---------------- вход по паролю ----------------
def _reload_sshd() -> str:
    return "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload"


def set_password_login(sid: int, allow: bool, extra_key: str = "") -> dict:
    """Запретить (allow=False) или снова разрешить вход по паролю. Возвращает новое состояние."""
    with server_lock(sid):
        s = get_server(sid)
        if not allow and s.get("ssh_auth") == "password":
            raise HyError("Панель сама входит на этот сервер по паролю. Сначала нажмите «Установить ключ панели», "
                          "иначе после запрета пароля панель потеряет доступ.")
        extra_key = " ".join((extra_key or "").split())
        if extra_key and not PUBKEY_RE.match(extra_key):
            raise HyError("Не похоже на публичный SSH-ключ (ожидается строка вида «ssh-ed25519 AAAA… комментарий»)")
        q = shlex.quote
        with Conn(s, timeout=20) as c:  # это соединение остаётся открытым до проверки нового
            if extra_key:
                c.run("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
                      f"(grep -qxF {q(extra_key)} ~/.ssh/authorized_keys || echo {q(extra_key)} >> ~/.ssh/authorized_keys)",
                      sudo=False, check=True)
            if allow:
                c.run(f"rm -f {q(SSHD_DROPIN)} && sshd -t && ({_reload_sshd()})", check=True, timeout=60)
            else:
                code, out, _ = c.run("grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' "
                                     "/etc/ssh/sshd_config && echo yes || echo no", timeout=30)
                if "yes" not in out:
                    raise HyError("В /etc/ssh/sshd_config нет строки Include /etc/ssh/sshd_config.d/*.conf "
                                  "(старая ОС?). Отключите пароль вручную: PasswordAuthentication no.")
                conf = ("# Created by SolaHelm: SSH login by key only. Delete this file and reload ssh to allow passwords again.\n"
                        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n")
                code, out, err = c.run(f"mkdir -p /etc/ssh/sshd_config.d && cat > {q(SSHD_DROPIN)} && chmod 644 {q(SSHD_DROPIN)} && "
                                       f"if sshd -t; then {_reload_sshd()}; else rm -f {q(SSHD_DROPIN)}; exit 3; fi",
                                       input=conf, timeout=60)
                if code != 0:
                    raise HyError(f"sshd отклонил настройку, изменения откачены: {(err or out).strip()[-400:]}")
                # проверка: панель должна войти новым подключением
                try:
                    with Conn(dict(s), timeout=20) as c2:
                        c2.run("true", check=True, timeout=20)
                except SSHError as e:
                    c.run(f"rm -f {q(SSHD_DROPIN)} && ({_reload_sshd()})", timeout=60)
                    raise HyError(f"После запрета пароля панель не смогла войти заново ({e}). Настройка откачена.")
            code, out, _ = c.run("sshd -T 2>/dev/null | awk '$1==\"passwordauthentication\"||$1==\"permitrootlogin\"{print $1\"=\"$2}'",
                                 timeout=30)
    res = dict(line.split("=", 1) for line in out.split() if "=" in line)
    try:
        status(sid)  # обновить сохранённое состояние для страницы сервера
    except (SSHError, HyError):
        pass
    return {"password_auth": res.get("passwordauthentication", "?"), "root_login": res.get("permitrootlogin", "?")}
