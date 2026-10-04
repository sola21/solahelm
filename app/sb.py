"""sing-box рядом с Hysteria2: VLESS (Reality, xtls-rprx-vision) и AnyTLS.

Панель владеет двумя inbound'ами (теги vless-in и anytls-in). Остальное содержимое конфига sing-box не трогается.
"""
import base64
import hashlib
import json
import re
import secrets
import shlex
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import db, hy, security
from .ssh import Conn

sh_echo = hy.sh_echo

TAG_VLESS, TAG_ANYTLS = "vless-in", "anytls-in"
FLOW = "xtls-rprx-vision"
CERT_DIR = "/etc/sing-box/certs"
PLACEHOLDER_USER = hy.PLACEHOLDER_USER
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def enabled(s: dict) -> bool:
    return bool(s.get("vless_enabled") or s.get("anytls_enabled"))


# ---------------- ключи Reality ----------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def gen_reality_keys() -> tuple[str, str]:
    """Пара x25519 в формате `sing-box generate reality-keypair` (base64url без padding)."""
    k = X25519PrivateKey.generate()
    raw = dict(encoding=serialization.Encoding.Raw)
    priv = k.private_bytes(**raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub = k.public_key().public_bytes(**raw, format=serialization.PublicFormat.Raw)
    return _b64u(priv), _b64u(pub)


def ensure_reality(s: dict) -> None:
    if s.get("reality_priv") and s.get("reality_pub") and s.get("reality_sid"):
        return
    priv, pub = gen_reality_keys()
    s["reality_priv"], s["reality_pub"], s["reality_sid"] = security.encrypt(priv), pub, secrets.token_hex(4)
    db.ex("UPDATE servers SET reality_priv=?, reality_pub=?, reality_sid=? WHERE id=?",
          (s["reality_priv"], s["reality_pub"], s["reality_sid"], s["id"]))


# ---------------- конфиг sing-box ----------------
def placeholder(s: dict) -> dict:
    # inbound без пользователей не стартует — держим служебного со случайными данными
    h = hashlib.sha256(f"{s['id']}:{s.get('host_key') or s['host']}:placeholder".encode()).hexdigest()
    return {"username": PLACEHOLDER_USER, "uuid": str(uuid.UUID(h[:32])), "password": h[32:56]}


def build_inbounds(s: dict, rows: list[dict]) -> list[dict]:
    rows = rows or [placeholder(s)]
    out = []
    if s["vless_enabled"]:
        ensure_reality(s)
        out.append({
            "type": "vless", "tag": TAG_VLESS, "listen": "::", "listen_port": int(s["vless_port"]),
            "users": [{"name": r["username"], "uuid": r["uuid"], "flow": FLOW} for r in rows],
            "tls": {"enabled": True, "server_name": s["reality_sni"],
                    "reality": {"enabled": True,
                                "handshake": {"server": s["reality_sni"], "server_port": 443},
                                "private_key": security.decrypt(s["reality_priv"]),
                                "short_id": [s["reality_sid"]]}},
        })
    if s["anytls_enabled"]:
        out.append({
            "type": "anytls", "tag": TAG_ANYTLS, "listen": "::", "listen_port": int(s["anytls_port"]),
            "users": [{"name": r["username"], "password": r["password"]} for r in rows],
            "tls": {"enabled": True, "server_name": s["anytls_domain"],
                    "certificate_path": f"{CERT_DIR}/anytls.crt", "key_path": f"{CERT_DIR}/anytls.key"},
        })
    return out


def merge_config(existing: dict | None, s: dict, rows: list[dict]) -> dict:
    cfg = existing if existing is not None else {"log": {"level": "warn", "timestamp": True}}
    cfg["inbounds"] = [i for i in cfg.get("inbounds", []) if i.get("tag") not in (TAG_VLESS, TAG_ANYTLS)] \
        + build_inbounds(s, rows)
    if not cfg.get("outbounds"):
        cfg["outbounds"] = [{"type": "direct", "tag": "direct"}]
    return cfg


def dump(cfg: dict) -> str:
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"


def sync(c: Conn, s: dict, rows: list[dict]) -> bool:
    """Привести inbound'ы панели на сервере к состоянию БД. True, если конфиг изменился (служба перезапущена)."""
    path = s["sb_config_path"]
    code, out, err = c.run(f"cat {shlex.quote(path)}")
    if code != 0:
        raise hy.HyError(f"не найден {path} — установите sing-box кнопкой «Установить sing-box» на странице сервера")
    try:
        cur = json.loads(out)
    except json.JSONDecodeError as e:
        raise hy.HyError(f"{path} не является корректным JSON: {e}")
    new = merge_config(json.loads(out), s, rows)
    if new == cur:
        return False
    c.write_file(path, dump(new))
    hy.svc_restart_verify(c, s, service=s["sb_service"], path=path)
    return True


def read_config(sid: int) -> str:
    s = hy.get_server(sid)
    with Conn(s) as c:
        code, out, err = c.run(f"cat {shlex.quote(s['sb_config_path'])}")
    if code != 0:
        raise hy.HyError(f"Не удалось прочитать {s['sb_config_path']}: {(err or out).strip()} — sing-box установлен?")
    return out


def save_config(sid: int, text: str) -> None:
    """Сохранить конфиг sing-box с бэкапом; проверяется `sing-box check`, при ошибке возвращается прежний."""
    try:
        json.loads(text)
    except json.JSONDecodeError as e:
        raise hy.HyError(f"Некорректный JSON: {e}")
    with hy.server_lock(sid):
        s = hy.get_server(sid)
        path = s["sb_config_path"]
        p = shlex.quote(path)
        with Conn(s) as c:
            c.write_file(path, text)
            code, out, err = c.run(f"sing-box check -c {p}")
            if code != 0:
                c.run(f'latest=$(ls -1 {p}.bak.* 2>/dev/null | sort | tail -n 1); '
                      f'if [ -n "$latest" ]; then cat "$latest" > {p}; fi')
                raise hy.HyError(f"sing-box отклонил конфиг, прежний восстановлен:\n{(err or out).strip()[-1500:]}")
            hy.svc_restart_verify(c, s, service=s["sb_service"], path=path)


# ---------------- установка ----------------
CERTSYNC = r"""#!/bin/bash
# Кладёт сертификат для AnyTLS в /etc/sing-box/certs и перечитывает sing-box при изменении.
# Использование: hy2panel-certsync <домен> <hysteria|selfsigned>
set -e
DOMAIN="$1"; MODE="$2"
DIR=__CERT_DIR__; CRT=$DIR/anytls.crt; KEY=$DIR/anytls.key
mkdir -p "$DIR"; changed=0
if [ "$MODE" = hysteria ]; then
  C=$(find /var/lib/hysteria /etc/hysteria -type f -name "$DOMAIN.crt" 2>/dev/null | head -n1)
  K=$(find /var/lib/hysteria /etc/hysteria -type f -name "$DOMAIN.key" 2>/dev/null | head -n1)
  if [ -z "$C" ] || [ -z "$K" ]; then
    echo "Сертификат Hysteria для домена AnyTLS не найден (нужен работающий ACME на этом сервере)" >&2; exit 2
  fi
  cmp -s "$C" "$CRT" || { cp "$C" "$CRT"; changed=1; }
  cmp -s "$K" "$KEY" || { cp "$K" "$KEY"; changed=1; }
else
  if [ ! -s "$CRT" ] || [ ! -s "$KEY" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" -keyout "$KEY" -out "$CRT" 2>/dev/null
    changed=1
  fi
fi
if getent group sing-box >/dev/null; then chgrp sing-box "$DIR" "$CRT" "$KEY"; fi
chmod 750 "$DIR"; chmod 640 "$CRT" "$KEY"
if [ "$changed" = 1 ] && systemctl is-active --quiet __SVC__; then
  systemctl reload __SVC__ || systemctl restart __SVC__
fi
"""


def build_install_script(s: dict, cfg_text: str, opts: dict) -> str:
    path = shlex.quote(s["sb_config_path"])
    svc = shlex.quote(s["sb_service"])
    L = ["set -e", "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a",
         sh_echo("== [1/6] Пакеты"), "apt-get update -y",
         "apt-get install -y curl ca-certificates openssl" + (" ufw" if opts["ufw"] else "")]
    if opts["vless"]:
        sni = shlex.quote(s["reality_sni"])
        ok_msg = f"== Проверка, что {s['reality_sni']} подходит для Reality (TLS 1.3)"
        bad_msg = f"!! {s['reality_sni']} не отвечает по TLS 1.3 — выберите другой домен для маскировки"
        L += [sh_echo(ok_msg),
              f"echo | timeout 15 openssl s_client -connect {sni}:443 -servername {sni} -tls1_3 >/dev/null 2>&1 || "
              f"{{ {sh_echo(bad_msg)}; exit 1; }}"]
    L += [sh_echo("== [2/6] Установка sing-box (sing-box.app)"),
          "if ! command -v sing-box >/dev/null 2>&1; then curl -fsSL https://sing-box.app/install.sh | sh; fi",
          "sing-box version | head -n 1", "mkdir -p /etc/sing-box"]
    if opts["anytls"]:
        cs = CERTSYNC.replace("__CERT_DIR__", CERT_DIR).replace("__SVC__", svc)
        dom, mode = shlex.quote(s["anytls_domain"]), shlex.quote(s["anytls_cert"])
        L += [sh_echo("== [3/6] Сертификат для AnyTLS"),
              "cat > /usr/local/sbin/hy2panel-certsync <<'HY2PANEL_CERT'", cs.rstrip("\n"), "HY2PANEL_CERT",
              "chmod 755 /usr/local/sbin/hy2panel-certsync",
              f"/usr/local/sbin/hy2panel-certsync {dom} {mode}",
              "cat > /etc/systemd/system/hy2panel-certsync.service <<'HY2PANEL_UNIT'",
              "[Unit]\nDescription=Sync AnyTLS certificate for sing-box\n\n[Service]\nType=oneshot\n"
              f"ExecStart=/usr/local/sbin/hy2panel-certsync {s['anytls_domain']} {s['anytls_cert']}",
              "HY2PANEL_UNIT",
              "cat > /etc/systemd/system/hy2panel-certsync.timer <<'HY2PANEL_UNIT'",
              "[Unit]\nDescription=Daily AnyTLS certificate sync\n\n[Timer]\nOnCalendar=daily\n"
              "RandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target",
              "HY2PANEL_UNIT",
              "systemctl daemon-reload", "systemctl enable --now hy2panel-certsync.timer"]
    else:
        L.append(sh_echo("== [3/6] AnyTLS не выбран — сертификат не нужен"))
    L += [sh_echo("== [4/6] Конфигурация"),
          f"cat > {path}.new <<'HY2PANEL_CFG'", cfg_text.rstrip("\n"), "HY2PANEL_CFG",
          f"sing-box check -c {path}.new",
          f"if [ -f {path} ]; then cp -a {path} {path}.bak.$(date +%Y%m%d-%H%M%S); fi",
          f"mv {path}.new {path}",
          f"if getent group sing-box >/dev/null; then chgrp sing-box {path}; chmod 640 {path}; else chmod 600 {path}; fi"]
    if opts["ufw"]:
        L.append(sh_echo("== [5/6] ufw"))
        for key in ("vless", "anytls"):
            if opts[key]:
                L.append(f"ufw allow {int(s[key + '_port'])}/tcp")
        L.append("ufw status | head -n 12 || true")
    else:
        L.append(sh_echo("== [5/6] ufw пропущен"))
    L += [sh_echo("== [6/6] Запуск службы"), "systemctl daemon-reload", f"systemctl enable {svc}",
          f"systemctl restart {svc}", "sleep 3",
          f"if ! systemctl is-active --quiet {svc}; then journalctl -u {svc} -n 40 --no-pager -o cat; exit 1; fi",
          sh_echo("== Готово")]
    return "\n".join(L) + "\n"


def provision(sid: int, opts: dict, log) -> None:
    """Установить sing-box и записать конфиг с VLESS и/или AnyTLS. Флаги протоколов сохраняются после успеха."""
    with hy.server_lock(sid):
        s = hy.get_server(sid)
        if opts.get("assign_all"):
            for u in db.q("SELECT id FROM users"):
                db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (u["id"], sid))
        upd = {
            "vless_enabled": int(opts["vless"]), "vless_port": opts["vless_port"], "reality_sni": opts["reality_sni"],
            "anytls_enabled": int(opts["anytls"]), "anytls_port": opts["anytls_port"],
            "anytls_domain": opts["anytls_domain"], "anytls_cert": opts["anytls_cert"],
            "anytls_insecure": 1 if opts["anytls_cert"] == "selfsigned" else 0,
        }
        s2 = dict(s, **upd)
        if opts["vless"]:
            ensure_reality(s2)
        rows = hy.desired_rows(sid)
        cfg_text = dump(merge_config(None, s2, rows))
        script = build_install_script(s2, cfg_text, opts)
        log(f"Подключение к {s['host']}:{s['ssh_port']} как {s['ssh_user']}…\n")
        with Conn(s, timeout=20) as c:
            code = c.run_stream(hy.RUN_SCRIPT, script, log, timeout=1800)
        if code != 0:
            raise hy.HyError(f"Скрипт установки завершился с кодом {code}")
        db.ex(f"UPDATE servers SET {','.join(k + '=?' for k in upd)}, last_sync=?, sync_error='' WHERE id=?",
              (*upd.values(), int(time.time()), sid))
        log(f"\nПрофилей на сервере: {len(rows)}\n")
    hy.poll_server(sid)
