"""Логика Hysteria2: разбор/правка config.yaml, синхронизация пользователей, мониторинг, установка."""
import hashlib
import io
import json
import re
import secrets
import shlex
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from . import db
from .ssh import Conn, SSHError

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
PLACEHOLDER_USER = "panel-placeholder"


class HyError(Exception):
    pass


_locks: dict[int, threading.Lock] = defaultdict(threading.Lock)
_locks_guard = threading.Lock()


def server_lock(sid: int) -> threading.Lock:
    with _locks_guard:
        return _locks[sid]


def get_server(sid: int) -> dict:
    s = db.q1("SELECT * FROM servers WHERE id=?", (sid,))
    if not s:
        raise HyError("Сервер не найден")
    return s


# ---------------- YAML ----------------
def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def load_cfg(text: str) -> CommentedMap:
    try:
        data = _yaml().load(text) if text.strip() else None
    except Exception as e:
        raise HyError(f"Ошибка YAML: {e}")
    if data is None:
        data = CommentedMap()
    if not isinstance(data, dict):
        raise HyError("Корень config.yaml должен быть словарём (mapping)")
    return data


def dump_cfg(data) -> str:
    buf = io.StringIO()
    _yaml().dump(data, buf)
    return buf.getvalue()


def _port_of(listen, default: int) -> int:
    if not listen:
        return default
    m = re.search(r":(\d+)$", str(listen).strip())
    return int(m.group(1)) if m else default


def cfg_info(cfg) -> dict:
    """Краткая сводка серверного конфига: порт, домены, пользователи, obfs, trafficStats."""
    info: dict = {"port": _port_of(cfg.get("listen"), 443)}
    acme = cfg.get("acme")
    info["domains"] = [str(d) for d in (acme.get("domains") or [])] if isinstance(acme, dict) else []
    info["tls"] = "acme" if isinstance(acme, dict) else ("file" if cfg.get("tls") else "none")
    auth = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else {}
    info["auth_type"] = str(auth.get("type", ""))
    up = auth.get("userpass")
    # viper в hysteria приводит ключи к нижнему регистру — логины регистронезависимы
    info["users"] = {str(k).lower(): str(v) for k, v in up.items()} if isinstance(up, dict) else {}
    obfs = cfg.get("obfs")
    if isinstance(obfs, dict) and str(obfs.get("type", "")) == "salamander":
        info["obfs"] = str((obfs.get("salamander") or {}).get("password", ""))
    ts = cfg.get("trafficStats")
    if isinstance(ts, dict) and ts.get("listen"):
        info["stats_port"] = _port_of(ts.get("listen"), 0)
        info["stats_secret"] = str(ts.get("secret") or "")
    m = cfg.get("masquerade")
    info["masquerade"] = str(m.get("type", "")) if isinstance(m, dict) else ""
    return info


def apply_users(cfg, users: dict[str, str], stats: tuple[int, str] | None) -> None:
    auth = cfg.get("auth")
    if not isinstance(auth, dict):
        auth = CommentedMap()
        cfg["auth"] = auth
    auth["type"] = "userpass"
    for k in ("password", "http", "command"):
        if k in auth:
            del auth[k]
    up = CommentedMap()
    for u in sorted(users):
        up[u] = users[u]
    auth["userpass"] = up
    if stats:
        ts = cfg.get("trafficStats")
        if not isinstance(ts, dict):
            ts = CommentedMap()
            cfg["trafficStats"] = ts
        ts["listen"] = f"127.0.0.1:{stats[0]}"
        ts["secret"] = stats[1]


# ---------------- пользователи ----------------
def user_is_active(u: dict, now: float | None = None) -> bool:
    now = now or time.time()
    if not u["enabled"]:
        return False
    if u["expires_at"] and u["expires_at"] <= now:
        return False
    if u["traffic_limit"] and u["tx"] + u["rx"] >= u["traffic_limit"]:
        return False
    return True


def desired_rows(sid: int) -> list[dict]:
    rows = db.q("SELECT u.* FROM users u JOIN user_servers us ON us.user_id=u.id WHERE us.server_id=? "
                "ORDER BY u.username", (sid,))
    now = time.time()
    return [r for r in rows if user_is_active(r, now)]


def desired_users(sid: int) -> dict[str, str]:
    return {r["username"]: r["password"] for r in desired_rows(sid)}


def placeholder(s: dict) -> dict[str, str]:
    # hysteria не запускается с пустым userpass — держим служебного пользователя со случайным паролем
    seed = (s.get("stats_secret") or s.get("host_key") or str(s["id"])) + ":placeholder"
    return {PLACEHOLDER_USER: hashlib.sha256(seed.encode()).hexdigest()[:32]}


def create_user(username: str, password: str, note: str = "", **kw) -> int:
    return db.ex(
        "INSERT INTO users(username,password,enabled,active,expires_at,traffic_limit,sub_token,note,created,uuid) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (username, password, kw.get("enabled", 1), 1, kw.get("expires_at", 0), kw.get("traffic_limit", 0),
         secrets.token_urlsafe(24), note, int(time.time()), str(uuid.uuid4())))


def mark_dirty(server_ids) -> None:
    for sid in set(server_ids):
        db.ex("UPDATE servers SET dirty=1 WHERE id=?", (sid,))
    from .tasks import worker
    worker.wake()


def user_server_ids(uid: int) -> list[int]:
    return [r["server_id"] for r in db.q("SELECT server_id FROM user_servers WHERE user_id=?", (uid,))]


def refresh_user_active(uid: int) -> None:
    """Пересчитать эффективное состояние пользователя; если изменилось — пометить его серверы к синхронизации."""
    u = db.q1("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        return
    act = 1 if user_is_active(u) else 0
    if act != u["active"]:
        db.ex("UPDATE users SET active=? WHERE id=?", (act, uid))
        mark_dirty(user_server_ids(uid))


def enforce_limits() -> None:
    now = time.time()
    dirty = set()
    for u in db.q("SELECT * FROM users"):
        act = 1 if user_is_active(u, now) else 0
        if act != u["active"]:
            db.ex("UPDATE users SET active=? WHERE id=?", (act, u["id"]))
            reason = "срок истёк" if u["expires_at"] and u["expires_at"] <= now else "лимит трафика"
            if not act:
                db.audit("user.auto_disable", f"{u['username']}: {reason}", "system")
            dirty.update(user_server_ids(u["id"]))
    if dirty:
        mark_dirty(dirty)


# ---------------- служба ----------------
def svc_restart_verify(c: Conn, s: dict, rollback: bool = True, service: str | None = None,
                       path: str | None = None) -> None:
    """Перезапустить службу (по умолчанию hysteria) и убедиться, что она поднялась; иначе откатить конфиг."""
    service = service or s["service"]
    svc, p = shlex.quote(service), shlex.quote(path or s["config_path"])
    c.run(f"systemctl restart {svc}", timeout=60)
    state = ""
    for _ in range(3):
        time.sleep(1.5)
        state = c.run(f"systemctl is-active {svc}")[1].strip()
        if state in ("failed", "inactive"):
            break
    if state == "active":
        return
    logs = c.run(f"journalctl -u {svc} -n 25 --no-pager -o cat")[1].strip()
    msg = f"Служба {service} не запустилась (состояние: {state or '?'})."
    if rollback:
        out = c.run(f'latest=$(ls -1 {p}.bak.* 2>/dev/null | sort | tail -n 1); '
                    f'if [ -n "$latest" ]; then cat "$latest" > {p}; systemctl restart {svc}; echo "$latest"; fi')[1]
        msg += f" Конфиг откатан к {out.strip()}." if out.strip() else " Бэкапа для отката нет."
    raise HyError(f"{msg}\n\nЖурнал:\n{logs[-3000:]}")


def ensure_stats(s: dict) -> tuple[int, str] | None:
    if not s["manage_stats"]:
        return None
    if not s["stats_secret"]:
        s["stats_secret"] = secrets.token_hex(16)
        db.ex("UPDATE servers SET stats_secret=? WHERE id=?", (s["stats_secret"], s["id"]))
    return int(s["stats_port"] or 25413), s["stats_secret"]


# ---------------- синхронизация ----------------
def sync_server(sid: int) -> dict:
    with server_lock(sid):
        s = get_server(sid)
        db.ex("UPDATE servers SET dirty=0 WHERE id=?", (sid,))
        try:
            from . import sb
            rows = desired_rows(sid)
            users = {r["username"]: r["password"] for r in rows}
            changed, errors = False, []
            with Conn(s) as c:
                # ошибка одного движка не должна мешать синхронизации другого
                if s["hy2_enabled"]:
                    try:
                        stats = ensure_stats(s)
                        text = c.read_file(s["config_path"])
                        cfg = load_cfg(text)
                        apply_users(cfg, users or placeholder(s), stats)
                        new = dump_cfg(cfg)
                        if new != text:
                            c.write_file(s["config_path"], new)
                            svc_restart_verify(c, s)
                            changed = True
                        db.ex("UPDATE servers SET cfg_info=? WHERE id=?", (json.dumps(cfg_info(cfg)), sid))
                    except (HyError, SSHError) as e:
                        errors.append(f"Hysteria2: {e}")
                if sb.enabled(s):
                    try:
                        changed = sb.sync(c, s, rows) or changed
                    except (HyError, SSHError) as e:
                        errors.append(f"sing-box: {e}")
            if errors:
                raise HyError("\n".join(errors))
            db.ex("UPDATE servers SET last_sync=?, sync_error='' WHERE id=?", (int(time.time()), sid))
            if changed:
                db.audit("server.sync", f"{s['name']}: пользователей {len(users)}, службы перезапущены", "system")
            return {"changed": changed, "users": len(users)}
        except Exception as e:
            db.ex("UPDATE servers SET dirty=1, sync_error=? WHERE id=?", (str(e)[:4000], sid))
            raise


def import_users(sid: int) -> dict:
    s = get_server(sid)
    with Conn(s) as c:
        text = c.read_file(s["config_path"])
    info = cfg_info(load_cfg(text))
    created, linked, conflicts = [], [], []
    for name, pw in info["users"].items():
        if name == PLACEHOLDER_USER:
            continue
        if not USERNAME_RE.match(name):
            conflicts.append(f"{name}: недопустимое имя"); continue
        u = db.q1("SELECT * FROM users WHERE username=?", (name,))
        if not u:
            uid = create_user(name, pw, note=f"импорт с {s['name']}")
            created.append(name)
        elif u["password"] != pw:
            conflicts.append(f"{name}: пароль на сервере отличается от панели — не привязан"); continue
        else:
            uid = u["id"]
            linked.append(name)
        db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (uid, sid))
    db.ex("UPDATE servers SET cfg_info=? WHERE id=?", (json.dumps(info), sid))
    if info["auth_type"] != "userpass":
        conflicts.append(f"auth.type = {info['auth_type'] or 'нет'}: при синхронизации будет заменён на userpass")
    return {"created": created, "linked": linked, "conflicts": conflicts}


def save_raw_config(sid: int, text: str) -> None:
    load_cfg(text)  # проверка синтаксиса
    with server_lock(sid):
        s = get_server(sid)
        with Conn(s) as c:
            c.write_file(s["config_path"], text)
            svc_restart_verify(c, s)
        db.ex("UPDATE servers SET cfg_info=? WHERE id=?", (json.dumps(cfg_info(load_cfg(text))), sid))


def rollback_config(sid: int, which: str = "hy") -> str:
    """Вернуть предыдущий конфиг из последнего бэкапа (which: hy — Hysteria2, sb — sing-box) и перезапустить службу."""
    with server_lock(sid):
        s = get_server(sid)
        sb_mode = which == "sb"
        path = s["sb_config_path"] if sb_mode else s["config_path"]
        service = s["sb_service"] if sb_mode else s["service"]
        p = shlex.quote(path)
        with Conn(s) as c:
            code, out, _ = c.run(f'ls -1 {p}.bak.* 2>/dev/null | sort | tail -n 1')
            latest = out.strip()
            if not latest:
                raise HyError("Бэкапов нет")
            c.run(f'cat {shlex.quote(latest)} > {p} && rm -f {shlex.quote(latest)}', check=True)
            svc_restart_verify(c, s, rollback=False, service=service, path=path)
            if not sb_mode:
                info = cfg_info(load_cfg(c.read_file(path)))
        if not sb_mode:
            db.ex("UPDATE servers SET cfg_info=? WHERE id=?", (json.dumps(info), sid))
        return latest


# ---------------- мониторинг ----------------
STATUS_CMD = r"""
S=__SVC__
echo "active=$(systemctl is-active $S 2>/dev/null)"
echo "enabled=$(systemctl is-enabled $S 2>/dev/null)"
echo "since=$(systemctl show -p ActiveEnterTimestamp --value $S 2>/dev/null)"
echo "uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
echo "cpus=$(nproc 2>/dev/null)"
echo "mem=$(free -b | awk 'NR==2{print $2" "$3}')"
echo "disk=$(df -B1 / | awk 'NR==2{print $2" "$3}')"
echo "version=$(hysteria version 2>/dev/null | awk '/^Version/{print $2}')"
echo "os=$(. /etc/os-release 2>/dev/null; echo $PRETTY_NAME)"
IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
echo "iface=$IF"
echo "net=$(grep "$IF:" /proc/net/dev | sed 's/.*://' | awk '{print $1" "$9}')"
SB=__SBSVC__
if [ -n "$SB" ]; then
  echo "sb_active=$(systemctl is-active $SB 2>/dev/null)"
  echo "sb_version=$(sing-box version 2>/dev/null | awk 'NR==1{print $NF}')"
fi
"""


def _kv(text: str) -> dict:
    d = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def _ints(s: str) -> list[int]:
    try:
        return [int(float(x)) for x in s.split()]
    except ValueError:
        return []


FAIL_THRESHOLD_DEFAULT = 3   # столько неудачных опросов подряд — и сервер считается недоступным
RETRY_PAUSE = 4              # пауза перед повтором опроса, c


def fail_threshold() -> int:
    try:
        return max(1, int(db.get_setting("fail_threshold", FAIL_THRESHOLD_DEFAULT)))
    except (TypeError, ValueError):
        return FAIL_THRESHOLD_DEFAULT


def _poll_once(s: dict, prev: dict, now: int):
    """Один опрос сервера по SSH: (статус, online, traffic, cfg_info). status['ok'] — удался ли опрос."""
    st: dict = {"ts": now, "ok": False}
    traffic = online = info = None
    try:
        from . import sb
        with Conn(s) as c:
            cmd = STATUS_CMD.replace("__SVC__", shlex.quote(s["service"])).replace(
                "__SBSVC__", shlex.quote(s["sb_service"]) if sb.enabled(s) else "''")
            code, out, err = c.run(cmd, timeout=45)
            kv = _kv(out)
            if sb.enabled(s):
                st["sb_active"], st["sb_version"] = kv.get("sb_active", ""), kv.get("sb_version", "")
            st.update(active=kv.get("active", ""), enabled=kv.get("enabled", ""), since=kv.get("since", ""),
                      version=kv.get("version", ""), os=kv.get("os", ""), iface=kv.get("iface", ""),
                      load=kv.get("load", ""), cpus=int(kv.get("cpus") or 0))
            st["uptime"] = int(float(kv.get("uptime") or 0))
            mem, disk, net = _ints(kv.get("mem", "")), _ints(kv.get("disk", "")), _ints(kv.get("net", ""))
            if len(mem) == 2:
                st["mem_total"], st["mem_used"] = mem
            if len(disk) == 2:
                st["disk_total"], st["disk_used"] = disk
            if len(net) == 2:
                st["net_rx"], st["net_tx"] = net
                dt = now - prev.get("ts", 0)
                if prev.get("net_rx") is not None and 0 < dt < 3600 and net[0] >= prev["net_rx"]:
                    st["rate_rx"] = (net[0] - prev["net_rx"]) / dt
                    st["rate_tx"] = (net[1] - prev["net_tx"]) / dt
            if not s["hy2_enabled"]:
                # сервер только под sing-box: общее состояние берём у него, Hysteria не опрашиваем
                st["active"] = st.get("sb_active", "")
                st["version"] = st.get("sb_version", "")
            else:
                try:
                    info = cfg_info(load_cfg(c.read_file(s["config_path"])))
                except Exception as e:
                    st["cfg_error"] = str(e)[:300]
            if info and info.get("stats_port") and st["active"] == "active":
                try:
                    online = c.http_json(info["stats_port"], "GET", "/online", info.get("stats_secret", "")) or {}
                    traffic = c.http_json(info["stats_port"], "GET", "/traffic?clear=1",
                                          info.get("stats_secret", "")) or {}
                except Exception as e:
                    st["stats_error"] = str(e)[:300]
        st["ok"] = True
    except Exception as e:
        st["error"] = str(e)[:500]
    return st, online, traffic, info


def poll_server(sid: int) -> dict:
    """Опросить сервер. Разовый сбой связи не портит картину: опрос повторяется, а при неудаче сохраняются последние
    известные данные и растёт счётчик fails (недоступным сервер считается при fails >= порога). Каждая проверка пишется
    в историю для графика доступности. Возвращаемый словарь: ok/error относятся к этой попытке."""
    s = get_server(sid)
    prev = json.loads(s["status"] or "{}")
    first_error = ""
    for attempt in (1, 2):
        now = int(time.time())
        t0 = time.monotonic()
        st, online, traffic, info = _poll_once(s, prev, now)
        ms = int((time.monotonic() - t0) * 1000)
        if traffic:
            _store_traffic(sid, traffic)   # счётчики на сервере уже сброшены (clear=1) — сохраняем сразу
        if st["ok"]:
            break
        first_error = first_error or st.get("error", "")
        if attempt == 1:
            time.sleep(RETRY_PAUSE)
    now = int(time.time())
    if st["ok"]:
        if online is not None:
            st["online"] = {k.lower(): int(v) for k, v in online.items()}
            st["online_total"] = sum(st["online"].values())
        st.update(fails=0, last_ok=now, checked=now)
        final = st
        if info:
            db.ex("UPDATE servers SET cfg_info=? WHERE id=?", (json.dumps(info), sid))
        if online is not None:
            _store_online(sid, st["online"], now)
    else:
        final = dict(prev)
        final.update(ok=False, error=st.get("error", "")[:500], fails=int(prev.get("fails", 0)) + 1, checked=now)
    db.ex("UPDATE servers SET status=?, last_check=? WHERE id=?", (json.dumps(final), now, sid))
    db.ex("INSERT INTO checks(server_id,ts,ok,ms,err) VALUES(?,?,?,?,?)",
          (sid, now, 1 if st["ok"] else 0, ms if st["ok"] else 0, first_error[:300]))
    return final


RANGES = {"24h": (24 * 3600, 48), "7d": (7 * 86400, 56), "30d": (30 * 86400, 60)}


def history(sid: int, rng: str = "24h") -> dict:
    """Данные для графика доступности: корзины по времени, процент доступности, задержка, последние проблемы."""
    span, n = RANGES.get(rng, RANGES["24h"])
    now = int(time.time())
    start, size = now - span, span / n
    rows = db.q("SELECT ts, ok, ms, err FROM checks WHERE server_id=? AND ts>=? ORDER BY ts", (sid, start))
    buckets = [{"t": int(start + i * size), "total": 0, "ok": 0, "flaky": 0, "ms_sum": 0} for i in range(n)]
    for r in rows:
        b = buckets[min(n - 1, int((r["ts"] - start) / size))]
        b["total"] += 1
        b["ok"] += r["ok"]
        b["flaky"] += 1 if (r["ok"] and r["err"]) else 0
        b["ms_sum"] += r["ms"] if r["ok"] else 0
    for b in buckets:
        b["state"] = ("none" if not b["total"] else "bad" if b["ok"] == 0 else
                      "ok" if b["ok"] == b["total"] and not b["flaky"] else "warn")
        b["ms"] = int(b["ms_sum"] / b["ok"]) if b["ok"] else None
    total, okc = sum(b["total"] for b in buckets), sum(b["ok"] for b in buckets)
    ms_vals = [b["ms"] for b in buckets if b["ms"]]
    mx = max(ms_vals) if ms_vals else 0
    for b in buckets:
        b["ms_pct"] = max(4, int(100 * b["ms"] / mx)) if b["ms"] else 0
    problems = db.q("SELECT ts, ok, err FROM checks WHERE server_id=? AND ts>=? AND err!='' ORDER BY ts DESC LIMIT 12",
                    (sid, start))
    return {"range": rng if rng in RANGES else "24h", "buckets": buckets, "total": total, "failed": total - okc,
            "uptime": round(100 * okc / total, 2) if total else None,
            "avg_ms": int(sum(ms_vals) / len(ms_vals)) if ms_vals else None, "max_ms": max(ms_vals) if ms_vals else None,
            "problems": problems}


def _umap() -> dict[str, int]:
    return {r["username"]: r["id"] for r in db.q("SELECT id, username FROM users")}


def _store_online(sid: int, online: dict, now: int) -> None:
    umap = _umap()
    db.ex("UPDATE user_servers SET online=0 WHERE server_id=?", (sid,))
    for name, n in online.items():
        uid = umap.get(name)
        if uid and n:
            db.ex("UPDATE user_servers SET online=?, last_online=? WHERE user_id=? AND server_id=?", (n, now, uid, sid))
            db.ex("UPDATE users SET last_online=? WHERE id=?", (now, uid))


def _store_traffic(sid: int, traffic: dict) -> None:
    umap = _umap()
    day = datetime.now().strftime("%Y-%m-%d")
    for name, v in traffic.items():
        uid = umap.get(str(name).lower())
        tx, rx = int((v or {}).get("tx", 0)), int((v or {}).get("rx", 0))
        if not uid or (tx == 0 and rx == 0):
            continue
        db.ex("UPDATE users SET tx=tx+?, rx=rx+? WHERE id=?", (tx, rx, uid))
        db.ex("UPDATE user_servers SET tx=tx+?, rx=rx+? WHERE user_id=? AND server_id=?", (tx, rx, uid, sid))
        db.ex("INSERT INTO traffic_daily(day,user_id,server_id,tx,rx) VALUES(?,?,?,?,?) "
              "ON CONFLICT(day,user_id,server_id) DO UPDATE SET tx=tx+excluded.tx, rx=rx+excluded.rx",
              (day, uid, sid, tx, rx))


def kick(sid: int, usernames: list[str]) -> None:
    s = get_server(sid)
    info = json.loads(s["cfg_info"] or "{}")
    if not info.get("stats_port"):
        raise HyError("На сервере не включён trafficStats API — синхронизируйте сервер")
    with Conn(s) as c:
        c.http_json(info["stats_port"], "POST", "/kick", info.get("stats_secret", ""), usernames)


def service_action(sid: int, op: str) -> str:
    if op not in ("start", "stop", "restart"):
        raise HyError("Неизвестное действие")
    s = get_server(sid)
    with server_lock(sid), Conn(s) as c:
        if op == "restart":
            svc_restart_verify(c, s, rollback=False)
        else:
            c.run(f"systemctl {op} {shlex.quote(s['service'])}", check=True, timeout=60)
        return c.run(f"systemctl is-active {shlex.quote(s['service'])}")[1].strip()


def get_logs(sid: int, lines: int = 200, which: str = "hy") -> str:
    s = get_server(sid)
    svc = s["sb_service"] if which == "sb" else s["service"]
    with Conn(s) as c:
        return c.run(f"journalctl -u {shlex.quote(svc)} -n {int(lines)} --no-pager -o short-iso",
                     timeout=30)[1]


def install_panel_key(sid: int, pubkey: str) -> None:
    """По паролю добавить ключ панели в authorized_keys и перейти на вход по ключу."""
    s = get_server(sid)
    if s["ssh_auth"] != "password":
        raise HyError("Действие доступно, только если вход настроен по паролю")
    q = shlex.quote(pubkey)
    with Conn(s) as c:
        c.run("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
              f"(grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys)",
              sudo=False, check=True)
    test = dict(s)
    with Conn(test, auth_override="panelkey") as c:
        c.run("true", check=True)
    db.ex("UPDATE servers SET ssh_auth='panelkey', ssh_secret='', ssh_key='' WHERE id=?", (sid,))


# ---------------- установка / обновление ----------------
# Скрипт сначала целиком сохраняется во временный файл, чтобы дочерние процессы не «съели» его из stdin.
def sh_echo(msg: str) -> str:
    """Команда shell, печатающая сообщение (сообщения установки вынесены в отдельные строки — их можно переводить)."""
    return "echo " + shlex.quote(msg)


RUN_SCRIPT = 'f=$(mktemp); cat > "$f"; bash "$f" </dev/null; rc=$?; rm -f "$f"; exit $rc'
HY_INSTALL = "bash <(curl -fsSL https://get.hy2.sh/)"
UPDATE_SCRIPT = f"set -e\n{HY_INSTALL}\nhysteria version | head -n 3\n"
MASQ_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Please wait</title><style>body{background:#0b0b0b;height:100vh;margin:0;display:flex;align-items:center;justify-content:center;font-family:sans-serif;color:#666;letter-spacing:2px}</style></head><body>LOADING…</body></html>"""


def build_server_config(domain: str, email: str, port: int, users: dict, stats: tuple[int, str] | None,
                        obfs: str = "") -> str:
    cfg = CommentedMap()
    cfg["listen"] = f"0.0.0.0:{port}"
    acme = CommentedMap()
    acme["type"] = "http"
    doms = CommentedSeq([domain])
    acme["domains"] = doms
    acme["email"] = email
    cfg["acme"] = acme
    if obfs:
        cfg["obfs"] = CommentedMap(type="salamander", salamander=CommentedMap(password=obfs))
    cfg["auth"] = CommentedMap(type="userpass")
    masq = CommentedMap()
    masq["type"] = "file"
    masq["file"] = CommentedMap(dir="/var/www/masq")
    masq["listenHTTP"] = ":80"
    masq["listenHTTPS"] = f":{port}"
    masq["forceHTTPS"] = True
    cfg["masquerade"] = masq
    apply_users(cfg, users, stats)
    return dump_cfg(cfg)


def build_install_script(s: dict, cfg_text: str, opts: dict) -> str:
    port = int(opts["port"])
    cp = shlex.quote(s["config_path"])
    svc = shlex.quote(s["service"])
    L = ["set -e", "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a",
         sh_echo("== [1/6] Обновление списка пакетов"), "apt-get update -y"]
    if opts.get("upgrade"):
        L.append("apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade")
    L.append("apt-get install -y curl ca-certificates openssl" + (" ufw" if opts.get("ufw") else ""))
    L += [sh_echo("== [2/6] Установка Hysteria2 (get.hy2.sh)"), HY_INSTALL]
    L += [sh_echo("== [3/6] Сайт-заглушка"), "mkdir -p /var/www/masq",
          "if [ ! -f /var/www/masq/index.html ]; then cat > /var/www/masq/index.html <<'HY2PANEL_HTML'",
          MASQ_HTML, "HY2PANEL_HTML", "fi", "chmod -R a+rX /var/www/masq"]
    L += [sh_echo("== [4/6] Конфигурация"), f'mkdir -p "$(dirname {cp})"',
          f"if [ -f {cp} ]; then cp -a {cp} {cp}.bak.$(date +%Y%m%d-%H%M%S); fi",
          f"cat > {cp} <<'HY2PANEL_CFG'", cfg_text.rstrip("\n"), "HY2PANEL_CFG",
          f"if getent group hysteria >/dev/null; then chown root:hysteria {cp}; chmod 640 {cp}; else chmod 644 {cp}; fi"]
    if opts.get("ufw"):
        ssh_port = int(s["ssh_port"] or 22)
        L += [sh_echo("== [5/6] Настройка ufw"), f"ufw allow {ssh_port}/tcp", "ufw allow 80/tcp",
              f"ufw allow {port}/tcp", f"ufw allow {port}/udp", "ufw --force enable", "ufw status verbose"]
    else:
        L.append(sh_echo("== [5/6] ufw пропущен"))
    L += [sh_echo("== [6/6] Запуск службы"), "systemctl daemon-reload", f"systemctl enable {svc}",
          f"systemctl restart {svc}", "sleep 4",
          f"if ! systemctl is-active --quiet {svc}; then journalctl -u {svc} -n 40 --no-pager; exit 1; fi",
          "hysteria version | head -n 3 || true", sh_echo("== Готово")]
    return "\n".join(L) + "\n"


def provision(sid: int, opts: dict, log) -> None:
    with server_lock(sid):
        s = get_server(sid)
        if opts.get("assign_all"):
            for u in db.q("SELECT id FROM users"):
                db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (u["id"], sid))
        db.ex("UPDATE servers SET manage_stats=1, hy2_enabled=1 WHERE id=?", (sid,))
        s["manage_stats"], s["hy2_enabled"] = 1, 1
        stats = ensure_stats(s)
        users = desired_users(sid)
        obfs = secrets.token_urlsafe(16) if opts.get("obfs") else ""
        cfg_text = build_server_config(opts["domain"], opts["email"], int(opts["port"]), users or placeholder(s),
                                       stats, obfs)
        script = build_install_script(s, cfg_text, opts)
        log(f"Подключение к {s['host']}:{s['ssh_port']} как {s['ssh_user']}…\n")
        with Conn(s, timeout=20) as c:
            code = c.run_stream(RUN_SCRIPT, script, log, timeout=1800)
        if code != 0:
            raise HyError(f"Скрипт установки завершился с кодом {code}")
        db.ex("UPDATE servers SET public_host=CASE WHEN public_host='' THEN ? ELSE public_host END, "
              "cfg_info=?, dirty=0, last_sync=?, sync_error='' WHERE id=?",
              (opts["domain"], json.dumps(cfg_info(load_cfg(cfg_text))), int(time.time()), sid))
        log(f"\nПользователей на сервере: {len(users)}\n")
    poll_server(sid)


def update_core(sid: int, log) -> None:
    with server_lock(sid):
        s = get_server(sid)
        with Conn(s, timeout=20) as c:
            code = c.run_stream(RUN_SCRIPT, UPDATE_SCRIPT, log, timeout=900)
            if code != 0:
                raise HyError(f"Обновление завершилось с кодом {code}")
            log("Перезапуск службы…\n")
            svc_restart_verify(c, s, rollback=False)
            log("Служба активна.\n")
    poll_server(sid)
