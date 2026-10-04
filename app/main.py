"""Веб-интерфейс панели (FastAPI + Jinja2)."""
import hmac
import json
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import clients, db, hy, routing, security, ssh
from .i18n import LANG_COOKIE, LANGS, detect_lang, get_lang, js_bundle, reset_lang, set_lang, tr, tr_html
from .config import (ADMIN_BASE as ABASE, APP_DIR, BASE_PATH as BASE, BRAND, COOKIE_SECURE, DEFAULT_LANG, LEGACY_ADMIN_REDIRECT,
                     LEGACY_BASES, POLL_INTERVAL, PUBLIC_URL, SESSION_HOURS, TRUSTED_PROXIES)
from .tasks import worker
from .version import VERSION


@asynccontextmanager
async def lifespan(app):
    db.init()
    routing.ensure_presets()
    _migrate_public_url()
    ssh.ensure_panel_key()
    worker.start()
    worker.poll_now()
    yield


def _migrate_public_url() -> None:
    """Публичный адрес в настройках раньше указывал на старый префикс (…/hy-admin): переводим на текущий."""
    pu = (db.get_setting("public_url") or "").rstrip("/")
    for lb in LEGACY_BASES:
        if pu.endswith(lb):
            db.set_setting("public_url", pu[: -len(lb)] + BASE)
            db.audit("settings.public_url.migrated", f"{pu} → {pu[: -len(lb)] + BASE}", "system")
            break


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
r = APIRouter(prefix=ABASE)    # админка: BASE/admin/...
pr = APIRouter(prefix=BASE)    # публично: кабинет клиентов, подписки
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


# ---------------- форматирование ----------------
def fmt_bytes(n) -> str:
    n = float(n or 0)
    units = ("B", "KB", "MB", "GB", "TB") if get_lang() == "en" else ("Б", "КБ", "МБ", "ГБ", "ТБ")
    for i, u in enumerate(units):
        if abs(n) < 1024 or i == len(units) - 1:
            return f"{n:.0f} {u}" if i == 0 else f"{n:.2f} {u}"
        n /= 1024


def fmt_ts(ts) -> str:
    return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M") if ts else "—"


def fmt_date(ts) -> str:
    return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d") if ts else ""


def fmt_dur(sec) -> str:
    sec = int(sec or 0)
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    if get_lang() == "en":
        return f"{d} d {h} h" if d else (f"{h} h {m} min" if h else f"{m} min")
    return f"{d} д {h} ч" if d else (f"{h} ч {m} мин" if h else f"{m} мин")


def fmt_ago(ts) -> str:
    en = get_lang() == "en"
    if not ts:
        return "never" if en else "никогда"
    dt = int(time.time() - int(ts))
    if dt < 60:
        return "just now" if en else "только что"
    return fmt_dur(dt) + (" ago" if en else " назад")


def pct(a, b) -> int:
    return int(100 * a / b) if a and b else 0


templates.env.filters.update(bytes=fmt_bytes, ts=fmt_ts, dur=fmt_dur, ago=fmt_ago, date=fmt_date)
# base — адрес админки, pub — публичный (кабинет, подписки), static — файлы оформления
templates.env.globals.update(base=ABASE, pub=BASE, static=BASE + "/static", pct=pct, version=VERSION, brand=BRAND, lang=get_lang)


def user_state(u: dict) -> tuple[str, str]:
    now = time.time()
    if not u["enabled"]:
        return "off", "Отключён"
    if u["expires_at"] and u["expires_at"] <= now:
        return "expired", "Срок истёк"
    if u["traffic_limit"] and u["tx"] + u["rx"] >= u["traffic_limit"]:
        return "limit", "Лимит"
    return "on", "Активен"


templates.env.globals["user_state"] = user_state


# ---------------- безопасность ----------------
class LoginRequired(Exception):
    pass


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, exc):
    if request.url.path.startswith(ABASE + "/api/"):
        return JSONResponse({"ok": False, "error": tr("Требуется вход")}, status_code=401)
    nxt = quote(request.url.path + (("?" + request.url.query) if request.url.query else ""), safe="")
    return RedirectResponse(f"{ABASE}/login?next={nxt}", status_code=303)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    token = set_lang(detect_lang(request))      # язык запроса виден всему коду обработки (и потокам пула)
    try:
        resp = await call_next(request)
    finally:
        reset_lang(token)
    h = resp.headers
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Content-Security-Policy",
                 "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                 "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    if "/static/" not in request.url.path:
        h.setdefault("Cache-Control", "no-store")
    return resp


def client_ip(request: Request) -> str:
    ip = request.client.host if request.client else ""
    if ip in TRUSTED_PROXIES:
        xr = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        if xr:
            return xr
    return ip


def is_https(request: Request) -> bool:
    if COOKIE_SECURE in ("1", "true", "yes"):
        return True
    if COOKIE_SECURE in ("0", "false", "no"):
        return False
    if request.client and request.client.host in TRUSTED_PROXIES:
        return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    return request.url.scheme == "https"


def public_base(request: Request) -> str:
    pu = db.get_setting("public_url") or PUBLIC_URL
    if pu:
        return pu.rstrip("/")
    proto, host = request.url.scheme, request.headers.get("host", "localhost")
    if request.client and request.client.host in TRUSTED_PROXIES:
        proto = request.headers.get("x-forwarded-proto", proto)
        host = request.headers.get("x-forwarded-host", host)
    return f"{proto}://{host}{BASE}"


def session_dep(request: Request) -> dict:
    s = security.get_session(request.cookies.get(security.COOKIE))
    if not s:
        raise LoginRequired()
    return s


async def csrf_dep(request: Request, sess: dict = Depends(session_dep)) -> dict:
    tok = request.headers.get("x-csrf-token")
    if not tok:
        ctype = request.headers.get("content-type", "")
        if "form" in ctype:
            tok = (await request.form()).get("csrf")
    if not tok or not hmac.compare_digest(str(tok), sess["csrf"]):
        raise HTTPException(403, "CSRF-токен неверен. Обновите страницу.")
    return sess


# ---------------- ответы об ошибках ----------------
NOT_FOUND_HTML = ("<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
                  "<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")


def not_found() -> HTMLResponse:
    """Нейтральный 404, неотличимый от стандартной страницы nginx: чужим не видно, что здесь панель."""
    return HTMLResponse(NOT_FOUND_HTML, status_code=404)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and not request.url.path.startswith(ABASE + "/api/"):
        return not_found()
    return JSONResponse({"detail": tr(str(exc.detail))}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


def render(request: Request, name: str, sess: dict | None, **ctx):
    ctx.update(sess=sess, csrf=sess["csrf"] if sess else "",
               ok=(request.query_params.get("ok") or "")[:300], err=(request.query_params.get("err") or "")[:300])
    return page(request, name, ctx)


def page(request: Request, name: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    """Отрисовать шаблон; для английского интерфейса перевести готовую страницу."""
    ctx.setdefault("request", request)
    return HTMLResponse(tr_html(templates.get_template(name).render(ctx)), status_code=status_code)


def redirect(path: str, ok: str = "", err: str = "") -> RedirectResponse:
    q = ""
    if ok:
        q = "?ok=" + quote(tr(ok))
    elif err:
        q = "?err=" + quote(tr(err))
    return RedirectResponse(ABASE + path + q, status_code=303)


def audit(request: Request, action: str, detail: str = "") -> None:
    db.audit(action, detail, client_ip(request))


def jok(**kw) -> JSONResponse:
    if "msg" in kw:
        kw["msg"] = tr(kw["msg"])
    return JSONResponse({"ok": True, **kw})


def jerr(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"ok": False, "error": tr(msg)}, status_code=code)


async def call(fn, *a):
    """Выполнить блокирующую функцию (SSH) в пуле потоков; ошибки вернуть как JSON."""
    try:
        return True, await run_in_threadpool(fn, *a)
    except (hy.HyError, ssh.SSHError, RuntimeError, OSError, ValueError) as e:
        return False, str(e)


# ---------------- вход ----------------
def _safe_next(n: str | None) -> str:
    if n and n.startswith(ABASE + "/") and not n.startswith("//") and "\\" not in n:
        return n
    return ABASE + "/"


@r.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if security.get_session(request.cookies.get(security.COOKIE)):
        return RedirectResponse(ABASE + "/", status_code=303)
    return render(request, "login.html", None, next=request.query_params.get("next", ""),
                  no_admins=not db.q1("SELECT 1 FROM admins"))


@r.post("/login")
async def login(request: Request):
    ip = client_ip(request)
    form = await request.form()
    nxt = str(form.get("next") or "")
    if not security.limiter.allowed(ip):
        audit(request, "login.blocked", "слишком много попыток")
        return render(request, "login.html", None, next=nxt, error="Слишком много попыток. Подождите 15 минут.")
    username, password = str(form.get("username", ""))[:64], str(form.get("password", ""))[:256]
    admin = await run_in_threadpool(security.authenticate, username, password)
    if not admin:
        security.limiter.fail(ip)
        audit(request, "login.fail", username)
        return render(request, "login.html", None, next=nxt, error="Неверный логин или пароль")
    security.limiter.reset(ip)
    token = security.create_session(admin["id"], ip, request.headers.get("user-agent", ""))
    audit(request, "login.ok", username)
    resp = RedirectResponse(_safe_next(nxt), status_code=303)
    resp.set_cookie(security.COOKIE, token, max_age=SESSION_HOURS * 3600, httponly=True, samesite="strict",
                    secure=is_https(request), path=ABASE)
    return resp


@r.post("/logout")
async def logout(request: Request, sess: dict = Depends(csrf_dep)):
    security.delete_session(request.cookies.get(security.COOKIE))
    resp = RedirectResponse(ABASE + "/login", status_code=303)
    resp.delete_cookie(security.COOKIE, path=ABASE)
    return resp


# ---------------- представления ----------------
def server_view(s: dict) -> dict:
    s["st"] = json.loads(s.get("status") or "{}")
    s["st"]["down"] = int(s["st"].get("fails", 0)) >= hy.fail_threshold()
    s["info"] = json.loads(s.get("cfg_info") or "{}")
    return s


def all_servers() -> list[dict]:
    rows = db.q("SELECT s.*, (SELECT COUNT(*) FROM user_servers us WHERE us.server_id=s.id) AS users_count "
                "FROM servers s ORDER BY s.name")
    return [server_view(s) for s in rows]


@r.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, sess: dict = Depends(session_dep)):
    servers = all_servers()
    users = db.q("SELECT * FROM users")
    stats = {
        "servers": len(servers),
        "servers_up": sum(1 for s in servers if s["st"].get("active") == "active" and not s["st"]["down"]),
        "users": len(users),
        "users_active": sum(1 for u in users if user_state(u)[0] == "on"),
        "online": sum(s["st"].get("online_total", 0) for s in servers),
        "traffic": sum(u["tx"] + u["rx"] for u in users),
    }
    for s in servers:
        s["hist"] = hy.history(s["id"], "24h")
    top = sorted(users, key=lambda u: u["tx"] + u["rx"], reverse=True)[:8]
    jobs = db.q("SELECT j.*, s.name AS server_name FROM jobs j LEFT JOIN servers s ON s.id=j.server_id "
                "ORDER BY j.id DESC LIMIT 5")
    return render(request, "dashboard.html", sess, nav="dash", servers=servers, stats=stats, top=top, jobs=jobs)


# ---------------- серверы ----------------
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")
SVC_RE = re.compile(r"^[A-Za-z0-9@_.\-]{1,100}$")
SSHUSER_RE = re.compile(r"^[a-z_][a-z0-9_.\-]{0,31}$")


def _int(v, lo, hi, default):
    try:
        x = int(str(v).strip())
    except (TypeError, ValueError):
        return default
    return x if lo <= x <= hi else default


def parse_server_form(form, existing: dict | None) -> tuple[dict, list[str]]:
    g = lambda k, d="": str(form.get(k, d) or "").strip()
    errs = []
    d = {
        "name": g("name")[:60], "host": g("host"), "ssh_port": _int(g("ssh_port", "22"), 1, 65535, 22),
        "ssh_user": g("ssh_user", "root") or "root", "ssh_auth": g("ssh_auth", "panelkey"),
        "config_path": g("config_path") or "/etc/hysteria/config.yaml",
        "service": g("service") or "hysteria-server.service",
        "public_host": g("public_host"), "public_port": _int(g("public_port", "0"), 0, 65535, 0),
        "sni": g("sni"), "insecure": 1 if form.get("insecure") else 0, "hop_ports": g("hop_ports"),
        "manage_stats": 1 if form.get("manage_stats") else 0,
        "hy2_enabled": 1 if form.get("hy2_enabled") else 0,
        "auto_assign": 1 if form.get("auto_assign") else 0,
        "sb_service": g("sb_service") or "sing-box.service",
        "sb_config_path": g("sb_config_path") or "/etc/sing-box/config.json",
        "stats_port": _int(g("stats_port", "25413"), 1, 65535, 25413),
        "enabled": 1 if form.get("enabled") else 0, "notes": g("notes")[:2000],
    }
    if not d["name"]:
        errs.append("Укажите название")
    if not HOST_RE.match(d["host"]):
        errs.append("Некорректный адрес сервера")
    if d["public_host"] and not HOST_RE.match(d["public_host"]):
        errs.append("Некорректный публичный адрес")
    if d["sni"] and not HOST_RE.match(d["sni"]):
        errs.append("Некорректный SNI")
    if not SSHUSER_RE.match(d["ssh_user"]):
        errs.append("Некорректный SSH-пользователь")
    if not SVC_RE.match(d["service"]):
        errs.append("Некорректное имя службы")
    if not d["config_path"].startswith("/") or not d["sb_config_path"].startswith("/"):
        errs.append("Пути к конфигам должны быть абсолютными")
    if not SVC_RE.match(d["sb_service"]):
        errs.append("Некорректное имя службы sing-box")
    if d["hop_ports"] and not re.match(r"^\d+(-\d+)?(,\d+(-\d+)?)*$", d["hop_ports"]):
        errs.append("Порты hopping: формат 443,20000-30000")
    if d["ssh_auth"] not in ("panelkey", "password", "key"):
        errs.append("Неизвестный способ входа SSH")

    pw, key, kpass = str(form.get("ssh_password") or ""), str(form.get("ssh_key") or "").strip(), str(
        form.get("ssh_key_pass") or "")
    same_mode = existing and existing["ssh_auth"] == d["ssh_auth"]
    if d["ssh_auth"] == "password":
        if pw:
            d["ssh_secret"], d["ssh_key"] = security.encrypt(pw), ""
        elif not same_mode:
            errs.append("Укажите SSH-пароль")
    elif d["ssh_auth"] == "key":
        if key:
            try:
                ssh.load_pkey(key, kpass)
                d["ssh_key"], d["ssh_secret"] = security.encrypt(key), security.encrypt(kpass)
            except ssh.SSHError as e:
                errs.append(str(e))
        elif not same_mode:
            errs.append("Вставьте приватный ключ")
    else:
        d["ssh_secret"], d["ssh_key"] = "", ""
    if existing and (existing["host"] != d["host"] or int(existing["ssh_port"]) != d["ssh_port"]):
        d["host_key"] = ""
    return d, errs


@r.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request, sess: dict = Depends(session_dep)):
    return render(request, "servers.html", sess, nav="servers", servers=all_servers())


@r.get("/servers/new", response_class=HTMLResponse)
async def server_new_page(request: Request, sess: dict = Depends(session_dep)):
    return render(request, "server_form.html", sess, nav="servers", s=None, form={"enabled": 1, "manage_stats": 1, "hy2_enabled": 1, "auto_assign": 0},
                  errors=[], pubkey=ssh.panel_pubkey())


@r.post("/servers/new")
async def server_new(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    d, errs = parse_server_form(form, None)
    if errs:
        return render(request, "server_form.html", sess, nav="servers", s=None, form=dict(form), errors=errs,
                      pubkey=ssh.panel_pubkey())
    d["created"] = int(time.time())
    cols = ",".join(d)
    sid = db.ex(f"INSERT INTO servers({cols}) VALUES({','.join('?' * len(d))})", tuple(d.values()))
    if form.get("assign_all"):
        for u in db.q("SELECT id FROM users"):
            db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (u["id"], sid))
    audit(request, "server.create", f"{d['name']} ({d['host']})")
    worker.poll_pool.submit(hy.poll_server, sid)
    return redirect(f"/servers/{sid}", ok="Сервер добавлен. Проверьте подключение и импортируйте/синхронизируйте пользователей.")


@r.get("/servers/{sid}", response_class=HTMLResponse)
async def server_page(request: Request, sid: int, sess: dict = Depends(session_dep)):
    s = db.q1("SELECT * FROM servers WHERE id=?", (sid,))
    if not s:
        return redirect("/servers", err="Сервер не найден")
    server_view(s)
    users = db.q("SELECT u.*, us.tx AS s_tx, us.rx AS s_rx, us.online AS s_online, us.last_online AS s_last "
                 "FROM users u JOIN user_servers us ON us.user_id=u.id WHERE us.server_id=? ORDER BY u.username",
                 (sid,))
    jobs = db.q("SELECT * FROM jobs WHERE server_id=? ORDER BY id DESC LIMIT 5", (sid,))
    linked = {u["id"] for u in users}
    linkable = [u for u in db.q("SELECT id, username, note FROM users ORDER BY username") if u["id"] not in linked]
    return render(request, "server.html", sess, nav="servers", s=s, users=users, jobs=jobs,
                  linkable=linkable, drift=_drift(s),
                  hostkey_fp=ssh.host_key_fingerprint(s["host_key"]), pubkey=ssh.panel_pubkey(),
                  endpoint=clients.endpoint(s), hist=hy.history(sid, request.query_params.get("range", "24h")),
                  fail_threshold=hy.fail_threshold(), poll_interval=db.get_setting("poll_interval", POLL_INTERVAL))


def _drift(s: dict) -> dict | None:
    """Расхождение между пользователями в config.yaml Hysteria и тем, что должно быть по панели."""
    users = (s.get("info") or {}).get("users")
    if not s["hy2_enabled"] or users is None:
        return None
    want = hy.desired_users(s["id"])
    have = {k: v for k, v in users.items() if k != hy.PLACEHOLDER_USER}
    if not want and not have:
        return None
    extra = sorted(set(have) - set(want))
    missing = sorted(set(want) - set(have))
    changed = sorted(k for k in set(want) & set(have) if want[k] != have[k])
    return {"extra": extra, "missing": missing, "changed": changed} if (extra or missing or changed) else None


@r.post("/servers/{sid}/users/add")
async def server_users_add(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    s = db.q1("SELECT name FROM servers WHERE id=?", (sid,))
    if not s:
        return redirect("/servers", err="Сервер не найден")
    form = await request.form()
    valid = {u["id"] for u in db.q("SELECT id FROM users")}
    if form.get("all"):
        ids = sorted(valid)
    else:
        ids = sorted({int(x) for x in form.getlist("profiles") if str(x).isdigit() and int(x) in valid})
    for uid in ids:
        db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (uid, sid))
    if ids:
        hy.mark_dirty([sid])
    audit(request, "access.add", f"сервер {s['name']}: профилей {len(ids)}")
    return redirect(f"/servers/{sid}", ok=f"Добавлено профилей: {len(ids)}. Конфиг сервера обновится автоматически." if ids
                    else "Ничего не выбрано")


@r.post("/servers/{sid}/users/{uid}/remove")
async def server_user_remove(request: Request, sid: int, uid: int, sess: dict = Depends(csrf_dep)):
    u = db.q1("SELECT username FROM users WHERE id=?", (uid,))
    db.ex("DELETE FROM user_servers WHERE user_id=? AND server_id=?", (uid, sid))
    hy.mark_dirty([sid])
    audit(request, "access.remove", f"сервер id={sid}: {u['username'] if u else uid}")
    return redirect(f"/servers/{sid}", ok="Профиль снят с сервера. Он будет удалён из конфига при ближайшей синхронизации.")


# ---------------- матрица доступа: профили × серверы ----------------
@r.get("/access", response_class=HTMLResponse)
async def access_page(request: Request, sess: dict = Depends(session_dep)):
    users = db.q("SELECT u.id, u.username, u.note, u.enabled, u.expires_at, u.traffic_limit, u.tx, u.rx, "
                 "c.login AS owner FROM users u LEFT JOIN clients c ON c.id=u.client_id ORDER BY u.username")
    servers = db.q("SELECT id, name, enabled, hy2_enabled, vless_enabled, anytls_enabled, auto_assign, dirty, sync_error "
                   "FROM servers ORDER BY name")
    linked = {f"{r['user_id']}:{r['server_id']}" for r in db.q("SELECT user_id, server_id FROM user_servers")}
    return render(request, "access.html", sess, nav="access", users=users, servers=servers, linked=linked)


@r.post("/api/access")
async def api_access(request: Request, sess: dict = Depends(csrf_dep)):
    """Пакет изменений доступа: {"changes": [{"user_id", "server_id", "on"}]}."""
    b = await request.json()
    changes = b.get("changes")
    if not isinstance(changes, list) or not changes or len(changes) > 3000:
        return jerr("Нет изменений")
    users = {u["id"] for u in db.q("SELECT id FROM users")}
    servers = {s["id"] for s in db.q("SELECT id FROM servers")}
    touched, n = set(), 0
    for c in changes:
        try:
            uid, sid, on = int(c["user_id"]), int(c["server_id"]), bool(c["on"])
        except (KeyError, TypeError, ValueError):
            return jerr("Некорректный запрос")
        if uid not in users or sid not in servers:
            continue
        if on:
            db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (uid, sid))
        else:
            db.ex("DELETE FROM user_servers WHERE user_id=? AND server_id=?", (uid, sid))
        touched.add(sid)
        n += 1
    if touched:
        hy.mark_dirty(touched)
    audit(request, "access.matrix", f"изменений: {n}, серверов затронуто: {len(touched)}")
    return jok(msg=f"Сохранено ({n}). Затронутые серверы синхронизируются автоматически.")


@r.get("/servers/{sid}/edit", response_class=HTMLResponse)
async def server_edit_page(request: Request, sid: int, sess: dict = Depends(session_dep)):
    s = db.q1("SELECT * FROM servers WHERE id=?", (sid,))
    if not s:
        return redirect("/servers", err="Сервер не найден")
    return render(request, "server_form.html", sess, nav="servers", s=s, form=s, errors=[], pubkey=ssh.panel_pubkey())


@r.post("/servers/{sid}/edit")
async def server_edit(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    s = db.q1("SELECT * FROM servers WHERE id=?", (sid,))
    if not s:
        return redirect("/servers", err="Сервер не найден")
    form = await request.form()
    d, errs = parse_server_form(form, s)
    if errs:
        return render(request, "server_form.html", sess, nav="servers", s=s, form=dict(form), errors=errs,
                      pubkey=ssh.panel_pubkey())
    db.ex(f"UPDATE servers SET {','.join(k + '=?' for k in d)} WHERE id=?", (*d.values(), sid))
    if (d["manage_stats"], d["stats_port"]) != (s["manage_stats"], s["stats_port"]):
        hy.mark_dirty([sid])
    audit(request, "server.edit", d["name"])
    return redirect(f"/servers/{sid}", ok="Сохранено")


@r.post("/servers/{sid}/delete")
async def server_delete(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    s = db.q1("SELECT name FROM servers WHERE id=?", (sid,))
    db.ex("DELETE FROM servers WHERE id=?", (sid,))
    audit(request, "server.delete", s["name"] if s else str(sid))
    return redirect("/servers", ok="Сервер удалён из панели (на самом VPS ничего не изменено)")


# ----- API серверов -----
@r.post("/api/servers/{sid}/check")
async def api_check(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    ok, res = await call(hy.poll_server, sid)
    if not ok:
        return jerr(res)
    return jok(status=res) if res.get("ok") else jerr(res.get("error", "Ошибка"))


@r.post("/api/servers/{sid}/service/{op}")
async def api_service(request: Request, sid: int, op: str, sess: dict = Depends(csrf_dep)):
    ok, res = await call(hy.service_action, sid, op)
    audit(request, f"server.{op}", f"id={sid} {'ok' if ok else res[:200]}")
    return jok(msg=f"Состояние службы: {res}") if ok else jerr(res)


@r.post("/api/servers/{sid}/sync")
async def api_sync(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    ok, res = await call(hy.sync_server, sid)
    audit(request, "server.sync.manual", f"id={sid} {'ok' if ok else res[:200]}")
    if not ok:
        return jerr(res)
    msg = f"Пользователей: {res['users']}. " + ("Конфиг обновлён, служба перезапущена." if res["changed"]
                                               else "Изменений нет.")
    return jok(msg=msg)


@r.post("/api/servers/{sid}/import")
async def api_import(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    ok, res = await call(hy.import_users, sid)
    if not ok:
        return jerr(res)
    audit(request, "server.import", f"id={sid} {json.dumps(res, ensure_ascii=False)[:500]}")
    lines = [f"Создано: {', '.join(res['created']) or '—'}", f"Привязано: {', '.join(res['linked']) or '—'}"]
    if res["conflicts"]:
        lines.append("Проблемы:\n  " + "\n  ".join(res["conflicts"]))
    return jok(msg="\n".join(lines))


@r.get("/api/servers/{sid}/logs")
async def api_logs(request: Request, sid: int, n: int = 200, which: str = "hy", sess: dict = Depends(session_dep)):
    ok, res = await call(hy.get_logs, sid, max(10, min(n, 2000)), "sb" if which == "sb" else "hy")
    return jok(text=res) if ok else jerr(res)


def _read_config(sid: int) -> str:
    s = hy.get_server(sid)
    with ssh.Conn(s) as c:
        return c.read_file(s["config_path"])


@r.get("/api/servers/{sid}/config")
async def api_config_get(request: Request, sid: int, sess: dict = Depends(session_dep)):
    ok, res = await call(_read_config, sid)
    return jok(text=res) if ok else jerr(res)


@r.post("/api/servers/{sid}/config")
async def api_config_save(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    body = await request.json()
    text = str(body.get("text", ""))
    if len(text) > 200_000:
        return jerr("Слишком большой файл")
    ok, res = await call(hy.save_raw_config, sid, text)
    audit(request, "server.config.edit", f"id={sid} {'ok' if ok else res[:300]}")
    return jok(msg="Конфиг сохранён, служба перезапущена") if ok else jerr(res)


@r.get("/api/servers/{sid}/sbconfig")
async def api_sbconfig_get(request: Request, sid: int, sess: dict = Depends(session_dep)):
    from . import sb
    ok, res = await call(sb.read_config, sid)
    return jok(text=res) if ok else jerr(res)


@r.post("/api/servers/{sid}/sbconfig")
async def api_sbconfig_save(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    from . import sb
    text = str((await request.json()).get("text", ""))
    if len(text) > 500_000:
        return jerr("Слишком большой файл")
    ok, res = await call(sb.save_config, sid, text)
    audit(request, "server.sbconfig.edit", f"id={sid} {'ok' if ok else res[:300]}")
    return jok(msg="Конфиг sing-box сохранён, служба перезапущена") if ok else jerr(res)


@r.post("/api/servers/{sid}/rollback")
async def api_rollback(request: Request, sid: int, which: str = "hy", sess: dict = Depends(csrf_dep)):
    ok, res = await call(hy.rollback_config, sid, "sb" if which == "sb" else "hy")
    audit(request, "server.config.rollback", f"id={sid} {res[:200] if isinstance(res, str) else ''}")
    return jok(msg=f"Восстановлен {res}") if ok else jerr(res)


@r.post("/api/servers/{sid}/reset-hostkey")
async def api_reset_hostkey(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    db.ex("UPDATE servers SET host_key='' WHERE id=?", (sid,))
    audit(request, "server.hostkey.reset", f"id={sid}")
    return jok(msg="Ключ хоста сброшен, будет запомнен при следующем подключении")


@r.post("/api/servers/{sid}/install-key")
async def api_install_key(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    ok, res = await call(hy.install_panel_key, sid, ssh.panel_pubkey())
    audit(request, "server.install_key", f"id={sid} {'ok' if ok else res[:200]}")
    return jok(msg="Ключ панели установлен, вход по паролю отключён в панели") if ok else jerr(res)


@r.post("/api/servers/{sid}/kick")
async def api_kick(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    body = await request.json()
    name = str(body.get("user", ""))
    ok, res = await call(hy.kick, sid, [name])
    audit(request, "server.kick", f"id={sid} {name}")
    return jok(msg=f"{name} отключён (переподключится, если профиль активен)") if ok else jerr(res)


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


@r.post("/api/servers/{sid}/provision")
async def api_provision(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    b = await request.json()
    opts = {"domain": str(b.get("domain", "")).strip().lower(), "email": str(b.get("email", "")).strip(),
            "port": _int(b.get("port", 443), 1, 65535, 0), "upgrade": bool(b.get("upgrade")),
            "ufw": bool(b.get("ufw")), "obfs": bool(b.get("obfs")), "assign_all": bool(b.get("assign_all"))}
    if not DOMAIN_RE.match(opts["domain"]):
        return jerr("Укажите домен, направленный (A-запись) на IP сервера")
    if not re.match(r"^[^@\s'\"]+@[^@\s'\"]+\.[^@\s'\"]+$", opts["email"]):
        return jerr("Укажите корректный e-mail для ACME")
    if not opts["port"]:
        return jerr("Некорректный порт")
    if not db.q1("SELECT 1 FROM servers WHERE id=?", (sid,)):
        return jerr("Сервер не найден", 404)
    audit(request, "server.provision", f"id={sid} {json.dumps(opts)}")
    jid = worker.run_job("provision", sid, lambda log: hy.provision(sid, opts, log))
    return jok(job=jid, url=f"{ABASE}/jobs/{jid}")


@r.post("/api/servers/{sid}/provision-sb")
async def api_provision_sb(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    from . import sb
    b = await request.json()
    s = db.q1("SELECT * FROM servers WHERE id=?", (sid,))
    if not s:
        return jerr("Сервер не найден", 404)
    opts = {"vless": bool(b.get("vless")), "anytls": bool(b.get("anytls")), "ufw": bool(b.get("ufw")),
            "assign_all": bool(b.get("assign_all")),
            "vless_port": _int(b.get("vless_port", 8443), 1, 65535, 0),
            "anytls_port": _int(b.get("anytls_port", 9443), 1, 65535, 0),
            "reality_sni": str(b.get("reality_sni", "")).strip().lower(),
            "anytls_domain": str(b.get("anytls_domain", "")).strip().lower(),
            "anytls_cert": "selfsigned" if b.get("anytls_cert") == "selfsigned" else "hysteria"}
    if not (opts["vless"] or opts["anytls"]):
        return jerr("Выберите хотя бы один протокол")
    if opts["vless"]:
        if not opts["vless_port"]:
            return jerr("Некорректный порт VLESS")
        if not sb.DOMAIN_RE.match(opts["reality_sni"]):
            return jerr("Укажите домен для маскировки Reality (например www.microsoft.com)")
    if opts["anytls"]:
        if not opts["anytls_port"]:
            return jerr("Некорректный порт AnyTLS")
        if not sb.DOMAIN_RE.match(opts["anytls_domain"]):
            return jerr("Укажите домен AnyTLS (A-запись должна указывать на этот сервер)")
    if opts["vless"] and opts["anytls"] and opts["vless_port"] == opts["anytls_port"]:
        return jerr("Порты VLESS и AnyTLS должны различаться")
    if s["hy2_enabled"]:
        # Hysteria2 по инструкции занимает TCP 443 (заглушка HTTPS) и TCP 80 (ACME)
        for name, key in (("VLESS", "vless"), ("AnyTLS", "anytls")):
            if opts[key] and opts[key + "_port"] in (80, 443):
                return jerr(f"Порт {name} {opts[key + '_port']} занят Hysteria2 — выберите другой, например 8443")
    audit(request, "server.provision_sb", f"id={sid} {json.dumps(opts)}")
    jid = worker.run_job("sing-box", sid, lambda log: sb.provision(sid, opts, log))
    return jok(job=jid, url=f"{ABASE}/jobs/{jid}")


@r.post("/api/servers/{sid}/update-core")
async def api_update_core(request: Request, sid: int, sess: dict = Depends(csrf_dep)):
    audit(request, "server.update_core", f"id={sid}")
    jid = worker.run_job("update", sid, lambda log: hy.update_core(sid, log))
    return jok(job=jid, url=f"{ABASE}/jobs/{jid}")


@r.post("/api/poll-all")
async def api_poll_all(request: Request, sess: dict = Depends(csrf_dep)):
    worker.poll_now()
    return jok(msg="Опрос серверов запущен")


# ---------------- задачи ----------------
@r.get("/jobs/{jid}", response_class=HTMLResponse)
async def job_page(request: Request, jid: int, sess: dict = Depends(session_dep)):
    j = db.q1("SELECT j.*, s.name AS server_name FROM jobs j LEFT JOIN servers s ON s.id=j.server_id WHERE j.id=?",
              (jid,))
    if not j:
        return redirect("/", err="Задача не найдена")
    return render(request, "job.html", sess, j=j)


@r.get("/api/jobs/{jid}")
async def api_job(request: Request, jid: int, sess: dict = Depends(session_dep)):
    j = db.q1("SELECT id,status,log,finished FROM jobs WHERE id=?", (jid,))
    if j:
        j["log"] = tr(j["log"])
    return jok(**j) if j else jerr("Не найдено", 404)


# ---------------- пользователи ----------------
PW_RE = re.compile(r"^[\x21-\x7e]{6,128}$")


def parse_user_form(form, existing: dict | None) -> tuple[dict, list[int], list[str]]:
    g = lambda k, d="": str(form.get(k, d) or "").strip()
    errs = []
    d = {"username": g("username").lower(), "password": g("password"), "enabled": 1 if form.get("enabled") else 0,
         "note": g("note")[:1000]}
    if not hy.USERNAME_RE.match(d["username"]):
        errs.append("Логин: 1–32 символа, латиница в нижнем регистре, цифры, . _ -")
    elif d["username"] == hy.PLACEHOLDER_USER:
        errs.append("Этот логин зарезервирован")
    else:
        other = db.q1("SELECT id FROM users WHERE username=?", (d["username"],))
        if other and (not existing or other["id"] != existing["id"]):
            errs.append("Такой логин уже существует")
    if not PW_RE.match(d["password"]):
        errs.append("Пароль: 6–128 печатных ASCII-символов без пробелов")
    exp = g("expires")
    if exp:
        try:
            d["expires_at"] = int(datetime.strptime(exp, "%Y-%m-%d").replace(hour=23, minute=59, second=59).timestamp())
        except ValueError:
            errs.append("Некорректная дата окончания")
    else:
        d["expires_at"] = 0
    try:
        gb = float(g("limit_gb", "0").replace(",", ".") or 0)
        d["traffic_limit"] = int(gb * 1024 ** 3) if gb > 0 else 0
    except ValueError:
        errs.append("Некорректный лимит трафика")
    cid = g("client_id")
    d["client_id"] = int(cid) if cid.isdigit() and db.q1("SELECT 1 FROM clients WHERE id=?", (int(cid),)) else None
    tid = g("template_id")
    d["template_id"] = int(tid) if tid.isdigit() and db.q1("SELECT 1 FROM route_templates WHERE id=?", (int(tid),)) else None
    valid = {s["id"] for s in db.q("SELECT id FROM servers")}
    sids = sorted({int(x) for x in form.getlist("servers") if str(x).isdigit() and int(x) in valid})
    return d, sids, errs


def _user_form_ctx(u: dict | None, form: dict, sids: list[int], errors: list[str]) -> dict:
    return dict(nav="users", u=u, form=form, sel=set(sids), errors=errors,
                servers=db.q("SELECT id,name,host,enabled FROM servers ORDER BY name"),
                clients=db.q("SELECT id,login,name FROM clients ORDER BY login"),
                templates=db.q("SELECT id,name FROM route_templates ORDER BY name"),
                default_template_name=(db.q1("SELECT name FROM route_templates WHERE id=?", (routing.default_id(),)) or {}).get("name"))


@r.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, sess: dict = Depends(session_dep)):
    qtext = (request.query_params.get("q") or "").strip().lower()
    state = request.query_params.get("state") or ""
    srv = request.query_params.get("server") or ""
    rows = db.q("SELECT u.*, (SELECT COUNT(*) FROM user_servers us WHERE us.user_id=u.id) AS servers_count, "
                "(SELECT GROUP_CONCAT(s.name, ', ') FROM servers s JOIN user_servers us ON us.server_id=s.id "
                "WHERE us.user_id=u.id) AS server_names, "
                "(SELECT COALESCE(SUM(online),0) FROM user_servers us WHERE us.user_id=u.id) AS online, "
                "c.login AS owner "
                "FROM users u LEFT JOIN clients c ON c.id=u.client_id ORDER BY u.username")
    if srv.isdigit():
        ids = {x["user_id"] for x in db.q("SELECT user_id FROM user_servers WHERE server_id=?", (int(srv),))}
        rows = [u for u in rows if u["id"] in ids]
    if qtext:
        rows = [u for u in rows if qtext in u["username"] or qtext in (u["note"] or "").lower()]
    if state:
        rows = [u for u in rows if user_state(u)[0] == state]
    return render(request, "users.html", sess, nav="users", users=rows, q=qtext, state=state, server=srv,
                  servers=db.q("SELECT id,name FROM servers ORDER BY name"))


@r.get("/users/new", response_class=HTMLResponse)
async def user_new_page(request: Request, sess: dict = Depends(session_dep)):
    sids = [s["id"] for s in db.q("SELECT id FROM servers WHERE enabled=1 AND auto_assign=1")]
    cid = request.query_params.get("client", "")
    form = {"password": security.gen_password(), "enabled": 1, "client_id": int(cid) if cid.isdigit() else None}
    return render(request, "user_form.html", sess, **_user_form_ctx(None, form, sids, []))


@r.post("/users/new")
async def user_new(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    d, sids, errs = parse_user_form(form, None)
    if errs:
        return render(request, "user_form.html", sess, **_user_form_ctx(None, dict(form), sids, errs))
    uid = hy.create_user(d["username"], d["password"], d["note"], enabled=d["enabled"],
                         expires_at=d["expires_at"], traffic_limit=d["traffic_limit"])
    db.ex("UPDATE users SET client_id=?, template_id=? WHERE id=?", (d["client_id"], d["template_id"], uid))
    for sid in sids:
        db.ex("INSERT INTO user_servers(user_id,server_id) VALUES(?,?)", (uid, sid))
    db.ex("UPDATE users SET active=? WHERE id=?",
          (1 if hy.user_is_active(db.q1("SELECT * FROM users WHERE id=?", (uid,))) else 0, uid))
    hy.mark_dirty(sids)
    audit(request, "user.create", d["username"])
    return redirect(f"/users/{uid}", ok="Профиль создан, серверы синхронизируются")


def _load_user(uid: int) -> dict | None:
    return db.q1("SELECT * FROM users WHERE id=?", (uid,))


@r.get("/users/{uid}", response_class=HTMLResponse)
async def user_page(request: Request, uid: int, sess: dict = Depends(session_dep)):
    u = _load_user(uid)
    if not u:
        return redirect("/users", err="Профиль не найден")
    servers = [server_view(s) for s in db.q(
        "SELECT s.*, us.tx AS u_tx, us.rx AS u_rx, us.online AS u_online, us.last_online AS u_last "
        "FROM servers s JOIN user_servers us ON us.server_id=s.id WHERE us.user_id=? ORDER BY s.name", (uid,))]
    for s in servers:
        s["links"] = clients.links(u, s)
    sub_url = f"{public_base(request)}/sub/{u['sub_token']}"
    daily = db.q("SELECT day, SUM(tx) AS tx, SUM(rx) AS rx FROM traffic_daily WHERE user_id=? "
                 "GROUP BY day ORDER BY day DESC LIMIT 14", (uid,))
    owner = db.q1("SELECT id, login, name FROM clients WHERE id=?", (u["client_id"],)) if u["client_id"] else None
    tpl = routing.template_for(u)
    return render(request, "user.html", sess, nav="users", u=u, servers=servers, sub_url=sub_url, owner=owner,
                  tpl=tpl, tpl_own=bool(u["template_id"]),
                  sub_qr=clients.qr_svg(sub_url), daily=list(reversed(daily)),
                  daily_max=max([d["tx"] + d["rx"] for d in daily] or [0]))


@r.get("/users/{uid}/edit", response_class=HTMLResponse)
async def user_edit_page(request: Request, uid: int, sess: dict = Depends(session_dep)):
    u = _load_user(uid)
    if not u:
        return redirect("/users", err="Профиль не найден")
    form = dict(u, expires=fmt_date(u["expires_at"]),
                limit_gb=("%g" % (u["traffic_limit"] / 1024 ** 3)) if u["traffic_limit"] else "")
    return render(request, "user_form.html", sess, **_user_form_ctx(u, form, hy.user_server_ids(uid), []))


@r.post("/users/{uid}/edit")
async def user_edit(request: Request, uid: int, sess: dict = Depends(csrf_dep)):
    u = _load_user(uid)
    if not u:
        return redirect("/users", err="Профиль не найден")
    form = await request.form()
    d, sids, errs = parse_user_form(form, u)
    if errs:
        return render(request, "user_form.html", sess, **_user_form_ctx(u, dict(form), sids, errs))
    old = set(hy.user_server_ids(uid))
    db.ex(f"UPDATE users SET {','.join(k + '=?' for k in d)} WHERE id=?", (*d.values(), uid))
    for sid in old - set(sids):
        db.ex("DELETE FROM user_servers WHERE user_id=? AND server_id=?", (uid, sid))
    for sid in set(sids) - old:
        db.ex("INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)", (uid, sid))
    nu = _load_user(uid)
    db.ex("UPDATE users SET active=? WHERE id=?", (1 if hy.user_is_active(nu) else 0, uid))
    hy.mark_dirty(old | set(sids))
    audit(request, "user.edit", d["username"])
    return redirect(f"/users/{uid}", ok="Сохранено, серверы синхронизируются")


@r.post("/users/{uid}/action/{act}")
async def user_action(request: Request, uid: int, act: str, sess: dict = Depends(csrf_dep)):
    u = _load_user(uid)
    if not u:
        return redirect("/users", err="Профиль не найден")
    sids = hy.user_server_ids(uid)
    if act == "delete":
        db.ex("DELETE FROM users WHERE id=?", (uid,))
        hy.mark_dirty(sids)
        audit(request, "user.delete", u["username"])
        return redirect("/users", ok=f"Профиль {u['username']} удалён")
    if act == "toggle":
        db.ex("UPDATE users SET enabled=? WHERE id=?", (0 if u["enabled"] else 1, uid))
        msg = "Профиль отключён" if u["enabled"] else "Профиль включён"
    elif act == "regen-password":
        # меняем все учётные данные: пароль (Hysteria2, AnyTLS) и UUID (VLESS)
        db.ex("UPDATE users SET password=?, uuid=? WHERE id=?", (security.gen_password(), str(uuid.uuid4()), uid))
        hy.mark_dirty(sids)
        msg = "Новый пароль сгенерирован — старые ссылки больше не работают"
    elif act == "reset-traffic":
        db.ex("UPDATE users SET tx=0, rx=0 WHERE id=?", (uid,))
        db.ex("UPDATE user_servers SET tx=0, rx=0 WHERE user_id=?", (uid,))
        msg = "Счётчик трафика сброшен"
    elif act == "regen-sub":
        db.ex("UPDATE users SET sub_token=? WHERE id=?", (secrets.token_urlsafe(24), uid))
        msg = "Ссылка подписки перевыпущена"
    elif act == "extend30":
        base = max(u["expires_at"], int(time.time()))
        end = datetime.fromtimestamp(base + 30 * 86400).replace(hour=23, minute=59, second=59)
        db.ex("UPDATE users SET expires_at=? WHERE id=?", (int(end.timestamp()), uid))
        msg = f"Срок продлён до {end.strftime('%d.%m.%Y')}"
    else:
        return redirect(f"/users/{uid}", err="Неизвестное действие")
    hy.refresh_user_active(uid)
    audit(request, f"user.{act}", u["username"])
    return redirect(f"/users/{uid}", ok=msg)


@r.post("/api/users/{uid}/kick")
async def api_user_kick(request: Request, uid: int, sess: dict = Depends(csrf_dep)):
    u = _load_user(uid)
    if not u:
        return jerr("Не найдено", 404)
    errors = []
    for sid in hy.user_server_ids(uid):
        ok, res = await call(hy.kick, sid, [u["username"]])
        if not ok:
            errors.append(res)
    audit(request, "user.kick", u["username"])
    return jok(msg="Отключён со всех серверов") if not errors else jerr("; ".join(errors))


def _user_server(uid: int, sid: int):
    u = _load_user(uid)
    s = db.q1("SELECT s.* FROM servers s JOIN user_servers us ON us.server_id=s.id WHERE us.user_id=? AND s.id=?",
              (uid, sid))
    if not u or not s:
        raise HTTPException(404)
    return u, s


def _safe_fn(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]+", "_", s)[:80] or "profile"


def _proto_arg(request: Request, s: dict) -> str:
    p = request.query_params.get("p", "hy2")
    if p not in clients.protos(s):
        raise HTTPException(404)
    return p


@r.get("/users/{uid}/qr/{sid}.png")
async def user_qr_png(request: Request, uid: int, sid: int, sess: dict = Depends(session_dep)):
    u, s = _user_server(uid, sid)
    return Response(clients.qr_png(clients.uri(u, s, _proto_arg(request, s))), media_type="image/png")


@r.get("/users/{uid}/hysteria/{sid}.yaml")
async def user_hy_yaml(uid: int, sid: int, sess: dict = Depends(session_dep)):
    u, s = _user_server(uid, sid)
    if "hy2" not in clients.protos(s):
        raise HTTPException(404)
    fn = _safe_fn(clients.profile_name(u, s)) + ".yaml"
    return PlainTextResponse(clients.hysteria_yaml(u, s), media_type="application/x-yaml",
                             headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@r.get("/users/{uid}/clash.yaml")
async def user_clash_yaml(uid: int, sess: dict = Depends(session_dep)):
    u = _load_user(uid)
    if not u:
        raise HTTPException(404)
    servers = db.q("SELECT s.* FROM servers s JOIN user_servers us ON us.server_id=s.id WHERE us.user_id=? "
                   "AND s.enabled=1 ORDER BY s.name", (uid,))
    return PlainTextResponse(clients.clash_yaml(u, servers, routing.template_for(u)), media_type="application/x-yaml",
                             headers={"Content-Disposition": f'attachment; filename="clash-{_safe_fn(u["username"])}.yaml"'})


# ---------------- публичная подписка ----------------
def _sub_user(token: str):
    if not token or len(token) > 64:
        raise HTTPException(404)
    u = db.q1("SELECT * FROM users WHERE sub_token=?", (token,))
    if not u:
        raise HTTPException(404)
    servers = []
    if hy.user_is_active(u):
        servers = db.q("SELECT s.* FROM servers s JOIN user_servers us ON us.server_id=s.id WHERE us.user_id=? "
                       "AND s.enabled=1 ORDER BY s.name", (u["id"],))
    return u, servers


@pr.get("/sub/{token}")
async def sub(request: Request, token: str):
    u, servers = _sub_user(token)
    if request.query_params.get("format") == "clash":
        return PlainTextResponse(clients.clash_yaml(u, servers, routing.template_for(u)), media_type="text/yaml; charset=utf-8",
                                 headers=clients.sub_headers(u))
    return PlainTextResponse(clients.sub_body(u, servers), headers=clients.sub_headers(u))


@pr.get("/sub/{token}/clash")
async def sub_clash(request: Request, token: str):
    u, servers = _sub_user(token)
    return PlainTextResponse(clients.clash_yaml(u, servers, routing.template_for(u)), media_type="text/yaml; charset=utf-8",
                             headers=clients.sub_headers(u))


# ---------------- настройки ----------------
@r.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, sess: dict = Depends(session_dep)):
    sessions = db.q("SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id=s.admin_id "
                    "WHERE s.expires>? ORDER BY s.created DESC", (int(time.time()),))
    return render(request, "settings.html", sess, nav="settings", pubkey=ssh.panel_pubkey(), sessions=sessions,
                  public_url=db.get_setting("public_url") or "", env_public_url=PUBLIC_URL,
                  poll_interval=db.get_setting("poll_interval", POLL_INTERVAL), detected=public_base(request),
                  fail_threshold=hy.fail_threshold(), admin_path=ABASE[len(BASE):])


@r.post("/settings/general")
async def settings_general(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    pu = str(form.get("public_url") or "").strip().rstrip("/")
    if pu and not re.match(r"^https?://[A-Za-z0-9.\-:\[\]]+(/[A-Za-z0-9._~\-/]*)?$", pu):
        return redirect("/settings", err="Некорректный адрес панели")
    db.set_setting("public_url", pu)
    db.set_setting("poll_interval", _int(form.get("poll_interval"), 15, 3600, POLL_INTERVAL))
    db.set_setting("fail_threshold", _int(form.get("fail_threshold"), 1, 20, hy.FAIL_THRESHOLD_DEFAULT))
    audit(request, "settings.general", pu)
    return redirect("/settings", ok="Настройки сохранены")


@r.post("/settings/password")
async def settings_password(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    cur, new, new2 = (str(form.get(k) or "") for k in ("current", "new", "new2"))
    admin = db.q1("SELECT * FROM admins WHERE id=?", (sess["admin_id"],))
    if not await run_in_threadpool(security.verify_password, cur, admin["pw_hash"]):
        return redirect("/settings", err="Текущий пароль неверен")
    if len(new) < 10 or new != new2:
        return redirect("/settings", err="Новый пароль: минимум 10 символов, оба поля должны совпадать")
    h = await run_in_threadpool(security.hash_password, new)
    db.ex("UPDATE admins SET pw_hash=? WHERE id=?", (h, admin["id"]))
    db.ex("DELETE FROM sessions WHERE admin_id=? AND token_hash<>?", (admin["id"], sess["token_hash"]))
    audit(request, "admin.password", admin["username"])
    return redirect("/settings", ok="Пароль изменён, остальные сессии завершены")


@r.post("/settings/sessions/revoke")
async def settings_revoke(request: Request, sess: dict = Depends(csrf_dep)):
    db.ex("DELETE FROM sessions WHERE token_hash<>?", (sess["token_hash"],))
    audit(request, "sessions.revoke")
    return redirect("/settings", ok="Все остальные сессии завершены")


@r.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request, sess: dict = Depends(session_dep)):
    return render(request, "audit.html", sess, nav="audit",
                  rows=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 500"))


# ---------------- шаблоны маршрутизации (Clash / mihomo) ----------------
def _tpl_form_ctx(t: dict | None, form: dict, errors: list[str]) -> dict:
    notes, info = [], None
    text = form.get("yaml") or ""
    if text.strip():
        try:
            info = routing.analyze(text)
            notes = info["notes"]
        except routing.TemplateError as e:
            errors = errors + [str(e)]
    return dict(nav="routing", t=t, form=form, errors=errors, notes=notes, info=info)


@r.get("/routing", response_class=HTMLResponse)
async def routing_page(request: Request, sess: dict = Depends(session_dep)):
    return render(request, "routing.html", sess, nav="routing", templates_=routing.list_templates(),
                  default_id=routing.default_id(),
                  no_default_users=db.q1("SELECT COUNT(*) AS n FROM users WHERE template_id IS NULL")["n"])


@r.post("/routing/default")
async def routing_default(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    tid = str(form.get("template_id") or "")
    if tid.isdigit() and db.q1("SELECT 1 FROM route_templates WHERE id=?", (int(tid),)):
        db.set_setting("default_template", tid)
        msg = "Шаблон по умолчанию назначен"
    else:
        db.set_setting("default_template", "")
        msg = "Шаблон по умолчанию отключён: выдаётся простой встроенный конфиг"
    audit(request, "routing.default", tid)
    return redirect("/routing", ok=msg)


def _save_template(name: str, text: str, tid: int | None) -> tuple[int | None, list[str]]:
    errs = []
    name = name.strip()[:80]
    if not name:
        errs.append("Укажите название")
    other = db.q1("SELECT id FROM route_templates WHERE name=?", (name,)) if name else None
    if other and other["id"] != tid:
        errs.append("Шаблон с таким названием уже есть")
    converted = text
    notes: list[str] = []
    if not errs:
        try:
            converted, notes = routing.convert(text)
            routing.analyze(converted)
        except routing.TemplateError as e:
            errs.append(str(e))
    if errs:
        return None, errs
    now = int(time.time())
    if tid:
        db.ex("UPDATE route_templates SET name=?, yaml=?, updated=? WHERE id=?", (name, converted, now, tid))
    else:
        tid = db.ex("INSERT INTO route_templates(name,yaml,created,updated) VALUES(?,?,?,?)", (name, converted, now, now))
    return tid, notes


@r.get("/routing/new", response_class=HTMLResponse)
async def routing_new_page(request: Request, sess: dict = Depends(session_dep)):
    return render(request, "routing_form.html", sess, **_tpl_form_ctx(None, {"name": "", "yaml": ""}, []))


@r.post("/routing/new")
async def routing_new(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    name, text = str(form.get("name") or ""), str(form.get("yaml") or "")
    tid, res = await run_in_threadpool(_save_template, name, text, None)
    if tid is None:
        return render(request, "routing_form.html", sess, **_tpl_form_ctx(None, {"name": name, "yaml": text}, res))
    audit(request, "routing.create", name)
    return redirect(f"/routing/{tid}", ok="Шаблон сохранён" + (" · " + " ".join(res) if res else ""))


@r.get("/routing/{tid}", response_class=HTMLResponse)
async def routing_edit_page(request: Request, tid: int, sess: dict = Depends(session_dep)):
    t = db.q1("SELECT * FROM route_templates WHERE id=?", (tid,))
    if not t:
        return redirect("/routing", err="Шаблон не найден")
    used = db.q("SELECT id, username FROM users WHERE template_id=? ORDER BY username", (tid,))
    return render(request, "routing_form.html", sess, used=used, is_default=routing.default_id() == tid,
                  **_tpl_form_ctx(t, t, []))


@r.post("/routing/{tid}/edit")
async def routing_edit(request: Request, tid: int, sess: dict = Depends(csrf_dep)):
    t = db.q1("SELECT * FROM route_templates WHERE id=?", (tid,))
    if not t:
        return redirect("/routing", err="Шаблон не найден")
    form = await request.form()
    name, text = str(form.get("name") or ""), str(form.get("yaml") or "")
    res_id, res = await run_in_threadpool(_save_template, name, text, tid)
    if res_id is None:
        return render(request, "routing_form.html", sess, used=[], is_default=routing.default_id() == tid,
                      **_tpl_form_ctx(t, {"name": name, "yaml": text}, res))
    audit(request, "routing.edit", name)
    return redirect(f"/routing/{tid}", ok="Сохранено. Клиенты получат новые правила при следующем обновлении подписки"
                    + (" · " + " ".join(res) if res else ""))


@r.post("/routing/{tid}/delete")
async def routing_delete(request: Request, tid: int, sess: dict = Depends(csrf_dep)):
    t = db.q1("SELECT name FROM route_templates WHERE id=?", (tid,))
    db.ex("UPDATE users SET template_id=NULL WHERE template_id=?", (tid,))
    if routing.default_id() == tid:
        db.set_setting("default_template", "")
    db.ex("DELETE FROM route_templates WHERE id=?", (tid,))
    audit(request, "routing.delete", t["name"] if t else str(tid))
    return redirect("/routing", ok="Шаблон удалён")


@r.get("/api/routing/{tid}/preview")
async def api_routing_preview(request: Request, tid: int, sess: dict = Depends(session_dep)):
    """Пример готового конфига: на реальном профиле (?user=ID) или на демо-данных."""
    t = db.q1("SELECT * FROM route_templates WHERE id=?", (tid,))
    if not t:
        return jerr("Не найдено", 404)
    uid = request.query_params.get("user", "")
    u = db.q1("SELECT * FROM users WHERE id=?", (int(uid),)) if uid.isdigit() else None
    if u:
        servers = db.q("SELECT s.* FROM servers s JOIN user_servers us ON us.server_id=s.id WHERE us.user_id=? "
                       "AND s.enabled=1 ORDER BY s.name", (u["id"],))
        text = clients.clash_yaml(u, servers, t)
    else:
        demo_s = {"id": 0, "name": "DEMO", "host": "203.0.113.10", "public_host": "vpn.example.com", "public_port": 0,
                  "sni": "", "insecure": 0, "hop_ports": "", "cfg_info": "{}", "hy2_enabled": 1, "vless_enabled": 0,
                  "anytls_enabled": 0}
        demo_u = {"username": "demo", "password": "demo-password", "uuid": "00000000-0000-0000-0000-000000000000"}
        text = clients.clash_yaml(demo_u, [demo_s], t)
    return jok(text=text)


# ---------------- клиенты (учётные записи личного кабинета) ----------------
LOGIN_RE = re.compile(r"^[a-z0-9][a-z0-9_.@\-]{1,63}$")


def portal_url(request: Request) -> str:
    return f"{public_base(request)}/"


def parse_client_form(form, existing: dict | None) -> tuple[dict, list[int], list[str]]:
    g = lambda k: str(form.get(k) or "").strip()
    errs = []
    d = {"login": g("login").lower(), "name": g("name")[:100], "enabled": 1 if form.get("enabled") else 0,
         "note": g("note")[:1000]}
    if not LOGIN_RE.match(d["login"]):
        errs.append("Логин: 2–64 символа, латиница в нижнем регистре, цифры, . _ - @")
    else:
        other = db.q1("SELECT id FROM clients WHERE login=?", (d["login"],))
        if other and (not existing or other["id"] != existing["id"]):
            errs.append("Такой логин уже существует")
    pw = str(form.get("password") or "")
    if pw:
        if len(pw) < 8 or len(pw) > 128:
            errs.append("Пароль клиента: от 8 до 128 символов")
        else:
            d["pw_hash"] = security.hash_password(pw)
    elif not existing:
        errs.append("Задайте пароль")
    valid = {u["id"] for u in db.q("SELECT id FROM users")}
    uids = sorted({int(x) for x in form.getlist("profiles") if str(x).isdigit() and int(x) in valid})
    return d, uids, errs


def _client_form_ctx(c: dict | None, form: dict, uids: list[int], errors: list[str]) -> dict:
    profiles = db.q("SELECT u.id, u.username, u.note, u.client_id, c.login AS owner FROM users u "
                    "LEFT JOIN clients c ON c.id=u.client_id ORDER BY u.username")
    return dict(nav="clients", c=c, form=form, sel=set(uids), errors=errors, profiles=profiles)


def _set_client_profiles(cid: int, uids: list[int]) -> None:
    if uids:
        db.ex(f"UPDATE users SET client_id=NULL WHERE client_id=? AND id NOT IN ({','.join('?' * len(uids))})",
              (cid, *uids))
    else:
        db.ex("UPDATE users SET client_id=NULL WHERE client_id=?", (cid,))
    for uid in uids:
        db.ex("UPDATE users SET client_id=? WHERE id=?", (cid, uid))


@r.get("/clients", response_class=HTMLResponse)
async def clients_page(request: Request, sess: dict = Depends(session_dep)):
    rows = db.q("SELECT c.*, (SELECT COUNT(*) FROM users u WHERE u.client_id=c.id) AS profiles_count, "
                "(SELECT GROUP_CONCAT(username, ', ') FROM users u WHERE u.client_id=c.id) AS profiles "
                "FROM clients c ORDER BY c.login")
    return render(request, "clients.html", sess, nav="clients", clients=rows, portal=portal_url(request),
                  orphans=db.q1("SELECT COUNT(*) AS n FROM users WHERE client_id IS NULL")["n"])


@r.get("/clients/new", response_class=HTMLResponse)
async def client_new_page(request: Request, sess: dict = Depends(session_dep)):
    return render(request, "client_form.html", sess, portal=portal_url(request),
                  **_client_form_ctx(None, {"enabled": 1, "password": security.gen_password(12)}, [], []))


@r.post("/clients/new")
async def client_new(request: Request, sess: dict = Depends(csrf_dep)):
    form = await request.form()
    d, uids, errs = await run_in_threadpool(parse_client_form, form, None)
    if errs:
        return render(request, "client_form.html", sess, portal=portal_url(request),
                      **_client_form_ctx(None, dict(form), uids, errs))
    cid = db.ex("INSERT INTO clients(login,pw_hash,name,enabled,note,created) VALUES(?,?,?,?,?,?)",
                (d["login"], d["pw_hash"], d["name"], d["enabled"], d["note"], int(time.time())))
    _set_client_profiles(cid, uids)
    audit(request, "client.create", f"{d['login']} профили: {uids}")
    return redirect(f"/clients/{cid}", ok="Клиент создан. Передайте ему адрес кабинета, логин и пароль.")


@r.get("/clients/{cid}", response_class=HTMLResponse)
async def client_page(request: Request, cid: int, sess: dict = Depends(session_dep)):
    c = db.q1("SELECT * FROM clients WHERE id=?", (cid,))
    if not c:
        return redirect("/clients", err="Клиент не найден")
    uids = [u["id"] for u in db.q("SELECT id FROM users WHERE client_id=?", (cid,))]
    sessions = db.q("SELECT * FROM client_sessions WHERE client_id=? AND expires>? ORDER BY created DESC",
                    (cid, int(time.time())))
    return render(request, "client_form.html", sess, portal=portal_url(request), sessions=sessions,
                  **_client_form_ctx(c, c, uids, []))


@r.post("/clients/{cid}/edit")
async def client_edit(request: Request, cid: int, sess: dict = Depends(csrf_dep)):
    c = db.q1("SELECT * FROM clients WHERE id=?", (cid,))
    if not c:
        return redirect("/clients", err="Клиент не найден")
    form = await request.form()
    d, uids, errs = await run_in_threadpool(parse_client_form, form, c)
    if errs:
        return render(request, "client_form.html", sess, portal=portal_url(request), sessions=[],
                      **_client_form_ctx(c, dict(form), uids, errs))
    db.ex(f"UPDATE clients SET {','.join(k + '=?' for k in d)} WHERE id=?", (*d.values(), cid))
    if "pw_hash" in d or not d["enabled"]:
        db.ex("DELETE FROM client_sessions WHERE client_id=?", (cid,))
    _set_client_profiles(cid, uids)
    audit(request, "client.edit", f"{d['login']} профили: {uids}{' пароль изменён' if 'pw_hash' in d else ''}")
    return redirect(f"/clients/{cid}", ok="Сохранено")


@r.post("/clients/{cid}/delete")
async def client_delete(request: Request, cid: int, sess: dict = Depends(csrf_dep)):
    c = db.q1("SELECT login FROM clients WHERE id=?", (cid,))
    db.ex("UPDATE users SET client_id=NULL WHERE client_id=?", (cid,))
    db.ex("DELETE FROM clients WHERE id=?", (cid,))
    audit(request, "client.delete", c["login"] if c else str(cid))
    return redirect("/clients", ok="Клиент удалён (его профили остались, но без владельца)")


@r.post("/clients/{cid}/logout-all")
async def client_logout_all(request: Request, cid: int, sess: dict = Depends(csrf_dep)):
    db.ex("DELETE FROM client_sessions WHERE client_id=?", (cid,))
    audit(request, "client.logout_all", str(cid))
    return redirect(f"/clients/{cid}", ok="Все сессии клиента завершены")


# ---------------- личный кабинет клиента (BASE/) ----------------
class ClientLoginRequired(Exception):
    pass


@app.exception_handler(ClientLoginRequired)
async def _client_login_required(request: Request, exc):
    return RedirectResponse(f"{BASE}/login", status_code=303)


def client_dep(request: Request) -> dict:
    s = security.get_client_session(request.cookies.get(security.CLIENT_COOKIE))
    if not s:
        raise ClientLoginRequired()
    return s


async def client_csrf_dep(request: Request, cs: dict = Depends(client_dep)) -> dict:
    tok = (await request.form()).get("csrf") if "form" in request.headers.get("content-type", "") else None
    if not tok or not hmac.compare_digest(str(tok), cs["csrf"]):
        raise HTTPException(403, "CSRF-токен неверен. Обновите страницу.")
    return cs


def render_portal(request: Request, name: str, cs: dict | None, **ctx):
    ctx.update(sess=None, client=cs, csrf=cs["csrf"] if cs else "",
               ok=(request.query_params.get("ok") or "")[:300], err=(request.query_params.get("err") or "")[:300])
    return page(request, name, ctx)


def _owned_profile(cs: dict, uid: int) -> dict:
    u = db.q1("SELECT * FROM users WHERE id=? AND client_id=?", (uid, cs["client_id"]))
    if not u:
        raise HTTPException(404)
    return u


def _profile_servers(uid: int) -> list[dict]:
    return db.q("SELECT s.* FROM servers s JOIN user_servers us ON us.server_id=s.id "
                "WHERE us.user_id=? AND s.enabled=1 ORDER BY s.name", (uid,))


@pr.get("/lang/{code}", include_in_schema=False)
async def set_language(request: Request, code: str):
    """Переключатель языка: запоминает выбор в cookie и возвращает на исходную страницу."""
    nxt = request.query_params.get("next", "")
    ok = nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt and (not BASE or nxt == BASE or nxt.startswith(BASE + "/"))
    resp = RedirectResponse(nxt if ok else BASE + "/", status_code=303)
    if code in LANGS:
        resp.set_cookie(LANG_COOKIE, code, max_age=365 * 86400, samesite="lax", secure=is_https(request), path=BASE or "/")
    return resp


@pr.get("/i18n.js", include_in_schema=False)
async def i18n_js():
    """Словарь для скриптов интерфейса (подключается только для английского языка)."""
    return Response(js_bundle(), media_type="application/javascript", headers={"Cache-Control": "public, max-age=3600"})


@pr.get("/login", response_class=HTMLResponse)
async def my_login_page(request: Request):
    if security.get_client_session(request.cookies.get(security.CLIENT_COOKIE)):
        return RedirectResponse(BASE + "/", status_code=303)
    return render_portal(request, "my_login.html", None)


@pr.post("/login")
async def my_login(request: Request):
    ip = client_ip(request)
    key = "client:" + ip
    form = await request.form()
    if not security.limiter.allowed(key):
        return render_portal(request, "my_login.html", None, error="Слишком много попыток. Подождите 15 минут.")
    login, password = str(form.get("login", ""))[:64], str(form.get("password", ""))[:256]
    c = await run_in_threadpool(security.authenticate_client, login, password)
    if not c:
        security.limiter.fail(key)
        db.audit("client.login.fail", login, ip)
        return render_portal(request, "my_login.html", None, error="Неверный логин или пароль")
    security.limiter.reset(key)
    token = security.create_client_session(c["id"], ip, request.headers.get("user-agent", ""))
    db.audit("client.login.ok", c["login"], ip)
    resp = RedirectResponse(BASE + "/", status_code=303)
    resp.set_cookie(security.CLIENT_COOKIE, token, max_age=security.CLIENT_SESSION_HOURS * 3600, httponly=True,
                    samesite="lax", secure=is_https(request), path=BASE or "/")
    return resp


@pr.post("/logout")
async def my_logout(request: Request, cs: dict = Depends(client_csrf_dep)):
    security.delete_client_session(request.cookies.get(security.CLIENT_COOKIE))
    resp = RedirectResponse(BASE + "/login", status_code=303)
    resp.delete_cookie(security.CLIENT_COOKIE, path=BASE or "/")
    return resp


@pr.get("/", response_class=HTMLResponse)
async def my_home(request: Request, cs: dict = Depends(client_dep)):
    profiles = db.q("SELECT * FROM users WHERE client_id=? ORDER BY username", (cs["client_id"],))
    pb = public_base(request)
    for u in profiles:
        u["state"] = user_state(u)
        u["conns"] = []
        if u["state"][0] == "on":
            for s in _profile_servers(u["id"]):
                s["links"] = clients.links(u, s)
                u["conns"].append(s)
            u["sub_url"] = f"{pb}/sub/{u['sub_token']}"
            u["sub_qr"] = clients.qr_svg(u["sub_url"])
    return render_portal(request, "my.html", cs, profiles=profiles)


@pr.get("/qr/{uid}/{sid}.png")
async def my_qr(request: Request, uid: int, sid: int, cs: dict = Depends(client_dep)):
    u = _owned_profile(cs, uid)
    s = next((x for x in _profile_servers(uid) if x["id"] == sid), None)
    if not s:
        raise HTTPException(404)
    return Response(clients.qr_png(clients.uri(u, s, _proto_arg(request, s))), media_type="image/png")


@pr.get("/hysteria/{uid}/{sid}.yaml")
async def my_hy_yaml(uid: int, sid: int, cs: dict = Depends(client_dep)):
    u = _owned_profile(cs, uid)
    s = next((x for x in _profile_servers(uid) if x["id"] == sid), None)
    if not s or "hy2" not in clients.protos(s):
        raise HTTPException(404)
    fn = _safe_fn(clients.profile_name(u, s)) + ".yaml"
    return PlainTextResponse(clients.hysteria_yaml(u, s), media_type="application/x-yaml",
                             headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@pr.get("/clash/{uid}.yaml")
async def my_clash(uid: int, cs: dict = Depends(client_dep)):
    u = _owned_profile(cs, uid)
    return PlainTextResponse(clients.clash_yaml(u, _profile_servers(uid), routing.template_for(u)), media_type="application/x-yaml",
                             headers={"Content-Disposition": f'attachment; filename="clash-{_safe_fn(u["username"])}.yaml"'})


@pr.post("/password")
async def my_password(request: Request, cs: dict = Depends(client_csrf_dep)):
    form = await request.form()
    cur, new, new2 = (str(form.get(k) or "") for k in ("current", "new", "new2"))
    c = db.q1("SELECT * FROM clients WHERE id=?", (cs["client_id"],))
    if not await run_in_threadpool(security.verify_password, cur, c["pw_hash"]):
        return RedirectResponse(BASE + "/?err=" + quote(tr("Текущий пароль неверен")), status_code=303)
    if len(new) < 8 or new != new2:
        return RedirectResponse(BASE + "/?err=" + quote(tr("Новый пароль: от 8 символов, оба поля должны совпадать")),
                                status_code=303)
    db.ex("UPDATE clients SET pw_hash=? WHERE id=?", (await run_in_threadpool(security.hash_password, new), c["id"]))
    db.ex("DELETE FROM client_sessions WHERE client_id=? AND token_hash<>?", (c["id"], cs["token_hash"]))
    db.audit("client.password", c["login"], client_ip(request))
    return RedirectResponse(BASE + "/?ok=" + quote(tr("Пароль изменён")), status_code=303)


app.include_router(r)
app.include_router(pr)
app.mount(BASE + "/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

if BASE:
    @app.get(BASE, include_in_schema=False)
    async def _base_redirect():
        return RedirectResponse(BASE + "/", status_code=308)


@app.get(ABASE, include_in_schema=False)
async def _admin_redirect():
    return RedirectResponse(ABASE + "/", status_code=308)


# ---- прежние адреса: подписки продолжают работать, остальное — перенаправление на новые адреса ----
def _legacy_target(path: str) -> str | None:
    if path.startswith("static/"):
        return f"{BASE}/{path}"
    if path == "my" or path.startswith("my/"):          # старый кабинет клиента /<legacy>/my/...
        return f"{BASE}/{path[3:].lstrip('/')}"
    # админка: перенаправляем только если это явно разрешено (иначе адрес админки раскрылся бы любому)
    return f"{ABASE}/{path}" if LEGACY_ADMIN_REDIRECT else None


for _lb in LEGACY_BASES:
    app.add_api_route(_lb + "/sub/{token}", sub, methods=["GET"], include_in_schema=False)
    app.add_api_route(_lb + "/sub/{token}/clash", sub_clash, methods=["GET"], include_in_schema=False)

    async def _legacy_redirect(request: Request, path: str = ""):
        target = _legacy_target(path)
        if target is None:
            return not_found()
        q = ("?" + request.url.query) if request.url.query else ""
        return RedirectResponse(target + q, status_code=307)

    app.add_api_route(_lb + "/{path:path}", _legacy_redirect, methods=["GET"], include_in_schema=False)
    app.add_api_route(_lb, _legacy_redirect, methods=["GET"], include_in_schema=False)
