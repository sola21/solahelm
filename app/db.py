"""SQLite-хранилище панели (одно соединение на поток, режим WAL)."""
import sqlite3
import threading
import time

from .config import DATA_DIR

DB_PATH = DATA_DIR / "panel.db"
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL,
    created INTEGER
);
CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    ip TEXT, ua TEXT,
    created INTEGER, expires INTEGER
);
CREATE TABLE IF NOT EXISTS servers(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    ssh_port INTEGER DEFAULT 22,
    ssh_user TEXT DEFAULT 'root',
    ssh_auth TEXT DEFAULT 'panelkey',      -- panelkey | password | key
    ssh_secret TEXT DEFAULT '',            -- зашифрованный пароль или passphrase ключа
    ssh_key TEXT DEFAULT '',               -- зашифрованный приватный ключ
    host_key TEXT DEFAULT '',              -- "<type> <base64>" (TOFU)
    config_path TEXT DEFAULT '/etc/hysteria/config.yaml',
    service TEXT DEFAULT 'hysteria-server.service',
    public_host TEXT DEFAULT '',
    public_port INTEGER DEFAULT 0,
    sni TEXT DEFAULT '',
    insecure INTEGER DEFAULT 0,
    hop_ports TEXT DEFAULT '',
    manage_stats INTEGER DEFAULT 1,
    stats_port INTEGER DEFAULT 25413,
    stats_secret TEXT DEFAULT '',
    cfg_info TEXT DEFAULT '{}',
    status TEXT DEFAULT '{}',
    last_check INTEGER DEFAULT 0,
    dirty INTEGER DEFAULT 0,
    last_sync INTEGER DEFAULT 0,
    sync_error TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    notes TEXT DEFAULT '',
    created INTEGER
);
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    active INTEGER DEFAULT 1,              -- эффективное состояние (с учётом срока и лимита)
    expires_at INTEGER DEFAULT 0,
    traffic_limit INTEGER DEFAULT 0,
    tx INTEGER DEFAULT 0,
    rx INTEGER DEFAULT 0,
    sub_token TEXT UNIQUE,
    note TEXT DEFAULT '',
    created INTEGER,
    last_online INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS user_servers(
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tx INTEGER DEFAULT 0,
    rx INTEGER DEFAULT 0,
    online INTEGER DEFAULT 0,
    last_online INTEGER DEFAULT 0,
    PRIMARY KEY(user_id, server_id)
);
CREATE TABLE IF NOT EXISTS traffic_daily(
    day TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tx INTEGER DEFAULT 0,
    rx INTEGER DEFAULT 0,
    PRIMARY KEY(day, user_id, server_id)
);
CREATE TABLE IF NOT EXISTS jobs(
    id INTEGER PRIMARY KEY,
    kind TEXT, server_id INTEGER, status TEXT,
    log TEXT DEFAULT '',
    created INTEGER, finished INTEGER
);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY,
    ts INTEGER, ip TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
-- клиенты: учётные записи личного кабинета, владеют одним или несколькими профилями (users.client_id)
CREATE TABLE IF NOT EXISTS clients(
    id INTEGER PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL,
    name TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    note TEXT DEFAULT '',
    created INTEGER,
    last_login INTEGER DEFAULT 0
);
-- шаблоны Clash/mihomo: DNS, TUN, наборы правил и правила маршрутизации (без proxies; группы ссылаются на "@proxies")
CREATE TABLE IF NOT EXISTS route_templates(
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    yaml TEXT NOT NULL,
    created INTEGER, updated INTEGER
);
-- история проверок серверов: график доступности
CREATE TABLE IF NOT EXISTS checks(
    id INTEGER PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    ms INTEGER DEFAULT 0,
    err TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS checks_srv_ts ON checks(server_id, ts);
CREATE TABLE IF NOT EXISTS client_sessions(
    token_hash TEXT PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    ip TEXT, ua TEXT,
    created INTEGER, expires INTEGER
);
"""


SERVER_COLS = {
    "hy2_enabled": "INTEGER DEFAULT 1",           # Hysteria2 установлена на сервере
    "sb_service": "TEXT DEFAULT 'sing-box.service'",
    "sb_config_path": "TEXT DEFAULT '/etc/sing-box/config.json'",
    "vless_enabled": "INTEGER DEFAULT 0",
    "vless_port": "INTEGER DEFAULT 8443",
    "reality_sni": "TEXT DEFAULT 'www.microsoft.com'",
    "reality_priv": "TEXT DEFAULT ''",             # зашифрован
    "reality_pub": "TEXT DEFAULT ''",
    "reality_sid": "TEXT DEFAULT ''",
    "anytls_enabled": "INTEGER DEFAULT 0",
    "anytls_port": "INTEGER DEFAULT 9443",
    "anytls_domain": "TEXT DEFAULT ''",
    "anytls_cert": "TEXT DEFAULT 'hysteria'",      # hysteria | selfsigned
    "anytls_insecure": "INTEGER DEFAULT 0",
    "auto_assign": "INTEGER DEFAULT 0",           # предлагать сервер новым профилям по умолчанию
}


def _migrate() -> None:
    cols = {r["name"] for r in q("PRAGMA table_info(users)")}
    if "client_id" not in cols:
        ex("ALTER TABLE users ADD COLUMN client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL")
    if "template_id" not in cols:
        ex("ALTER TABLE users ADD COLUMN template_id INTEGER")   # NULL = шаблон по умолчанию
    if "uuid" not in cols:
        ex("ALTER TABLE users ADD COLUMN uuid TEXT")
    import uuid as _uuid
    for r in q("SELECT id FROM users WHERE uuid IS NULL OR uuid=''"):
        ex("UPDATE users SET uuid=? WHERE id=?", (str(_uuid.uuid4()), r["id"]))
    ex("CREATE UNIQUE INDEX IF NOT EXISTS users_uuid ON users(uuid)")
    scols = {r["name"] for r in q("PRAGMA table_info(servers)")}
    for name, decl in SERVER_COLS.items():
        if name not in scols:
            ex(f"ALTER TABLE servers ADD COLUMN {name} {decl}")
    if "auto_assign" not in scols:
        ex("UPDATE servers SET auto_assign=1")   # прежнее поведение сохраняется для уже добавленных серверов


def conn() -> sqlite3.Connection:
    c = getattr(_local, "c", None)
    if c is None:
        c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=30000")
        _local.c = c
    return c


def q(sql: str, args=()) -> list[dict]:
    return [dict(r) for r in conn().execute(sql, args).fetchall()]


def q1(sql: str, args=()) -> dict | None:
    r = conn().execute(sql, args).fetchone()
    return dict(r) if r else None


def ex(sql: str, args=()) -> int:
    return conn().execute(sql, args).lastrowid


def init() -> None:
    conn().executescript(SCHEMA)
    _migrate()
    ex("UPDATE jobs SET status='interrupted', finished=? WHERE status='running'", (int(time.time()),))


def get_setting(key: str, default=None):
    r = q1("SELECT v FROM settings WHERE k=?", (key,))
    return r["v"] if r else default


def set_setting(key: str, value) -> None:
    ex("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, str(value)))


def audit(action: str, detail: str = "", ip: str = "") -> None:
    ex("INSERT INTO audit(ts,ip,action,detail) VALUES(?,?,?,?)", (int(time.time()), ip, action, detail[:2000]))
