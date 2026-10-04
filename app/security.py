"""Пароли администраторов, сессии, CSRF, шифрование секретов, ограничение попыток входа."""
import hashlib
import hmac
import os
import secrets
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

from . import db
from .config import DATA_DIR, SESSION_HOURS

COOKIE = "hy2panel_session"

# ---------- пароли ----------
_N, _R, _P = 2 ** 15, 8, 1


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=len(h) // 2)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


_DUMMY = hash_password(secrets.token_hex(8))


def authenticate(username: str, password: str) -> dict | None:
    a = db.q1("SELECT * FROM admins WHERE username=?", (username.strip(),))
    if not a:
        verify_password(password, _DUMMY)  # выравниваем время ответа
        return None
    return a if verify_password(password, a["pw_hash"]) else None


# ---------- сессии ----------
def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(admin_id: int, ip: str, ua: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.ex("DELETE FROM sessions WHERE expires<?", (now,))
    db.ex("INSERT INTO sessions(token_hash,admin_id,csrf,ip,ua,created,expires) VALUES(?,?,?,?,?,?,?)",
          (_th(token), admin_id, secrets.token_urlsafe(24), ip, ua[:300], now, now + SESSION_HOURS * 3600))
    return token


def get_session(token: str | None) -> dict | None:
    if not token or len(token) > 200:
        return None
    s = db.q1("SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?",
              (_th(token),))
    if not s or s["expires"] < time.time():
        return None
    s["token_hash"] = _th(token)
    return s


def delete_session(token: str | None) -> None:
    if token:
        db.ex("DELETE FROM sessions WHERE token_hash=?", (_th(token),))


# ---------- сессии личного кабинета клиентов ----------
CLIENT_COOKIE = "hy2panel_client"
CLIENT_SESSION_HOURS = 24 * 7


def authenticate_client(login: str, password: str) -> dict | None:
    c = db.q1("SELECT * FROM clients WHERE login=?", (login.strip().lower(),))
    if not c:
        verify_password(password, _DUMMY)
        return None
    if not verify_password(password, c["pw_hash"]) or not c["enabled"]:
        return None
    return c


def create_client_session(client_id: int, ip: str, ua: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.ex("DELETE FROM client_sessions WHERE expires<?", (now,))
    db.ex("INSERT INTO client_sessions(token_hash,client_id,csrf,ip,ua,created,expires) VALUES(?,?,?,?,?,?,?)",
          (_th(token), client_id, secrets.token_urlsafe(24), ip, ua[:300], now, now + CLIENT_SESSION_HOURS * 3600))
    db.ex("UPDATE clients SET last_login=? WHERE id=?", (now, client_id))
    return token


def get_client_session(token: str | None) -> dict | None:
    if not token or len(token) > 200:
        return None
    s = db.q1("SELECT s.*, c.login, c.name, c.enabled FROM client_sessions s JOIN clients c ON c.id=s.client_id "
              "WHERE s.token_hash=?", (_th(token),))
    if not s or s["expires"] < time.time() or not s["enabled"]:
        return None
    s["token_hash"] = _th(token)
    return s


def delete_client_session(token: str | None) -> None:
    if token:
        db.ex("DELETE FROM client_sessions WHERE token_hash=?", (_th(token),))


# ---------- шифрование секретов (пароли SSH, ключи) ----------
_KEY_FILE = DATA_DIR / "secret.key"
_fernet: Fernet | None = None


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        if not _KEY_FILE.exists():
            _KEY_FILE.write_bytes(Fernet.generate_key())
            try:
                os.chmod(_KEY_FILE, 0o600)
            except OSError:
                pass
        _fernet = Fernet(_KEY_FILE.read_bytes().strip())
    return _fernet


def encrypt(s: str) -> str:
    return _f().encrypt(s.encode()).decode() if s else ""


def decrypt(s: str) -> str:
    if not s:
        return ""
    try:
        return _f().decrypt(s.encode()).decode()
    except InvalidToken:
        raise RuntimeError("Не удалось расшифровать секрет (сменился data/secret.key?)")


# ---------- защита от перебора ----------
class LoginLimiter:
    WINDOW = 15 * 60
    MAX_FAILS = 8

    def __init__(self):
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, ip: str) -> list[float]:
        now = time.time()
        lst = [t for t in self._fails.get(ip, []) if now - t < self.WINDOW]
        self._fails[ip] = lst
        return lst

    def allowed(self, ip: str) -> bool:
        with self._lock:
            return len(self._recent(ip)) < self.MAX_FAILS

    def fail(self, ip: str) -> None:
        with self._lock:
            self._recent(ip).append(time.time())

    def reset(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)


limiter = LoginLimiter()


def gen_password(n: int = 20) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))
