"""Настройки панели. Читаются из переменных окружения или файла .env в корне проекта."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent


def _load_env_file() -> None:
    p = ROOT / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env_file()


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _path(v: str) -> str:
    v = v.strip().strip("/")
    return f"/{v}" if v else ""


# Публичный адрес: кабинет клиентов (BASE/), подписки (BASE/sub/...), статика. Например "/hy". Пусто = корень.
BASE_PATH = _path(_env("HY_BASE_PATH", ""))
# Админка живёт внутри публичного префикса: BASE/admin/. Меняется через HY_ADMIN_PATH (по умолчанию "admin").
ADMIN_BASE = BASE_PATH + (_path(_env("HY_ADMIN_PATH", "admin")) or "/admin")
# Прежние префиксы (через запятую), например "/hy-admin": подписки по старым ссылкам продолжают работать,
# остальные страницы перенаправляются на новые адреса.
LEGACY_BASES = [p for p in (_path(x) for x in _env("HY_LEGACY_BASE", "").split(","))
                if p and p != BASE_PATH and p != ADMIN_BASE]

HOST = _env("HY_HOST", "127.0.0.1")
PORT = int(_env("HY_PORT", "8088"))
DATA_DIR = Path(_env("HY_DATA_DIR", str(ROOT / "data"))).resolve()
# Адреса reverse-proxy (nginx), которым доверяем заголовки X-Real-IP / X-Forwarded-*
TRUSTED_PROXIES = {x.strip() for x in _env("HY_TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if x.strip()}
POLL_INTERVAL = int(_env("HY_POLL_INTERVAL", "60"))
# Внешний адрес панели для ссылок подписки, например https://panel.example.com/hy
PUBLIC_URL = _env("HY_PUBLIC_URL", "").rstrip("/")
SESSION_HOURS = int(_env("HY_SESSION_HOURS", "12"))
COOKIE_SECURE = _env("HY_COOKIE_SECURE", "auto").lower()  # auto | 1 | 0

# Название продукта в интерфейсе (заголовки, шапка, подвал). Технические имена (служба, каталоги) от него не зависят.
BRAND = _env("HY_BRAND", "").strip() or "SolaHelm"
# Язык интерфейса по умолчанию: ru | en | auto (по заголовку Accept-Language браузера). Выбор пользователя хранится в cookie.
DEFAULT_LANG = _env("HY_DEFAULT_LANG", "ru").strip().lower()
if DEFAULT_LANG not in ("ru", "en", "auto"):
    DEFAULT_LANG = "ru"
# Старые префиксы (HY_LEGACY_BASE): перенаправлять ли их страницы админки на новый адрес админки.
# По умолчанию НЕТ: адрес админки не должен раскрываться тому, кто обратился по старому пути.
LEGACY_ADMIN_REDIRECT = _env("HY_LEGACY_ADMIN_REDIRECT", "0").strip().lower() in ("1", "true", "yes")

DATA_DIR.mkdir(parents=True, exist_ok=True)
