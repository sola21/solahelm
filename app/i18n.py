"""Локализация интерфейса. Исходный язык — русский, перевод — английский.

Как это устроено: тексты в шаблонах и коде остаются русскими. Для английского языка готовый HTML (и сообщения API)
проходит через словарь app/i18n_en.py: {"русская фраза": "english phrase"}. Фраза — непрерывный кусок текста без
вставок (динамические значения остаются между переведёнными кусками). Что не найдено в словаре — остаётся русским.

Список фраз и проверка полноты словаря: python scripts/i18n_extract.py
"""
import contextvars
import json
import re
from pathlib import Path

from .config import APP_DIR, DEFAULT_LANG
from .i18n_en import EN

LANGS = ("ru", "en")
LANG_COOKIE = "hy2panel_lang"
_lang: contextvars.ContextVar[str] = contextvars.ContextVar("hy2panel_lang", default="ru")

_CYR = "А-Яа-яЁё"
_WORD = re.compile(f"[{_CYR}]+")
_HAS_CYR = re.compile(f"[{_CYR}]")
# языки, для которых по умолчанию (режим auto) показывается русский; остальным — английский
RU_FAMILY = {"ru", "uk", "be", "kk", "ky", "uz", "tg", "hy", "az", "ka", "tt", "ba"}


def get_lang() -> str:
    return _lang.get()


def set_lang(code: str):
    return _lang.set(code if code in LANGS else "ru")


def reset_lang(token) -> None:
    _lang.reset(token)


def detect_lang(request) -> str:
    """Язык запроса: cookie (выбор пользователя) → HY_DEFAULT_LANG → (auto) Accept-Language."""
    c = request.cookies.get(LANG_COOKIE)
    if c in LANGS:
        return c
    if DEFAULT_LANG in LANGS:
        return DEFAULT_LANG
    first = request.headers.get("accept-language", "").split(",")[0].strip().lower()[:2]
    return "ru" if first in RU_FAMILY or not first else "en"


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _build_index() -> dict[str, list]:
    """Индекс: первое русское слово фразы → [(префикс, регулярка всей фразы, перевод, длина)] от длинных к коротким."""
    index: dict[str, list] = {}
    for key, en in EN.items():
        k = _norm(key)
        m = _WORD.search(k)
        if not m:
            continue
        body = r"\s+".join(re.escape(tok) for tok in k.split(" "))
        end = f"(?![{_CYR}])" if _HAS_CYR.match(k[-1]) else ""
        prefix = k[:m.start()]
        # префикс (знаки перед первым русским словом) ищем с гибкими пробелами: между точкой и словом может быть перенос строки
        pre_rx = re.compile(r"\s+".join(re.escape(tok) for tok in prefix.split(" ")) + "$") if prefix else None
        index.setdefault(m.group(), []).append((len(prefix), pre_rx, re.compile(body + end), en, len(k)))
    for v in index.values():
        v.sort(key=lambda x: -x[4])
    return index


_INDEX = _build_index()


def translate(text: str) -> str:
    """Заменить известные русские фразы на английские (в любом языке интерфейса — без проверки текущего)."""
    if not text or not _HAS_CYR.search(text):
        return text
    found = []
    for m in _WORD.finditer(text):
        cands = _INDEX.get(m.group())
        if not cands:
            continue
        p = m.start()
        for plen, pre_rx, rx, en, _ in cands:
            s = p
            if pre_rx is not None:
                lo = max(0, p - plen - 64)
                pm = pre_rx.search(text, lo, p)
                if not pm:
                    continue
                s = pm.start()
            mm = rx.match(text, s)
            if mm:
                found.append((s, mm.end(), en))
                break
    if not found:
        return text
    found.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    out, last = [], 0
    for s, e, en in found:
        if s < last:
            continue
        out.append(text[last:s])
        out.append(en)
        last = e
    out.append(text[last:])
    return "".join(out)


def tr(text):
    """Перевести строку, если интерфейс сейчас английский (иначе вернуть как есть)."""
    if not isinstance(text, str) or _lang.get() == "ru":
        return text
    return translate(text)


# ---------- HTML ----------
_TOKEN = re.compile(r"<(script|style|textarea)\b.*?</\1\s*>|<!--.*?-->|<[^>]+>|[^<]+", re.S | re.I)
_ATTR = re.compile(r'\b(placeholder|title|data-confirm|data-confirm-btn|data-title|aria-label|alt)="([^"]*)"')


def tr_html(page: str) -> str:
    """Перевести готовую страницу: текстовые узлы и переводимые атрибуты (script / style / textarea не трогаем)."""
    if _lang.get() == "ru" or not _HAS_CYR.search(page):
        return page
    out = []
    for m in _TOKEN.finditer(page):
        tok = m.group(0)
        if tok.startswith("<"):
            if m.group(1) or tok.startswith("<!--"):
                out.append(tok)
            else:
                out.append(_ATTR.sub(lambda a: f'{a.group(1)}="{translate(a.group(2))}"', tok))
        else:
            out.append(translate(tok))
    return "".join(out)


# ---------- JS ----------
def js_dictionary() -> dict[str, str]:
    """Фразы из app.js, которым есть перевод (для window.I18N_EN)."""
    src = (APP_DIR / "static" / "app.js").read_text(encoding="utf-8")
    keys = set()
    for lit in re.findall(r"\"((?:[^\"\\\n]|\\.)*)\"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`", src):
        s = next((x for x in lit if x), "")
        for part in re.split(r"\$\{[^}]*\}", s):
            part = _norm(part)
            if part and _HAS_CYR.search(part):
                keys.add(part)
    norm_en = {_norm(k): v for k, v in EN.items()}
    return {k: norm_en[k] for k in sorted(keys) if k in norm_en}


def js_bundle() -> str:
    return "window.I18N_EN = " + json.dumps(js_dictionary(), ensure_ascii=False) + ";\n"
