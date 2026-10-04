"""Извлечение русских строк интерфейса (шаблоны, Python, JS) — «фраз», которые нужно перевести.

Фраза — непрерывный кусок русского текста без вставок: шаблонные теги {{ }}/{% %} и f-string подстановки делят текст на фразы.
Перевод хранится в app/i18n/en.py: {"русская фраза": "english phrase"}.

Запуск:
    python scripts/i18n_extract.py            # сводка и список непереведённых фраз
    python scripts/i18n_extract.py --all      # все найденные фразы
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CYR = re.compile(r"[А-Яа-яЁё]")
MARK = "\x00"
# единицы измерения и «давность» форматируются кодом сразу на нужном языке (main.py: fmt_bytes / fmt_dur / fmt_ago)
IGNORE = {"д", "ч", "мин", "Б", "КБ", "МБ", "ГБ", "ТБ", "только что", "назад"}
ECHO_MSG = re.compile(r"""\becho\s+(?:-\w+\s+)?(["'])(.*?)\1""")
TRANSLATABLE_ATTRS = ("placeholder", "title", "data-confirm", "data-confirm-btn", "data-title", "aria-label", "alt", "value")


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _chunks(text: str) -> list[str]:
    out = []
    for part in text.split(MARK):
        part = norm(part)
        if part and CYR.search(part):
            out.append(part)
    return out


def from_template(src: str) -> list[str]:
    found: list[str] = []
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    # русские литералы внутри {{ }} и {% %} попадают в вывод — берём их отдельно
    for tag in re.findall(r"\{\{.*?\}\}|\{%.*?%\}", src, flags=re.S):
        for lit in re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'|\"([^\"\\]*(?:\\.[^\"\\]*)*)\"", tag):
            s = lit[0] or lit[1]
            if CYR.search(s):
                found.append(norm(s))
    text = re.sub(r"\{\{.*?\}\}|\{%.*?%\}", MARK, src, flags=re.S)
    # теги: из атрибутов берём переводимые, из остального — текстовые узлы
    pos = 0
    for m in re.finditer(r"<(script|style|pre|textarea)\b.*?</\1>|<[^>]*>", text, flags=re.S | re.I):
        found.extend(_chunks(text[pos:m.start()]))
        tag = m.group(0)
        if not re.match(r"<(script|style|pre|textarea)\b", tag, re.I):
            for attr, val in re.findall(r'([\w-]+)="([^"]*)"', tag):
                if attr in TRANSLATABLE_ATTRS:
                    found.extend(_chunks(val))
        pos = m.end()
    found.extend(_chunks(text[pos:]))
    return found


def from_python(src: str) -> list[str]:
    found: list[str] = []
    tree = ast.parse(src)
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
                skip.add(id(body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    skip.add(id(v))
                    if CYR.search(v.value):
                        found.append(norm(v.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip and CYR.search(node.value):
            # многострочные «скрипты» (shell) делим по строкам: переводится каждая строка отдельно
            for line in node.value.split("\n"):
                line = line.strip()
                if line.startswith("#"):                 # комментарии shell-скриптов не показываются
                    continue
                m = ECHO_MSG.search(line)                # echo "текст" >&2 → в логе виден только текст
                if m:
                    line = m.group(2)
                line = norm(line)
                if line and CYR.search(line):
                    found.append(line)
    return found


def from_js(src: str) -> list[str]:
    found = []
    for lit in re.findall(r"\"((?:[^\"\\\n]|\\.)*)\"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`", src):
        s = next((x for x in lit if x), "")
        if CYR.search(s):
            for part in re.split(r"\$\{[^}]*\}", s):
                part = norm(part)
                if part and CYR.search(part):
                    found.append(part)
    return found


def collect() -> dict[str, set[str]]:
    """{фраза: {файлы}}"""
    res: dict[str, set[str]] = {}
    def add(items, f):
        for it in items:
            res.setdefault(it, set()).add(f)
    for p in sorted((ROOT / "app" / "templates").glob("*.html")):
        add(from_template(p.read_text(encoding="utf-8")), f"templates/{p.name}")
    for p in sorted((ROOT / "app").glob("*.py")):
        if p.name in ("i18n.py", "i18n_en.py", "db.py"):     # db.py — комментарии SQL, не интерфейс
            continue
        add(from_python(p.read_text(encoding="utf-8")), p.name)
    js = ROOT / "app" / "static" / "app.js"
    add(from_js(js.read_text(encoding="utf-8")), "static/app.js")
    for k in IGNORE:
        res.pop(k, None)
    return res


def load_en() -> dict[str, str]:
    sys.path.insert(0, str(ROOT))
    try:
        from app.i18n_en import EN
        return EN
    except Exception:
        return {}


if __name__ == "__main__":
    phrases = collect()
    en = load_en()
    missing = {k: v for k, v in phrases.items() if k not in en}
    print(f"всего фраз: {len(phrases)}, переведено: {len(phrases) - len(missing)}, не хватает: {len(missing)}")
    shown = phrases if "--all" in sys.argv else missing
    for k in sorted(shown):
        print(f"{'/'.join(sorted(shown[k]))[:28]:28} | {k}")
    unused = [k for k in en if k not in phrases]
    if unused and "--all" not in sys.argv:
        print(f"\nлишних (в словаре, но нет в коде): {len(unused)}")
