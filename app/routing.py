"""Шаблоны маршрутизации для Clash Meta / mihomo.

Шаблон — обычный клиентский YAML (DNS, TUN, sniffer, rule-providers, rules, proxy-groups) без секции proxies.
В группах вместо серверов стоит "@proxies": при выдаче конфига панель заменяет его на серверы и протоколы профиля.
"""
import io
import json
import re
import time

from ruamel.yaml import YAML

from . import db
from .config import APP_DIR

PROXIES_TOKEN = "@proxies"
BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
PRESETS = [("Весь трафик через VPN", "all-vpn.yaml"), ("РФ напрямую, остальное через VPN", "ru-direct.yaml")]
# github.com/<u>/<r>/blob/<ref>/<path> отдаёт HTML-страницу, а не файл
BLOB_RE = re.compile(r"^(https://github\.com/[^/]+/[^/]+)/blob/(.+)$")
MAX_SIZE = 300_000


class TemplateError(ValueError):
    pass


def _yaml() -> YAML:
    y = YAML()
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    y.allow_unicode = True
    return y


def _load(text: str):
    if len(text) > MAX_SIZE:
        raise TemplateError("Файл слишком большой")
    try:
        data = _yaml().load(text)
    except Exception as e:
        raise TemplateError(f"Ошибка YAML: {str(e).splitlines()[0] if str(e) else e}")
    if not isinstance(data, dict):
        raise TemplateError("Корень YAML должен быть словарём (mapping) с ключами вроде rules, dns, rule-providers")
    return data


def _dump(data) -> str:
    buf = io.StringIO()
    _yaml().dump(data, buf)
    return buf.getvalue()


def _rule_target(rule) -> str | None:
    """Группа/действие, на которое указывает правило (для MATCH — второе поле, для остальных — третье)."""
    if not isinstance(rule, str) or rule.startswith(("AND", "OR", "NOT", "SUB-RULE")):
        return None
    parts = [p.strip() for p in rule.split(",")]
    if parts[0] == "MATCH":
        return parts[1] if len(parts) > 1 else None
    return parts[2] if len(parts) > 2 else None


def convert(text: str) -> tuple[str, list[str]]:
    """Привести YAML пользователя к шаблону: убрать proxies (их имена в группах заменить на "@proxies"),
    исправить ссылки github blob → raw. Возвращает (текст шаблона, замечания)."""
    data = _load(text)
    notes: list[str] = []
    names = {str(p.get("name")) for p in (data.get("proxies") or []) if isinstance(p, dict)}
    if "proxies" in data:
        del data["proxies"]
        notes.append(f"Секция proxies удалена ({len(names)} шт.): панель подставляет собственные серверы.")
    for g in data.get("proxy-groups") or []:
        lst = g.get("proxies") if isinstance(g, dict) else None
        if not isinstance(lst, list):
            continue
        new, replaced = [], False
        for item in lst:
            if item in names or item == PROXIES_TOKEN:
                if not replaced:
                    new.append(PROXIES_TOKEN)
                    replaced = True
            elif item not in new:
                new.append(item)
        g["proxies"] = new
    fixed = 0
    for rp in (data.get("rule-providers") or {}).values():
        url = rp.get("url") if isinstance(rp, dict) else None
        m = BLOB_RE.match(url) if isinstance(url, str) else None
        if m:
            rp["url"] = f"{m.group(1)}/raw/{m.group(2)}"
            fixed += 1
    if fixed:
        notes.append(f"Исправлено ссылок github.com/…/blob/… → …/raw/… : {fixed} (по blob отдаётся HTML, а не список правил).")
    return _dump(data), notes


def analyze(text: str) -> dict:
    """Сводка и замечания для шаблона; бросает TemplateError, если шаблон непригоден."""
    data = _load(text)
    rules = data.get("rules") or []
    providers = data.get("rule-providers") or {}
    groups = data.get("proxy-groups") or []
    notes: list[str] = []
    if not rules:
        notes.append("Нет секции rules — клиент будет пускать весь трафик по правилам по умолчанию.")
    if "proxies" in data:
        notes.append("Секция proxies будет проигнорирована: панель подставляет свои серверы.")
    group_names = {g.get("name") for g in groups if isinstance(g, dict)}
    used = {t for t in (_rule_target(r) for r in rules) if t and t not in BUILTIN_TARGETS}
    missing = sorted(used - group_names)
    if missing and groups:
        notes.append("Правила ссылаются на несуществующие группы: " + ", ".join(missing))
    provider_names = set(providers)
    for r in rules:
        if isinstance(r, str) and r.startswith("RULE-SET,"):
            p = r.split(",")[1]
            if p not in provider_names:
                notes.append(f"Правило использует набор «{p}», которого нет в rule-providers")
                break
    if groups and not any(isinstance(g, dict) and PROXIES_TOKEN in (g.get("proxies") or []) for g in groups):
        notes.append('Ни одна группа не содержит "@proxies" — серверы профиля не попадут ни в одну группу.')
    render(text, [{"name": "demo", "type": "ss"}])  # пробный рендер
    return {"rules": len(rules), "providers": len(providers), "groups": len(groups), "notes": notes,
            "dns": "dns" in data, "tun": bool((data.get("tun") or {}).get("enable"))}


def render(text: str, proxies: list[dict]) -> dict:
    """Собрать клиентский конфиг: шаблон + прокси профиля."""
    tpl = _load(text)
    names = [p["name"] for p in proxies]
    groups_src = tpl.get("proxy-groups")
    groups: list[dict] = []
    if groups_src:
        for g in groups_src:
            g2 = dict(g)
            lst = g.get("proxies")
            if isinstance(lst, list):
                new: list = []
                for item in lst:
                    for x in (names if item == PROXIES_TOKEN else [item]):
                        if x not in new:
                            new.append(x)
                g2["proxies"] = new or ["DIRECT"]
            groups.append(g2)
    else:
        # в шаблоне нет групп: создаём одну, с именем, которое использует MATCH/правила
        targets = [t for t in (_rule_target(r) for r in reversed(tpl.get("rules") or [])) if t]
        custom = [t for t in targets if t not in BUILTIN_TARGETS]
        groups.append({"name": custom[0] if custom else "PROXY", "type": "select", "proxies": names + ["DIRECT"]})
    out: dict = {}
    for k, v in tpl.items():
        if k in ("proxies", "proxy-groups"):
            continue
        if k in ("rule-providers", "rules") and "proxies" not in out:
            out["proxies"], out["proxy-groups"] = proxies, groups
        out[k] = v
    if "proxies" not in out:
        out["proxies"], out["proxy-groups"] = proxies, groups
    return out


def dump_config(cfg: dict, header: str = "") -> str:
    return header + _dump(cfg)


# ---------------- хранилище ----------------
def list_templates() -> list[dict]:
    rows = db.q("SELECT id, name, updated, (SELECT COUNT(*) FROM users u WHERE u.template_id=t.id) AS used "
                "FROM route_templates t ORDER BY name")
    default = default_id()
    for r in rows:
        r["is_default"] = r["id"] == default
        try:
            r["info"] = analyze(db.q1("SELECT yaml FROM route_templates WHERE id=?", (r["id"],))["yaml"])
        except TemplateError:
            r["info"] = None
    return rows


def default_id() -> int | None:
    v = db.get_setting("default_template")
    return int(v) if v and str(v).isdigit() else None


def template_for(user: dict) -> dict | None:
    """Шаблон профиля: назначенный ему, иначе общий по умолчанию, иначе None (встроенный простой конфиг)."""
    tid = user.get("template_id") or default_id()
    return db.q1("SELECT id, name, yaml FROM route_templates WHERE id=?", (tid,)) if tid else None


def ensure_presets() -> None:
    """Однократно добавить встроенные шаблоны (удалённые пользователем не возвращаются)."""
    seeded = set(json.loads(db.get_setting("seeded_presets", "[]")))
    for name, fname in PRESETS:
        if fname in seeded:
            continue
        text = (APP_DIR / "presets" / fname).read_text(encoding="utf-8")
        if not db.q1("SELECT 1 FROM route_templates WHERE name=?", (name,)):
            now = int(time.time())
            db.ex("INSERT INTO route_templates(name,yaml,created,updated) VALUES(?,?,?,?)", (name, text, now, now))
        seeded.add(fname)
    db.set_setting("seeded_presets", json.dumps(sorted(seeded)))
