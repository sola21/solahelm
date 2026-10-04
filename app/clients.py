"""Клиентские артефакты: ссылки hysteria2:// / vless:// / anytls://, QR-коды, YAML для клиента Hysteria
и Clash Meta (mihomo), подписки."""
import base64
import io
import ipaddress
import json
from urllib.parse import quote

import segno
from ruamel.yaml import YAML

PROTO_LABELS = {"hy2": "Hysteria2", "vless": "VLESS Reality", "anytls": "AnyTLS"}
FLOW = "xtls-rprx-vision"


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _fmt_host(h: str) -> str:
    return f"[{h}]" if ":" in h and _is_ip(h) else h


def protos(s: dict) -> list[str]:
    """Протоколы, доступные клиенту на этом сервере."""
    out = []
    if s.get("hy2_enabled", 1):
        out.append("hy2")
    if s.get("vless_enabled") and s.get("reality_pub"):
        out.append("vless")
    if s.get("anytls_enabled") and s.get("anytls_domain"):
        out.append("anytls")
    return out


def endpoint(s: dict) -> dict:
    """Параметры Hysteria2."""
    info = json.loads(s.get("cfg_info") or "{}")
    host = (s.get("public_host") or "").strip() or (info.get("domains") or [""])[0] or s["host"]
    port = int(s.get("public_port") or 0) or int(info.get("port") or 443)
    sni = (s.get("sni") or "").strip() or ("" if _is_ip(host) else host)
    return {"host": host, "port": port, "sni": sni, "insecure": bool(s.get("insecure")),
            "obfs": info.get("obfs") or "", "hop": (s.get("hop_ports") or "").strip()}


def vless_endpoint(s: dict) -> dict:
    host = (s.get("public_host") or "").strip() or s["host"]
    return {"host": host, "port": int(s["vless_port"]), "sni": s["reality_sni"], "pbk": s["reality_pub"],
            "sid": s["reality_sid"]}


def anytls_endpoint(s: dict) -> dict:
    """Хост для подключения: домен сертификата (он же SNI); при самоподписанном — insecure."""
    dom = s["anytls_domain"]
    return {"host": dom, "port": int(s["anytls_port"]), "sni": dom, "insecure": bool(s.get("anytls_insecure"))}


def profile_name(user: dict, s: dict) -> str:
    return f"{s['name']}-{user['username']}"


def _tag(user: dict, s: dict, proto: str) -> str:
    base = profile_name(user, s)
    return base if len(protos(s)) == 1 else f"{base}-{proto}"


def uri(user: dict, s: dict, proto: str = "hy2") -> str:
    name = quote(_tag(user, s, proto), safe="")
    if proto == "vless":
        e = vless_endpoint(s)
        q = (f"encryption=none&flow={FLOW}&security=reality&sni={quote(e['sni'], safe='')}&fp=chrome"
             f"&pbk={e['pbk']}&sid={e['sid']}&type=tcp&headerType=none")
        return f"vless://{user['uuid']}@{_fmt_host(e['host'])}:{e['port']}?{q}#{name}"
    if proto == "anytls":
        e = anytls_endpoint(s)
        q = f"sni={quote(e['sni'], safe='')}" + ("&insecure=1" if e["insecure"] else "")
        return f"anytls://{quote(user['password'], safe='')}@{_fmt_host(e['host'])}:{e['port']}/?{q}#{name}"
    e = endpoint(s)
    auth = quote(user["username"], safe="") + ":" + quote(user["password"], safe="")
    params = []
    if e["sni"]:
        params.append("sni=" + quote(e["sni"], safe=""))
    if e["insecure"]:
        params.append("insecure=1")
    if e["obfs"]:
        params += ["obfs=salamander", "obfs-password=" + quote(e["obfs"], safe="")]
    qs = ("?" + "&".join(params)) if params else ""
    ports = e["hop"] or str(e["port"])
    return f"hysteria2://{auth}@{_fmt_host(e['host'])}:{ports}/{qs}#{name}"


def links(user: dict, s: dict) -> list[dict]:
    """Все ссылки профиля на сервере: [{proto, label, uri, qr}]."""
    out = []
    for p in protos(s):
        u = uri(user, s, p)
        out.append({"proto": p, "label": PROTO_LABELS[p], "uri": u, "qr": qr_svg(u)})
    return out


def all_uris(user: dict, servers: list[dict]) -> list[str]:
    return [uri(user, s, p) for s in servers for p in protos(s)]


def _dump(data, header: str = "") -> str:
    y = YAML()
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    buf = io.StringIO()
    y.dump(data, buf)
    return header + buf.getvalue()


def hysteria_yaml(user: dict, s: dict) -> str:
    e = endpoint(s)
    d: dict = {"server": f"{_fmt_host(e['host'])}:{e['hop'] or e['port']}",
               "auth": f"{user['username']}:{user['password']}"}
    tls = {}
    if e["sni"]:
        tls["sni"] = e["sni"]
    if e["insecure"]:
        tls["insecure"] = True
    if tls:
        d["tls"] = tls
    if e["obfs"]:
        d["obfs"] = {"type": "salamander", "salamander": {"password": e["obfs"]}}
    d["socks5"] = {"listen": "127.0.0.1:1080"}
    d["http"] = {"listen": "127.0.0.1:8080"}
    return _dump(d, f"# Hysteria2 client — {profile_name(user, s)}\n# Run: hysteria client -c {profile_name(user, s)}.yaml\n")


def clash_yaml(user: dict, servers: list[dict], template: dict | None = None) -> str:
    """Клиентский конфиг Clash Meta. С шаблоном маршрутизации (routing) — с его DNS/TUN/правилами."""
    proxies, names = [], []

    def add(name: str, p: dict) -> None:
        while name in names:
            name += "*"
        names.append(name)
        proxies.append({"name": name, **p})

    for s in servers:
        multi = len(protos(s)) > 1
        for proto in protos(s):
            name = f"{s['name']}-{proto}" if multi else s["name"]
            if proto == "vless":
                e = vless_endpoint(s)
                add(name, {"type": "vless", "server": e["host"], "port": e["port"], "uuid": user["uuid"],
                           "network": "tcp", "udp": True, "tls": True, "flow": FLOW, "servername": e["sni"],
                           "reality-opts": {"public-key": e["pbk"], "short-id": e["sid"]},
                           "client-fingerprint": "chrome"})
            elif proto == "anytls":
                e = anytls_endpoint(s)
                add(name, {"type": "anytls", "server": e["host"], "port": e["port"], "password": user["password"],
                           "sni": e["sni"], "client-fingerprint": "chrome", "udp": True,
                           "skip-cert-verify": e["insecure"]})
            else:
                e = endpoint(s)
                p = {"type": "hysteria2", "server": e["host"], "port": e["port"],
                     "password": f"{user['username']}:{user['password']}"}
                if e["hop"]:
                    p["ports"] = e["hop"]
                if e["sni"]:
                    p["sni"] = e["sni"]
                p["skip-cert-verify"] = e["insecure"]
                if e["obfs"]:
                    p["obfs"] = "salamander"
                    p["obfs-password"] = e["obfs"]
                p["alpn"] = ["h3"]
                add(name, p)
    if template:
        from . import routing
        try:
            cfg = routing.render(template["yaml"], proxies)
            return routing.dump_config(
                cfg, f"# Clash Meta / mihomo — {user['username']}\n# Routing rules: {template['name']}\n")
        except routing.TemplateError:
            pass  # испорченный шаблон не должен ломать выдачу — отдаём встроенный простой конфиг
    groups = []
    select = list(names)
    if len(names) > 1:
        groups.append({"name": "AUTO", "type": "url-test", "proxies": list(names),
                       "url": "https://www.gstatic.com/generate_204", "interval": 300})
        select = ["AUTO"] + select
    groups.insert(0, {"name": "PROXY", "type": "select", "proxies": select + ["DIRECT"]})
    cfg = {"mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info", "ipv6": True,
           "proxies": proxies, "proxy-groups": groups,
           "rules": ["IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                     "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                     "MATCH,PROXY"]}
    return _dump(cfg, f"# Clash Meta / mihomo — {user['username']}\n")


def sub_body(user: dict, servers: list[dict]) -> str:
    return base64.b64encode("\n".join(all_uris(user, servers)).encode()).decode()


def sub_headers(user: dict) -> dict:
    title = base64.b64encode(f"Hy2 · {user['username']}".encode()).decode()
    info = f"upload={user['tx']}; download={user['rx']}; total={user['traffic_limit']}; expire={user['expires_at']}"
    return {"profile-title": f"base64:{title}", "subscription-userinfo": info,
            "profile-update-interval": "12", "Cache-Control": "no-store"}


def qr_svg(data: str) -> str:
    # omitsize: вместо фиксированных width/height — viewBox, иначе CSS обрезает QR вместо масштабирования.
    # Уровень L: на экране ошибок почти нет, а плотность ниже (проще сканировать длинные ссылки).
    return segno.make_qr(data, error="l").svg_inline(scale=4, border=3, dark="#111111", light="#ffffff", omitsize=True)


def qr_png(data: str) -> bytes:
    buf = io.BytesIO()
    segno.make_qr(data, error="l").save(buf, kind="png", scale=8, border=3)
    return buf.getvalue()
