"""Клиентские артефакты: ссылки hysteria2:// / vless:// / anytls:// / trojan:// / tuic:// / ss://, QR-коды,
YAML для клиента Hysteria и Clash Meta (mihomo), подписки."""
import base64
import io
import ipaddress
import json
from urllib.parse import quote

import segno
from ruamel.yaml import YAML

from . import security

PROTO_LABELS = {"hy2": "Hysteria2", "vless": "VLESS Reality", "vgrpc": "VLESS Reality gRPC", "anytls": "AnyTLS",
                "trojan": "Trojan", "tuic": "TUIC v5", "ss": "Shadowsocks-2022", "naive": "Naive", "masque": "MASQUE"}
NO_URI = ("masque",)          # у MASQUE нет общепринятой ссылки — клиенту отдаётся конфиг sing-box (JSON)
SS_METHOD = "2022-blake3-aes-128-gcm"
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
    if s.get("vgrpc_enabled") and s.get("reality_pub") and s.get("grpc_service"):
        out.append("vgrpc")
    for p in ("anytls", "trojan", "tuic", "naive"):               # TLS-протоколы работают на домене сервера
        if s.get(f"{p}_enabled") and s.get("anytls_domain"):
            out.append(p)
    if s.get("ss_enabled") and s.get("ss_key"):
        out.append("ss")
    if s.get("masque_enabled") and s.get("anytls_domain"):
        out.append("masque")
    return out


def uri_protos(s: dict) -> list[str]:
    """Протоколы, у которых есть ссылка (для подписки и QR)."""
    return [p for p in protos(s) if p not in NO_URI]


def endpoint(s: dict) -> dict:
    """Параметры Hysteria2."""
    info = json.loads(s.get("cfg_info") or "{}")
    host = (s.get("public_host") or "").strip() or (info.get("domains") or [""])[0] or s["host"]
    port = int(s.get("public_port") or 0) or int(info.get("port") or 443)
    sni = (s.get("sni") or "").strip() or ("" if _is_ip(host) else host)
    return {"host": host, "port": port, "sni": sni, "insecure": bool(s.get("insecure")),
            "obfs": info.get("obfs") or "", "hop": (s.get("hop_ports") or "").strip()}


def vless_endpoint(s: dict, proto: str = "vless") -> dict:
    host = (s.get("public_host") or "").strip() or s["host"]
    return {"host": host, "port": int(s[f"{proto}_port"]), "sni": s["reality_sni"], "pbk": s["reality_pub"],
            "sid": s["reality_sid"], "service": s.get("grpc_service") or ""}


def anytls_endpoint(s: dict) -> dict:
    """Хост для подключения: домен сертификата (он же SNI); при самоподписанном — insecure."""
    dom = s["anytls_domain"]
    return {"host": dom, "port": int(s["anytls_port"]), "sni": dom, "insecure": bool(s.get("anytls_insecure"))}


def ss_endpoint(s: dict) -> dict:
    host = (s.get("public_host") or "").strip() or s["host"]
    return {"host": host, "port": int(s["ss_port"]), "method": SS_METHOD}


def ss_password(user: dict, s: dict) -> str:
    """Пароль клиента Shadowsocks-2022 в многопользовательском режиме: «ключ сервера:ключ профиля»."""
    return f"{security.decrypt(s['ss_key'])}:{user['ss_key']}"


def tls_endpoint(s: dict, proto: str) -> dict:
    """Параметры TLS-протоколов на домене сервера (AnyTLS / Trojan / TUIC): общий домен и сертификат, свой порт."""
    e = anytls_endpoint(s)
    return {**e, "port": int(s[f"{proto}_port"])}


def profile_name(user: dict, s: dict) -> str:
    return f"{s['name']}-{user['username']}"


def _tag(user: dict, s: dict, proto: str) -> str:
    base = profile_name(user, s)
    return base if len(protos(s)) == 1 else f"{base}-{proto}"


def masque_endpoint(s: dict) -> dict:
    e = anytls_endpoint(s)
    return {**e, "port": int(s["masque_port"])}


def uri(user: dict, s: dict, proto: str = "hy2") -> str:
    name = quote(_tag(user, s, proto), safe="")
    if proto == "vless":
        e = vless_endpoint(s)
        q = (f"encryption=none&flow={FLOW}&security=reality&sni={quote(e['sni'], safe='')}&fp=chrome"
             f"&pbk={e['pbk']}&sid={e['sid']}&type=tcp&headerType=none")
        return f"vless://{user['uuid']}@{_fmt_host(e['host'])}:{e['port']}?{q}#{name}"
    if proto == "vgrpc":
        e = vless_endpoint(s, "vgrpc")
        q = (f"encryption=none&security=reality&sni={quote(e['sni'], safe='')}&fp=chrome"
             f"&pbk={e['pbk']}&sid={e['sid']}&type=grpc&serviceName={quote(e['service'], safe='')}&mode=gun")
        return f"vless://{user['uuid']}@{_fmt_host(e['host'])}:{e['port']}?{q}#{name}"
    if proto == "masque":
        return ""
    if proto == "anytls":
        e = anytls_endpoint(s)
        q = f"sni={quote(e['sni'], safe='')}" + ("&insecure=1" if e["insecure"] else "")
        return f"anytls://{quote(user['password'], safe='')}@{_fmt_host(e['host'])}:{e['port']}/?{q}#{name}"
    if proto == "trojan":
        e = tls_endpoint(s, "trojan")
        q = f"security=tls&sni={quote(e['sni'], safe='')}&type=tcp" + ("&allowInsecure=1" if e["insecure"] else "")
        return f"trojan://{quote(user['password'], safe='')}@{_fmt_host(e['host'])}:{e['port']}?{q}#{name}"
    if proto == "tuic":
        e = tls_endpoint(s, "tuic")
        q = (f"congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={quote(e['sni'], safe='')}"
             + ("&allow_insecure=1" if e["insecure"] else ""))
        return f"tuic://{user['uuid']}:{quote(user['password'], safe='')}@{_fmt_host(e['host'])}:{e['port']}?{q}#{name}"
    if proto == "naive":
        e = tls_endpoint(s, "naive")
        return (f"naive+https://{quote(user['username'], safe='')}:{quote(user['password'], safe='')}"
                f"@{_fmt_host(e['host'])}:{e['port']}#{name}")
    if proto == "ss":
        e = ss_endpoint(s)
        # для AEAD-2022 userinfo — обычный (не base64) «метод:пароль» с процентным кодированием (SIP002)
        return f"ss://{e['method']}:{quote(ss_password(user, s), safe='')}@{_fmt_host(e['host'])}:{e['port']}#{name}"
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
        if p in NO_URI:
            out.append({"proto": p, "label": PROTO_LABELS[p], "uri": "", "qr": ""})
            continue
        u = uri(user, s, p)
        out.append({"proto": p, "label": PROTO_LABELS[p], "uri": u, "qr": qr_svg(u)})
    return out


def all_uris(user: dict, servers: list[dict]) -> list[str]:
    return [uri(user, s, p) for s in servers for p in uri_protos(s)]


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
            elif proto == "vgrpc":
                e = vless_endpoint(s, "vgrpc")
                add(name, {"type": "vless", "server": e["host"], "port": e["port"], "uuid": user["uuid"],
                           "network": "grpc", "udp": True, "tls": True, "servername": e["sni"],
                           "grpc-opts": {"grpc-service-name": e["service"]},
                           "reality-opts": {"public-key": e["pbk"], "short-id": e["sid"]},
                           "client-fingerprint": "chrome"})
            elif proto in ("naive", "masque"):
                continue                       # Clash Meta / mihomo не поддерживает Naive и MASQUE
            elif proto == "anytls":
                e = anytls_endpoint(s)
                add(name, {"type": "anytls", "server": e["host"], "port": e["port"], "password": user["password"],
                           "sni": e["sni"], "client-fingerprint": "chrome", "udp": True,
                           "skip-cert-verify": e["insecure"]})
            elif proto == "trojan":
                e = tls_endpoint(s, "trojan")
                add(name, {"type": "trojan", "server": e["host"], "port": e["port"], "password": user["password"],
                           "sni": e["sni"], "udp": True, "skip-cert-verify": e["insecure"]})
            elif proto == "tuic":
                e = tls_endpoint(s, "tuic")
                add(name, {"type": "tuic", "server": e["host"], "port": e["port"], "uuid": user["uuid"],
                           "password": user["password"], "alpn": ["h3"], "udp-relay-mode": "native",
                           "congestion-controller": "bbr", "sni": e["sni"], "skip-cert-verify": e["insecure"]})
            elif proto == "ss":
                e = ss_endpoint(s)
                add(name, {"type": "ss", "server": e["host"], "port": e["port"], "cipher": e["method"],
                           "password": ss_password(user, s), "udp": True})
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


def masque_json(user: dict, s: dict) -> str:
    """Конфиг клиента sing-box 1.15+ для MASQUE: TUN (весь трафик устройства) + локальный прокси 127.0.0.1:2080."""
    e = masque_endpoint(s)
    tls = {"enabled": True, "server_name": e["sni"]}
    if e["insecure"]:
        tls["insecure"] = True
    cfg = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "masque"},
                            {"type": "local", "tag": "dns-local"}],
                "rules": [{"domain": [e["host"]], "server": "dns-local"}],
                "final": "dns-remote"},
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True,
                      "strict_route": True},
                     {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "endpoints": [{"type": "masque-client", "tag": "masque", "server": e["host"], "server_port": e["port"],
                       "username": user["username"], "password": user["password"], "tls": tls}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"},
                            {"ip_is_private": True, "outbound": "direct"}],
                  "final": "masque", "auto_detect_interface": True, "default_domain_resolver": "dns-local"},
    }
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"


def _sb_tls(sni: str, insecure: bool = False, **extra) -> dict:
    d = {"enabled": True, "server_name": sni}
    if insecure:
        d["insecure"] = True
    d.update(extra)
    return d


def singbox_outbound(user: dict, s: dict, proto: str, tag: str) -> dict | None:
    """Один протокол сервера как outbound (или endpoint для MASQUE) конфига sing-box. None — протокол не поддерживается."""
    utls = {"enabled": True, "fingerprint": "chrome"}
    if proto in ("vless", "vgrpc"):
        e = vless_endpoint(s, proto)
        o = {"type": "vless", "tag": tag, "server": e["host"], "server_port": e["port"], "uuid": user["uuid"],
             "tls": _sb_tls(e["sni"], utls=utls, reality={"enabled": True, "public_key": e["pbk"], "short_id": e["sid"]})}
        if proto == "vless":
            o["flow"] = FLOW
        else:
            o["transport"] = {"type": "grpc", "service_name": e["service"]}
        return o
    if proto in ("anytls", "trojan"):
        e = tls_endpoint(s, proto)
        return {"type": proto, "tag": tag, "server": e["host"], "server_port": e["port"], "password": user["password"],
                "tls": _sb_tls(e["sni"], e["insecure"], utls=utls)}
    if proto == "tuic":
        e = tls_endpoint(s, "tuic")
        return {"type": "tuic", "tag": tag, "server": e["host"], "server_port": e["port"], "uuid": user["uuid"],
                "password": user["password"], "congestion_control": "bbr", "udp_relay_mode": "native",
                "tls": _sb_tls(e["sni"], e["insecure"], alpn=["h3"])}
    if proto == "ss":
        e = ss_endpoint(s)
        return {"type": "shadowsocks", "tag": tag, "server": e["host"], "server_port": e["port"], "method": e["method"],
                "password": ss_password(user, s)}
    if proto == "masque":
        e = masque_endpoint(s)
        return {"type": "masque-client", "tag": tag, "server": e["host"], "server_port": e["port"],
                "username": user["username"], "password": user["password"], "tls": _sb_tls(e["sni"], e["insecure"])}
    if proto == "hy2":
        e = endpoint(s)
        o = {"type": "hysteria2", "tag": tag, "server": e["host"], "server_port": e["port"],
             "password": f"{user['username']}:{user['password']}",
             "tls": _sb_tls(e["sni"] or e["host"], e["insecure"], alpn=["h3"])}
        if e["hop"]:
            ranges = []
            for part in e["hop"].split(","):
                a, _, b = part.strip().partition("-")
                ranges.append(f"{a}:{b or a}")
            o["server_ports"] = ranges
            o["hop_interval"] = "30s"
            o.pop("server_port")
        if e["obfs"]:
            o["obfs"] = {"type": "salamander", "password": e["obfs"]}
        return o
    return None                      # Naive: в сборках sing-box для телефонов его может не быть — не включаем


def singbox_json(user: dict, servers: list[dict], masque: bool = False) -> str:
    """Подписка для приложения sing-box: все серверы и протоколы профиля, автовыбор (urltest) и ручной выбор.
    MASQUE — только при masque=True: конфиг с ним открывается лишь в sing-box 1.15+."""
    outbounds, endpoints, tags, hosts = [], [], [], []
    for s in servers:
        for proto in protos(s):
            if proto == "masque" and not masque:
                continue
            tag = f"{s['name']}-{PROTO_LABELS[proto]}"
            while tag in tags:
                tag += "*"
            o = singbox_outbound(user, s, proto, tag)
            if not o:
                continue
            tags.append(tag)
            (endpoints if proto == "masque" else outbounds).append(o)
            if not _is_ip(o["server"]) and o["server"] not in hosts:
                hosts.append(o["server"])
    sel = ["auto"] + tags if len(tags) > 1 else list(tags)
    groups = [{"type": "selector", "tag": "proxy", "outbounds": sel or ["direct"], "default": sel[0] if sel else "direct"}]
    if len(tags) > 1:
        groups.append({"type": "urltest", "tag": "auto", "outbounds": tags, "url": "https://www.gstatic.com/generate_204",
                       "interval": "5m", "tolerance": 100})
    dns_rules = [{"domain": hosts, "server": "dns-local"}] if hosts else []
    cfg = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "proxy"},
                            {"type": "local", "tag": "dns-local"}],
                "rules": dns_rules, "final": "dns-remote"},
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True},
                     {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": groups + outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"},
                            {"ip_is_private": True, "outbound": "direct"}],
                  "final": "proxy", "auto_detect_interface": True, "default_domain_resolver": "dns-local"},
    }
    if endpoints:
        cfg["endpoints"] = endpoints
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"


def has_masque(servers: list[dict]) -> bool:
    return any("masque" in protos(s) for s in servers)


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
