# SolaHelm

Self-hosted web panel for managing **Hysteria2** servers — and **VLESS (Reality)** / **AnyTLS** via sing-box on the same
servers — from one place. Create client profiles, hand out links / QR codes / subscriptions, watch server health,
and let your users open a personal cabinet with their own connections.

Bilingual interface (**English / Русский**) with a language switch on every page.

> Русская версия: [README.ru.md](README.ru.md)

> **Disclaimer.** Independent community project, not affiliated with Hysteria, sing-box, mihomo or Clash.
> You are responsible for using it in compliance with the laws that apply to you and to your servers.

## Features

- **Many VPS from one panel.** Add servers by SSH (panel key, password or your own key), see service state, version,
  uptime, CPU / RAM / disk, network speed. Start / stop / restart, journal, config editor with backup and automatic rollback.
- **One-click install on a clean Debian/Ubuntu VPS:** Hysteria2 (ACME certificate, masquerade site, `userpass` auth,
  traffic stats API, ufw) and/or sing-box with VLESS Reality + AnyTLS. Live install log.
- **Profiles:** create / edit / disable / delete, expiry date, traffic limit, per-profile access to chosen servers
  (matrix page "Access"). Changes are pushed to server configs automatically, with verification and rollback.
- **Client artifacts:** `hysteria2://`, `vless://`, `anytls://` links, QR codes (SVG / PNG), Hysteria YAML,
  Clash Meta / mihomo YAML, and a **subscription URL** (base64 and Clash format) with traffic/expiry headers.
- **Routing templates** for Clash/mihomo (DNS, TUN, rule providers, rules). Upload any ready-made mihomo config;
  the panel keeps routing and injects your servers. Two presets included.
- **Client cabinet:** separate accounts (login + password); a client sees only the profiles assigned to them.
- **Monitoring:** online users and traffic per profile / server / day (Hysteria2), availability history with charts,
  tolerant "no connection" detection (retries + N failures in a row).
- **Low profile:** random URL prefixes generated at install, every unknown path answers with a plain nginx-style 404,
  admin area isolated on its own prefix (and its own cookie path).
- **Security:** scrypt password hashes, server-side sessions, CSRF tokens, login throttling, CSP, audit log,
  encrypted SSH secrets, SSH host-key pinning.

## How it works

```
Browser ──HTTPS──► nginx ──HTTP──► SolaHelm (127.0.0.1:8088, systemd service)
  /<prefix>/          client cabinet, /<prefix>/sub/<token> subscriptions
  /<prefix>/<admin>/  admin panel (random path; restrict by IP in nginx)
                                      │ SSH
                  ┌───────────────────┼───────────────────┐
                 VPS 1               VPS 2               VPS N
        config.yaml + systemd    hysteria / sing-box    (trafficStats via SSH tunnel)
```

The panel is the **source of truth** for users: it rewrites the `auth.userpass` section of Hysteria's `config.yaml`
and the `vless-in` / `anytls-in` inbounds of sing-box (everything else is left alone), keeps timestamped backups
and restarts the service only when something changed.

## Requirements

- A Linux machine, VM or WSL2 (Ubuntu / Debian, **systemd enabled**) to run the panel, with **nginx** serving a
  site over **HTTPS** (domain + certificate, e.g. certbot).
- Python 3.10+ (tested on 3.12; the installer pulls `python3-venv`).
- One or more VPS with Debian/Ubuntu, reachable over SSH as `root` (or a sudo user with passwordless sudo).
  A supported (not end-of-life) OS release is strongly recommended.

## Quick start (Linux / WSL)

```bash
git clone https://github.com/sola21/solahelm.git
cd solahelm
sudo bash deploy/install-linux.sh
```

The installer asks for your site domain (the one nginx already serves), a public prefix for clients
(**Enter = random**) and a panel admin login/password. It generates a **random admin path**, installs the app into
`/opt/hy2panel` (venv, `.env`, data), registers the `hy2panel` systemd service, generates
`/etc/nginx/snippets/hy2panel.conf` and adds one `include` line to your site config (backup first; reverted if
`nginx -t` fails).

At the end it prints your addresses — **save the admin address**, it is random on purpose:

| What | URL |
|---|---|
| Client cabinet | `https://your-domain/<prefix>/` |
| Admin panel | `https://your-domain/<prefix>/<random-admin-path>/` |
| Subscription | `https://your-domain/<prefix>/sub/<token>` (append `/clash` for Clash format) |

New random admin address any time: `sudo ROTATE_ADMIN_PATH=1 bash deploy/install-linux.sh`.

**Restrict the admin area** (strongly recommended): edit `/etc/nginx/snippets/hy2panel-admin-acl.conf`,
uncomment `allow` / `deny`, then `sudo nginx -t && sudo systemctl reload nginx`.

Update: `git pull` and run the installer again (code is replaced, `data/` and `.env` are kept; a backup tarball
of the previous install is made first). Logs: `journalctl -u hy2panel -f`.

Useful installer variables: `SITE_DOMAIN=panel.example.org`, `NGINX_SITE=/etc/nginx/sites-available/mysite`.
Admins: `sudo -u hy2panel /opt/hy2panel/.venv/bin/python /opt/hy2panel/manage.py create-admin|passwd|list-admins <login>`.

Windows without WSL is possible too: see `deploy/install-windows.ps1` and `deploy/nginx-hy2panel.conf`.

### About hiding the panel

HTTPS already hides URL paths from anyone watching the network (they only see the domain / IP). What actually finds
panels is **scanners probing well-known paths** (`/admin`, `/panel`, …) and fingerprints in responses. So SolaHelm uses
random prefixes, answers unknown paths with an ordinary nginx-style 404, never redirects old paths to the admin area,
and keeps the admin session cookie scoped to the admin path. Combine it with an IP allow-list in nginx for real protection.

## Languages

The UI switches between English and Russian with the **RU | EN** control in the top right (also on the login pages);
the choice is remembered in a cookie. Default language: `HY_DEFAULT_LANG=ru|en|auto` (`auto` follows the browser).
Russian is the source language; English is a dictionary (`app/i18n_en.py`) applied to pages, API messages, install logs.
Check the dictionary after editing the UI: `python scripts/i18n_extract.py` (lists untranslated phrases). Anything missing
simply stays in Russian. Adding another language means adding another dictionary — see `app/i18n.py`; contributions welcome.

## Adding a VPS

1. **Servers → Add VPS**: address, SSH port, user (`root`).
2. SSH access: add the panel's public key (Settings → "Panel SSH key") to `~/.ssh/authorized_keys`,
   or choose "Password" once and press "Install panel key".
3. **Check**. If Hysteria2 is already running there: **Import profiles from server**, then **Sync**.
   On a clean VPS use the **Install** block (needs a domain with an A record pointing to the VPS and an e-mail for ACME).

Hysteria2 listens on UDP 443 and (masquerade + ACME) TCP 443/80, so VLESS and AnyTLS default to TCP 8443 / 9443.

## Configuration (`.env`)

See [`.env.example`](.env.example). The most important keys:

| Key | Meaning |
|---|---|
| `HY_BASE_PATH` | public prefix (cabinet, subscriptions); random after a fresh install |
| `HY_ADMIN_PATH` | admin sub-path inside it; random after a fresh install |
| `HY_LEGACY_BASE` | old prefixes: subscriptions keep working, other paths answer 404 |
| `HY_LEGACY_ADMIN_REDIRECT` | `1` = redirect old admin paths to the new admin address (reveals it; default off) |
| `HY_BRAND` | product name shown in the UI (default `SolaHelm`) |
| `HY_DEFAULT_LANG` | `ru`, `en` or `auto` |
| `HY_HOST`, `HY_PORT` | where the app listens (default `127.0.0.1:8088`) |
| `HY_TRUSTED_PROXIES` | IPs of your reverse proxy (to trust `X-Real-IP`) |
| `HY_PUBLIC_URL` | public URL used in subscription links (also editable in Settings) |
| `HY_POLL_INTERVAL` | server polling interval, seconds |

## Security notes

- The panel holds an SSH key that can log in to **all** your servers as root. Treat the panel host accordingly:
  keep it patched, expose only nginx, restrict the admin path by IP, use HTTPS only.
- Everything sensitive is in `data/` (`panel.db`, `secret.key`, `panel_ed25519`). **Back it up and never publish it.**
  Without `secret.key` stored SSH passwords cannot be decrypted.
- Traffic accounting and "online" are only available for Hysteria2 (its stats API); VLESS/AnyTLS get state only.
- If your reverse proxy hides the real client IP (e.g. NAT / port-proxy), login throttling sees one shared address.
- Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Development

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                 # defaults: /hy and /hy/admin
python manage.py create-admin admin
python run.py                                        # http://127.0.0.1:8088/hy/admin/
```

Layout: `app/main.py` (routes), `app/hy.py` (Hysteria config / sync / monitoring), `app/sb.py` (sing-box),
`app/ssh.py`, `app/clients.py` (links, QR, YAML), `app/routing.py` (Clash templates), `app/security.py`,
`app/i18n.py` + `app/i18n_en.py` (localization), `app/templates`, `app/static`, `deploy/`, `scripts/`.

## Credits and licenses

[Hysteria 2](https://github.com/apernet/hysteria), [sing-box](https://github.com/SagerNet/sing-box),
[mihomo](https://github.com/MetaCubeX/mihomo) are separate projects with their own licenses.
The bundled routing preset references public rule sets from
[legiz-ru/mihomo-rule-sets](https://github.com/legiz-ru/mihomo-rule-sets) and
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat); they are downloaded by clients at runtime.

SolaHelm itself is released under the [MIT License](LICENSE).
