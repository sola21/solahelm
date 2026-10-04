# SolaHelm for beginners: step by step

> Русский: [GUIDE.ru.md](GUIDE.ru.md) · Full reference: [README.md](README.md)

Goal: in one evening, get your own panel, connect a VPN VPS to it and hand the first client a link.
All examples are placeholders — **use your own values** (`myhelm.mooo.com`, `203.0.113.10`, …).

## What you need

| What | Example | Why |
|---|---|---|
| A computer or VM running Ubuntu/Debian (or Windows with WSL2), systemd enabled | a home mini-PC | the panel lives here |
| A domain name | `myhelm.mooo.com` | required for HTTPS; no domain? see step 1 |
| A VPS with Debian/Ubuntu and root SSH access | `203.0.113.10` | the actual VPN server |
| 30–60 minutes | | |

Layout: **you → panel (nginx + SolaHelm) → over SSH → your VPS**. Clients connect to the VPS and take their links and
subscriptions from the panel.

## Step 1. Get a domain (if you have none)

1. Go to <https://freedns.afraid.org/signup/>, register, confirm the e-mail.
2. **Subdomains → Add**: Type `A`, Subdomain `myhelm`, Domain `mooo.com`, Destination = public IP of the panel
   machine (find it with `curl ifconfig.me`). Save.
3. For the VPS add a second record: Subdomain `vps1`, Destination `203.0.113.10`.
4. Check (after 5–10 minutes): `nslookup myhelm.mooo.com` must show your IP.

Panel at home behind a router? Forward TCP **80 and 443** from the router to the panel machine.
More details and the changing-IP case: "No domain of your own?" in [README.md](README.md).

## Step 2. Install nginx and a certificate

On the panel machine, one by one:

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx git
sudo certbot --nginx -d myhelm.mooo.com
```

Certbot asks for an e-mail and the terms. Afterwards open `https://myhelm.mooo.com` — you should see the nginx page
with no certificate warning.

## Step 3. Install SolaHelm

```bash
git clone https://github.com/sola21/solahelm.git
cd solahelm
sudo bash deploy/install-linux.sh
```

Installer questions:

| Question | What to enter (example) |
|---|---|
| Site domain | `myhelm.mooo.com` |
| Public prefix for clients | just press **Enter** (random) |
| Admin login | `admin` |
| Password | long and unique (not like the examples!) |

At the end the installer prints the addresses. **Save the admin address somewhere safe** — it is random on purpose,
something like `https://myhelm.mooo.com/k3x9/a7f2q1/`.

Restrict the admin area by IP (recommended): open `/etc/nginx/snippets/hy2panel-admin-acl.conf`, uncomment
`allow` (put your IP) and `deny all;`, then:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Step 4. Log in

Open the admin address from step 3 and sign in. The language is switched with **RU | EN** at the top right.

Something wrong? `journalctl -u hy2panel -f` shows the panel log.

## Step 5. Add a VPS

1. **Servers → Add VPS**: address `203.0.113.10`, SSH port `22`, user `root`.
2. SSH access: in **Settings → "Panel SSH key"** copy the public key and add it to `~/.ssh/authorized_keys` on the VPS.
   Or choose "Password" once and press "Install panel key".
3. Press **Check**: the server state should appear.

## Step 6. Install the VPN on a clean VPS

In the server card open the **Install** block:

- domain: `vps1.mooo.com` (A record to this VPS, step 1; without it the certificate cannot be issued, and port 80
  must be free on the VPS);
- e-mail for the certificate: yours;
- pick Hysteria2 and/or sing-box (VLESS Reality + AnyTLS).

Press Install and watch the live log. If Hysteria2 is already running there: **Import profiles from server**, then **Sync**.

## Step 7. Create a client profile

1. **Profiles → create**: name `ivan`, expiry (e.g. one month), traffic limit (optional).
2. **Access** page: tick which servers the profile may use.
3. The panel pushes the changes to the servers itself. Open the profile: `hysteria2://`, `vless://`, `anytls://` links,
   QR code, Clash config and the **subscription link** are there.

## Step 8. Connect the client

Give the person the subscription link or QR code. They paste it into an app:

- Android: v2rayNG, Hiddify, NekoBox, sing-box;
- iOS: Streisand, Shadowrocket, sing-box;
- Windows/macOS/Linux: Hiddify, Clash Verge / mihomo, Nekoray.

(Apps are not part of this project and change over time; any app that understands the protocol will do.)

For the client cabinet: **Clients → create** an account and attach the profile; the cabinet address is
`https://myhelm.mooo.com/<prefix>/`.

## Troubleshooting

| Symptom | Check |
|---|---|
| `nslookup` shows no IP | wait 10–30 minutes; record type (`A`) and IP |
| certbot fails the challenge | is port 80 reachable from outside? forwarded on the router? does DNS match the IP? |
| Admin page does not open | exact address from step 3; did your own IP allow-list lock you out (step 3)? |
| VPS "does not check" | SSH port, panel key in `authorized_keys`, firewall |
| VPS install failed at the certificate | does the A record for `vps1…` point to this VPS? is port 80 free? |
| Forgot the admin address | `sudo ROTATE_ADMIN_PATH=1 bash deploy/install-linux.sh` makes a new one |
| Forgot the admin password | `sudo -u hy2panel /opt/hy2panel/.venv/bin/python /opt/hy2panel/manage.py passwd admin` |

## Security in two lines

- Back up the `data/` directory (keys and database) and **never share it**.
- Use a unique admin password and restrict the admin area by IP.
- Update: `cd solahelm && git pull && sudo bash deploy/install-linux.sh` (data is kept).
