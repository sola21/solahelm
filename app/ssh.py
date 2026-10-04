"""SSH-подключение к VPS: выполнение команд, чтение/запись файлов, HTTP к локальным портам через туннель."""
import base64
import io
import json
import re
import shlex
import socket
import time

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import db, security
from .config import DATA_DIR

KEY_PATH = DATA_DIR / "panel_ed25519"
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\r")


class SSHError(Exception):
    pass


# ---------- собственный ключ панели ----------
def ensure_panel_key() -> None:
    if KEY_PATH.exists():
        return
    k = ed25519.Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                         serialization.NoEncryption()))
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    KEY_PATH.with_suffix(".pub").write_bytes(pub + b" hy2panel\n")


def panel_pubkey() -> str:
    ensure_panel_key()
    return KEY_PATH.with_suffix(".pub").read_text().strip()


def load_pkey(text: str, passphrase: str | None = None) -> paramiko.PKey:
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text.strip() + "\n"), password=passphrase or None)
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    raise SSHError("Не удалось прочитать приватный ключ (формат OpenSSH/PEM, верная passphrase?)")


class Conn:
    """Использование: with Conn(server_row) as c: c.run("uptime")"""

    def __init__(self, server: dict, timeout: int = 25, auth_override: str | None = None):
        self.s = server
        self.timeout = timeout
        self.auth = auth_override or server.get("ssh_auth") or "panelkey"
        self.t: paramiko.Transport | None = None

    # ----- подключение -----
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.close()

    def connect(self) -> None:
        s = self.s
        host, port, user = s["host"], int(s.get("ssh_port") or 22), s.get("ssh_user") or "root"
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        except OSError as e:
            raise SSHError(f"Нет TCP-соединения с {host}:{port}: {e}")
        t = paramiko.Transport(sock)
        t.banner_timeout = 40
        t.auth_timeout = 40
        try:
            t.start_client(timeout=self.timeout)
            key = t.get_remote_server_key()
            fp = f"{key.get_name()} {key.get_base64()}"
            stored = s.get("host_key") or ""
            if stored and stored != fp:
                raise SSHError("КЛЮЧ ХОСТА ИЗМЕНИЛСЯ! Возможна подмена сервера. Если сервер переустановлен — "
                               "сбросьте сохранённый ключ хоста в настройках сервера.")
            if not stored and s.get("id"):
                db.ex("UPDATE servers SET host_key=? WHERE id=?", (fp, s["id"]))
                s["host_key"] = fp
            self._authenticate(t, user)
        except SSHError:
            t.close()
            raise
        except Exception as e:
            t.close()
            raise SSHError(f"SSH {host}:{port}: {e}")
        t.set_keepalive(30)
        self.t = t

    def _authenticate(self, t: paramiko.Transport, user: str) -> None:
        mode = self.auth
        try:
            if mode == "password":
                pw = security.decrypt(self.s.get("ssh_secret", ""))
                try:
                    t.auth_password(user, pw)
                except paramiko.BadAuthenticationType:
                    t.auth_interactive(user, lambda title, instr, prompts: [pw for _ in prompts])
            elif mode == "key":
                pkey = load_pkey(security.decrypt(self.s.get("ssh_key", "")),
                                 security.decrypt(self.s.get("ssh_secret", "")))
                t.auth_publickey(user, pkey)
            else:
                ensure_panel_key()
                t.auth_publickey(user, paramiko.Ed25519Key.from_private_key_file(str(KEY_PATH)))
        except paramiko.AuthenticationException as e:
            raise SSHError(f"Ошибка аутентификации SSH ({mode}): {e}")
        if not t.is_authenticated():
            raise SSHError("SSH: аутентификация не пройдена")

    def close(self) -> None:
        if self.t:
            self.t.close()
            self.t = None

    # ----- команды -----
    @property
    def is_root(self) -> bool:
        return (self.s.get("ssh_user") or "root") == "root"

    def _wrap(self, cmd: str, sudo: bool) -> str:
        if not sudo or self.is_root:
            return cmd
        return "sudo -n sh -c " + shlex.quote(cmd)

    def _open(self, cmd: str, sudo: bool, timeout: int):
        ch = self.t.open_session(timeout=15)
        ch.settimeout(timeout)
        ch.exec_command(self._wrap(cmd, sudo))
        return ch

    def run(self, cmd: str, input: str | bytes | None = None, timeout: int = 120, sudo: bool = True,
            check: bool = False) -> tuple[int, str, str]:
        ch = self._open(cmd, sudo, timeout)
        if input is not None:
            ch.sendall(input.encode() if isinstance(input, str) else input)
            ch.shutdown_write()
        out, err = [], []
        deadline = time.time() + timeout
        while True:
            got = False
            if ch.recv_ready():
                out.append(ch.recv(65536)); got = True
            if ch.recv_stderr_ready():
                err.append(ch.recv_stderr(65536)); got = True
            if not got:
                if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
                    break
                if time.time() > deadline:
                    ch.close()
                    raise SSHError(f"Таймаут команды ({timeout} c)")
                time.sleep(0.03)
        code = ch.recv_exit_status()
        ch.close()
        o = b"".join(out).decode("utf-8", "replace")
        e = b"".join(err).decode("utf-8", "replace")
        if check and code != 0:
            raise SSHError(f"Команда завершилась с кодом {code}: {(e or o).strip()[-800:]}")
        return code, o, e

    def run_stream(self, cmd: str, input: str | None, log, timeout: int = 1800, sudo: bool = True) -> int:
        """Выполнить команду, передавая объединённый вывод в log(text) по мере поступления."""
        ch = self._open(cmd, sudo, timeout)
        ch.set_combine_stderr(True)
        if input is not None:
            ch.sendall(input.encode())
            ch.shutdown_write()
        deadline = time.time() + timeout
        buf = b""
        last_flush = time.time()
        while True:
            if ch.recv_ready():
                buf += ch.recv(65536)
            elif ch.exit_status_ready():
                break
            else:
                if time.time() > deadline:
                    ch.close()
                    raise SSHError(f"Таймаут ({timeout} c)")
                time.sleep(0.1)
            if buf and (b"\n" in buf and time.time() - last_flush > 0.5 or len(buf) > 8192):
                cut = buf.rfind(b"\n") + 1 or len(buf)
                log(ANSI_RE.sub("", buf[:cut].decode("utf-8", "replace")))
                buf = buf[cut:]
                last_flush = time.time()
        while ch.recv_ready():
            buf += ch.recv(65536)
        if buf:
            log(ANSI_RE.sub("", buf.decode("utf-8", "replace")))
        code = ch.recv_exit_status()
        ch.close()
        return code

    # ----- файлы -----
    def read_file(self, path: str) -> str:
        code, out, err = self.run(f"cat {shlex.quote(path)}")
        if code != 0:
            raise SSHError(f"Не удалось прочитать {path}: {err.strip() or out.strip()}")
        return out

    def write_file(self, path: str, content: str, backup: bool = True, keep: int = 10) -> None:
        """Атомарная (насколько возможно) запись с сохранением прав файла и ротацией бэкапов."""
        p = shlex.quote(path)
        tmp = shlex.quote(path + ".hy2panel.tmp")
        cmd = ""
        if backup:
            cmd += (f"if [ -f {p} ]; then cp -a {p} {p}.bak.$(date +%Y%m%d-%H%M%S); "
                    f"ls -1 {p}.bak.* 2>/dev/null | sort | head -n -{keep} | xargs -r rm -f; fi; ")
        cmd += f'mkdir -p "$(dirname {p})" && cat > {tmp} && cat {tmp} > {p} && rm -f {tmp}'
        code, out, err = self.run(cmd, input=content)
        if code != 0:
            raise SSHError(f"Не удалось записать {path}: {err.strip() or out.strip()}")

    # ----- HTTP к 127.0.0.1:port на VPS (API trafficStats) -----
    def http(self, port: int, method: str, path: str, secret: str = "", body: str | None = None) -> tuple[int, str]:
        try:
            return self._http_tunnel(port, method, path, secret, body)
        except (paramiko.ChannelException, paramiko.SSHException):
            return self._http_curl(port, method, path, secret, body)

    def _http_tunnel(self, port, method, path, secret, body):
        ch = self.t.open_channel("direct-tcpip", ("127.0.0.1", int(port)), ("127.0.0.1", 0), timeout=10)
        ch.settimeout(15)
        data = (body or "").encode()
        head = [f"{method} {path} HTTP/1.0", f"Host: 127.0.0.1:{port}", "Connection: close"]
        if secret:
            head.append(f"Authorization: {secret}")
        if body is not None:
            head += ["Content-Type: application/json", f"Content-Length: {len(data)}"]
        ch.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + data)
        resp = b""
        while True:
            chunk = ch.recv(65536)
            if not chunk:
                break
            resp += chunk
        ch.close()
        hdr, _, payload = resp.partition(b"\r\n\r\n")
        try:
            status = int(hdr.split(b" ", 2)[1])
        except Exception:
            raise SSHError(f"Некорректный HTTP-ответ от 127.0.0.1:{port}")
        return status, payload.decode("utf-8", "replace")

    def _http_curl(self, port, method, path, secret, body):
        cmd = (f"curl -sS -m 10 -o - -w '\\n%{{http_code}}' -X {method} "
               f"-H {shlex.quote('Authorization: ' + secret)} ")
        if body is not None:
            cmd += "-H 'Content-Type: application/json' --data-binary @- "
        cmd += shlex.quote(f"http://127.0.0.1:{int(port)}{path}")
        code, out, err = self.run(cmd, input=body, sudo=False, timeout=20)
        if code != 0:
            raise SSHError(f"curl: {err.strip()}")
        payload, _, status = out.rpartition("\n")
        return int(status or 0), payload

    def http_json(self, port: int, method: str, path: str, secret: str, body=None):
        status, text = self.http(port, method, path, secret, json.dumps(body) if body is not None else None)
        if status != 200:
            raise SSHError(f"trafficStats API {path}: HTTP {status} {text[:200]}")
        return json.loads(text) if text.strip() else None


def host_key_fingerprint(stored: str) -> str:
    """SHA256-отпечаток сохранённого ключа хоста, как в ssh-keygen -lf."""
    if not stored:
        return ""
    try:
        import hashlib
        ktype, b64 = stored.split(" ", 1)
        fp = base64.b64encode(hashlib.sha256(base64.b64decode(b64)).digest()).decode().rstrip("=")
        return f"{ktype} SHA256:{fp}"
    except Exception:
        return stored[:40]
