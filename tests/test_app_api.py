"""API для приложений (BASE/api/app/...) и «Подключённые приложения» в кабинете.

Запуск: pip install pytest httpx && pytest
Панель поднимается в памяти с временным каталогом данных; к серверам не подключается.
"""
import os
import re
import sys
import tempfile
import time
from pathlib import Path

DATA = tempfile.mkdtemp(prefix="solahelm-test-")
os.environ.update(HY_DATA_DIR=DATA, HY_BASE_PATH="/hy", HY_PUBLIC_URL="https://panel.example.org/hy",
                  HY_POLL_INTERVAL="3600", HY_COOKIE_SECURE="0")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db, security  # noqa: E402
from app.main import app  # noqa: E402

LOGIN, PASSWORD = "test1", "correct horse battery"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        now = int(time.time())
        db.ex("INSERT INTO clients(login,pw_hash,name,enabled,created) VALUES(?,?,?,1,?)",
              (LOGIN, security.hash_password(PASSWORD), "Test One", now))
        cid = db.q1("SELECT id FROM clients WHERE login=?", (LOGIN,))["id"]
        db.ex("INSERT INTO users(username,password,enabled,sub_token,client_id,created,traffic_limit,tx,rx) "
              "VALUES('alpha','p1',1,'tokA',?,?,0,10,20)", (cid, now))
        db.ex("INSERT INTO users(username,password,enabled,sub_token,client_id,created) "
              "VALUES('beta','p2',0,'tokB',?,?)", (cid, now))
        yield c


@pytest.fixture(autouse=True)
def _reset_limiter():
    security.limiter._fails.clear()
    yield


def login(c, password=None, device="Test PC"):
    return c.post("/hy/api/app/login", json={"login": LOGIN, "password": password or PASSWORD, "device": device})


def test_login_returns_token_and_profiles(client):
    r = login(client)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] and d["token"].startswith("sht_")
    assert d["client"] == {"login": LOGIN, "name": "Test One"}
    assert d["panel"]["version"]
    by = {p["name"]: p for p in d["profiles"]}
    assert by["alpha"]["state"] == "on"
    assert by["alpha"]["traffic_used"] == 30
    assert by["alpha"]["subscription"]["universal"] == "https://panel.example.org/hy/sub/tokA"
    assert by["alpha"]["subscription"]["clash"].endswith("/sub/tokA/clash")
    # A disabled profile is listed, but without links.
    assert by["beta"]["state"] == "off" and by["beta"]["subscription"] is None
    # Only the hash is stored.
    assert db.q1("SELECT COUNT(*) n FROM app_tokens WHERE token_hash=?", (d["token"],))["n"] == 0


def test_errors_are_codes(client):
    assert login(client, password="wrong").json() == {"ok": False, "error": "bad_credentials"}
    assert client.post("/hy/api/app/login", json={"login": LOGIN}).json()["error"] == "bad_request"
    assert client.post("/hy/api/app/login", content=b"not json").status_code == 400
    r = client.get("/hy/api/app/profiles")
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    r = client.get("/hy/api/app/profiles", headers={"Authorization": "Bearer sht_nope"})
    assert r.status_code == 401


def test_rate_limit_shared_with_cabinet(client):
    for _ in range(security.LoginLimiter.MAX_FAILS):
        assert login(client, password="wrong").status_code == 401
    r = login(client)  # even the right password is refused for a while
    assert r.status_code == 429 and r.json()["error"] == "rate_limited"


def test_profiles_and_logout(client):
    tok = login(client).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.get("/hy/api/app/profiles", headers=h)
    assert r.status_code == 200 and len(r.json()["profiles"]) == 2 and "token" not in r.json()
    assert client.post("/hy/api/app/logout", headers=h).json() == {"ok": True}
    assert client.get("/hy/api/app/profiles", headers=h).status_code == 401


def _cabinet(client):
    client.cookies.clear()
    r = client.post("/hy/login", data={"login": LOGIN, "password": PASSWORD}, follow_redirects=True)
    assert r.status_code == 200
    return r.text


def test_cabinet_lists_and_revokes_apps(client):
    tok = login(client, device="Pixel of Test").json()["token"]
    page = _cabinet(client)
    assert "Подключённые приложения" in page and "Pixel of Test" in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    tid = db.q1("SELECT id FROM app_tokens WHERE device='Pixel of Test'")["id"]
    r = client.post(f"/hy/apps/{tid}/revoke", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/hy/api/app/profiles", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    # Someone else's token id can't be revoked through this client (no such row for them).
    assert client.post("/hy/apps/999999/revoke", data={"csrf": csrf}, follow_redirects=False).status_code == 303


def test_password_change_and_disable_revoke_tokens(client):
    global PASSWORD
    tok = login(client).json()["token"]
    page = _cabinet(client)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    new = "another long password"
    r = client.post("/hy/password", data={"csrf": csrf, "current": PASSWORD, "new": new, "new2": new},
                    follow_redirects=False)
    assert r.status_code == 303 and "ok=" in r.headers["location"]
    PASSWORD = new
    assert client.get("/hy/api/app/profiles", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

    tok = login(client).json()["token"]
    db.ex("UPDATE clients SET enabled=0 WHERE login=?", (LOGIN,))
    try:
        assert client.get("/hy/api/app/profiles", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
        assert login(client).json()["error"] == "bad_credentials"
    finally:
        db.ex("UPDATE clients SET enabled=1 WHERE login=?", (LOGIN,))


def test_token_limit_per_client(client):
    for i in range(security.MAX_APP_TOKENS + 5):
        security.create_app_token(db.q1("SELECT id FROM clients WHERE login=?", (LOGIN,))["id"], f"dev{i}", "")
    n = db.q1("SELECT COUNT(*) n FROM app_tokens t JOIN clients c ON c.id=t.client_id WHERE c.login=?", (LOGIN,))["n"]
    assert n == security.MAX_APP_TOKENS
