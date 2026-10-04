"""Управление администраторами панели.

python manage.py create-admin <логин>   создать администратора (пароль спросит)
python manage.py passwd <логин>         сменить пароль
python manage.py list-admins            список
python manage.py delete-admin <логин>   удалить
"""
import getpass
import sys
import time

from app import db, security


def ask_password() -> str:
    while True:
        p1 = getpass.getpass("Пароль (от 10 символов): ")
        if len(p1) < 10:
            print("Слишком короткий пароль")
            continue
        if p1 != getpass.getpass("Повторите: "):
            print("Пароли не совпадают")
            continue
        return p1


def main(argv: list[str]) -> int:
    db.init()
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd = argv[1]
    if cmd == "list-admins":
        for a in db.q("SELECT id, username, created FROM admins ORDER BY id"):
            print(a["id"], a["username"], time.strftime("%Y-%m-%d %H:%M", time.localtime(a["created"] or 0)))
        return 0
    if len(argv) < 3:
        print(__doc__)
        return 1
    name = argv[2].strip()
    if cmd == "create-admin":
        if db.q1("SELECT 1 FROM admins WHERE username=?", (name,)):
            print("Такой администратор уже есть")
            return 1
        db.ex("INSERT INTO admins(username,pw_hash,created) VALUES(?,?,?)",
              (name, security.hash_password(ask_password()), int(time.time())))
        print(f"Администратор {name} создан")
    elif cmd == "passwd":
        a = db.q1("SELECT id FROM admins WHERE username=?", (name,))
        if not a:
            print("Нет такого администратора")
            return 1
        db.ex("UPDATE admins SET pw_hash=? WHERE id=?", (security.hash_password(ask_password()), a["id"]))
        db.ex("DELETE FROM sessions WHERE admin_id=?", (a["id"],))
        print("Пароль изменён, сессии завершены")
    elif cmd == "delete-admin":
        db.ex("DELETE FROM admins WHERE username=?", (name,))
        print("Удалён")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
