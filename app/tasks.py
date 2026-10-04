"""Фоновый воркер: синхронизация «грязных» серверов, периодический опрос, длительные задачи (установка)."""
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from . import db
from .config import POLL_INTERVAL


class Worker:
    RETRY_AFTER = 60  # пауза перед повтором неудачной синхронизации, c

    def __init__(self):
        self.ev = threading.Event()
        self.sync_pool = ThreadPoolExecutor(8, thread_name_prefix="hy-sync")
        self.poll_pool = ThreadPoolExecutor(8, thread_name_prefix="hy-poll")
        self.job_pool = ThreadPoolExecutor(4, thread_name_prefix="hy-job")
        self.lock = threading.Lock()
        self.inflight: set[int] = set()
        self.last_try: dict[int, float] = {}
        self.polling = False
        self.last_poll = 0.0
        self.last_prune = 0.0
        self.started = False

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        threading.Thread(target=self._loop, daemon=True, name="hy-worker").start()

    def wake(self) -> None:
        self.ev.set()

    def poll_now(self) -> None:
        self.last_poll = 0
        self.wake()

    def _loop(self) -> None:
        while True:
            self.ev.wait(5)
            self.ev.clear()
            try:
                self._sync_dirty()
                interval = int(db.get_setting("poll_interval", POLL_INTERVAL))
                if interval > 0 and time.time() - self.last_poll >= interval and not self.polling:
                    self.last_poll = time.time()
                    self.polling = True
                    self.poll_pool.submit(self._poll_round)
            except Exception:
                traceback.print_exc()

    def _sync_dirty(self) -> None:
        for row in db.q("SELECT id, sync_error FROM servers WHERE dirty=1 AND enabled=1"):
            sid = row["id"]
            with self.lock:
                if sid in self.inflight:
                    continue
                if row["sync_error"] and time.time() - self.last_try.get(sid, 0) < self.RETRY_AFTER:
                    continue
                self.inflight.add(sid)
                self.last_try[sid] = time.time()
            self.sync_pool.submit(self._do_sync, sid)

    def _do_sync(self, sid: int) -> None:
        from . import hy
        try:
            hy.sync_server(sid)
        except Exception:
            pass  # ошибка сохранена в servers.sync_error
        finally:
            with self.lock:
                self.inflight.discard(sid)
            self.wake()

    def _poll_round(self) -> None:
        from . import hy
        try:
            ids = [r["id"] for r in db.q("SELECT id FROM servers WHERE enabled=1")]
            futs = [self.poll_pool.submit(hy.poll_server, i) for i in ids]
            for f in futs:
                try:
                    f.result(timeout=180)
                except Exception:
                    pass
            hy.enforce_limits()
            if time.time() - self.last_prune > 3600:
                self.last_prune = time.time()
                db.ex("DELETE FROM checks WHERE ts<?", (int(time.time()) - 35 * 86400,))
        except Exception:
            traceback.print_exc()
        finally:
            self.polling = False
            self.wake()

    # ----- длительные задачи с логом -----
    def run_job(self, kind: str, sid: int | None, fn) -> int:
        jid = db.ex("INSERT INTO jobs(kind,server_id,status,log,created) VALUES(?,?,?,?,?)",
                    (kind, sid, "running", "", int(time.time())))
        self.job_pool.submit(self._job_wrap, jid, fn)
        return jid

    def _job_wrap(self, jid: int, fn) -> None:
        def log(text: str) -> None:
            db.ex("UPDATE jobs SET log=substr(log || ?, -200000) WHERE id=?", (text, jid))

        status = "ok"
        try:
            fn(log)
        except Exception as e:
            status = "error"
            log(f"\n[ОШИБКА] {e}\n")
        db.ex("UPDATE jobs SET status=?, finished=? WHERE id=?", (status, int(time.time()), jid))


worker = Worker()
