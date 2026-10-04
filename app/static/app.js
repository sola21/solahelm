(() => {
  "use strict";
  const BASE = document.body.dataset.base || "";
  const CSRF = document.body.dataset.csrf || "";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  // ---- перевод строк интерфейса: словарь window.I18N_EN подключает сервер, только если выбран английский ----
  const I18N = window.I18N_EN || {};
  const I18N_KEYS = Object.keys(I18N).sort((a, b) => b.length - a.length);
  const I18N_RX = I18N_KEYS.length
    ? new RegExp(I18N_KEYS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+")).join("|"), "g")
    : null;
  const T = (s) => (I18N_RX && typeof s === "string" ? s.replace(I18N_RX, (m) => I18N[m.replace(/\s+/g, " ")] || m) : s);
  const ask = (m) => window.confirm(T(m));

  let toastTimer;
  function toast(msg, isErr) {
    const t = $("#toast");
    t.textContent = T(msg);
    t.className = "toast" + (isErr ? " err" : "");
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), isErr ? 12000 : 5000);
  }

  async function api(path, opts = {}) {
    const init = { method: opts.method || "POST", headers: { "X-CSRF-Token": CSRF }, credentials: "same-origin" };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    const res = await fetch(BASE + path, init);
    let data;
    try { data = await res.json(); } catch { data = { ok: false, error: "HTTP " + res.status }; }
    if (res.status === 401) { location.href = BASE + "/login?next=" + encodeURIComponent(location.pathname); }
    if (!data.ok && !data.error) data.error = data.detail || "Ошибка";
    return data;
  }

  function out(text, isErr) {
    const o = $("#out");
    if (!o) return toast(text, isErr);
    o.hidden = false;
    o.textContent = T(text);
    o.classList.toggle("err", !!isErr);
    o.scrollIntoView({ block: "nearest" });
  }

  async function busy(btn, fn) {
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "⏳ " + label;
    try { await fn(); } finally { btn.disabled = false; btn.textContent = label; }
  }

  // ---- запоминание введённого в формах: не пропадает после «Назад» из консоли задачи ----
  $$("form[data-persist]").forEach((f) => {
    const key = "hy2form:" + f.dataset.persist;
    const fields = () => $$("input, select, textarea", f).filter((e) => e.name && !["password", "hidden", "file"].includes(e.type));
    try {
      const saved = JSON.parse(localStorage.getItem(key) || "null");
      if (saved) fields().forEach((e) => {
        if (!(e.name in saved)) return;
        if (e.type === "checkbox") e.checked = !!saved[e.name]; else e.value = saved[e.name];
      });
    } catch {}
    const save = () => {
      try {
        const o = {};
        fields().forEach((e) => (o[e.name] = e.type === "checkbox" ? e.checked : e.value));
        localStorage.setItem(key, JSON.stringify(o));
      } catch {}
    };
    f.addEventListener("input", save);
    f.addEventListener("change", save);
  });

  // ---- результат действия, пережившего перезагрузку ----
  try {
    const f = JSON.parse(sessionStorage.getItem("hy2flash") || "null");
    sessionStorage.removeItem("hy2flash");
    if (f) out(f.text, f.err);
  } catch {}

  // ---- копирование ----
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    const el = $(b.dataset.copy);
    const text = el ? (el.value || el.textContent).trim() : "";
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    toast("Скопировано");
  });

  // ---- подтверждение форм ----
  $$("form[data-confirm]").forEach((f) =>
    f.addEventListener("submit", (e) => { if (!ask(f.dataset.confirm)) e.preventDefault(); })
  );

  // ---- кнопки API ----
  $$("[data-api]").forEach((b) =>
    b.addEventListener("click", () => {
      if (b.dataset.confirm && !ask(b.dataset.confirm)) return;
      busy(b, async () => {
        const d = await api(b.dataset.api);
        const text = d.ok ? d.msg || (d.status ? "Сервер доступен, данные обновлены" : "Готово") : d.error;
        out(text, !d.ok);
        if (d.ok && b.dataset.reload) {
          // сохраняем результат, чтобы показать его и после перезагрузки страницы
          try { sessionStorage.setItem("hy2flash", JSON.stringify({ text, err: false })); } catch {}
          setTimeout(() => location.reload(), +b.dataset.reload);
        }
      });
    })
  );

  // ---- длительные задачи ----
  $$("[data-job]").forEach((b) =>
    b.addEventListener("click", () => {
      if (b.dataset.confirm && !ask(b.dataset.confirm)) return;
      busy(b, async () => {
        const d = await api(b.dataset.job);
        if (d.ok) location.href = d.url; else out(d.error, true);
      });
    })
  );

  // ---- журнал ----
  $$("[data-logs]").forEach((b) =>
    b.addEventListener("click", () =>
      busy(b, async () => {
        const d = await api(b.dataset.logs + "?n=300", { method: "GET" });
        out(d.ok ? d.text || "(пусто)" : d.error, !d.ok);
        const o = $("#out"); if (o) o.scrollTop = o.scrollHeight;
      })
    )
  );

  // ---- редактор конфига ----
  const cfgBox = $("#cfgbox");
  $$("[data-config]").forEach((b) =>
    b.addEventListener("click", () =>
      busy(b, async () => {
        const d = await api(b.dataset.config, { method: "GET" });
        if (!d.ok) return out(d.error, true);
        $("#cfgtext").value = d.text;
        $("#cfgsave").dataset.url = b.dataset.save || b.dataset.config;
        $("#cfgtitle").textContent = b.dataset.title || "";
        cfgBox.hidden = false;
        $("#cfgtext").focus();
        cfgBox.scrollIntoView({ block: "nearest" });
      })
    )
  );
  const cfgSave = $("#cfgsave");
  if (cfgSave) {
    cfgSave.addEventListener("click", () => {
      if (!ask("Сохранить config.yaml и перезапустить службу?")) return;
      busy(cfgSave, async () => {
        const d = await api(cfgSave.dataset.url, { body: { text: $("#cfgtext").value } });
        out(d.ok ? d.msg : d.error, !d.ok);
      });
    });
    $("#cfgclose").addEventListener("click", () => (cfgBox.hidden = true));
    $("#cfgtext").addEventListener("keydown", (e) => {
      if (e.key === "Tab") {
        e.preventDefault();
        const t = e.target, s = t.selectionStart;
        t.setRangeText("  ", s, t.selectionEnd, "end");
      }
    });
  }

  // ---- установка ----
  const prov = $("#provision");
  if (prov) {
    prov.addEventListener("submit", (e) => {
      e.preventDefault();
      if (!ask("Запустить установку Hysteria2 на сервер? Текущий config.yaml будет заменён (бэкап сохранится).")) return;
      const fd = new FormData(prov);
      const body = {
        domain: fd.get("domain"), email: fd.get("email"), port: +fd.get("port"),
        upgrade: fd.has("upgrade"), ufw: fd.has("ufw"), assign_all: fd.has("assign_all"), obfs: fd.has("obfs"),
      };
      const btn = prov.querySelector("button");
      busy(btn, async () => {
        const d = await api(prov.dataset.url, { body });
        if (d.ok) location.href = d.url; else out(d.error, true);
      });
    });
  }

  // ---- подтверждение для кнопок внутри форм ----
  $$("[data-confirm-btn]").forEach((b) =>
    b.addEventListener("click", (e) => { if (!ask(b.dataset.confirmBtn)) e.preventDefault(); })
  );

  // ---- матрица доступа: профили × серверы ----
  const matrix = $("#access");
  if (matrix) {
    const recount = () =>
      $$("tbody tr", matrix).forEach((tr) => {
        tr.querySelector(".cnt").textContent = $$("input[type=checkbox]:checked", tr).length;
      });
    const send = async (changes) => {
      const d = await api("/api/access", { body: { changes } });
      toast(d.ok ? d.msg : d.error, !d.ok);
      return d.ok;
    };
    matrix.addEventListener("change", async (e) => {
      const cb = e.target.closest("input[data-u]");
      if (!cb) return;
      const ok = await send([{ user_id: +cb.dataset.u, server_id: +cb.dataset.s, on: cb.checked }]);
      if (!ok) cb.checked = !cb.checked;
      recount();
    });
    matrix.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-bulk]");
      if (!b) return;
      const [kind, id] = b.dataset.bulk.split(":");
      const on = b.dataset.on === "1";
      const sel = kind === "row" ? `input[data-u="${id}"]` : `input[data-s="${id}"]`;
      const boxes = $$(sel, matrix).filter((x) => x.checked !== on && x.closest("tr").style.display !== "none");
      if (!boxes.length) return toast("Уже так и есть");
      const what = kind === "row" ? "у этого профиля" : "на этом сервере";
      if (!ask((on ? "Дать доступ" : "Снять доступ") + ` ${what}: изменений ${boxes.length}. Продолжить?`)) return;
      const ok = await send(boxes.map((x) => ({ user_id: +x.dataset.u, server_id: +x.dataset.s, on })));
      if (ok) boxes.forEach((x) => (x.checked = on));
      recount();
    });
    const flt = $("#accessfilter");
    if (flt) flt.addEventListener("input", () => {
      const q = flt.value.trim().toLowerCase();
      $$("tbody tr", matrix).forEach((tr) => (tr.style.display = !q || tr.dataset.name.toLowerCase().includes(q) ? "" : "none"));
    });
    recount();
  }

  // ---- шаблоны маршрутизации: загрузка файла и предпросмотр ----
  const tplFile = $("#tplfile");
  if (tplFile) {
    tplFile.addEventListener("change", () => {
      const f = tplFile.files[0];
      if (!f) return;
      if (f.size > 300000) return toast("Файл слишком большой", true);
      const rd = new FileReader();
      rd.onload = () => {
        $("#tpltext").value = rd.result;
        const nm = $("input[name=name]");
        if (nm && !nm.value) nm.value = f.name.replace(/\.(ya?ml|txt)$/i, "");
        toast("Файл загружен. Нажмите «Добавить/Сохранить»: лишнее (proxies) панель уберёт сама.");
      };
      rd.readAsText(f, "utf-8");
    });
  }
  $$("[data-preview]").forEach((b) =>
    b.addEventListener("click", () =>
      busy(b, async () => {
        const d = await api(b.dataset.preview, { method: "GET" });
        out(d.ok ? d.text : d.error, !d.ok);
      })
    )
  );

  // ---- установка sing-box ----
  const provSb = $("#provision-sb");
  if (provSb) {
    provSb.addEventListener("submit", (e) => {
      e.preventDefault();
      if (!ask("Установить/применить sing-box на сервере? Существующий конфиг sing-box сохранится в бэкап, Hysteria2 не затрагивается.")) return;
      const fd = new FormData(provSb);
      const body = {
        vless: fd.has("vless"), anytls: fd.has("anytls"), ufw: fd.has("ufw"), assign_all: fd.has("assign_all"),
        vless_port: +fd.get("vless_port"), anytls_port: +fd.get("anytls_port"),
        reality_sni: fd.get("reality_sni"), anytls_domain: fd.get("anytls_domain"), anytls_cert: fd.get("anytls_cert"),
      };
      busy(provSb.querySelector("button"), async () => {
        const d = await api(provSb.dataset.url, { body });
        if (d.ok) location.href = d.url; else out(d.error, true);
      });
    });
  }

  // ---- отключение клиента ----
  $$("[data-kick]").forEach((b) =>
    b.addEventListener("click", () => {
      if (!ask("Разорвать подключения " + b.dataset.user + "?")) return;
      busy(b, async () => {
        const d = await api(b.dataset.kick, { body: { user: b.dataset.user } });
        toast(d.ok ? d.msg : d.error, !d.ok);
      });
    })
  );

  // ---- формы профиля ----
  $$("[data-genpw]").forEach((b) =>
    b.addEventListener("click", () => {
      const abc = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      const arr = new Uint32Array(20);
      crypto.getRandomValues(arr);
      $(b.dataset.genpw).value = Array.from(arr, (x) => abc[x % abc.length]).join("");
    })
  );
  $$("[data-days]").forEach((b) =>
    b.addEventListener("click", () => {
      const inp = $(b.dataset.target), days = +b.dataset.days;
      if (!days) { inp.value = ""; return; }
      const today = new Date(); today.setHours(0, 0, 0, 0);
      let base = inp.value ? new Date(inp.value + "T00:00:00") : today;
      if (base < today) base = today;
      base.setDate(base.getDate() + days);
      const p = (n) => String(n).padStart(2, "0");
      inp.value = `${base.getFullYear()}-${p(base.getMonth() + 1)}-${p(base.getDate())}`;
    })
  );
  $$("[data-checkall]").forEach((b) =>
    b.addEventListener("click", () => {
      const boxes = $$(`input[name="${b.dataset.checkall}"]`);
      const all = boxes.every((x) => x.checked);
      boxes.forEach((x) => (x.checked = !all));
    })
  );

  // ---- способ входа SSH ----
  const authSel = $("[data-toggle-auth]");
  if (authSel) {
    const upd = () => $$("[data-auth]").forEach((d) => (d.hidden = d.dataset.auth !== authSel.value));
    authSel.addEventListener("change", upd);
    upd();
  }

  // ---- лог задачи ----
  const jl = $("#joblog");
  if (jl && jl.dataset.running === "1") {
    const tick = async () => {
      const d = await api("/api/jobs/" + jl.dataset.job, { method: "GET" });
      if (!d.ok) return;
      const stick = jl.scrollTop + jl.clientHeight >= jl.scrollHeight - 30;
      jl.textContent = d.log;
      if (stick) jl.scrollTop = jl.scrollHeight;
      const st = $("#jobstatus");
      st.textContent = d.status;
      st.className = "badge " + ({ ok: "ok", error: "err", running: "warn" }[d.status] || "");
      if (d.status === "running") setTimeout(tick, 1500);
    };
    jl.scrollTop = jl.scrollHeight;
    setTimeout(tick, 1000);
  }
})();
