// Кабинет клиента: тема (тёмная/светлая) и акцентный цвет.
// Ключи localStorage те же, что у главной страницы сайта (v2-theme, bred-accent): если панель живёт
// на том же домене, кабинет выглядит так же, как сайт, а переключение темы здесь меняет её и там.
(function () {
  var root = document.documentElement;
  root.classList.add("portal");
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* приватный режим */ } }
  };
  var t = store.get("v2-theme");
  if (t === "light" || t === "dark") root.dataset.theme = t;

  var c = store.get("bred-accent");
  if (c && /^#[0-9a-f]{6}$/i.test(c)) {
    var n = parseInt(c.slice(1), 16);
    var light = (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) > 150;
    root.style.setProperty("--accent", c);
    root.style.setProperty("--accent-ink", light ? "#0c0d0b" : "#ffffff");
    root.style.setProperty("--ink-rgb", light ? "12,13,11" : "255,255,255");
  }

  function current() {
    if (root.dataset.theme) return root.dataset.theme;
    return window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.addEventListener("DOMContentLoaded", function () {
    var b = document.getElementById("themeBtn");
    if (!b) return;
    b.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      store.set("v2-theme", next);
    });
  });
})();
