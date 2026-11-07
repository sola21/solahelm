"""Сайт-заглушка для VPS: страница входа в веб-интерфейс сетевого устройства. Вход всегда «не удаётся» (проверка только в браузере, на сервер ничего не уходит)."""

# фон: тёмный градиент с сеткой узлов и «волнами», целиком в SVG (без внешних запросов)
_BG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1600 900' preserveAspectRatio='xMidYMid slice'>"
    "<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='%230b2545'/>"
    "<stop offset='.55' stop-color='%2313315c'/><stop offset='1' stop-color='%23134074'/></linearGradient>"
    "<radialGradient id='r' cx='.78' cy='.25' r='.6'><stop offset='0' stop-color='%238da9c4' stop-opacity='.35'/>"
    "<stop offset='1' stop-color='%238da9c4' stop-opacity='0'/></radialGradient></defs>"
    "<rect width='1600' height='900' fill='url(%23g)'/><rect width='1600' height='900' fill='url(%23r)'/>"
    "<g fill='none' stroke='%238da9c4' stroke-opacity='.18' stroke-width='1.2'>"
    "<path d='M0 640 C240 560 420 740 700 660 S1180 540 1600 640'/>"
    "<path d='M0 700 C260 620 460 800 740 720 S1200 600 1600 700'/>"
    "<path d='M0 760 C280 680 500 860 780 780 S1220 660 1600 760'/></g>"
    "<g fill='none' stroke='%238da9c4' stroke-opacity='.22' stroke-width='1'>"
    "<path d='M170 140L360 250L560 120L760 260L980 150L1180 290L1400 170'/>"
    "<path d='M360 250L430 430L620 380L760 260M620 380L820 470L1040 400L1180 290M820 470L900 620'/></g>"
    "<g fill='%23c9d6e6' fill-opacity='.55'>"
    "<circle cx='170' cy='140' r='4'/><circle cx='360' cy='250' r='5'/><circle cx='560' cy='120' r='4'/>"
    "<circle cx='760' cy='260' r='5'/><circle cx='980' cy='150' r='4'/><circle cx='1180' cy='290' r='5'/>"
    "<circle cx='1400' cy='170' r='4'/><circle cx='430' cy='430' r='4'/><circle cx='620' cy='380' r='4'/>"
    "<circle cx='820' cy='470' r='5'/><circle cx='1040' cy='400' r='4'/><circle cx='900' cy='620' r='4'/></g></svg>"
)

ROUTER_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NX-AX3000 | Sign in</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23134074'/%3E%3Cpath d='M6 22a14 14 0 0 1 20 0M10 18a8 8 0 0 1 12 0' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round'/%3E%3Ccircle cx='16' cy='24' r='2' fill='%23fff'/%3E%3C/svg%3E">
<style>
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;display:flex;flex-direction:column;font:14px/1.45 "Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d2a3a;
background:#0b2545 url("data:image/svg+xml,__BG__") center/cover no-repeat fixed}
header{padding:22px 34px;display:flex;align-items:center;gap:12px;color:#fff}
.logo{width:34px;height:34px}
header b{font-size:20px;letter-spacing:.5px}header span{opacity:.7;font-size:13px;margin-left:6px}
main{flex:1;display:flex;align-items:center;justify-content:center;padding:20px}
.card{width:380px;max-width:100%;background:rgba(255,255,255,.97);border-radius:8px;box-shadow:0 18px 50px rgba(0,0,0,.35);padding:30px 32px 26px}
.model{font-size:12px;letter-spacing:1.2px;text-transform:uppercase;color:#5c6f86;margin:0 0 4px}
h1{margin:0 0 20px;font-size:22px;font-weight:600;color:#0b2545}
label{display:block;font-size:12.5px;color:#4a5a6e;margin:0 0 5px}
input[type=text],input[type=password]{width:100%;padding:10px 12px;border:1px solid #b7c3d3;border-radius:4px;font-size:14px;margin-bottom:15px;background:#fff}
input:focus{outline:0;border-color:#134074;box-shadow:0 0 0 3px rgba(19,64,116,.18)}
.row{display:flex;justify-content:space-between;align-items:center;font-size:12.5px;color:#4a5a6e;margin:-3px 0 18px}
.row a{color:#134074;text-decoration:none;cursor:pointer}
button{width:100%;padding:11px;border:0;border-radius:4px;background:#134074;color:#fff;font-size:14.5px;font-weight:600;cursor:pointer}
button:hover{background:#0f3560}button:disabled{background:#7f98b5;cursor:default}
.err{display:none;margin:0 0 16px;padding:9px 11px;background:#fdecea;border:1px solid #f1b5af;color:#a32a20;border-radius:4px;font-size:13px}
.st{margin-top:18px;padding-top:14px;border-top:1px solid #e3e9f0;display:flex;justify-content:space-between;font-size:11.5px;color:#6b7c93}
.st i{display:inline-block;width:7px;height:7px;border-radius:50%;background:#2e9e5b;margin-right:5px}
footer{padding:16px;text-align:center;font-size:11.5px;color:#b8c7da}
</style></head><body>
<header>
<svg class="logo" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#fff" fill-opacity=".14"/><path d="M6 22a14 14 0 0 1 20 0M10 18a8 8 0 0 1 12 0" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="16" cy="24" r="2" fill="#fff"/></svg>
<b>NEXORA</b><span>Network Devices</span>
</header>
<main><div class="card">
<p class="model">NX-AX3000 &middot; Dual-Band Gigabit Router</p>
<h1>Sign in to continue</h1>
<form id="f" autocomplete="off">
<div id="e" class="err" role="alert"></div>
<label for="u">Username</label><input id="u" name="u" type="text" autocapitalize="off" spellcheck="false" autofocus>
<label for="p">Password</label><input id="p" name="p" type="password">
<div class="row"><label style="margin:0"><input type="checkbox" style="vertical-align:-2px"> Keep me signed in</label><a>Forgot password?</a></div>
<button id="b" type="submit">Sign In</button>
</form>
<div class="st"><span><i></i>WAN: Connected</span><span>Firmware 3.0.4.218</span></div>
</div></main>
<footer>&copy; 2024 Nexora Network Devices. All rights reserved.</footer>
<script>
var n=0,f=document.getElementById('f'),e=document.getElementById('e'),b=document.getElementById('b'),p=document.getElementById('p');
f.addEventListener('submit',function(x){x.preventDefault();b.disabled=true;b.textContent='Signing in\\u2026';e.style.display='none';
setTimeout(function(){n++;p.value='';
if(n>=5){e.textContent='Too many failed login attempts. Please try again in 5 minutes.';e.style.display='block';b.textContent='Locked';setTimeout(function(){n=0;b.disabled=false;b.textContent='Sign In'},300000);return}
e.textContent='Incorrect username or password. Please try again.';e.style.display='block';b.disabled=false;b.textContent='Sign In';p.focus()},800+Math.random()*600)});
</script></body></html>""".replace("__BG__", _BG)
