# Установка панели как фоновой службы Windows (через Планировщик заданий).
# Запускать из PowerShell от имени администратора в каталоге проекта:
#   powershell -ExecutionPolicy Bypass -File deploy\install-windows.ps1
param(
    [string]$TaskName = "Hy2Panel",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "== Каталог проекта: $Root"
$Py = "$Root\.venv\Scripts\python.exe"
# .venv, скопированный с другого компьютера, не работает — пересоздаём
$venvOk = $false
if (Test-Path $Py) { try { & $Py -c "import sys" 2>$null; $venvOk = ($LASTEXITCODE -eq 0) } catch {} }
if (-not $venvOk) {
    Write-Host "== Создаю виртуальное окружение"
    if (Test-Path "$Root\.venv") { Remove-Item -Recurse -Force "$Root\.venv" }
    & $Python -m venv "$Root\.venv"
    if ($LASTEXITCODE -ne 0) { throw "Не удалось создать venv. Установлен ли Python и есть ли он в PATH?" }
}
& $Py -m pip install --upgrade pip | Out-Null
& $Py -m pip install -r "$Root\requirements.txt"

if (-not (Test-Path "$Root\.env")) {
    Copy-Item "$Root\.env.example" "$Root\.env"
    Write-Host "== Создан .env из примера — проверьте HY_BASE_PATH / HY_HOST / HY_PUBLIC_URL" -ForegroundColor Yellow
}

# Каталог data: доступ только SYSTEM и администраторам (там БД, ключ шифрования и SSH-ключ панели)
New-Item -ItemType Directory -Force "$Root\data" | Out-Null
# SID вместо имён: на русской Windows группа называется «Администраторы»
icacls "$Root\data" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

$admins = & $Py -c "from app import db; db.init(); print(len(db.q('SELECT 1 FROM admins')))"
if ($null -eq $admins) { throw "Python из .venv не запускается" }
if ("$admins".Trim() -eq "0") {
    $name = Read-Host "Логин администратора панели"
    & $Py manage.py create-admin $name
}

Write-Host "== Регистрирую задачу планировщика $TaskName (автозапуск, перезапуск при сбое)"
$action = New-ScheduledTaskAction -Execute "$Root\.venv\Scripts\pythonw.exe" -Argument "run.py" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep 3

$envText = Get-Content "$Root\.env" -Raw
$port = if ($envText -match "HY_PORT=(\d+)") { $Matches[1] } else { "8088" }
$hostAddr = if ($envText -match "HY_HOST=([^\r\n]+)") { $Matches[1].Trim() } else { "127.0.0.1" }
if ($hostAddr -eq "0.0.0.0") { $hostAddr = "127.0.0.1" }
$bp = if ($envText -match "HY_BASE_PATH=([^\r\n]*)") { $Matches[1].Trim().TrimEnd("/") } else { "" }
try {
    $r = Invoke-WebRequest -UseBasicParsing "http://${hostAddr}:$port$bp/login" -TimeoutSec 5
    Write-Host "== Панель отвечает: HTTP $($r.StatusCode) на http://${hostAddr}:$port$bp/" -ForegroundColor Green
} catch {
    Write-Host "== Панель пока не отвечает: $_" -ForegroundColor Yellow
}
Write-Host "Дальше: добавьте фрагмент deploy\nginx-hy2panel.conf в конфиг nginx и выполните nginx -s reload"
