@echo off
rem Copyright (c) 2026 StackAndPointer
rem SPDX-License-Identifier: MIT
rem
rem Triggers script hot reload for injected SigilHook hosts.
rem   SigilHookReload.bat            reload every live SigilHook host
rem   SigilHookReload.bat <pid>      reload only the host with that process id
setlocal
set "SIGILHOOK_TARGET=%~1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $target=$env:SIGILHOOK_TARGET; $pipes=[System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Where-Object { $_ -match '^SigilHook(\.\d+)?$' } | Sort-Object; if ($target) { if ($target -eq 'all') { } else { $want='SigilHook.' + $target; $pipes=$pipes | Where-Object { $_ -eq $want } } }; if (-not $pipes) { Write-Host 'ERR no SigilHook pipe found'; exit 1 }; $ok=0; $failed=0; foreach ($name in @($pipes)) { try { $client=New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::In, [System.IO.Pipes.PipeOptions]::None); $client.Connect(3000); $reader=New-Object System.IO.StreamReader($client); $response=$reader.ReadLine(); $reader.Dispose(); $client.Dispose(); if ($response -and $response.StartsWith('OK')) { Write-Host ($name + ': ' + $response); $ok++ } else { Write-Host ($name + ': ERR ' + $response); $failed++ } } catch { Write-Host ($name + ': ERR ' + $_.Exception.Message); $failed++ } }; if ($ok -gt 0) { exit 0 } else { exit 2 }"
exit /b %ERRORLEVEL%
