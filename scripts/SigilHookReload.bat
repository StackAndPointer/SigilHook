@echo off
rem Copyright (c) 2026 StackAndPointer
rem SPDX-License-Identifier: MIT
setlocal
set "SIGILHOOK_PIPE=SigilHook"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $client=New-Object System.IO.Pipes.NamedPipeClientStream('.', $env:SIGILHOOK_PIPE, [System.IO.Pipes.PipeDirection]::In, [System.IO.Pipes.PipeOptions]::None); try { $client.Connect(3000) } catch { Write-Host ('ERR pipe unavailable: ' + $_.Exception.Message); exit 2 }; $reader=New-Object System.IO.StreamReader($client); $response=$reader.ReadLine(); $reader.Dispose(); $client.Dispose(); if ($null -eq $response) { Write-Host 'ERR no response'; exit 3 }; Write-Host $response; if (-not $response.StartsWith('OK')) { exit 1 }"
exit /b %ERRORLEVEL%
