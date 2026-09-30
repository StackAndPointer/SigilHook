// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "include/sigilhook.h"

#if defined(_WIN32)
#include <filesystem>
#include <string>
#include <windows.h>

namespace {
HMODULE g_runtimeModule = nullptr;
HANDLE g_pipeThread = nullptr;
HANDLE g_pipeStopEvent = nullptr;

constexpr wchar_t kHotReloadPipeName[] = L"\\\\.\\pipe\\SigilHook";

void disconnectAndStopPipe() {
    if (g_pipeThread == nullptr && g_pipeStopEvent == nullptr) {
        return;
    }
    if (g_pipeStopEvent != nullptr) {
        SetEvent(g_pipeStopEvent);
    }
    if (g_pipeThread != nullptr) {
        WaitForSingleObject(g_pipeThread, 5000);
        CloseHandle(g_pipeThread);
        g_pipeThread = nullptr;
    }
    if (g_pipeStopEvent != nullptr) {
        CloseHandle(g_pipeStopEvent);
        g_pipeStopEvent = nullptr;
    }
}

DWORD WINAPI hotReloadPipeThread(LPVOID) {
    while (g_pipeStopEvent == nullptr || WaitForSingleObject(g_pipeStopEvent, 0) != WAIT_OBJECT_0) {
        // A client connects and receives an acknowledgement before the reload
        // starts. The pipe is a request channel; the worker thread owns the
        // actual stop/start sequence.
        HANDLE pipe = CreateNamedPipeW(
            kHotReloadPipeName,
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            0,
            0,
            nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }
        const bool connected = ConnectNamedPipe(pipe, nullptr) != FALSE ||
            GetLastError() == ERROR_PIPE_CONNECTED;
        if (connected) {
            DWORD bytes = 0;
            WriteFile(pipe, "OK\n", 3, &bytes, nullptr);
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
            // The acknowledgement means the request arrived, not that the
            // reload succeeded. Failures are recorded by the runtime log.
            sigilhook_runtime_reload();
        }
        CloseHandle(pipe);
    }
    return 0;
}

bool startHotReloadPipe() {
    if (g_pipeThread != nullptr) return true;
    g_pipeStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_pipeStopEvent == nullptr) return false;
    DWORD threadId = 0;
    g_pipeThread = CreateThread(nullptr, 0, hotReloadPipeThread, nullptr, 0, &threadId);
    if (g_pipeThread == nullptr) {
        CloseHandle(g_pipeStopEvent);
        g_pipeStopEvent = nullptr;
        return false;
    }
    return true;
}

void stopHotReloadPipe() {
    disconnectAndStopPipe();
}

DWORD WINAPI runtimeThread(LPVOID parameter) {
    auto* instance = static_cast<HINSTANCE>(parameter);
    wchar_t path[32768] = {};
    const DWORD length = GetModuleFileNameW(instance, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
    if (length == 0) {
        if (g_runtimeModule != nullptr) FreeLibraryAndExitThread(g_runtimeModule, 0);
        return 1;
    }
    const std::filesystem::path scriptDirectory =
        std::filesystem::path(std::wstring(path, length)).parent_path() / L"SigilHook";
    const sigilhook_status startStatus = sigilhook_runtime_start(scriptDirectory.c_str());
    const sigilhook_status loadStatus =
        startStatus == SIGILHOOK_OK ? sigilhook_runtime_load_directory(scriptDirectory.c_str()) : startStatus;
    if (loadStatus != SIGILHOOK_OK) {
        // A failed auto-load must not leave AngelScript or hooks behind while
        // this bootstrap thread releases its extra module reference.
        if (startStatus == SIGILHOOK_OK) {
            sigilhook_runtime_stop();
        }
        if (g_runtimeModule != nullptr) FreeLibraryAndExitThread(g_runtimeModule, 1);
        return 1;
    }
    startHotReloadPipe();
    if (g_runtimeModule != nullptr) FreeLibraryAndExitThread(g_runtimeModule, 0);
    return 0;
}
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(instance);
        wchar_t disabled[8] = {};
        if (GetEnvironmentVariableW(L"SIGILHOOK_DISABLE_AUTOLOAD", disabled, static_cast<DWORD>(sizeof(disabled) / sizeof(disabled[0]))) > 0) {
            break;
        }
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                reinterpret_cast<LPCWSTR>(&DllMain),
                &g_runtimeModule)) {
            break;
        }
        HANDLE thread = CreateThread(nullptr, 0, runtimeThread, instance, 0, nullptr);
        if (thread == nullptr) {
            g_runtimeModule = nullptr;
            break;
        }
        CloseHandle(thread);
        break;
    }
    case DLL_PROCESS_DETACH:
        // Do not tear down AngelScript under the loader lock. The host must
        // call sigilhook_runtime_stop() before FreeLibrary.
        stopHotReloadPipe();
        break;
    default:
        break;
    }
    return TRUE;
}
#endif
