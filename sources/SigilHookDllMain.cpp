// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "include/sigilhook.h"

#if defined(_WIN32)
#include <filesystem>
#include <windows.h>

namespace {
HMODULE g_runtimeModule = nullptr;

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
    sigilhook_runtime_start(scriptDirectory.c_str());
    sigilhook_runtime_load_directory(scriptDirectory.c_str());
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
        // Do not stop the runtime under the loader lock. Hosts must call
        // sigilhook_runtime_stop() successfully before FreeLibrary.
        break;
    default:
        break;
    }
    return TRUE;
}
#endif
