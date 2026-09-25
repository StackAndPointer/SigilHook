#include "include/sigilhook.h"

#if defined(_WIN32)
#include <filesystem>
#include <windows.h>

namespace {
DWORD WINAPI runtimeThread(LPVOID parameter) {
    auto* instance = static_cast<HINSTANCE>(parameter);
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(instance, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0) return 1;
    path.resize(length);
    const std::filesystem::path scriptDirectory = std::filesystem::path(path).parent_path() / L"SigilHook";
    sigilhook_runtime_start(scriptDirectory.c_str());
    sigilhook_runtime_load_directory(scriptDirectory.c_str());
    return 0;
}
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(instance);
        wchar_t disabled[8];
        if (GetEnvironmentVariableW(L"SIGILHOOK_DISABLE_AUTOLOAD", disabled, 8) > 0) break;
        CreateThread(nullptr, 0, runtimeThread, instance, 0, nullptr);
        break;
    }
    case DLL_PROCESS_DETACH:
        sigilhook_runtime_stop();
        break;
    default:
        break;
    }
    return TRUE;
}
#endif


