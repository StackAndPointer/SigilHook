// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Runs the user-facing UsageExamples against a synthetic target. The target
// mirrors the common "hook a function, run script code, then continue through
// the original" workflow, and also verifies the "hook A, call B" shape.

#include "sigilhook.h"

#include <Windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression << " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; sigilhook_runtime_stop(); return __LINE__; } } while (false)

namespace {

std::atomic<uint64_t> g_targetCalls{0};
std::atomic<uint64_t> g_calledFunctionCalls{0};

#if defined(_MSC_VER)
__declspec(noinline)
#endif
int SIGILHOOK_CALL usageTarget(int value) {
    g_targetCalls.fetch_add(1, std::memory_order_relaxed);
    return value + 1;
}

#if defined(_MSC_VER)
__declspec(noinline)
#endif
int SIGILHOOK_CALL usageCalledFunction(int value) {
    g_calledFunctionCalls.fetch_add(1, std::memory_order_relaxed);
    return value + 10;
}

std::filesystem::path scriptRoot() {
    return std::filesystem::temp_directory_path() /
        ("SigilHookUsageSmoke-" + std::to_string(GetCurrentProcessId()));
}

bool writeFile(const std::filesystem::path& path, const std::string& text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << text;
    return output.good();
}

bool copyStandardHeader(const std::filesystem::path& directory) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error) return false;
    std::filesystem::copy_file(
        std::filesystem::path(SIGILHOOK_USAGE_HEADER),
        directory / "SigilHook.ash",
        std::filesystem::copy_options::overwrite_existing,
        error);
    return !error;
}

std::string mainSource() {
    return
        "#include \"SigilHook.ash\"\n"
        "uint64 g_entryHook = SH_INVALID_HANDLE;\n"
        "uint64 g_entryCalls = 0;\n"
        "\n"
        "void onEntryDetour() {\n"
        "    g_entryCalls++;\n"
        "    shSetSharedU64(\"entryCalls\", g_entryCalls);\n"
        "    shSetArg(0, shArg(0) + 100);\n"
        "    shKeepOriginal();\n"
        "}\n"
        "\n"
        "void onCallAnother() {\n"
        "    array<uint64> args(1);\n"
        "    args[0] = 5;\n"
        "    uint64 result = 0;\n"
        "    const uint8 status = shCallUsercall(\n"
        "        shSharedU64(\"calledFunction\"), \"int\", \"int\", \"usercall:arg0=rcx;ret=rax\",\n"
        "        args, result);\n"
        "    if (status != SH_OK) shLog(\"usage called-function invocation failed\");\n"
        "}\n"
        "\n"
        "void main() {\n"
        "    g_entryHook = shHookScript(\n"
        "        shSharedU64(\"target\"), \"void onEntryDetour()\", \"int:int\");\n"
        "    if (!shIsValidHook(g_entryHook)) return;\n"
        "    onCallAnother();\n"
        "}\n"
        "\n"
        "void unload() {\n"
        "    if (shIsValidHook(g_entryHook)) shDestroyHook(g_entryHook);\n"
        "}\n";
}

} // namespace

int main() {
    const std::filesystem::path root = scriptRoot();
    std::error_code error;
    std::filesystem::remove_all(root, error);
    const bool copiedHeader = copyStandardHeader(root);
    if (!copiedHeader) {
        std::wcerr << L"standard header copy failed from " << SIGILHOOK_USAGE_HEADER << L'\n';
        return 1;
    }
    CHECK(writeFile(root / "main.as", mainSource()));

    CHECK(sigilhook_runtime_start(root.c_str()) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("target",
        reinterpret_cast<uint64_t>(&usageTarget)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64("calledFunction",
        reinterpret_cast<uint64_t>(&usageCalledFunction)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_load_directory(root.c_str()) == SIGILHOOK_OK);

    // onCallAnother() calls B first (5 + 10) and ignores its result, then the
    // entry detour changes the original argument to 101. The visible result is
    // the original function's result: 102.
    CHECK(usageTarget(1) == 102);
    CHECK(g_targetCalls.load(std::memory_order_relaxed) == 1);
    CHECK(g_calledFunctionCalls.load(std::memory_order_relaxed) == 1);

    uint64_t entryCalls = 0;
    CHECK(sigilhook_runtime_get_shared_u64("entryCalls", &entryCalls) == SIGILHOOK_OK);
    CHECK(entryCalls == 1);

    CHECK(sigilhook_runtime_stop() == SIGILHOOK_OK);
    std::filesystem::remove_all(root, error);
    return 0;
}
