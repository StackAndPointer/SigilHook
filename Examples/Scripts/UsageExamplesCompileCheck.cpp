// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
//
// Compile-only check for the usage examples. The examples run in compile-only
// mode, which builds the module and discards it before main() executes, so no
// real target address is required. The staging copy mirrors deployment: the
// standard header is copied beside the scripts.

#include "sigilhook.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#if defined(_WIN32)
#include <process.h>
#define SIGILHOOK_TEST_PID _getpid()
#else
#include <unistd.h>
#define SIGILHOOK_TEST_PID getpid()
#endif

int main() {
    const std::filesystem::path source = SIGILHOOK_USAGE_EXAMPLE_DIRECTORY;
    const std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("SigilHookUsageExamples-" + std::to_string(SIGILHOOK_TEST_PID));
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    error.clear();
    std::filesystem::copy(source, directory,
        std::filesystem::copy_options::recursive, error);
    if (error) {
        std::cerr << "failed to stage examples: " << error.message() << '\n';
        return 1;
    }
    std::filesystem::copy_file(
        std::filesystem::path(SIGILHOOK_USAGE_HEADER), directory / "SigilHook.ash",
        std::filesystem::copy_options::overwrite_existing, error);
    if (error) {
        std::cerr << "failed to copy standard header: " << error.message() << '\n';
        return 1;
    }
    {
        std::ofstream entry(directory / "main.as", std::ios::binary | std::ios::trunc);
        entry << "#include \"SigilHook.ash\"\n"
                 "void main() {}\n"
                 "void unload() {}\n";
        if (!entry.good()) {
            std::cerr << "failed to stage compile-only entry\n";
            return 1;
        }
    }

    const std::wstring wide = directory.wstring();
    const sigilhook_status status = sigilhook_runtime_start(wide.c_str());
    if (status != SIGILHOOK_OK) {
        char buffer[1024] = {};
        sigilhook_get_last_error(buffer, sizeof(buffer));
        std::cerr << "runtime start failed: " << buffer << '\n';
        return 1;
    }
    const sigilhook_status loadStatus = sigilhook_runtime_load_directory(wide.c_str());
    if (loadStatus != SIGILHOOK_OK) {
        std::cerr << "usage examples failed to compile: " << static_cast<int>(loadStatus) << '\n';
        sigilhook_runtime_stop();
        std::filesystem::remove_all(directory, error);
        return 2;
    }
    const sigilhook_status stopStatus = sigilhook_runtime_stop();
    if (stopStatus != SIGILHOOK_OK) {
        std::cerr << "usage examples runtime stop failed: " << static_cast<int>(stopStatus) << '\n';
        std::filesystem::remove_all(directory, error);
        return 3;
    }
    std::cout << "usage examples compiled\n";
    std::filesystem::remove_all(directory, error);
    return 0;
}
