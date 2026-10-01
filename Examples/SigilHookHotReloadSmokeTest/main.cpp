// Copyright (c) 2026 StackAndPointer
// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression " at line " << __LINE__ << '\n'; sigilhook_runtime_stop(); return __LINE__; } } while (false)

namespace {

std::filesystem::path scriptRoot() {
    return std::filesystem::temp_directory_path() /
        ("SigilHookHotReload-" + std::to_string(GetCurrentProcessId()));
}

bool writeFile(const std::filesystem::path& path, const std::string& text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << text;
    return output.good();
}

bool copyHeader(const std::filesystem::path& directory) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error) return false;
    std::filesystem::copy_file(
        std::filesystem::path(SIGILHOOK_TEST_SCRIPT_DIRECTORY) / "SigilHook.ash",
        directory / "SigilHook.ash",
        std::filesystem::copy_options::overwrite_existing,
        error);
    return !error;
}

std::string mainSource(int generation) {
    return
        "#include \"SigilHook.ash\"\n"
        "void main() {\n"
        "    shSetSharedU64(\"generation\", " + std::to_string(generation) + ");\n"
        "    shSetSharedU64(\"mainRuns\", shSharedU64(\"mainRuns\") + 1);\n"
        "}\n"
        "void unload() {\n"
        "    shSetSharedU64(\"unloadRuns\", shSharedU64(\"unloadRuns\") + 1);\n"
        "}\n";
}

std::string malformedMainSource() {
    return
        "#include \"SigilHook.ash\"\n"
        "void main() {\n"
        "    this is not valid AngelScript;\n"
        "}\n";
}

} // namespace

int main() {
    const std::filesystem::path root = scriptRoot();
    std::error_code error;
    std::filesystem::remove_all(root, error);
    error.clear();
    CHECK(copyHeader(root));
    CHECK(writeFile(root / "main.as", mainSource(1)));

    CHECK(sigilhook_runtime_start(root.c_str()) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_load_directory(root.c_str()) == SIGILHOOK_OK);

    uint64_t generation = 0;
    CHECK(sigilhook_runtime_get_shared_u64("generation", &generation) == SIGILHOOK_OK);
    CHECK(generation == 1);

    // Direct C ABI reload must re-run main() from the on-disk script.
    CHECK(writeFile(root / "main.as", mainSource(2)));
    CHECK(sigilhook_runtime_reload() == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_get_shared_u64("generation", &generation) == SIGILHOOK_OK);
    CHECK(generation == 2);

    uint64_t mainRuns = 0;
    uint64_t unloadRuns = 0;
    CHECK(sigilhook_runtime_get_shared_u64("mainRuns", &mainRuns) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_get_shared_u64("unloadRuns", &unloadRuns) == SIGILHOOK_OK);
    CHECK(mainRuns == 2);
    CHECK(unloadRuns == 1);

    // A successful reload can be repeated and does not duplicate the entry.
    CHECK(writeFile(root / "main.as", mainSource(3)));
    CHECK(sigilhook_runtime_reload_with_timeout(5000) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_get_shared_u64("generation", &generation) == SIGILHOOK_OK);
    CHECK(generation == 3);
    CHECK(sigilhook_runtime_get_shared_u64("mainRuns", &mainRuns) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_get_shared_u64("unloadRuns", &unloadRuns) == SIGILHOOK_OK);
    CHECK(mainRuns == 3);
    CHECK(unloadRuns == 2);

    // A failed compile must leave the runtime available for a later retry.
    CHECK(writeFile(root / "main.as", "void main() { this is not valid AngelScript; }\n"));
    CHECK(sigilhook_runtime_reload() == SIGILHOOK_ERROR_SCRIPT);
    CHECK(sigilhook_runtime_reload() == SIGILHOOK_ERROR_SCRIPT);
    CHECK(writeFile(root / "main.as", mainSource(3)));
    CHECK(sigilhook_runtime_reload() == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_get_shared_u64("generation", &generation) == SIGILHOOK_OK);
    CHECK(generation == 3);

    // main() runs once more after recovery while the generation counter stays
    // on the recovered value.
    uint64_t finalMainRuns = 0;
    CHECK(sigilhook_runtime_get_shared_u64("mainRuns", &finalMainRuns) == SIGILHOOK_OK);
    CHECK(finalMainRuns == 4);

    CHECK(sigilhook_runtime_stop() == SIGILHOOK_OK);
    std::filesystem::remove_all(root, error);
    return 0;
}
