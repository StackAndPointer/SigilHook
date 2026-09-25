// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#include <cstdint>
#include <iostream>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression << " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; return __LINE__; } } while (false)

namespace {
volatile int g_targetCalls = 0;

#if defined(_MSC_VER)
__declspec(noinline)
#endif
int SIGILHOOK_CALL target(int value) {
    volatile int result = value;
    for (int index = 0; index < 8; ++index) {
        result = result + (index - index);
    }
    ++g_targetCalls;
    return result + 1;
}
}

int main() {
    CHECK(sigilhook_runtime_start(nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_set_shared_u64(
        "target", reinterpret_cast<uint64_t>(&target)) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_load_directory(SIGILHOOK_TEST_SCRIPT_DIRECTORY) == SIGILHOOK_OK);
    CHECK(sigilhook_runtime_call_entry("void verify()") == SIGILHOOK_OK);
    CHECK(target(1) == 77);
    CHECK(g_targetCalls == 0);
    CHECK(sigilhook_runtime_stop() == SIGILHOOK_OK);
    return 0;
}
