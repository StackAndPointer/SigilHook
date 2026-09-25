// SPDX-License-Identifier: MIT
#include "sigilhook.h"

#include <cstdint>
#include <iostream>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "check failed: " #expression << " at line " << __LINE__ << '\n'; char error[1024] = {}; sigilhook_get_last_error(error, sizeof(error)); std::cerr << error << '\n'; return __LINE__; } } while (false)

namespace {
int g_testMode = 0;
volatile int g_targetCalls = 0;
volatile int g_badArgumentValues = 0;

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

void SIGILHOOK_CALL callback(sigilhook_call_frame* frame, void*) {
    if (frame->argument_count != 1 || frame->arguments[0] != 1) {
        ++g_badArgumentValues;
    }
    frame->arguments[0] = 41;
    switch (g_testMode) {
    case 0:
        *frame->return_value = 42;
        *frame->return_value_overridden = 1;
        break;
    case 1:
        *frame->return_value = 99;
        *frame->return_value_overridden = 1;
        *frame->call_original = 0;
        break;
    case 2:
        *frame->call_original = 1;
        break;
    default:
        break;
    }
}
}

int main() {
    CHECK(sigilhook_api_version() >= 0x00020002);
    sigilhook_jit_handle jit{};
    uint64_t callbackAddress = 0;
    CHECK(sigilhook_create_jit_callback(
        "int", "int", "cdecl", callback, nullptr, &jit, &callbackAddress) == SIGILHOOK_OK);
    sigilhook_handle hook{};
    uint64_t trampoline = 0;
    CHECK(sigilhook_create_detour(
        reinterpret_cast<uint64_t>(&target), callbackAddress, &hook, &trampoline) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(hook, jit, nullptr) == SIGILHOOK_OK);
    sigilhook_handle secondHook{};
    CHECK(sigilhook_create_detour(
        reinterpret_cast<uint64_t>(&target), callbackAddress, &secondHook, nullptr) == SIGILHOOK_OK);
    CHECK(sigilhook_bind_detour_to_jit(secondHook, jit, nullptr) == SIGILHOOK_ERROR_BUSY);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_ERROR_BUSY);
    CHECK(sigilhook_destroy(secondHook) == SIGILHOOK_OK);
    CHECK(sigilhook_hook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_get_trampoline(hook, &trampoline) == SIGILHOOK_OK);
    CHECK(trampoline != 0);

    g_testMode = 0;
    CHECK(target(1) == 42);
    CHECK(g_targetCalls == 1);

    g_testMode = 1;
    CHECK(target(1) == 99);
    CHECK(g_targetCalls == 1);

    g_testMode = 2;
    CHECK(target(1) == 42);
    CHECK(g_targetCalls == 2);
    CHECK(g_badArgumentValues == 0);

    CHECK(sigilhook_unhook(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy(hook) == SIGILHOOK_OK);
    CHECK(sigilhook_destroy_jit_callback(jit) == SIGILHOOK_OK);
    return 0;
}
